/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **The Warden gate for the Rust tunnel loop** — the in-crate typed bridge to
//! `torta_firewall_verdict` (`lib.rs:2393`), the same verdict the legacy C engine calls from
//! `ip.c:353`. The DENY verdict is the ONE thing the loop honors for a NON-DNS-intercepted packet
//! (the Stage-2-min "forward_or_warden_drop"); for DNS queries, the resolver owns its own blocklist
//! gate (NXDOMAIN), so the Warden gate is applied only to the non-:53 passthrough.
//!
//! ## GENESIS — bind (no overhaul needed)
//!
//! The verdict engine itself is `torta_firewall_verdict` (lib.rs:2393) — the C-ABI surface the C
//! engine already calls. The Rust loop is in the SAME crate as that fn, so the bind is a direct
//! in-crate call (no `dlsym`, no cross-library flag — the spec §1 contract). This module is the
//! thin typed wrapper: it formats the destination as an `inet_ntop`-equivalent string (the exact
//! shape `ip.c` passes — a string, not raw bytes) + the qname as UTF-8, marshals them as the C-ABI
//! expects, and returns the verdict enum. The C-ABI fn is `pub extern "C" fn` (not `unsafe fn`):
//! it NULL-checks its raw pointers and contains its own `unsafe` blocks, so the call site is safe.
//!
//! ## FAIL-SAFE
//!
//! `torta_firewall_verdict` returns `-1` (ABSTAIN) on any malformation or an unconfigured singleton
//! — the verdict can ONLY ADD a block, never open a hole. The loop treats ABSTAIN as "pass" (no
//! deny): the Warden is not consulted on the DNS-intercept path (the resolver blocklists there);
//! it rules ONLY on the non-DNS passthrough, and a DENY there drops the packet.
//!
//! ## THE TRACKER FEED (A5 slice-4)
//!
//! This bridge is the ONE choke point every non-DNS judgment crosses — the tunnel loop's gate
//! (`tunnel/mod.rs` `handle_packet`) and the netstack forwarder's per-flow `warden_allows`
//! (`forwarder/run.rs`) both land here — so [`verdict`] also feeds the judged flow into the global
//! live-panel ring (`warden::tracker::feed`). The feed INFORMS, never authorizes: nothing on the
//! verdict path reads what the tracker holds.

#![forbid(unsafe_code)]

use std::net::IpAddr;

use crate::tunnel::parse::IpAddrBytes;
use crate::warden::object::WardenVerdict;
use crate::warden::{ConnFacts, NetworkType, Verdict as EngineVerdict};

/// The Warden's verdict (the `torta_firewall_verdict` return shape, as an enum). Matches the
/// `i32` contract of lib.rs:2393: `-1` ABSTAIN, `0` DENY, `1` ALLOW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// `-1`: the Warden is unconfigured or the facts are insufficient — fall through (pass).
    Abstain,
    /// `0`: the Warden DENIES — drop the packet (the additive-block contract).
    Deny,
    /// `1`: the Warden ALLOWs — pass.
    Allow,
}

impl Verdict {
    #[inline]
    pub fn is_deny(self) -> bool {
        matches!(self, Verdict::Deny)
    }

    /// The tracker-feed grain ([`WardenVerdict`]): DENY is the only refusal; ALLOW and ABSTAIN
    /// both map to [`WardenVerdict::Allow`], whose contract is "no cascade tier denied — the
    /// connection passes the firewall gate" (object.rs:181) — exactly what an abstain is (the
    /// fail-safe pass). The panel shows what FLOWED, not which rule engine was awake.
    fn bridged(self) -> WardenVerdict {
        match self {
            Verdict::Deny => WardenVerdict::DenyByFirewall,
            Verdict::Allow | Verdict::Abstain => WardenVerdict::Allow,
        }
    }
}

impl From<i32> for Verdict {
    fn from(raw: i32) -> Self {
        match raw {
            0 => Verdict::Deny,
            1 => Verdict::Allow,
            _ => Verdict::Abstain, // -1 or any other ⇒ abstain (the fail-safe)
        }
    }
}

/// Consult the Warden for a non-DNS-intercepted packet — the typed in-crate bridge to
/// `torta_firewall_verdict` (lib.rs:2393). The destination is formatted as an `inet` string (the
/// exact shape `ip.c:353` passes — `inet_ntop`'d, not raw bytes).
///
/// The qname: when the caller has none (both datapaths — the W3 firewall seam is name-blind),
/// A4 ATTRIBUTES the destination from the global `answer IP → query qname` map: the loop IS the
/// resolver, so the domain the app resolved moments ago labels the flow it dials now. The
/// attribution rides into the per-app domain rules AND the tracker row — under the FAIL-OPEN LAW
/// below.
///
/// ## The A4 fail-open law (GENESIS-pillar-warden.md, the spec caveat)
///
/// Attribution is BEST-EFFORT: CDNs collapse many names onto one IP, entries expire, cached
/// answers never pass through the map. A wrong label must NEVER drive a DENY. So when a deny
/// exists ONLY because we attributed (the caller had no name), the verdict is re-asked BARE —
/// and if the facts alone (uid/ip/port) don't deny, the label's deny is DISCARDED. Nothing real
/// is lost: on the DNS path the domain rules already fired authoritatively at resolve time with
/// the true qname, so a domain-blocked name never resolves — the flow this gate judges shouldn't
/// exist. The label's remaining job is honest: inform the panel, sharpen an allow.
///
/// `uid` may be `-1` (unresolved) ⇒ the C-ABI fn ABSTAINs (lib.rs:2407). `ip_version` is `4` or
/// `6`. `protocol` is the IP protocol number (the C-ABI fn takes `i32`).
///
/// `carries` is the CALLER's datapath disposition (#20 ROW HONESTY): `true` when the caller will
/// carry the flow if allowed (the netstack forwarder), `false` when it drops regardless (the sync
/// loop's Stage-2-min non-DNS gate). It NEVER shades the verdict — it rides into the tracker feed
/// so the panel row can say DROPPED instead of a false ALLOW. A denied flow is never `carried`.
pub fn verdict(
    uid: i32,
    ip_version: u8,
    protocol: u8,
    daddr: &IpAddrBytes,
    dport: u16,
    qname: Option<&str>,
    carries: bool,
) -> Verdict {
    let daddr_ip: IpAddr = match daddr {
        IpAddrBytes::V4(b) => IpAddr::V4(std::net::Ipv4Addr::from(*b)),
        IpAddrBytes::V6(b) => IpAddr::V6(std::net::Ipv6Addr::from(*b)),
    };
    let daddr_str = daddr_ip.to_string();

    // A4 — attribute the destination when the caller has no name. None when unknown/expired.
    let attributed: Option<std::sync::Arc<str>> = if qname.is_none() {
        crate::warden::attribution::lookup(&daddr_ip)
    } else {
        None
    };
    let effective_qname: Option<&str> = qname.or(attributed.as_deref());

    // The ONE consult point — both the initial ask and the A4 BARE re-ask enter here, so the
    // fail-open law holds on whichever engine rules. A6: the CANONICAL datapath engine (the
    // instance Kotlin's gate arms — rules / matrix / toggles / durable rehydrate) is consulted
    // FIRST; it abstains (`None`) unless the user ARMED the firewall, and then this falls
    // through to the legacy flat-global C-ABI ask — byte-identical to the pre-A6 datapath.
    //
    // The C-ABI fn (lib.rs:2393) takes `*const u8` + `usize` for daddr and qname. It is `pub
    // extern "C" fn` (NOT `unsafe fn`) and NULL-checks its pointers internally, so passing valid
    // slice pointers is a safe call. The slices outlive the call (the C-ABI fn does not retain).
    let ask = |q: Option<&str>| -> Verdict {
        if let Some(v) = ask_canonical(uid, daddr_ip, dport, protocol, q) {
            return v;
        }
        let qname_bytes = q.map(|s| s.as_bytes()).unwrap_or(&[]);
        Verdict::from(crate::torta_firewall_verdict(
            uid,
            ip_version as i32,
            protocol as i32,
            daddr_str.as_ptr(),
            daddr_str.len(),
            dport,
            qname_bytes.as_ptr(),
            qname_bytes.len(),
        ))
    };

    let mut v = ask(effective_qname);

    // The fail-open law's teeth: an attribution-only deny must survive a BARE re-ask or die.
    if v.is_deny() && qname.is_none() && attributed.is_some() {
        let bare = ask(None);
        if !bare.is_deny() {
            v = bare;
        }
    }

    // A5 slice-4 — the tracker feed. INFORMS only: the verdict above is already sealed; the ring
    // is a render surface, never an authorizer. `carried` = the caller carries AND the verdict
    // allows — a deny is never carried, and the sync loop's drops are never dressed as carries.
    // The domain rides along (A4): the row shows WHAT the app dialed, not just where.
    crate::warden::tracker::feed(
        uid,
        daddr_ip,
        dport,
        protocol,
        v.bridged(),
        carries && !v.is_deny(),
        effective_qname,
    );
    v
}

/// A6 — consult THE CANONICAL DATAPATH ENGINE (`warden::object::datapath_verdict`), the same
/// `WardenObject` the Kotlin gate arms and the Java VPN datapath queries. `None` (⇒ the caller
/// falls to the legacy flat-global ask) unless the user ARMED the firewall AND the instance
/// exists.
///
/// Fact-building mirrors the flat C-ABI `torta_firewall_verdict` EXACTLY so the only delta
/// between the two paths is WHICH engine rules: `uid < 0` abstains here too (the one
/// unresolved-uid law stays in one shape), and `net` classifies Lan-else-Wifi via the same
/// `crate::is_lan_addr` axis (the tunnel cannot see the underlying transport; pushing the real
/// connectivity class from Kotlin is a banked later road). `dns_blocked` is `false` — the TIER-5
/// seam belongs to the resolver's own gate, not this per-packet consult.
///
/// The engine's verdict is BINARY (Allow/Deny — no Abstain): an armed canonical engine RULES,
/// under the object's fail-CLOSED fault posture, exactly like the Java datapath sees it.
fn ask_canonical(
    uid: i32,
    daddr: IpAddr,
    dport: u16,
    proto: u8,
    qname: Option<&str>,
) -> Option<Verdict> {
    if uid < 0 {
        return None;
    }
    let net = if crate::is_lan_addr(&daddr) {
        NetworkType::Lan
    } else {
        NetworkType::Wifi
    };
    let conn = ConnFacts {
        uid: uid as u32,
        daddr,
        dport,
        proto,
        qname: qname.map(str::to_string),
        net,
        dns_blocked: false,
    };
    crate::warden::object::datapath_verdict(&conn).map(|v| match v {
        EngineVerdict::Allow => Verdict::Allow,
        EngineVerdict::Deny => Verdict::Deny,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_from_raw() {
        assert_eq!(Verdict::from(-1), Verdict::Abstain);
        assert_eq!(Verdict::from(0), Verdict::Deny);
        assert_eq!(Verdict::from(1), Verdict::Allow);
        assert_eq!(Verdict::from(99), Verdict::Abstain); // fail-safe
    }

    #[test]
    fn is_deny_only_for_zero() {
        assert!(Verdict::Deny.is_deny());
        assert!(!Verdict::Allow.is_deny());
        assert!(!Verdict::Abstain.is_deny());
    }

    #[test]
    fn bridged_maps_abstain_and_allow_to_allow_deny_to_firewall_deny() {
        assert_eq!(Verdict::Abstain.bridged(), WardenVerdict::Allow);
        assert_eq!(Verdict::Allow.bridged(), WardenVerdict::Allow);
        assert_eq!(Verdict::Deny.bridged(), WardenVerdict::DenyByFirewall);
    }

    #[test]
    fn verdict_feeds_the_global_tracker_with_the_bridged_grain() {
        // The ring is process-global: EVERY test that feeds or clears it takes the crate gate —
        // the comment-only "test-threads=1 law" was never enforced and flaked under the default
        // parallel harness (measured 1042/1: a gated sibling fed the ring between our clear() and
        // snapshot()). Same idiom as WARDEN_GLOBAL_TEST_LOCK's own charter (lib.rs).
        let _w = crate::lock_warden_global();
        let g = crate::warden::tracker::global();
        g.clear();
        let v = verdict(1000, 4, 6, &IpAddrBytes::V4([8, 8, 4, 4]), 443, None, true);
        let snap = g.snapshot();
        assert_eq!(snap.len(), 1, "ONE judgment ⇒ ONE ring record");
        let f = &snap[0];
        assert_eq!((f.uid, f.port, f.proto, f.ip.as_str()), (1000, 443, 6, "8.8.4.4"));
        assert_eq!(
            (f.cc.as_str(), f.asn.as_str()),
            ("us", "GOOGLE"),
            "attribution trio fires on the fed flow"
        );
        // The mapping invariant holds whatever state the process-global Warden singleton is in
        // (other tests may configure it): the ring's grain IS the bridge of the returned verdict.
        assert_eq!(f.verdict, v.bridged());
        // #20 — carries=true + a non-deny verdict ⇒ the row records CARRIED.
        assert_eq!(f.carried, !v.is_deny());
        g.clear(); // leave no residue
    }

    #[test]
    fn verdict_with_carries_false_feeds_an_uncarried_row() {
        // #20 ROW HONESTY — the sync-loop shape: the Warden may allow, but the caller drops the
        // flow regardless (Stage-2-min carries nothing). The ring row MUST record carried=false so
        // the panel renders DROPPED, never a false ALLOW.
        let _w = crate::lock_warden_global(); // ring feeders serialize on the crate gate
        let g = crate::warden::tracker::global();
        g.clear();
        let v = verdict(1000, 4, 6, &IpAddrBytes::V4([8, 8, 4, 4]), 443, None, false);
        assert!(!v.is_deny(), "unconfigured singleton abstains — the flow is allowed");
        let snap = g.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(
            !snap[0].carried,
            "an allowed-but-dropped flow must never be dressed as carried"
        );
        g.clear(); // leave no residue
    }

    #[test]
    fn verdict_abstains_on_unconfigured_singleton() {
        // The Warden singleton is unconfigured in the bare test environment ⇒ ABSTAIN (-1). This
        // is the fail-safe proof: a NULL/daddr-only call never bricks connectivity.
        // Serialize vs the sibling warden tests + ENSURE the unconfigured state (the test-threads=1
        // law: this branch asserts the DISARMED singleton, so it must never inherit a prior test's
        // armed one — the same lock+clear hygiene `verdict_attributes_a_nameless_flow_and_feeds_the_domain`
        // uses).
        let _w = crate::lock_warden_global();
        crate::clear_warden_for_test();
        let v = verdict(
            1000,
            4,
            17, // UDP
            &IpAddrBytes::V4([8, 8, 8, 8]),
            53,
            None,
            false,
        );
        assert_eq!(v, Verdict::Abstain);
    }

    #[test]
    fn verdict_attributes_a_nameless_flow_and_feeds_the_domain() {
        // A4 — the loop IS the resolver: a name the app resolved moments ago labels the nameless
        // flow it dials now. Attribution INFORMS the row; it never manufactures a verdict.
        let _w = crate::lock_warden_global();
        crate::clear_warden_for_test(); // unconfigured singleton ⇒ ABSTAIN
        let g = crate::warden::tracker::global();
        g.clear(); // process-global ring (test-threads=1 law)

        // TEST-NET-2 destination — no collision with the attribution module's own global-map
        // test (which owns 203.0.113.77) or the sibling verdict tests (8.8.4.4 / 8.8.8.8).
        let dst = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9));
        crate::warden::attribution::global().record(dst, "cdn.example", 300);

        let v = verdict(1000, 4, 6, &IpAddrBytes::V4([198, 51, 100, 9]), 443, None, true);
        assert_eq!(v, Verdict::Abstain, "attribution never manufactures a verdict on its own");
        let snap = g.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[0].domain, "cdn.example",
            "the attributed name labels the nameless flow's ring row"
        );

        // A caller-known qname OUTRANKS the map — attribution serves only the nameless.
        g.clear();
        let _ = verdict(
            1000,
            4,
            6,
            &IpAddrBytes::V4([198, 51, 100, 9]),
            443,
            Some("caller.example"),
            true,
        );
        assert_eq!(
            g.snapshot()[0].domain,
            "caller.example",
            "caller truth wins; the map is the fallback, never the override"
        );
        g.clear(); // leave no residue
    }

    #[test]
    fn attribution_only_deny_dies_on_the_bare_re_ask_but_a_facts_deny_stands() {
        // THE A4 FAIL-OPEN LAW'S TEETH — attribution is best-effort (CDN collapse, expiry, cached
        // answers), so a deny that exists ONLY because we guessed the name must be re-asked bare
        // and die. Nothing real is lost: the DNS path already fired the domain rules with the
        // TRUE qname at resolve time.
        let _w = crate::lock_warden_global();
        const UID: u32 = 10_777;
        // Arm a Warden whose ONLY deny is a per-app domain rule — the bare facts allow.
        let mut w = crate::warden::Warden::new();
        let mut ds = crate::warden::DomainRuleSet::new();
        ds.insert(crate::warden::DomainRule {
            domain: "tracker.example".into(),
            uid: UID,
            wildcard: true,
        });
        ds.finalize();
        w.set_domain_rules(ds);
        *crate::warden_lock() = Some(w);

        // The map attributes the destination to the BLOCKED name.
        let dst = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7));
        crate::warden::attribution::global().record(dst, "tracker.example", 300);

        let g = crate::warden::tracker::global();
        g.clear(); // process-global ring (test-threads=1 law)
        let v = verdict(UID as i32, 4, 6, &IpAddrBytes::V4([198, 51, 100, 7]), 443, None, true);
        assert_eq!(
            v,
            Verdict::Allow,
            "an attribution-ONLY deny is re-asked bare and dies — a guessed label never drives DENY"
        );
        let snap = g.snapshot();
        assert_eq!(snap.len(), 1, "the guard's re-ask feeds NO second row — one judgment, one record");
        assert_eq!(
            snap[0].domain, "tracker.example",
            "the label still INFORMS the row it failed to deny"
        );
        assert!(snap[0].carried, "the rescued allow carries");

        // The control arm: a REAL facts deny (Isolate ⇒ non-LAN denied, warden/mod.rs:1182)
        // survives the guard — the bare re-ask denies too, so the deny STANDS. The guard rescues
        // only label-manufactured denies; it is fail-open, not deny-blind.
        let mut w = crate::warden::Warden::new();
        let mut row = crate::warden::AppMatrixRow::new(UID);
        row.mode = crate::warden::AppFirewallMode::Isolate;
        w.set_app_row(row);
        *crate::warden_lock() = Some(w);
        g.clear();
        let v = verdict(UID as i32, 4, 6, &IpAddrBytes::V4([198, 51, 100, 7]), 443, None, true);
        assert!(v.is_deny(), "a facts-based deny is NOT rescued by the attribution guard");
        assert!(!g.snapshot()[0].carried, "a denied flow is never carried");

        crate::clear_warden_for_test();
        g.clear(); // leave no residue
    }

    // ---- A6 — THE CANONICAL ENGINE CONSULT ------------------------------------------------
    //
    // The canonical `DATAPATH` slot + ARM bit are process-global (single-thread test law):
    // these tests use uids unique to this block (97_91x), TEST-NET-2 addrs owned here
    // (198.51.100.40/.41), and restore enforced=false + remove their rows before returning —
    // the sibling tests above PROVE the disarmed fall-through (flat global) still rules.

    #[test]
    fn canonical_engine_rules_the_tunnel_when_enforced() {
        let _w = crate::lock_warden_global();
        crate::clear_warden_for_test(); // flat global UNCONFIGURED — any ruling below is canonical
        let g = crate::warden::tracker::global();
        g.clear();

        let w = crate::warden::object::warden_datapath_instance();
        w.set_app_row(crate::warden::object::WardenAppRow {
            uid: 97_910,
            mode: crate::warden::object::WardenAppMode::Isolate,
            meteredness: crate::warden::object::WardenNetClass::Allow,
            temp_allow_until: 0,
        });
        let dst = IpAddrBytes::V4([198, 51, 100, 40]);

        // DISARMED: the armed row is silent — falls to the unconfigured flat global ⇒ Abstain.
        crate::warden::object::warden_set_datapath_enforced(false);
        assert_eq!(
            verdict(97_910, 4, 6, &dst, 443, None, false),
            Verdict::Abstain,
            "disarmed ⇒ byte-identical fall-through to the (unconfigured) flat global"
        );

        // ARMED: the SAME facts now hit the canonical engine — the Isolate row denies WAN.
        crate::warden::object::warden_set_datapath_enforced(true);
        assert_eq!(
            verdict(97_910, 4, 6, &dst, 443, None, false),
            Verdict::Deny,
            "the row armed on the CANONICAL engine rules the Rust tunnel datapath"
        );
        // An unruled uid is RULED Allow (the armed engine judges — never Abstain).
        assert_eq!(
            verdict(97_911, 4, 6, &dst, 443, None, false),
            Verdict::Allow,
            "an armed canonical engine rules Allow explicitly, not Abstain"
        );
        // uid -1 (unresolved) abstains BEFORE the canonical consult — the one uid law.
        assert_eq!(
            verdict(-1, 4, 6, &dst, 443, None, false),
            Verdict::Abstain,
            "unresolved uid abstains on the canonical path exactly like the flat path"
        );

        crate::warden::object::warden_set_datapath_enforced(false);
        w.remove_app_row(97_910);
        g.clear(); // leave no residue
    }

    #[test]
    fn canonical_attribution_only_deny_still_dies_on_the_bare_re_ask() {
        // The A4 fail-open law must survive the seam swap: an attribution-manufactured deny on
        // the CANONICAL path is re-asked BARE through the SAME canonical engine and discarded
        // when the facts alone don't deny.
        let _w = crate::lock_warden_global();
        crate::clear_warden_for_test();
        let g = crate::warden::tracker::global();
        g.clear();

        let w = crate::warden::object::warden_datapath_instance();
        let report = w.install_domain_rules(vec![crate::warden::object::WardenDomainRule {
            domain: "a6-evil.example.net".to_string(),
            uid: 0,
            wildcard: true,
        }]);
        assert_eq!(report.accepted, 1, "the fixture rule must arm");
        let dst_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 41));
        crate::warden::attribution::global().record(dst_ip, "a6-evil.example.net", 300);
        crate::warden::object::warden_set_datapath_enforced(true);

        // Nameless flow → attributed to the blocked apex → canonical DENY → BARE re-ask on the
        // canonical engine allows (facts alone don't deny) → the label's deny is DISCARDED.
        let v = verdict(97_912, 4, 6, &IpAddrBytes::V4([198, 51, 100, 41]), 443, None, true);
        assert_eq!(
            v,
            Verdict::Allow,
            "an attribution-only canonical deny dies on the bare re-ask (A4 fail-open law)"
        );
        let snap = g.snapshot();
        assert_eq!(snap.len(), 1, "one judgment, one ring record — the re-ask feeds no second row");
        assert_eq!(
            snap[0].domain, "a6-evil.example.net",
            "the label still informs the row it failed to deny"
        );

        // The control arm: a caller-KNOWN qname on the blocked apex is an authoritative deny —
        // no attribution, no rescue.
        g.clear();
        let v = verdict(
            97_912,
            4,
            6,
            &IpAddrBytes::V4([198, 51, 100, 41]),
            443,
            Some("a6-evil.example.net"),
            true,
        );
        assert_eq!(v, Verdict::Deny, "a caller-known blocked qname denies authoritatively");
        assert!(!g.snapshot()[0].carried, "a denied flow is never carried");

        crate::warden::object::warden_set_datapath_enforced(false);
        let cleared = w.install_domain_rules(vec![]);
        assert_eq!(cleared.accepted, 0, "replace semantics ⇒ the armed set is now empty");
        g.clear(); // leave no residue
    }
}
