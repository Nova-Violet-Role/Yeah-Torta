/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! THE WARDEN — the per-connection verdict engine. The Monokuma judge that rules on every connection:
//! a deterministic **6-tier first-match-DENY cascade** over the armed rule-sets + per-app matrix +
//! universal toggles into one authoritative `Allow`/`Deny`. Ring-only, allocation-light (like the
//! blocklist trie), `#![forbid(unsafe_code)]`, and FAIL-SAFE (never bricks connectivity, never silently
//! opens a hole).
//!
//! ## THE LAW — additive-block-only, first-match-DENY (REWORKED design §2, load-bearing, Socio)
//! The verdict is a PURE FIREWALL: the blocklist `Matcher` is NO LONGER a verdict parameter (the
//! block-wins two-half compose RETIRED, slice 1 rework). A connection ALLOWS unless a cascade tier
//! DENIES it; the FIRST tier that fires wins and is the deny's attribution. The cascade ([`verdict_at`]):
//!   * TIER 0 — CACHE: O(1) epoch-gated replay.
//!   * TIER 1 — SELF-EXEMPT: the resolver/VPN uid passes (datapath concern; no-op here).
//!   * TIER 2 — UNIVERSAL TOGGLES: the 9 global DENY switches (the `|||` settings section).
//!   * TIER 3 — PER-APP DENY: the matrix (mode/meteredness/temp-allow) + per-app domain/CIDR rules.
//!   * TIER 4 — UNIVERSAL DENY: the universal domain/CIDR rule-set (skipped for `BypassUniversal`).
//!   * TIER 5 — DNS-BLOCKED: the resolver's `dns_blocked` seam (skipped for `BypassDnsFirewall`).
//!   * TIER 6 — DEFAULT ALLOW (RULE0); FAIL-CLOSED on engine exception.
//!
//! ## ALLOW-BY-DEFAULT — no baseline allow-set gate (REWORKED design, the policy removal, Socio)
//! The legacy per-UID allow-set baseline (the old `WardenPolicy` 5-set gate) is REMOVED: there is no
//! "is this UID allowed on this network type" pre-gate at the head of the cascade. The verdict is now a
//! PURE additive-block — a connection ALLOWS unless a deny TIER fires. Per-app / per-network control is
//! carried by the per-app matrix ([`AppMatrixRow`] / [`AppFirewallMode`]), the universal toggles
//! ([`UniversalToggles`]), and the armed rule-sets ([`WardenRuleSets`]) — the Genesis-ready surfaces that
//! supersede the 5 allow-sets with ZERO firewall-control capability lost. [`NetworkType`] survives as the
//! deny-tier SELECTOR (the datapath sets `net = Lan` for a LAN-range destination, the orthogonal axis).
//!
//! ## The DNS-blocked seam — the narrow resolver integration point (Anti-Venom §5d)
//! The blocklist verdict enters the cascade ONLY at TIER 5, as the [`ConnFacts::dns_blocked`] boolean
//! the DNS resolver sets when ITS blocklist denied the resolved name+addr. The Warden does NOT re-query
//! the blocklist; it trusts the flag. The cache is epoch-gated on
//! [`crate::blocklist::installed_fingerprint`] (`blocklist.rs:581`) so a blocklist re-arm lazily
//! invalidates any stale verdict — a hit can NEVER contradict a fresh compute (the cache invariant).
//!
//! ## SCOPE
//! The verdict + the rule-set/matrix/toggle layer + the [`object::WardenObject`] surface. The public
//! engine surface is `#[cfg_attr(not(test), allow(dead_code))]` (the crate's dead-code-until-wired idiom,
//! `blocklist.rs:235`) so clippy `-D warnings` stays clean in the non-test build until the datapath +
//! the Object reference it.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::path::PathBuf;

/// The R1.x.3 stateful Object lift — the `#[derive(uniffi::Object)] WardenObject` that wraps THIS
/// engine (a stateful pillar Object alongside Beast/Centauri). ADDITIVE: the Object is a NEW
/// stateful Kotlin surface ALONGSIDE the flat `lib.rs` exports + the engine below, which stay live +
/// byte-identical. The Object's verdict is the REWORKED-design PURE FIREWALL (no blocklist param); see
/// [`object`] for the why. Always-built (NOT feature-gated — the Warden ships in every config).
pub mod object;

/// SLICE 3 — the clean-room dnsmasq DOMAIN-PATTERN engine: the per-label glob matcher + the RFC-1123
/// integrity gate ([`pattern::validate_pattern`], the poisoned-blocklist defense). Studied from
/// dnsmasq-2.93 `pattern.c` (IDEAS only — the Russ Cox public glob + RFC-1123); ZERO derived bytes.
pub mod pattern;

/// SLICE 3 — the clean-room FAMILY-AWARE CIDR matcher (v4 + v6), the overhaul of dnsmasq's `bogus_addr`
/// family-tagged prefix match. Closes the v4-only gap for the DNS-answer address-walk; ZERO derived bytes.
pub mod cidr_match;

/// SLICE 3 — the DNS-ANSWER verdict loop ([`verdict_loop::apply_dns_verdict`]): the overhaul of the
/// dnsmasq `cache_recv_insert` name→address→rule loop, INVERTED to deny-on-match. The PRODUCER of the
/// TIER-5 `dns_blocked` seam the per-connection cascade consumes; ZERO derived bytes.
pub mod verdict_loop;

/// SLICE 6 — `query-warden.log`: the per-pillar, human-legible VERDICT feed written through the shared
/// RAM⊗NAND [`crate::log_tier`] substrate (#133, the `query.log` precedent). Emitted ONLY from the explicit
/// review-channel seam ([`Warden::dns_verdict_logged`]) — never the pure hot-path verdict.
pub mod log;

/// A5 — the LIVE CONNECTION TRACKER: the bounded per-flow RAM ring ([`tracker::ConnTracker`]) + the
/// country-flag derivation ([`tracker::flag_emoji`]) behind the "where your data goes" panel
/// (🇺🇸 chrome · 443 · TCP · ALLOW). Studied from RethinkDNS `ConnectionTracker.kt`/`CountryConfig.kt`/
/// `StatsSummaryDao.kt` (IDEAS only); ZERO derived bytes. The GeoIP `cc` producer is [`geoip`]
/// (slice-2, LIVE); the `asn` producer is [`asn`] (slice-3, LIVE).
pub mod tracker;

/// A5 slice-2 — GEOIP ([`geoip::country_code`]): `IP → ISO country`, answered zero-copy from two
/// embedded RIR start-tables (`data/geoip{4,6}.bin`, built by `examples/geoip_gen.rs` from the five
/// registries' delegated-stats files). Geography INFORMS, never authorizes — the caveat law (wrong
/// attribution must never drive a DENY) holds by construction: nothing on a verdict path reads this.
pub mod geoip;

/// A5 slice-3 — ASN ([`asn::as_name`]): `IP → AS name`, answered zero-copy from embedded BGP
/// start-tables + an interned name blob (`data/asn{4,6}.bin` + `data/asnames.bin`, built by
/// `examples/asn_gen.rs` from the iptoasn.com dumps). Same caveat law as [`geoip`]: attribution
/// informs the panel, never a verdict.
pub mod asn;

/// The shared START-TABLE binary search under [`geoip`] and [`asn`] — BE keys make byte compare
/// numeric compare, so one search body serves every key width.
pub(crate) mod start_table;

/// A4 — ATTRIBUTION ([`attribution::lookup`]): `answer IP → query qname`, fed by the resolve
/// hooks (the loop IS the resolver — every A/AAAA answer passes through our hands), consumed by
/// the verdict seam and the LIVE FLOWS panel. Bounded + TTL-clamped; the fail-open law (a wrong
/// label must NEVER drive a DENY) is enforced by the consumer's bare re-ask, documented there.
pub mod attribution;

/// Default bound on the per-connection decision cache (the hot RAM tier). Capped + LRU-evicted so the
/// churning connection path can never balloon memory on an Android device — the lean-crowd / RAM-tier
/// discipline. The W3 bridge MAY pass an Expert-tuned cap via [`Warden::with_cache_cap`].
const DEFAULT_CACHE_CAP: usize = 4096;

// ===========================================================================================
// The types (the connection facts, the network-type selector, the verdict)
// ===========================================================================================

/// The active network type — the SELECTOR that resolves which firewall allow-set governs a connection
/// (`ServiceVPNHandler.java:406-411`: Ethernet folds into `Wifi`; resolution order Wifi → Roaming →
/// Gsm). [`Lan`](NetworkType::Lan) is the ORTHOGONAL axis: a LAN-destined connection is decided by the
/// LAN set regardless of the live network type (W3 sets `net = Lan` when the destination is LAN-range).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NetworkType {
    /// A LAN-range destination — the orthogonal axis, decided by the LAN allow-set.
    Lan,
    /// Wi-Fi (also covers Ethernet, which collapses to the Wi-Fi set).
    Wifi,
    /// Cellular / mobile data (non-roaming).
    Gsm,
    /// Cellular while roaming — checked BEFORE [`Gsm`](NetworkType::Gsm) (order is load-bearing).
    Roaming,
    /// The VPN-tunnel-bypass axis (root-mode / VPN-app allowance, `APPS_ALLOW_VPN`).
    Vpn,
}

/// The one-glance verdict over a connection — the authoritative output of the PURE-FIREWALL cascade.
/// INTELLIGENCE-free binary by design: a connection [`Allow`](Verdict::Allow)s unless a cascade tier
/// DENIES it ([`Deny`](Verdict::Deny)). The first-match tier that fired is the deny's attribution (the
/// [`WardenStats`] deny-by-tier breakdown), but the verdict ITSELF is binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// No cascade tier denied — the connection passes (TIER 6 default-allow, or a tier explicitly
    /// allowed it).
    Allow,
    /// A cascade tier denied (first-match-wins) — the connection is dropped.
    Deny,
}

/// AGGREGATE verdict counters — the observe-only stats the dashboard card reads. Counts ONLY: allow vs
/// deny, and (on a deny) WHICH cascade tier fired (the first-match-DENY attribution). NEVER a qname /
/// domain / UID / per-connection history (the `nativeResolverStats` "no qname ever" law, T20) — only
/// monotonic tallies leave the engine.
///
/// CHEAP by construction: plain `u64` fields on the [`Warden`] (which is held behind a `Mutex` and whose
/// [`verdict`](Warden::verdict) already takes `&mut self`, so a recorded count is a single in-memory add
/// under the lock the verdict already holds — NO atomics, NO IO, NO flash write). When the Warden is
/// disarmed (the global singleton is `None`, the production posture) the verdict point is never reached →
/// every tally stays zero (inert-graceful: the card shows an honest "off").
///
/// REWORKED (slice 1, the pure-firewall cascade): the OLD block-wins split (firewall vs blocklist) is
/// RETIRED. The deny attribution now honors the 6-tier cascade — a deny is attributed to EXACTLY the
/// tier that fired (first-match-wins). The invariant:
/// `deny == deny_by_universal_toggle + deny_by_app + deny_by_universal_rule + deny_by_blocklist`.
/// `deny_by_blocklist` is KEPT (name preserved for the dashboard-card label continuity); its semantics
/// narrows to TIER 5 — the `dns_blocked` resolver seam (the single integration point between the DNS
/// resolver blocklist verdict and the firewall, per the Anti-Venom §5d study).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WardenStats {
    /// Connections the cascade ALLOWED (no tier denied; default-allow).
    pub allow: u64,
    /// Connections the cascade DENIED (at least one tier fired).
    pub deny: u64,
    /// Of the denies, those attributed to TIER 2 — the universal toggles (the `|||` settings section:
    /// lockdown, block-new-apps, block-metered, device-lock, block-background, block-http, block-udp-ntp,
    /// block-dns-bypass, block-unknown-conns).
    pub deny_by_universal_toggle: u64,
    /// Of the denies, those attributed to TIER 3 — the per-app matrix (app-mode Isolate, meteredness
    /// block, temp-allow expiry, per-app domain/CIDR rules).
    pub deny_by_app: u64,
    /// Of the denies, those attributed to TIER 4 — the universal rule-set (universal-domain + universal-
    /// CIDR rules; skipped for `AppFirewallMode::BypassUniversal`).
    pub deny_by_universal_rule: u64,
    /// Of the denies, those attributed to TIER 5 — the `dns_blocked` resolver seam (the blocklist verdict
    /// the DNS resolver set on the connection metadata; skipped for `AppFirewallMode::BypassDnsFirewall`).
    /// Name kept for dashboard label continuity; semantics = TIER 5 only.
    pub deny_by_blocklist: u64,
}

/// The facts the datapath hands the verdict engine for ONE connection. W3 fills this from the tun
/// bridge (the `#85 torta_resolve` pattern); in W2 it is the test/host input shape. `qname` is `Some`
/// only for a DNS-bearing connection (the blocklist half abstains when it is `None`).
///
/// REWORKED (slice 1): `dns_blocked` is the TIER 5 seam — the boolean the DNS resolver sets on the
/// connection metadata when its blocklist denied the resolved name+addr (the single integration point
/// between the resolver blocklist verdict and the firewall, Anti-Venom §5d). The Warden does NOT re-query
/// the blocklist; it trusts the resolver's flag. Skipped for `AppFirewallMode::BypassDnsFirewall`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnFacts {
    /// The owning app's UID (Android UID = Java `Int` → `u32`; negative special-UIDs are firewall-
    /// internal and OUT of the W2 compose scope — handled by the existing Java enforcer).
    pub uid: u32,
    /// The destination IP (used by W3 for LAN-range detection → `net = Lan`).
    pub daddr: IpAddr,
    /// The destination port.
    pub dport: u16,
    /// The IP protocol number (e.g. 6 = TCP, 17 = UDP).
    pub proto: u8,
    /// The queried domain when this is a DNS-bearing connection; `None` → the blocklist half abstains.
    pub qname: Option<String>,
    /// The resolved active network type (the firewall-half set selector).
    pub net: NetworkType,
    /// TIER 5 seam — the DNS resolver set this when its blocklist denied the resolved name+addr. Default
    /// `false` (the resolver abstained or this is a non-DNS conn). The Warden trusts the flag; it does
    /// NOT re-query the blocklist.
    pub dns_blocked: bool,
}

// ===========================================================================================
// (The legacy per-UID allow-set `WardenPolicy` was REMOVED — the verdict is ALLOW-BY-DEFAULT
// additive-block. Per-app / per-network firewall control lives in the matrix + universal toggles +
// rule-sets below; the `NetworkType` selector + the `is_lan_addr` LAN axis are retained.)
// ===========================================================================================

// ===========================================================================================
// The bounded per-connection decision cache (the RAM hot tier)
// ===========================================================================================

/// The cache key — the connection IDENTITY. Two connections with the SAME identity collapse to one
/// cached verdict (an O(1) repeat). `qname` is part of the identity (the blocklist half depends on it).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    uid: u32,
    daddr: IpAddr,
    dport: u16,
    proto: u8,
    net: NetworkType,
    qname: Option<String>,
}

impl CacheKey {
    fn from_conn(conn: &ConnFacts) -> Self {
        CacheKey {
            uid: conn.uid,
            daddr: conn.daddr,
            dport: conn.dport,
            proto: conn.proto,
            net: conn.net,
            qname: conn.qname.clone(),
        }
    }

    /// Clone-free identity compare against a live [`ConnFacts`] — the collision-safe re-check on the
    /// [`DecisionCache`] GET hot path (compares `qname` by `as_deref`, allocating nothing). A 64-bit
    /// identity-hash bucket can, astronomically rarely, collide; this makes a collision a safe
    /// MISS+recompute, NEVER a wrong verdict.
    fn matches(&self, conn: &ConnFacts) -> bool {
        self.uid == conn.uid
            && self.daddr == conn.daddr
            && self.dport == conn.dport
            && self.proto == conn.proto
            && self.net == conn.net
            && self.qname.as_deref() == conn.qname.as_deref()
    }
}

/// One cached verdict slot — the full connection identity (for a clone-free equality re-check on the hot
/// GET path), the verdict, the blocklist epoch it was computed under, and the LRU recency stamp. The epoch
/// gate is the load-bearing coherence invariant: a hit whose epoch no longer matches the LIVE blocklist
/// fingerprint is a MISS+drop, so the cache can never serve a verdict that contradicts a fresh compute.
#[derive(Clone, Debug)]
struct CacheSlot {
    /// The full connection identity — kept so a 64-bit hash-bucket collision is a safe MISS+recompute
    /// (compared clone-free via [`CacheKey::matches`]), NEVER a wrong verdict.
    key: CacheKey,
    verdict: Verdict,
    epoch: u64,
    /// The recency stamp (a monotonic sequence) — the O(log n) LRU order key into [`DecisionCache::recency`].
    last_used: u64,
}

/// A bounded, epoch-invalidated LRU verdict cache with O(1)/O(log n) recency — the D20 full-power rework
/// of the former `HashMap` + parallel `Vec` order (whose `touch`/evict were an O(n) `position` scan +
/// `remove(0)` memmove on the per-verdict hot path). Now: a `HashMap<u64, CacheSlot>` keyed by the
/// connection-identity HASH (so the hot GET is CLONE-FREE — the owned [`CacheKey`] is built ONLY on a
/// miss/insert) + a `BTreeMap` recency index (last-used seq → identity hash) giving O(log n) touch +
/// O(log n) evict-the-LRU. Semantics are byte-identical to the old cache: epoch-gated hits, LRU eviction
/// past `cap`, `cap.max(1)` clamp. (The resolver answer cache — `resolver/cache.rs` — shares this shape;
/// D16/D20 deliberately keep the two recency engines in step, `warden/mod.rs:233-235` documents the twin.)
struct DecisionCache {
    /// identity-hash → slot. Collisions resolve SAFELY: a get whose stored `key` does not match the live
    /// conn is a MISS (never a wrong verdict); an insert on a colliding hash overwrites (the rare loser
    /// recomputes next time).
    map: HashMap<u64, CacheSlot>,
    /// last-used seq → identity hash (LRU at the FRONT / smallest seq, MRU at the BACK / largest).
    recency: BTreeMap<u64, u64>,
    /// A strictly-monotonic recency counter — every touch/insert takes the next value.
    seq: u64,
    cap: usize,
}

impl DecisionCache {
    fn new(cap: usize) -> Self {
        DecisionCache {
            map: HashMap::new(),
            recency: BTreeMap::new(),
            seq: 0,
            // A 0 cap would make the cache a no-op (insert then instantly evict); clamp to ≥1 so the
            // hot path always benefits from at least one slot (the resolver-cache clamp, cache.rs:174).
            cap: cap.max(1),
        }
    }

    /// The connection-identity hash (a fixed-seed `DefaultHasher`, deterministic within the process) — the
    /// map bucket. Computed CLONE-FREE from `&ConnFacts` on the GET path and from the owned [`CacheKey`] on
    /// the INSERT path; both hash the SAME identity fields in the SAME order so a rebuilt key lands in the
    /// same bucket.
    fn hash_conn(conn: &ConnFacts) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        conn.uid.hash(&mut h);
        conn.daddr.hash(&mut h);
        conn.dport.hash(&mut h);
        conn.proto.hash(&mut h);
        conn.net.hash(&mut h);
        conn.qname.as_deref().hash(&mut h);
        h.finish()
    }

    /// Bump `hash`'s slot to the MRU end of the recency index (on a hit + on an insert). O(log n): drop the
    /// slot's old recency entry, assign a fresh monotonic seq, re-insert. No-op if absent.
    fn touch(&mut self, hash: u64) {
        if let Some(slot) = self.map.get_mut(&hash) {
            self.recency.remove(&slot.last_used);
            self.seq += 1;
            slot.last_used = self.seq;
            self.recency.insert(self.seq, hash);
        }
    }

    /// Fetch a verdict for `conn` if cached AND its epoch matches `live_epoch`. CLONE-FREE: hashes the
    /// borrowed conn, re-checks identity to stay collision-safe, and on a hit TOUCHES to the MRU end; an
    /// epoch-stale entry is dropped (a miss). No owned [`CacheKey`] is built on this path.
    fn get(&mut self, conn: &ConnFacts, live_epoch: u64) -> Option<Verdict> {
        let hash = Self::hash_conn(conn);
        // Read what we need under the immutable borrow, then release it before any mutation.
        let (verdict, epoch, last_used, identity_ok) = {
            let slot = self.map.get(&hash)?;
            (
                slot.verdict,
                slot.epoch,
                slot.last_used,
                slot.key.matches(conn),
            )
        };
        // A hash collision with a DIFFERENT identity ⇒ a miss (a later insert will overwrite the slot).
        if !identity_ok {
            return None;
        }
        // Epoch-stale (a blocklist re-arm) ⇒ drop it; a fresh compute will re-cache.
        if epoch != live_epoch {
            self.recency.remove(&last_used);
            self.map.remove(&hash);
            return None;
        }
        // A real hit ⇒ bump to MRU and serve.
        self.touch(hash);
        Some(verdict)
    }

    /// Store/replace `conn`'s verdict at `epoch`, maintaining the LRU recency and evicting the LRU past
    /// `cap`. The owned [`CacheKey`] is built HERE — the ONLY clone, on the miss/insert path.
    fn insert(&mut self, conn: &ConnFacts, verdict: Verdict, epoch: u64) {
        let hash = Self::hash_conn(conn);
        // A colliding/replaced slot at this hash — drop its stale recency entry first (extract the seq so
        // the map borrow ends before the recency mutation).
        if let Some(old_seq) = self.map.get(&hash).map(|s| s.last_used) {
            self.recency.remove(&old_seq);
        }
        self.seq += 1;
        let seq = self.seq;
        self.map.insert(
            hash,
            CacheSlot {
                key: CacheKey::from_conn(conn),
                verdict,
                epoch,
                last_used: seq,
            },
        );
        self.recency.insert(seq, hash);
        // Evict the least-recently-used (smallest seq) until within cap.
        while self.map.len() > self.cap {
            let Some((&lru_seq, &lru_hash)) = self.recency.iter().next() else {
                break;
            };
            self.recency.remove(&lru_seq);
            self.map.remove(&lru_hash);
        }
    }

    /// Drop every cached verdict (a rule/matrix/toggle re-arm must re-decide every connection). `seq`
    /// keeps advancing — a monotonic stamp never needs resetting.
    fn clear(&mut self) {
        self.map.clear();
        self.recency.clear();
    }

    /// Live entry count (the RAM hot-tier size the snapshot surfaces).
    fn len(&self) -> usize {
        self.map.len()
    }

    /// TEST-ONLY — is `conn`'s identity currently cached? (Collision-safe: hash bucket + identity re-check.)
    #[cfg(test)]
    fn contains_conn(&self, conn: &ConnFacts) -> bool {
        self.map
            .get(&Self::hash_conn(conn))
            .is_some_and(|slot| slot.key.matches(conn))
    }
}

// ===========================================================================================
// The engine — the PURE-FIREWALL verdict cascade (slice 1 rework), cache, and fail-safe
// ===========================================================================================
//
// REWORKED (slice 1) — the verdict is NO LONGER the block-wins two-half compose. It is a deterministic
// 6-tier first-match-DENY cascade (additive-block-only fork #1, the REWORKED posture):
//
//   TIER 0 — CACHE       : O(1) replay (epoch-gated).
//   TIER 1 — SELF-EXEMPT  : the resolver/VPN uid itself always passes (RethinkDNS step 1).
//   TIER 2 — UNIVERSAL TOGGLES: the 9 global DENY switches (the ||| settings section).
//   TIER 3 — PER-APP DENY : the matrix (app-mode, meteredness, temp-allow) + per-app domain/CIDR rules.
//   TIER 4 — UNIVERSAL DENY: the universal domain/CIDR rule-set (skipped for BypassUniversal).
//   TIER 5 — DNS-BLOCKED  : the resolver's dns_blocked seam (skipped for BypassDnsFirewall).
//   TIER 6 — DEFAULT ALLOW: RULE0; FAIL-CLOSED on engine exception.
//
// The blocklist `Matcher` is NO LONGER a verdict parameter. The DNS-blocked signal enters at TIER 5 as a
// boolean on the connection metadata (the narrow seam from the Anti-Venom §5d study). The signed-policy
// load path was RETIRED (slice 4); the decision source is now the rule-sets + matrix + toggles the caller
// installs. The CASCADE SYNTHESIS is the 4-way cross (Nova §1): rethink-app cascade × dnsmasq verdict-loop
// shape × the existing scaffold (DecisionCache + built rule-set types) × the harvested Trust (advisory
// band on WHICH armed source supplied a deny rule, NEVER a verdict input).

/// The 9 universal DENY toggles — the `|||` settings section (Anti-Venom §6: the global on/off switches
/// above the per-app matrix). Each is an INDEPENDENT DENY; the cascade consults them in the RethinkDNS
/// precedence at TIER 2 (before the per-app matrix). All default `false` (the inert allow-all baseline;
/// an unarmed Warden never bricks connectivity).
///
/// Overhauled from rethink-app-main `PersistentState.kt:513-590` (the 11 universal toggles, IDEA only —
/// zero derived bytes; Apache-2.0 study corpus). The bypass/proxy toggles are DROPPED (additive-block-only
/// fork #1 = DENY only).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UniversalToggles {
    /// RULE1B — block apps not yet seen (gated by `AppFirewallMode::Untracked`).
    pub block_new_apps: bool,
    /// RethinkDNS step 3 — block connections from unknown/untracked UIDs.
    pub block_unknown_conns: bool,
    /// RULE1F — block all metered (cellular/roaming) traffic.
    pub block_metered: bool,
    /// RULE11 — universal lockdown (block everything except the allow-list).
    pub lockdown: bool,
    /// RULE3 — device-lock (block on screen-off). The caller sets this from the device-lock signal.
    pub device_lock: bool,
    /// RULE4 — block background-data (foreground-only). The caller sets this from the foreground signal.
    pub block_background: bool,
    /// RULE6 — block UDP-NTP (port 123 / UDP). A proto+port sub-check.
    pub block_udp_ntp: bool,
    /// RULE10 — block HTTP (port 80, any proto). A port sub-check.
    pub block_http: bool,
    /// RULE7 — block DNS bypass (a query trying to skip the resolver; qname is None).
    pub block_dns_bypass: bool,
}

impl UniversalToggles {
    /// True if EVERY toggle is off (the inert allow-all baseline). Convenience predicate (the cascade
    /// reads the individual bits directly); exercised by tests.
    pub fn is_empty(self) -> bool {
        self == Self::default()
    }

    /// Pack the 9 toggle bits into a `u16` bitfield for the durable matrix-state blob (slice 2). The
    /// bit order is STABLE (a format contract — never reorder; a new toggle takes the next free bit).
    fn to_bits(self) -> u16 {
        (self.block_new_apps as u16)
            | ((self.block_unknown_conns as u16) << 1)
            | ((self.block_metered as u16) << 2)
            | ((self.lockdown as u16) << 3)
            | ((self.device_lock as u16) << 4)
            | ((self.block_background as u16) << 5)
            | ((self.block_udp_ntp as u16) << 6)
            | ((self.block_http as u16) << 7)
            | ((self.block_dns_bypass as u16) << 8)
    }

    /// Unpack the 9 toggle bits from a `u16` bitfield (the inverse of [`to_bits`](Self::to_bits)). An
    /// unknown high bit is IGNORED (a forward-compatible toggle the prior version didn't write is simply
    /// off) — a fail-safe, never an over-block.
    fn from_bits(bits: u16) -> Self {
        Self {
            block_new_apps: bits & 1 != 0,
            block_unknown_conns: bits & (1 << 1) != 0,
            block_metered: bits & (1 << 2) != 0,
            lockdown: bits & (1 << 3) != 0,
            device_lock: bits & (1 << 4) != 0,
            block_background: bits & (1 << 5) != 0,
            block_udp_ntp: bits & (1 << 6) != 0,
            block_http: bits & (1 << 7) != 0,
            block_dns_bypass: bits & (1 << 8) != 0,
        }
    }
}

/// One row of the per-app matrix — the per-app verdict tier (TIER 3). Overhauled from rethink-app-main
/// `AppInfo.kt` (composite PK uid+package, IDEA only — zero derived bytes; Apache-2.0 study corpus). The
/// two built-but-unwired enums ([`AppFirewallMode`] / [`NetClass`]) are KEPT; this row carries the
/// per-app USER intent (mode + meteredness + temp-allow), distinct from the rule-sets (which carry the
/// trust-scored deny rules) and from the toggles (which carry the global DENY switches).
///
/// RAM-tier during the verdict hot path (held by [`Warden`] in [`AppMatrix`]); the DurableTier mirror is
/// slice 2's persistence layer (write-through + boot rehydrate, the #133 query.log precedent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppMatrixRow {
    /// The owning app's UID (Android UID). Shared-uid apps collapse to one row (rethink §3).
    pub uid: u32,
    /// The per-app firewall mode. Additive-block-only keeps `None | Isolate | Untracked`; the bypass
    /// variants (`BypassUniversal`/`Exclude`/`BypassDnsFirewall`) are recognized but are SKIP signals,
    /// not DENY (they skip a tier, never deny).
    pub mode: AppFirewallMode,
    /// The meteredness block (rethink `ConnectionStatus`), orthogonal to `mode`. `Allow` = no meteredness
    /// block; the others block on the matching network class.
    pub meteredness: NetClass,
    /// Temp-allow expiry (epoch ms). `0` = disabled. RULE19: while `now_ms < temp_allow_until`, the app's
    /// per-app denies are paused (NOT the universal toggles — a lockdown is not paused by a temp-allow).
    pub temp_allow_until: u64,
}

// WIRED: `new` is the single definition of a default-allow row (used by `AppMatrix::grant_temp_allow`,
// so a pause granted to an app with no row inherits any field added later instead of a struct literal
// silently defaulting it); `temp_allow_active` is the single definition of "still paused", now also
// driving `expire_temp_allows` so the sweep and the cascade cannot disagree about what active means.
impl AppMatrixRow {
    /// A per-app row with no special mode, no meteredness block, no temp-allow — the default-allow row.
    pub fn new(uid: u32) -> Self {
        Self {
            uid,
            mode: AppFirewallMode::None,
            meteredness: NetClass::Allow,
            temp_allow_until: 0,
        }
    }

    /// True if this row's temp-allow is currently active — `enabled` (non-zero expiry) AND `now < expiry`.
    /// RULE19 precedence: temp-allow is checked at TIER 3 AFTER universal toggles but BEFORE per-app denies
    /// (a lockdown is NOT paused by a temp-allow; an app-level block IS).
    pub fn temp_allow_active(&self, now_ms: u64) -> bool {
        self.temp_allow_until != 0 && now_ms < self.temp_allow_until
    }
}

/// The per-app matrix — a `HashMap` keyed by UID. RAM-tier during the verdict; a shared-uid app may have
/// one row (the composite-PK collapse — rethink §3's "uid can be shared by multiple packages" folds to
/// one row because the Warden judges by UID, not package). Held by [`Warden`] behind its `&mut self`.
#[derive(Clone, Debug, Default)]
pub struct AppMatrix {
    rows: HashMap<u32, AppMatrixRow>,
}

impl AppMatrix {
    /// An empty matrix (the default-allow baseline — no rows ⇒ the per-app tier abstains).
    pub fn new() -> Self {
        Self::default()
    }

    /// Install/replace a row for `uid`. Overwrites any prior row (the matrix is the source of truth for
    /// the per-app verdict tier).
    pub fn set(&mut self, row: AppMatrixRow) {
        self.rows.insert(row.uid, row);
    }

    /// Remove the row for `uid` (e.g. on app uninstall — the tombstone is a separate concern, slice 2).
    pub fn remove(&mut self, uid: u32) {
        self.rows.remove(&uid);
    }

    /// Look up the row for `uid`. `None` if the app is untracked (the cascade treats untracked as
    /// subject to `UniversalToggles::block_new_apps` + `block_unknown_conns`, TIER 2).
    pub fn get(&self, uid: u32) -> Option<&AppMatrixRow> {
        self.rows.get(&uid)
    }

    /// Iterate the held rows — the control-plane READ for the per-app firewall UI (each row is the
    /// durable user intent for one UID). Order unspecified (the Object sorts for a stable UI).
    pub fn rows(&self) -> impl Iterator<Item = &AppMatrixRow> {
        self.rows.values()
    }

    /// The number of held rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// True if the matrix holds no rows. Convenience predicate; exercised by tests.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// TempAllow TTL sweep (RULE19) — clear the temp-allow pause on every row whose expiry has
    /// WALL-CLOCK-passed `now_ms` (`temp_allow_until != 0 && now_ms >= temp_allow_until`). Returns the
    /// count expired. The datapath holds the epoch-ms clock the verdict hot path lacks, so it drives
    /// this on its control plane; once a row's pause is cleared, that app's per-app denies resume (the
    /// cascade's `check_per_app` no longer short-circuits on a non-zero `temp_allow_until`). The ROW is
    /// kept (mode/meteredness are durable user intent — only the TTL'd pause expires).
    pub fn expire_temp_allows(&mut self, now_ms: u64) -> usize {
        let mut expired = 0usize;
        for row in self.rows.values_mut() {
            // Expressed through the ROW's own predicate rather than re-inlining its condition. The
            // two used to be written out separately — `temp_allow_active` said what "still paused"
            // means and this loop restated its negation — so any future change to the meaning
            // (a grace period, a monotonic clock) would have had to be made in two places, and
            // missing one would leave a pause that the cascade honours and the sweep never clears.
            // Enabled-but-not-active IS exactly "expired".
            if row.temp_allow_until != 0 && !row.temp_allow_active(now_ms) {
                row.temp_allow_until = 0;
                expired += 1;
            }
        }
        expired
    }

    /// GRANT a temp-allow (RULE19 tap-pause) to `uid`, creating a default-allow row if the app has
    /// none.
    ///
    /// This is the capability the matrix was missing: `set` replaces a whole row, so granting a
    /// pause to an app with no existing row previously meant the caller had to compose the row
    /// itself — and composing it by struct literal is how a future field silently defaults to zero.
    /// [`AppMatrixRow::new`] is the one place that decides what an untouched row looks like, so the
    /// grant goes through it and inherits any field added later.
    ///
    /// `expires_at_ms == 0` CLEARS the pause (the disabled encoding), which makes revoke and grant
    /// the same call. Durable user intent (mode / meteredness) on an existing row is preserved.
    pub fn grant_temp_allow(&mut self, uid: u32, expires_at_ms: u64) {
        self.rows
            .entry(uid)
            .or_insert_with(|| AppMatrixRow::new(uid))
            .temp_allow_until = expires_at_ms;
    }

    /// The temp-allow currently held for `uid`, as the standalone [`TempAllow`] value, or `None`
    /// when the app has no row or no pause. Lets a caller ask "is this app paused, and until when?"
    /// without reaching into the row's representation.
    pub fn temp_allow_of(&self, uid: u32) -> Option<TempAllow> {
        let row = self.rows.get(&uid)?;
        if row.temp_allow_until == 0 {
            return None;
        }
        Some(TempAllow::new(uid, row.temp_allow_until))
    }
}

/// The held rule-sets — the armed deny rules the cascade consults at TIER 3 (per-app) and TIER 4
/// (universal). This is the ENGINE-side mirror of the Object's [`WardenRuleSets`](object::WardenRuleSets);
/// the Object installs rule-sets into the engine (via the verdict path) so the cascade can consult them
/// under the engine's single `&mut self` lock (no second mutex on the hot path).
///
/// `Default` only (NOT `Clone`/`Debug`): the inner [`DomainRuleSet`]/[`CidrRuleSet`] are ring-only
/// trie holders the cascade READS by reference; nothing clones or `{:?}`-prints the set, so the
/// derive stays minimal (the Object installs each tier via the granular [`Warden::set_domain_rules`] /
/// [`Warden::set_cidr_rules`] setters — no whole-set clone on the install path).
#[derive(Default)]
pub struct WardenRuleSets {
    /// The BLOCK domain rule-set (per-app TIER 3 + universal TIER 4, by each rule's `uid`).
    pub domain: DomainRuleSet,
    /// The BLOCK/Bypass CIDR rule-set (per-app TIER 3 + universal TIER 4).
    pub cidr: CidrRuleSet,
    /// SLICE 3 — validated GLOB domain patterns (`*.ads.net`, `ad*.tracker.net`), the dnsmasq per-label
    /// glob. A domain rule whose canonical form carries a `*` is parsed + RFC-1123-validated into a
    /// [`pattern::DomainPattern`] and held here; a plain domain flows to the [`domain`](Self::domain)
    /// trie. Consulted by the DNS-answer verdict ([`verdict_loop::apply_dns_verdict`]) ONLY — the
    /// per-connection cascade matches the qname against the trie, so this Vec being empty (the default)
    /// is exactly the prior behavior (zero per-conn regression).
    pub glob_domains: Vec<pattern::DomainPattern>,
}

/// Which cascade tier fired on a deny — the first-match-DENY attribution. Maps 1:1 to the
/// [`WardenStats`] deny-by-tier fields so a deny is attributed to EXACTLY one tier. `Allow`-producing
/// tiers (`SelfExempt`, `Default`) and the cache replay are here for completeness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyTier {
    /// TIER 2 — a universal toggle denied.
    UniversalToggle,
    /// TIER 3 — the per-app matrix denied (mode/meteredness/temp-allow-expiry/per-app rule).
    App,
    /// TIER 4 — a universal domain/CIDR rule denied.
    UniversalRule,
    /// TIER 5 — the `dns_blocked` resolver seam denied.
    Blocklist,
}

// ===========================================================================================

/// THE WARDEN — the per-connection verdict engine. Holds a bounded per-connection decision
/// [`DecisionCache`], the per-app [`AppMatrix`], the [`UniversalToggles`], and the armed
/// [`WardenRuleSets`]. [`verdict`](Warden::verdict) is the single authoritative PURE-FIREWALL cascade
/// composition point (ALLOW-BY-DEFAULT additive-block; the legacy `WardenPolicy` allow-set baseline was
/// removed — denies come only from the matrix / toggles / rule-sets / the `dns_blocked` seam).
pub struct Warden {
    /// The bounded per-connection decision cache (the RAM hot tier).
    cache: DecisionCache,
    /// FAIL-CLOSED posture bit (Nerd / the paranoid): a stored, snapshot-surfaced posture flag. The
    /// legacy policy-absent deny path was removed with `WardenPolicy`, so under the additive-block model
    /// this bit has NO verdict effect today; it is KEPT as the Nerd posture surface
    /// ([`set_fail_closed`](Warden::set_fail_closed) flushes the cache on a flip). Default `false`.
    fail_closed: bool,
    /// AGGREGATE observe-only verdict tallies. Incremented at the verdict resolve point under the same
    /// `&mut self` the cascade already holds — a single in-memory `u64` add, NO IO / NO flash write.
    /// Counts only; never a qname/domain/UID. Cache-HIT replays do NOT re-count.
    stats: WardenStats,
    /// The per-app matrix (TIER 3 per-app DENY). RAM-tier hot copy; the DurableTier mirror + boot
    /// rehydrate is slice 2's persistence layer.
    matrix: AppMatrix,
    /// The 9 universal DENY toggles (TIER 2, the `|||` settings section). Default = all-off (allow-all).
    toggles: UniversalToggles,
    /// The armed deny rule-sets (TIER 3 per-app domain/CIDR + TIER 4 universal domain/CIDR). The
    /// engine-side mirror of the Object's rule-sets; installed by the Object so the cascade consults
    /// them under the engine's single lock.
    rule_sets: WardenRuleSets,
    /// The armed universal rules (the RULE1B/F/3/4/6/7/10/11 toggles expressed as the enum). Drives
    /// TIER 2 alongside [`toggles`](Self::toggles) (the enum carries the RULE identity; the toggles
    /// struct carries the on/off state).
    universal_rules: Vec<UniversalRule>,
    /// The per-app matrix + toggles DURABLE backing (RAM⊗NAND, slice 2). `None` until the datapath wires
    /// the app-private dir via [`bind_durable`](Warden::bind_durable); while `None` the matrix is RAM-only
    /// (fail-safe — an unbound Warden never bricks + never touches disk). Once bound, every control-plane
    /// matrix / toggle mutation GENTLY write-throughs the small state blob — NEVER from the verdict hot
    /// path (the no-hot-path-write law, `runtime_tier.rs:20`).
    durable: Option<crate::runtime_tier::DurableTier>,
    /// ★ THE REVIEW-LOG DIR (checkpoint 99) — where `query-warden.log` is written, INDEPENDENT of
    /// [`durable`](Self::durable).
    ///
    /// The two are separate on purpose. `bind_durable` does two things at once: it names a directory
    /// AND it REHYDRATES persisted matrix state into this Warden. The inline `WARDEN_GATE` Warden
    /// that actually enforces in the resolver (`resolver::arm_warden`) must NOT rehydrate — its
    /// ruleset comes from the arm call and nowhere else, and quietly loading a persisted matrix into
    /// the enforcing instance would change what the firewall blocks as a side effect of wanting a log
    /// file. That is a security-relevant behaviour change disguised as a logging fix, so it is not
    /// what happens here.
    ///
    /// `None` = no review log (the fail-open default, byte-identical to before this existed).
    log_dir: Option<PathBuf>,
    /// W-D (#79) — THE GEO-FAMILY BLOCK SET: ISO-3166 alpha-2 codes (lowercase, 2 bytes) the user has
    /// chosen to block wholesale ("block every IP that resolves to this country"). Consulted in TIER 4
    /// (universal) via [`geoip::country_code_raw`] of the destination — a `HashSet` membership test on a
    /// fixed 2-byte key, cheap under the lock. Empty = no country blocked (the default). This is a
    /// USER-EXPLICIT policy, not an engine auto-attribution: the geoip caveat law forbids the latter
    /// driving a deny, not the former (the user chose it; the block stays best-effort by that same law).
    geo_blocks: HashSet<[u8; 2]>,
}

impl Warden {
    /// Construct an ALLOW-BY-DEFAULT Warden with the default cache cap. No policy — the verdict is a pure
    /// additive-block (denies come only from the matrix / toggles / rule-sets / the `dns_blocked` seam).
    #[allow(clippy::new_without_default)] // an empty Warden is the explicit "armed but no rules" state
    pub fn new() -> Self {
        Self::with_cache_cap(DEFAULT_CACHE_CAP)
    }

    /// Construct with an explicit cache cap (the W3 Expert-tuned RAM-tier knob). Allow-by-default.
    pub fn with_cache_cap(cap: usize) -> Self {
        Warden {
            cache: DecisionCache::new(cap),
            fail_closed: false,
            stats: WardenStats::default(),
            matrix: AppMatrix::new(),
            toggles: UniversalToggles::default(),
            rule_sets: WardenRuleSets::default(),
            universal_rules: Vec::new(),
            durable: None,
            log_dir: None,
            geo_blocks: HashSet::new(),
        }
    }

    /// Set the FAIL-CLOSED posture bit (Nerd). A stored, snapshot-surfaced flag; the additive-block model
    /// has no policy-absent deny path, so it has NO verdict effect today (kept as the Nerd posture
    /// surface). Flushes the cache on a flip (defensive — a posture change never stale-serves).
    pub fn set_fail_closed(&mut self, fail_closed: bool) -> &mut Self {
        self.fail_closed = fail_closed;
        // Flush on a posture change — never stale-serve a verdict computed under the prior posture.
        self.cache.clear();
        self
    }

    /// Install/replace a per-app matrix row (TIER 3). Invalidates the cache (a new per-app rule must
    /// re-decide every connection for that UID).
    pub fn set_app_row(&mut self, row: AppMatrixRow) -> &mut Self {
        self.matrix.set(row);
        self.cache.clear();
        self.write_through_state(); // RAM⊗NAND: gentle control-plane persist (no-op if unbound)
        self
    }

    /// Install/replace the universal toggles (TIER 2). Invalidates the cache.
    pub fn set_universal_toggles(&mut self, toggles: UniversalToggles) -> &mut Self {
        self.toggles = toggles;
        self.cache.clear();
        self.write_through_state(); // RAM⊗NAND: gentle control-plane persist (no-op if unbound)
        self
    }

    /// Install/replace the armed rule-sets (TIER 3 per-app + TIER 4 universal) as ONE unit. Invalidates
    /// the cache. The granular [`set_domain_rules`](Self::set_domain_rules) /
    /// [`set_cidr_rules`](Self::set_cidr_rules) setters are the Object's per-tier install path (a partial
    /// authoring replaces one trie without clobbering the other); this whole-unit install is the engine's
    /// direct seam (host tests + the cascade-truth-table fixtures arm a full set with it).
    pub fn install_rule_sets(&mut self, rule_sets: WardenRuleSets) -> &mut Self {
        self.rule_sets = rule_sets;
        self.cache.clear();
        self
    }

    /// READ-ONLY view of the armed rule-sets — the diagnostics seam behind `warden_rule_sets()`
    /// (lib.rs). Hands out a shared reference so a panel can report SHAPE (empty / fingerprint)
    /// without the ability to author, and without copying a rule body across the FFI boundary.
    pub fn rule_sets(&self) -> &WardenRuleSets {
        &self.rule_sets
    }

    /// READ-ONLY view of the universal (TIER-4) toggle field. Diagnostics seam, see [`Self::rule_sets`].
    pub fn toggles(&self) -> UniversalToggles {
        self.toggles
    }

    /// READ-ONLY view of the per-app matrix. Diagnostics seam, see [`Self::rule_sets`].
    /// GRANT or REVOKE an app's RULE19 temp-allow (tap-pause) without resending its whole row.
    ///
    /// The Object's `WardenAppRow::to_internal` path replaces an entire row, which is right when the
    /// host is pushing complete user intent but wrong for a pause: a caller that only wants to pause
    /// an app must otherwise reconstruct mode and meteredness correctly or silently reset them. This
    /// touches ONLY the pause and preserves durable intent, creating a default-allow row via
    /// [`AppMatrixRow::new`] when the app has none.
    ///
    /// `expires_at_ms == 0` revokes (the disabled encoding), so grant and revoke are one call.
    pub fn set_temp_allow(&mut self, uid: u32, expires_at_ms: u64) -> &mut Self {
        self.matrix.grant_temp_allow(uid, expires_at_ms);
        self
    }

    pub fn matrix(&self) -> &AppMatrix {
        &self.matrix
    }

    /// Install/replace ONLY the BLOCK domain rule-set (TIER 3 per-app domain + TIER 4 universal domain),
    /// leaving the CIDR set untouched. Invalidates the cache. The Object's `install_domain_rules` seam:
    /// re-authoring the domain rules must not clobber the armed CIDR rules.
    pub fn set_domain_rules(&mut self, domain: DomainRuleSet) -> &mut Self {
        self.rule_sets.domain = domain;
        self.cache.clear();
        self.write_through_state(); // RAM⊗NAND (#78 W-C): the armed domain set survives an engine restart.
        self
    }

    /// Install/replace ONLY the BLOCK/Bypass CIDR rule-set, leaving the domain set untouched. Invalidates
    /// the cache. The Object's `install_cidr_rules` seam (the sibling of [`set_domain_rules`]).
    pub fn set_cidr_rules(&mut self, cidr: CidrRuleSet) -> &mut Self {
        self.rule_sets.cidr = cidr;
        self.cache.clear();
        self.write_through_state(); // RAM⊗NAND (#78 W-C): the armed CIDR set survives an engine restart.
        self
    }

    /// W-D (#79) — ADD one CIDR block rule to the armed set WITHOUT clobbering the rest (the ADDITIVE
    /// sibling of [`set_cidr_rules`](Self::set_cidr_rules), which REPLACES the whole set). The inspector's
    /// block-ladder taps this per IP / family: a `/32` host block, a `/24` neighbourhood, up the ladder.
    /// Re-finalizes (re-sorts most-specific-first + re-digests, so the new rule takes effect in priority
    /// order) and flushes the cache. Idempotent — [`CidrRuleSet::insert`] drops an exact duplicate.
    pub fn add_cidr_rule(&mut self, rule: IpRule) -> &mut Self {
        self.rule_sets.cidr.insert(rule);
        self.rule_sets.cidr.finalize();
        self.cache.clear();
        self.write_through_state(); // RAM⊗NAND (#78 W-C): an inspector/settings IP block survives a restart.
        self
    }

    /// W-C (#86) — REMOVE the CIDR rule at flat index `index` (the [`CidrRuleSet::rules`] enumeration
    /// order the settings pane renders) WITHOUT reinstalling the rest — the additive counterpart to the
    /// v4-only `install_cidr_rules` REPLACE wire, which a v6 rule can't round-trip. Re-finalizes (via
    /// [`CidrRuleSet::remove_at`]) and flushes the decision cache on a hit, so the next verdict re-decides
    /// against the shrunk set. Returns `true` iff a rule was dropped (`false` = out-of-range index).
    pub fn remove_cidr_rule_at(&mut self, index: usize) -> bool {
        let removed = self.rule_sets.cidr.remove_at(index);
        if removed {
            self.cache.clear();
            self.write_through_state(); // RAM⊗NAND (#78 W-C): the shrunk set persists (a removed rule stays gone).
        }
        removed
    }

    /// SLICE 3 — install/replace the validated GLOB domain patterns (the dnsmasq per-label glob set the
    /// DNS-answer verdict walks). The Object's `install_domain_rules` validates each incoming rule and
    /// routes the `*`-bearing ones here (the plain ones to [`set_domain_rules`](Self::set_domain_rules)).
    /// Invalidates the decision cache (a new deny set must re-decide). The per-connection cascade does NOT
    /// consult globs, so this never alters a per-conn verdict.
    pub fn set_domain_globs(&mut self, globs: Vec<pattern::DomainPattern>) -> &mut Self {
        self.rule_sets.glob_domains = globs;
        self.cache.clear();
        self.write_through_state(); // RAM⊗NAND (#78 W-C): the armed glob set survives an engine restart.
        self
    }

    /// Remove the per-app matrix row for `uid` (e.g. on app uninstall). Invalidates the cache (the app's
    /// per-app tier reverts to the untracked/default-allow path). The Object's `remove_app_row` seam.
    pub fn remove_app_row(&mut self, uid: u32) -> &mut Self {
        self.matrix.remove(uid);
        self.cache.clear();
        self.write_through_state(); // RAM⊗NAND: gentle control-plane persist (no-op if unbound)
        self
    }

    /// Install/replace the armed universal rules (the RULE enum set driving TIER 2). Invalidates the cache.
    pub fn set_universal_rules(&mut self, rules: Vec<UniversalRule>) -> &mut Self {
        self.universal_rules = rules;
        self.cache.clear();
        self.write_through_state(); // RAM⊗NAND (#78 W-C): the armed universal rule set survives a restart.
        self
    }

    /// W-D (#79) — install/replace the GEO-FAMILY BLOCK SET (TIER 4). Each entry is an ISO-3166 alpha-2
    /// code, lowercased + gated to exactly two ASCII letters (garbage is dropped, never blocks the world).
    /// Invalidates the cache (a new country block must re-decide every connection). The Object's
    /// `set_geo_blocks` seam; the durable mirror rides slice-2's state blob when bound.
    pub fn set_geo_blocks(&mut self, codes: &[String]) -> &mut Self {
        self.geo_blocks = codes
            .iter()
            .filter_map(|c| {
                let b = c.as_bytes();
                if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1].is_ascii_alphabetic() {
                    Some([b[0].to_ascii_lowercase(), b[1].to_ascii_lowercase()])
                } else {
                    None
                }
            })
            .collect();
        self.cache.clear();
        self.write_through_state(); // RAM⊗NAND (#78 W-C): the armed country-block set survives a restart.
        self
    }

    /// W-D (#79) — the armed GEO-family block codes, lowercase, sorted ASC (a stable inspector list,
    /// never a `HashSet`-order shuffle).
    pub fn geo_blocks(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .geo_blocks
            .iter()
            .map(|cc| String::from_utf8_lossy(cc).into_owned())
            .collect();
        out.sort();
        out
    }

    // -------------------------------------------------------------------------------------------
    // SLICE 2 — the RAM⊗NAND DURABLE backing for the per-app matrix + universal toggles + the
    // TempAllow TTL sweep. The matrix + toggles are pure USER intent (no other producer), so THIS
    // facility owns their durability; the rule-sets re-arm on boot from the trust-scored source
    // (slice 5). Write-through is CONTROL-PLANE only (the mutators above + the TTL sweep below);
    // the verdict hot path (`verdict_at`) never touches disk (the no-hot-path-write law).
    // -------------------------------------------------------------------------------------------

    /// Wire the per-app matrix + toggles + (V2) the armed rule-sets to a DURABLE backing dir (RAM⊗NAND,
    /// slice 2 + #78 W-C) AND rehydrate the persisted posture from it. Call ONCE at boot, BEFORE any
    /// matrix/toggle/rule mutation (the rehydrate REPLACES the in-memory toggles + REPOPULATES the matrix
    /// AND re-arms the user's CIDR / domain / glob / universal / geo rule-sets from the persisted blob; a
    /// mutation issued before binding would be clobbered by this restore). After binding, every
    /// control-plane matrix / toggle / rule mutation auto-write-throughs (gentle, best-effort). `dir` is
    /// the app-private `filesDir` (the no-permission NAND tier); `now_ms` the wall clock for the [RULE19]
    /// TempAllow TTL drop. Returns the count of MATRIX ROWS rehydrated (`0` = cold start / absent / corrupt
    /// — a fail-safe empty matrix, NEVER an error; the re-armed rule-set counts are a side effect). The
    /// decision cache is flushed (the restored posture must re-decide every connection).
    pub fn bind_durable(&mut self, dir: PathBuf, now_ms: u64) -> usize {
        let tier = crate::runtime_tier::DurableTier::with_dir(dir, MATRIX_RECORD_NAME);
        let restored = match tier.rehydrate() {
            Some(blob) => self.restore_state(&blob, now_ms),
            None => 0,
        };
        self.durable = Some(tier);
        self.cache.clear();
        restored
    }

    /// TempAllow TTL sweep (RULE19) — expire every per-app temp-allow whose wall-clock expiry has passed
    /// `now_ms`, so an expired pause stops letting that app through (its per-app denies resume). The
    /// datapath calls this on its control plane (the verdict hot path holds no clock — [`ConnFacts`] has
    /// no `now_ms`). On ANY expiry the cache is flushed (an expired pause changes the verdict) AND the
    /// state is gently write-through. Returns the count expired.
    pub fn expire_temp_allows(&mut self, now_ms: u64) -> usize {
        let expired = self.matrix.expire_temp_allows(now_ms);
        if expired > 0 {
            self.cache.clear();
            self.write_through_state();
        }
        expired
    }

    /// GENTLE write-through of the live matrix + toggles to the durable backing (a no-op if unbound).
    /// Best-effort: a [`WriteReject`](crate::runtime_tier::WriteReject) is swallowed (the in-memory tier
    /// is the source of truth; the durable copy is best-effort — the charter's FAIL-SAFE invariant).
    /// CONTROL-PLANE only — called by the matrix/toggle mutators + the TTL sweep AFTER the mutation,
    /// NEVER from [`verdict_at`](Warden::verdict_at).
    fn write_through_state(&self) {
        if let Some(tier) = self.durable.as_ref() {
            let _ = tier.write_through(&self.snapshot_state());
        }
    }

    /// Serialize the per-app matrix + universal toggles + the armed rule-sets into a bounded,
    /// self-describing blob for [`crate::runtime_tier::DurableTier::write_through`]. Format (all big-endian):
    ///
    /// ```text
    /// version:u8 = 2
    /// toggles:u16 (9-bit field)
    /// row_count:u32 | rows[uid:u32, mode:u8, net:u8, temp_allow_until:u64]   // V1 body, MATRIX_ROW_BYTES each
    /// --- V2 rule-set sections (this #78 W-C addition) ---
    /// cidr_count:u32   | cidr[uid:u32, family:u8, net:u128(16B), prefix:u8,
    ///                        port_kind:u8, port_val:u16, proto_kind:u8, proto_val:u8, status:u8]
    /// domain_count:u32 | domain[uid:u32, wildcard:u8, name_len:u16, name_bytes]
    /// glob_count:u32   | glob[src_len:u16, src_bytes]
    /// univ_count:u32   | univ[rule:u8]
    /// geo_count:u32    | geo[cc0:u8, cc1:u8]
    /// ```
    ///
    /// The temp-allow expiry is a WALL-CLOCK epoch (Android `currentTimeMillis`), so a pause that lapses
    /// while the device is OFF is correctly dropped at [`restore_state`]. The rule-sets ARE persisted here
    /// (V2, #78): they are the user's OWN interactive blocks (a settings-add / an inspector block-ladder
    /// tap), NOT a signed source — the blocklist trie is the SEPARATE TIER-5 seam, so this is the (a)
    /// NEW-durable charter path, never a signed-source dump. A DurableTier `TooLarge` reject (an
    /// implausibly huge armed set past the 256 KiB cap) is swallowed by [`write_through_state`] — the
    /// in-memory tier stays the source of truth.
    fn snapshot_state(&self) -> Vec<u8> {
        let rows = &self.matrix.rows;
        let cidr_rules = self.rule_sets.cidr.rules();
        let domain_rules = self.rule_sets.domain.rules();
        let mut out = Vec::with_capacity(7 + rows.len() * MATRIX_ROW_BYTES + cidr_rules.len() * 28);
        out.push(MATRIX_SNAP_VERSION);
        out.extend_from_slice(&self.toggles.to_bits().to_be_bytes());
        out.extend_from_slice(&(rows.len() as u32).to_be_bytes());
        for row in rows.values() {
            out.extend_from_slice(&row.uid.to_be_bytes());
            out.push(app_mode_to_u8(row.mode));
            out.push(net_class_to_u8(row.meteredness));
            out.extend_from_slice(&row.temp_allow_until.to_be_bytes());
        }

        // --- V2: CIDR rule-set (uid ASC, most-specific-first within uid — the finalized enumeration order) ---
        out.extend_from_slice(&(cidr_rules.len() as u32).to_be_bytes());
        for r in &cidr_rules {
            out.extend_from_slice(&r.uid.to_be_bytes());
            let (family, net) = match r.cidr {
                cidr_match::CidrMatch::V4 { net, prefix: _ } => (4u8, net as u128),
                cidr_match::CidrMatch::V6 { net, prefix: _ } => (6u8, net),
            };
            let prefix = match r.cidr {
                cidr_match::CidrMatch::V4 { prefix, .. } => prefix,
                cidr_match::CidrMatch::V6 { prefix, .. } => prefix,
            };
            out.push(family);
            out.extend_from_slice(&net.to_be_bytes());
            out.push(prefix);
            // Port: (kind, val) — kind 0 = Any (val ignored), 1 = Exact(val). Lossless (unlike the
            // finalize fingerprint's lossy 0xFFFF fold).
            match r.port {
                PortSpec::Any => {
                    out.push(0);
                    out.extend_from_slice(&0u16.to_be_bytes());
                }
                PortSpec::Exact(p) => {
                    out.push(1);
                    out.extend_from_slice(&p.to_be_bytes());
                }
            }
            // Proto: (kind, val) — 0 Any, 1 Tcp, 2 Udp, 3 Other(val). Lossless round-trip of the raw byte.
            match r.proto {
                ProtoSpec::Any => {
                    out.push(0);
                    out.push(0);
                }
                ProtoSpec::Tcp => {
                    out.push(1);
                    out.push(0);
                }
                ProtoSpec::Udp => {
                    out.push(2);
                    out.push(0);
                }
                ProtoSpec::Other(p) => {
                    out.push(3);
                    out.push(p);
                }
            }
            out.push(ip_status_to_u8(r.status));
        }

        // --- V2: DOMAIN rule-set (plain trie, uid ASC then domain ASC — the finalized enumeration order) ---
        out.extend_from_slice(&(domain_rules.len() as u32).to_be_bytes());
        for r in &domain_rules {
            out.extend_from_slice(&r.uid.to_be_bytes());
            out.push(r.wildcard as u8);
            let name = r.domain.as_bytes();
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(name);
        }

        // --- V2: GLOB domain patterns (the *-bearing rules the install path routed to the glob set) ---
        out.extend_from_slice(&(self.rule_sets.glob_domains.len() as u32).to_be_bytes());
        for p in &self.rule_sets.glob_domains {
            let src = p.source();
            let bytes = src.as_bytes();
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(bytes);
        }

        // --- V2: UNIVERSAL rules (the TIER-2 enum set) ---
        out.extend_from_slice(&(self.universal_rules.len() as u32).to_be_bytes());
        for r in &self.universal_rules {
            out.push(universal_rule_to_u8(r));
        }

        // --- V2: GEO-family block codes (sorted for a deterministic blob — a HashSet has no order) ---
        let mut geo: Vec<[u8; 2]> = self.geo_blocks.iter().copied().collect();
        geo.sort_unstable();
        out.extend_from_slice(&(geo.len() as u32).to_be_bytes());
        for cc in geo {
            out.push(cc[0]);
            out.push(cc[1]);
        }

        out
    }

    /// Restore the matrix + toggles + (V2) the armed rule-sets from a [`snapshot_state`](Warden::snapshot_state)
    /// blob (handed back by the DurableTier, already integrity-checked + bound-capped). Every field is
    /// length-guarded — a truncated/garbage tail simply STOPS the parse (never an OOB read, never a panic;
    /// whatever fully parsed stays installed). [RULE19] TTL is honored across the reboot: a row whose
    /// temp-allow wall-clock-EXPIRED (`now_ms >= expiry`) is restored with the pause CLEARED (the
    /// resolver-cache wall-clock-drop discipline, `cache.rs:682`); an unknown mode/net byte maps to the
    /// inert default (fail-safe, never an over-block).
    ///
    /// BACKWARD-compatible: a V1 blob (matrix + toggles only) rehydrates its matrix + toggles and leaves the
    /// rule-sets cold (empty) — byte-identical to pre-V2 behavior. A V2 blob additionally re-arms the CIDR /
    /// domain / glob / universal / geo rule-sets the user had armed (each family fail-safe: an unknown CIDR
    /// family, a non-UTF-8 domain, a malformed glob, an unknown universal byte, or a non-alpha country code
    /// is DROPPED, never guessed). A foreign / forward (`> 2`) version is a cold start (returns `0`).
    /// Returns the count of MATRIX rows admitted (the rule-set counts are a side effect — the matrix-row
    /// count is the boot-log metric [`bind_durable`] surfaces).
    fn restore_state(&mut self, payload: &[u8], now_ms: u64) -> usize {
        let mut cur = payload;
        let Some((&ver, rest)) = cur.split_first() else {
            return 0;
        };
        if ver != MATRIX_SNAP_VERSION_MATRIX_ONLY && ver != MATRIX_SNAP_VERSION {
            return 0; // a foreign / forward-version blob is a cold start, never a guessed parse.
        }
        cur = rest;
        let Some(bits) = read_u16_be(&mut cur) else {
            return 0;
        };
        self.toggles = UniversalToggles::from_bits(bits);
        let Some(count) = read_u32_be(&mut cur) else {
            return 0;
        };
        let mut restored = 0usize;
        for _ in 0..count {
            let Some(uid) = read_u32_be(&mut cur) else {
                break;
            };
            let Some(mode_b) = take_one(&mut cur) else {
                break;
            };
            let Some(net_b) = take_one(&mut cur) else {
                break;
            };
            let Some(mut expiry) = read_u64_be(&mut cur) else {
                break;
            };
            if expiry != 0 && now_ms >= expiry {
                expiry = 0; // the TTL lapsed while the device was OFF ⇒ the pause is dropped.
            }
            self.matrix.set(AppMatrixRow {
                uid,
                mode: app_mode_from_u8(mode_b),
                meteredness: net_class_from_u8(net_b),
                temp_allow_until: expiry,
            });
            restored += 1;
        }

        // --- V2 rule-set sections. A V1 blob has no more bytes; the guard skips this entirely. Any truncation
        // mid-section breaks out of the labeled block — fully-parsed sections stay installed, the tail drops. ---
        if ver >= MATRIX_SNAP_VERSION {
            'v2: {
                // CIDR — build a fresh set, insert each rule, finalize once (sorts most-specific-first +
                // digests, as the arm path does). An unknown family byte drops that one rule (fail-safe).
                let Some(n) = read_u32_be(&mut cur) else {
                    break 'v2;
                };
                let mut cidr = CidrRuleSet::new();
                for _ in 0..n {
                    let Some(uid) = read_u32_be(&mut cur) else {
                        break 'v2;
                    };
                    let Some(family) = take_one(&mut cur) else {
                        break 'v2;
                    };
                    let Some(net) = read_u128_be(&mut cur) else {
                        break 'v2;
                    };
                    let Some(prefix) = take_one(&mut cur) else {
                        break 'v2;
                    };
                    let Some(port_kind) = take_one(&mut cur) else {
                        break 'v2;
                    };
                    let Some(port_val) = read_u16_be(&mut cur) else {
                        break 'v2;
                    };
                    let Some(proto_kind) = take_one(&mut cur) else {
                        break 'v2;
                    };
                    let Some(proto_val) = take_one(&mut cur) else {
                        break 'v2;
                    };
                    let Some(status_b) = take_one(&mut cur) else {
                        break 'v2;
                    };
                    let matched = match family {
                        4 => cidr_match::CidrMatch::V4 {
                            net: net as u32,
                            prefix,
                        },
                        6 => cidr_match::CidrMatch::V6 { net, prefix },
                        _ => continue, // an unknown family byte — drop this rule (fail-safe).
                    };
                    let port = if port_kind == 1 {
                        PortSpec::Exact(port_val)
                    } else {
                        PortSpec::Any
                    };
                    let proto = match proto_kind {
                        1 => ProtoSpec::Tcp,
                        2 => ProtoSpec::Udp,
                        3 => ProtoSpec::Other(proto_val),
                        _ => ProtoSpec::Any,
                    };
                    cidr.insert(IpRule {
                        uid,
                        cidr: matched,
                        port,
                        proto,
                        status: ip_status_from_u8(status_b),
                    });
                }
                cidr.finalize();
                self.rule_sets.cidr = cidr;

                // DOMAIN — plain reversed-label trie. A non-UTF-8 name drops that one rule (fail-safe).
                let Some(n) = read_u32_be(&mut cur) else {
                    break 'v2;
                };
                let mut domain = DomainRuleSet::default();
                for _ in 0..n {
                    let Some(uid) = read_u32_be(&mut cur) else {
                        break 'v2;
                    };
                    let Some(wildcard_b) = take_one(&mut cur) else {
                        break 'v2;
                    };
                    let Some(name_len) = read_u16_be(&mut cur) else {
                        break 'v2;
                    };
                    let Some(name_bytes) = read_bytes(&mut cur, name_len as usize) else {
                        break 'v2;
                    };
                    if let Ok(name) = String::from_utf8(name_bytes) {
                        domain.insert(DomainRule {
                            domain: name.into(),
                            uid,
                            wildcard: wildcard_b != 0,
                        });
                    }
                }
                self.rule_sets.domain = domain;

                // GLOB — re-validate each source string through the SAME gate the arm path uses; a
                // malformed pattern drops (fail-safe, never a guessed glob).
                let Some(n) = read_u32_be(&mut cur) else {
                    break 'v2;
                };
                let mut globs: Vec<pattern::DomainPattern> = Vec::new();
                for _ in 0..n {
                    let Some(src_len) = read_u16_be(&mut cur) else {
                        break 'v2;
                    };
                    let Some(src_bytes) = read_bytes(&mut cur, src_len as usize) else {
                        break 'v2;
                    };
                    if let Ok(src) = String::from_utf8(src_bytes) {
                        if let Ok(p) = pattern::validate_pattern(&src) {
                            globs.push(p);
                        }
                    }
                }
                self.rule_sets.glob_domains = globs;

                // UNIVERSAL — the TIER-2 enum set. An unknown byte drops (fail-safe).
                let Some(n) = read_u32_be(&mut cur) else {
                    break 'v2;
                };
                let mut univ: Vec<UniversalRule> = Vec::new();
                for _ in 0..n {
                    let Some(b) = take_one(&mut cur) else {
                        break 'v2;
                    };
                    if let Some(r) = universal_rule_from_u8(b) {
                        univ.push(r);
                    }
                }
                self.universal_rules = univ;

                // GEO — 2-letter ISO codes, re-gated to lowercase ASCII letters (the set_geo_blocks law).
                let Some(n) = read_u32_be(&mut cur) else {
                    break 'v2;
                };
                let mut geo: HashSet<[u8; 2]> = HashSet::new();
                for _ in 0..n {
                    let Some(a) = take_one(&mut cur) else {
                        break 'v2;
                    };
                    let Some(b) = take_one(&mut cur) else {
                        break 'v2;
                    };
                    if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() {
                        geo.insert([a.to_ascii_lowercase(), b.to_ascii_lowercase()]);
                    }
                }
                self.geo_blocks = geo;
            }
        }

        restored
    }

    /// THE VERDICT FN — the single authoritative PURE-FIREWALL cascade composition point.
    ///
    /// REWORKED (slice 1 + the policy removal): the blocklist `Matcher` parameter is RETIRED and the
    /// allow-set baseline is GONE. The cascade is a deterministic first-match-DENY over the matrix +
    /// toggles + rule-sets the caller installed; ALLOW-BY-DEFAULT (no policy baseline — every connection
    /// allows unless a deny tier fires). The `dns_blocked` signal enters at TIER 5 as a boolean on
    /// [`ConnFacts`] (the narrow resolver seam). The cache epoch
    /// ([`crate::blocklist::installed_fingerprint`]) gates the cache so a re-arm invalidates lazily (the
    /// rule-sets are the deny source; the epoch is the cache-coherence signal).
    pub fn verdict(&mut self, conn: &ConnFacts) -> Verdict {
        self.verdict_at(conn, crate::blocklist::installed_fingerprint())
    }

    /// THE DNS-ANSWER VERDICT (slice 3) — the PRODUCER of the TIER-5 `dns_blocked` seam. Judges a
    /// RESOLVED DNS answer (`name` + its resolved `addrs`) against the armed UNIVERSAL block rules: the
    /// plain-domain trie, the validated glob patterns (the dnsmasq per-label glob), and the family-aware
    /// CIDR blocks (v4 + v6, [`cidr_match`]). Returns [`Verdict::Deny`] when the name or ANY resolved
    /// address matches — the DNS resolver maps that to the `ConnFacts::dns_blocked` flag the
    /// per-connection cascade then consumes at TIER 5 (the single narrow seam, Anti-Venom §5d).
    ///
    /// DISTINCT from [`verdict`](Warden::verdict): this is the DNS-RESOLUTION verdict (does this resolved
    /// name+addr deny?), `&self` + side-effect-free (NO cache, NO stats, NO clock) — an ADVISORY producer
    /// feeding the real per-conn gate, never itself the per-conn authority. The cascade's per-conn cache
    /// and tallies belong to the CONNECTION verdict; this answer verdict leaves them untouched.
    pub fn dns_verdict(&self, name: &str, addrs: &[IpAddr]) -> Verdict {
        if self.dns_outcome(name, addrs).is_deny() {
            Verdict::Deny
        } else {
            Verdict::Allow
        }
    }

    /// The shared DNS-answer outcome (slice 3 + 6) — runs the pure [`verdict_loop::apply_dns_verdict`] over
    /// the armed UNIVERSAL rules and returns the FULL [`verdict_loop::DnsVerdict`] (carrying the deny
    /// REASON). The binary [`dns_verdict`](Self::dns_verdict) maps it to [`Verdict`]; the logged
    /// [`dns_verdict_logged`](Self::dns_verdict_logged) also writes that reason to `query-warden.log`. Pure
    /// (NO cache, NO stats, NO clock, NO IO) — the producer-half invariant.
    fn dns_outcome(&self, name: &str, addrs: &[IpAddr]) -> verdict_loop::DnsVerdict {
        let cidr_blocks = self.rule_sets.cidr.universal_blocks();
        verdict_loop::apply_dns_verdict(
            name,
            addrs,
            &self.rule_sets.domain,
            &self.rule_sets.glob_domains,
            &cidr_blocks,
        )
    }

    /// THE LOGGED DNS-ANSWER VERDICT (slice 6) — [`dns_verdict`](Self::dns_verdict) PLUS one human-legible
    /// line appended to the Warden's per-pillar `query-warden.log` (the #133 [`crate::log_tier`] substrate,
    /// the `query.log` / `query-fortress.log` precedent). The verdict computation is the SAME pure producer;
    /// the log write is FAIL-OPEN and OFF the per-connection hot path (this is the explicit review-channel
    /// seam — call it for the Socio's verdict feed, the plain [`dns_verdict`] for the hot resolver path).
    /// The line lands in the Warden's bound durable dir ([`query_warden_log_path`](Self::query_warden_log_path));
    /// an UNBOUND Warden is a silent no-op (no dir → no log, NEVER an error). `now_ms` is the injected wall
    /// clock (the warden clock-injection invariant). A no-op or failed log NEVER changes the returned verdict.
    pub fn dns_verdict_logged(&self, name: &str, addrs: &[IpAddr], now_ms: u64) -> Verdict {
        let outcome = self.dns_outcome(name, addrs);
        let verdict = if outcome.is_deny() {
            Verdict::Deny
        } else {
            Verdict::Allow
        };
        if let Some(path) = self.query_warden_log_path() {
            let reason = match outcome {
                verdict_loop::DnsVerdict::Deny(r) => Some(r),
                verdict_loop::DnsVerdict::Allow => None,
            };
            log::append_dns_verdict(&path, now_ms, verdict, name, addrs, reason);
        }
        verdict
    }

    /// The on-disk path of the per-pillar `query-warden.log` — a sibling of the matrix-state blob under the
    /// Warden's app-private durable dir (slice 2's [`bind_durable`](Self::bind_durable)). `None` when the
    /// Warden is UNBOUND (RAM-only; the verdict still works, it simply writes no review log — the fail-safe).
    fn query_warden_log_path(&self) -> Option<PathBuf> {
        // The explicit review-log bind wins; the durable-derived path stays as the fallback so every
        // caller that only ever called `bind_durable` keeps the exact path it had.
        if let Some(dir) = self.log_dir.as_ref() {
            return Some(dir.join(log::QUERY_WARDEN_LOG_NAME));
        }
        self.durable
            .as_ref()
            .map(|tier| tier.path().with_file_name(log::QUERY_WARDEN_LOG_NAME))
    }

    /// Bind ONLY the review-log directory — no rehydrate, no durable tier, no state change of any
    /// kind. This is what the enforcing inline Warden uses so `query-warden.log` can exist without
    /// the firewall silently inheriting a persisted matrix. See [`log_dir`](Self::log_dir).
    pub fn bind_log_dir(&mut self, dir: PathBuf) {
        self.log_dir = Some(dir);
    }

    /// Testable core of [`verdict`](Warden::verdict): the `epoch` is injected so tests need no
    /// process-global matcher. The cascade (slice 1 rework):
    ///
    /// - TIER 0 — cache replay (O(1) on a repeat).
    /// - TIER 1 — self-exempt (the resolver uid always passes; reserved for the datapath, no-op here).
    /// - TIER 2 — universal toggles (lockdown, block-new-apps, block-metered, device-lock, block-
    ///   background, block-http, block-udp-ntp, block-dns-bypass, block-unknown-conns).
    /// - TIER 3 — per-app matrix (temp-allow wins; then mode Isolate; then meteredness block; then per-
    ///   app domain/CIDR rules).
    /// - TIER 4 — universal domain/CIDR rules (skipped for `BypassUniversal`).
    /// - TIER 5 — `dns_blocked` resolver seam (skipped for `BypassDnsFirewall`).
    /// - TIER 6 — default ALLOW (RULE0); FAIL-CLOSED on engine exception.
    fn verdict_at(&mut self, conn: &ConnFacts, epoch: u64) -> Verdict {
        // CLONE-FREE hit path (D20): the borrowed conn hashes into the cache directly; the owned CacheKey
        // is minted ONLY on a miss (inside `cache.insert`), never on a repeat verdict.
        if let Some(v) = self.cache.get(conn, epoch) {
            return v;
        }

        // ALLOW-BY-DEFAULT: there is NO allow-set baseline gate (the legacy `WardenPolicy` 5-set head-gate
        // + the policy-absent fail-closed short-circuit were removed). The cascade flows straight into the
        // additive deny tiers (TIER 2 toggles → TIER 3 matrix → TIER 4 universal rules → TIER 5
        // dns_blocked → TIER 6 default ALLOW); `fail_closed` is an inert posture bit (no verdict effect).

        let app_row = self.matrix.get(conn.uid).cloned();
        let app_mode = app_row
            .as_ref()
            .map(|r| r.mode)
            .unwrap_or(AppFirewallMode::None);

        // TIER 2 — universal toggles (the 9 global DENY switches). Precedence per Anti-Venom §2.
        if let Some(tier) = self.check_universal_toggles(conn, app_mode) {
            self.record_deny(tier);
            let v = Verdict::Deny;
            self.cache.insert(conn, v, epoch);
            return v;
        }

        // TIER 3 — per-app matrix (temp-allow wins, then mode/meteredness, then per-app rules).
        if let Some(tier) = self.check_per_app(conn, &app_row) {
            self.record_deny(tier);
            let v = Verdict::Deny;
            self.cache.insert(conn, v, epoch);
            return v;
        }

        // TIER 4 — universal domain/CIDR rules (skipped for BypassUniversal).
        if app_mode != AppFirewallMode::BypassUniversal {
            if let Some(tier) = self.check_universal_rules(conn) {
                self.record_deny(tier);
                let v = Verdict::Deny;
                self.cache.insert(conn, v, epoch);
                return v;
            }
        }

        // TIER 5 — dns_blocked resolver seam (skipped for BypassDnsFirewall).
        if app_mode != AppFirewallMode::BypassDnsFirewall && conn.dns_blocked {
            self.record_deny(DenyTier::Blocklist);
            let v = Verdict::Deny;
            self.cache.insert(conn, v, epoch);
            return v;
        }

        // TIER 6 — default ALLOW (RULE0).
        self.stats.allow += 1;
        let v = Verdict::Allow;
        self.cache.insert(conn, v, epoch);
        v
    }

    /// TIER 2 — consult the universal toggles. Returns the deny tier if a toggle fires, `None` otherwise.
    /// The toggle state lives in [`self.toggles`](Warden::toggles); the RULE identity (which RethinkDNS
    /// rule) lives in [`self.universal_rules`](Warden::universal_rules) — a toggle fires only if BOTH its
    /// on/off bit is set AND its RULE is armed (defense-in-depth: an unarmed toggle is inert even if the
    /// bit is set, so a stale settings write cannot deny alone).
    fn check_universal_toggles(
        &self,
        conn: &ConnFacts,
        app_mode: AppFirewallMode,
    ) -> Option<DenyTier> {
        let armed = |rule: UniversalRule| self.universal_rules.contains(&rule);
        let t = self.toggles;
        // RULE11 — lockdown (block everything).
        if t.lockdown && armed(UniversalRule::Lockdown) {
            return Some(DenyTier::UniversalToggle);
        }
        // RULE1B — block apps not yet seen (gated by Untracked mode).
        if t.block_new_apps
            && armed(UniversalRule::BlockNewApps)
            && app_mode == AppFirewallMode::Untracked
        {
            return Some(DenyTier::UniversalToggle);
        }
        // RethinkDNS step 3 — block unknown/untracked UIDs.
        if t.block_unknown_conns && app_mode == AppFirewallMode::Untracked {
            return Some(DenyTier::UniversalToggle);
        }
        // RULE1F — block metered (cellular/roaming) traffic.
        if t.block_metered
            && armed(UniversalRule::BlockMetered)
            && (conn.net == NetworkType::Gsm || conn.net == NetworkType::Roaming)
        {
            return Some(DenyTier::UniversalToggle);
        }
        // RULE3 — device-lock (the caller sets the toggle from the screen-off signal).
        if t.device_lock && armed(UniversalRule::DeviceLock) {
            return Some(DenyTier::UniversalToggle);
        }
        // RULE4 — block background-data (the caller sets the toggle from the foreground signal).
        if t.block_background && armed(UniversalRule::BlockBackground) {
            return Some(DenyTier::UniversalToggle);
        }
        // RULE10 — block HTTP (port 80).
        if t.block_http && armed(UniversalRule::BlockHttp) && conn.dport == 80 {
            return Some(DenyTier::UniversalToggle);
        }
        // RULE6 — block UDP-NTP (port 123 / UDP).
        if t.block_udp_ntp
            && armed(UniversalRule::BlockUdpNtp)
            && conn.proto == 17
            && conn.dport == 123
        {
            return Some(DenyTier::UniversalToggle);
        }
        // RULE7 — block DNS bypass (a query with no qname trying to skip the resolver).
        if t.block_dns_bypass && armed(UniversalRule::BlockDnsBypass) && conn.qname.is_none() {
            return Some(DenyTier::UniversalToggle);
        }
        None
    }

    /// TIER 3 — consult the per-app matrix + per-app rules. Returns the deny tier if a per-app deny
    /// fires, `None` otherwise. RULE19 temp-allow is checked FIRST (it pauses per-app denies, NOT the
    /// universal toggles — a lockdown is not paused by a temp-allow; that was TIER 2 above).
    fn check_per_app(&self, conn: &ConnFacts, app_row: &Option<AppMatrixRow>) -> Option<DenyTier> {
        // The MATRIX-ROW axis (mode / meteredness / temp-allow) applies ONLY when the app HAS a row; the
        // per-app DOMAIN/CIDR rules below apply by uid REGARDLESS of a row (a CustomDomain/CustomIp rule is
        // a rule independent of the app's firewallStatus — RethinkDNS §3/§4). When a row's temp-allow is
        // active it pauses ALL of this app's per-app denies (matrix AND rules); the NEXT cascade tier
        // (TIER 4 universal) still applies.
        if let Some(row) = app_row.as_ref() {
            // RULE19 — temp-allow. `now_ms` is not available on ConnFacts (no clock on the hot path); the
            // Object/datapath layer clears `temp_allow_until` to 0 once the wall-clock passes the expiry,
            // so a non-zero value here means "still active". An active temp-allow pauses this app's per-app
            // denies (matrix + per-app rules) — the cascade falls through to TIER 4.
            if row.temp_allow_until != 0 {
                return None;
            }
            // RULE1G — isolate: the app may only talk the resolver + LAN (net==Lan heuristic; the resolver
            // uid is self-exempt at TIER 1).
            if row.mode == AppFirewallMode::Isolate && conn.net != NetworkType::Lan {
                return Some(DenyTier::App);
            }
            // RULE1/1D/1E — meteredness block.
            if row.meteredness != NetClass::Allow && meteredness_blocks(row.meteredness, conn.net) {
                return Some(DenyTier::App);
            }
        }
        // RULE2E — per-app domain rule (BLOCK only). SCOPED to the uid's own trie (the universal tier is
        // TIER 4, below) so a universal rule is NOT mis-attributed to the per-app tier. Applies whether or
        // not the app has a matrix row.
        if let Some(qname) = conn.qname.as_deref() {
            if self.rule_sets.domain.matches_app(conn.uid, qname) {
                return Some(DenyTier::App);
            }
        }
        // RULE2 — per-app CIDR rule (BLOCK only). SCOPED to the uid's own bucket. Family-aware (A3):
        // a v4 AND a v6 daddr are both judged — the old v4-only gate silently abstained on v6, so a
        // blocked app could slip out over IPv6.
        if let Some(CidrHit::Block) =
            self.rule_sets
                .cidr
                .lookup_app(conn.uid, conn.daddr, conn.dport, conn.proto)
        {
            return Some(DenyTier::App);
        }
        None
    }

    /// TIER 4 — consult the universal domain/CIDR rules (UID_UNIVERSAL tier). Returns the deny tier if a
    /// universal deny fires, `None` otherwise.
    fn check_universal_rules(&self, conn: &ConnFacts) -> Option<DenyTier> {
        // RULE2H — universal domain block (the universal trie ONLY).
        if let Some(qname) = conn.qname.as_deref() {
            if self.rule_sets.domain.matches_universal(qname) {
                return Some(DenyTier::UniversalRule);
            }
        }
        // RULE2D — universal CIDR block (the universal bucket ONLY). Family-aware (A3): v4 AND v6
        // daddrs are both judged.
        if let Some(CidrHit::Block) =
            self.rule_sets
                .cidr
                .lookup_universal(conn.daddr, conn.dport, conn.proto)
        {
            return Some(DenyTier::UniversalRule);
        }
        // W-D (#79) — THE GEO-FAMILY BLOCK (universal, user-explicit). Skip the geoip probe entirely when
        // no country is blocked (the common case — one branch, zero table hits). Otherwise resolve the
        // destination's country alloc-free ([`geoip::country_code_raw`]) and deny on membership. Best-
        // effort by the caveat law: a mislabeled IP is the user's known trade-off, never an engine guess.
        if !self.geo_blocks.is_empty() {
            if let Some(cc) = geoip::country_code_raw(conn.daddr) {
                if self.geo_blocks.contains(&cc) {
                    return Some(DenyTier::UniversalRule);
                }
            }
        }
        None
    }

    /// Record a deny at `tier` — increments the deny + the tier-specific counter (the first-match
    /// attribution invariant: a deny is attributed to EXACTLY one tier).
    fn record_deny(&mut self, tier: DenyTier) {
        self.stats.deny += 1;
        match tier {
            DenyTier::UniversalToggle => self.stats.deny_by_universal_toggle += 1,
            DenyTier::App => self.stats.deny_by_app += 1,
            DenyTier::UniversalRule => self.stats.deny_by_universal_rule += 1,
            DenyTier::Blocklist => self.stats.deny_by_blocklist += 1,
        }
    }

    /// The aggregate observe-only verdict tallies — a cheap by-value copy of the `u64` counters.
    /// AGGREGATE counts only; never a qname/domain/UID. The dashboard card reads these via the
    /// [`stats_json`](Warden::stats_json) serializer behind the `nativeWardenStats` JNI export. A
    /// freshly-constructed / disarmed Warden returns all-zero (the inert "off" the card shows honestly).
    pub fn stats(&self) -> WardenStats {
        self.stats
    }

    /// Serialize the aggregate tallies into the tiny hand-built JSON the JNI export hands Kotlin — the
    /// EXACT shape/style of `resolver::stats()` (no serde): a flat object of `u64` counts plus a
    /// `configured` bool. NO qname/domain/UID ever — counts only (the T20 "no qname ever" law). `armed`
    /// here means a policy is loaded into THIS Warden; the global-singleton-`None` (disarmed) case is the
    /// caller's `unavailable`/zeroed JSON in lib.rs (this method is only reached on a live Warden).
    ///
    /// REWORKED (slice 1): the keys now reflect the tier attribution (deny_by_universal_toggle /
    /// deny_by_app / deny_by_universal_rule / deny_by_blocklist). The `deny_by_blocklist` key is KEPT
    /// (dashboard label continuity) but its value is now TIER 5 only (the dns_blocked seam).
    pub fn stats_json(&self) -> String {
        let s = &self.stats;
        format!(
            "{{\"configured\":true,\"allow\":{},\"deny\":{},\"deny_by_universal_toggle\":{},\"deny_by_app\":{},\"deny_by_universal_rule\":{},\"deny_by_blocklist\":{}}}",
            s.allow,
            s.deny,
            s.deny_by_universal_toggle,
            s.deny_by_app,
            s.deny_by_universal_rule,
            s.deny_by_blocklist,
        )
    }
}

// ===========================================================================================
// W-A — the PURE-ADDITIVE rule-set layer (Warden rebuild wave A, atomic-serial this wave).
// ===========================================================================================
//
// GROUND-TRUTH — sources mirrored (file:line, never doctrine):
//   * rethink-app-main `service/FirewallRuleset.kt` RULE1–RULE19 — the universal-rule enum +
//     the per-app IP/domain rule models (TRUST arms dropped per the REWORKED design).
//   * rethink-app-main `service/BraveVPNService.kt:667-919` — the firewall() precedence chain
//     (W-B reproduces the compose; W-A only owns the rule TYPES + their pure-Rust matchers).
//   * rethink-app-main `database/CustomIp.kt:33-50` — the per-app IP/CIDR rule primary key
//     (uid, ipAddress, port, protocol, status, wildcard, ruleType) → [`IpRule`]/[`CidrRuleSet`].
//   * rethink-app-main `database/CustomDomain.kt:25-36` — the per-app domain rule (domain, uid,
//     status, type) → [`DomainRule`]/[`DomainRuleSet`] (the reversed-label trie mirrors
//     `blocklist.rs:67-208` byte-for-byte; it reuses [`crate::blocklist`]'s `normalize` SHAPE —
//     a private copy lives here to keep the rule-set module hermetic, see [`normalize_rule`]).
//   * rethink-app-main `AppInfo.kt:32/36/44-45` — `firewallStatus`/`connectionStatus`/
//     `tempAllowEnabled`/`tempAllowExpiryTime` → [`AppFirewallMode`]/[`NetClass`]/[`TempAllow`].
//   * NO dnsmasq absorb — the Warden is a pure RethinkDNS firewall (Socio 2026-06-27: "dont transcend
//     them inside the firewall"). Rebind / bogus-priv / bogus-nxdomain / ignore-address all live in
//     the Dnsmasq pillar (P12), NOT here. A stale-direction dnsmasq leak (CidrAction + BlockDnsRebind)
//     was stripped in the W-A SEAL-LOOP.
//
// THE LAW (REWORKED design §2 — TRUST trashed). Every `WHITELIST` / `TRUST` arm of RethinkDNS's
// rule models is DROPPED on port — trust is blocklist scoring, a SEPARATE pillar. Only `BLOCK`
// and the bypass/exempt arms survive. There is NO trust field, NO trust weight, NO allow-bypass
// anywhere in this layer. The bypass arms (`RULE8` bypass-universal, `RULE1H` bypass-dns-firewall,
// `RULE2C` IP-wildcard bypass) are modeled as [`AppFirewallMode`]/[`IpStatus`] BYPASS FLAGS —
// "skip the universal tier" — NOT as trust.
//
// SCOPE (W-A only). PURE-ADDITIVE: these types + their host-tested pure-Rust matchers + the
// unit tests. ZERO touch of [`Warden::verdict`], [`WardenPolicy`], or the JNI
// surface, or any existing fn. W-B wires these into the verdict compose (reproducing the
// RULE0–RULE19 precedence, TRUST arms removed). The public surface carries
// `#[cfg_attr(not(test), allow(dead_code))]` — the crate's dead-code-until-wired idiom
// (`blocklist.rs:235`) so clippy `-D warnings` stays clean in the non-test build until W-B.
//
// `#![forbid(unsafe_code)]` honored: the trie is plain `HashMap<Box<str>, Node>` (no bit-ptr
// tricks), CIDR is host-order `u32` + prefix `0..=32` (`warden_cidr_match` contract, lib.rs:592).
// Ring-only, allocation-light (mirrors the blocklist trie hot path — `&str` walks, one `Box<str>`
// per node at insert time, no `HashSet<String>`).

/// One trie node for the domain rule-set — the `blocklist.rs:67-78` shape verbatim (TLD-first label
/// keys, `terminal` marks "this zone is a rule terminal"). Allocation-light by construction: one
/// `Box<str>` per distinct label, shared across all rules that traverse it.
#[derive(Default)]
struct RuleNode {
    children: HashMap<Box<str>, RuleNode>,
    /// This label path is a rule terminal — every domain at or beneath it is matched by the set.
    terminal: bool,
}

impl RuleNode {
    /// Visit every canonical terminal domain (top-down; terminals are leaves so subsumed descendants
    /// never appear). Depth is bounded by [`MAX_RULE_LABELS`], so this recursion cannot overflow the
    /// stack. Mirrors `blocklist.rs:84-97`.
    fn walk_terminals(&self, suffix: &str, f: &mut impl FnMut(&str)) {
        if self.terminal {
            f(suffix);
            return;
        }
        for (label, child) in &self.children {
            let next = if suffix.is_empty() {
                label.to_string()
            } else {
                format!("{}.{}", label, suffix)
            };
            child.walk_terminals(&next, f);
        }
    }
}

/// DNS bounds — cap trie depth so recursion cannot overflow the stack (`blocklist.rs:36-37`).
const MAX_RULE_NAME_LEN: usize = 253;
const MAX_RULE_LABELS: usize = 127;

/// Canonicalize a domain for rule matching: trim, drop trailing dot AND empty labels, full-Unicode
/// lowercase (DNS is case-insensitive; `to_lowercase` folds É→é — `blocklist.rs:354-361`). A private
/// copy keeps the rule-set module hermetic (it does not reach into the blocklist module's private
/// `normalize`); the SHAPE is identical so a rule and a blocklist entry describing the same zone
/// canonicalize byte-identically.
fn normalize_rule(domain: &str) -> String {
    let lowered = domain.trim().trim_end_matches('.').to_lowercase();
    lowered
        .split('.')
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

/// FNV-1a 64-bit over the canonical terminal set — a fast, non-cryptographic content digest
/// (`blocklist.rs:364-371`). XOR-folded over the sorted terminal set so it is order- and format-
/// independent: two authorings of the same rule-set produce the same digest (the W3 epoch-gated
/// cache + the W6 "rule-set changed" dashboard card depend on this).
fn rule_fnv1a(s: &str) -> u64 {
    rule_fnv1a_bytes(s.as_bytes())
}

/// FNV-1a 64-bit over RAW bytes — the byte-oriented core of [`rule_fnv1a`]. Used directly for the CIDR
/// fingerprint's `(uid, net)` fold (D39): those are RAW `to_le_bytes()` (any octet ≥ `0x80`), so routing
/// them through `str::from_utf8` (as the prior `rule_fnv1a(from_utf8(&buf).unwrap_or(""))` did) SILENTLY
/// degraded to hashing `""` for most real-world IPs — the digest IGNORED ip+prefix, so two CIDR sets
/// differing only in a high-octet IP collided (the "rule-set changed" signal could report "unchanged").
fn rule_fnv1a_bytes(b: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in b {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A single domain rule — a (domain, uid, wildcard) triple with BLOCK-only status
/// (`CustomDomain.kt:25-36`, `status` ∈ {BLOCK, NONE} after TRUST is trashed). `wildcard = true`
/// means "this rule matches the apex AND every subdomain" (the `*.domain` form); `false` is an
/// EXACT apex-only match. The rule-set trie subsumes both by setting the apex node `terminal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainRule {
    /// The canonical (lowercased, dot-trimmed) domain — the rule's apex.
    pub domain: Box<str>,
    /// Owning app UID; `UID_UNIVERSAL` (0) = the universal tier (RethinkDNS global-domain table).
    pub uid: u32,
    /// `true` → apex + every subdomain (the `*.domain` form, `CustomDomain.kt:31` DOMAIN-WILDCARD).
    pub wildcard: bool,
}

/// Sentinel UID marking a UNIVERSAL domain rule (RethinkDNS's global-domain table, consulted at
/// the universal tier — distinct from a per-app `CustomDomain` row). Apps and universal rules
/// share one [`DomainRuleSet`] keyed on `(uid, domain)`; `UID_UNIVERSAL` is the "everybody" slot.
pub const UID_UNIVERSAL: u32 = 0;

/// A BLOCK-only set of wildcard domain rules, mirrored on the `blocklist.rs` trie style. Per-app
/// rules and universal rules coexist: the set is keyed on `(uid, apex)` so a lookup for
/// `(uid, qname)` answers "does a rule for THIS app (or universal) match this domain?". Insert is
/// idempotent and canonical (a parent apex subsumes its children — `blocklist.rs:144-161`).
///
/// BLOCK-only by REWORKED-design law: there is NO allow/trust field. The verdict compose (W-B)
/// treats a `DomainRuleSet::matches` hit as a BLOCK signal; absence of a hit is "no domain rule
/// objects" (NOT an allow — it just means this gate abstains). This mirrors exactly how the
/// blocklist half abstains when `qname` is `None` (`warden.rs` block-wins compose).
#[derive(Default)]
pub struct DomainRuleSet {
    /// One trie per UID (TLD-first label walk). `UID_UNIVERSAL` holds the universal-domain rules.
    /// A `HashMap<u32, …>` of tries keeps per-app isolation cheap: a lookup walks exactly ONE trie
    /// (the app's) plus the universal trie — not a linear scan of every app.
    by_uid: HashMap<u32, DomainTrie>,
    count: usize,
    fingerprint: u64,
}

/// The per-UID reversed-label trie (root + its own finalize). Extracted so lookups hold a single
/// `&DomainTrie` rather than re-indexing `by_uid` twice (per-app + universal).
#[derive(Default)]
struct DomainTrie {
    root: RuleNode,
}

impl DomainTrie {
    /// Insert `domain` as a terminal. Idempotent + canonical: a parent terminal subsumes children
    /// (`blocklist.rs:144-161`). Returns `true` if a NEW terminal was created (so the set's count/
    /// fingerprint stay accurate — the caller folds them in `DomainRuleSet::insert`).
    fn insert(&mut self, domain: &str) -> bool {
        let domain = normalize_rule(domain);
        if domain.is_empty() || domain.len() > MAX_RULE_NAME_LEN {
            return false;
        }
        if domain.split('.').count() > MAX_RULE_LABELS {
            return false;
        }
        let mut node = &mut self.root;
        let mut labels = domain.rsplit('.').peekable();
        for label in labels.by_ref() {
            node = node.children.entry(label.into()).or_default();
            if node.terminal {
                return false; // an ancestor already covers this — redundant, no new terminal
            }
        }
        if node.terminal {
            return false;
        }
        node.terminal = true;
        node.children.clear(); // prune subsumed descendants — keeps the set canonical
        true
    }

    /// True if `domain` or any parent apex is a terminal in this trie (`blocklist.rs:211-229`).
    ///
    /// ZERO-ALLOC on the hot path (D21): the former `normalize_rule(domain)` materialized a
    /// `to_lowercase()` String + a `split.collect::<Vec>().join(".")` String (3 heap allocs) on EVERY
    /// DNS-answer verdict + every uncached conn verdict with a qname. This walks the borrowed `domain`
    /// directly — trim, drop the trailing dot AND empty labels, apex-first `rsplit` — and per label
    /// borrows the slice when it is already lowercase-ASCII (the common case, zero alloc), owning a
    /// lowercased label ONLY when an uppercase/non-ASCII byte exists (matching the full-`to_lowercase`
    /// fold the stored keys were `normalize_rule`'d with, so lookups stay byte-identical).
    fn matches(&self, domain: &str) -> bool {
        let trimmed = domain.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return false;
        }
        let mut node = &self.root;
        for label in trimmed.rsplit('.') {
            // Drop empty labels (a `..` / leading dot) — the `normalize_rule` filter, allocation-free.
            if label.is_empty() {
                continue;
            }
            // Lowercase-only-if-needed: borrow when already lowercase-ASCII, else own the folded label.
            let needs_fold = !label.is_ascii() || label.bytes().any(|b| b.is_ascii_uppercase());
            let child = if needs_fold {
                node.children.get(label.to_lowercase().as_str())
            } else {
                node.children.get(label)
            };
            match child {
                Some(c) => {
                    if c.terminal {
                        return true;
                    }
                    node = c;
                }
                None => return false,
            }
        }
        node.terminal
    }
}

impl DomainRuleSet {
    /// An empty rule-set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a BLOCK domain rule. `wildcard = true` (apex + subdomains) is the natural form of the
    /// trie — every insert is wildcard by construction. `wildcard = false` (exact apex only) is the
    /// `CustomDomain.kt:31` DOMAIN form: an exact-only rule would need a `terminal`/`exact` split,
    /// but RethinkDNS's exact arm is TRASHED-only-for-allow — BLOCK exact is subsumed by BLOCK
    /// wildcard-at-apex (a block on `ads.com` apex blocks `ads.com` itself under block-wins), so the
    /// `wildcard` flag is preserved on the [`DomainRule`] model for fidelity but does NOT fork the
    /// trie. Idempotent + canonical; call [`finalize`](Self::finalize) once after a batch.
    pub fn insert(&mut self, rule: DomainRule) -> &mut Self {
        let trie = self.by_uid.entry(rule.uid).or_default();
        if trie.insert(&rule.domain) {
            self.count += 1;
        }
        self
    }

    /// Recompute [`count`](Self::len) + [`fingerprint`](Self::fingerprint) from the canonical
    /// terminal set. Order- and format-independent (the XOR-fold over sorted terminals), so two
    /// authorings of the same set produce the same digest. Mirrors `blocklist.rs:199-208`.
    pub fn finalize(&mut self) {
        let mut count = 0usize;
        let mut fingerprint = 0u64;
        // For set-determinism across UIDs, fold (uid, domain) pairs into the digest — a per-app
        // rule and a universal rule for the same domain are DIFFERENT rules and must hash apart.
        let mut uid_terminals: Vec<(u32, String)> = Vec::new();
        for (&uid, trie) in &self.by_uid {
            trie.root.walk_terminals("", &mut |domain| {
                uid_terminals.push((uid, domain.to_string()));
            });
        }
        uid_terminals.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        for (uid, domain) in &uid_terminals {
            count += 1;
            // Fold the UID into the digest input so (uid=5, "ads.com") ≠ (uid=0, "ads.com").
            let mut key = uid.to_string();
            key.push('|');
            key.push_str(domain);
            fingerprint ^= rule_fnv1a(&key);
        }
        self.count = count;
        self.fingerprint = fingerprint;
    }

    /// The number of canonical terminal rules (after [`finalize`](Self::finalize)).
    pub fn len(&self) -> usize {
        self.count
    }

    /// True if the set holds no rules.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The set-derived content digest (after [`finalize`](Self::finalize)).
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// True if a BLOCK rule matches `qname` for `uid` — consults the per-app trie AND the universal
    /// trie (`UID_UNIVERSAL`). A rule on a parent apex covers every subdomain. BLOCK-only: a hit
    /// means "a domain rule blocks this"; absence means "no domain rule objects". The universal-inclusive
    /// form (kept for the standalone matcher contract + the host matcher tests); the CASCADE uses the
    /// SCOPED [`matches_app`](Self::matches_app) (TIER 3, per-app only) + [`matches_universal`](
    /// Self::matches_universal) (TIER 4, universal only) so the two tiers attribute distinctly and
    /// `AppFirewallMode::BypassUniversal` can skip TIER 4 without the per-app check re-catching it.
    pub fn matches(&self, uid: u32, qname: &str) -> bool {
        if let Some(trie) = self.by_uid.get(&uid) {
            if trie.matches(qname) {
                return true;
            }
        }
        // The universal tier — distinct from the per-app trie (RethinkDNS global-domain table).
        if uid != UID_UNIVERSAL {
            if let Some(universal) = self.by_uid.get(&UID_UNIVERSAL) {
                return universal.matches(qname);
            }
        }
        false
    }

    /// TIER 3 — true if a PER-APP (uid-scoped) BLOCK rule matches `qname`. ONLY the uid's own trie, NOT
    /// the universal tier (that is [`matches_universal`](Self::matches_universal), TIER 4). The cascade's
    /// per-app domain check consults this so a universal rule is NOT attributed to the per-app tier and
    /// `BypassUniversal` truly bypasses the universal domain rules.
    pub fn matches_app(&self, uid: u32, qname: &str) -> bool {
        self.by_uid
            .get(&uid)
            .is_some_and(|trie| trie.matches(qname))
    }

    /// TIER 4 — true if a UNIVERSAL (`UID_UNIVERSAL`) BLOCK rule matches `qname`. ONLY the universal trie.
    pub fn matches_universal(&self, qname: &str) -> bool {
        self.by_uid
            .get(&UID_UNIVERSAL)
            .is_some_and(|trie| trie.matches(qname))
    }

    /// Enumerate every armed BLOCK domain rule as its [`DomainRule`] twin — the reverse of
    /// [`insert`](Self::insert), for the settings-pane rule LIST + per-index REMOVE (M2). The trie
    /// stores every rule wildcard-at-apex (an exact rule is subsumed by its apex terminal — see
    /// [`insert`]), so every enumerated rule reports `wildcard = true`: the storage TRUTH, not the
    /// authoring flag. Order is (uid ASC, domain ASC) so the rendered list + the remove-by-index stay
    /// stable across reads (the walk itself is HashMap-order, hence the explicit sort).
    pub fn rules(&self) -> Vec<DomainRule> {
        let mut out: Vec<DomainRule> = Vec::new();
        for (&uid, trie) in &self.by_uid {
            trie.root.walk_terminals("", &mut |domain| {
                out.push(DomainRule {
                    domain: domain.into(),
                    uid,
                    wildcard: true,
                });
            });
        }
        out.sort_unstable_by(|a, b| a.uid.cmp(&b.uid).then_with(|| a.domain.cmp(&b.domain)));
        out
    }
}

// The CIDR primitive lives in [`cidr_match::CidrMatch`] — family-aware (V4 host-order `u32` /
// V6 `u128`), one masked compare per family, allocation-free `Copy`. The old v4-only `Cidr`
// (`net: u32`) was retired by A3: it forced `ipv4_host_order` to ABSTAIN on every IPv6 daddr,
// making every v6 flow invisible to the CIDR tiers. The `warden_cidr_match` contract (lib.rs:588)
// semantics carry over unchanged for v4.

// The action a CIDR rule takes on a match: the Warden is a pure FIREWALL (RethinkDNS-matrix, NO
// dnsmasq transcendence — Socio 2026-06-27). A CIDR match is a BLOCK, full stop. dnsmasq's reply-
// munging semantics (NXDOMAIN vs silent-drop) belong to the Dnsmasq pillar (P12), NOT here.
// (The bogus-nxdomain / ignore-address absorb was a stale-direction leak, stripped this SEAL-LOOP.)

/// The status of an IP/CIDR rule — BLOCK-only after TRUST is trashed
/// (`CustomIp.kt` status ∈ {BLOCK, NONE} + the BYPASS_UNIVERSAL wildcard arm). [`IpStatus::Bypass`]
/// is "skip the universal tier" (RULE2C, the IP-wildcard bypass), NOT a trust weight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpStatus {
    /// Block matching traffic.
    Block,
    /// Bypass the universal tier for matching traffic (RULE2C IP-wildcard bypass — NOT trust).
    Bypass,
    /// No rule (the row exists but is inert).
    None,
}

/// One CIDR rule — `(uid, cidr, port, proto, status)` from `CustomIp.kt:33-50`, TRUST
/// removed. The `wildcard` flag (IPV4_WILDCARD / IPV6_WILDCARD `ruleType`) folds into
/// [`cidr_match::CidrMatch`]: a wildcard rule is a `prefix == 0` CIDR for the matching family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpRule {
    /// Owning app UID; `UID_UNIVERSAL` = the universal/global-IP table (RULE2D).
    pub uid: u32,
    /// The family-aware CIDR (V4 or V6). `prefix == 0` is the IP-wildcard form FOR THAT FAMILY;
    /// a rule NEVER matches across families (a v4 rule cannot judge a v6 daddr, and vice-versa).
    pub cidr: cidr_match::CidrMatch,
    /// Port filter; [`PortSpec::Any`] = `CustomIp.kt:37` `UNSPECIFIED_PORT`.
    pub port: PortSpec,
    /// Protocol filter; [`ProtoSpec::Any`] = `CustomIp.kt:38` empty-string protocol.
    pub proto: ProtoSpec,
    /// Rule status (BLOCK / Bypass / None). BLOCK-only on the deny path; Bypass is RULE2C.
    pub status: IpStatus,
}

/// Port filter — `CustomIp.kt:37` `UNSPECIFIED_PORT` → [`PortSpec::Any`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortSpec {
    /// Any port (the `UNSPECIFIED_PORT` default).
    Any,
    /// An exact port match.
    Exact(u16),
}

/// Protocol filter — `CustomIp.kt:38` empty-string protocol → [`ProtoSpec::Any`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoSpec {
    /// Any protocol (the empty-string default).
    Any,
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// Any other IP protocol number (ICMP=1, etc.).
    Other(u8),
}

impl ProtoSpec {
    /// Does this filter accept `proto` (the IP protocol byte from [`ConnFacts::proto`])?
    pub fn accepts(&self, proto: u8) -> bool {
        match self {
            ProtoSpec::Any => true,
            ProtoSpec::Tcp => proto == 6,
            ProtoSpec::Udp => proto == 17,
            ProtoSpec::Other(p) => *p == proto,
        }
    }
}

impl PortSpec {
    /// Does this filter accept `port` (the destination port from [`ConnFacts::dport`])?
    pub fn accepts(&self, port: u16) -> bool {
        match self {
            PortSpec::Any => true,
            PortSpec::Exact(p) => *p == port,
        }
    }
}

/// A BLOCK-only set of CIDR rules, keyed on `(uid, cidr)`. Per-app rules (RULE2) and universal
/// rules (RULE2D) coexist (`UID_UNIVERSAL`). Lookup walks the rules for the app + the universal
/// rules and returns the first BLOCK match (cidr + port + proto all accept). BLOCK-only by the
/// REWORKED law — there is NO allow/trust CIDR rule. An [`IpStatus::Bypass`] rule is a SKIP signal
/// for the universal tier (consumed by W-B's compose, NOT a block).
#[derive(Default)]
pub struct CidrRuleSet {
    /// Rules bucketed by UID so a lookup scans only the app's rules + the universal rules, not
    /// every app's. [`finalize`](Self::finalize) sorts each bucket MOST-SPECIFIC-FIRST (prefix
    /// DESC, stable), so a `/32` host rule beats a `/0` wildcard no matter the authoring order —
    /// the A3 tightening (RethinkDNS sorts the same way, `IpRulesManager.kt:352`). Within equal
    /// specificity the insertion order still breaks the tie (first-match-wins).
    by_uid: HashMap<u32, Vec<IpRule>>,
    count: usize,
    fingerprint: u64,
}

/// The outcome of a CIDR-rule lookup — did a BLOCK rule fire, or did a BYPASS rule fire (skip the
/// universal tier)? `None` = no rule matches. Distinct from a plain `bool` so W-B's compose can
/// honor the RULE2C bypass arm without re-walking the set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CidrHit {
    /// A BLOCK rule matched (the connection is denied by this gate).
    Block,
    /// A BYPASS rule matched (skip the universal tier — RULE2C, NOT trust).
    Bypass,
}

impl CidrRuleSet {
    /// An empty rule-set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a CIDR rule. Idempotent on (uid, cidr, port, proto, status, action) — a duplicate is
    /// dropped. BLOCK and Bypass rules coexist; the lookup distinguishes them by [`IpStatus`].
    pub fn insert(&mut self, rule: IpRule) -> &mut Self {
        let bucket = self.by_uid.entry(rule.uid).or_default();
        if bucket.iter().any(|r| rules_key_equal(r, &rule)) {
            return self; // duplicate — drop
        }
        bucket.push(rule);
        self.count += 1;
        self
    }

    /// Recompute [`count`](Self::len) + [`fingerprint`](Self::fingerprint), and ARM the
    /// most-specific-first bucket order (A3): each bucket sorts by prefix DESC (stable — equal
    /// specificity keeps insertion order), so a `/32` block beats a `/0` bypass regardless of the
    /// authoring order. MUST run before the set is armed; [`object::WardenObject::install_cidr_rules`]
    /// always does. The digest is order- and format-independent: the XOR-fold over the SORTED
    /// (uid, family, net, prefix, port, proto, status) tuples, so two authorings of the same set
    /// produce the same digest.
    pub fn finalize(&mut self) {
        for bucket in self.by_uid.values_mut() {
            bucket.sort_by_key(|r| std::cmp::Reverse(cidr_specificity(&r.cidr)));
        }
        let mut keyed: Vec<(u32, u8, u128, u8, u16, u8, u8)> = Vec::new();
        for (&uid, bucket) in &self.by_uid {
            for r in bucket {
                let (family, net, prefix) = match r.cidr {
                    cidr_match::CidrMatch::V4 { net, prefix } => (4u8, net as u128, prefix),
                    cidr_match::CidrMatch::V6 { net, prefix } => (6u8, net, prefix),
                };
                keyed.push((
                    uid,
                    family,
                    net,
                    prefix,
                    match r.port {
                        PortSpec::Any => 0xFFFFu16,
                        PortSpec::Exact(p) => p,
                    },
                    match r.proto {
                        ProtoSpec::Any => 0u8,
                        ProtoSpec::Tcp => 6,
                        ProtoSpec::Udp => 17,
                        ProtoSpec::Other(p) => p.wrapping_add(32), // avoid collision with Any/Tcp/Udp
                    },
                    r.status as u8,
                ));
            }
        }
        keyed.sort_unstable();
        let mut count = 0usize;
        let mut fingerprint = 0u64;
        for k in &keyed {
            count += 1;
            let mut buf = [0u8; 21];
            buf[0..4].copy_from_slice(&k.0.to_le_bytes());
            buf[4] = k.1;
            buf[5..21].copy_from_slice(&k.2.to_le_bytes());
            // D39: fold the RAW (uid, family, net) bytes directly — a high octet (≥ 0x80) is NOT valid
            // UTF-8, so a `from_utf8`-gated route would silently hash "" and drop ip+prefix. The family
            // byte keeps a v4 net and the numerically-equal v6 net from colliding.
            fingerprint ^= rule_fnv1a_bytes(&buf);
            fingerprint ^= rule_fnv1a(&format!("|{}|{}|{}|{}", k.3, k.4, k.5, k.6));
        }
        self.count = count;
        self.fingerprint = fingerprint;
    }

    /// The number of rules (after [`finalize`](Self::finalize)).
    pub fn len(&self) -> usize {
        self.count
    }

    /// True if the set holds no rules.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The set-derived content digest (after [`finalize`](Self::finalize)).
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// Enumerate every armed CIDR rule as its [`IpRule`] twin — the reverse of [`insert`](Self::insert),
    /// for the settings-pane rule LIST + per-index REMOVE (M2). Emitted in the finalized
    /// most-specific-first bucket order within each uid, uids ASC — a deterministic order so the
    /// rendered list + the remove-by-index stay stable across reads.
    pub fn rules(&self) -> Vec<IpRule> {
        let mut uids: Vec<u32> = self.by_uid.keys().copied().collect();
        uids.sort_unstable();
        let mut out: Vec<IpRule> = Vec::new();
        for uid in uids {
            if let Some(bucket) = self.by_uid.get(&uid) {
                out.extend(bucket.iter().cloned());
            }
        }
        out
    }

    /// W-C (#86) — remove the rule at flat index `index` in the [`rules`](Self::rules) enumeration order
    /// (uids ASC, then the finalized in-bucket order), then re-[`finalize`](Self::finalize) so
    /// count/fingerprint/order stay consistent for the next read. Returns `true` iff a rule was removed
    /// (`false` = out-of-range). The v6-capable settings REMOVE: an index-remove touches the held set
    /// directly, so a v6 rule (which the u32 install wire can't re-carry) drops cleanly. The last rule for
    /// a uid empties + drops its bucket. Walks the SAME uid-ASC + in-bucket order as [`rules`](Self::rules),
    /// so the index the pane rendered points at the same rule.
    pub fn remove_at(&mut self, index: usize) -> bool {
        let mut uids: Vec<u32> = self.by_uid.keys().copied().collect();
        uids.sort_unstable();
        let mut seen = 0usize;
        for uid in uids {
            let len = self.by_uid.get(&uid).map(|b| b.len()).unwrap_or(0);
            if index < seen + len {
                let local = index - seen;
                if let Some(bucket) = self.by_uid.get_mut(&uid) {
                    if local < bucket.len() {
                        bucket.remove(local);
                        if bucket.is_empty() {
                            self.by_uid.remove(&uid);
                        }
                        self.finalize();
                        return true;
                    }
                }
                return false;
            }
            seen += len;
        }
        false
    }

    /// Scan ONE uid bucket for the MOST-SPECIFIC matching BLOCK/Bypass rule (cidr.matches(addr) AND
    /// port.accepts(dport) AND proto.accepts(proto)) — the bucket is prefix-DESC after
    /// [`finalize`](Self::finalize), so the first hit IS the most specific. Family-aware: a v4 rule
    /// only judges a v4 `addr`, a v6 rule only a v6 `addr`. The shared core of the scoped + the
    /// universal-inclusive lookups. `None` = no rule in THIS bucket matches.
    fn scan_bucket(&self, uid: u32, addr: IpAddr, dport: u16, proto: u8) -> Option<CidrHit> {
        let bucket = self.by_uid.get(&uid)?;
        for r in bucket {
            if r.status == IpStatus::None {
                continue;
            }
            if r.cidr.matches(addr) && r.port.accepts(dport) && r.proto.accepts(proto) {
                return Some(match r.status {
                    IpStatus::Block => CidrHit::Block,
                    IpStatus::Bypass => CidrHit::Bypass,
                    IpStatus::None => unreachable!(),
                });
            }
        }
        None
    }

    /// Look up the CIDR rules for `uid` + universal. Returns the MOST-SPECIFIC matching BLOCK or
    /// Bypass rule, per-app tier first then universal. `None` = no rule matches. The universal-inclusive
    /// form (kept for the standalone matcher contract + the host matcher tests); the CASCADE uses the
    /// SCOPED [`lookup_app`](Self::lookup_app) (TIER 3) + [`lookup_universal`](Self::lookup_universal)
    /// (TIER 4).
    pub fn lookup(&self, uid: u32, addr: IpAddr, dport: u16, proto: u8) -> Option<CidrHit> {
        if let Some(hit) = self.scan_bucket(uid, addr, dport, proto) {
            return Some(hit);
        }
        if uid != UID_UNIVERSAL {
            return self.scan_bucket(UID_UNIVERSAL, addr, dport, proto);
        }
        None
    }

    /// TIER 3 — look up ONLY the PER-APP (uid-scoped) CIDR rules (NOT the universal tier). The cascade's
    /// per-app CIDR check consults this so a universal rule is not attributed to the per-app tier and
    /// `BypassUniversal` truly bypasses the universal CIDR rules.
    pub fn lookup_app(&self, uid: u32, addr: IpAddr, dport: u16, proto: u8) -> Option<CidrHit> {
        self.scan_bucket(uid, addr, dport, proto)
    }

    /// TIER 4 — look up ONLY the UNIVERSAL (`UID_UNIVERSAL`) CIDR rules.
    pub fn lookup_universal(&self, addr: IpAddr, dport: u16, proto: u8) -> Option<CidrHit> {
        self.scan_bucket(UID_UNIVERSAL, addr, dport, proto)
    }

    /// SLICE 3 — project the UNIVERSAL BLOCK CIDR rules into the [`cidr_match::CidrMatch`] form the
    /// DNS-answer verdict ([`verdict_loop::apply_dns_verdict`]) walks. The per-connection cascade uses
    /// `scan_bucket` over a FLOW (it has a port + proto); a DNS-answer verdict judges a bare resolved
    /// ADDRESS (no flow context), so ONLY the unscoped (any-port, any-proto) universal BLOCK rules
    /// project — a port/proto-scoped CIDR rule stays a per-connection-only rule and is NOT applied to
    /// a name resolution. Since A3 the rule's CIDR IS a family-aware `CidrMatch`, so v4 AND v6
    /// universal blocks both project (a straight copy). Allocation is one small `Vec` per answer
    /// verdict (off the per-connection hot path).
    fn universal_blocks(&self) -> Vec<cidr_match::CidrMatch> {
        let mut out = Vec::new();
        if let Some(bucket) = self.by_uid.get(&UID_UNIVERSAL) {
            for r in bucket {
                if r.status == IpStatus::Block
                    && matches!(r.port, PortSpec::Any)
                    && matches!(r.proto, ProtoSpec::Any)
                {
                    out.push(r.cidr);
                }
            }
        }
        out
    }
}

/// Key equality for IpRule dedup — all discriminators except the bucket index. (uid is the bucket
/// key, so it is implied equal here.)
fn rules_key_equal(a: &IpRule, b: &IpRule) -> bool {
    a.cidr == b.cidr && a.port == b.port && a.proto == b.proto && a.status == b.status
}

/// A universal firewall rule — the RULE1B/F/3/4/6/7/10/11 toggles from `FirewallRuleset.kt`, the
/// dnsmasq rebind guard (`forward.c:145` / `rfc1035.c:418-434`), and the global-IP/global-domain
/// absorb. Each variant is an INDEPENDENT universal-tier toggle; W-B's compose arms them in the
/// RethinkDNS precedence (RULE1B → RULE1F → RULE11 → RULE10 → RULE3 → RULE6 → RULE4 → RULE7).
///
/// BLOCK-only by REWORKED law: every variant is a BLOCK/deny toggle. There is NO trust variant.
/// TRUST arms (RULE2B/F/I) were DROPPED on port — trust is blocklist scoring, a separate pillar.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UniversalRule {
    /// RULE1B — block apps not yet seen (the new-app-default, gated by `AppFirewallMode::Untracked`).
    BlockNewApps,
    /// RULE1F — block all metered (cellular/roaming) traffic. A global toggle.
    BlockMetered,
    /// RULE11 — universal lockdown (block everything except the allow-list).
    Lockdown,
    /// RULE3 — device-lock (block on screen-off).
    DeviceLock,
    /// RULE4 — block background-data (foreground-only).
    BlockBackground,
    /// RULE6 — block UDP-NTP (port 123 / UDP). A proto+port sub-check.
    BlockUdpNtp,
    /// RULE10 — block HTTP (port 80, any proto). A port sub-check.
    BlockHttp,
    /// RULE7 — block DNS bypass (a query with empty qname trying to skip the resolver). A
    /// query-shape sub-check; interoperates with the SEPARATE blocklist gate (does not consume it).
    BlockDnsBypass,
    /// RULE2D absorb — a universal CIDR block (the global-IP table). Reuses [`CidrRuleSet`] with
    /// `UID_UNIVERSAL`; this variant is the universal-tier marker so W-B can attribute denies to
    /// the universal gate vs the per-app gate. The rules themselves live in the [`CidrRuleSet`].
    BlockUniversalCidr,
    /// RULE2H absorb — a universal domain block (the global-domain table). Same shape as
    /// [`UniversalRule::BlockUniversalCidr`] for the domain tier; rules live in [`DomainRuleSet`]
    /// under `UID_UNIVERSAL`.
    BlockUniversalDomain,
}

/// The per-app firewall mode — `AppInfo.kt:32` `firewallStatus` (ids 2–7), TRUST-free. Each variant
/// is a MODE the verdict compose consults; `Exclude` means the app bypasses the VPN itself (not a
/// Warden verdict — handled by the datapath before the Warden sees the connection).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppFirewallMode {
    /// RULE8 — bypass the universal tier for this app (NOT trust — "skip universal", still subject
    /// to per-app rules + the blocklist).
    BypassUniversal,
    /// The app is excluded from the VPN entirely (not a Warden verdict — datapath drops it before
    /// the Warden). Modeled for completeness so the W-B compose can recognize it.
    Exclude,
    /// RULE1G — isolate: the app may only talk the DNS resolver + the LAN, nothing else.
    Isolate,
    /// No special mode — the app is subject to the per-UID allow-sets + universal rules.
    None,
    /// RULE5 — untracked (never seen by the firewall). Subject to [`UniversalRule::BlockNewApps`].
    Untracked,
    /// RULE1H — bypass the DNS firewall (the blocklist gate) for this app. NOT trust — "skip the
    /// blocklist half" (mirrors `BypassUniversal` for the universal tier).
    BypassDnsFirewall,
}

/// The per-network meteredness class — `AppInfo.kt:36` `connectionStatus`
/// (BOTH/UNMETERED/METERED/ALLOW). RULE1/1D/1E derive the per-app net verdict from this (the per-app
/// matrix is the allow-by-default firewall surface now; the legacy `WardenPolicy` allow-sets were removed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NetClass {
    /// Allowed on both metered (cellular) and unmetered (Wi-Fi) networks.
    Both,
    /// Allowed on unmetered (Wi-Fi) only.
    Unmetered,
    /// Allowed on metered (cellular) only.
    Metered,
    /// Allowed (the catch-all — distinct from `Both` which is the explicit dual-allow).
    Allow,
}

/// A temp-allow TTL — `AppInfo.kt:44-45` `tempAllowEnabled` / `tempAllowExpiryTime` (epoch ms).
/// RULE19 returns Allow while `now < expiry`, regardless of the underlying mode. This is the
/// "pause" knob: the Socio taps an app to let it through for N minutes, then it reverts.
///
/// Time-bounded by construction: [`expires_at`](Self::expires_at) is a `u64` epoch-ms (Android's
/// `System.currentTimeMillis()` shape) so there is no `Instant`/`Duration` drift across the FFI
/// seam. [`is_active`](Self::is_active) takes `now_ms: u64` for the same reason — the datapath
/// supplies the clock, the rule-set does not reach for one (no `Date.now` in the hot path).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TempAllow {
    /// Owning app UID.
    pub uid: u32,
    /// Epoch-millis expiry (`AppInfo.kt:45` `tempAllowExpiryTime`). `0` = disabled.
    pub expires_at: u64,
}

impl TempAllow {
    /// Construct a temp-allow for `uid` expiring at `expires_at_ms` (epoch ms).
    pub fn new(uid: u32, expires_at_ms: u64) -> Self {
        Self {
            uid,
            expires_at: expires_at_ms,
        }
    }

    /// True if this temp-allow is currently active — `enabled` (non-zero expiry) AND `now < expiry`.
    /// `now_ms` is the datapath's epoch-ms clock (supplied, not reached-for). A disabled or expired
    /// temp-allow is inert: RULE19 does not fire, the underlying [`AppFirewallMode`] governs.
    pub fn is_active(&self, now_ms: u64) -> bool {
        self.expires_at != 0 && now_ms < self.expires_at
    }
}

// ===========================================================================================
// Free helpers — the cascade's pure predicates (allocation-free, no IO)
// ===========================================================================================

/// RULE1/1D/1E — does `meteredness` block a connection on `net`? rethink-app-main `ConnectionStatus`
/// (IDEA only — zero derived bytes; Apache-2.0 study corpus). `Allow` never blocks; the others block on
/// the matching network class:
/// - `Both` blocks on BOTH metered (Gsm/Roaming) AND unmetered (Wifi/Vpn) — the block-all.
/// - `Unmetered` blocks on Wifi/Vpn only (block-wifi).
/// - `Metered` blocks on Gsm/Roaming only (block-mobile).
fn meteredness_blocks(meteredness: NetClass, net: NetworkType) -> bool {
    match meteredness {
        NetClass::Allow => false,
        NetClass::Both => true, // blocks every non-Lan net (Lan is the resolver/LAN axis, exempt)
        NetClass::Unmetered => matches!(net, NetworkType::Wifi | NetworkType::Vpn),
        NetClass::Metered => matches!(net, NetworkType::Gsm | NetworkType::Roaming),
    }
}

/// Rank a CIDR's specificity for the most-specific-first bucket order (A3): higher = more specific.
/// The v4 prefix scales ×4 onto the 0..=128 v6 lattice (a v4 `/32` host route ranks with a v6
/// `/128`); families never co-match, so the cross-family order is inert — the scale just keeps the
/// one sort axis honest.
fn cidr_specificity(c: &cidr_match::CidrMatch) -> u16 {
    match c {
        cidr_match::CidrMatch::V4 { prefix, .. } => (*prefix as u16) * 4,
        cidr_match::CidrMatch::V6 { prefix, .. } => *prefix as u16,
    }
}

// ===========================================================================================
// SLICE 2 — the durable matrix-state codec: constants, the enum↔u8 stable maps, and the bounded
// cursor read helpers (mirroring the resolver-cache discipline at `resolver/cache.rs:750-778`).
// ===========================================================================================

/// The DurableTier record name for the Warden matrix + toggles state (slice 2). A stable per-pillar
/// filename under the app-private `filesDir` (sanitized by `DurableTier::with_dir`).
const MATRIX_RECORD_NAME: &str = "warden-matrix";

/// The matrix-state blob format version. Bumped if the framing changes; a record written by a NEWER
/// version rehydrates as a cold start (the forward-incompat discipline — never a guessed parse).
///
/// V1 (slice 2) framed matrix + toggles ONLY. V2 (#78 W-C) APPENDS the armed rule-sets — the user's
/// interactive CIDR / domain / glob / universal / geo-family blocks that a settings-add or an inspector
/// block-ladder tap arms into the ENGINE (never a signed source: the blocklist trie is the SEPARATE TIER-5
/// seam, so persisting these is the (a) NEW-durable charter path, not a signed-source dump). [`restore_state`]
/// stays BACKWARD-compatible: a V1 blob still rehydrates matrix + toggles (its rule-sets cold-start, exactly
/// as before V2 existed). A forward (`> 2`) blob is still a cold start.
const MATRIX_SNAP_VERSION: u8 = 2;

/// The FIRST rule-set-carrying blob version — the backward-compat floor [`restore_state`] parses
/// matrix + toggles for (V1 wrote no rule-sets; V2+ append them). A blob whose version is neither this
/// nor [`MATRIX_SNAP_VERSION`] is a cold start.
const MATRIX_SNAP_VERSION_MATRIX_ONLY: u8 = 1;

/// Per-row encoded width: `uid`(4) + `mode`(1) + `meteredness`(1) + `temp_allow_until`(8).
const MATRIX_ROW_BYTES: usize = 4 + 1 + 1 + 8;

/// Stable [`AppFirewallMode`] → `u8` map for the durable blob (a FORMAT CONTRACT — never renumber).
fn app_mode_to_u8(m: AppFirewallMode) -> u8 {
    match m {
        AppFirewallMode::None => 0,
        AppFirewallMode::Isolate => 1,
        AppFirewallMode::Untracked => 2,
        AppFirewallMode::BypassUniversal => 3,
        AppFirewallMode::Exclude => 4,
        AppFirewallMode::BypassDnsFirewall => 5,
    }
}

/// Inverse of [`app_mode_to_u8`]. An UNKNOWN byte → [`AppFirewallMode::None`] (the inert default — a
/// fail-safe: a corrupt/forward mode never silently denies, it falls to the no-special-mode path).
fn app_mode_from_u8(b: u8) -> AppFirewallMode {
    match b {
        1 => AppFirewallMode::Isolate,
        2 => AppFirewallMode::Untracked,
        3 => AppFirewallMode::BypassUniversal,
        4 => AppFirewallMode::Exclude,
        5 => AppFirewallMode::BypassDnsFirewall,
        _ => AppFirewallMode::None,
    }
}

/// Stable [`NetClass`] → `u8` map for the durable blob (a FORMAT CONTRACT — never renumber).
fn net_class_to_u8(n: NetClass) -> u8 {
    match n {
        NetClass::Allow => 0,
        NetClass::Both => 1,
        NetClass::Unmetered => 2,
        NetClass::Metered => 3,
    }
}

/// Inverse of [`net_class_to_u8`]. An UNKNOWN byte → [`NetClass::Allow`] (the inert default — a
/// fail-safe: a corrupt/forward meteredness never silently blocks the network).
fn net_class_from_u8(b: u8) -> NetClass {
    match b {
        1 => NetClass::Both,
        2 => NetClass::Unmetered,
        3 => NetClass::Metered,
        _ => NetClass::Allow,
    }
}

/// Stable [`IpStatus`] → `u8` map for the V2 rule-set blob (a FORMAT CONTRACT — never renumber).
fn ip_status_to_u8(s: IpStatus) -> u8 {
    match s {
        IpStatus::Block => 0,
        IpStatus::Bypass => 1,
        IpStatus::None => 2,
    }
}

/// Inverse of [`ip_status_to_u8`]. An UNKNOWN byte → [`IpStatus::Block`] (a restored rule was armed to
/// DENY; a corrupt/forward status falls to the BLOCK it was authored as, never silently to an inert None).
fn ip_status_from_u8(b: u8) -> IpStatus {
    match b {
        1 => IpStatus::Bypass,
        2 => IpStatus::None,
        _ => IpStatus::Block,
    }
}

/// Stable [`UniversalRule`] → `u8` map for the V2 rule-set blob (a FORMAT CONTRACT — never renumber; a
/// new variant takes the next free byte). By-ref (the enum is not `Copy`); match ergonomics bind through.
fn universal_rule_to_u8(r: &UniversalRule) -> u8 {
    match r {
        UniversalRule::BlockNewApps => 0,
        UniversalRule::BlockMetered => 1,
        UniversalRule::Lockdown => 2,
        UniversalRule::DeviceLock => 3,
        UniversalRule::BlockBackground => 4,
        UniversalRule::BlockUdpNtp => 5,
        UniversalRule::BlockHttp => 6,
        UniversalRule::BlockDnsBypass => 7,
        UniversalRule::BlockUniversalCidr => 8,
        UniversalRule::BlockUniversalDomain => 9,
    }
}

/// Inverse of [`universal_rule_to_u8`]. An UNKNOWN byte → `None` (a forward variant the prior version
/// never wrote is simply DROPPED from the restored set — fail-safe, never a guessed rule).
fn universal_rule_from_u8(b: u8) -> Option<UniversalRule> {
    Some(match b {
        0 => UniversalRule::BlockNewApps,
        1 => UniversalRule::BlockMetered,
        2 => UniversalRule::Lockdown,
        3 => UniversalRule::DeviceLock,
        4 => UniversalRule::BlockBackground,
        5 => UniversalRule::BlockUdpNtp,
        6 => UniversalRule::BlockHttp,
        7 => UniversalRule::BlockDnsBypass,
        8 => UniversalRule::BlockUniversalCidr,
        9 => UniversalRule::BlockUniversalDomain,
        _ => return None,
    })
}

/// Take the next byte off the cursor, advancing it; `None` if the cursor is empty (a length guard —
/// the parse STOPS, never an OOB read). Mirrors `resolver/cache.rs:750`.
fn take_one(cur: &mut &[u8]) -> Option<u8> {
    let (&b, rest) = cur.split_first()?;
    *cur = rest;
    Some(b)
}

/// Read a big-endian `u16` off the cursor, advancing it; `None` if fewer than 2 bytes remain.
fn read_u16_be(cur: &mut &[u8]) -> Option<u16> {
    if cur.len() < 2 {
        return None;
    }
    let v = u16::from_be_bytes([cur[0], cur[1]]);
    *cur = &cur[2..];
    Some(v)
}

/// Read a big-endian `u32` off the cursor, advancing it; `None` if fewer than 4 bytes remain.
fn read_u32_be(cur: &mut &[u8]) -> Option<u32> {
    if cur.len() < 4 {
        return None;
    }
    let v = u32::from_be_bytes([cur[0], cur[1], cur[2], cur[3]]);
    *cur = &cur[4..];
    Some(v)
}

/// Read a big-endian `u64` off the cursor, advancing it; `None` if fewer than 8 bytes remain.
fn read_u64_be(cur: &mut &[u8]) -> Option<u64> {
    if cur.len() < 8 {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&cur[..8]);
    *cur = &cur[8..];
    Some(u64::from_be_bytes(b))
}

/// Read a big-endian `u128` off the cursor, advancing it; `None` if fewer than 16 bytes remain. The V2
/// rule-set blob carries every CIDR net at the widest family width (a v4 `u32` sits in the low 32 bits),
/// so one fixed-width read serves both families.
fn read_u128_be(cur: &mut &[u8]) -> Option<u128> {
    if cur.len() < 16 {
        return None;
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(&cur[..16]);
    *cur = &cur[16..];
    Some(u128::from_be_bytes(b))
}

/// Read `len` bytes off the cursor as an owned `Vec<u8>`, advancing it; `None` if fewer than `len` bytes
/// remain (a length guard — the parse STOPS, never an OOB read). The V2 blob's variable-width fields
/// (domain / glob names) ride this.
fn read_bytes(cur: &mut &[u8], len: usize) -> Option<Vec<u8>> {
    if cur.len() < len {
        return None;
    }
    let out = cur[..len].to_vec();
    *cur = &cur[len..];
    Some(out)
}

// ===========================================================================================
// Tests (host cargo — the proof: the 6-tier cascade truth table, cache-coherence, fail-safe, eviction)
// ===========================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// A DNS-bearing connection on Wi-Fi for `uid` querying `qname`. `dns_blocked = false` (the resolver
    /// did not flag it) — the TIER-5 seam abstains unless a test sets the flag explicitly.
    fn dns_conn(uid: u32, qname: &str) -> ConnFacts {
        ConnFacts {
            uid,
            daddr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dport: 443,
            proto: 6,
            qname: Some(qname.to_string()),
            net: NetworkType::Wifi,
            dns_blocked: false,
        }
    }

    /// A non-DNS connection on Wi-Fi for `uid` (no qname). `dns_blocked = false`.
    fn plain_conn(uid: u32) -> ConnFacts {
        ConnFacts {
            uid,
            daddr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dport: 443,
            proto: 6,
            qname: None,
            net: NetworkType::Wifi,
            dns_blocked: false,
        }
    }

    /// A finalized UNIVERSAL-domain (`UID_UNIVERSAL`) BLOCK rule-set over `domains` (TIER 4 deny source).
    fn universal_domain_block(domains: &[&str]) -> DomainRuleSet {
        let mut set = DomainRuleSet::new();
        for d in domains {
            set.insert(DomainRule {
                domain: (*d).into(),
                uid: UID_UNIVERSAL,
                wildcard: true,
            });
        }
        set.finalize();
        set
    }

    /// A finalized PER-APP domain BLOCK rule-set over `domains` for `uid` (TIER 3 deny source).
    fn app_domain_block(uid: u32, domains: &[&str]) -> DomainRuleSet {
        let mut set = DomainRuleSet::new();
        for d in domains {
            set.insert(DomainRule {
                domain: (*d).into(),
                uid,
                wildcard: true,
            });
        }
        set.finalize();
        set
    }

    // ---- THE CASCADE TRUTH TABLE — first-match-DENY across the 6 tiers (slice-1 rework) ----

    #[test]
    fn cascade_universal_domain_rule_denies_at_tier4_and_covers_subdomains() {
        // A universal-domain BLOCK rule (TIER 4) denies even when the firewall baseline allows — and a
        // subdomain of a blocked parent is covered (the trie's parent-cover semantics).
        const UID: u32 = 10_002;
        let mut w = Warden::new();
        w.set_domain_rules(universal_domain_block(&["doubleclick.net"]));
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "ads.doubleclick.net"), 1),
            Verdict::Deny,
            "a subdomain of a universal-blocked parent denies at TIER 4 despite the firewall baseline allow"
        );
        // A non-blocked sibling label passes.
        let mut w = Warden::new();
        w.set_domain_rules(universal_domain_block(&["doubleclick.net"]));
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "notdoubleclick.net"), 1),
            Verdict::Allow,
            "a non-blocked name passes when the baseline allows and no rule matches"
        );
    }

    #[test]
    fn cascade_dns_blocked_seam_denies_at_tier5() {
        // The resolver's dns_blocked flag denies at TIER 5 (the narrow blocklist seam, Anti-Venom §5d).
        const UID: u32 = 10_003;
        let mut w = Warden::new();
        let mut flagged = dns_conn(UID, "ads.example.com");
        flagged.dns_blocked = true;
        assert_eq!(
            w.verdict_at(&flagged, 1),
            Verdict::Deny,
            "dns_blocked = true denies at TIER 5"
        );
        // The same conn-identity WITHOUT the flag (a FRESH Warden — dns_blocked is not part of the cache
        // key, so reusing `w` would replay the cached Deny within one epoch).
        let mut w = Warden::new();
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "ads.example.com"), 1),
            Verdict::Allow,
            "dns_blocked = false falls through the seam to allow"
        );
    }

    // ---- THE PER-APP MATRIX + UNIVERSAL TOGGLES + RULE-SETS wired into the cascade (slice-1) ----

    #[test]
    fn per_app_domain_rule_denies_at_tier3() {
        // A PER-APP domain rule denies at TIER 3 only for ITS uid; a different uid is unaffected.
        const UID: u32 = 10_010;
        let mut w = Warden::new(); // allow-all baseline — isolate the tier
        w.set_domain_rules(app_domain_block(UID, &["ads.example.com"]));
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "ads.example.com"), 1),
            Verdict::Deny,
            "the app's own domain rule denies at TIER 3"
        );
        let mut w = Warden::new();
        w.set_domain_rules(app_domain_block(UID, &["ads.example.com"]));
        assert_eq!(
            w.verdict_at(&dns_conn(99_999, "ads.example.com"), 1),
            Verdict::Allow,
            "a DIFFERENT uid is not bound by another app's per-app rule"
        );
    }

    #[test]
    fn per_app_cidr_rule_denies_at_tier3() {
        const UID: u32 = 10_011;
        let mut w = Warden::new();
        let mut cidr = CidrRuleSet::new();
        cidr.insert(IpRule {
            uid: UID,
            cidr: cidr_match::CidrMatch::V4 {
                net: u32::from(Ipv4Addr::new(93, 184, 216, 0)),
                prefix: 24,
            },
            port: PortSpec::Any,
            proto: ProtoSpec::Any,
            status: IpStatus::Block,
        });
        cidr.finalize();
        w.set_cidr_rules(cidr);
        // dns_conn's daddr 93.184.216.34 is inside 93.184.216.0/24 ⇒ TIER 3 CIDR deny.
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "x.example.com"), 1),
            Verdict::Deny,
            "a per-app CIDR rule denies at TIER 3"
        );
    }

    #[test]
    fn per_app_cidr_rule_denies_a_v6_daddr_at_tier3() {
        // A3 regression: pre-A3 the cascade abstained on EVERY IPv6 daddr (`ipv4_host_order` →
        // `None`), so a CIDR-blocked app slipped out over v6. A v6 rule must now deny a v6 flow.
        const UID: u32 = 10_011;
        let mut w = Warden::new();
        let mut cidr = CidrRuleSet::new();
        cidr.insert(IpRule {
            uid: UID,
            cidr: cidr_match::CidrMatch::V6 {
                net: u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                prefix: 32,
            },
            port: PortSpec::Any,
            proto: ProtoSpec::Any,
            status: IpStatus::Block,
        });
        cidr.finalize();
        w.set_cidr_rules(cidr);
        let mut conn = dns_conn(UID, "x.example.com");
        conn.daddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x34));
        assert_eq!(
            w.verdict_at(&conn, 1),
            Verdict::Deny,
            "a v6 per-app CIDR rule denies a v6 daddr at TIER 3 (pre-A3: silent Allow)"
        );
        // The SAME set judges the app's v4 daddr as no-match (family isolation) ⇒ Allow.
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "x.example.com"), 1),
            Verdict::Allow,
            "a v6 rule never matches a v4 daddr"
        );
    }

    #[test]
    fn geo_family_block_denies_the_country_at_tier4() {
        // W-D (#79): the user-explicit GEO-family block. Arm "us"; a destination the GeoIP table places
        // in the US denies at TIER 4, a non-US destination passes, and no country armed = no geoip probe.
        const UID: u32 = 10_050;
        // Stable anchors (the geoip.rs test set): 8.8.8.8 = US, 1.1.1.1 = AU.
        let us_conn = |uid| {
            let mut c = dns_conn(uid, "x.example.com");
            c.daddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            c
        };
        let au_conn = |uid| {
            let mut c = dns_conn(uid, "x.example.com");
            c.daddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
            c
        };
        // No country armed ⇒ the block is inert (baseline allow, the geoip probe is skipped).
        let mut w = Warden::new();
        assert_eq!(w.verdict_at(&us_conn(UID), 1), Verdict::Allow, "no geo block ⇒ allow");
        // Arm "US" (mixed-case + garbage entries are gated out by set_geo_blocks).
        let mut w = Warden::new();
        w.set_geo_blocks(&["US".to_string(), "zz9".to_string(), "".to_string()]);
        assert_eq!(w.geo_blocks(), vec!["us".to_string()], "only the valid 2-letter code arms, lowercased");
        assert_eq!(
            w.verdict_at(&us_conn(UID), 1),
            Verdict::Deny,
            "a US destination denies at TIER 4 under the user-explicit geo block"
        );
        // A non-US destination passes (a FRESH Warden — the cache is keyed on conn identity).
        let mut w = Warden::new();
        w.set_geo_blocks(&["us".to_string()]);
        assert_eq!(
            w.verdict_at(&au_conn(UID), 1),
            Verdict::Allow,
            "an AU destination is not caught by a US-only geo block"
        );
    }

    #[test]
    fn add_cidr_rule_is_additive_and_blocks_the_host() {
        // W-D (#79): the inspector's block-ladder adds ONE host block additively without clobbering a
        // prior rule. Arm a /24 for one app, then add a /32 universal block for another host — both fire.
        const UID: u32 = 10_051;
        let mut w = Warden::new();
        w.add_cidr_rule(IpRule {
            uid: UID_UNIVERSAL,
            cidr: cidr_match::CidrMatch::V4 { net: u32::from(Ipv4Addr::new(8, 8, 8, 8)), prefix: 32 },
            port: PortSpec::Any,
            proto: ProtoSpec::Any,
            status: IpStatus::Block,
        });
        let mut c = dns_conn(UID, "x.example.com");
        c.daddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(w.verdict_at(&c, 1), Verdict::Deny, "the added /32 universal block denies the host");
        // A second additive add leaves the first intact.
        w.add_cidr_rule(IpRule {
            uid: UID_UNIVERSAL,
            cidr: cidr_match::CidrMatch::V4 { net: u32::from(Ipv4Addr::new(1, 1, 1, 1)), prefix: 32 },
            port: PortSpec::Any,
            proto: ProtoSpec::Any,
            status: IpStatus::Block,
        });
        let mut c2 = dns_conn(UID, "x.example.com");
        c2.daddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(w.verdict_at(&c2, 2), Verdict::Deny, "the 2nd added block fires");
        let mut c3 = dns_conn(UID, "x.example.com");
        c3.daddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(w.verdict_at(&c3, 2), Verdict::Deny, "the 1st block SURVIVED the additive 2nd");
    }

    #[test]
    fn app_mode_isolate_denies_non_lan_allows_lan() {
        const UID: u32 = 10_012;
        let mk = |w: &mut Warden| {
            let mut row = AppMatrixRow::new(UID);
            row.mode = AppFirewallMode::Isolate;
            w.set_app_row(row);
        };
        let mut w = Warden::new();
        mk(&mut w);
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "x.example.com"), 1),
            Verdict::Deny,
            "isolate denies a non-LAN conn at TIER 3"
        );
        // A LAN conn is exempt (the app may talk the LAN).
        let mut w = Warden::new();
        mk(&mut w);
        let mut lan = dns_conn(UID, "x.example.com");
        lan.net = NetworkType::Lan;
        assert_eq!(
            w.verdict_at(&lan, 1),
            Verdict::Allow,
            "isolate allows a LAN conn"
        );
    }

    #[test]
    fn app_meteredness_blocks_metered_passes_unmetered() {
        const UID: u32 = 10_013;
        let arm = |w: &mut Warden| {
            let mut row = AppMatrixRow::new(UID);
            row.meteredness = NetClass::Metered; // block cellular
            w.set_app_row(row);
        };
        let mut w = Warden::new();
        arm(&mut w);
        let mut gsm = dns_conn(UID, "x.example.com");
        gsm.net = NetworkType::Gsm;
        assert_eq!(
            w.verdict_at(&gsm, 1),
            Verdict::Deny,
            "Metered blocks a Gsm conn at TIER 3"
        );
        let mut w = Warden::new();
        arm(&mut w);
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "x.example.com"), 1),
            Verdict::Allow,
            "Metered passes a Wi-Fi (unmetered) conn"
        );
    }

    #[test]
    fn app_temp_allow_pauses_per_app_denies() {
        // RULE19: temp-allow (non-zero expiry) pauses the app's PER-APP denies (an isolate block here),
        // but NOT the universal toggles (proven separately).
        const UID: u32 = 10_014;
        let mut w = Warden::new();
        let mut row = AppMatrixRow::new(UID);
        row.mode = AppFirewallMode::Isolate; // would deny a non-LAN conn...
        row.temp_allow_until = 1; // ...but temp-allow is active (non-zero) ⇒ paused
        w.set_app_row(row);
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "x.example.com"), 1),
            Verdict::Allow,
            "an active temp-allow pauses the per-app isolate deny"
        );
    }

    // ---- SLICE 2 — the TempAllow TTL sweep + the RAM⊗NAND durable backing ----

    /// A unique-per-test temp dir under the OS temp root (process-unique counter → collision-free, no rng
    /// dep). Mirrors `runtime_tier.rs:271` / `resolver/cache.rs` `temp_cache_dir`.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("torta-warden-{tag}-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    // ---- SLICE 6 — query-warden.log: the per-pillar verdict feed via the log_tier substrate ----

    /// ★ THE LOG-ONLY BIND (checkpoint 99) — `bind_log_dir` gives the ENFORCING Warden a review log
    /// WITHOUT the state rehydrate `bind_durable` performs. This is the whole reason the two are
    /// separate: the inline `WARDEN_GATE` warden must not silently inherit a persisted matrix as a
    /// side effect of wanting a log file.
    #[test]
    fn bind_log_dir_writes_the_review_log_without_binding_durable() {
        let dir = temp_dir("logonly");
        std::fs::create_dir_all(&dir).unwrap();
        let mut w = Warden::new();
        w.bind_log_dir(dir.clone());

        // No durable tier was bound, so nothing may have been rehydrated.
        assert!(w.durable.is_none(), "bind_log_dir must NOT create a durable tier");

        let mut set = DomainRuleSet::new();
        set.insert(DomainRule { domain: "evil.example".into(), uid: 0, wildcard: true });
        set.finalize();
        w.set_domain_rules(set);

        assert_eq!(w.dns_verdict_logged("evil.example", &[], 1_751_300_000_000), Verdict::Deny);

        let body = std::fs::read_to_string(dir.join(log::QUERY_WARDEN_LOG_NAME))
            .expect("query-warden.log must exist in the log-only bound dir");
        assert!(body.contains("evil.example"), "the denied name must appear: {body}");
    }

    /// THE NEGATIVE CONTROL for the test above. An UNBOUND Warden — no durable tier AND no log dir —
    /// writes nothing at all, and the verdict is unchanged. Without this, the test above would pass
    /// just as happily if `query_warden_log_path` returned some unrelated default path.
    #[test]
    fn an_unbound_warden_writes_no_review_log() {
        let dir = temp_dir("unbound");
        std::fs::create_dir_all(&dir).unwrap();
        let mut w = Warden::new();

        let mut set = DomainRuleSet::new();
        set.insert(DomainRule { domain: "evil.example".into(), uid: 0, wildcard: true });
        set.finalize();
        w.set_domain_rules(set);

        // The verdict still works — the log is a review channel, never the authority.
        assert_eq!(w.dns_verdict_logged("evil.example", &[], 1_751_300_000_000), Verdict::Deny);
        assert!(
            !dir.join(log::QUERY_WARDEN_LOG_NAME).exists(),
            "an UNBOUND warden must write no log at all"
        );
    }

    #[test]
    fn dns_verdict_logged_writes_query_warden_log() {
        // A BOUND Warden writes one human-legible line per DNS-answer verdict to query-warden.log, BESIDE
        // the matrix-state blob in the same app-private durable dir. The blocklist intelligence (the deny
        // reason) is made visible; the pure dns_verdict stays untouched.
        let dir = temp_dir("querylog");
        let mut w = Warden::new();
        w.bind_durable(dir.clone(), 1_000);
        w.set_domain_rules(universal_domain_block(&["ads.evil.net"]));

        // A blocked universal-domain answer → DENY, logged with the `domain` reason.
        assert_eq!(
            w.dns_verdict_logged("ads.evil.net", &[], 1_751_300_000_000),
            Verdict::Deny
        );
        // A clean answer → ALLOW, also logged (the feed records the pass too).
        assert_eq!(
            w.dns_verdict_logged(
                "ok.example.org",
                &["93.184.216.34".parse::<IpAddr>().unwrap()],
                1_751_300_000_001
            ),
            Verdict::Allow
        );

        let log_path = dir.join("query-warden.log");
        let body = std::fs::read_to_string(&log_path).expect("query-warden.log was written");
        assert!(
            body.contains("DENY ads.evil.net domain"),
            "the deny verdict is logged with its reason: {body}"
        );
        assert!(
            body.contains("ALLOW ok.example.org - 93.184.216.34"),
            "the allow verdict is logged with the resolved addr: {body}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dns_verdict_logged_unbound_is_silent_noop() {
        // An UNBOUND Warden (RAM-only) still returns the correct verdict but writes no log (no dir → no
        // path → no file) — the fail-safe: the review channel is best-effort, never a brick.
        let mut w = Warden::new();
        w.set_domain_rules(universal_domain_block(&["ads.evil.net"]));
        assert!(
            w.query_warden_log_path().is_none(),
            "an unbound Warden has no query-warden.log path"
        );
        assert_eq!(
            w.dns_verdict_logged("ads.evil.net", &[], 1_000),
            Verdict::Deny,
            "the verdict is correct even with no log sink"
        );
        assert_eq!(
            w.dns_verdict_logged("ok.example.org", &[], 1_000),
            Verdict::Allow
        );
    }

    #[test]
    fn query_warden_log_path_sits_beside_the_matrix_blob() {
        // The per-pillar log is a sibling of the matrix-state record in the SAME bound app-private dir.
        let dir = temp_dir("logpath");
        let mut w = Warden::new();
        w.bind_durable(dir.clone(), 1_000);
        let path = w.query_warden_log_path().expect("bound ⇒ a log path");
        assert_eq!(path, dir.join("query-warden.log"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn temp_allow_ttl_sweep_resumes_per_app_deny() {
        // RULE19 TTL: a temp-allow pauses the app's per-app deny; the datapath's control-plane
        // `expire_temp_allows(now_ms)` is what makes the TTL REAL (the verdict hot path has no clock).
        const UID: u32 = 10_302;
        let mut w = Warden::new();
        let mut row = AppMatrixRow::new(UID);
        row.mode = AppFirewallMode::Isolate; // would deny a non-LAN conn...
        row.temp_allow_until = 5_000; // ...but paused until t=5000
        w.set_app_row(row);
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "x.example.com"), 1),
            Verdict::Allow,
            "an active temp-allow pauses the isolate deny"
        );
        // A sweep BEFORE the deadline is a no-op — still paused.
        assert_eq!(
            w.expire_temp_allows(4_000),
            0,
            "no expiry before the deadline"
        );
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "x.example.com"), 1),
            Verdict::Allow,
            "still paused before the TTL lapses"
        );
        // A sweep AT/AFTER the deadline clears the pause (flushes the cache) — the deny resumes.
        assert_eq!(
            w.expire_temp_allows(5_000),
            1,
            "the pause expires at the deadline"
        );
        assert_eq!(
            w.matrix.get(UID).unwrap().temp_allow_until,
            0,
            "the swept row's pause is cleared (the ROW is kept — only the TTL'd pause expires)"
        );
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "x.example.com"), 1),
            Verdict::Deny,
            "the isolate deny resumes once the temp-allow TTL lapses"
        );
    }

    #[test]
    fn matrix_durable_round_trips_through_bind() {
        // The RAM⊗NAND backing: bind → mutate (auto-write-through) → a FRESH Warden binds the same dir
        // and rehydrates the EXACT matrix + toggles (the reboot guarantee).
        const UID: u32 = 10_300;
        let dir = temp_dir("roundtrip");
        let mut w = Warden::new();
        assert_eq!(
            w.bind_durable(dir.clone(), 1_000),
            0,
            "cold start ⇒ 0 rows rehydrated"
        );
        let mut row = AppMatrixRow::new(UID);
        row.mode = AppFirewallMode::Isolate;
        row.meteredness = NetClass::Metered;
        w.set_app_row(row); // auto-write-through
        w.set_universal_toggles(UniversalToggles {
            lockdown: true,
            block_http: true,
            ..Default::default()
        }); // auto-write-through

        let mut reborn = Warden::new();
        let restored = reborn.bind_durable(dir.clone(), 1_000);
        assert_eq!(restored, 1, "one row rehydrated across the reboot");
        let got = reborn
            .matrix
            .get(UID)
            .cloned()
            .expect("the row survives the reboot");
        assert_eq!(got.mode, AppFirewallMode::Isolate, "mode round-trips");
        assert_eq!(
            got.meteredness,
            NetClass::Metered,
            "meteredness round-trips"
        );
        assert!(reborn.toggles.lockdown, "the lockdown toggle survives");
        assert!(reborn.toggles.block_http, "the block_http toggle survives");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn temp_allow_expires_across_reboot() {
        // RULE19 TTL across a power-off: a pause that lapsed while the device was OFF is restored EXPIRED
        // (cleared to 0); a still-valid pause is restored INTACT (the resolver-cache wall-clock-drop law).
        const UID: u32 = 10_301;
        let dir = temp_dir("reboot-ttl");
        let mut w = Warden::new();
        w.bind_durable(dir.clone(), 1_000);
        let mut row = AppMatrixRow::new(UID);
        row.mode = AppFirewallMode::Isolate; // would deny non-LAN...
        row.temp_allow_until = 5_000; // ...paused until t=5000
        w.set_app_row(row); // auto-write-through (disk now holds expiry=5000)

        // Reboot at t=6000 (past the pause) → restored expired ⇒ the isolate deny resumes.
        let mut reborn = Warden::new();
        reborn.bind_durable(dir.clone(), 6_000);
        assert_eq!(
            reborn.matrix.get(UID).unwrap().temp_allow_until,
            0,
            "a pause that lapsed while OFF is dropped on reboot"
        );
        assert_eq!(
            reborn.verdict_at(&dns_conn(UID, "x.example.com"), 1),
            Verdict::Deny,
            "the underlying isolate deny resumes after the pause expired across the reboot"
        );

        // Reboot at t=4000 (still within the pause) → restored INTACT (the disk still holds 5000 — the
        // expired reborn above never wrote back).
        let mut early = Warden::new();
        early.bind_durable(dir.clone(), 4_000);
        assert_eq!(
            early.matrix.get(UID).unwrap().temp_allow_until,
            5_000,
            "a still-valid pause survives the reboot intact"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_restore_codec_is_faithful() {
        // The pure codec (no IO): toggles bitfield + every (mode, net) pairing round-trip byte-faithfully.
        let mut w = Warden::new();
        w.set_universal_toggles(UniversalToggles {
            block_new_apps: true,
            block_dns_bypass: true,
            block_http: true,
            ..Default::default()
        });
        let cases = [
            (AppFirewallMode::Isolate, NetClass::Both),
            (AppFirewallMode::Untracked, NetClass::Unmetered),
            (AppFirewallMode::BypassUniversal, NetClass::Metered),
            (AppFirewallMode::BypassDnsFirewall, NetClass::Allow),
            (AppFirewallMode::Exclude, NetClass::Allow),
        ];
        for (i, (mode, net)) in cases.into_iter().enumerate() {
            let mut row = AppMatrixRow::new(10_500 + i as u32);
            row.mode = mode;
            row.meteredness = net;
            row.temp_allow_until = (i as u64) * 1_000;
            w.set_app_row(row);
        }
        let blob = w.snapshot_state();
        let mut reborn = Warden::new();
        let n = reborn.restore_state(&blob, 0); // now_ms=0 keeps every pause
        assert_eq!(n, 5, "all five rows round-trip");
        assert_eq!(
            reborn.toggles, w.toggles,
            "the 9-bit toggle field round-trips exactly"
        );
        for i in 0..5u32 {
            assert_eq!(
                reborn.matrix.get(10_500 + i).cloned(),
                w.matrix.get(10_500 + i).cloned(),
                "row {i} round-trips byte-faithfully"
            );
        }
    }

    #[test]
    fn restore_state_is_failsafe_on_corrupt_input() {
        // Unknown mode/net bytes → inert defaults (None/Allow); forward version → cold start; a truncated
        // tail STOPS the parse without a panic (the bounded-read guard).
        let mut blob = vec![MATRIX_SNAP_VERSION];
        blob.extend_from_slice(&0u16.to_be_bytes()); // toggles: all off
        blob.extend_from_slice(&1u32.to_be_bytes()); // one row
        blob.extend_from_slice(&10_400u32.to_be_bytes()); // uid
        blob.push(99); // an UNKNOWN mode byte
        blob.push(88); // an UNKNOWN net byte
        blob.extend_from_slice(&0u64.to_be_bytes()); // no temp-allow

        let mut w = Warden::new();
        assert_eq!(w.restore_state(&blob, 1_000), 1);
        let got = w.matrix.get(10_400).cloned().unwrap();
        assert_eq!(
            got.mode,
            AppFirewallMode::None,
            "an unknown mode byte ⇒ inert None (fail-safe)"
        );
        assert_eq!(
            got.meteredness,
            NetClass::Allow,
            "an unknown net byte ⇒ inert Allow (fail-safe)"
        );

        let mut w2 = Warden::new();
        let mut fwd = blob.clone();
        fwd[0] = MATRIX_SNAP_VERSION.wrapping_add(9);
        assert_eq!(
            w2.restore_state(&fwd, 1_000),
            0,
            "a forward-version blob is a cold start"
        );
        assert!(w2.matrix.is_empty(), "no rows from a forward-version blob");

        let mut w3 = Warden::new();
        let truncated = &blob[..blob.len() - 4]; // chop into the temp_allow_until field
        assert_eq!(
            w3.restore_state(truncated, 1_000),
            0,
            "a half-row tail is not admitted (the parse stops, no panic)"
        );
    }

    #[test]
    fn v2_rulesets_round_trip_across_a_restart() {
        // #78 W-C: the WHOLE armed posture — matrix + toggles + all FIVE rule-set families (CIDR v4+v6,
        // domain, glob, universal, geo) — survives a snapshot⊗restore byte-faithfully. This is the
        // RAM⊗NAND durability the pillar was missing: a user's blocks no longer vanish on engine restart.
        use std::net::{Ipv4Addr, Ipv6Addr};
        let mut w = Warden::new();

        // --- V1 body (must STILL round-trip under the V2 codec) ---
        w.set_universal_toggles(UniversalToggles {
            lockdown: true,
            block_udp_ntp: true,
            ..Default::default()
        });
        let mut row = AppMatrixRow::new(10_777);
        row.mode = AppFirewallMode::Isolate;
        row.meteredness = NetClass::Metered;
        w.set_app_row(row);

        // --- CIDR: a v4 /24 (exact port + TCP + Block), a v6 /32 (Any port + UDP + Bypass), a v4 /32
        // (exact port + a raw proto number + inert None) — exercises every port/proto/status/family arm. ---
        w.add_cidr_rule(IpRule {
            uid: UID_UNIVERSAL,
            cidr: cidr_match::CidrMatch::V4 {
                net: u32::from(Ipv4Addr::new(198, 51, 100, 0)),
                prefix: 24,
            },
            port: PortSpec::Exact(443),
            proto: ProtoSpec::Tcp,
            status: IpStatus::Block,
        });
        w.add_cidr_rule(IpRule {
            uid: 10_500,
            cidr: cidr_match::CidrMatch::V6 {
                net: u128::from(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)),
                prefix: 32,
            },
            port: PortSpec::Any,
            proto: ProtoSpec::Udp,
            status: IpStatus::Bypass,
        });
        w.add_cidr_rule(IpRule {
            uid: 10_501,
            cidr: cidr_match::CidrMatch::V4 {
                net: u32::from(Ipv4Addr::new(192, 0, 2, 5)),
                prefix: 32,
            },
            port: PortSpec::Exact(53),
            proto: ProtoSpec::Other(1),
            status: IpStatus::None,
        });

        // --- DOMAIN (plain trie): two apex rules under different uids. ---
        let mut dom = DomainRuleSet::default();
        dom.insert(DomainRule {
            domain: "ads.example.com".into(),
            uid: UID_UNIVERSAL,
            wildcard: false,
        });
        dom.insert(DomainRule {
            domain: "tracker.example.net".into(),
            uid: 10_500,
            wildcard: true,
        });
        w.set_domain_rules(dom);

        // --- GLOB patterns (the *-bearing rules). ---
        w.set_domain_globs(vec![
            pattern::validate_pattern("*.doubleclick.example").unwrap(),
            pattern::validate_pattern("*.ads.example.net").unwrap(),
        ]);

        // --- UNIVERSAL rules (order-preserving). ---
        w.set_universal_rules(vec![
            UniversalRule::Lockdown,
            UniversalRule::BlockUdpNtp,
            UniversalRule::BlockUniversalCidr,
        ]);

        // --- GEO country blocks. ---
        w.set_geo_blocks(&["ru".to_string(), "cn".to_string(), "kp".to_string()]);

        // Snapshot → restore into a fresh (cold) Warden, exactly as bind_durable does at boot.
        let blob = w.snapshot_state();
        let mut reborn = Warden::new();
        let n = reborn.restore_state(&blob, 0);

        assert_eq!(n, 1, "the single matrix row rehydrates (the returned metric)");
        assert_eq!(reborn.toggles, w.toggles, "toggles still round-trip under V2");
        assert_eq!(
            reborn.matrix.get(10_777).cloned(),
            w.matrix.get(10_777).cloned(),
            "the matrix row still round-trips under V2"
        );
        assert_eq!(
            reborn.rule_sets.cidr.rules(),
            w.rule_sets.cidr.rules(),
            "every CIDR rule (v4 + v6, all port/proto/status arms) round-trips"
        );
        assert_eq!(
            reborn.rule_sets.domain.rules(),
            w.rule_sets.domain.rules(),
            "every domain rule round-trips"
        );
        let want_globs: Vec<String> = w.rule_sets.glob_domains.iter().map(|p| p.source()).collect();
        let got_globs: Vec<String> = reborn
            .rule_sets
            .glob_domains
            .iter()
            .map(|p| p.source())
            .collect();
        assert_eq!(got_globs, want_globs, "every glob pattern round-trips");
        assert_eq!(
            reborn.universal_rules, w.universal_rules,
            "the universal rule set round-trips (order-preserving)"
        );
        assert_eq!(
            reborn.geo_blocks, w.geo_blocks,
            "the geo country-block set round-trips"
        );
    }

    #[test]
    fn v1_matrix_only_blob_still_restores_under_v2_codec() {
        // A blob written by the PRE-#78 engine (version 1 = MATRIX_SNAP_VERSION_MATRIX_ONLY, matrix +
        // toggles ONLY, NO rule-set sections) must still rehydrate its matrix + toggles — and leave the
        // rule-sets cold. This is the on-disk backward-compat guarantee across an app update.
        let mut v1 = vec![MATRIX_SNAP_VERSION_MATRIX_ONLY];
        let toggles = UniversalToggles {
            lockdown: true,
            block_http: true,
            ..Default::default()
        };
        v1.extend_from_slice(&toggles.to_bits().to_be_bytes());
        v1.extend_from_slice(&1u32.to_be_bytes()); // one row
        v1.extend_from_slice(&10_808u32.to_be_bytes()); // uid
        v1.push(app_mode_to_u8(AppFirewallMode::Isolate));
        v1.push(net_class_to_u8(NetClass::Unmetered));
        v1.extend_from_slice(&0u64.to_be_bytes()); // no temp-allow

        let mut w = Warden::new();
        let n = w.restore_state(&v1, 1_000);
        assert_eq!(n, 1, "the v1 row rehydrates");
        assert_eq!(w.toggles, toggles, "v1 toggles rehydrate under the v2 codec");
        let row = w.matrix.get(10_808).cloned().unwrap();
        assert_eq!(row.mode, AppFirewallMode::Isolate);
        assert_eq!(row.meteredness, NetClass::Unmetered);
        assert!(
            w.rule_sets.cidr.rules().is_empty(),
            "a v1 blob leaves CIDR cold (no v2 section)"
        );
        assert!(
            w.rule_sets.domain.rules().is_empty(),
            "a v1 blob leaves domain cold"
        );
        assert!(
            w.rule_sets.glob_domains.is_empty(),
            "a v1 blob leaves globs cold"
        );
        assert!(w.universal_rules.is_empty(), "a v1 blob leaves universal cold");
        assert!(w.geo_blocks.is_empty(), "a v1 blob leaves geo cold");
    }

    #[test]
    fn every_truncation_of_a_v2_blob_is_panic_free() {
        // The bounded-read guard, fuzzed: a v2 blob carrying all five rule-set families is truncated at
        // EVERY possible length; each prefix must parse without a panic or an OOB read (partial-install
        // correctness is not asserted here — only that a corrupt/short blob NEVER crashes the restore).
        use std::net::Ipv4Addr;
        let mut w = Warden::new();
        w.set_universal_toggles(UniversalToggles {
            lockdown: true,
            ..Default::default()
        });
        let mut row = AppMatrixRow::new(10_909);
        row.mode = AppFirewallMode::Isolate;
        w.set_app_row(row);
        w.add_cidr_rule(IpRule {
            uid: UID_UNIVERSAL,
            cidr: cidr_match::CidrMatch::V4 {
                net: u32::from(Ipv4Addr::new(203, 0, 113, 0)),
                prefix: 24,
            },
            port: PortSpec::Exact(80),
            proto: ProtoSpec::Tcp,
            status: IpStatus::Block,
        });
        let mut dom = DomainRuleSet::default();
        dom.insert(DomainRule {
            domain: "x.example".into(),
            uid: UID_UNIVERSAL,
            wildcard: true,
        });
        w.set_domain_rules(dom);
        w.set_domain_globs(vec![pattern::validate_pattern("*.y.example").unwrap()]);
        w.set_universal_rules(vec![UniversalRule::Lockdown]);
        w.set_geo_blocks(&["ru".to_string()]);

        let blob = w.snapshot_state();
        for cut in 0..=blob.len() {
            let mut reborn = Warden::new();
            let _ = reborn.restore_state(&blob[..cut], 0); // must not panic at ANY truncation point
        }
    }

    #[test]
    fn unbound_matrix_is_ram_only_and_touches_no_disk() {
        // An unbound Warden is RAM-only: mutations never write (write_through_state is a no-op without a
        // tier), and the verdict hot path is unconditionally IO-free.
        const UID: u32 = 10_401;
        let mut w = Warden::new();
        assert!(w.durable.is_none(), "a fresh Warden is unbound (RAM-only)");
        w.set_app_row(AppMatrixRow::new(UID));
        w.set_universal_toggles(UniversalToggles {
            lockdown: true,
            ..Default::default()
        });
        w.expire_temp_allows(9_999);
        assert!(w.durable.is_none(), "still unbound after mutations");
        assert_eq!(w.matrix.len(), 1, "the row lives in RAM");
    }

    #[test]
    fn convenience_predicates() {
        // The inert-baseline / empty-matrix / temp-allow-active convenience predicates (read by the UI +
        // exercised here; the cascade reads the underlying fields directly).
        assert!(
            UniversalToggles::default().is_empty(),
            "all-off toggles are empty"
        );
        assert!(
            !UniversalToggles {
                lockdown: true,
                ..Default::default()
            }
            .is_empty(),
            "any set bit ⇒ not empty"
        );
        assert!(AppMatrix::new().is_empty(), "a fresh matrix holds no rows");
        let mut row = AppMatrixRow::new(10_200);
        assert!(!row.temp_allow_active(1_000), "no temp-allow ⇒ inactive");
        row.temp_allow_until = 2_000;
        assert!(row.temp_allow_active(1_000), "now < expiry ⇒ active");
        assert!(
            !row.temp_allow_active(2_000),
            "now == expiry ⇒ inactive (expired)"
        );
    }

    /// Build a toggle set from a 9-bit index, bit i selecting the toggle at shift i in `to_bits`.
    /// Used only by the exhaustive codec tests below.
    fn toggles_from_index(i: u16) -> UniversalToggles {
        UniversalToggles {
            block_new_apps: i & (1 << 0) != 0,
            block_unknown_conns: i & (1 << 1) != 0,
            block_metered: i & (1 << 2) != 0,
            lockdown: i & (1 << 3) != 0,
            device_lock: i & (1 << 4) != 0,
            block_background: i & (1 << 5) != 0,
            block_udp_ntp: i & (1 << 6) != 0,
            block_http: i & (1 << 7) != 0,
            block_dns_bypass: i & (1 << 8) != 0,
        }
    }

    #[test]
    fn universal_toggle_codec_round_trips_every_one_of_the_512_combinations() {
        // The settings pane writes these nine bits to app_data/runtime_tier/warden-matrix and reads
        // them back at app start. Every bit ARMS A FIREWALL RULE, so a codec slip does not crash and
        // does not look wrong - it silently arms a DIFFERENT rule from the one the user touched.
        //
        // The other toggle tests in this file sample two or three combinations through the blob
        // path; none enumerates the space. This does: all 512, executing the real `to_bits` /
        // `from_bits`. The matching Lean proof (D:\Lean\proofs\Proofs\WardenToggleBits.lean,
        // `round_trip`) settles it for a MODEL of the codec - this test is what binds that model to
        // the code that actually ships.
        for i in 0..512u16 {
            let t = toggles_from_index(i);
            assert_eq!(
                UniversalToggles::from_bits(t.to_bits()),
                t,
                "combination {i:#05x} must survive the write/read round trip"
            );
            // This second assertion is NOT redundant, and mutation testing says which one earns its
            // keep. Transposing two toggles in BOTH `to_bits` and `from_bits` was applied to this
            // file and the round-trip assertion above SURVIVED it - the codec is still a perfect
            // bijection, it just renames the bits. What failed was this line ("the index IS the
            // encoding for combination 8"). The round trip proves the codec is invertible; only the
            // wire value proves it is invertible to the SAME MEANING the last version wrote.
            assert_eq!(t.to_bits(), i, "the index IS the encoding for combination {i}");
            assert!(
                t.to_bits() < 512,
                "the encoding never leaves the 9 bits the format reserves"
            );
        }
    }

    #[test]
    fn universal_toggle_bit_order_is_the_documented_format_contract() {
        // `to_bits` calls its bit order "STABLE (a format contract - never reorder)". A round-trip
        // test CANNOT enforce that: transposing two toggles in BOTH `to_bits` and `from_bits`
        // leaves every round trip green while changing what the persisted record means to the next
        // version. Measured, not assumed - that exact mutation was run against the Lean file and
        // the round-trip theorems survived it. So this test pins the WIRE VALUES instead.
        let cases: [(UniversalToggles, u16); 9] = [
            (UniversalToggles { block_new_apps: true, ..Default::default() }, 1),
            (UniversalToggles { block_unknown_conns: true, ..Default::default() }, 2),
            (UniversalToggles { block_metered: true, ..Default::default() }, 4),
            (UniversalToggles { lockdown: true, ..Default::default() }, 8),
            (UniversalToggles { device_lock: true, ..Default::default() }, 16),
            (UniversalToggles { block_background: true, ..Default::default() }, 32),
            (UniversalToggles { block_udp_ntp: true, ..Default::default() }, 64),
            (UniversalToggles { block_http: true, ..Default::default() }, 128),
            (UniversalToggles { block_dns_bypass: true, ..Default::default() }, 256),
        ];
        for (toggle, wire) in cases {
            assert_eq!(toggle.to_bits(), wire, "the on-disk value for this toggle is fixed by the format");
            assert_eq!(UniversalToggles::from_bits(wire), toggle, "and it decodes back to that toggle alone");
        }
        // The concrete confusion this prevents: RULE6 (block UDP-NTP, driven from the settings pane)
        // must never decode as RULE11 (lockdown), which blocks everything except the allow-list.
        let decoded = UniversalToggles::from_bits(64);
        assert!(decoded.block_udp_ntp, "64 is RULE6");
        assert!(!decoded.lockdown, "64 is NOT lockdown");
        assert_eq!(UniversalToggles::default().to_bits(), 0, "no blocks set encodes to zero");
    }

    #[test]
    fn arming_a_universal_toggle_never_turns_a_deny_into_an_allow() {
        // MONOTONICITY of the TIER-2 cascade, bound to the REAL `verdict_at` rather than a model.
        //
        // Proved for every input in `D:\Lean\proofs\Proofs\WardenUniversalMonotone.lean`
        // (`arming_is_monotone`, axioms: propext + Quot.sound, no sorryAx). A theorem SETTLES the
        // space; this test BINDS that theorem to the code, so the model cannot silently drift from
        // the cascade without a red test here.
        //
        // Why it is the property worth pinning: a firewall whose deny-set is NOT monotone in its
        // armed rules can OPEN A HOLE when the user arms a rule -- the worst failure this component
        // has, and one no round-trip or wire-value test can see. The Lean mutation M48 ("only the
        // FIRST armed rule decides", a realistic refactor of the if-cascade into a find-first) makes
        // exactly that hole and was measured to produce (denies=true, denies_superset=false) on a
        // strict superset. This test is the tripwire for that refactor landing in Rust.
        const UID: u32 = 10_042;
        // Every rule armed, so the `armed(rule)` conjunct is never what is being varied -- the
        // toggle bitfield is. Those are two genuinely different stores on the device (the persisted
        // `warden-matrix` vs the runtime datapath switch) and conflating them caused a false UI
        // instruction at checkpoint 41.
        let all_rules = vec![
            UniversalRule::BlockNewApps,
            UniversalRule::BlockMetered,
            UniversalRule::Lockdown,
            UniversalRule::DeviceLock,
            UniversalRule::BlockBackground,
            UniversalRule::BlockUdpNtp,
            UniversalRule::BlockHttp,
            UniversalRule::BlockDnsBypass,
        ];
        // The fixture set must let EVERY rule fire, or the walk silently cannot see some of them.
        // First cut of this test used only dns_conn + plain_conn -- both dport 443 -- so RULE10
        // (port 80) and RULE6 (UDP/123) could never fire and two of the nine rules went untested
        // while the test still passed. Port-80 and UDP-123 connections are therefore explicit.
        let http_conn = ConnFacts { dport: 80, ..dns_conn(UID, "example.com") };
        let ntp_conn = ConnFacts { dport: 123, proto: 17, ..dns_conn(UID, "example.com") };
        let conns = [
            dns_conn(UID, "example.com"), // resolved, 443  -- RULE7 must NOT fire
            plain_conn(UID),              // qname-less, 443 -- RULE7 fires
            http_conn,                    // RULE10 fires
            ntp_conn,                     // RULE6 fires
        ];
        let mut deny_pairs = 0usize;
        for base in 0u16..512 {
            for bit in 0u16..9 {
                let sup = base | (1 << bit);
                if sup == base {
                    continue; // already set -- not a strict superset, nothing to check
                }
                for conn in &conns {
                    let mut lo = Warden::new();
                    lo.set_universal_rules(all_rules.clone());
                    lo.set_universal_toggles(UniversalToggles::from_bits(base));
                    if lo.verdict_at(conn, 1) != Verdict::Deny {
                        continue;
                    }
                    deny_pairs += 1;
                    let mut hi = Warden::new();
                    hi.set_universal_rules(all_rules.clone());
                    hi.set_universal_toggles(UniversalToggles::from_bits(sup));
                    assert_eq!(
                        hi.verdict_at(conn, 1),
                        Verdict::Deny,
                        "monotonicity violated: toggles {base:#05x} DENIED but the strict superset \
                         {sup:#05x} ALLOWED -- arming a rule opened a hole"
                    );
                }
            }
        }
        // Guard the guard: if the lattice walk stopped producing denies (say `verdict_at` started
        // allowing everything), the loop above would pass vacuously while testing nothing.
        assert!(
            deny_pairs > 1_000,
            "the monotonicity walk observed only {deny_pairs} denying configurations -- too few for \
             the assertion to mean anything; the cascade or the fixtures changed shape"
        );
    }

    #[test]
    fn universal_toggle_decoder_ignores_unknown_high_bits() {
        // The documented fail-safe: "An unknown high bit is IGNORED (a forward-compatible toggle the
        // prior version didn't write is simply off) - a fail-safe, never an over-block." A record
        // written by a FUTURE version with a tenth toggle must decode to the same nine values here,
        // not to a stricter posture the user never chose.
        for i in 0..512u16 {
            let base = UniversalToggles::from_bits(i);
            for high in [0xFE00u16, 0x0200, 0x8000] {
                assert_eq!(
                    UniversalToggles::from_bits(i | high),
                    base,
                    "high bits {high:#06x} must not change the decoded posture for {i:#05x}"
                );
            }
        }
    }

    #[test]
    fn universal_toggle_lockdown_inert_until_rule_armed() {
        // Defense-in-depth: the toggle BIT alone is inert until the matching RULE is armed (a stale
        // settings write cannot deny alone). Bit + armed rule ⇒ TIER 2 deny.
        const UID: u32 = 10_015;
        let mut w = Warden::new();
        w.set_universal_toggles(UniversalToggles {
            lockdown: true,
            ..Default::default()
        });
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "x.example.com"), 1),
            Verdict::Allow,
            "lockdown bit set but the rule UNARMED ⇒ inert"
        );
        w.set_universal_rules(vec![UniversalRule::Lockdown]);
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "x.example.com"), 1),
            Verdict::Deny,
            "lockdown bit + rule armed ⇒ TIER 2 deny"
        );
    }

    #[test]
    fn bypass_universal_skips_tier4_universal_rules() {
        // AppFirewallMode::BypassUniversal skips ONLY TIER 4 (the universal rule-set). The per-app-scoped
        // TIER 3 must NOT re-catch a universal rule (the scoped-matcher fix), else bypass would be a no-op.
        const UID: u32 = 10_016;
        let mut w = Warden::new();
        w.set_domain_rules(universal_domain_block(&["blocked.example.com"]));
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "blocked.example.com"), 1),
            Verdict::Deny,
            "without bypass, a universal-domain rule denies at TIER 4"
        );
        let mut w = Warden::new();
        w.set_domain_rules(universal_domain_block(&["blocked.example.com"]));
        let mut row = AppMatrixRow::new(UID);
        row.mode = AppFirewallMode::BypassUniversal;
        w.set_app_row(row);
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "blocked.example.com"), 1),
            Verdict::Allow,
            "BypassUniversal skips TIER 4 ⇒ the universal rule does NOT deny"
        );
    }

    #[test]
    fn bypass_dns_firewall_skips_tier5_seam() {
        // AppFirewallMode::BypassDnsFirewall skips ONLY TIER 5 (the dns_blocked seam).
        const UID: u32 = 10_017;
        let mut flagged = dns_conn(UID, "ads.example.com");
        flagged.dns_blocked = true;
        let mut w = Warden::new();
        let mut row = AppMatrixRow::new(UID);
        row.mode = AppFirewallMode::BypassDnsFirewall;
        w.set_app_row(row);
        assert_eq!(
            w.verdict_at(&flagged, 1),
            Verdict::Allow,
            "BypassDnsFirewall skips TIER 5 ⇒ the dns_blocked flag does NOT deny"
        );
    }

    #[test]
    fn install_rule_sets_whole_unit_arms_the_cascade() {
        // The whole-unit install_rule_sets seam (the engine's direct fixture path) arms the per-app
        // domain tier; the cascade consults it at TIER 3.
        const UID: u32 = 10_018;
        let rs = WardenRuleSets {
            domain: app_domain_block(UID, &["ads.example.com"]),
            ..Default::default()
        };
        let mut w = Warden::new();
        w.install_rule_sets(rs);
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "ads.example.com"), 1),
            Verdict::Deny,
            "install_rule_sets arms the per-app domain tier ⇒ TIER 3 deny"
        );
        // remove_app_row + re-arm coherence: removing a (non-existent here) row still flushes + recomputes.
        w.remove_app_row(UID);
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "ads.example.com"), 1),
            Verdict::Deny,
            "the domain rule survives a matrix-row removal (rule-sets are independent of the matrix)"
        );
    }

    // ---- CACHE-COHERENCE — a hit equals a fresh compute, across all inputs ----

    #[test]
    fn cache_hit_equals_fresh_compute() {
        const UID: u32 = 10_030;

        // Exhaustive coherence: for a fixed input vector spanning Allow + a deny tier, the SECOND (cached)
        // verdict must equal the first AND a fresh-Warden compute of the same input. Deterministic,
        // std-only stand-in for a property test.
        let mut flagged = dns_conn(UID, "ads.example.com");
        flagged.dns_blocked = true; // TIER 5 deny
        let inputs = [
            dns_conn(UID, "good.example.com"),    // allow-by-default → Allow
            flagged,                              // TIER 5 dns_blocked → Deny
            plain_conn(UID),                      // no-qname, no rule → Allow
            dns_conn(99_999, "good.example.com"), // unruled uid → Allow (allow-by-default)
        ];
        for conn in &inputs {
            let mut warm = Warden::new();
            let first = warm.verdict_at(conn, 7); // computes + caches
            let cached = warm.verdict_at(conn, 7); // must be the cache hit
            let mut fresh = Warden::new();
            let recomputed = fresh.verdict_at(conn, 7); // an independent fresh compute
            assert_eq!(
                first, cached,
                "a cache hit must equal the first compute for {conn:?}"
            );
            assert_eq!(
                cached, recomputed,
                "a cache hit must equal a fresh compute for {conn:?}"
            );
        }
    }

    #[test]
    fn cache_epoch_change_invalidates() {
        // The cache is epoch-gated on the blocklist fingerprint. A dns_blocked (TIER 5) deny cached at
        // epoch 1 must NOT be served at epoch 2 (a blocklist re-arm) — the entry recomputes. dns_blocked
        // is the resolver's per-epoch-deterministic flag, so the epoch IS its coherence signal.
        const UID: u32 = 10_031;
        let mut blocked = dns_conn(UID, "ads.example.com");
        blocked.dns_blocked = true;
        let mut w = Warden::new();
        assert_eq!(
            w.verdict_at(&blocked, 1),
            Verdict::Deny,
            "dns_blocked deny cached at epoch 1"
        );
        // Epoch 2: the resolver no longer flags it (the list changed). SAME cache key (dns_blocked is not
        // part of the key), so a stale serve would return Deny — but the epoch gate forces a recompute → Allow.
        let clean = dns_conn(UID, "ads.example.com");
        assert_eq!(
            w.verdict_at(&clean, 2),
            Verdict::Allow,
            "an epoch change must invalidate the stale verdict (no contradiction)"
        );
    }

    // ---- BOUNDED-CACHE EVICTION — cap holds, LRU evicts the front ----

    #[test]
    fn cache_is_bounded_and_evicts_lru() {
        let mut w = Warden::with_cache_cap(2);
        let conn = |uid| plain_conn(uid);

        // Fill to cap with two distinct connection identities (different UIDs).
        w.verdict_at(&conn(1), 1);
        w.verdict_at(&conn(2), 1);
        assert_eq!(w.cache.len(), 2, "cache filled to cap");

        // Touch uid=1 so uid=2 becomes the LRU.
        w.verdict_at(&conn(1), 1);
        // Insert a third identity → the cap holds at 2 and the LRU (uid=2) is evicted.
        w.verdict_at(&conn(3), 1);
        assert_eq!(w.cache.len(), 2, "cap holds after a 3rd insert");
        assert!(
            w.cache.contains_conn(&conn(1)),
            "the recently-used uid=1 survives"
        );
        assert!(
            w.cache.contains_conn(&conn(3)),
            "the newest uid=3 is present"
        );
        assert!(
            !w.cache.contains_conn(&conn(2)),
            "the LRU uid=2 was evicted"
        );
    }

    #[test]
    fn zero_cap_clamps_to_one() {
        let mut w = Warden::with_cache_cap(0);
        w.verdict_at(&plain_conn(1), 1);
        assert_eq!(
            w.cache.len(),
            1,
            "a 0 cap clamps to 1 (never a no-op cache)"
        );
    }

    // ---- THE OBSERVE-ONLY STATS (slice-1 rework) — allow/deny tally + the per-tier attribution ----

    #[test]
    fn stats_zero_on_fresh_warden() {
        // A freshly-constructed Warden has made no verdict ⇒ every tally is zero (the inert "off" the
        // card shows; the same shape a disarmed/None singleton yields).
        let w = Warden::new();
        assert_eq!(
            w.stats(),
            WardenStats::default(),
            "fresh Warden has zero stats"
        );
        assert_eq!(
            w.stats_json(),
            "{\"configured\":true,\"allow\":0,\"deny\":0,\"deny_by_universal_toggle\":0,\"deny_by_app\":0,\"deny_by_universal_rule\":0,\"deny_by_blocklist\":0}",
            "fresh stats_json is all-zero (counts only, no qname ever)"
        );
    }

    #[test]
    fn stats_tally_allow_and_the_deny_tier_split() {
        const UID: u32 = 10_070;
        const ISO_UID: u32 = 10_079;
        // ONE Warden (distinct conns ⇒ no cache collapse), armed with a universal-domain rule (TIER 4) and
        // a per-app Isolate row (TIER 3) so an allow + three distinct deny tiers (3/4/5) are all in play.
        let mut w = Warden::new();
        w.set_domain_rules(universal_domain_block(&["tracker.example.com"]));
        let mut iso = AppMatrixRow::new(ISO_UID);
        iso.mode = AppFirewallMode::Isolate; // a non-LAN conn for ISO_UID denies at TIER 3
        w.set_app_row(iso);
        // 1. allow-by-default, no rule → Allow
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "good.example.com"), 1),
            Verdict::Allow
        );
        // 2. TIER 4 universal-domain rule → Deny (deny_by_universal_rule)
        assert_eq!(
            w.verdict_at(&dns_conn(UID, "tracker.example.com"), 1),
            Verdict::Deny
        );
        // 3. TIER 5 dns_blocked → Deny (deny_by_blocklist)
        let mut flagged = dns_conn(UID, "ads.example.com");
        flagged.dns_blocked = true;
        assert_eq!(w.verdict_at(&flagged, 1), Verdict::Deny);
        // 4. TIER 3 per-app Isolate (a non-LAN conn for the isolated UID) → Deny (deny_by_app)
        assert_eq!(
            w.verdict_at(&dns_conn(ISO_UID, "good.example.com"), 1),
            Verdict::Deny
        );

        let s = w.stats();
        assert_eq!(s.allow, 1, "one allow tallied");
        assert_eq!(s.deny, 3, "three denies tallied");
        assert_eq!(
            s.deny_by_universal_rule, 1,
            "the TIER-4 deny attributed to the universal rule"
        );
        assert_eq!(
            s.deny_by_blocklist, 1,
            "the TIER-5 dns_blocked deny attributed to the blocklist seam"
        );
        assert_eq!(
            s.deny_by_app, 1,
            "the TIER-3 per-app isolate deny attributed to the app tier"
        );
        assert_eq!(
            s.deny_by_universal_toggle, 0,
            "no universal-toggle deny in this run"
        );
        // The load-bearing invariant: a deny is attributed to EXACTLY one tier (first-match-wins).
        assert_eq!(
            s.deny_by_universal_toggle
                + s.deny_by_app
                + s.deny_by_universal_rule
                + s.deny_by_blocklist,
            s.deny,
            "the per-tier counts sum to deny (exactly-one-tier attribution)"
        );
    }

    #[test]
    fn stats_first_match_attribution() {
        // When MULTIPLE tiers would deny (a universal-domain rule AND the dns_blocked seam), the FIRST tier
        // in the cascade wins the attribution (first-match-DENY) — never double-counted.
        const UID: u32 = 10_071;
        let mut w = Warden::new();
        w.set_domain_rules(universal_domain_block(&["ads.example.com"])); // TIER 4 denies
        let mut conn = dns_conn(UID, "ads.example.com");
        conn.dns_blocked = true; // TIER 5 would ALSO deny
        assert_eq!(w.verdict_at(&conn, 1), Verdict::Deny);
        let s = w.stats();
        assert_eq!(s.deny, 1, "one deny");
        assert_eq!(
            s.deny_by_universal_rule, 1,
            "first-match: the universal rule (TIER 4) wins before the TIER-5 seam"
        );
        assert_eq!(s.deny_by_app, 0);
        assert_eq!(s.deny_by_universal_toggle, 0);
        assert_eq!(s.deny_by_blocklist, 0, "not double-counted on TIER 5");
    }

    #[test]
    fn stats_cache_hit_does_not_recount() {
        // A cache-HIT replay must NOT re-increment the tallies (stats reflect COMPUTED verdicts).
        const UID: u32 = 10_072;
        let mut w = Warden::new();
        let conn = dns_conn(UID, "good.example.com");
        assert_eq!(w.verdict_at(&conn, 1), Verdict::Allow); // computes + caches + tallies
        assert_eq!(w.verdict_at(&conn, 1), Verdict::Allow); // cache HIT — must NOT re-tally
        assert_eq!(
            w.stats().allow,
            1,
            "a cache-hit replay does not re-count the allow"
        );
        assert_eq!(w.stats().deny, 0, "no deny");
    }

    #[test]
    fn stats_json_carries_no_qname_or_domain() {
        // PRIVACY: the serialized stats are AGGREGATE COUNTS ONLY — never a qname/domain string leaks.
        const UID: u32 = 10_075;
        let secret_domain = "super-secret-private-domain.example";
        let mut w = Warden::new();
        w.set_domain_rules(universal_domain_block(&[secret_domain]));
        let _ = w.verdict_at(&dns_conn(UID, secret_domain), 1); // a universal-rule deny
        let json = w.stats_json();
        assert!(
            !json.contains(secret_domain) && !json.contains("example"),
            "the stats JSON must NEVER contain a qname/domain ({json})"
        );
        assert!(
            json.contains("\"deny\":1"),
            "but the aggregate deny count is present ({json})"
        );
    }

    // ---- THE PUBLIC verdict() — the production path (pure firewall + the LIVE blocklist epoch) ----

    /// Serialize the tests that mutate the process-shared blocklist `GLOBAL`, the `blocklist.rs:594`
    /// idiom (recover from poison so one panicking test cannot wedge the rest).
    static GLOBAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn public_verdict_is_pure_firewall_at_the_live_epoch() {
        let _guard = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        const UID: u32 = 10_060;

        // The public `verdict()` is PURE FIREWALL (no blocklist param) and pulls the cache EPOCH live from
        // `crate::blocklist::installed_fingerprint`. Install a NON-empty global list so the live
        // fingerprint is non-zero — this proves `verdict()` reads the real epoch, not a hardcoded 0.
        // `false` = replace (not merge).
        let (_n, fp) = crate::blocklist::compile_and_install_text("ads.example.com\n", false);
        assert_ne!(
            fp, 0,
            "the installed list must yield a non-zero live fingerprint (the epoch)"
        );

        let mut w = Warden::new();
        // Allow-by-default: an unruled conn passes (the blocklist is the resolver's SEPARATE gate now).
        assert_eq!(
            w.verdict(&dns_conn(UID, "good.example.com")),
            Verdict::Allow,
            "public verdict() must Allow an unruled conn (allow-by-default)"
        );
        // The TIER-5 dns_blocked seam denies via the live-epoch path.
        let mut flagged = dns_conn(UID, "ads.example.com");
        flagged.dns_blocked = true;
        assert_eq!(
            w.verdict(&flagged),
            Verdict::Deny,
            "public verdict() must Deny a dns_blocked conn (the resolver seam, TIER 5)"
        );
    }
}

// ===========================================================================================
// W-A rule-set layer tests (host cargo — the pure-Rust matcher proofs: domain trie, CIDR
// lookup, port/proto filters, temp-allow TTL). A SEPARATE `mod wa_tests` so it never collides
// with the engine `mod tests` helpers; exercises EVERY W-A matcher (incl. the ones the
// `WardenObject` does not yet call — `contains`/`accepts`/`lookup`/`matches`/`is_active`).
// ===========================================================================================

#[cfg(test)]
mod wa_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// A host-order v4 `u32` as the [`IpAddr`] the lookups take (`Ipv4Addr::from(u32)` reads the
    /// same big-endian/host-order convention the rules' `net: u32` uses).
    fn v4(ip: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(ip))
    }

    fn dom(domain: &str, uid: u32) -> DomainRule {
        DomainRule {
            domain: domain.into(),
            uid,
            wildcard: true,
        }
    }

    #[test]
    fn empty_rule_sets_match_nothing_and_have_zero_fingerprint() {
        let d = DomainRuleSet::new();
        assert!(d.is_empty());
        assert_eq!(d.len(), 0);
        assert_eq!(d.fingerprint(), 0);
        assert!(!d.matches(10_001, "anything.example.com"));

        let c = CidrRuleSet::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        assert_eq!(c.fingerprint(), 0);
        assert_eq!(c.lookup(10_001, v4(0x0A00_0005), 443, 6), None);
    }

    #[test]
    fn domain_rule_matches_apex_and_every_subdomain() {
        let mut d = DomainRuleSet::new();
        d.insert(dom("ads.example.com", 10_001));
        d.finalize();
        assert_eq!(d.len(), 1);
        // apex + subdomains (wildcard-at-apex)
        assert!(d.matches(10_001, "ads.example.com"));
        assert!(d.matches(10_001, "track.ads.example.com"));
        // a sibling / parent that is NOT under the apex
        assert!(!d.matches(10_001, "example.com"));
        assert!(!d.matches(10_001, "notads.example.com"));
    }

    #[test]
    fn domain_rule_is_case_insensitive_and_dot_trimmed() {
        let mut d = DomainRuleSet::new();
        d.insert(dom("Ads.Example.COM.", 10_001));
        d.finalize();
        assert!(d.matches(10_001, "ADS.EXAMPLE.com"));
        assert!(d.matches(10_001, "x.ads.example.com."));
    }

    #[test]
    fn domain_universal_tier_applies_to_every_app_but_per_app_is_isolated() {
        let mut d = DomainRuleSet::new();
        d.insert(dom("global-ad.example", UID_UNIVERSAL)); // universal
        d.insert(dom("perapp.example", 10_001)); // per-app
        d.finalize();
        assert_eq!(d.len(), 2);
        // universal applies to ANY uid
        assert!(d.matches(10_001, "global-ad.example"));
        assert!(d.matches(99_999, "global-ad.example"));
        // per-app rule is isolated to its uid
        assert!(d.matches(10_001, "perapp.example"));
        assert!(!d.matches(10_002, "perapp.example"));
    }

    #[test]
    fn domain_canonical_parent_subsumes_children() {
        let mut d = DomainRuleSet::new();
        d.insert(dom("example.com", 10_001)); // apex
        d.insert(dom("sub.example.com", 10_001)); // subsumed by the apex ⇒ no new terminal
        d.finalize();
        assert_eq!(d.len(), 1, "the child is subsumed by the parent apex");
        assert!(d.matches(10_001, "sub.example.com"));
    }

    #[test]
    fn domain_fingerprint_is_order_independent() {
        let mut a = DomainRuleSet::new();
        a.insert(dom("a.test", 10_001));
        a.insert(dom("b.test", 10_001));
        a.finalize();
        let mut b = DomainRuleSet::new();
        b.insert(dom("b.test", 10_001));
        b.insert(dom("a.test", 10_001));
        b.finalize();
        assert_eq!(
            a.fingerprint(),
            b.fingerprint(),
            "XOR-fold is order-independent"
        );
        assert_ne!(a.fingerprint(), 0);
    }

    #[test]
    fn cidr_fingerprint_folds_high_octet_ips_d39() {
        // D39 regression: two single-rule CIDR sets differing ONLY in a high-octet IP (an octet ≥ 0x80,
        // NOT valid UTF-8) MUST produce different fingerprints. Before D39 the `(uid, net)` fold went
        // through `str::from_utf8(&buf).unwrap_or("")`, which degraded to hashing "" for such IPs — so the
        // digest ignored ip+prefix and these two sets collided (the "rule-set changed" signal lied).
        let rule = |net: u32| IpRule {
            uid: UID_UNIVERSAL,
            cidr: cidr_match::CidrMatch::V4 { net, prefix: 32 },
            port: PortSpec::Any,
            proto: ProtoSpec::Any,
            status: IpStatus::Block,
        };
        // 200.0.0.1 (0xC8..) and 201.0.0.1 (0xC9..) — both lead with a high octet (≥ 0x80).
        let mut a = CidrRuleSet::new();
        a.insert(rule(0xC800_0001));
        a.finalize();
        let mut b = CidrRuleSet::new();
        b.insert(rule(0xC900_0001));
        b.finalize();
        assert_ne!(
            a.fingerprint(),
            b.fingerprint(),
            "high-octet IPs must not collide (the pre-D39 UTF-8-gate no-op)"
        );
        assert_ne!(a.fingerprint(), 0, "a non-empty set has a non-zero digest");
        // Sanity: the same IP still fingerprints identically (order/format independence preserved).
        let mut c = CidrRuleSet::new();
        c.insert(rule(0xC800_0001));
        c.finalize();
        assert_eq!(a.fingerprint(), c.fingerprint(), "same rule → same digest");
    }

    #[test]
    fn cidr_contains_honors_prefix_boundaries() {
        // The rules' matcher IS `cidr_match::CidrMatch` since A3 — prove the boundary semantics
        // hold through the rule-set's own type (deeper family coverage lives in cidr_match.rs).
        use cidr_match::CidrMatch;
        // /0 matches everything (v4).
        assert!(CidrMatch::V4 { net: 0, prefix: 0 }.matches(v4(0xDEAD_BEEF)));
        // /8 on 10.0.0.0
        let c = CidrMatch::V4 {
            net: 0x0A00_0000,
            prefix: 8,
        };
        assert!(c.matches(v4(0x0A00_0005))); // 10.0.0.5
        assert!(c.matches(v4(0x0AFF_FFFF))); // 10.255.255.255
        assert!(!c.matches(v4(0x0B00_0000))); // 11.0.0.0
                                              // /32 exact
        let e = CidrMatch::V4 {
            net: 0xC0A8_0101,
            prefix: 32,
        };
        assert!(e.matches(v4(0xC0A8_0101)));
        assert!(!e.matches(v4(0xC0A8_0102)));
        // family isolation: a v4 CIDR NEVER matches a v6 addr (even the v4-mapped form).
        assert!(!c.matches(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0005))));
    }

    #[test]
    fn proto_and_port_filters_accept_correctly() {
        assert!(ProtoSpec::Any.accepts(6));
        assert!(ProtoSpec::Any.accepts(17));
        assert!(ProtoSpec::Tcp.accepts(6));
        assert!(!ProtoSpec::Tcp.accepts(17));
        assert!(ProtoSpec::Udp.accepts(17));
        assert!(!ProtoSpec::Udp.accepts(6));
        assert!(ProtoSpec::Other(1).accepts(1));
        assert!(!ProtoSpec::Other(1).accepts(6));
        assert!(PortSpec::Any.accepts(0));
        assert!(PortSpec::Any.accepts(443));
        assert!(PortSpec::Exact(80).accepts(80));
        assert!(!PortSpec::Exact(80).accepts(443));
    }

    fn ip_rule(
        uid: u32,
        net: u32,
        prefix: u8,
        port: PortSpec,
        proto: ProtoSpec,
        status: IpStatus,
    ) -> IpRule {
        IpRule {
            uid,
            cidr: cidr_match::CidrMatch::V4 { net, prefix },
            port,
            proto,
            status,
        }
    }

    #[test]
    fn cidr_lookup_block_bypass_and_filters() {
        let mut c = CidrRuleSet::new();
        // Block 10.0.0.0/8 any port/proto for uid 10_001.
        c.insert(ip_rule(
            10_001,
            0x0A00_0000,
            8,
            PortSpec::Any,
            ProtoSpec::Any,
            IpStatus::Block,
        ));
        // Bypass a universal /0 on TCP:443.
        c.insert(ip_rule(
            UID_UNIVERSAL,
            0,
            0,
            PortSpec::Exact(443),
            ProtoSpec::Tcp,
            IpStatus::Bypass,
        ));
        c.finalize();
        assert_eq!(c.len(), 2);
        // per-app BLOCK hit
        assert_eq!(
            c.lookup(10_001, v4(0x0A00_0005), 12345, 6),
            Some(CidrHit::Block)
        );
        // outside the per-app CIDR → falls to universal; TCP:443 ⇒ Bypass
        assert_eq!(
            c.lookup(10_001, v4(0x0808_0808), 443, 6),
            Some(CidrHit::Bypass)
        );
        // universal bypass is port/proto-gated: UDP:443 ⇒ no hit
        assert_eq!(c.lookup(10_001, v4(0x0808_0808), 443, 17), None);
        // a different app sees ONLY the universal rule (per-app isolation)
        assert_eq!(c.lookup(10_002, v4(0x0A00_0005), 12345, 6), None);
    }

    #[test]
    fn cidr_inert_none_status_is_skipped() {
        let mut c = CidrRuleSet::new();
        c.insert(ip_rule(
            10_001,
            0x0A00_0000,
            8,
            PortSpec::Any,
            ProtoSpec::Any,
            IpStatus::None,
        ));
        c.finalize();
        // an inert (None) rule never fires.
        assert_eq!(c.lookup(10_001, v4(0x0A00_0005), 443, 6), None);
    }

    #[test]
    fn most_specific_rule_wins_regardless_of_insertion_order() {
        // A3 regression: pre-A3 the bucket scanned in INSERTION order, so a broad /0 Bypass
        // authored first swallowed a /32 Block authored later. finalize() now sorts prefix DESC —
        // the /32 must win in BOTH authoring orders.
        let broad = ip_rule(
            UID_UNIVERSAL,
            0,
            0,
            PortSpec::Any,
            ProtoSpec::Any,
            IpStatus::Bypass,
        );
        let host = ip_rule(
            UID_UNIVERSAL,
            0xC0A8_0101,
            32,
            PortSpec::Any,
            ProtoSpec::Any,
            IpStatus::Block,
        );
        for order in [[&broad, &host], [&host, &broad]] {
            let mut c = CidrRuleSet::new();
            for r in order {
                c.insert(r.clone());
            }
            c.finalize();
            assert_eq!(
                c.lookup(UID_UNIVERSAL, v4(0xC0A8_0101), 443, 6),
                Some(CidrHit::Block),
                "/32 Block beats /0 Bypass regardless of authoring order"
            );
            // off the /32 the /0 Bypass still answers.
            assert_eq!(
                c.lookup(UID_UNIVERSAL, v4(0xC0A8_0102), 443, 6),
                Some(CidrHit::Bypass)
            );
        }
    }

    #[test]
    fn v6_rule_matches_v6_and_never_v4() {
        // A3: a v6 CIDR rule is a first-class rule-set citizen — matches in-range v6, abstains
        // out-of-range v6, and NEVER crosses into v4.
        let mut c = CidrRuleSet::new();
        c.insert(IpRule {
            uid: 10_001,
            cidr: cidr_match::CidrMatch::V6 {
                net: u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                prefix: 32,
            },
            port: PortSpec::Any,
            proto: ProtoSpec::Any,
            status: IpStatus::Block,
        });
        c.finalize();
        let in_range = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xBEEF, 0, 0, 0, 0, 1));
        let out_of_range = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1));
        assert_eq!(c.lookup(10_001, in_range, 443, 6), Some(CidrHit::Block));
        assert_eq!(c.lookup(10_001, out_of_range, 443, 6), None);
        assert_eq!(
            c.lookup(10_001, v4(0x2001_0db8), 443, 6),
            None,
            "a v6 rule never matches a v4 addr, even one sharing the leading bits"
        );
    }

    #[test]
    fn fingerprint_separates_v4_and_v6_rules_with_equal_net_bits() {
        // The digest folds a FAMILY byte (finalize), so a v4 rule and the numerically-equal v6
        // rule hash apart — else swapping one for the other would go unnoticed by change detection.
        let mut a = CidrRuleSet::new();
        a.insert(ip_rule(
            10_001,
            1,
            16,
            PortSpec::Any,
            ProtoSpec::Any,
            IpStatus::Block,
        ));
        a.finalize();
        let mut b = CidrRuleSet::new();
        b.insert(IpRule {
            uid: 10_001,
            cidr: cidr_match::CidrMatch::V6 { net: 1, prefix: 16 },
            port: PortSpec::Any,
            proto: ProtoSpec::Any,
            status: IpStatus::Block,
        });
        b.finalize();
        assert_ne!(
            a.fingerprint(),
            b.fingerprint(),
            "family byte keeps V4{{net:1}} and V6{{net:1}} digests apart"
        );
    }

    #[test]
    fn cidr_dedup_drops_identical_rule() {
        let mut c = CidrRuleSet::new();
        let r = ip_rule(
            10_001,
            0x0A00_0000,
            8,
            PortSpec::Any,
            ProtoSpec::Any,
            IpStatus::Block,
        );
        c.insert(r.clone());
        c.insert(r);
        c.finalize();
        assert_eq!(
            c.len(),
            1,
            "an identical (uid,cidr,port,proto,status) rule is dropped"
        );
    }

    #[test]
    fn temp_allow_ttl_is_active_window_only() {
        // disabled (expiry 0) is never active
        assert!(!TempAllow::new(10_001, 0).is_active(123));
        // active before expiry, inert at/after
        let t = TempAllow::new(10_001, 1_000);
        assert!(t.is_active(999));
        assert!(!t.is_active(1_000));
        assert!(!t.is_active(1_001));
    }

    #[test]
    fn universal_rule_variants_are_distinct() {
        // a smoke proof the BLOCK-only enum variants compare by identity (no trust variant exists).
        assert_ne!(UniversalRule::Lockdown, UniversalRule::BlockMetered);
        assert_eq!(UniversalRule::BlockHttp, UniversalRule::BlockHttp);
    }
}
