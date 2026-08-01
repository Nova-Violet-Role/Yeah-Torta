/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! N5 — TORTÄ SHAPING over REAL forwarded flows (the Beast leaves the DNS-probe cage).
//!
//! The Beast engine ([`crate::beast`]) was born pacing DNS *probes*: its CAKE key is
//! `(endpoint_idx, qname)` (`scheduler.rs:1026`) and its YeAH window paces probe dispatch. N5 is the
//! GENESIS widening — the SAME flagship engine judged over the netstack's REAL flows:
//!
//!   - **The widened CAKE key**: [`flow_key`] folds the full 5-tuple [`SessionKey`] through the SAME
//!     FNV-ish law the pinned scheduler uses (seed `1125899906842597`, `h = 31·h + component` —
//!     `scheduler.rs:1027-1031`), so a real TCP/UDP flow gets the same 64-bit identity a probe flow
//!     gets. The pinned scheduler is NOT touched: its `(endpoint_idx, qname)` law stays byte-exact
//!     for the DNS-probe plane; this is the parallel law for the forwarded plane.
//!   - **The tin classifier**: [`tin_for_flow`] maps destination port → [`ProbePriority`] tin —
//!     DNS-plane (53/853) CRITICAL (floor-protected, the resolver heartbeat), interactive web
//!     (443/80/22) HIGH (page-load latency class), everything else NORMAL (bulk).
//!   - **The pacer**: [`FlowShaper`] owns ONE [`YeahController`] per flow on the LineRate brain
//!     (Rung C — UDP samples are first-class, per-family RTT floors), fed by REAL flow RTT
//!     (upstream write-drain latency), and answers [`FlowShaper::write_budget`] — cwnd (1..16)
//!     segments per burst — which the forwarder loop uses to pace BULK splice writes
//!     (`run.rs`: NORMAL-tin TCP flows are budget-paced; CRITICAL/HIGH run unshaped, latency-first).
//!
//! Pure logic — no sockets, no unix — so the whole module is host-testable (the beast discipline).

use std::net::SocketAddr;

use crate::beast::yeah::YeahController;
use crate::beast::ProbePriority;

use super::session::{Proto, SessionKey};

/// Fixed IPv4 + TCP header cost that a segment must leave room for inside one tun packet.
///
/// 20 B IPv4 (no options) + 20 B TCP (no options). Timestamps/SACK push the real TCP header to 32 B,
/// so 40 is the FLOOR of the overhead and a segment sized against it is the largest that can ever
/// fit — which is why the derivation below subtracts it rather than something more optimistic.
pub(crate) const IPV4_TCP_HEADER_BYTES: usize = 40;

/// One paced write segment (bytes) — DERIVED from the tun MTU, never assumed.
///
/// THE BUG THIS REPLACES, and it is the reason changing `VPN_MTU` alone did not fix
/// ERR_CONNECTION_CLOSED. This constant was `1448`, documented as "the classic TCP MSS over an
/// IPv4/**1500**-MTU path". The tun is 1400. So every full-size paced segment was 1448 + 40 = 1488
/// bytes on a 1400-byte interface — 88 bytes over, on every single one. Small packets (DNS, 60-100 B)
/// always fit, which is exactly why the failure looked site-dependent rather than size-dependent and
/// hid behind a perfectly green resolver ledger for three weeks.
///
/// MEASURED ATTRIBUTION (the control that finally pinned it): the identical 111-URL Brave Nightly run
/// with Tortä ENTIRELY out of the path (app force-stopped, `tun0` absent, no VPN transport) produced
/// `handshake failed` = **0**; with the tunnel up at a verified MTU of 1400 it produced **570**. The
/// AVD's network is therefore exonerated and the datapath owns the failure. MTU 1500 -> 1400 could
/// never have been sufficient on its own, because this constant did not move with it.
///
/// Now derived, so the two can no longer disagree: 1400 - 40 = 1360.
///
/// PROVED FOR ALL MTUs in `D:/Lean/proofs/Proofs/SegmentFitsMtu.lean`:
/// `segment_plus_headers_never_exceeds_mtu`, `the_old_constant_overflowed_the_tun`,
/// `derived_segment_is_monotone_in_mtu`, `a_derived_segment_always_fits`.
pub(crate) const SHAPE_SEGMENT_BYTES: usize =
    crate::tunnel::TUN_MTU_CEILING - IPV4_TCP_HEADER_BYTES;

/// Destination-port → Tortä tin (the N5 DiffServ demux at the flow seam).
///
/// CRITICAL — the DNS plane: `:53` (the demux port, answered in-loop but classified here for the
/// session map) and `:853` (DoT an app dials directly). The CRITICAL tin is floor-protected in the
/// beast AQM; the same contract holds here: the resolver heartbeat is never starved by bulk.
/// HIGH — the interactive page-load class: `:443` (TLS + QUIC/HTTP3), `:80` (HTTP), `:22` (SSH —
/// a keystroke flow is the canonical interactive victim of bufferbloat, the CAKE motivation).
/// NORMAL — everything else: bulk transfer, torrents, updates. Only this tin is budget-paced.
pub(crate) fn tin_for_flow(key: &SessionKey) -> ProbePriority {
    match key.dst_port() {
        53 | 853 => ProbePriority::Critical,
        443 | 80 | 22 => ProbePriority::High,
        _ => ProbePriority::Normal,
    }
}

/// The WIDENED CAKE key: 5-tuple [`SessionKey`] → 64-bit flow key. The SAME FNV-ish law as the
/// pinned probe-plane `flow_key(endpoint_idx, qname)` (`scheduler.rs:1026-1033` — seed
/// `1125899906842597`, `h = 31·h + component`), folded over `proto · src(ip,port) · dst(ip,port)`
/// instead of `(endpoint_idx, qname)`. Deterministic; a different sport is a DIFFERENT flow.
pub(crate) fn flow_key(key: &SessionKey) -> i64 {
    let mut h: i64 = 1125899906842597; // FNV-ish seed (scheduler.rs:1027, verbatim)
    h = 31i64
        .wrapping_mul(h)
        .wrapping_add(key.proto.ip_number() as i64);
    h = fold_addr(h, &key.src);
    fold_addr(h, &key.dst)
}

/// Fold one `ip:port` endpoint into the running key (octets then port, the same 31·h+c step).
fn fold_addr(mut h: i64, addr: &SocketAddr) -> i64 {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            for b in ip.octets() {
                h = 31i64.wrapping_mul(h).wrapping_add(b as i64);
            }
        }
        std::net::IpAddr::V6(ip) => {
            for b in ip.octets() {
                h = 31i64.wrapping_mul(h).wrapping_add(b as i64);
            }
        }
    }
    31i64.wrapping_mul(h).wrapping_add(addr.port() as i64)
}

/// ONE real flow's shaping state: its tin, its widened CAKE key, and its OWN YeAH window.
///
/// Per-flow controller (not the shared probe-plane Beast): each forwarded flow's cwnd learns from
/// THAT flow's real RTT — the LineRate brain (per-family floors, kernel-grade hysteresis) judging
/// real bytes instead of probe transactions. This is the surpassing move: firestack shapes nothing
/// (gVisor forwards flat-out); the Windows nautilus-rs shapes only probes. Tortä paces real bulk.
pub(crate) struct FlowShaper {
    tin: ProbePriority,
    key: i64,
    proto: Proto,
    yeah: YeahController,
}

impl FlowShaper {
    /// Classify + key the flow and seed a fresh window on the user's chosen YeAH brain (LineRate by
    /// default — the born state) carrying the user's live Expert tunables. The SETTINGS pick governs the
    /// REAL per-flow shaping, not just the telemetry Beast: [`crate::beast::live_yeah_profile`] +
    /// [`crate::beast::apply_live_tune`] read the process-global tune the apply/restore path broadcasts.
    /// cwnd still starts at MIN_WINDOW=1 (slow-start over the real flow, exactly the YeAH birth state).
    pub(crate) fn new(session: &SessionKey) -> Self {
        let mut yeah = YeahController::with_profile(crate::beast::live_yeah_profile());
        crate::beast::apply_live_tune(&mut yeah);
        Self {
            tin: tin_for_flow(session),
            key: flow_key(session),
            proto: session.proto,
            yeah,
        }
    }

    pub(crate) fn tin(&self) -> ProbePriority {
        self.tin
    }

    /// The widened CAKE key (the session map + the N6 snapshot read this).
    pub(crate) fn key(&self) -> i64 {
        self.key
    }

    /// The live YeAH window (1..16 segments) — exposed for the N6 ForwarderSnapshot.
    ///
    /// ★ Rung D — THE PLANE YOU FEED IS THE PLANE YOU PACE. A UDP flow's samples go to the
    /// independent UDP brain (`sample()` below), so its budget must be read from that same brain.
    /// Reading `yeah.cwnd()` for a UDP flow would pace it off the TCP window it never feeds — which
    /// pins every UDP flow at MIN_WINDOW forever, since nothing ever grows that window. That is
    /// exactly the defect the split introduced here and this is the fix; the law is proved for all
    /// flows in `D:/Lean/proofs/Proofs/ShaperPlane.lean::the_budget_tracks_the_fed_plane`.
    pub(crate) fn cwnd(&self) -> i32 {
        match self.proto {
            Proto::Udp => self.yeah.udp_cwnd(),
            // TCP and the (never-shaped) ICMP arm read the TCP-family window.
            Proto::Tcp | Proto::Icmp => self.yeah.cwnd(),
        }
    }

    /// This flow's window ceiling as it landed on the controller — test-only witness that the live
    /// SETTINGS tune (window override) reached the per-flow shaper, not just the telemetry Beast.
    #[cfg(test)]
    pub(crate) fn max_window(&self) -> i32 {
        self.yeah.max_window()
    }

    /// The paced write budget in BYTES for the next bulk burst: `cwnd × SHAPE_SEGMENT_BYTES`.
    /// Floor-clamped to one segment (the YeAH MIN_WINDOW law — a flow is never starved to zero).
    pub(crate) fn write_budget(&self) -> usize {
        // Through `self.cwnd()`, never `self.yeah.cwnd()` — the per-plane accessor above. Reading the
        // controller field directly here is precisely how a UDP flow got paced off a window it never
        // fed; the test `a_udp_flow_paces_off_the_udp_window_it_feeds` caught exactly this line.
        (self.cwnd().max(1) as usize) * SHAPE_SEGMENT_BYTES
    }

    /// Feed ONE real RTT sample (ms) measured on the flow (upstream write-drain latency). TCP flows
    /// feed the TCP-family brain; UDP flows the first-class UDP-family (the LineRate per-family
    /// floors — no cross-family poisoning).
    pub(crate) fn sample(&mut self, rtt_ms: f64) {
        match self.proto {
            Proto::Tcp => self.yeah.apply(rtt_ms),
            Proto::Udp => self.yeah.apply_udp(rtt_ms),
            // ★ #51 — an ICMP echo is a one-shot probe, not a byte stream: it has no window to
            // grow and no queue to drain, so feeding its RTT to a YeAH brain would teach the
            // congestion controller from a flow it never paces. The echo lane builds its docket
            // row directly (`forwarder::icmp`) and never constructs a shaper; this arm exists so
            // the match stays exhaustive if that ever changes.
            Proto::Icmp => {}
        }
    }

    /// A stall/error on the flow — the YeAH loss reaction (LineRate: `cwnd -= clamp(Q̄, cwnd/8, cwnd/2)`).
    pub(crate) fn on_stall(&mut self) {
        // ★ Rung D — a UDP flow's stall is a UDP loss event and must reduce the UDP window. Calling
        // the TCP entry here would let a stalled UDP flow shed the TCP flows' window while leaving
        // its own untouched: the loss half of the same cross-talk the split abolished.
        match self.proto {
            Proto::Udp => self.yeah.on_udp_loss_or_timeout(),
            Proto::Tcp | Proto::Icmp => self.yeah.on_loss_or_timeout(),
        }
    }

    /// ★ #22 slice 3 · N7 — the flow's live adaptive answer window (ms): `max(500, base_rtt×2.5)`,
    /// 2000 before the first sample ([`YeahController::adaptive_timeout_ms`]). The UDP paced lane
    /// arms its transaction-loss ear with this — a request unanswered past the window IS the UDP
    /// loss event (the first UDP congestion algorithm's loss sense, end-to-end).
    pub(crate) fn adaptive_timeout_ms(&self) -> i32 {
        self.yeah.adaptive_timeout_ms(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beast::YeahProfile;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn v4(a: [u8; 4], p: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a[0], a[1], a[2], a[3]), p))
    }

    fn key_to(port: u16, proto: Proto) -> SessionKey {
        SessionKey::new(proto, v4([10, 1, 10, 1], 40000), v4([1, 2, 3, 4], port))
    }

    fn v6(seg: [u16; 8], p: u16) -> SocketAddr {
        SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::new(
                seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
            ),
            p,
            0,
            0,
        ))
    }

    /// ★ IPv4/IPv6 PARITY — the routing law must not depend on the address family.
    ///
    /// `tin_for_flow` matches on `dst_port()` alone (`shape.rs:75-79`), which is family-agnostic
    /// by construction. That is a claim about EVERY port and BOTH families, so it is checked
    /// exhaustively rather than sampled: 65536 ports x 2 protocols x (v4, v6).
    ///
    /// This closes a gap that had NO instrument of any kind: nothing in the tree measured that
    /// IPv6 flows are classified, shaped and paced identically to IPv4 flows.
    #[test]
    fn the_tin_law_is_identical_for_ipv4_and_ipv6_on_every_port() {
        let mut checked = 0usize;
        for port in 0..=u16::MAX {
            for proto in [Proto::Tcp, Proto::Udp] {
                let k4 = SessionKey::new(proto, v4([10, 1, 10, 1], 40000), v4([1, 2, 3, 4], port));
                let k6 = SessionKey::new(
                    proto,
                    v6([0xfd00, 0, 0, 0, 0, 0, 0, 1], 40000),
                    v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], port),
                );
                assert_eq!(
                    tin_for_flow(&k4),
                    tin_for_flow(&k6),
                    "IPv4/IPv6 tin divergence at port {port} ({proto:?}): v4 -> {:?}, v6 -> {:?}. \
                     The routing law reads dst_port() only, so the families MUST agree.",
                    tin_for_flow(&k4),
                    tin_for_flow(&k6)
                );
                checked += 1;
            }
        }
        // Negative control: if the loop never ran, the assertion above proves nothing.
        assert_eq!(
            checked,
            65536 * 2,
            "the exhaustive sweep did not cover the port space"
        );
    }

    /// ★ IPv4/IPv6 SEPARATION — a v4 flow and a v6 flow must not share a shaping identity.
    ///
    /// # What is NOT claimed
    ///
    /// `flow_key` is a 64-bit FNV-ish hash over up to 16 address octets plus ports. Injectivity is
    /// IMPOSSIBLE by pigeonhole and is deliberately not asserted — a theorem claiming it would be
    /// false. This is a MEASURED property over a concrete corpus, never a proof.
    ///
    /// # The real finding it guards
    ///
    /// `fold_addr` (`shape.rs:97-110`) has two match arms that are byte-for-byte identical
    /// (`for b in ip.octets()`), and folds NO family tag and NO length prefix. The families are
    /// distinguished only by how many octets happen to be folded. This corpus pins that the
    /// separation holds in practice for the addresses actually in play; if a future edit collapses
    /// the two arms further (or normalises v4-mapped v6), this fails.
    #[test]
    fn ipv4_and_ipv6_flows_keep_separate_shaping_identities() {
        let mut keys: std::collections::HashMap<i64, String> = std::collections::HashMap::new();
        let mut collisions = Vec::new();

        for proto in [Proto::Tcp, Proto::Udp] {
            for port in [53u16, 80, 443, 853, 22, 8080, 1, 65535] {
                let cases: [(&str, SessionKey); 4] = [
                    (
                        "v4",
                        SessionKey::new(proto, v4([10, 1, 10, 1], 40000), v4([1, 2, 3, 4], port)),
                    ),
                    (
                        "v6",
                        SessionKey::new(
                            proto,
                            v6([0xfd00, 0, 0, 0, 0, 0, 0, 1], 40000),
                            v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], port),
                        ),
                    ),
                    (
                        // The v4-MAPPED v6 form of 1.2.3.4 — the classic aliasing hazard: it must
                        // NOT collide with the plain v4 flow above, or a dual-stack app's two
                        // flows would share one window.
                        "v4-mapped-v6",
                        SessionKey::new(
                            proto,
                            v4([10, 1, 10, 1], 40000),
                            v6([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304], port),
                        ),
                    ),
                    (
                        "v6-loopback",
                        SessionKey::new(
                            proto,
                            v6([0, 0, 0, 0, 0, 0, 0, 1], 40000),
                            v6([0, 0, 0, 0, 0, 0, 0, 1], port),
                        ),
                    ),
                ];
                for (label, k) in cases {
                    let id = format!("{label}/{proto:?}/{port}");
                    let fk = flow_key(&k);
                    if let Some(prev) = keys.insert(fk, id.clone()) {
                        collisions.push(format!("{prev} <-> {id} (key {fk})"));
                    }
                }
            }
        }

        assert!(
            collisions.is_empty(),
            "flow_key COLLISION across address families — two distinct flows would share one \
             FlowShaper (and therefore one YeAH window): {collisions:?}. fold_addr folds no family \
             tag and no length prefix; if this fires, add one."
        );

        // Negative control: the corpus must actually have produced distinct keys, not zero keys.
        assert_eq!(
            keys.len(),
            2 * 8 * 4,
            "the corpus did not generate the expected number of distinct flows"
        );
    }

    /// ★ IPv4/IPv6 PACING PARITY — a v6 flow must pace off its own window exactly as a v4 flow
    /// does. Guards the plane fix (`cwnd()`/`write_budget()`/`on_stall()` routing on `self.proto`)
    /// against being v4-only by accident.
    #[test]
    fn a_v6_udp_flow_paces_off_the_udp_window_like_v4() {
        let k6 = SessionKey::new(
            Proto::Udp,
            v6([0xfd00, 0, 0, 0, 0, 0, 0, 1], 40000),
            v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443),
        );
        let k4 = SessionKey::new(Proto::Udp, v4([10, 1, 10, 1], 40000), v4([1, 2, 3, 4], 443));

        let mut s6 = FlowShaper::new(&k6);
        let mut s4 = FlowShaper::new(&k4);

        for _ in 0..8 {
            s6.sample(12.0);
            s4.sample(12.0);
        }

        assert_eq!(
            s6.cwnd(),
            s4.cwnd(),
            "a v6 UDP flow learned a different window than the identical v4 flow — the shaper is \
             family-sensitive where it must not be"
        );
        assert_eq!(
            s6.write_budget(),
            s4.write_budget(),
            "a v6 UDP flow got a different write budget than the identical v4 flow"
        );
        assert!(
            s6.write_budget() > 0,
            "the v6 budget is zero — a zero budget means read(&mut buf[..0]) -> Ok(0) -> silent \
             teardown (run.rs:379). This test would be vacuous."
        );
    }

    #[test]
    fn tin_classifier_matches_the_diffserv_law() {
        // DNS plane — CRITICAL on both transports (53 demux + 853 DoT).
        assert_eq!(
            tin_for_flow(&key_to(53, Proto::Udp)),
            ProbePriority::Critical
        );
        assert_eq!(
            tin_for_flow(&key_to(53, Proto::Tcp)),
            ProbePriority::Critical
        );
        assert_eq!(
            tin_for_flow(&key_to(853, Proto::Tcp)),
            ProbePriority::Critical
        );
        // Interactive page-load class — HIGH (TLS/QUIC, HTTP, SSH).
        assert_eq!(tin_for_flow(&key_to(443, Proto::Tcp)), ProbePriority::High);
        assert_eq!(tin_for_flow(&key_to(443, Proto::Udp)), ProbePriority::High); // QUIC
        assert_eq!(tin_for_flow(&key_to(80, Proto::Tcp)), ProbePriority::High);
        assert_eq!(tin_for_flow(&key_to(22, Proto::Tcp)), ProbePriority::High);
        // Bulk — NORMAL.
        assert_eq!(
            tin_for_flow(&key_to(8080, Proto::Tcp)),
            ProbePriority::Normal
        );
        assert_eq!(
            tin_for_flow(&key_to(6881, Proto::Tcp)),
            ProbePriority::Normal
        );
    }

    #[test]
    fn widened_flow_key_is_deterministic_and_sport_distinct() {
        let a = SessionKey::new(
            Proto::Tcp,
            v4([10, 1, 10, 1], 44321),
            v4([140, 82, 121, 3], 443),
        );
        let a2 = SessionKey::new(
            Proto::Tcp,
            v4([10, 1, 10, 1], 44321),
            v4([140, 82, 121, 3], 443),
        );
        // Deterministic: the same 5-tuple keys the same flow across calls.
        assert_eq!(flow_key(&a), flow_key(&a2));
        // A different sport is a DIFFERENT flow (the NAT-correctness law from session.rs).
        let b = SessionKey::new(
            Proto::Tcp,
            v4([10, 1, 10, 1], 44322),
            v4([140, 82, 121, 3], 443),
        );
        assert_ne!(flow_key(&a), flow_key(&b));
        // A different proto over the same addresses is a different flow.
        let c = SessionKey::new(
            Proto::Udp,
            v4([10, 1, 10, 1], 44321),
            v4([140, 82, 121, 3], 443),
        );
        assert_ne!(flow_key(&a), flow_key(&c));
    }

    #[test]
    fn live_settings_tune_governs_a_fresh_flow_shaper() {
        // GROUND-TRUTH the SURPASS wire: a SETTINGS window ceiling reaches the REAL per-flow shaper (born
        // here), not merely the telemetry Beast. Pin a window override via the SAME broadcast the
        // apply/restore path uses; a fresh flow must be born on it. Deterministic — reads the ceiling
        // field, no growth dynamics. (Crate runs --test-threads=1, so the process-global tune is serial.)
        let default_max = YeahController::with_profile(YeahProfile::LineRate).max_window();
        crate::beast::store_live_yeah_profile(2); // LineRate — the armed brain
        crate::beast::store_live_tunables(3, 0, 0); // window ceiling = 3 segments
        let s = FlowShaper::new(&key_to(8080, Proto::Tcp));
        assert_eq!(
            s.max_window(),
            3,
            "the SETTINGS window override never reached the per-flow shaper"
        );
        // Cleared (0 = don't-clobber) → a fresh flow is born on the profile default again, so the
        // process-global tune does not poison sibling tests.
        crate::beast::store_live_tunables(0, 0, 0);
        let s2 = FlowShaper::new(&key_to(8080, Proto::Tcp));
        assert_eq!(
            s2.max_window(),
            default_max,
            "clearing the override did not restore the LineRate default"
        );
    }

    #[test]
    fn shaper_budget_grows_on_free_bandwidth_and_sheds_on_stall() {
        let mut s = FlowShaper::new(&key_to(8080, Proto::Tcp));
        assert_eq!(s.tin(), ProbePriority::Normal);
        // Birth state: cwnd = MIN_WINDOW = 1 → one-segment budget.
        assert_eq!(s.cwnd(), 1);
        assert_eq!(s.write_budget(), SHAPE_SEGMENT_BYTES);
        // Free bandwidth (flat RTT) — slow-start grows the window; budget tracks cwnd exactly.
        for _ in 0..32 {
            s.sample(20.0);
        }
        let grown = s.cwnd();
        assert!(grown > 1, "cwnd never grew on free bandwidth: {grown}");
        assert_eq!(s.write_budget(), grown as usize * SHAPE_SEGMENT_BYTES);
        // A stall sheds window (the LineRate loss rule) — never below the floor.
        s.on_stall();
        assert!(
            s.cwnd() < grown,
            "stall did not shed: {} !< {grown}",
            s.cwnd()
        );
        assert!(s.cwnd() >= 1);
    }
    /// ★ Rung D — THE PLANE YOU FEED IS THE PLANE YOU PACE.
    ///
    /// A UDP flow feeds the independent UDP brain, so its budget must come from that brain. If
    /// `cwnd()` read the TCP window instead, a UDP flow would sit at MIN_WINDOW forever (nothing
    /// feeds that window) while its stalls sheared the TCP flows' window. Both halves are checked,
    /// each with the negative control that the OTHER plane did not move.
    #[test]
    fn a_udp_flow_paces_off_the_udp_window_it_feeds() {
        let mut u = FlowShaper::new(&key_to(9999, Proto::Udp));
        assert_eq!(u.cwnd(), 1, "birth state is MIN_WINDOW on either plane");
        for _ in 0..32 {
            u.sample(20.0);
        }
        let grown = u.cwnd();
        assert!(grown > 1, "a UDP flow never grew its own window: {grown}");
        assert_eq!(
            u.write_budget(),
            grown as usize * SHAPE_SEGMENT_BYTES,
            "the paced budget must track the window the flow actually feeds"
        );
        // NEGATIVE CONTROL: the TCP-family window of this UDP flow never moved.
        assert_eq!(
            u.yeah.cwnd(),
            1,
            "a UDP flow must not grow the TCP-family window"
        );
        // A UDP stall sheds the UDP window, not the TCP one.
        u.on_stall();
        assert!(u.cwnd() < grown, "a UDP stall did not shed the UDP window");
        assert!(u.cwnd() >= 1, "never below the floor");
        assert_eq!(
            u.yeah.cwnd(),
            1,
            "a UDP stall must not touch the TCP-family window"
        );
    }
    /// EXHAUSTIVE over the whole u16 destination-port space: the tin demux and the pacing
    /// predicate obey the routing law for EVERY port, on BOTH transports.
    ///
    /// This is the instrument that binds `Proofs/RoutingTins.lean` to the real code. The Lean
    /// theorems quantify over the TIN ("whatever is CRITICAL is never paced"), which is the
    /// durable law; this test quantifies over the PORT against the real `tin_for_flow`, which
    /// is what would actually drift. Neither alone is enough: the theorem cannot see this file,
    /// and a test cannot settle a property it does not enumerate -- so here it enumerates all
    /// 65536 of them, which for a u16 is not a sample but the whole domain.
    #[test]
    fn the_tin_demux_obeys_the_routing_law_for_every_port() {
        // The five ports the DiffServ demux lifts out of the bulk lane, and nothing else.
        for port in 0..=u16::MAX {
            let tcp = tin_for_flow(&key_to(port, Proto::Tcp));
            let udp = tin_for_flow(&key_to(port, Proto::Udp));
            // RoutingTins.the_two_transports_agree -- one table, keyed on the port alone.
            assert_eq!(tcp, udp, "transports disagree on port {port}");
            let expected = match port {
                53 | 853 => ProbePriority::Critical,
                443 | 80 | 22 => ProbePriority::High,
                _ => ProbePriority::Normal,
            };
            assert_eq!(tcp, expected, "tin wrong for port {port}");
            // RoutingTins.only_bulk_is_paced -- the predicate run.rs:191/:215 both compute.
            let paced = tcp == ProbePriority::Normal;
            // RoutingTins.the_dns_plane_is_never_paced / the_interactive_class_is_never_paced.
            if matches!(tcp, ProbePriority::Critical | ProbePriority::High) {
                assert!(!paced, "a latency-class flow on port {port} would be paced");
            } else {
                assert!(
                    paced,
                    "a bulk flow on port {port} would escape the logarithm"
                );
            }
        }
        // NEGATIVE CONTROL: the law is not vacuous -- both branches were actually taken.
        assert!(!(tin_for_flow(&key_to(53, Proto::Udp)) == ProbePriority::Normal));
        assert!(tin_for_flow(&key_to(6881, Proto::Tcp)) == ProbePriority::Normal);
    }
}
