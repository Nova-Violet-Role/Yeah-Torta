/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! N4 — the PROTECTED UPSTREAM (the anti-loop keystone).
//!
//! UNIX-ONLY. Every socket the forwarder dials to the real internet MUST be excluded from the tun, or its
//! packets re-enter the `0.0.0.0/0` tun and the flow loops forever (the exact egress-loop measured 2026-07-04).
//! firestack/NetGuard call `protect_socket(fd)` before connect (tcp.c:1139); tokio has NO pre-connect hook, so
//! we open the socket via `socket2` (which exposes the raw fd BEFORE connect), call the [`ProtectFn`]
//! (Kotlin's `vpnService.protect(fd)`), and only THEN connect + hand to tokio.
//!
//! On protect-fail we return `None` — the caller drops the flow. We NEVER dial an unprotected socket (a hole
//! that would leak the app's traffic outside the VPN AND loop it back into the tun).

use std::net::SocketAddr;

use log::{error, warn};
use socket2::{Domain, Protocol, Socket, Type};
use std::os::unix::io::AsRawFd;

use super::run::ProtectFn;

/// Open a UDP upstream socket, protect its fd, connect it to `dst`, and hand back a tokio [`UdpSocket`].
/// `None` on any failure (protect-fail included) — the caller drops the flow.
///
/// ★ N-dial-UDP — EVERY failure exit here now WITNESSES itself, exactly as the TCP dial below already
/// did. This function used to hold FIVE bare `None` returns (`Socket::new`, `protect` refusal, the
/// non-blocking switch, `connect`, and the tokio handover): a UDP flow could die at any of them while
/// no counter moved anywhere in the app, and the caller then logged the loss as
/// `forward_tcp: connect_tcp_protected failed` — the wrong function AND the wrong helper.
///
/// That is the same blind spot the TCP dial was fixed for, on the transport that hides it best. For a
/// browser UDP is HTTP/3, so a failing QUIC dial usually still renders the page over the TCP fallback:
/// the operator sees intermittent slowness and the odd dead request instead of a clean failure, and
/// every log line points at TCP, which is healthy. Silent + mislabelled + self-healing is precisely the
/// shape of a defect that survives weeks of debugging.
///
/// The UDP totals are kept SEPARATE from the TCP ones (that separation IS the diagnostic: HTTP/3 vs
/// HTTP/2), while the four cause buckets are SHARED, because `classify_dial_failure` maps an errno and
/// an errno is transport-agnostic. Hence the widened invariant, proved in
/// `D:/Lean/proofs/Proofs/DialFailure.lean`:
///   refused + unreachable + timed_out + other == dial_connect_failed + udp_dial_connect_failed
pub(crate) async fn connect_udp_protected(
    dst: SocketAddr,
    protect: &ProtectFn,
    fwd: &crate::tunnel::ForwarderStats,
) -> Option<tokio::net::UdpSocket> {
    use std::sync::atomic::Ordering;
    /// Record one UDP dial failure: bump the UDP total, then classify the errno into the shared bucket.
    /// Local failures are classified too, so the partition stays TOTAL rather than lossy.
    fn witness(fwd: &crate::tunnel::ForwarderStats, err: Option<i32>) {
        fwd.udp_dial_connect_failed.fetch_add(1, Ordering::Relaxed);
        let bucket = match crate::tunnel::classify_dial_failure(err) {
            crate::tunnel::DialFailure::Refused => &fwd.dial_refused,
            crate::tunnel::DialFailure::Unreachable => &fwd.dial_unreachable,
            crate::tunnel::DialFailure::TimedOut => &fwd.dial_timed_out,
            crate::tunnel::DialFailure::Other => &fwd.dial_other,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }
    let domain = if dst.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = match Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(s) => s,
        Err(e) => {
            error!("upstream: UDP Socket::new failed for dst={}: {:?}", dst, e);
            witness(fwd, e.raw_os_error());
            return None;
        }
    };
    // ★ THE KEYSTONE — protect BEFORE any egress. protect(fd) excludes the fd from the tun.
    if !protect(sock.as_raw_fd()) {
        error!("upstream: protect() failed for UDP dst={}", dst);
        fwd.udp_dial_protect_failed.fetch_add(1, Ordering::Relaxed);
        return None; // never dial an unprotected socket
    }
    if let Err(e) = sock.set_nonblocking(true) {
        error!(
            "upstream: UDP set_nonblocking failed for dst={}: {:?}",
            dst, e
        );
        witness(fwd, e.raw_os_error());
        return None;
    }
    // connect() pins the peer so send/recv (not sendto/recvfrom) work — one flow, one socket.
    if let Err(e) = sock.connect(&dst.into()) {
        error!("upstream: UDP connect failed for dst={}: {:?}", dst, e);
        witness(fwd, e.raw_os_error());
        return None;
    }
    let std_sock: std::net::UdpSocket = sock.into();
    match tokio::net::UdpSocket::from_std(std_sock) {
        Ok(u) => Some(u),
        Err(e) => {
            error!("upstream: UDP from_std failed for dst={}: {:?}", dst, e);
            witness(fwd, e.raw_os_error());
            None
        }
    }
}

/// Open a TCP upstream socket, protect its fd, connect it to `dst`, and hand back a tokio [`TcpStream`].
/// `None` on any failure (protect-fail included) — the caller drops the flow. The connect is async (tokio
/// drives the non-blocking connect to completion), so a slow/dead dst never blocks the worker.
///
/// ★ N-dial — EVERY failure exit here now WITNESSES itself on [`ForwarderStats`]. Before, all five
/// returned a bare `None`: the caller dropped the flow, the client saw its already-accepted TCP
/// connection close with no response (`ERR_CONNECTION_CLOSED`), and NOT ONE counter moved anywhere
/// in the app. The one path that can kill every page was the one path that recorded nothing, which
/// is why it stayed invisible across a whole debugging session. `protect` refusal is counted
/// SEPARATELY from network failure because they demand opposite fixes: the first means the
/// VpnService seam is broken (and DNS keeps working, since in-loop DNS is never dialed — that
/// asymmetry is the tell), the second means the destination is unreachable.
pub(crate) async fn connect_tcp_protected(
    dst: SocketAddr,
    protect: &ProtectFn,
    fwd: &crate::tunnel::ForwarderStats,
) -> Option<tokio::net::TcpStream> {
    use std::sync::atomic::Ordering;
    let domain = if dst.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(e) => {
            // A LOCAL failure -- the network was never touched (fd exhaustion, no such family).
            // Classified all the same so the four buckets stay a TOTAL partition of the counter;
            // an uncounted failure is exactly the blind spot this change exists to remove.
            fwd.dial_connect_failed.fetch_add(1, Ordering::Relaxed);
            let bucket = match crate::tunnel::classify_dial_failure(e.raw_os_error()) {
                crate::tunnel::DialFailure::Refused => &fwd.dial_refused,
                crate::tunnel::DialFailure::Unreachable => &fwd.dial_unreachable,
                crate::tunnel::DialFailure::TimedOut => &fwd.dial_timed_out,
                crate::tunnel::DialFailure::Other => &fwd.dial_other,
            };
            bucket.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    // ★ FAMILY CAPABILITY — do not spend a user-visible connection on a doomed dial.
    // MEASURED: 181/181 failed dials were IPv6:443 while IPv4 failures were zero, each arriving as
    // ECONNREFUSED (the path RSTs; it never reports "no route"). When IPv6 has failed
    // `DEAD_AFTER` times CONSECUTIVELY we skip it -- EXCEPT on the probe cadence, which never
    // stops, so a network that later gains IPv6 is always re-discovered. Proved in
    // D:/Lean/proofs/Proofs/EgressCapability.lean: `every_window_contains_a_probe` and
    // `there_is_always_a_later_probe` (suppression is never total). Never a hardcoded "IPv6 off" --
    // that would be a spec forbidding a correct future.
    //
    // ★ CITATION CORRECTED 2026-07-31. This block used to cite `one_success_revives_from_any_depth`
    // for the claim "revival is never rate-limited". That theorem was DELETED from the Lean file
    // when `reviveAfter` was introduced, and the file records the deletion at its lines 40 and 120.
    // The comment outlived the theorem AND asserted the OPPOSITE of current behaviour: revival IS
    // rate-limited now. The three theorems that actually hold are
    //   `one_success_never_lifts_the_latch`  (EgressCapability.lean:156) -- a single success can
    //      never lift the latch while `reviveAfter` exceeds one; the oscillation is impossible,
    //   `enough_successes_lift_the_latch`    (:161) -- `reviveAfter` CONSECUTIVE successes do lift
    //      it, so suppression is still never a one-way door,
    //   `a_failure_destroys_revival_credit`  (:167) -- a failure in the middle destroys the credit,
    //      so sprinkled successes never revive.
    // Verified together, not by eye: `lake build Proofs.EgressCapability` exit 0, `#print axioms` on
    // the two surviving cited theorems -> [propext, Classical.choice, Quot.sound], no `sorryAx`.
    // A stale citation is worse than no citation: it launders a WITHDRAWN guarantee into the code
    // that depends on it, and the reader has no way to tell without opening the .lean.
    // ★ A PROBE MUST NEVER BE A USER FLOW.
    //
    // MEASURED: with the cadence exception living HERE, the residual ERR_CONNECTION_CLOSED count was
    // exactly equal to the dial-failure count (36 == 36, then 2 == 2, both times to a real host on
    // :443). Every remaining user-visible closure WAS a rediscovery probe. The mechanism was paying
    // for its own learning with the Socio's page loads.
    //
    // ★ THAT MEASUREMENT IS STILL TRUE, AND ITS CONCLUSION HAS BEEN SUPERSEDED — stated plainly
    //   rather than quietly rewritten. The 36 == 36 reading was taken while the RESOLVER released
    //   an AAAA on every cadence tick, so each tick manufactured a fresh user flow onto a dead
    //   family. The block that followed drew the conclusion "refuse EVERY latched v6 destination,
    //   no cadence exception here", and that text sat directly above the gate until 2026-07-31.
    //
    //   It was answering the wrong question. The cost was never that the cadence lived HERE; it was
    //   that the two gates disagreed, so the resolver MADE the doomed flows this gate then refused.
    //   With the release gate fixed (`resolver/mod.rs` now withholds AAAA on the raw latch), the
    //   cadence tick no longer manufactures anything: Torta's own DNS hands out no v6 address while
    //   latched, so the population this exception applies to is only cached AAAA / address
    //   literals. That is why the exception is safe to keep HERE now and was not safe before.
    //
    // HONEST LIMIT, restated for the current design: rediscovery is still coarse for hosts Torta
    // resolves itself — it withholds their AAAA, so they never produce a probe dial at all. What
    // the cadence recovers is the residual v6 traffic the client already held. `reset_for_new_network()`
    // at tunnel start remains the reliable clear. An out-of-band prober is still the right end
    // state, and `EgressGateAgreement.the_prober_design_is_also_coherent` proves the invariant
    // proved here does not forbid it.
    // ★ THE CADENCE LIVES HERE NOW, NOT IN THE RESOLVER — 2026-07-31.
    //
    // The gate above used to be `v6_presumed_dead()` while `resolver/mod.rs` withheld AAAA on
    // `!v6_should_attempt()`. Those two predicates DISAGREE on the probe tick: the resolver released
    // a v6 address and this function then refused to dial it, so the cadence spent a user page load
    // and — because `record_dial` below is the ONLY writer of the latch and sits AFTER this early
    // return — learned nothing. A throttle so tight that the traffic which would relieve it can
    // never complete.
    //
    // The repair moves the cadence exception from the RELEASE gate to the DIAL gate:
    //   * `resolver/mod.rs` now withholds AAAA whenever the latch is set, with NO exception, so
    //     Torta's own DNS never steers a client onto a family this datapath declines;
    //   * this gate refuses a v6 dial UNLESS it is the probe tick.
    // The only v6 dials that can still arrive while latched are ones the client already held (a
    // cached AAAA, an address literal). For those, refusing GUARANTEES a failed flow while
    // attempting may succeed — and either way it reaches `record_dial`, which is the only thing
    // that can clear the latch. Attempting on the cadence is never worse for the flow and strictly
    // better for the mechanism.
    //
    // Proved over arbitrary gate functions in D:/Lean/proofs/Proofs/EgressGateAgreement.lean:
    //   `the_shipped_repair_is_coherent`        -- no lane is offered a family its dial path refuses
    //   `the_probe_tick_learns_again`           -- the deadlock is broken without a new prober
    //   `off_cadence_v6_is_still_refused`       -- the doomed-dial saving is RETAINED
    //   `repaired_dial_refuses_no_more_than_shipped` -- cannot break a v6 flow that works today
    //   `a_live_network_dials_v6_freely`        -- this is not "IPv6 off" by another route
    // 13/13 mutants killed, 0 survived, 0 discarded; leanchecker exit 0 / zero bytes.
    if dst.is_ipv6() && !crate::egress::v6_should_attempt() {
        warn!(
            "upstream: skipping IPv6 dial for dst={} -- v6 egress presumed dead, awaiting probe",
            dst
        );
        fwd.dial_connect_failed.fetch_add(1, Ordering::Relaxed);
        // ★ SUPPRESSION IS NOT UNREACHABILITY. This used to bump `dial_unreachable`, so the ENGINE
        // ROOM panel reported "dial unreachable 126" for dials TORTA ITSELF declined to make. That
        // tells the operator the NETWORK has no route when the truth is that WE chose not to try --
        // a policy decision laundered into a network measurement, and it also inflated the very
        // counter used to diagnose this subsystem. Measured on the AVD: 126 "unreachable" beside 5
        // genuinely refused.
        fwd.dial_v6_suppressed.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    // ★ THE KEYSTONE — protect BEFORE connect.
    if !protect(sock.as_raw_fd()) {
        error!("upstream: protect() failed for dst={}", dst);
        fwd.dial_protect_failed.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    if let Err(e) = sock.set_nonblocking(true) {
        // Also local, also classified -- see the Socket::new arm above.
        fwd.dial_connect_failed.fetch_add(1, Ordering::Relaxed);
        let bucket = match crate::tunnel::classify_dial_failure(e.raw_os_error()) {
            crate::tunnel::DialFailure::Refused => &fwd.dial_refused,
            crate::tunnel::DialFailure::Unreachable => &fwd.dial_unreachable,
            crate::tunnel::DialFailure::TimedOut => &fwd.dial_timed_out,
            crate::tunnel::DialFailure::Other => &fwd.dial_other,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    // Hand the protected, not-yet-connected socket to tokio's TcpSocket (from_std_stream, socket.rs:957),
    // then drive the async connect via the reactor (socket.rs:837 — completes the non-blocking EINPROGRESS).
    let std_stream: std::net::TcpStream = sock.into();
    let tcp_sock = tokio::net::TcpSocket::from_std_stream(std_stream);
    match tcp_sock.connect(dst).await {
        Ok(s) => {
            // Learn what this network reaches, per FAMILY, from the DESTINATION. The
            // errno cannot say: a refused v6 dial is ECONNREFUSED, not ENETUNREACH.
            crate::egress::record_dial(dst.is_ipv6(), true);
            Some(s)
        }
        Err(e) => {
            // Keep the TOTAL exactly as before, then record WHY. The reason used to be discarded
            // here (`Err(_)`), which forced the Engine panel to label every failure "DIAL
            // unreachable" even when the peer had actively refused us or the dial had timed out --
            // three causes with three different fixes, shown as one number.
            fwd.dial_connect_failed.fetch_add(1, Ordering::Relaxed);
            crate::egress::record_dial(dst.is_ipv6(), false);
            let bucket = match crate::tunnel::classify_dial_failure(e.raw_os_error()) {
                crate::tunnel::DialFailure::Refused => &fwd.dial_refused,
                crate::tunnel::DialFailure::Unreachable => &fwd.dial_unreachable,
                crate::tunnel::DialFailure::TimedOut => &fwd.dial_timed_out,
                crate::tunnel::DialFailure::Other => &fwd.dial_other,
            };
            bucket.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// ★ N-dial-UDP — tests that drive the REAL `connect_udp_protected`, not a simulation of its counters.
///
/// The invariant test in `tunnel::dial_failure_tests` bumps the counters by hand, so it proves the
/// PARTITION but could never catch `witness()` incrementing the wrong field. These drive the actual
/// function, which is the only way to prove the WIRING. Neither test needs the network: a `protect`
/// that refuses returns before any dial, and a port-0 destination fails locally.
#[cfg(test)]
mod udp_dial_witness_tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    /// A refusing `protect` must land in the UDP SEAM counter and nowhere else. Before this change the
    /// same path returned a bare `None`: the flow died, the log blamed `forward_tcp`, and every counter
    /// in the app stayed at zero.
    #[tokio::test]
    async fn a_refused_protect_witnesses_the_udp_seam_counter() {
        let fwd = crate::tunnel::ForwarderStats::default();
        let protect: ProtectFn = Arc::new(|_fd: i32| false); // the VpnService seam refuses
        let dst: SocketAddr = "203.0.113.1:443".parse().unwrap();

        let out = connect_udp_protected(dst, &protect, &fwd).await;

        assert!(out.is_none(), "an unprotected socket must NEVER be dialed");
        assert_eq!(
            fwd.udp_dial_protect_failed.load(Ordering::Relaxed),
            1,
            "the UDP protect refusal must witness itself — this is the counter that did not exist"
        );
        assert_eq!(
            fwd.udp_dial_connect_failed.load(Ordering::Relaxed),
            0,
            "protect refusal never reached the network, so the network total must stay at 0"
        );
        assert_eq!(
            fwd.dial_protect_failed.load(Ordering::Relaxed),
            0,
            "the UDP seam must not be confused with the TCP seam — they are separate diagnoses"
        );
        let buckets = fwd.dial_refused.load(Ordering::Relaxed)
            + fwd.dial_unreachable.load(Ordering::Relaxed)
            + fwd.dial_timed_out.load(Ordering::Relaxed)
            + fwd.dial_other.load(Ordering::Relaxed);
        assert_eq!(
            buckets, 0,
            "a seam refusal is not a network cause and must not fill a bucket"
        );
    }

    /// ★ THE LIMIT OF THIS INSTRUMENT, pinned deliberately — and it is load-bearing knowledge for the
    /// `ERR_CONNECTION_CLOSED` hunt, so it is a test rather than a comment.
    ///
    /// This test originally asserted that a UDP dial to port 0 FAILS and witnessed itself. Run on the
    /// real target (the x86_64 AVD, not this Windows host) it panicked at `assert!(out.is_none())`:
    /// the dial SUCCEEDED. The premise was wrong, and wrong in an instructive way.
    ///
    /// `connect()` on a UDP socket is not a handshake. It only records a default peer and consults the
    /// routing table; nothing is sent and no peer has to exist. So with a default route present — which
    /// is always the case inside the tun — a UDP `connect()` to a black-holed, filtered or simply dead
    /// destination returns Ok. The consequence, stated plainly because it bounds what the new counters
    /// can ever prove:
    ///
    ///   `udp_dial_connect_failed` witnesses socket creation, `set_nonblocking`, the tokio handover and
    ///   genuine routing refusals. It CANNOT witness a QUIC destination that is reachable-but-silent.
    ///   That failure has no dial error to count: it surfaces later as a response that never comes.
    ///
    /// So a flat `udp_dial_connect_failed` during a failing HTTP/3 session is NOT evidence that UDP is
    /// healthy — it is the expected reading either way. Anyone debugging QUIC from this counter alone
    /// would clear UDP wrongly, which is exactly the class of mistake the whole ★ N-dial work exists to
    /// stop. Detecting silent-peer UDP needs a response-side timeout, not a dial-side counter.
    #[tokio::test]
    async fn a_udp_dial_cannot_witness_an_unreachable_peer_because_connect_does_not_probe() {
        let fwd = crate::tunnel::ForwarderStats::default();
        let protect: ProtectFn = Arc::new(|_fd: i32| true);
        // 203.0.113.0/24 is TEST-NET-3 (RFC 5737): guaranteed never routable to a real host, and
        // port 9 is discard. If `connect()` probed anything at all, this would fail.
        let dst: SocketAddr = "203.0.113.1:9".parse().unwrap();

        let out = connect_udp_protected(dst, &protect, &fwd).await;

        assert!(
            out.is_some(),
            "UDP connect() sets a default peer and consults the route table — it does NOT probe, so \
             an unreachable TEST-NET-3 destination still yields a socket. If this ever fails, the \
             platform's UDP semantics changed and the comment above must be re-measured."
        );
        assert_eq!(
            fwd.udp_dial_connect_failed.load(Ordering::Relaxed),
            0,
            "nothing failed, so nothing may be witnessed — a counter that moved here would be lying"
        );
        assert_eq!(
            fwd.udp_dial_protect_failed.load(Ordering::Relaxed),
            0,
            "the seam accepted the fd"
        );
        // The proved partition still holds, trivially, over two totals that are both zero
        // (Proofs/DialFailure.lean, buckets_sum_to_both_totals).
        let buckets = fwd.dial_refused.load(Ordering::Relaxed)
            + fwd.dial_unreachable.load(Ordering::Relaxed)
            + fwd.dial_timed_out.load(Ordering::Relaxed)
            + fwd.dial_other.load(Ordering::Relaxed);
        assert_eq!(
            buckets,
            fwd.dial_connect_failed.load(Ordering::Relaxed)
                + fwd.udp_dial_connect_failed.load(Ordering::Relaxed),
            "the shared buckets must partition BOTH totals, exactly as the Lean proof states"
        );
    }
}
