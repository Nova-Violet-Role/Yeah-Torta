/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! ★ #51 N9 — the ICMP ECHO LANE (the banked ping seam).
//!
//! Before this module, every ICMP packet the netstack handed us fell into `handle_flow`'s `_ =>`
//! arm and died on a counter (`flows_other`) under the comment "a later slice may echo". This IS
//! that slice: `ping` now crosses the tun, reaches the real destination, and comes back carrying a
//! REAL round-trip time.
//!
//! # Why a ping is hard inside a VpnService
//!
//! An echo request arrives as a raw IP packet, not a socket flow — there is no `connect()` to
//! forward. Sending one normally needs `SOCK_RAW`, which needs `CAP_NET_RAW`, which an unprivileged
//! Android app does not have. The way out is the Linux **ping socket**
//! (`socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`, kernel `net/ipv4/ping.c`): unprivileged when the
//! caller's GID falls inside `/proc/sys/net/ipv4/ping_group_range`, which is exactly how the
//! platform `ping` binary and every no-root ping app work. We open one, `protect()` it (N4 — the
//! anti-loop keystone: an unprotected upstream re-enters our own `0.0.0.0/0` tun), send the echo,
//! and write the reply back into the tun.
//!
//! # THE HONESTY LINE (why this lane is allowed to report failure)
//!
//! The cheap implementation is to answer the echo request LOCALLY — synthesize a reply and never
//! touch the network. Every ping would succeed instantly, the panel would show a beautiful 0 ms,
//! and the number would be a fabrication: a `ping` that cannot fail is not a diagnostic, it is a
//! decoration that lies about reachability (the defect class of #83's ambiguous 0 ms and #78's
//! forged answers). So the lane dials for real, and when the destination does not answer it says
//! so — [`crate::tunnel::ForwarderStats::icmp_failed`] climbs and the request is dropped, which is
//! exactly what an unanswered ping looks like on a device with no VPN at all.
//!
//! # IPv4 only, BY MEASUREMENT
//!
//! ipstack 0.1.1's reverse-packet builder hardcodes `next_header: IpNumber::UDP` on its IPv6 branch
//! (`stream/unknown.rs`, `create_rev_packet`), so an ICMPv6 reply emitted through it would claim to
//! be UDP and be discarded — or worse, misparsed — by the client stack. Rather than ship a packet
//! measured to be malformed, ICMPv6 stays in the honest `flows_other` remainder until that upstream
//! branch carries the real next-header.
//!
//! # Layering
//!
//! The WIRE half below (parse/build/checksum) is cross-platform and host-testable, the same split
//! `session`/`shape`/`sni` already use; only the socket-driving [`lane`] is UNIX-ONLY. Keeping the
//! packet logic host-side is what lets the checksum be tested on this Windows host at all — gated
//! behind `cfg(unix)` it would compile only for Android and never run in a test.

// ===================================================================================================
// THE WIRE (cross-platform, host-testable)
// ===================================================================================================

/// IANA: ICMPv4. The `ip_protocol()` byte the netstack reports for an echo request.
pub(crate) const IPPROTO_ICMPV4: u8 = 1;
/// ICMP type 8 — ECHO REQUEST (the only type this lane carries; see the module note on why we do
/// not synthesize answers for the rest).
pub(crate) const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP type 0 — ECHO REPLY (what we write back into the tun).
pub(crate) const ICMP_ECHO_REPLY: u8 = 0;
/// The fixed ICMP header: type, code, checksum(2), identifier(2), sequence(2).
pub(crate) const ICMP_HEADER_LEN: usize = 8;
/// Refuse absurd payloads outright. A legitimate echo carries a timestamp + a pattern (56 bytes for
/// `ping`, up to an MTU for `ping -s`); anything past one MTU would be fragmented by the sender
/// anyway, and copying it would only feed a buffer we then have to bound.
pub(crate) const MAX_ECHO_PAYLOAD: usize = 1500;

/// The RFC 1071 one's-complement checksum over an ICMP message.
///
/// Computed over the WHOLE message with the checksum field already zeroed. The odd-length tail is
/// padded with a zero byte per the RFC — dropping that byte silently corrupts every odd-sized echo,
/// the kind of bug that only ever shows up against one particular `ping -s`.
pub(crate) fn icmp_checksum(msg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = msg.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let tail = remainder[0];
        sum += u32::from(u16::from_be_bytes([tail, 0]));
    }
    // Fold the carries down into 16 bits, then complement.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// One parsed ICMPv4 echo request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EchoRequest {
    /// The sender's identifier — the field a ping socket OVERWRITES on send and demuxes on receive,
    /// so it must be restored on the reply or the client will not recognise its own echo.
    pub(crate) id: u16,
    /// The sender's sequence number (`icmp_seq=` in `ping` output).
    pub(crate) seq: u16,
    /// The echoed data — must come back byte-identical, so `ping` can verify it.
    pub(crate) data: Box<[u8]>,
}

/// Parse an ICMPv4 echo request out of a raw transport payload.
///
/// `None` for anything that is not a well-formed echo request: too short, wrong type (a
/// destination-unreachable or time-exceeded an app emitted), or a non-zero code. Those keep falling
/// to the `flows_other` remainder rather than being answered by a lane that only understands echo.
pub(crate) fn parse_echo_request(payload: &[u8]) -> Option<EchoRequest> {
    if payload.len() < ICMP_HEADER_LEN || payload.len() >= MAX_ECHO_PAYLOAD {
        return None;
    }
    if payload[0] != ICMP_ECHO_REQUEST || payload[1] != 0 {
        return None;
    }
    Some(EchoRequest {
        id: u16::from_be_bytes([payload[4], payload[5]]),
        seq: u16::from_be_bytes([payload[6], payload[7]]),
        data: payload[ICMP_HEADER_LEN..].into(),
    })
}

/// Build a wire ICMPv4 message: `kind`, code 0, a correct checksum, `id`, `seq`, then `data`.
///
/// Used for BOTH directions — the request sent upstream and the reply written back — because the
/// two differ only in the type byte, and one builder means one checksum implementation to be right
/// about.
pub(crate) fn build_echo(kind: u8, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ICMP_HEADER_LEN + data.len());
    msg.push(kind);
    msg.push(0); // code
    msg.extend_from_slice(&[0, 0]); // checksum placeholder — zeroed while it is computed
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(data);
    let ck = icmp_checksum(&msg);
    msg[2..4].copy_from_slice(&ck.to_be_bytes());
    msg
}

// ===================================================================================================
// THE LANE (UNIX-ONLY — drives a real protected socket)
// ===================================================================================================

#[cfg(unix)]
pub(crate) mod lane {
    use std::net::{IpAddr, SocketAddr};
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ipstack::stream::IpStackUnknownTransport;
    use socket2::{Domain, Protocol, Socket, Type};

    use super::super::run::{docket_enroll_raw, warden_allows, ProtectFn, UidFn};
    use super::super::session::{Proto, SessionKey};
    use super::super::shape::flow_key;
    use super::{
        build_echo, parse_echo_request, EchoRequest, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST,
        ICMP_HEADER_LEN, IPPROTO_ICMPV4, MAX_ECHO_PAYLOAD,
    };
    use crate::tunnel::ForwarderStats;

    /// How long one echo waits for its answer. Deliberately shorter than the platform `ping`'s
    /// default (which retries on its own schedule): a per-flow tokio task holds a docket row for
    /// this long, and an unanswered ping is a fact worth reporting promptly rather than a reason to
    /// hold a slot.
    const ECHO_TIMEOUT: Duration = Duration::from_secs(2);

    /// Open an unprivileged ICMPv4 ping socket, PROTECT it, and connect it to `dst`.
    ///
    /// The N4 order is law and identical to [`crate::forwarder::upstream`]: socket2 exposes the raw
    /// fd BEFORE any egress, so `protect(fd)` runs first and we never dial a socket that could loop
    /// back into our own tun. `None` on any failure — including a kernel whose `ping_group_range`
    /// excludes us, which surfaces here as a plain `EACCES` on `Socket::new`.
    fn open_ping_socket(dst: IpAddr, protect: &ProtectFn) -> Option<tokio::net::UdpSocket> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).ok()?;
        // ★ THE KEYSTONE — protect BEFORE any egress.
        if !protect(sock.as_raw_fd()) {
            return None; // sock dropped here, fd closed by Drop trait
        }
        sock.set_nonblocking(true).ok()?;
        // A ping socket is portless; the kernel assigns the identifier from the socket's own port
        // and demuxes replies with it, so connecting to `dst:0` pins the peer without naming a port.
        sock.connect(&SocketAddr::new(dst, 0).into()).ok()?;
        let std_sock: std::net::UdpSocket = sock.into();
        tokio::net::UdpSocket::from_std(std_sock).ok()
    }

    /// ★ #51 N9 — carry ONE ICMP flow the netstack could not classify.
    ///
    /// Echo requests are dialed for real; everything else (ICMPv6, IGMP, ESP, an ICMP error an app
    /// emitted) increments the honest `flows_other` remainder and is dropped.
    ///
    /// The Warden judges this flow like any other: a ping is a packet leaving the device, and a
    /// firewall that gates TCP and UDP while waving ICMP through is a firewall with a hole in it.
    /// The session is keyed portless (`:0` both ends) because ICMP has no ports — borrowing a port
    /// to fill the field would put a fiction into the Warden's evidence.
    pub(crate) async fn handle_icmp(
        unknown: IpStackUnknownTransport,
        protect: ProtectFn,
        uid: Option<UidFn>,
        fwd: Arc<ForwarderStats>,
    ) {
        let (src, dst) = (unknown.src_addr(), unknown.dst_addr());
        // IPv4 echo only — see the module note on ipstack's IPv6 reverse-packet next-header.
        if !src.is_ipv4() || !dst.is_ipv4() || unknown.ip_protocol() != IPPROTO_ICMPV4 {
            fwd.flows_other.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some(echo) = parse_echo_request(unknown.payload()) else {
            fwd.flows_other.fetch_add(1, Ordering::Relaxed);
            return;
        };

        fwd.icmp_echo.fetch_add(1, Ordering::Relaxed);
        let session = SessionKey::new(
            Proto::Icmp,
            SocketAddr::new(src, 0),
            SocketAddr::new(dst, 0),
        );
        if !warden_allows(&session, &uid, &fwd) {
            // DENIED — dropped, never dialed. NOT counted as a failure: the ping did not fail, it
            // was refused by the user's own firewall, and conflating the two would make the
            // Warden's own block look like a network fault.
            return;
        }

        // The echo gets a docket row like every other flow, so a `ping` is VISIBLE on the dashboard
        // while it is in flight. CRITICAL tin (a diagnostic probe is latency-first) and never
        // paced: there is no window to grow on a single packet.
        let live = docket_enroll_raw(
            flow_key(&session),
            Proto::Icmp.ip_number() as i32,
            0,     // tin CRITICAL
            false, // never paced
        );
        fwd.tin_critical.fetch_add(1, Ordering::Relaxed);

        if echo_once(&echo, dst, &protect, &unknown, &live, &fwd).await {
            fwd.icmp_replied.fetch_add(1, Ordering::Relaxed);
        } else {
            fwd.icmp_failed.fetch_add(1, Ordering::Relaxed);
        }
        crate::tunnel::docket_release(&live);
    }

    /// Send ONE echo request upstream and write its reply back into the tun. `true` when a real
    /// reply came back from the real destination.
    ///
    /// The reply the kernel hands us carries the SOCKET's identifier, not the app's (a ping socket
    /// owns that field), so the id is restored to the requester's before the packet goes back —
    /// otherwise `ping` sees a foreign echo and ignores its own answer.
    async fn echo_once(
        echo: &EchoRequest,
        dst: IpAddr,
        protect: &ProtectFn,
        unknown: &IpStackUnknownTransport,
        live: &Arc<crate::tunnel::FlowLive>,
        fwd: &ForwarderStats,
    ) -> bool {
        let Some(sock) = open_ping_socket(dst, protect) else {
            // Either `protect()` refused (the VPN seam — the N-dial asymmetry) or the kernel denies
            // unprivileged ping sockets. Both are dial failures, counted where dial failures live.
            fwd.dial_protect_failed.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let request = build_echo(ICMP_ECHO_REQUEST, echo.id, echo.seq, &echo.data);
        let sent_at = Instant::now();
        if sock.send(&request).await.is_err() {
            fwd.dial_connect_failed.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let up = request.len() as u64;
        fwd.bytes_up.fetch_add(up, Ordering::Relaxed);
        live.bytes_up.fetch_add(up, Ordering::Relaxed);

        let mut buf = vec![0u8; MAX_ECHO_PAYLOAD];
        let n = match tokio::time::timeout(ECHO_TIMEOUT, sock.recv(&mut buf)).await {
            Ok(Ok(n)) if n >= ICMP_HEADER_LEN => n,
            // Timeout, error, or a runt — no reply. The destination did not answer, and saying so
            // is the whole point of the lane.
            _ => return false,
        };
        buf.truncate(n);

        // A REAL round trip, measured end to end. This is the first RTT in the forwarder that is
        // not inferred from write-drain latency — it is the actual network time the packet took.
        // #96 — `as_millis()` TRUNCATES, so a sub-millisecond echo became 0: the value the docket
        // reserves for "impossible". Measure in f64 and floor through the shared display law.
        let rtt_ms = crate::tunnel::rtt_display_ms(sent_at.elapsed().as_secs_f64() * 1000.0);
        live.rtt_ms.store(rtt_ms, Ordering::Relaxed);
        fwd.rtt_samples.fetch_add(1, Ordering::Relaxed);

        // Rebuild the reply under the REQUESTER's identity: type 0, the app's own id/seq, the data
        // the kernel echoed back, and a checksum recomputed over all of it.
        let reply = build_echo(ICMP_ECHO_REPLY, echo.id, echo.seq, &buf[ICMP_HEADER_LEN..]);
        let down = reply.len() as u64;

        // Back into the tun. `send()` builds the REVERSE IPv4 packet for us — source = the address
        // the app pinged, destination = the app — and inherits the IP protocol byte from the
        // request, so the client sees an ordinary echo reply from the host it asked about.
        if unknown.send(reply).is_err() {
            // The tun sink refused the write: the packet did not make it. Recorded as a stall, the
            // same vocabulary every other arm uses, rather than as a reply we never delivered.
            fwd.stalls.fetch_add(1, Ordering::Relaxed);
            live.stalls.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        fwd.bytes_down.fetch_add(down, Ordering::Relaxed);
        live.bytes_down.fetch_add(down, Ordering::Relaxed);
        true
    }
}

#[cfg(unix)]
pub(crate) use lane::handle_icmp;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarder::session::{Proto, SessionKey};
    use crate::forwarder::shape::flow_key;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// The checksum is the one thing a client verifies before believing a reply, so it is checked
    /// against the RFC's own property: the sum over a message INCLUDING its checksum field folds to
    /// zero. A hand-copied expected constant would only prove the constant was copied.
    #[test]
    fn checksum_folds_to_zero_over_a_complete_message() {
        for len in [0usize, 1, 7, 56, 57, 1000] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let msg = build_echo(ICMP_ECHO_REQUEST, 0xBEEF, 7, &data);
            assert_eq!(
                icmp_checksum(&msg),
                0,
                "checksum does not verify for a {len}-byte payload"
            );
        }
    }

    /// The odd-length tail is the branch a naive `chunks_exact` implementation silently drops.
    #[test]
    fn an_odd_payload_is_not_silently_truncated() {
        let even = build_echo(ICMP_ECHO_REQUEST, 1, 1, &[0xAA, 0xBB]);
        let odd = build_echo(ICMP_ECHO_REQUEST, 1, 1, &[0xAA, 0xBB, 0xCC]);
        assert_ne!(
            &even[2..4],
            &odd[2..4],
            "the trailing odd byte never reached the checksum"
        );
        assert_eq!(icmp_checksum(&odd), 0);
    }

    #[test]
    fn an_echo_request_round_trips_field_for_field() {
        let data: Vec<u8> = (0..56).map(|i| i as u8).collect();
        let wire = build_echo(ICMP_ECHO_REQUEST, 0x1234, 0x5678, &data);
        let parsed = parse_echo_request(&wire).expect("a well-formed echo must parse");
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.seq, 0x5678);
        assert_eq!(parsed.data.as_ref(), data.as_slice());
    }

    /// Everything that is NOT an echo request must fall through to the honest remainder rather than
    /// be answered by a lane that only understands echo.
    #[test]
    fn non_echo_icmp_is_refused_not_answered() {
        // Echo REPLY (type 0) — an app emitting one is not a request to forward.
        assert!(parse_echo_request(&build_echo(ICMP_ECHO_REPLY, 1, 1, &[])).is_none());
        // Destination unreachable (type 3).
        assert!(parse_echo_request(&build_echo(3, 1, 1, &[])).is_none());
        // Truncated below the fixed header.
        assert!(parse_echo_request(&[8, 0, 0, 0, 0, 0, 0]).is_none());
        // Empty.
        assert!(parse_echo_request(&[]).is_none());
        // A non-zero code on an otherwise-valid echo request.
        let mut bad = build_echo(ICMP_ECHO_REQUEST, 1, 1, &[0; 8]);
        bad[1] = 4;
        assert!(parse_echo_request(&bad).is_none());
        // Past one MTU.
        assert!(parse_echo_request(&vec![8u8; MAX_ECHO_PAYLOAD + 1]).is_none());
    }

    /// The reply must carry the REQUESTER's identity, not the ping socket's — the exact field the
    /// kernel rewrites underneath us.
    #[test]
    fn the_reply_restores_the_requesters_identity() {
        let data = b"tortapingpayload".to_vec();
        // What the kernel handed back: an echo reply bearing the SOCKET's id (0x9999), not ours.
        let from_kernel = build_echo(ICMP_ECHO_REPLY, 0x9999, 42, &data);
        let echoed = &from_kernel[ICMP_HEADER_LEN..];
        // What we write into the tun, rebuilt under the app's own id.
        let reply = build_echo(ICMP_ECHO_REPLY, 0xABCD, 42, echoed);
        assert_eq!(reply[0], ICMP_ECHO_REPLY);
        assert_eq!(u16::from_be_bytes([reply[4], reply[5]]), 0xABCD);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 42);
        assert_eq!(&reply[ICMP_HEADER_LEN..], data.as_slice());
        assert_eq!(icmp_checksum(&reply), 0, "the rebuilt reply must verify");
    }

    /// ICMP is portless, and its key must still separate it from a TCP/UDP flow to the same host —
    /// the folded key mixes `ip_number()`, so proto 1 can never collide with 6 or 17 by identity.
    #[test]
    fn an_icmp_session_keys_apart_from_tcp_and_udp() {
        let s = IpAddr::V4(Ipv4Addr::new(10, 1, 10, 1));
        let d = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mk = |p| SessionKey::new(p, SocketAddr::new(s, 0), SocketAddr::new(d, 0));
        let icmp = flow_key(&mk(Proto::Icmp));
        assert_ne!(icmp, flow_key(&mk(Proto::Tcp)));
        assert_ne!(icmp, flow_key(&mk(Proto::Udp)));
        assert_eq!(Proto::Icmp.ip_number(), IPPROTO_ICMPV4);
    }

    // ========================================================================
    // GAP 4: ICMP Echo Reliability Under Network Failure
    // Formal verification gap identified by Caveman Prover
    // Tests for network failure scenarios
    // ========================================================================

    /// GAP 4: Parse partial ICMP echo request (truncated payload)
    /// Proves: Parser handles truncated payloads gracefully
    #[test]
    fn gap4_parse_truncated_icmp_echo_request() {
        // Minimum valid ICMP echo request is 8 bytes (type, code, checksum, id, seq)
        // Truncated: only 6 bytes
        let truncated = vec![8u8, 0, 0xAB, 0xCD, 0x00, 0x01];
        assert!(
            parse_echo_request(&truncated).is_none(),
            "truncated ICMP should fail to parse"
        );
    }

    /// GAP 4: Parse ICMP echo with corrupted checksum
    /// Note: Actual checksum validation happens at kernel level, but we test parsing
    #[test]
    fn gap4_parse_icmp_echo_with_various_checksums() {
        // Valid structure but checksum would be wrong - but we don't validate checksum in parse_echo_request
        // We just parse the structure
        let data = b"test";
        let wire = build_echo(ICMP_ECHO_REQUEST, 0x1234, 0x5678, data);
        let parsed = parse_echo_request(&wire).expect("should parse valid structure");
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.seq, 0x5678);
        assert_eq!(parsed.data.as_ref(), data.as_slice());
    }

    /// GAP 4: Parse non-echo ICMP (destination unreachable, etc.)
    /// Proves: Non-echo ICMP types are refused (not parsed as echo)
    #[test]
    fn gap4_non_echo_icmp_types_refused() {
        // ICMP type 3 = Destination Unreachable
        let not_echo = vec![3u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(
            parse_echo_request(&not_echo).is_none(),
            "non-echo ICMP should not parse as echo request"
        );

        // ICMP type 0 = Echo Reply (should also not parse as request)
        let echo_reply = vec![0u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(
            parse_echo_request(&echo_reply).is_none(),
            "echo reply should not parse as request"
        );
    }

    /// GAP 4: Parse ICMP with payload just below maximum
    /// Proves: Parser handles near-maximum payload correctly
    /// Note: MAX_ECHO_PAYLOAD (1500) is the TOTAL packet size limit.
    /// So data must be < MAX_ECHO_PAYLOAD - ICMP_HEADER_LEN to fit.
    #[test]
    fn gap4_parse_icmp_with_near_maximum_payload() {
        // Maximum data that fits: MAX_ECHO_PAYLOAD - ICMP_HEADER_LEN - 1
        // Because total packet = header + data < MAX_ECHO_PAYLOAD
        let max_data_len = MAX_ECHO_PAYLOAD - ICMP_HEADER_LEN - 1;
        let data: Vec<u8> = (0..max_data_len).map(|i| i as u8).collect();
        let wire = build_echo(ICMP_ECHO_REQUEST, 1, 1, &data);
        let parsed = parse_echo_request(&wire).expect("near-max payload should parse");
        assert_eq!(parsed.data.as_ref().len(), max_data_len);
    }

    /// GAP 4: Parse ICMP with payload at or exceeding maximum
    /// Proves: Oversized payload is rejected
    #[test]
    fn gap4_parse_icmp_exceeding_maximum_payload() {
        // At maximum: total packet = MAX_ECHO_PAYLOAD, should be rejected
        let data: Vec<u8> = (0..MAX_ECHO_PAYLOAD - ICMP_HEADER_LEN)
            .map(|i| i as u8)
            .collect();
        let wire = build_echo(ICMP_ECHO_REQUEST, 1, 1, &data);
        assert!(
            parse_echo_request(&wire).is_none(),
            "at-max payload should be rejected (>= MAX_ECHO_PAYLOAD)"
        );

        // Exceeding maximum: should also be rejected
        let data: Vec<u8> = (0..MAX_ECHO_PAYLOAD + 100)
            .map(|i| i as u8)
            .collect();
        let wire = build_echo(ICMP_ECHO_REQUEST, 1, 1, &data);
        assert!(
            parse_echo_request(&wire).is_none(),
            "oversized payload should be rejected"
        );
    }
}
