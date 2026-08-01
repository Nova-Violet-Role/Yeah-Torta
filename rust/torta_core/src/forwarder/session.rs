/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! N1 — the SESSION KEY (the 5-tuple that identifies one forwarded flow).
//!
//! The Rust twin of firestack's `tcpipConnectionID` (netstack/forwarders.go:62) + NetGuard's `ng_session`
//! 5-tuple. Every non-DNS flow the netstack `accept()` yields is keyed by `(proto, src, dst)` — src/dst are
//! full `SocketAddr` (ip:port), so the pair already carries sport/dport. The forwarder's session map
//! (`HashMap<SessionKey, Session>`, RAM tier) uses this as the key; the Warden verdict + the protected
//! upstream dial read the `dst` (N2/N3/N-warden).
//!
//! ipstack yields `peer_addr()` (the ORIGINAL destination the app dialed — what we forward TO) and
//! `local_addr()` (the app's source) per stream (`stream/mod.rs:21/34`), so a `SessionKey` is built directly
//! from the accepted stream — no re-parse of the raw packet. Pure value type, `Copy`, host-testable.

use std::net::SocketAddr;

/// The transport of a forwarded flow. TCP carries page loads (the North Star, N2); UDP carries QUIC/HTTP3
/// (the simpler first witness, N3). Kept as our own enum (not ipstack's) so the session map + the Warden
/// verdict do not depend on the netstack crate's types — the dnscrypt-port discipline (our types at the seam).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Proto {
    Tcp,
    Udp,
    /// ★ #51 N9 — ICMPv4, the ECHO lane. Portless by nature: an ICMP session's `src`/`dst` carry
    /// port `0`, which is the honest value (there is no port to report) rather than a borrowed one.
    /// It is a transport class here for exactly one reason — the Warden gates on `ip_number()`, and
    /// a ping must be judged by the same court as every other flow.
    Icmp,
}

impl Proto {
    /// The IANA protocol number (TCP 6, UDP 17, ICMP 1) — the value the Warden `verdict(proto, ...)`
    /// gate reads (warden.rs:74) + the `parse.rs` `proto` field speaks. Keeps the forwarder and the
    /// firewall in one vocabulary.
    pub(crate) fn ip_number(self) -> u8 {
        match self {
            Proto::Tcp => 6,
            Proto::Udp => 17,
            Proto::Icmp => 1,
        }
    }
}

/// One forwarded flow's identity — the 5-tuple (`proto` + `src` ip:port + `dst` ip:port). `Copy` + `Hash` so
/// it keys the RAM-tier session map with zero allocation (the D45 slot-per-key discipline the pool uses).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionKey {
    pub(crate) proto: Proto,
    /// The app's source endpoint (`local_addr()` of the accepted stream — the tun-side origin).
    pub(crate) src: SocketAddr,
    /// The ORIGINAL destination the app dialed (`peer_addr()` — what the forwarder connects the protected
    /// upstream socket TO, and what the Warden verdict gates on).
    pub(crate) dst: SocketAddr,
}

impl SessionKey {
    pub(crate) fn new(proto: Proto, src: SocketAddr, dst: SocketAddr) -> Self {
        SessionKey { proto, src, dst }
    }

    /// The destination IP (for the Warden verdict + attribution — the Beast ip→domain reverse-map, B2).
    pub(crate) fn dst_ip(&self) -> std::net::IpAddr {
        self.dst.ip()
    }

    /// The destination port (the Warden verdict + the Tortä tin classification, N5: 53/443 → Critical/High).
    pub(crate) fn dst_port(&self) -> u16 {
        self.dst.port()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn v4(a: [u8; 4], p: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a[0], a[1], a[2], a[3]), p))
    }

    #[test]
    fn proto_ip_numbers_match_iana() {
        assert_eq!(Proto::Tcp.ip_number(), 6);
        assert_eq!(Proto::Udp.ip_number(), 17);
    }

    #[test]
    fn session_key_is_a_hashable_5_tuple() {
        use std::collections::HashMap;
        let k = SessionKey::new(
            Proto::Tcp,
            v4([10, 1, 10, 1], 44321),
            v4([140, 82, 121, 3], 443),
        );
        assert_eq!(k.dst_ip(), Ipv4Addr::new(140, 82, 121, 3));
        assert_eq!(k.dst_port(), 443);
        // The map keys on the whole 5-tuple: a different sport is a DIFFERENT flow (NAT correctness).
        let mut m: HashMap<SessionKey, u32> = HashMap::new();
        m.insert(k, 1);
        let k2 = SessionKey::new(
            Proto::Tcp,
            v4([10, 1, 10, 1], 44322),
            v4([140, 82, 121, 3], 443),
        );
        assert!(
            m.get(&k2).is_none(),
            "a different source port is a distinct flow"
        );
        assert_eq!(m.get(&k), Some(&1));
    }
}
