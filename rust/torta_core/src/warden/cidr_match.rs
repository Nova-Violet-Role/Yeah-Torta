/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! THE FAMILY-AWARE CIDR MATCHER — slice 3, a clean-room reimplementation of the dnsmasq
//! address-prefix deny IDEA.
//!
//! ## CLEAN-ROOM PROVENANCE (the Genesis law — ZERO derived bytes)
//! The dnsmasq-2.93 firewall functions carry a family-tagged prefix-bounded address match
//! (`struct bogus_addr` = an `is6` flag + a `prefix` length + a `union all_addr` network — a
//! CIDR with a family bit). That SHAPE — "a family-tagged network/prefix matched by one masked
//! compare, dispatched on the address family" — is the IDEA this module overhauls. The dnsmasq C
//! was NOT read while writing this; every line is original Rust over [`std::net::IpAddr`], and the
//! masked-compare is the textbook subnet test (public knowledge, not dnsmasq's IP). GPL-2.0 corpus
//! credited in NOTICE; no source byte ships.
//!
//! ## WHY (the gap it closes)
//! The original per-connection CIDR matcher (`Cidr { net: u32 }`) was IPv4-only and abstained on
//! IPv6 (`ipv4_host_order` returned `None` for v6). The DNS-answer verdict
//! ([`super::verdict_loop::apply_dns_verdict`]) walks the RESOLVED addresses of a name, which can be
//! A (v4) **or** AAAA (v6). This matcher judges BOTH families with one masked compare, so a resolved
//! IPv6 address is no longer silently un-judged. Since A3 the per-connection cascade routes through
//! this matcher TOO ([`super::IpRule`] carries a [`CidrMatch`]) — the v4-only `Cidr` and its
//! abstain gate are retired, so a v6 FLOW is judged the same as a v6 answer.

use std::net::IpAddr;

/// One family-tagged CIDR — a network address + a prefix length, matched by a single masked compare.
/// Allocation-free and `Copy`; the DNS-answer verdict holds a small `Vec<CidrMatch>` of the armed
/// universal blocks and walks every resolved address against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CidrMatch {
    /// An IPv4 network (host-order `u32`) + prefix `0..=32`. `prefix == 0` matches every IPv4 address.
    V4 {
        /// Host-order IPv4 network address (host bits below the prefix are ignored on match).
        net: u32,
        /// Prefix length `0..=32`.
        prefix: u8,
    },
    /// An IPv6 network (`u128`) + prefix `0..=128`. `prefix == 0` matches every IPv6 address.
    V6 {
        /// IPv6 network address as a `u128` (host bits below the prefix are ignored on match).
        net: u128,
        /// Prefix length `0..=128`.
        prefix: u8,
    },
}

impl CidrMatch {
    /// True if `addr` falls inside this CIDR. Family-dispatched: an IPv4 rule NEVER matches an IPv6
    /// address and vice-versa (a family mismatch is `false`, not a panic — the dnsmasq family-bit
    /// idea, expressed as the enum tag). One masked compare per family; no allocation.
    pub fn matches(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (CidrMatch::V4 { net, prefix }, IpAddr::V4(v4)) => {
                v4_contains(*net, *prefix, u32::from(v4))
            }
            (CidrMatch::V6 { net, prefix }, IpAddr::V6(v6)) => {
                v6_contains(*net, *prefix, u128::from(v6))
            }
            // Family mismatch — a v4 rule cannot deny a v6 address (and vice-versa). Never matches.
            _ => false,
        }
    }

    /// Parse a CIDR string (`"203.0.113.0/24"`, `"2001:db8::/32"`, or a bare address = host route).
    /// Returns `None` on a malformed address / out-of-range prefix (the caller drops the rule —
    /// abstain-on-bad-input, never a false deny). The natural constructor for a CIDR arriving as text
    /// from a Trust-scored blocklist (slice 5); the engine's own conversion path builds the variants
    /// directly.
    pub fn parse(input: &str) -> Option<CidrMatch> {
        let s = input.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (s, None),
        };
        let addr: IpAddr = addr_part.parse().ok()?;
        match addr {
            IpAddr::V4(v4) => {
                let prefix = match prefix_part {
                    Some(p) => p.parse::<u8>().ok().filter(|&x| x <= 32)?,
                    None => 32,
                };
                Some(CidrMatch::V4 {
                    net: u32::from(v4),
                    prefix,
                })
            }
            IpAddr::V6(v6) => {
                let prefix = match prefix_part {
                    Some(p) => p.parse::<u8>().ok().filter(|&x| x <= 128)?,
                    None => 128,
                };
                Some(CidrMatch::V6 {
                    net: u128::from(v6),
                    prefix,
                })
            }
        }
    }
}

/// `ip` ∈ `net/prefix` for IPv4 — the masked compare. `prefix == 0` is the IP-wildcard (matches all);
/// `prefix >= 32` is the exact host route. The shift is bounded (`prefix ∈ 1..=31` ⇒ `32 - prefix ∈
/// 1..=31`), so no overflow.
fn v4_contains(net: u32, prefix: u8, ip: u32) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix >= 32 {
        return ip == net;
    }
    let mask = u32::MAX << (32 - prefix);
    (ip & mask) == (net & mask)
}

/// `ip` ∈ `net/prefix` for IPv6 — the masked compare (the `u128` sibling of [`v4_contains`]).
fn v6_contains(net: u128, prefix: u8, ip: u128) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix >= 128 {
        return ip == net;
    }
    let mask = u128::MAX << (128 - prefix);
    (ip & mask) == (net & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn cidr_match_v4_v6() {
        // IPv4 /24 — in-range vs out-of-range, host bits ignored.
        let net4 = CidrMatch::V4 {
            net: u32::from("203.0.113.0".parse::<Ipv4Addr>().unwrap()),
            prefix: 24,
        };
        assert!(
            net4.matches(v4("203.0.113.7")),
            "203.0.113.7 ∈ 203.0.113.0/24"
        );
        assert!(
            net4.matches(v4("203.0.113.255")),
            "the broadcast host is still in the /24"
        );
        assert!(!net4.matches(v4("203.0.114.1")), "203.0.114.1 ∉ the /24");

        // A /32 host route is an exact match.
        let host4 = CidrMatch::V4 {
            net: u32::from("198.51.100.9".parse::<Ipv4Addr>().unwrap()),
            prefix: 32,
        };
        assert!(host4.matches(v4("198.51.100.9")));
        assert!(!host4.matches(v4("198.51.100.10")));

        // IPv6 /32 — the dnsmasq-v4-only gap this module closes.
        let net6 = CidrMatch::V6 {
            net: u128::from("2001:db8::".parse::<Ipv6Addr>().unwrap()),
            prefix: 32,
        };
        assert!(
            net6.matches(v6("2001:db8:dead:beef::1")),
            "inside 2001:db8::/32"
        );
        assert!(!net6.matches(v6("2001:db9::1")), "outside the /32");
    }

    #[test]
    fn prefix_zero_matches_all() {
        let all4 = CidrMatch::V4 { net: 0, prefix: 0 };
        assert!(all4.matches(v4("1.2.3.4")));
        assert!(all4.matches(v4("255.255.255.255")));
        let all6 = CidrMatch::V6 { net: 0, prefix: 0 };
        assert!(all6.matches(v6("::1")));
        assert!(all6.matches(v6("fe80::abcd")));
    }

    #[test]
    fn family_mismatch_never_matches() {
        // A v4 rule NEVER denies a v6 address (and vice-versa) — the family bit is load-bearing.
        let net4 = CidrMatch::V4 { net: 0, prefix: 0 };
        assert!(
            !net4.matches(v6("::1")),
            "a v4 rule must not match a v6 address"
        );
        let net6 = CidrMatch::V6 { net: 0, prefix: 0 };
        assert!(
            !net6.matches(v4("1.2.3.4")),
            "a v6 rule must not match a v4 address"
        );
    }

    #[test]
    fn parse_round_trips_v4_and_v6() {
        assert_eq!(
            CidrMatch::parse("203.0.113.0/24"),
            Some(CidrMatch::V4 {
                net: u32::from("203.0.113.0".parse::<Ipv4Addr>().unwrap()),
                prefix: 24
            })
        );
        // A bare v4 address = a /32 host route.
        assert_eq!(
            CidrMatch::parse("8.8.8.8"),
            Some(CidrMatch::V4 {
                net: u32::from("8.8.8.8".parse::<Ipv4Addr>().unwrap()),
                prefix: 32
            })
        );
        // A bare v6 address = a /128 host route.
        assert_eq!(
            CidrMatch::parse("2001:db8::1"),
            Some(CidrMatch::V6 {
                net: u128::from("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
                prefix: 128
            })
        );
        // Out-of-range prefix / garbage ⇒ None (abstain, never a false deny).
        assert_eq!(CidrMatch::parse("203.0.113.0/33"), None);
        assert_eq!(CidrMatch::parse("2001:db8::/129"), None);
        assert_eq!(CidrMatch::parse("not-an-ip/8"), None);
        assert_eq!(CidrMatch::parse(""), None);
    }
}
