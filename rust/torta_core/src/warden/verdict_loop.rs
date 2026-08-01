/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! THE DNS-ANSWER VERDICT LOOP — slice 3, the clean-room reimplementation of the dnsmasq
//! per-domain verdict-loop SHAPE.
//!
//! ## CLEAN-ROOM PROVENANCE (the Genesis law — ZERO derived bytes)
//! dnsmasq-2.93 walks a resolved DNS answer with a nested loop — "for each resolved address, for each
//! armed per-domain rule-set whose domain matches the query name, emit an ADD to the kernel ipset".
//! That nested **name-driven, address-walked, per-rule** SHAPE is the IDEA this module overhauls; the
//! dnsmasq C was NOT read while writing it. The Warden INVERTS the action (the additive-block-only
//! fork, REWORKED §): where dnsmasq ADDs a resolved address to a kernel set on a match, the Warden
//! DENIES on the first match and ABSTAINS otherwise — and it is app-layer (the Monokuma datapath), so
//! there is NO kernel netlink/nftset push (out of scope, Eidolon §4). The GPL-2.0 corpus is credited in
//! NOTICE; no source byte ships.
//!
//! ## THE TWO VERDICT PATHS (do NOT conflate)
//!   1. The per-connection FIREWALL verdict ([`super::Warden::verdict`] — the 6-tier cascade) judges a
//!      CONNECTION (uid + daddr + dport + proto + qname).
//!   2. THIS DNS-answer verdict ([`apply_dns_verdict`]) judges a RESOLVED ANSWER (a name + its resolved
//!      addresses) against the armed UNIVERSAL block rules.
//!
//! They meet at exactly ONE narrow seam (Anti-Venom §5d): a [`DnsVerdict::Deny`] here is what the DNS
//! resolver turns into the `ConnFacts::dns_blocked` flag that the per-connection cascade then consumes
//! at TIER 5. The Warden does not re-query the blocklist on the connection path; it trusts the flag this
//! loop produced. This loop is the PRODUCER half of that seam — the half that was missing.

use std::net::IpAddr;

use super::cidr_match::CidrMatch;
use super::pattern::DomainPattern;
use super::DomainRuleSet;

/// Why a resolved DNS answer was denied — the rule class that fired (first-match). Carried for the
/// `query-warden.log` verdict line (slice 6); the per-connection seam only needs the binary outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsDenyReason {
    /// The resolved NAME matched a universal BLOCK domain rule (the reversed-label trie, the plain
    /// blocklist-entry case).
    Domain,
    /// The resolved NAME matched a validated GLOB pattern (`*.ads.net`, `ad*.tracker.net`) — the
    /// dnsmasq per-label glob.
    GlobDomain,
    /// A resolved ADDRESS fell inside a universal BLOCK CIDR (v4 or v6).
    Address,
}

/// The outcome of judging a resolved DNS answer. The DNS resolver maps [`Deny`](DnsVerdict::Deny) to the
/// `ConnFacts::dns_blocked` flag (the TIER-5 seam); [`Allow`](DnsVerdict::Allow) leaves it `false`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsVerdict {
    /// No universal rule matched the name or any resolved address — the resolver does NOT set
    /// `dns_blocked`.
    Allow,
    /// A universal rule matched (first-match-wins) — the resolver sets `dns_blocked`. The `DnsDenyReason`
    /// is the rule class that fired.
    Deny(DnsDenyReason),
}

impl DnsVerdict {
    /// True for a [`Deny`](DnsVerdict::Deny). The seam only needs the binary outcome (the reason feeds
    /// the slice-6 log).
    pub fn is_deny(self) -> bool {
        matches!(self, DnsVerdict::Deny(_))
    }
}

/// Judge a resolved DNS answer (`name` + its resolved `addrs`) against the armed UNIVERSAL block rules.
/// NAME-driven first, then ADDRESS-walked, FIRST-match denies (additive-block-only):
///   1. the universal plain-domain trie (the 99% blocklist-entry case),
///   2. the validated glob patterns (the dnsmasq per-label glob, dot-is-a-barrier),
///   3. every resolved address against the family-aware universal CIDR blocks (v4 AND v6).
///
/// Abstains ([`DnsVerdict::Allow`]) when nothing matches. Pure + allocation-free over the caller's
/// slices; no IO, no clock, no lock. The overhauled dnsmasq `cache_recv_insert` loop — deny-on-match,
/// never add-to-kernel-set.
pub fn apply_dns_verdict(
    name: &str,
    addrs: &[IpAddr],
    domain: &DomainRuleSet,
    glob_patterns: &[DomainPattern],
    cidr_blocks: &[CidrMatch],
) -> DnsVerdict {
    let name = name.trim().trim_end_matches('.');

    // NAME tier 1 — the universal plain-domain trie (apex + subdomains; the common blocklist entry).
    if !name.is_empty() && domain.matches_universal(name) {
        return DnsVerdict::Deny(DnsDenyReason::Domain);
    }

    // NAME tier 2 — the validated glob patterns (the dnsmasq per-label glob; the dot-is-a-barrier law
    // is enforced inside `DomainPattern::matches`).
    if !name.is_empty() {
        for pat in glob_patterns {
            if pat.matches(name) {
                return DnsVerdict::Deny(DnsDenyReason::GlobDomain);
            }
        }
    }

    // ADDRESS tier — walk EVERY resolved address against EVERY universal CIDR block (v4 and v6). This
    // is where the family-aware matcher closes the old v4-only gap: a resolved AAAA is now judged too.
    for &addr in addrs {
        for cidr in cidr_blocks {
            if cidr.matches(addr) {
                return DnsVerdict::Deny(DnsDenyReason::Address);
            }
        }
    }

    DnsVerdict::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warden::pattern::validate_pattern;
    use crate::warden::{DomainRule, DomainRuleSet, UID_UNIVERSAL};
    use std::net::Ipv4Addr;

    fn universal_domain(domains: &[&str]) -> DomainRuleSet {
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

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    #[test]
    fn dns_verdict_first_match_deny() {
        let domain = universal_domain(&["ads.example.com"]);
        let globs = vec![validate_pattern("*.tracker.net").unwrap()];
        let cidrs = vec![CidrMatch::V4 {
            net: u32::from("203.0.113.0".parse::<Ipv4Addr>().unwrap()),
            prefix: 24,
        }];

        // NAME hit (the plain trie) — denies on the name, never reaching the addresses.
        assert_eq!(
            apply_dns_verdict("ads.example.com", &[v4("8.8.8.8")], &domain, &globs, &cidrs),
            DnsVerdict::Deny(DnsDenyReason::Domain)
        );
        // A subdomain of a wildcard trie rule.
        assert_eq!(
            apply_dns_verdict("pixel.ads.example.com", &[], &domain, &globs, &cidrs),
            DnsVerdict::Deny(DnsDenyReason::Domain)
        );
        // GLOB name hit.
        assert_eq!(
            apply_dns_verdict(
                "metrics.tracker.net",
                &[v4("8.8.8.8")],
                &domain,
                &globs,
                &cidrs
            ),
            DnsVerdict::Deny(DnsDenyReason::GlobDomain)
        );
        // ADDRESS hit (name clean, a resolved addr lands in the blocked /24).
        assert_eq!(
            apply_dns_verdict(
                "good.example.org",
                &[v4("203.0.113.9")],
                &domain,
                &globs,
                &cidrs
            ),
            DnsVerdict::Deny(DnsDenyReason::Address)
        );
    }

    #[test]
    fn dns_verdict_allow_when_no_match() {
        let domain = universal_domain(&["ads.example.com"]);
        let globs = vec![validate_pattern("*.tracker.net").unwrap()];
        let cidrs = vec![CidrMatch::V4 {
            net: 0x0A000000,
            prefix: 8,
        }]; // 10.0.0.0/8

        let v = apply_dns_verdict(
            "cdn.example.org",
            &[v4("93.184.216.34"), v4("8.8.4.4")],
            &domain,
            &globs,
            &cidrs,
        );
        assert_eq!(v, DnsVerdict::Allow);
        assert!(!v.is_deny());

        // An empty answer (no addrs) on a clean name is also Allow.
        assert_eq!(
            apply_dns_verdict("clean.example.org", &[], &domain, &globs, &cidrs),
            DnsVerdict::Allow
        );
    }

    #[test]
    fn dns_verdict_cidr_v6_deny() {
        // The v6 address-walk — the gap the family-aware matcher closes (a resolved AAAA in a blocked
        // /32 denies, where the legacy v4-only path abstained).
        let domain = DomainRuleSet::new();
        let globs: Vec<DomainPattern> = Vec::new();
        let cidrs = vec![CidrMatch::V6 {
            net: u128::from("2001:db8::".parse::<std::net::Ipv6Addr>().unwrap()),
            prefix: 32,
        }];
        let answer = IpAddr::V6("2001:db8:dead::1".parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(
            apply_dns_verdict("tracker.example", &[answer], &domain, &globs, &cidrs),
            DnsVerdict::Deny(DnsDenyReason::Address)
        );
        // A v6 address OUTSIDE the block abstains.
        let clean = IpAddr::V6("2001:db9::1".parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(
            apply_dns_verdict("tracker.example", &[clean], &domain, &globs, &cidrs),
            DnsVerdict::Allow
        );
    }
}
