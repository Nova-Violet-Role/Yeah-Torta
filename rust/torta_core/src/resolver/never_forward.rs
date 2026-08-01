/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

#![forbid(unsafe_code)]

//! #91 (P12 step-1.5) — the **never-forward privacy guard** (the `.arpa` / sonar block).
//!
//! A reverse-DNS PTR lookup of a *private* address (`192.168.0.1 → 1.0.168.192.in-addr.arpa`) is a
//! query the upstream resolver has no business seeing: forwarding it lets the resolver "sonar"-map your
//! LAN from your own reverse lookups (RFC 1918 / loopback / link-local / ULA space is private by
//! definition). The same is true of the RFC 6761/8375 special-use zones (`.home.arpa`, `.lan`,
//! `.internal`, `.local`): a name under them with no local record is *meant* to be answered locally,
//! never egressed.
//!
//! This module answers both LOCALLY with an **NXDOMAIN synthesized in-crate** —
//! [`crate::dns::build_nxdomain_response`], the same denial primitive the blocklist uses — so **ZERO
//! transport emission, ZERO new query leak**. That is the whole point of #91: the guard cannot create a
//! leak because it never reaches the pool; the answer is built from the query bytes already in hand.
//!
//! ## Where it runs (the seam)
//!
//! [`local_answer_if_never_forward`] is consulted at the **step-1.5 seam** in
//! [`super::Resolver::resolve_inner`] — AFTER the block-check, BEFORE cache / routing / egress
//! (`mod.rs:295`). A `Some(resp)` short-circuits the resolve: the synthesized NXDOMAIN returns
//! immediately and the pool / cache / step-4 validate are provably never touched (the egress is
//! unreachable code past the early `return`). A `None` falls through to the normal ladder, so a PUBLIC
//! PTR (a legitimate reverse lookup of a routable address) still forwards exactly as before.
//!
//! ## Two branches, no overlap
//!
//! 1. **PTR private-IP block** — `qtype == 12` (PTR) and [`crate::dns::decode_ptr_to_ip`] decodes the
//!    `.in-addr.arpa`/`.ip6.arpa` qname to an `IpAddr` that is NOT public → NXDOMAIN. A *public*-IP
//!    PTR decodes fine but is public → falls through (forwards). A malformed/garbage reverse name
//!    decodes to `None` → falls through (it isn't ours to deny).
//! 2. **Never-forward suffix trie** — a name under a seeded RFC 6761/8375 special-use suffix
//!    (`.home.arpa`/`.lan`/`.internal`/`.local`) with no local record → NXDOMAIN. (We hold no local
//!    records today, so any match denies; when a local-record store lands it is consulted before this.)
//!    The reverse zones `.in-addr.arpa`/`.ip6.arpa` are deliberately **NOT** seeded here — they are
//!    handled by branch 1 keyed on the *decoded IP's* privacy, so a PUBLIC reverse lookup still works.
//!
//! ## Why a reversed-label trie (a structural clone, not a fork)
//!
//! The suffix matcher is the EXACT structural shape of the blocklist matcher
//! (`blocklist.rs:68-72` `Node{children:HashMap<Box<str>,Node>, terminal}`) and the routing trie
//! (`routing.rs:67-74`) — a label-keyed trie inserted TLD-first (`rsplit('.')`) so a parent zone is a
//! PREFIX of the path and **subdomain coverage falls out for free** (`.home.arpa` covers
//! `printer.home.arpa`). Lookup is longest-suffix-wins but, like `blocklist::is_blocked`, we early-exit
//! at the FIRST terminal: any seeded suffix on the path → NXDOMAIN, no "deeper override" semantics
//! needed. We do NOT call into `blocklist.rs` (its `Node`/`Matcher` are private); we clone the *shape*,
//! the only honest reuse — exactly the posture `routing.rs` took (`routing.rs:30-34`).
//!
//! ## Invariants
//!
//! Pure `std::net` (`Ipv4Addr`/`Ipv6Addr`/`IpAddr`) + `crate::dns` + `crate::resolver::rebind` — **no
//! new crate dep**, `#![forbid(unsafe_code)]`, additive. The trie depth is bounded by [`MAX_LABELS`]
//! (mirrors `blocklist.rs`/`routing.rs:56`) so the recursive `Drop` and the walks cannot overflow on a
//! hostile name. INERT until Stage-1 (#85) arms the resolver primary — it ships dormant like the rest of
//! the resolver.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::dns;
use crate::resolver::rebind;

/// DNS PTR (reverse-lookup) qtype — RFC 1035 §3.2.2.
const QTYPE_PTR: u16 = 12;

/// P12 Expert toggle — `DNSMASQ_NEVER_FORWARD` (default ON, `PreferenceKeys.java:247`). When the Socio
/// turns it OFF the step-1.5 privacy guard is bypassed wholesale: [`local_answer_if_never_forward`]
/// returns `None` for every name, so private PTR / special-use lookups take the normal resolve ladder.
/// Default `true` mirrors the pref default. Pushed from Kotlin via `TortaCore.nativeResolverSetNeverForward`.
static NEVER_FORWARD_ENABLED: AtomicBool = AtomicBool::new(true);

/// Set the `--never-forward` privacy guard on/off (the `DNSMASQ_NEVER_FORWARD` Expert toggle).
pub fn set_never_forward_enabled(on: bool) {
    NEVER_FORWARD_ENABLED.store(on, Ordering::Relaxed);
}

/// The live `--never-forward` state (the 2-FEED-MaskSolver SETTINGS read-back; `stats()` surfaces it so
/// the pane shows the ENGINE's real guard state on entry, never an optimistic UI echo).
pub fn never_forward_enabled() -> bool {
    NEVER_FORWARD_ENABLED.load(Ordering::Relaxed)
}

/// Trie-depth cap — mirrors `blocklist.rs:37` / `routing.rs:56` (`MAX_LABELS`). A suffix with more
/// labels than this is rejected at seed and never walked at lookup, so the recursive `Drop`/walks
/// cannot overflow on a hostile suffix.
const MAX_LABELS: usize = 127;

/// The RFC 6761 / RFC 8375 special-use suffixes seeded into the never-forward trie. A name under any of
/// these (with no local record) is answered locally (NXDOMAIN), never egressed.
///
/// - `.home.arpa` — RFC 8375 (the designated home-network zone).
/// - `.local` — RFC 6761 §6.4 (and mDNS, RFC 6762).
/// - `.lan` / `.internal` — de-facto RFC 6761-class special-use local zones.
///
/// The reverse zones `.in-addr.arpa`/`.ip6.arpa` are intentionally absent — they are decided by the
/// PTR branch keyed on the *decoded IP*, so a PUBLIC reverse lookup still forwards. Seeding them here
/// would wrongly NXDOMAIN public reverse lookups.
const SEED_SUFFIXES: [&str; 4] = ["home.arpa", "local", "lan", "internal"];

/// The step-1.5 oracle. Returns `Some(nxdomain_bytes)` when the query is a never-forward name that must
/// be answered LOCALLY (so the caller short-circuits BEFORE cache/routing/egress), or `None` when the
/// query should take the normal resolve ladder.
///
/// Branches (first match wins):
/// 1. PTR (`qtype == 12`) of a private/loopback/link-local/ULA IP → NXDOMAIN (no LAN sonar egress).
/// 2. A name under a seeded RFC 6761/8375 special-use suffix → NXDOMAIN (no special-use egress).
///
/// `qname` is expected already lowercased + trailing-dot-stripped (as `dns::parse_question` /
/// `dns::read_name` produce, `dns.rs:31-33`); the trie is seeded lowercase so the match is exact. Pure,
/// never panics: a malformed reverse name or a malformed query yields `None` rather than a denial.
///
/// PRIVACY LAW: the only response this can produce is a locally-synthesized NXDOMAIN built from the
/// query bytes already in hand ([`crate::dns::build_nxdomain_response`]) — it NEVER constructs, holds,
/// or forwards an upstream query. It cannot introduce a new leak.
pub fn local_answer_if_never_forward(query: &[u8], qname: &str, qtype: u16) -> Option<Vec<u8>> {
    // P12 toggle (`DNSMASQ_NEVER_FORWARD`): disabled ⇒ no guard, every name takes the resolve ladder.
    if !NEVER_FORWARD_ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    // Branch 1 — reverse-DNS PTR of a NON-public IP: never let a private reverse lookup egress.
    if qtype == QTYPE_PTR {
        if let Some(ip) = dns::decode_ptr_to_ip(qname) {
            // `is_rebind(&[ip])` == `!is_public_ip(ip)` for a single IP (`resolver/rebind.rs`); reused
            // here so the private classifier is never re-implemented (REUSE-law) and `rebind`'s
            // `is_public_ip` visibility is left untouched. A private/loopback/link-local/ULA IP → deny;
            // a public IP → fall through (a legitimate public reverse lookup still forwards).
            if rebind::is_rebind(&[ip]) {
                // Locally synthesized — no transport, no egress, no new leak.
                return dns::build_nxdomain_response(query);
            }
            // public-IP PTR: not ours to deny → fall through to the normal ladder.
        }
        // malformed / garbage reverse name (decode → None): not a private reverse lookup we recognize →
        // fall through (do NOT deny a name we could not decode).
    }

    // Branch 2 — a name under a seeded RFC 6761/8375 special-use suffix, with no local record. We hold
    // no local records today, so a suffix match denies (NXDOMAIN, no egress). Any qtype: a special-use
    // name's A/AAAA/PTR/etc. all must stay local.
    if NEVER_FORWARD_TRIE.with(|trie| trie.matches(qname)) {
        return dns::build_nxdomain_response(query);
    }

    None
}

// ---------------------------------------------------------------------------------------------------
// The never-forward suffix trie — a structural clone of `blocklist.rs`/`routing.rs` (label-keyed,
// TLD-first, bounded), seeded once with the RFC 6761/8375 special-use suffixes.
// ---------------------------------------------------------------------------------------------------

thread_local! {
    /// The seeded never-forward trie, built once per thread from [`SEED_SUFFIXES`]. Thread-local keeps
    /// it allocation-free at the seam (no per-query rebuild, no global lock) and dependency-free (no new
    /// crate dep for a `OnceLock`-vs-`thread_local` choice — `std::thread_local!` is std). It is
    /// immutable after seeding; a thread builds it lazily on first use.
    static NEVER_FORWARD_TRIE: SuffixTrie = SuffixTrie::seeded();
}

/// One trie node, keyed by DNS label (TLD-first) — the structural clone of `blocklist.rs:68-72`
/// (`Node{children, terminal}`). `terminal` marks a seeded never-forward suffix ending here.
#[derive(Default)]
struct Node {
    children: HashMap<Box<str>, Node>,
    /// A seeded never-forward suffix terminates here — this suffix AND everything beneath it is a
    /// never-forward match (early-exit at the first terminal, like `blocklist::is_blocked`).
    terminal: bool,
}

/// A compiled never-forward suffix matcher: TLD-first label trie, first-terminal-wins with free
/// subdomain coverage. Seeded once from [`SEED_SUFFIXES`]; immutable thereafter.
struct SuffixTrie {
    root: Node,
}

impl SuffixTrie {
    /// Build the trie pre-seeded with the RFC 6761/8375 special-use suffixes.
    fn seeded() -> Self {
        let mut trie = SuffixTrie {
            root: Node::default(),
        };
        for suffix in SEED_SUFFIXES {
            trie.insert(suffix);
        }
        trie
    }

    /// Insert a suffix (already canonical/lowercase, no leading/trailing dot). Walks labels TLD-first
    /// (`rsplit('.')`) so a parent zone is a PREFIX of the path — the blocklist/routing shape. An empty
    /// or over-deep suffix is dropped (never panics, never an unbounded `Drop`).
    fn insert(&mut self, suffix: &str) {
        if suffix.is_empty() || suffix.split('.').count() > MAX_LABELS {
            return;
        }
        let mut node = &mut self.root;
        for label in suffix.rsplit('.') {
            if label.is_empty() {
                continue; // skip empty labels (defensive; seeds are clean)
            }
            node = node.children.entry(label.into()).or_default();
        }
        node.terminal = true;
    }

    /// `true` iff `qname` is at or beneath a seeded never-forward suffix. Walks `qname` TLD-first and
    /// early-exits at the FIRST terminal on the path (any seeded suffix → match, like
    /// `blocklist::is_blocked`, `blocklist.rs:211-228`). `qname` is expected already lowercased +
    /// dot-normalized (`dns::read_name`, `dns.rs:33`); `O(labels)`, bounded by [`MAX_LABELS`], never a
    /// full rescan, never panics.
    fn matches(&self, qname: &str) -> bool {
        if qname.is_empty() {
            return false;
        }
        let mut node = &self.root;
        let mut depth = 0usize;
        for label in qname.rsplit('.') {
            depth += 1;
            if depth > MAX_LABELS {
                return false; // hostile over-deep name — stop walking (no match seen)
            }
            if label.is_empty() {
                continue;
            }
            match node.children.get(label) {
                Some(child) => {
                    if child.terminal {
                        return true; // a seeded suffix ends here — match (first-terminal-wins)
                    }
                    node = child;
                }
                None => return false, // path diverges from every seeded suffix — not ours
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // ---- helpers ----

    /// Forge a minimal DNS query wire for `qname`/`qtype` so the synthesized NXDOMAIN has a real
    /// question to echo. Reuses the crate's own `dns::build_query` (`dns.rs`), the canonical builder —
    /// no hand-rolled wire here.
    fn query_for(qname: &str, qtype: u16) -> Vec<u8> {
        dns::build_query(0x1234, qname, qtype)
    }

    /// Assert `resp` is a structurally-valid NXDOMAIN for `query`: QR=1, RCODE=3, ANCOUNT=0, and it
    /// `validate_response`s as a legitimate reply to the question (so a real client would accept it).
    fn assert_is_nxdomain(query: &[u8], resp: &[u8]) {
        // RCODE == 3 (NXDOMAIN)
        assert_eq!(resp[3] & 0x0F, 3, "RCODE must be NXDOMAIN(3)");
        // QR == 1 (response)
        assert_eq!(resp[2] & 0x80, 0x80, "QR must be 1 (response)");
        // ANCOUNT == 0 (no answer records — a pure denial, no egress-derived data)
        assert_eq!(
            u16::from_be_bytes([resp[6], resp[7]]),
            0,
            "ANCOUNT must be 0 (denial carries no answers)"
        );
        // It validates as a genuine reply to this exact question (anti-poisoning keystone).
        assert!(
            dns::validate_response(query, resp).is_ok(),
            "the synthesized NXDOMAIN must validate against its own query"
        );
    }

    // ---- Branch 1: PTR of a PRIVATE IP → NXDOMAIN (the LAN-sonar block) ----

    #[test]
    fn ptr_of_private_ipv4_is_never_forwarded() {
        // 192.168.0.1 (RFC1918) → reverse qname → must be answered LOCALLY (NXDOMAIN), zero egress.
        let qname = "1.0.168.192.in-addr.arpa";
        let query = query_for(qname, QTYPE_PTR);
        let resp = local_answer_if_never_forward(&query, qname, QTYPE_PTR)
            .expect("a private-IP PTR must be answered locally");
        assert_is_nxdomain(&query, &resp);
    }

    #[test]
    fn ptr_of_loopback_and_linklocal_ipv4_is_never_forwarded() {
        for qname in ["1.0.0.127.in-addr.arpa", "1.0.254.169.in-addr.arpa"] {
            // 127.0.0.1 (loopback) and 169.254.0.1 (link-local) → both private-class → NXDOMAIN.
            let query = query_for(qname, QTYPE_PTR);
            let resp = local_answer_if_never_forward(&query, qname, QTYPE_PTR)
                .unwrap_or_else(|| panic!("{qname} must be answered locally"));
            assert_is_nxdomain(&query, &resp);
        }
    }

    #[test]
    fn ptr_of_private_ipv6_is_never_forwarded() {
        // fd00::1 (ULA, fc00::/7) reverse — 32 nibble-reversed hex + .ip6.arpa.
        let qname = ptr_qname_v6(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let query = query_for(&qname, QTYPE_PTR);
        let resp = local_answer_if_never_forward(&query, &qname, QTYPE_PTR)
            .expect("a ULA-IPv6 PTR must be answered locally");
        assert_is_nxdomain(&query, &resp);
    }

    // ---- Branch 1: PTR of a PUBLIC IP → forwards (returns None) ----

    #[test]
    fn ptr_of_public_ipv4_still_forwards() {
        // 8.8.8.8 (public) reverse → NOT ours to deny → None → normal ladder.
        let qname = "8.8.8.8.in-addr.arpa";
        let query = query_for(qname, QTYPE_PTR);
        assert!(
            local_answer_if_never_forward(&query, qname, QTYPE_PTR).is_none(),
            "a public-IP PTR must fall through (forward), not be denied"
        );
    }

    #[test]
    fn ptr_of_public_ipv6_still_forwards() {
        // 2001:4860:4860::8888 (Google public DNS, a routable 2000::/3 address) → forwards.
        let qname = ptr_qname_v6(&Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
        let query = query_for(&qname, QTYPE_PTR);
        assert!(
            local_answer_if_never_forward(&query, &qname, QTYPE_PTR).is_none(),
            "a public-IPv6 PTR must fall through (forward), not be denied"
        );
    }

    // ---- Branch 1: a malformed reverse name → forwards (None), never panics ----

    #[test]
    fn malformed_reverse_name_falls_through_not_denied() {
        for qname in [
            "not-a-ptr.in-addr.arpa", // non-numeric octets
            "1.2.3.in-addr.arpa",     // too few octets
            "1.2.3.4.5.in-addr.arpa", // too many octets
            "256.0.0.1.in-addr.arpa", // octet out of range
            "zzzz.ip6.arpa",          // garbage v6
            "8.8.8.8.example.com",    // not a reverse zone at all
        ] {
            let query = query_for(qname, QTYPE_PTR);
            // None for the malformed-reverse cases that are not also a seeded suffix.
            assert!(
                local_answer_if_never_forward(&query, qname, QTYPE_PTR).is_none(),
                "{qname}: a malformed/garbage reverse name must fall through (forward), not deny"
            );
        }
    }

    #[test]
    fn private_reverse_name_with_non_ptr_qtype_is_not_blocked_by_branch1() {
        // The SAME reverse-name string but as an A query (qtype 1) is NOT a PTR — branch 1 is skipped.
        // `.in-addr.arpa` is NOT a seeded never-forward suffix either, so branch 2 also misses → None.
        let qname = "1.0.168.192.in-addr.arpa";
        let query = query_for(qname, 1 /* A */);
        assert!(
            local_answer_if_never_forward(&query, qname, 1).is_none(),
            "a non-PTR query of a reverse name is not a branch-1 hit and .in-addr.arpa is not seeded"
        );
    }

    // ---- Branch 2: seeded RFC6761/8375 special-use suffixes → NXDOMAIN ----

    #[test]
    fn seeded_special_use_suffixes_are_never_forwarded() {
        // Each seeded zone + a subdomain beneath it must be denied locally (any qtype).
        for qname in [
            "home.arpa",
            "printer.home.arpa",
            "myhost.local",
            "fileserver.lan",
            "wiki.internal",
            "a.b.c.home.arpa",
        ] {
            let query = query_for(qname, 1 /* A */);
            let resp = local_answer_if_never_forward(&query, qname, 1)
                .unwrap_or_else(|| panic!("{qname} (special-use) must be answered locally"));
            assert_is_nxdomain(&query, &resp);
        }
    }

    #[test]
    fn public_names_are_not_never_forwarded() {
        // Ordinary public names — and names that merely SHARE a tail with a seed but are not under it —
        // must fall through (forward).
        for qname in [
            "example.com",
            "www.google.com",
            "notlocal.com", // shares "local" only as a substring, not a label
            "internal.com", // "internal" as a 2LD label under .com, not the seeded suffix
        ] {
            let query = query_for(qname, 1);
            assert!(
                local_answer_if_never_forward(&query, qname, 1).is_none(),
                "{qname}: an ordinary public name must forward, not be denied"
            );
        }
    }

    #[test]
    fn bare_seed_label_is_matched() {
        // A bare "local"/"lan" etc. (the suffix itself, no subdomain) is a never-forward match.
        for qname in ["local", "lan", "internal"] {
            let query = query_for(qname, 1);
            assert!(
                local_answer_if_never_forward(&query, qname, 1).is_some(),
                "the bare seed label {qname} must itself be a never-forward match"
            );
        }
    }

    #[test]
    fn near_miss_labels_do_not_match() {
        // A name whose deepest label only RESEMBLES a seed (substring, not a whole label) must miss.
        for qname in ["mylocal", "locale", "wlan", "internals"] {
            let query = query_for(qname, 1);
            assert!(
                local_answer_if_never_forward(&query, qname, 1).is_none(),
                "{qname}: a substring-only resemblance to a seed must NOT match (label-exact trie)"
            );
        }
    }

    // ---- the suffix trie unit-level ----

    #[test]
    fn trie_matches_seeded_and_subdomains_only() {
        let trie = SuffixTrie::seeded();
        assert!(trie.matches("home.arpa"));
        assert!(trie.matches("x.home.arpa"));
        assert!(trie.matches("local"));
        assert!(trie.matches("host.local"));
        assert!(!trie.matches("home.example")); // shares "home" label but not the suffix
        assert!(!trie.matches("arpa")); // bare "arpa" is not seeded (only ".home.arpa")
        assert!(!trie.matches("example.com"));
        assert!(!trie.matches("")); // empty never matches
    }

    #[test]
    fn trie_is_robust_to_hostile_over_deep_query() {
        let trie = SuffixTrie::seeded();
        // An over-deep query must return false safely (no panic, no overflow), not match.
        let deep = vec!["x"; MAX_LABELS + 50].join(".");
        assert!(!trie.matches(&deep));
        // …and one that ends in a real seed but is over-deep still returns safely.
        let deep_seed = format!("{}.home.arpa", vec!["x"; MAX_LABELS + 50].join("."));
        // It must not panic; the result (match-or-not) is irrelevant to the safety claim.
        let _ = trie.matches(&deep_seed);
    }

    // ---- IPv6 reverse-name helper (RFC 3596) for the tests above ----

    /// Build the `.ip6.arpa` reverse qname for an IPv6 address: each of the 16 bytes → 2 nibbles, all
    /// 32 nibbles in REVERSE order (low nibble first), dot-separated, then `.ip6.arpa`. This is the
    /// inverse of `dns::decode_ptr_to_ip`'s v6 path — used only to FORGE test inputs.
    fn ptr_qname_v6(ip: &Ipv6Addr) -> String {
        let octets = ip.octets();
        let mut nibbles = Vec::with_capacity(32);
        for b in octets {
            nibbles.push(b >> 4); // high nibble
            nibbles.push(b & 0x0F); // low nibble
        }
        nibbles.reverse();
        let mut s = String::with_capacity(64 + 9);
        for (i, n) in nibbles.iter().enumerate() {
            if i > 0 {
                s.push('.');
            }
            s.push(std::char::from_digit(u32::from(*n), 16).unwrap());
        }
        s.push_str(".ip6.arpa");
        s
    }

    // ---- sanity: the reverse helpers round-trip through decode (guards the test vectors) ----

    #[test]
    fn test_vectors_round_trip_through_decode() {
        // Guard: our hand-written IPv4 reverse vectors decode to the IP we intend (so the privacy
        // assertions above are testing the right address class).
        assert_eq!(
            dns::decode_ptr_to_ip("1.0.168.192.in-addr.arpa"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))
        );
        assert_eq!(
            dns::decode_ptr_to_ip("8.8.8.8.in-addr.arpa"),
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        );
        // and the v6 forge helper inverts the decode
        let v6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        assert_eq!(
            dns::decode_ptr_to_ip(&ptr_qname_v6(&v6)),
            Some(IpAddr::V6(v6))
        );
    }
}
