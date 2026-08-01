/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

#![forbid(unsafe_code)]

//! Conditional / domain-specific upstream routing — the dnsmasq `server=/domain/<upstream>` evoke
//! (P12 MUST, `P12_DNSMASQ_EVOKE.md:49`).
//!
//! A per-domain → upstream-id map consulted in `resolve_inner()` **right after the block-check and
//! before the cache** (the qname is already parsed + lowercased there), so a name under a configured
//! suffix is steered to a NAMED transport in the pool; an unmatched name falls through to the default
//! exchange ladder. This is the split-horizon / conditional-forwarding seam too (P12 SHOULD,
//! `P12_DNSMASQ_EVOKE.md:62`) — `>1` terminal upstream is emergent from the same trie, no new code.
//!
//! ## Why a reversed-label trie (a structural clone of `blocklist.rs`, not a fork)
//!
//! The router is the EXACT structural shape of the blocklist matcher
//! (`blocklist.rs:68-72` `Node{children:HashMap<Box<str>,Node>, terminal}`,
//! `blocklist.rs:211-228` `is_blocked` longest-suffix-wins `rsplit('.')` walk) — but the terminal
//! carries a `RouteTarget` (an upstream id) instead of a bare `bool`. Inserting TLD-first
//! (`domain.rsplit('.')`, `blocklist.rs:151`) makes a parent zone a PREFIX of the path, so
//! **subdomain coverage falls out for free** (a route on `corp.example` also routes
//! `vpn.corp.example`) exactly as the blocklist's parent-zone coverage does
//! (`blocklist.rs:220-221`), and **longest-suffix-wins**: the DEEPEST terminal on the path is the
//! match, so a more-specific route overrides a broader one.
//!
//! We do NOT call into `blocklist.rs` (its `Node`/`Matcher` are private and carry a `terminal: bool`
//! plus provenance, not a route target); we clone the *shape*, the only honest reuse — the blocklist's
//! own `Node` is not generic. Canonicalization mirrors `blocklist::normalize` (`blocklist.rs:352-359`:
//! trim, strip trailing dot, lowercase, drop empty labels) so a route suffix keys identically to the
//! way the cache/blocklist see a name.
//!
//! ## Bounds (the same DNS limits the rest of the crate honors)
//!
//! Insert + lookup are bounded by [`MAX_LABELS`] (mirrors `blocklist.rs:37` `MAX_LABELS`) so the
//! recursive `Drop` of the trie and the walks cannot overflow the stack on a hostile suffix. The
//! lookup is a single `rsplit('.')` pass with early-exit — `O(labels)`, never a full-name rescan.
//!
//! ## Ties to the configured set (P10 rotation)
//!
//! The router is parsed inside `configure()` from a NEW top-level `"routes"` JSON key alongside
//! `"upstreams"` (the same serde-free `find_key`/`string_field` helpers, `mod.rs:513`/`mod.rs:520`),
//! and lives INSIDE `Inner` next to `pool` + `cache` (`mod.rs:107-113`). So a P10 `configure` re-call
//! atomically swaps the routing map TOGETHER with the pool (`mod.rs:218`) — no separate install path,
//! no torn state between a rotated pool and a stale map. A route whose `upstream` id is not among the
//! just-built transports is DROPPED at parse time (never fatal — the `Err(_) => continue` posture of
//! `mod.rs:169`), so the router can only ever name a transport the pool actually holds.

use std::collections::HashMap;
use std::net::IpAddr;

/// Trie-depth cap — mirrors `blocklist.rs:37` (`MAX_LABELS`). A suffix with more labels than this is
/// rejected at insert and never walked at lookup, so the recursive `Drop`/walks cannot overflow.
const MAX_LABELS: usize = 127;

/// What a matched suffix routes to. **Two terminal kinds, one struct (additive — the field set only
/// GREW, the `upstream` field every existing reader uses is untouched):**
///
/// 1. **Upstream terminal** (the dnsmasq `server=/domain/<upstream>` evoke) — `ip == None`, and
///    [`upstream`](Self::upstream) is the stable `id()` of a configured
///    [`super::transport::Transport`] (e.g. `"do53:proxy"`, `"doh:cf"`). The pool addresses its
///    transports by this id (`pool::Pool::exchange_via`), so the router only ever names a transport the
///    pool holds. This is the pre-R3 behavior, byte-for-byte.
/// 2. **Literal-IP terminal** (the dnsmasq `address=/domain/<ip>` evoke, R3 / `P12_DNSMASQ_EVOKE.md:63`)
///    — `ip == Some(addr)` carries a literal A/AAAA answer. The resolver synthesizes the positive
///    record at **step-1.5** via R1 `dns::build_address_response` and returns immediately, BEFORE the
///    cache read and WITHOUT any upstream — a literal answer needs no transport. For such a terminal
///    [`upstream`](Self::upstream) holds the synthetic sentinel [`LITERAL_UPSTREAM`] (never a real
///    transport id), so a reader that only inspects `.upstream` still sees a stable, harmless string and
///    NEVER mistakes a literal terminal for a pool route — the discriminator is `ip.is_some()`, checked
///    FIRST by the step-1.5 consumer (`mod.rs`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteTarget {
    /// The configured upstream id this suffix steers to — a real transport id for an upstream
    /// terminal, or the [`LITERAL_UPSTREAM`] sentinel when [`ip`](Self::ip) is `Some` (a literal-IP
    /// terminal carries no real upstream).
    pub upstream: Box<str>,
    /// `Some(addr)` ⇒ this is an `address=/domain/ip` literal terminal: the resolver answers the name
    /// LOCALLY with this A/AAAA at step-1.5 (R1 synthesis), no egress. `None` ⇒ an ordinary upstream
    /// route (the pre-R3 shape). Additive — every pre-R3 `RouteTarget` reads `ip == None`.
    pub ip: Option<IpAddr>,
}

/// The synthetic `upstream` id stamped on a literal-IP (`address=/domain/ip`) terminal. It is NOT a
/// transport id and will never match a configured upstream (so `parse_routes`'s `valid_ids` gate, which
/// only runs for upstream terminals, can never confuse the two). The step-1.5 consumer branches on
/// [`RouteTarget::ip`]`.is_some()`, never on this string — it exists only so `.upstream` stays a stable,
/// non-empty value for any reader that inspects it.
pub const LITERAL_UPSTREAM: &str = "\u{0}literal";

/// One trie node, keyed by DNS label (TLD-first), the structural clone of `blocklist.rs:68-72`.
#[derive(Default)]
struct Node {
    children: HashMap<Box<str>, Node>,
    /// A route terminates here — this suffix AND everything beneath it routes to `target`, unless a
    /// DEEPER terminal on the path overrides it (longest-suffix-wins).
    target: Option<RouteTarget>,
}

/// A compiled conditional-routing map: `suffix → upstream id`, longest-suffix-wins with free
/// subdomain coverage. Empty by default (no `"routes"` key ⇒ every name takes the default pool path,
/// behavior identical to pre-P12).
#[derive(Default)]
pub struct Router {
    root: Node,
    /// Number of distinct routed suffixes installed (for stats / the empty fast-path).
    count: usize,
}

impl Router {
    /// An empty router — every lookup misses, every name takes the default pool ladder.
    pub fn new() -> Self {
        Self::default()
    }

    /// True when no routes are installed — the resolver short-circuits the consult entirely.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Number of distinct routed suffixes.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Insert a `suffix → upstream` route. Canonicalizes the suffix exactly like
    /// `blocklist::normalize` (trim, strip trailing dot, lowercase, drop empty labels) so it keys
    /// identically to how the cache/blocklist see a name. Idempotent on the SAME (suffix, upstream);
    /// a re-insert on the same suffix with a DIFFERENT upstream overwrites (last write wins — a
    /// configure rebuild is the only writer, so order is deterministic per-config). An empty or
    /// over-deep suffix is dropped (never panics).
    pub fn insert(&mut self, suffix: &str, upstream: &str) {
        let suffix = normalize_suffix(suffix);
        if suffix.is_empty() || upstream.is_empty() {
            return;
        }
        // Reject a pathologically deep suffix up front so the trie depth (and its recursive Drop)
        // stays bounded — mirrors the blocklist's MAX_LABELS guard intent.
        if suffix.split('.').count() > MAX_LABELS {
            return;
        }
        let mut node = &mut self.root;
        // Walk labels TLD-first (rsplit) so a parent suffix is a PREFIX of the path — the blocklist
        // shape (`blocklist.rs:151`). Subdomain coverage + longest-suffix-wins fall out of this.
        for label in suffix.rsplit('.') {
            node = node.children.entry(label.into()).or_default();
        }
        if node.target.is_none() {
            self.count += 1;
        }
        node.target = Some(RouteTarget {
            upstream: upstream.into(),
            ip: None,
        });
    }

    /// Insert a `suffix → literal IP` route — the dnsmasq `address=/domain/<ip>` evoke (R3,
    /// `P12_DNSMASQ_EVOKE.md:63`). The terminal carries a literal A/AAAA the resolver answers LOCALLY at
    /// step-1.5 (R1 `dns::build_address_response`), no upstream, no egress. Same trie shape, same
    /// canonicalization, same bounds, same longest-suffix-wins, same idempotency/last-write-wins as
    /// [`insert`](Self::insert) — only the terminal payload differs (`ip: Some(addr)` +
    /// the [`LITERAL_UPSTREAM`] sentinel instead of a transport id). An empty or over-deep suffix is
    /// dropped (never panics). A re-insert on a suffix that already holds a route overwrites it (last
    /// write wins) — so `address=` and `server=` on the SAME suffix resolve deterministically to
    /// whichever the configure pass installs last, exactly as two `server=` on one suffix would.
    pub fn insert_address(&mut self, suffix: &str, ip: IpAddr) {
        let suffix = normalize_suffix(suffix);
        if suffix.is_empty() {
            return;
        }
        if suffix.split('.').count() > MAX_LABELS {
            return;
        }
        let mut node = &mut self.root;
        for label in suffix.rsplit('.') {
            node = node.children.entry(label.into()).or_default();
        }
        if node.target.is_none() {
            self.count += 1;
        }
        node.target = Some(RouteTarget {
            upstream: LITERAL_UPSTREAM.into(),
            ip: Some(ip),
        });
    }

    /// Longest-suffix-wins lookup: walk `qname` TLD-first and return the DEEPEST terminal's
    /// [`RouteTarget`] on the path (so a more-specific route overrides a broader one), or `None` if no
    /// configured suffix covers the name. The qname is expected already lowercased (it comes from
    /// `dns::parse_question`, `dns.rs`/`cache.rs:33`); we still normalize for safety. `O(labels)`,
    /// bounded by [`MAX_LABELS`], never a full rescan, never panics.
    ///
    /// NOTE: unlike `blocklist::is_blocked` (which early-returns at the FIRST terminal because a
    /// blocked parent zone subsumes everything beneath), routing keeps walking to honor
    /// longest-suffix-wins — a deeper, more-specific route must override a shallower one. The walk is
    /// still a single `rsplit('.')` pass; it just remembers the last terminal seen.
    pub fn lookup(&self, qname: &str) -> Option<RouteTarget> {
        if self.count == 0 {
            return None; // empty router — every name is default-routed
        }
        let qname = normalize_suffix(qname);
        if qname.is_empty() {
            return None;
        }
        let mut node = &self.root;
        let mut best: Option<&RouteTarget> = None;
        let mut depth = 0usize;
        for label in qname.rsplit('.') {
            depth += 1;
            if depth > MAX_LABELS {
                break; // hostile over-deep name — stop walking, return the best so far
            }
            match node.children.get(label) {
                Some(child) => {
                    if let Some(t) = child.target.as_ref() {
                        best = Some(t); // a terminal here — remember it, keep going for a deeper one
                    }
                    node = child;
                }
                None => break, // the path diverges from every configured suffix — done
            }
        }
        best.cloned()
    }
}

/// Canonicalize a domain/suffix the way the rest of the crate does — a structural mirror of
/// `blocklist::normalize` (`blocklist.rs:352-359`): trim, strip a trailing root dot, lowercase, drop
/// empty labels, rejoin. We re-implement it here (it is a private `fn` in `blocklist.rs`, not `pub`),
/// keeping the router self-contained and `#![forbid(unsafe_code)]`. Pure, allocation-bounded by the
/// input, never panics.
fn normalize_suffix(domain: &str) -> String {
    let lowered = domain.trim().trim_end_matches('.').to_lowercase();
    lowered
        .split('.')
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

/// Parse the OPTIONAL top-level `"routes"` array of a configure JSON into a [`Router`], keeping only
/// routes whose `upstream` id is present in `valid_ids` (the ids of the just-built transports). A
/// route naming an absent/dropped upstream is SKIPPED (never fatal — the `mod.rs:169` posture), so
/// the router can only ever steer to a transport the pool actually holds.
///
/// Shape: `{"upstreams":[...], "routes":[`
/// `{"suffix":"corp.example","upstream":"vpn-doh"},`            ← `server=` upstream terminal
/// `{"suffix":"router.box","address":"192.168.1.1"}`           ← `address=` literal-IP terminal (R3)
/// `]}`.
/// Absent `"routes"` key ⇒ an empty [`Router`] (every name default-routed; pre-P12 behavior). Uses
/// the SAME serde-free object scanner + `find_key`/`string_field` helpers the upstream parser uses
/// (passed in as `obj_field`), so there is one JSON dialect, not two.
///
/// **R3 — the `address=/domain/ip` terminal (`P12_DNSMASQ_EVOKE.md:63`):** a route is read as a
/// LITERAL terminal when it carries an `"address"` (alias `"ip"`) field parseable as an [`IpAddr`].
/// It needs NO upstream, so it is installed via [`Router::insert_address`] WITHOUT the `valid_ids`
/// gate (that gate exists only to ensure an upstream id names a real transport — a literal answer has
/// no transport). The literal field is checked FIRST; only if it is absent/unparseable does the route
/// fall back to the ordinary `"upstream"` terminal path (so a malformed `address` never silently
/// becomes a bogus upstream — it is skipped, the `mod.rs:169` never-fatal posture). IP parse reuses
/// the crate idiom (`str::parse::<IpAddr>()`, e.g. `lib.rs:1230`) — no second address parser.
///
/// `obj_field` is the resolver's existing `string_field` (`mod.rs:520`), threaded in so this module
/// never duplicates the escape-handling string reader. `find_routes_array` does the same brace-scan
/// as `parse_upstreams` (`mod.rs:449-492`); it is kept here, generic over the array key, so the
/// shared `mod.rs` parse region stays small.
pub fn parse_routes<F>(json: &str, valid_ids: &[String], string_field: F) -> Router
where
    F: Fn(&str, &str) -> Option<String>,
{
    let mut router = Router::new();
    for obj in object_slices(json, "routes") {
        let suffix = match string_field(obj, "suffix") {
            Some(s) => s,
            None => continue, // a route with no suffix is unusable — skip it
        };
        // R3: an `address=`/`ip=` literal terminal — checked FIRST. A literal answer carries its own
        // IP and is answered locally at step-1.5; it has no upstream, so it skips the `valid_ids` gate.
        // A present-but-unparseable address is NOT promoted to an upstream — it falls through (and, if
        // there is no valid `upstream` either, the route is skipped). `address` then `ip` as an alias.
        if let Some(addr_str) = string_field(obj, "address").or_else(|| string_field(obj, "ip")) {
            if let Ok(ip) = addr_str.trim().parse::<IpAddr>() {
                router.insert_address(&suffix, ip);
                continue;
            }
            // else: malformed literal IP — do not fabricate an upstream; fall through to the upstream
            // path below (which will skip the route if no valid `upstream` is present).
        }
        let upstream = match string_field(obj, "upstream") {
            Some(u) => u,
            None => continue, // a route with no upstream target — skip it
        };
        // Only keep a route whose target is a configured transport id (validated against the pool).
        if valid_ids.iter().any(|id| id == &upstream) {
            router.insert(&suffix, &upstream);
        }
        // else: a route to a dropped/unknown upstream is silently skipped (never fatal).
    }
    router
}

/// Yield each `{...}` object slice inside the array named `key` — the SAME brace-balanced,
/// string-aware scan as `parse_upstreams` (`mod.rs:449-492`), factored to a free fn so the router
/// reuses it instead of copying the loop into `mod.rs`. Returns an empty iter when `key` is absent.
/// Never panics (all indexing is `min`-clamped / bounds-checked).
fn object_slices<'a>(json: &'a str, key: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let bytes = json.as_bytes();
    let needle = format!("\"{key}\"");
    let start_at = match json.find(&needle) {
        Some(i) => i + needle.len(),
        None => return out, // no such array — empty
    };
    let len = bytes.len();
    let mut i = start_at;
    while i < len {
        match bytes[i] {
            b']' => break, // end of the named array
            b'{' => {
                let start = i;
                let mut depth = 0usize;
                let mut end = i;
                let mut in_str = false;
                let mut esc = false;
                while end < len {
                    let c = bytes[end];
                    if in_str {
                        if esc {
                            esc = false;
                        } else if c == b'\\' {
                            esc = true;
                        } else if c == b'"' {
                            in_str = false;
                        }
                    } else {
                        match c {
                            b'"' => in_str = true,
                            b'{' => depth += 1,
                            b'}' => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    end += 1;
                }
                out.push(&json[start..=end.min(len - 1)]);
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror of `mod.rs`'s `string_field` (`mod.rs:520`) for self-contained tests of `parse_routes`.
    /// (The real wiring threads the resolver's own `string_field` in — this is the same contract.)
    fn string_field(obj: &str, key: &str) -> Option<String> {
        let needle = format!("\"{key}\"");
        let after_key = obj.find(&needle)? + needle.len();
        let rest = &obj[after_key..];
        let bytes = rest.as_bytes();
        let mut i = 0;
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b':' {
            return None;
        }
        i += 1;
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'"' {
            return None;
        }
        i += 1;
        let mut value = String::new();
        let mut esc = false;
        while i < bytes.len() {
            let c = bytes[i];
            if esc {
                value.push(c as char);
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                return Some(value);
            } else {
                value.push(c as char);
            }
            i += 1;
        }
        None
    }

    // ---- the load-bearing disjoint claim: matched domain → mapped upstream; unmatched → default ----

    #[test]
    fn matched_domain_routes_to_its_upstream() {
        let mut r = Router::new();
        r.insert("corp.example", "vpn-doh");
        // exact suffix hit
        assert_eq!(
            r.lookup("corp.example").map(|t| t.upstream),
            Some("vpn-doh".into()),
            "the configured suffix must route to its mapped upstream id",
        );
    }

    #[test]
    fn unmatched_domain_routes_to_default_none() {
        let mut r = Router::new();
        r.insert("corp.example", "vpn-doh");
        // a name NOT under any configured suffix → None → the resolver takes the default pool ladder
        assert_eq!(
            r.lookup("example.com"),
            None,
            "an unmatched name must miss (None) so the default pool path is taken",
        );
        // a sibling that merely SHARES a tail but is not under the suffix must also miss
        assert_eq!(r.lookup("notcorp.example"), None);
        // the bare parent label of a deeper suffix is NOT itself routed
        assert_eq!(r.lookup("example"), None);
    }

    #[test]
    fn subdomain_coverage_is_free() {
        let mut r = Router::new();
        r.insert("corp.example", "vpn-doh");
        // every subdomain beneath the routed suffix inherits the route (the blocklist parent-coverage
        // property, `blocklist.rs:220-221`)
        assert_eq!(
            r.lookup("vpn.corp.example").map(|t| t.upstream),
            Some("vpn-doh".into())
        );
        assert_eq!(
            r.lookup("a.b.c.corp.example").map(|t| t.upstream),
            Some("vpn-doh".into()),
        );
    }

    #[test]
    fn longest_suffix_wins() {
        let mut r = Router::new();
        r.insert("example", "broad");
        r.insert("corp.example", "specific");
        // the DEEPER terminal overrides the broader one (split-horizon: `.corp.example`→specific,
        // everything else under `.example`→broad)
        assert_eq!(
            r.lookup("corp.example").map(|t| t.upstream),
            Some("specific".into())
        );
        assert_eq!(
            r.lookup("vpn.corp.example").map(|t| t.upstream),
            Some("specific".into())
        );
        assert_eq!(
            r.lookup("other.example").map(|t| t.upstream),
            Some("broad".into())
        );
        assert_eq!(
            r.lookup("example").map(|t| t.upstream),
            Some("broad".into())
        );
    }

    #[test]
    fn lookup_is_case_and_dot_insensitive() {
        let mut r = Router::new();
        r.insert("Corp.Example.", "vpn"); // mixed case + trailing root dot at INSERT
                                          // a query in any case / with a trailing dot still hits (normalize mirrors blocklist::normalize)
        assert_eq!(
            r.lookup("VPN.CORP.example").map(|t| t.upstream),
            Some("vpn".into())
        );
        assert_eq!(
            r.lookup("corp.example.").map(|t| t.upstream),
            Some("vpn".into())
        );
    }

    #[test]
    fn empty_router_always_misses() {
        let r = Router::new();
        assert!(r.is_empty());
        assert_eq!(r.lookup("anything.example"), None);
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn insert_is_robust_to_hostile_and_empty_input() {
        let mut r = Router::new();
        r.insert("", "u"); // empty suffix dropped
        r.insert("a.b.c", ""); // empty upstream dropped
        assert!(
            r.is_empty(),
            "empty suffix or upstream must not install a route"
        );
        // an over-deep suffix is dropped, never a stack-overflow on Drop
        let deep = vec!["x"; MAX_LABELS + 5].join(".");
        r.insert(&deep, "u");
        assert!(
            r.is_empty(),
            "an over-deep suffix must be rejected (bounded like the blocklist)"
        );
        // a hostile over-deep QUERY never panics either — it returns None safely
        r.insert("ok.example", "u");
        let deep_q = vec!["x"; MAX_LABELS + 50].join(".");
        assert_eq!(r.lookup(&deep_q), None);
    }

    #[test]
    fn reinsert_same_suffix_overwrites_upstream_no_double_count() {
        let mut r = Router::new();
        r.insert("corp.example", "old");
        r.insert("corp.example", "new"); // last write wins
        assert_eq!(
            r.lookup("corp.example").map(|t| t.upstream),
            Some("new".into())
        );
        assert_eq!(
            r.len(),
            1,
            "re-inserting the same suffix must not double-count"
        );
    }

    // ---- parse_routes: ties the trie to the configured set (validated against transport ids) ----

    #[test]
    fn parse_routes_keeps_only_routes_to_known_upstreams() {
        let json = r#"{
            "upstreams":[{"id":"vpn-doh","transport":"doh","url":"https://v/dns-query"}],
            "routes":[
                {"suffix":"corp.example","upstream":"vpn-doh"},
                {"suffix":"orphan.example","upstream":"does-not-exist"}
            ]
        }"#;
        let valid = vec!["vpn-doh".to_string()];
        let router = parse_routes(json, &valid, string_field);
        // the corp route survives (its upstream is configured)
        assert_eq!(
            router.lookup("corp.example").map(|t| t.upstream),
            Some("vpn-doh".into()),
        );
        // the orphan route to an unknown upstream is dropped — never fatal, never installed
        assert_eq!(router.lookup("orphan.example"), None);
        assert_eq!(
            router.len(),
            1,
            "only the route to a known upstream is kept"
        );
    }

    #[test]
    fn parse_routes_absent_key_is_empty_router() {
        // No "routes" key at all → an empty router (pre-P12 behavior: every name default-routed).
        let json = r#"{"upstreams":[{"id":"cf","transport":"doh","url":"https://c/dns-query"}]}"#;
        let router = parse_routes(json, &["cf".to_string()], string_field);
        assert!(router.is_empty());
        assert_eq!(router.lookup("anything.example"), None);
    }

    #[test]
    fn parse_routes_skips_malformed_entries() {
        // a route missing suffix or upstream is skipped; well-formed siblings survive.
        let json = r#"{
            "routes":[
                {"upstream":"cf"},
                {"suffix":"x.example"},
                {"suffix":"corp.example","upstream":"cf"}
            ]
        }"#;
        let router = parse_routes(json, &["cf".to_string()], string_field);
        assert_eq!(router.len(), 1);
        assert_eq!(
            router.lookup("corp.example").map(|t| t.upstream),
            Some("cf".into())
        );
    }

    #[test]
    fn parse_routes_multiple_upstreams_split_horizon() {
        // The emergent split-horizon shape (P12 SHOULD): >1 terminal upstream from one trie.
        let json = r#"{
            "routes":[
                {"suffix":"corp.example","upstream":"vpn"},
                {"suffix":"internal.test","upstream":"lan"}
            ]
        }"#;
        let valid = vec!["vpn".to_string(), "lan".to_string()];
        let router = parse_routes(json, &valid, string_field);
        assert_eq!(
            router.lookup("host.corp.example").map(|t| t.upstream),
            Some("vpn".into())
        );
        assert_eq!(
            router.lookup("svc.internal.test").map(|t| t.upstream),
            Some("lan".into())
        );
        assert_eq!(router.lookup("public.com"), None);
    }

    // ---- R3 · the `address=/domain/ip` literal-IP terminal (P12_DNSMASQ_EVOKE.md:63) ----

    #[test]
    fn route_target_with_literal_ip_synthesizes_at_step_1_5_via_r1() {
        // A route `{"suffix":"router.box","address":"192.168.1.1"}` parses to a LITERAL-IP terminal:
        // `ip == Some(...)` (the discriminator the step-1.5 consumer branches on FIRST), and `.upstream`
        // is the synthetic sentinel — never a real transport id. This is the routing.rs half of the
        // step-1.5 R1 synthesis (the synth itself lives in mod.rs/dns.rs, the other owners' files).
        let json = r#"{
            "routes":[
                {"suffix":"router.box","address":"192.168.1.1"}
            ]
        }"#;
        // valid_ids is irrelevant for a literal terminal — it skips the upstream gate entirely.
        let router = parse_routes(json, &[], string_field);
        let target = router
            .lookup("router.box")
            .expect("the literal route must be installed");
        assert_eq!(
            target.ip,
            Some("192.168.1.1".parse().unwrap()),
            "an address= route must carry the literal A the resolver will synthesize at step-1.5",
        );
        assert_eq!(
            &*target.upstream, LITERAL_UPSTREAM,
            "a literal terminal carries the sentinel upstream, never a real transport id",
        );
        // upstream-routing path is UNAFFECTED: a name with no configured suffix still misses.
        assert_eq!(router.lookup("example.com"), None);
    }

    #[test]
    fn literal_ip_terminal_inherits_the_trie_shape() {
        // The literal terminal rides the EXACT same trie: subdomain coverage is free, longest-suffix
        // -wins holds, and an IPv6 literal parses just like an IPv4 one.
        let mut r = Router::new();
        r.insert_address("home.arpa", "10.0.0.1".parse().unwrap());
        r.insert_address("printer.home.arpa", "fd00::5".parse().unwrap()); // deeper + v6
                                                                           // subdomain coverage (free, the blocklist parent-coverage property)
        assert_eq!(
            r.lookup("nas.home.arpa").map(|t| t.ip),
            Some(Some("10.0.0.1".parse().unwrap()))
        );
        // longest-suffix-wins: the deeper printer suffix overrides the broader home.arpa one
        assert_eq!(
            r.lookup("printer.home.arpa").map(|t| t.ip),
            Some(Some("fd00::5".parse().unwrap())),
        );
        assert_eq!(
            r.lookup("x.printer.home.arpa").map(|t| t.ip),
            Some(Some("fd00::5".parse().unwrap()))
        );
        // an unrelated name still misses
        assert_eq!(r.lookup("example.com"), None);
    }

    #[test]
    fn literal_and_upstream_terminals_coexist_in_one_trie() {
        // `address=` and `server=` routes live in the SAME router; each terminal keeps its own kind.
        let json = r#"{
            "routes":[
                {"suffix":"corp.example","upstream":"vpn"},
                {"suffix":"router.box","address":"192.168.1.1"},
                {"suffix":"ns.lan","ip":"10.1.2.3"}
            ]
        }"#;
        let valid = vec!["vpn".to_string()];
        let router = parse_routes(json, &valid, string_field);
        // upstream terminal: ip is None, upstream is the real id
        let up = router
            .lookup("host.corp.example")
            .expect("upstream route present");
        assert_eq!(up.ip, None);
        assert_eq!(&*up.upstream, "vpn");
        // literal terminal via "address"
        assert_eq!(
            router.lookup("router.box").and_then(|t| t.ip),
            Some("192.168.1.1".parse().unwrap()),
        );
        // literal terminal via the "ip" alias
        assert_eq!(
            router.lookup("ns.lan").and_then(|t| t.ip),
            Some("10.1.2.3".parse().unwrap()),
        );
        assert_eq!(router.len(), 3);
    }

    #[test]
    fn malformed_literal_address_is_skipped_never_a_bogus_upstream() {
        // A present-but-unparseable `address` must NOT be promoted to an upstream id. With no valid
        // `upstream` fallback, the route is skipped entirely (the never-fatal mod.rs:169 posture).
        let json = r#"{
            "routes":[
                {"suffix":"bad.example","address":"not-an-ip"},
                {"suffix":"good.example","address":"203.0.113.7"}
            ]
        }"#;
        let router = parse_routes(json, &[], string_field);
        assert_eq!(
            router.lookup("bad.example"),
            None,
            "a malformed address must not install a route"
        );
        assert_eq!(
            router.lookup("good.example").and_then(|t| t.ip),
            Some("203.0.113.7".parse().unwrap()),
            "a well-formed sibling literal still installs",
        );
        assert_eq!(router.len(), 1);
    }

    #[test]
    fn malformed_address_falls_back_to_a_valid_upstream_on_the_same_route() {
        // If a route carries BOTH a bad `address` and a good `upstream`, the bad literal is ignored and
        // the route falls back to the upstream terminal (graceful degrade, never a silent drop of a
        // usable route).
        let json = r#"{
            "routes":[
                {"suffix":"corp.example","address":"999.999.999.999","upstream":"vpn"}
            ]
        }"#;
        let valid = vec!["vpn".to_string()];
        let router = parse_routes(json, &valid, string_field);
        let t = router
            .lookup("corp.example")
            .expect("falls back to the valid upstream");
        assert_eq!(t.ip, None, "the bad literal must not survive");
        assert_eq!(&*t.upstream, "vpn");
    }

    #[test]
    fn insert_address_is_robust_to_empty_and_hostile_suffix() {
        let mut r = Router::new();
        r.insert_address("", "1.2.3.4".parse().unwrap()); // empty suffix dropped
        assert!(
            r.is_empty(),
            "an empty suffix must not install a literal route"
        );
        let deep = vec!["x"; MAX_LABELS + 5].join(".");
        r.insert_address(&deep, "1.2.3.4".parse().unwrap()); // over-deep dropped, no Drop overflow
        assert!(
            r.is_empty(),
            "an over-deep suffix must be rejected for literals too"
        );
    }
}
