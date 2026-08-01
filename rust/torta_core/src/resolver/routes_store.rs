/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

#![forbid(unsafe_code)]

//! D33b (P12) — the **conditional-routing store**: the user's dnsmasq-style routing rules, persisted
//! durably and emitted as the `"routes"` specs key so [`super::routing::parse_routes`] — wired into
//! [`super::configure`] since R3 but fed by NOBODY in production — finally receives real rules.
//!
//! ## The line dialect (dnsmasq-true, documented in the editor)
//!
//! - `server=/suffix[/suffix…]/upstream-id` — route every name under `suffix` to the configured
//!   upstream whose pool id is `upstream-id` (our engine's analogue of dnsmasq's
//!   `server=/domain/server`: the pool speaks transport ids, not raw server IPs). An id that is not
//!   in the configured pool is skipped by `parse_routes`'s `valid_ids` gate at configure time —
//!   silently, never fatally (fail-open, the name takes the default pool path).
//! - `address=/suffix[/suffix…]/ip` — answer every A/AAAA under `suffix` LOCALLY with the literal
//!   `ip` (zero egress — the R3 literal terminal, `mod.rs` step 1.6b). dnsmasq's multi-domain form
//!   (`server=/a/b/target`) is honored: every middle segment is a suffix, the LAST segment is the
//!   target.
//! - `#`/`!` comments and blank lines are skipped silently; any other non-blank line (or a malformed
//!   target) is counted `skipped` — the editor's honest feedback, never a guess.
//!
//! ## Where it flows
//!
//! `resolver_routes_set` (lib.rs) parses + persists the raw text into the integrity-framed
//! `resolver-routes` [`crate::runtime_tier::DurableTier`] record (RAM⊗NAND: one control-plane
//! write-through per editor save, no hot-path write). At every configure edge the Kotlin side embeds
//! [`to_json_fragment`]'s output as the `"routes"` key of the specs JSON — the SAME JSON
//! `resolver::configure` already parses (`routing::parse_routes`, validated against the live pool
//! ids) — so the Router is built by the ONE proven path, never a second installer. No boot rehydrate
//! is needed: the store is READ at configure time, and the Router lives inside the configured
//! resolver.
//!
//! Pure `std` + `crate::runtime_tier` — no new crate dep, control-plane only, never panics.

use std::net::IpAddr;

/// The durable-record name under the shared runtime-tier root — the `resolver-cache` /
/// `resolver-local-records` naming family.
const DURABLE_NAME: &str = "resolver-routes";

/// Per-suffix label cap — mirrors `routing.rs:56` (`MAX_LABELS`) so a hostile suffix can never bloat
/// the store or a later trie walk (the Router re-bounds at insert; this is the editor-side gate).
const MAX_LABELS: usize = 127;

/// DNS name length cap (RFC 1035 §3.1) — mirrors `blocklist.rs` `MAX_NAME_LEN`.
const MAX_NAME_LEN: usize = 255;

/// One parsed routing rule target: a configured-upstream id, or a literal answer IP.
#[derive(Debug, Clone, PartialEq)]
pub enum RouteTarget {
    /// `server=/suffix/id` — route to the pool transport with this id (validated at configure).
    Upstream(String),
    /// `address=/suffix/ip` — answer locally with this literal (the R3 step-1.6b terminal).
    Literal(IpAddr),
}

/// One parsed routing rule: `suffix` → [`RouteTarget`].
#[derive(Debug, Clone, PartialEq)]
pub struct StoredRoute {
    pub suffix: String,
    pub target: RouteTarget,
}

/// Parse the editor's rule text into routes. Returns `(routes, skipped_lines)` — comments/blanks are
/// skipped silently, any other unusable line counts `skipped` (honest editor feedback). A multi-suffix
/// line yields one route per suffix. Never panics.
pub fn parse_lines(text: &str) -> (Vec<StoredRoute>, usize) {
    let mut routes = Vec::new();
    let mut skipped = 0usize;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with('!') {
            continue; // comment/blank — never counted
        }
        match parse_rule_line(t) {
            Some(mut parsed) if !parsed.is_empty() => routes.append(&mut parsed),
            _ => skipped += 1,
        }
    }
    (routes, skipped)
}

/// Parse ONE trimmed non-comment line into its routes (`None`/empty = unusable). The dnsmasq shape:
/// `server=/s1[/s2…]/target` or `address=/s1[/s2…]/ip` — middle segments are suffixes, the last is
/// the target. A suffix that canonicalizes to nothing (empty / over-bound) is dropped; a line whose
/// target is malformed (or with zero usable suffixes) is unusable.
fn parse_rule_line(line: &str) -> Option<Vec<StoredRoute>> {
    let (is_address, value) = if let Some(v) = line.strip_prefix("server=") {
        (false, v)
    } else if let Some(v) = line.strip_prefix("address=") {
        (true, v)
    } else {
        return None; // not a rule form we speak
    };
    let value = value.trim();
    if !value.starts_with('/') {
        return None; // dnsmasq rule values are /-framed
    }
    // Split "/a/b/target" → ["", "a", "b", "target"]; need ≥1 suffix + 1 target.
    let parts: Vec<&str> = value.split('/').collect();
    if parts.len() < 3 {
        return None;
    }
    let target_raw = parts[parts.len() - 1].trim();
    if target_raw.is_empty() {
        return None;
    }
    let target = if is_address {
        RouteTarget::Literal(target_raw.parse::<IpAddr>().ok()?)
    } else {
        RouteTarget::Upstream(target_raw.to_string())
    };
    let mut out = Vec::new();
    for suffix_raw in &parts[1..parts.len() - 1] {
        if let Some(suffix) = canonicalize_suffix(suffix_raw) {
            out.push(StoredRoute {
                suffix,
                target: target.clone(),
            });
        }
    }
    Some(out)
}

/// Canonicalize a rule suffix: trim, strip a trailing dot, lowercase, drop empty labels, bound-check —
/// the SAME shape `local.rs::canonicalize_name` / the blocklist normalize twins key by, so the stored
/// suffix matches the Router's canonical insert. `None` for an empty / over-bound suffix.
fn canonicalize_suffix(suffix: &str) -> Option<String> {
    let lowered = suffix.trim().trim_end_matches('.').to_lowercase();
    let canon: String = lowered
        .split('.')
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    if canon.is_empty() || canon.len() > MAX_NAME_LEN || canon.split('.').count() > MAX_LABELS {
        return None;
    }
    Some(canon)
}

/// Render the routes as the `"routes"` specs-JSON ARRAY (`[{"suffix":…,"upstream":…},…]`) —
/// byte-compatible with what [`super::routing::parse_routes`] reads (`suffix` + `upstream` /
/// `address` keys). Every value is JSON-string-escaped via the ONE crate escaper
/// ([`crate::json_escape_into`]) so a quote/backslash in a rule can never corrupt the specs object.
/// Empty input → `"[]"`.
pub fn to_json_fragment(routes: &[StoredRoute]) -> String {
    let mut out = String::from("[");
    for (i, r) in routes.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"suffix\":\"");
        crate::json_escape_into(&mut out, &r.suffix);
        out.push_str("\",");
        match &r.target {
            RouteTarget::Upstream(id) => {
                out.push_str("\"upstream\":\"");
                crate::json_escape_into(&mut out, id);
                out.push('"');
            }
            RouteTarget::Literal(ip) => {
                out.push_str("\"address\":\"");
                // An IpAddr Display can never contain a quote/backslash, but the one-escaper law is
                // cheaper to keep than to argue per-site.
                crate::json_escape_into(&mut out, &ip.to_string());
                out.push('"');
            }
        }
        out.push('}');
    }
    out.push(']');
    out
}

/// Persist the editor's rule text into the integrity-framed `resolver-routes` durable record
/// (RAM⊗NAND write-through — control-plane, off the resolve path). Empty/blank text CLEARS the record.
/// `false` = the write was refused.
pub fn persist_text(dir: &str, text: &str) -> bool {
    let tier =
        crate::runtime_tier::DurableTier::with_dir(std::path::PathBuf::from(dir), DURABLE_NAME);
    if text.trim().is_empty() {
        tier.clear();
        return true;
    }
    tier.write_through(text.as_bytes()).is_ok()
}

/// Load the persisted rule text (`None` = cold / cleared / corrupt — the integrity frame rejects a
/// torn record; non-UTF-8 degrades to `None`, never a panic).
pub fn load_text(dir: &str) -> Option<String> {
    let tier =
        crate::runtime_tier::DurableTier::with_dir(std::path::PathBuf::from(dir), DURABLE_NAME);
    let bytes = tier.rehydrate()?;
    String::from_utf8(bytes).ok()
}

/// Load + parse the persisted rules in one move (the configure-edge read): `(routes, skipped)`.
/// Cold store ⇒ `([], 0)` — the empty Router fast-path, behavior identical to pre-P12.
pub fn load_parsed(dir: &str) -> (Vec<StoredRoute>, usize) {
    match load_text(dir) {
        Some(text) => parse_lines(&text),
        None => (Vec::new(), 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_server_and_address_forms_with_multi_suffix_and_comments() {
        let text = "\
# route the corp zone to the quad9 pool arm
server=/corp.example/dc-quad9
server=/a.lan/b.lan/dc-fr
address=/ads.example/0.0.0.0
address=/v6.sink/::1
! adblock-style comment

server=missing-slash-form
address=/bad.ip/not-an-ip
server=//dc-quad9
";
        let (routes, skipped) = parse_lines(text);
        // 2 (multi-suffix) + 1 + 1 + 1 = 5 routes; 3 unusable lines skipped.
        assert_eq!(routes.len(), 5, "every usable rule parsed");
        assert_eq!(skipped, 3, "malformed lines counted, comments not");
        assert_eq!(
            routes[0],
            StoredRoute {
                suffix: "corp.example".into(),
                target: RouteTarget::Upstream("dc-quad9".into()),
            }
        );
        assert_eq!(routes[1].suffix, "a.lan");
        assert_eq!(routes[2].suffix, "b.lan");
        assert_eq!(
            routes[2].target,
            RouteTarget::Upstream("dc-fr".into()),
            "a multi-suffix line routes EVERY suffix to the one target"
        );
        assert_eq!(
            routes[3].target,
            RouteTarget::Literal(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
        );
        assert_eq!(
            routes[4].target,
            RouteTarget::Literal(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    #[test]
    fn suffixes_canonicalize_like_the_router_keys() {
        let (routes, skipped) = parse_lines("server=/Corp.Example./dc-quad9\n");
        assert_eq!(skipped, 0);
        assert_eq!(
            routes[0].suffix, "corp.example",
            "lowercased + trailing-dot-stripped, the Router's canonical key shape"
        );
    }

    #[test]
    fn json_fragment_matches_the_parse_routes_contract_and_escapes() {
        let routes = vec![
            StoredRoute {
                suffix: "corp.example".into(),
                target: RouteTarget::Upstream("dc\"quad9".into()),
            },
            StoredRoute {
                suffix: "ads.example".into(),
                target: RouteTarget::Literal(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            },
        ];
        let json = to_json_fragment(&routes);
        assert_eq!(
            json,
            r#"[{"suffix":"corp.example","upstream":"dc\"quad9"},{"suffix":"ads.example","address":"10.0.0.1"}]"#
        );
        assert_eq!(to_json_fragment(&[]), "[]");
    }

    #[test]
    fn persist_load_round_trip_and_blank_clears() {
        let dir = std::env::temp_dir().join(format!(
            "torta-routes-store-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("test dir");
        let dir_s = dir.to_string_lossy().to_string();

        let text = "server=/corp.example/dc-quad9\naddress=/ads.example/0.0.0.0\n";
        assert!(persist_text(&dir_s, text), "write-through accepted");
        assert_eq!(load_text(&dir_s).as_deref(), Some(text), "text round-trips");
        let (routes, skipped) = load_parsed(&dir_s);
        assert_eq!((routes.len(), skipped), (2, 0));

        // Blank text CLEARS the record — cold again, the empty-Router fast path.
        assert!(persist_text(&dir_s, "   \n"));
        assert!(load_text(&dir_s).is_none(), "cleared record reads cold");
        assert_eq!(load_parsed(&dir_s).0.len(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
