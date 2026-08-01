/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! SLICE 6 — `query-centauri.log`: the Centauri mirror's per-pillar, human-legible SERVE feed, written
//! through the shared RAM⊗NAND [`crate::log_tier`] substrate (#133, the `query-warden.log` /
//! `query-fortress.log` / `query.log` precedent).
//!
//! ## Why a per-pillar log (the CROWN made GREPPABLE — the Socio's review channel)
//! The way dnscrypt-proxy's `query.log` feeds the resolver dashboard and the Warden's `query-warden.log`
//! feeds the firewall card, Centauri writes ONE line per loopback serve to `query-centauri.log` — a
//! greppable, human-legible record of WHAT the mirror served and at WHAT privacy cost. This is the CROWN
//! ("the CDN sees ≤ 1 request") made AUDITABLE rather than asserted (Chroma F2): each line names whether the
//! asset was served from the device (the CDN saw 0), self-filled with the one allowed leak, blocked in strict
//! mode (the CDN saw 0), missed the catalog, or failed its fetch. `grep -c ' LOCAL '` counts the 0-egress
//! serves; `grep -c ' LEAK '` is the ≤ 1-per-asset proof; in strict mode `grep -c ' LEAK '` is **0** and every
//! miss is a `BLOCK` line — the privacy property is witnessable from the file. The log lives BESIDE the
//! content-addressed cache in the Centauri Object's own app-private `cache_dir`
//! ([`super::object::Centauri::query_centauri_log_path`]), so the pillar OWNS its log location — no path
//! plumbing across the FFI.
//!
//! ## The RAM⊗NAND + off-hot-path law (load-bearing)
//! The serve verdict ([`super::serve::serve_addressed`]) stays the lean, content-address-gated datapath; this
//! log is emitted ONLY from the EXPLICIT review-channel seam
//! ([`super::object::Centauri::record_serve_logged`]) — never inlined into the serve decision itself. The
//! write goes through [`crate::log_tier::log_append`] (the durable NAND source, bounded by a line-boundary
//! tail-rewrite at 256 KiB — the T20 bounded-ring covenant, NEVER an unbounded per-serve history). FAIL-OPEN:
//! any IO error is a silent no-op inside `log_append` — a debug log must NEVER break a serve.
//!
//! ## Clock-injected (the #133 / warden invariant)
//! The Centauri Object is `SystemTime`-free on the serve path — the event clock is INJECTED as `now_ms` by the
//! caller and carried on the [`super::object::CentauriServeRecord`] (the structured twin of one log line). This
//! log honors that: [`format_serve_line`] reads `record.now_ms`, so the formatter is PURE + deterministic
//! (unit-testable to the exact byte) — it never reads a wall clock.

use std::path::Path;

use super::object::{CentauriServeOutcome, CentauriServeRecord, CentauriSubstitution};

/// The per-pillar log filename — a sibling of the content-addressed cache under the Centauri Object's
/// app-private `cache_dir` (the `query-<pillar>.log` convention, #133). Joined to that dir by
/// [`super::object::Centauri::query_centauri_log_path`].
pub const QUERY_CENTAURI_LOG_NAME: &str = "query-centauri.log";

/// The human-legible serve verb (the CROWN made greppable) — the first token after the timestamp.
///   - `LOCAL`     — cache hit, served from the device, the CDN saw 0 (the win).
///   - `LEAK`      — a genuine miss self-filled with the ONE allowed upstream fetch (the ≤ 1, AUDITABLE).
///   - `BLOCK`     — strict mode served NOTHING on a miss ⇒ the CDN saw 0 (the crown).
///   - `MISS`      — the name was not authorized by the signed catalog (fell through to the real CDN).
///   - `FETCHFAIL` — the one allowed fetch failed (transport / oversize / hash-mismatch) — no bytes served.
fn outcome_verb(o: CentauriServeOutcome) -> &'static str {
    match o {
        CentauriServeOutcome::ServedLocal => "LOCAL",
        CentauriServeOutcome::LeakedThenServed => "LEAK",
        CentauriServeOutcome::BlockedMissing => "BLOCK",
        CentauriServeOutcome::NotInCatalog => "MISS",
        CentauriServeOutcome::FetchFailed => "FETCHFAIL",
    }
}

/// The version-substitution token — the F3 honesty split made legible. `-` for `Incompatible` (never served)
/// AND for `NotApplicable` (a non-serve miss: no verdict exists — the log never fakes an "exact" on a 404).
fn sub_token(s: CentauriSubstitution) -> &'static str {
    match s {
        CentauriSubstitution::Exact => "exact",
        CentauriSubstitution::SafeNewer => "newer",
        CentauriSubstitution::RiskyOlder => "older",
        CentauriSubstitution::Incompatible | CentauriSubstitution::NotApplicable => "-",
    }
}

/// Format ONE `query-centauri.log` line from a serve event [`CentauriServeRecord`] (its structured twin).
/// PURE and deterministic — the `now_ms` clock is INJECTED on the record (the #133 invariant), so this never
/// reads a wall clock. Schema (single-space-separated, greppable):
///
/// ```text
/// <ts_ms> <VERB> <host> <canonical_name> <sub> <bytes> <req→served>
/// ```
///
/// where `host` is the cloaked CDN host the request carried (`-` if none), `canonical_name` is the
/// host-independent catalog asset name `<library>/<served_version>/<file>` (`-` if unresolved), `sub` is the
/// substitution verdict (`exact`/`newer`/`older`/`-`), `bytes` is the served byte count (0 unless `LOCAL`/
/// `LEAK`), and `req→served` is the version drift `3.6.0→3.7.1` on a fallback (else `-`). No PII beyond the
/// library URL the device already requested; the file is device-local and bounded (the T20 ring) — never
/// network-exported.
pub fn format_serve_line(record: &CentauriServeRecord) -> String {
    let host = {
        let h = record.host.trim();
        if h.is_empty() {
            "-"
        } else {
            h
        }
    };
    let name = {
        let n = record.canonical_name.trim();
        if n.is_empty() {
            "-"
        } else {
            n
        }
    };
    // The version drift — shown ONLY when the served version genuinely differs (a fallback substitution); an
    // exact serve (or a degenerate empty version) renders `-` so the field is never a torn/blank token.
    let drift = if record.requested_version != record.served_version
        && !record.requested_version.is_empty()
        && !record.served_version.is_empty()
    {
        format!("{}→{}", record.requested_version, record.served_version)
    } else {
        "-".to_string()
    };
    format!(
        "{} {} {host} {name} {} {} {drift}",
        record.now_ms,
        outcome_verb(record.outcome),
        sub_token(record.substitution),
        record.bytes,
    )
}

/// Append ONE serve-event line to `path` (the Centauri Object's `query-centauri.log`) through the shared
/// [`crate::log_tier`] substrate (#133). FAIL-OPEN inside `log_append` (a no-op on any IO error). The path is
/// the Object's `cache_dir` + [`QUERY_CENTAURI_LOG_NAME`] (always present — the Object always has a `cache_dir`,
/// unlike the RAM-unbound Warden). The serve verdict computation is the SAME pure datapath; this write is the
/// explicit review-channel seam, off the per-serve hot path.
pub fn append_serve(path: &Path, record: &CentauriServeRecord) {
    let line = format_serve_line(record);
    // Ensure the app-private dir exists. In production the `cache_dir` always does (the cache is rooted there),
    // but a serve logged before the first cache write would otherwise have no dir. FAIL-OPEN: a create error
    // falls through to `log_append`'s own silent no-op (a debug log never breaks a serve).
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    crate::log_tier::log_append(&path.to_string_lossy(), &line);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a serve record with the fields the log cares about (the `library` field is unused by the
    /// formatter — the canonical name already carries it — so it is left empty for terse, byte-exact tests).
    #[allow(clippy::too_many_arguments)]
    fn rec(
        now_ms: u64,
        outcome: CentauriServeOutcome,
        host: &str,
        canonical_name: &str,
        requested_version: &str,
        served_version: &str,
        substitution: CentauriSubstitution,
        bytes: i64,
    ) -> CentauriServeRecord {
        CentauriServeRecord {
            now_ms,
            host: host.to_string(),
            canonical_name: canonical_name.to_string(),
            library: String::new(),
            requested_version: requested_version.to_string(),
            served_version: served_version.to_string(),
            substitution,
            outcome,
            bytes,
        }
    }

    #[test]
    fn format_local_exact_line_is_deterministic() {
        // A 0-egress local hit at an EXACT version: the CDN saw 0, no version drift.
        let line = format_serve_line(&rec(
            1_751_300_000_123,
            CentauriServeOutcome::ServedLocal,
            "cdnjs.cloudflare.com",
            "jquery/3.6.0/jquery.min.js",
            "3.6.0",
            "3.6.0",
            CentauriSubstitution::Exact,
            89_476,
        ));
        assert_eq!(
            line,
            "1751300000123 LOCAL cdnjs.cloudflare.com jquery/3.6.0/jquery.min.js exact 89476 -"
        );
    }

    #[test]
    fn format_leak_fallback_line_carries_the_version_drift() {
        // The one allowed leak (≤ 1) on a SafeNewer fallback — the drift names requested→served.
        let line = format_serve_line(&rec(
            1_751_300_000_200,
            CentauriServeOutcome::LeakedThenServed,
            "ajax.googleapis.com",
            "bootstrap/5.3.3/css/bootstrap.min.css",
            "5.3.0",
            "5.3.3",
            CentauriSubstitution::SafeNewer,
            162_540,
        ));
        assert_eq!(
            line,
            "1751300000200 LEAK ajax.googleapis.com bootstrap/5.3.3/css/bootstrap.min.css newer 162540 5.3.0→5.3.3"
        );
    }

    #[test]
    fn format_block_miss_and_fetchfail_lines_are_deterministic() {
        // strict-mode block (the crown, CDN saw 0, no bytes) — a covered-but-uncached asset.
        assert_eq!(
            format_serve_line(&rec(
                10,
                CentauriServeOutcome::BlockedMissing,
                "cdnjs.cloudflare.com",
                "mathjax/3.2.2/MathJax.js",
                "3.2.2",
                "3.2.2",
                CentauriSubstitution::Exact,
                0,
            )),
            "10 BLOCK cdnjs.cloudflare.com mathjax/3.2.2/MathJax.js exact 0 -"
        );
        // an unmapped/uncatalogued name fell through to the real CDN — unresolved name + sub render `-`.
        // A miss served no bytes, so its verdict is `NotApplicable` (what `record_from_trace` now emits),
        // NOT a phantom `Exact`; the log token is `-`.
        assert_eq!(
            format_serve_line(&rec(
                11,
                CentauriServeOutcome::NotInCatalog,
                "unmapped.cdn.example",
                "",
                "",
                "",
                CentauriSubstitution::NotApplicable,
                0,
            )),
            "11 MISS unmapped.cdn.example - - 0 -"
        );
        // the one allowed fetch failed (transport/oversize/hash-mismatch) — no bytes served.
        assert_eq!(
            format_serve_line(&rec(
                12,
                CentauriServeOutcome::FetchFailed,
                "cdnjs.cloudflare.com",
                "d3/7.8.5/d3.min.js",
                "7.8.5",
                "7.8.5",
                CentauriSubstitution::Exact,
                0,
            )),
            "12 FETCHFAIL cdnjs.cloudflare.com d3/7.8.5/d3.min.js exact 0 -"
        );
    }

    #[test]
    fn empty_host_and_name_render_dash() {
        // A degenerate (whitespace) host + an empty canonical name collapse to `-` — never a torn/blank field.
        assert_eq!(
            format_serve_line(&rec(
                5,
                CentauriServeOutcome::ServedLocal,
                "   ",
                "",
                "1.0.0",
                "1.0.0",
                CentauriSubstitution::Exact,
                42,
            )),
            "5 LOCAL - - exact 42 -"
        );
    }

    #[test]
    fn round_trips_through_log_tier() {
        // The #133 substrate: append serve lines, read them back through the SAME log_tier tailer (the shared
        // write→read path that proves the per-pillar log is wired to the substrate, not a bespoke file).
        let mut p = std::env::temp_dir();
        p.push(format!(
            "torta-centauri-log-roundtrip-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);

        append_serve(
            &p,
            &rec(
                100,
                CentauriServeOutcome::ServedLocal,
                "cdnjs.cloudflare.com",
                "jquery/3.6.0/jquery.min.js",
                "3.6.0",
                "3.6.0",
                CentauriSubstitution::Exact,
                89_476,
            ),
        );
        append_serve(
            &p,
            &rec(
                101,
                CentauriServeOutcome::LeakedThenServed,
                "ajax.googleapis.com",
                "bootstrap/5.3.3/css/bootstrap.min.css",
                "5.3.0",
                "5.3.3",
                CentauriSubstitution::SafeNewer,
                162_540,
            ),
        );

        let got = crate::log_tier::log_tail_recent(&p.to_string_lossy(), 10);
        assert!(
            got.contains("LOCAL cdnjs.cloudflare.com jquery/3.6.0/jquery.min.js exact 89476 -"),
            "the local-hit line round-trips through log_tier: {got}"
        );
        assert!(
            got.contains(
                "LEAK ajax.googleapis.com bootstrap/5.3.3/css/bootstrap.min.css newer 162540 5.3.0→5.3.3"
            ),
            "the leak line round-trips through log_tier: {got}"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn strict_mode_emits_no_leak_lines_so_the_crown_is_greppable() {
        // The CROWN, witnessed: in strict mode a miss is a BLOCK (CDN saw 0), never a LEAK. `grep ' LEAK '`
        // over the log is the privacy proof — strict mode ⇒ 0 leak lines, every miss a block.
        let mut p = std::env::temp_dir();
        p.push(format!(
            "torta-centauri-log-strict-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);

        append_serve(
            &p,
            &rec(
                200,
                CentauriServeOutcome::BlockedMissing,
                "cdnjs.cloudflare.com",
                "mathjax/3.2.2/MathJax.js",
                "3.2.2",
                "3.2.2",
                CentauriSubstitution::Exact,
                0,
            ),
        );
        append_serve(
            &p,
            &rec(
                201,
                CentauriServeOutcome::ServedLocal,
                "ajax.googleapis.com",
                "jquery/3.7.1/jquery.min.js",
                "3.7.1",
                "3.7.1",
                CentauriSubstitution::Exact,
                90_000,
            ),
        );

        let got = crate::log_tier::log_tail_recent(&p.to_string_lossy(), 10);
        assert!(
            !got.contains(" LEAK "),
            "strict mode emits ZERO leak lines (the CDN saw 0): {got}"
        );
        assert!(
            got.contains("BLOCK cdnjs.cloudflare.com mathjax/3.2.2/MathJax.js exact 0 -"),
            "the strict-mode miss is a block line: {got}"
        );
        let _ = std::fs::remove_file(&p);
    }
}
