/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! SLICE 6 — `query-masksolver.log`: the MaskSolver's per-pillar, human-legible RESOLVE feed, written
//! through the shared RAM⊗NAND [`crate::log_tier`] substrate (#133, the `query.log` / `query-fortress.log`
//! / `query-warden.log` precedent).
//!
//! ## Why a per-pillar log (the Socio's review channel)
//! The same way dnscrypt-proxy's `query.log` feeds the resolver dashboard and the Warden's
//! `query-warden.log` feeds the firewall card, MaskSolver writes ONE line per RESOLVE OUTCOME to
//! `query-masksolver.log` — a greppable, human-legible record of the SOLVE+CACHE story made visible: WAS
//! it a cache HIT, a serve-STALE, a live SOLVE, a BLOCK, or a MISS. The file lands BESIDE the resolver's
//! durable cache/rotation blobs in the pillar's own app-private durable dir (the
//! [`bind_durable`](super::MaskSolver::bind_durable) target), so the pillar OWNS its log location — no
//! path plumbing across the FFI.
//!
//! ## The RAM⊗NAND + hot-path law (load-bearing)
//! The pure datapath ([`super::resolve`] → `resolve_inner`) stays ALLOCATION-LIGHT, IO-FREE — the
//! no-`std::fs`-on-the-hot-path keystone (`runtime_tier.rs:20`, the same law the byte-identical base `.so`
//! rests on). This log is emitted ONLY from the EXPLICIT review-channel seam ([`super::resolve_logged`] →
//! [`super::MaskSolver::resolve_logged`]), never the hot [`super::resolve`]. The datapath classifies its
//! own outcome ([`ResolveOutcome`], threaded out as a stack-local — never a global, so no cross-thread
//! misattribution); the logged seam maps that to a line + appends it. The write goes through
//! [`crate::log_tier::log_append`] (the durable NAND source, bounded by a line-boundary tail-rewrite at
//! 256 KiB — the T20 bounded-ring covenant, NEVER an unbounded per-query history). FAIL-OPEN: any IO error
//! is a silent no-op inside `log_append` — a debug log must NEVER break the resolve path.
//!
//! ## Clock-injected + PII-free (the resolver-log invariants)
//! [`format_query_line`] takes `now_ms` (the wall clock is INJECTED by the control plane — the formatter is
//! PURE + deterministic, unit-testable to the exact byte). T20: the line carries the OUTCOME token, the
//! answering-transport id label (or `-`), the exchange RTT (or `-`), and the numeric DNS QTYPE — a COUNT,
//! NEVER a qname / client-IP / answer rdata. The file is device-local + bounded — never network-exported.

use std::path::Path;

/// The per-pillar log filename — a sibling of the resolver's durable cache/rotation blobs under the
/// MaskSolver's app-private durable dir (the `query-<pillar>.log` convention, #133). Joined to that dir by
/// [`super::MaskSolver::query_masksolver_log_path`].
pub const QUERY_MASKSOLVER_LOG_NAME: &str = "query-masksolver.log";

/// The classified RESOLVE OUTCOME the datapath (`resolve_inner`) hands back to the logged seam — the
/// discriminator behind each `query-masksolver.log` line's leading token. Each variant maps to a REAL
/// `resolve_inner` return point (its atomic-counter bump), so a logged token is never fabricated: it is the
/// GROUND TRUTH of what the datapath actually did on this query.
///
/// [`ServeStale`](ResolveOutcome::ServeStale) is schema-complete but honest-ZERO until the slice-3
/// serve-stale-while-revalidate wiring routes a stale [`super::cache::CacheHit`] to its own datapath return
/// (today the datapath's `cache.get` return is classified [`CacheHit`](ResolveOutcome::CacheHit)) — the
/// crate's dead-code-until-wired idiom applied to a log token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// A fresh RAM-cache hit — served from the hot tier, zero egress (`resolve_inner` cache return).
    CacheHit,
    /// RFC 8767 serve-stale — an expired-but-usable entry answered while a refresh was due. Honest-ZERO
    /// until slice-3's revalidate seam routes it to its own datapath return: schema-complete but not yet
    /// constructed on the live path (the crate's dead-code-until-wired idiom, `blocklist.rs:235`), so a
    /// stale hit is classified [`CacheHit`](ResolveOutcome::CacheHit) today.
    ServeStale,
    /// A live upstream (or a locally-synthesized DNS64) POSITIVE answer — the SOLVE-cross "got through".
    Solved,
    /// A live upstream VALIDATED NEGATIVE (RCODE=3 NXDOMAIN) returned to the caller (never cached — the
    /// C1 no-negative-cache law). ★ E-FIX r3: distinct from [`Solved`](ResolveOutcome::Solved) so a
    /// nonexistent-domain answer is grep-able as its own verdict row ("NXDOMAIN") in the review feed —
    /// the AVD block/NXDOMAIN sub-facet was un-witnessable while negatives logged as SOLVE.
    SolvedNegative,
    /// A locally-synthesized POSITIVE answer with zero egress — a user pin / `address=` literal / Centauri
    /// cloak loopback redirect.
    LocalAnswer,
    /// A gate denied the name — a synthesized block reply (NXDOMAIN / sink / custom-IP). The
    /// payload names WHICH gate, which the log could not previously express: four distinct gates
    /// all set this outcome and `query_feed::zero_egress_server` rendered every one of them as
    /// `"blocklist"`. On device that hid the real denier completely — the UNDERGROUND teeth fired
    /// 1467 times under the blocklist's name, and it cost a whole debugging pass.
    ///
    /// Proved for ALL gates in D:/Lean/proofs/Proofs/DenyAttribution.lean: the old labelling is
    /// NOT injective (`shipped_labelling_is_not_injective`), the per-gate one is
    /// (`fixed_labelling_is_injective`), and `injective_labelling_needs_a_label_per_gate` is
    /// quantified over any labelling and any gate list, so a FIFTH gate cannot silently re-collapse
    /// into an existing label.
    Blocked(DenyGate),
    /// A privacy guard answered locally (NXDOMAIN, zero egress) — `--bogus-priv` private-PTR or the
    /// never-forward RFC6761/8375 local-zone guard.
    Guarded,
    /// A rebind-protection REJECT — a public name resolved to a private address, dropped (never cached,
    /// never returned).
    RebindReject,
    /// The keystone `validate_response` rejected a forged/poisoned upstream answer — dropped.
    Rejected,
    /// No answer produced — the ladder exhausted / the deadline hit / not configured / a malformed query
    /// (the datapath falls through to dnscrypt-proxy).
    Miss,
}

impl ResolveOutcome {
    /// The single greppable UPPERCASE token for this outcome (the line's 2nd field).
    fn token(self) -> &'static str {
        match self {
            ResolveOutcome::CacheHit => "HIT",
            ResolveOutcome::ServeStale => "STALE",
            ResolveOutcome::Solved => "SOLVE",
            ResolveOutcome::SolvedNegative => "NXDOMAIN",
            ResolveOutcome::LocalAnswer => "LOCAL",
            ResolveOutcome::Blocked(_) => "BLOCK",
            ResolveOutcome::Guarded => "GUARD",
            ResolveOutcome::RebindReject => "REBIND",
            ResolveOutcome::Rejected => "REJECT",
            ResolveOutcome::Miss => "MISS",
        }
    }
}

/// Format ONE `query-masksolver.log` line for a resolve outcome. PURE + deterministic (the `now_ms` clock is
/// INJECTED — the resolver-log invariant). Schema (single-space-separated, greppable):
///
/// ```text
/// <ts_ms> <HIT|STALE|SOLVE|NXDOMAIN|LOCAL|BLOCK|GUARD|REBIND|REJECT|MISS> <transport|-> <rtt_ms|-> <qtype>
/// ```
///
/// where `transport` is the answering upstream id label (`-` for a cache/local/block/miss outcome with no
/// upstream, or when the answering transport is not surfaced at this seam), `rtt_ms` is the measured
/// exchange latency (`-` when not a live solve / not surfaced), and `qtype` is the numeric DNS QTYPE
/// (A=1 / AAAA=28 / …, a COUNT — never the qname). No qname, no client IP, no answer rdata — T20.
/// Device-local, bounded (the 256 KiB #133 ring), never network-exported.
pub fn format_query_line(
    now_ms: u64,
    outcome: ResolveOutcome,
    transport: Option<&str>,
    rtt_ms: Option<u32>,
    qtype: u16,
) -> String {
    let t = transport
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("-");
    let rtt = rtt_ms
        .map(|r| r.to_string())
        .unwrap_or_else(|| "-".to_string());
    format!("{now_ms} {} {t} {rtt} {qtype}", outcome.token())
}

/// Append ONE resolve-outcome line to `path` (the MaskSolver's `query-masksolver.log`) through the shared
/// [`crate::log_tier`] substrate (#133). FAIL-OPEN inside `log_append` (a no-op on any IO error). The path
/// is the MaskSolver's bound durable dir + [`QUERY_MASKSOLVER_LOG_NAME`]; an UNBOUND MaskSolver never calls
/// this (no dir → no path → no log).
pub fn append_resolve(
    path: &Path,
    now_ms: u64,
    outcome: ResolveOutcome,
    transport: Option<&str>,
    rtt_ms: Option<u32>,
    qtype: u16,
) {
    let line = format_query_line(now_ms, outcome, transport, rtt_ms, qtype);
    // Ensure the app-private dir exists. In production it always does (the `filesDir`), and the cache/
    // rotation persist paths also create it — but a bound MaskSolver that logs a resolve BEFORE any persist
    // would otherwise have no dir. FAIL-OPEN: a create error falls through to `log_append`'s own silent
    // no-op (a debug log never breaks a resolve).
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    crate::log_tier::log_append(&path.to_string_lossy(), &line);
}

/// ★ A1 — emit the AAAA-withholding marker. Kept as a named function so the string literal lives in
/// exactly one place and is greppable INSIDE the shipped `.so` (the artifact witness a doc comment
/// can never be), and so the resolver hot path carries no formatting cost beyond the call.
pub(crate) fn debug_v6_withheld() {
    ::log::warn!(
        "resolver: AAAA withheld as NODATA -- v6 egress presumed dead, probe cadence live"
    );
}

/// WHICH gate denied a query. Four distinct gates synthesize the same NXDOMAIN, and before this
/// existed the query log rendered all four as `"blocklist"` — so a denial could not be attributed
/// to the pillar that issued it. Each variant maps to a DISTINCT label; see
/// `query_feed::zero_egress_server`.
///
/// SCOPE NOTE: this enum must live at FILE scope, never inside `mod tests`. A rewind spliced it
/// into the body of a `#[cfg(test)]` test function, which made it invisible to release builds and
/// produced `E0425: cannot find type DenyGate in this scope` at its own use site 176 lines above —
/// while `cargo test` stayed green, because under `--test` the type WAS in scope. A type used by
/// the non-test datapath and defined under `cfg(test)` is a build that passes its own test suite
/// and cannot ship.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DenyGate {
    /// The blocklist matcher — the deny the user actually asked for.
    Blocklist,
    /// The WARDEN inline firewall verdict.
    Warden,
    /// The UNDERGROUND teeth — a licence provably drained to 0.
    Underground,
    /// The IDN homograph guard.
    Homograph,
    /// The client-DoH bootstrap sinkhole — a browser was denied its own encrypted resolver so the
    /// pillars can see the traffic again. Its OWN label because attributing it to the blocklist
    /// would hide the one denial a user is most likely to want explained.
    DohBypass,
}

impl DenyGate {
    /// The log label. INJECTIVE by construction — proved in
    /// D:/Lean/proofs/Proofs/DenyAttribution.lean (`fixed_labelling_is_injective`,
    /// `fixed_labelling_is_never_empty`).
    pub(crate) fn label(self) -> &'static str {
        match self {
            DenyGate::Blocklist => "blocklist",
            DenyGate::Warden => "warden",
            DenyGate::Underground => "underground",
            DenyGate::Homograph => "homograph",
            DenyGate::DohBypass => "doh-bypass",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_hit_line_is_deterministic_no_upstream() {
        // A cache hit: no answering transport, no rtt — both render `-`; the qtype is the numeric A=1.
        let line = format_query_line(1_751_300_000_123, ResolveOutcome::CacheHit, None, None, 1);
        assert_eq!(line, "1751300000123 HIT - - 1");
    }

    #[test]
    fn format_solve_line_carries_transport_and_rtt() {
        // A live solve: the answering upstream id + the measured rtt land in the line; AAAA=28.
        let line = format_query_line(
            10,
            ResolveOutcome::Solved,
            Some("doh:cloudflare"),
            Some(42),
            28,
        );
        assert_eq!(line, "10 SOLVE doh:cloudflare 42 28");
    }

    #[test]
    fn each_outcome_renders_its_token() {
        let cases = [
            (ResolveOutcome::CacheHit, "HIT"),
            (ResolveOutcome::ServeStale, "STALE"),
            (ResolveOutcome::Solved, "SOLVE"),
            (ResolveOutcome::SolvedNegative, "NXDOMAIN"),
            (ResolveOutcome::LocalAnswer, "LOCAL"),
            (ResolveOutcome::Blocked(DenyGate::Blocklist), "BLOCK"),
            (ResolveOutcome::Guarded, "GUARD"),
            (ResolveOutcome::RebindReject, "REBIND"),
            (ResolveOutcome::Rejected, "REJECT"),
            (ResolveOutcome::Miss, "MISS"),
        ];
        for (outcome, token) in cases {
            let line = format_query_line(7, outcome, None, None, 1);
            assert_eq!(line, format!("7 {token} - - 1"), "token for {outcome:?}");
        }
    }

    #[test]
    fn blank_transport_renders_dash() {
        // A whitespace-only transport label collapses to `-` — never a torn/blank field.
        let line = format_query_line(5, ResolveOutcome::Solved, Some("   "), None, 1);
        assert_eq!(line, "5 SOLVE - - 1");
    }

    #[test]
    fn round_trips_through_log_tier() {
        // The #133 substrate: append outcome lines, read them back through the SAME log_tier tailer (the
        // shared write→read path that proves the per-pillar log is wired to the substrate, not a bespoke
        // file).
        let mut p = std::env::temp_dir();
        p.push(format!(
            "torta-masksolver-log-roundtrip-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);

        append_resolve(&p, 100, ResolveOutcome::CacheHit, None, None, 1);
        append_resolve(
            &p,
            101,
            ResolveOutcome::Solved,
            Some("do53:proxy"),
            Some(12),
            28,
        );
        append_resolve(
            &p,
            102,
            ResolveOutcome::Blocked(DenyGate::Blocklist),
            None,
            None,
            1,
        );

        let got = crate::log_tier::log_tail_recent(&p.to_string_lossy(), 10);
        assert!(
            got.contains("100 HIT - - 1"),
            "the cache-hit line round-trips through log_tier: {got}"
        );
        assert!(
            got.contains("101 SOLVE do53:proxy 12 28"),
            "the solve line round-trips through log_tier: {got}"
        );
        assert!(
            got.contains("102 BLOCK - - 1"),
            "the block line round-trips through log_tier: {got}"
        );
        let _ = std::fs::remove_file(&p);
    }
}
