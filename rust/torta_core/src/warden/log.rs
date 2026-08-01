/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! SLICE 6 — `query-warden.log`: the Warden's per-pillar, human-legible VERDICT feed, written through the
//! shared RAM⊗NAND [`crate::log_tier`] substrate (#133, the `query.log` / `query-fortress.log` precedent).
//!
//! ## Why a per-pillar log (the Socio's review channel)
//! The same way dnscrypt-proxy's `query.log` feeds the resolver dashboard and F6's `query-fortress.log`
//! feeds the DNSSEC card, the Warden writes ONE line per DNS-answer verdict to `query-warden.log` — a
//! greppable, human-legible record of WHAT the firewall denied and WHY (the blocklist intelligence made
//! visible). The file lives BESIDE the matrix-state blob in the Warden's own app-private durable dir
//! (slice 2's [`bind_durable`](super::Warden::bind_durable)), so the pillar OWNS its log location — no
//! path plumbing across the FFI.
//!
//! ## The RAM⊗NAND + hot-path law (load-bearing)
//! The per-connection cascade ([`super::Warden::verdict`]) and the pure DNS-answer verdict
//! ([`super::Warden::dns_verdict`]) stay ALLOCATION-FREE, LOCK-HELD, ZERO-IO — the no-`std::fs`-on-the-
//! hot-path law (`runtime_tier.rs:20`). This log is emitted ONLY from the EXPLICIT review-channel seam
//! ([`super::Warden::dns_verdict_logged`]), never the hot verdict. The write goes through
//! [`crate::log_tier::log_append`] (the durable NAND source, bounded by a line-boundary tail-rewrite at
//! 256 KiB — the T20 bounded-ring covenant, NEVER an unbounded per-connection history). FAIL-OPEN: any IO
//! error is a silent no-op inside `log_append` — a debug log must NEVER break a verdict.
//!
//! ## Clock-injected (the warden invariant)
//! The whole `warden` module is `SystemTime`-free — every clock is INJECTED as `now_ms` by the datapath
//! control plane (the matrix TTL, the toggles, F6's verdict events). This log honors that:
//! [`format_dns_line`] takes `now_ms`, so the formatter is PURE + deterministic (unit-testable to the
//! exact byte).

use std::net::IpAddr;
use std::path::Path;

use super::verdict_loop::DnsDenyReason;
use super::Verdict;

/// The per-pillar log filename — a sibling of the matrix-state blob under the Warden's app-private durable
/// dir (the `query-<pillar>.log` convention, #133). Joined to that dir by
/// [`super::Warden::query_warden_log_path`].
pub const QUERY_WARDEN_LOG_NAME: &str = "query-warden.log";

/// The human-legible reason token for a DENY — the rule class that fired (first-match). `-` on an ALLOW.
fn reason_token(reason: Option<DnsDenyReason>) -> &'static str {
    match reason {
        Some(DnsDenyReason::Domain) => "domain",
        Some(DnsDenyReason::GlobDomain) => "glob",
        Some(DnsDenyReason::Address) => "address",
        None => "-",
    }
}

/// Format ONE `query-warden.log` line for a DNS-answer verdict. PURE + deterministic (the `now_ms` clock is
/// INJECTED — the warden invariant). Schema (single-space-separated, greppable):
///
/// ```text
/// <ts_ms> <ALLOW|DENY> <name> <reason> <addrs_csv>
/// ```
///
/// where `name` is the trimmed query name (trailing `.` stripped, `-` if empty), `reason` is the deny rule
/// class (`domain` / `glob` / `address`, `-` on an allow), and `addrs_csv` is the comma-joined resolved
/// addresses (`-` if none). No PII beyond the name + addr the device already resolved; the file is
/// device-local and bounded (the T20 ring) — never network-exported.
pub fn format_dns_line(
    now_ms: u64,
    verdict: Verdict,
    name: &str,
    addrs: &[IpAddr],
    reason: Option<DnsDenyReason>,
) -> String {
    let v = match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY",
    };
    let name = name.trim().trim_end_matches('.');
    let name = if name.is_empty() { "-" } else { name };
    let addrs_csv = if addrs.is_empty() {
        "-".to_string()
    } else {
        addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    format!("{now_ms} {v} {name} {} {addrs_csv}", reason_token(reason))
}

/// Append ONE DNS-answer verdict line to `path` (the Warden's `query-warden.log`) through the shared
/// [`crate::log_tier`] substrate (#133). FAIL-OPEN inside `log_append` (a no-op on any IO error). The path
/// is the Warden's bound durable dir + [`QUERY_WARDEN_LOG_NAME`]; an UNBOUND Warden never calls this (no
/// dir → no path → no log).
pub fn append_dns_verdict(
    path: &Path,
    now_ms: u64,
    verdict: Verdict,
    name: &str,
    addrs: &[IpAddr],
    reason: Option<DnsDenyReason>,
) {
    let line = format_dns_line(now_ms, verdict, name, addrs, reason);
    // Ensure the app-private dir exists. In production it always does (the `filesDir`), and slice 2's
    // matrix `write_through` also creates it — but the constructor [`DurableTier::with_dir`] does NO IO, so
    // a bound Warden that logs a verdict BEFORE any matrix write would otherwise have no dir. FAIL-OPEN: a
    // create error falls through to `log_append`'s own silent no-op (a debug log never breaks a verdict).
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    crate::log_tier::log_append(&path.to_string_lossy(), &line);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    #[test]
    fn format_allow_line_is_deterministic() {
        // A clean answer: trailing-dot stripped, no reason, the two resolved A records joined.
        let line = format_dns_line(
            1_751_300_000_123,
            Verdict::Allow,
            "api.example.com.",
            &[v4("93.184.216.34"), v4("8.8.4.4")],
            None,
        );
        assert_eq!(
            line,
            "1751300000123 ALLOW api.example.com - 93.184.216.34,8.8.4.4"
        );
    }

    #[test]
    fn format_deny_lines_carry_the_reason() {
        assert_eq!(
            format_dns_line(
                10,
                Verdict::Deny,
                "ads.evil.net",
                &[v4("203.0.113.9")],
                Some(DnsDenyReason::Domain)
            ),
            "10 DENY ads.evil.net domain 203.0.113.9"
        );
        // A glob deny on a name with NO resolved addrs → the addr field is `-`.
        assert_eq!(
            format_dns_line(
                11,
                Verdict::Deny,
                "metrics.tracker.net",
                &[],
                Some(DnsDenyReason::GlobDomain)
            ),
            "11 DENY metrics.tracker.net glob -"
        );
        // An ADDRESS deny: the name is clean, a resolved addr landed in a blocked CIDR.
        assert_eq!(
            format_dns_line(
                12,
                Verdict::Deny,
                "good.example.org",
                &[v4("203.0.113.9")],
                Some(DnsDenyReason::Address)
            ),
            "12 DENY good.example.org address 203.0.113.9"
        );
    }

    #[test]
    fn empty_name_renders_dash() {
        // A degenerate name (whitespace + bare root dot) collapses to `-` — never a torn/blank field.
        assert_eq!(
            format_dns_line(5, Verdict::Allow, "  .  ", &[], None),
            "5 ALLOW - - -"
        );
    }

    #[test]
    fn round_trips_through_log_tier() {
        // The #133 substrate: append verdict lines, read them back through the SAME log_tier tailer (the
        // shared write→read path that proves the per-pillar log is wired to the substrate, not a bespoke file).
        let mut p = std::env::temp_dir();
        p.push(format!(
            "torta-warden-log-roundtrip-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);

        append_dns_verdict(
            &p,
            100,
            Verdict::Deny,
            "ads.evil.net",
            &[v4("203.0.113.9")],
            Some(DnsDenyReason::Domain),
        );
        append_dns_verdict(
            &p,
            101,
            Verdict::Allow,
            "ok.example.org",
            &[v4("93.184.216.34")],
            None,
        );

        let got = crate::log_tier::log_tail_recent(&p.to_string_lossy(), 10);
        assert!(
            got.contains("DENY ads.evil.net domain 203.0.113.9"),
            "the deny line round-trips through log_tier: {got}"
        );
        assert!(
            got.contains("ALLOW ok.example.org - 93.184.216.34"),
            "the allow line round-trips through log_tier: {got}"
        );
        let _ = std::fs::remove_file(&p);
    }
}
