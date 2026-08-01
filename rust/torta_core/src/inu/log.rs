/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! `query-inu.log` — the Wire Cake Inu pillar's per-pillar, human-legible ELEVATION-EVENT feed, written
//! through the shared RAM⊗NAND [`crate::log_tier`] substrate (#133, the `query.log` /
//! `query-warden.log` / `query-fortress.log` precedent).
//!
//! ## Why a per-pillar log (the Socio's review channel)
//! The same way each pillar surfaces ONE greppable line per meaningful event, the Inu core writes one line
//! per elevation event — PAIR / ELEVATE / GRANT / REVERT / SWITCH / DRIFT_REAPPLY / FAIL (the typed
//! [`InuEvent`] set) — a device-local record of WHAT elevated and WHAT power changed. The file is a
//! SIBLING of the state blob in the pillar's own
//! app-private durable dir ([`super::object::InuStore`] owns its location), so the pillar OWNS its log path
//! — no path plumbing across the FFI.
//!
//! ## The RAM⊗NAND + bounded law (load-bearing)
//! The write goes through [`crate::log_tier::log_append`] (the durable NAND source, bounded by a
//! line-boundary tail-rewrite at 256 KiB — never an unbounded elevation history) and is emitted ONLY from
//! the EXPLICIT review-channel seam ([`super::object::InuStore::log_event`]), NEVER a hot path. FAIL-OPEN:
//! any IO error is a silent no-op inside `log_append` — a debug log must NEVER break an elevation grant.
//!
//! ## Clock-injected + greppable (deterministic)
//! [`format_inu_line`] takes `now_ms` INJECTED by the Kotlin control plane (no `SystemTime` here) and
//! sanitizes every free token (event/detail) so a stray space/newline can never tear the single-space
//! schema — the formatter is PURE + unit-testable to the exact byte.

use std::path::Path;

use super::{InuEvent, InuProvider};

/// The per-pillar log filename — a sibling of the Inu state blob under the pillar's app-private durable dir
/// (the `query-<pillar>.log` convention, #133). Joined to that dir by
/// [`super::object::InuStore::query_inu_log_path`].
pub const QUERY_INU_LOG_NAME: &str = "query-inu.log";

/// Sanitize a free-text token so it can never tear the single-space-separated schema: any ASCII whitespace
/// (space, tab, CR, LF) becomes `_`; an empty token becomes `-`. Keeps the line greppable + one-record.
fn sanitize_token(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        return "-".to_string();
    }
    t.chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect()
}

/// Format ONE `query-inu.log` line for an elevation event. PURE + deterministic (the `now_ms` clock is
/// INJECTED). Schema (single-space-separated, greppable):
///
/// ```text
/// <ts_ms> <EVENT> <provider> <detail>
/// ```
///
/// e.g. `1751300000123 GRANT self-adb always_on_vpn=held`. No PII beyond the power tokens the device
/// already holds; the file is device-local + bounded (the #133 ring) — never network-exported.
pub fn format_inu_line(now_ms: i64, event: &str, provider: InuProvider, detail: &str) -> String {
    format!(
        "{now_ms} {} {} {}",
        sanitize_token(event),
        provider.key(),
        sanitize_token(detail)
    )
}

/// Append ONE elevation-event line to `path` (the pillar's `query-inu.log`) through the shared
/// [`crate::log_tier`] substrate (#133). FAIL-OPEN inside `log_append` (a no-op on any IO error). The
/// app-private dir is created if absent (the constructor does NO IO, so a pillar that logs BEFORE its first
/// `persist` would otherwise have no dir — the create error itself falls through to `log_append`'s silent
/// no-op).
pub fn append_inu_event(
    path: &Path,
    now_ms: i64,
    event: &str,
    provider: InuProvider,
    detail: &str,
) {
    let line = format_inu_line(now_ms, event, provider, detail);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    crate::log_tier::log_append(&path.to_string_lossy(), &line);
}

/// Append a PROVIDER-SWITCH event ([`InuEvent::ProviderSwitch`] → `SWITCH`): the active elevation channel
/// changed from `from` to `to` (e.g. Shizuku→self-adb, the role-named switch). The `to` provider is the
/// line's provider field; the `from` is carried in the `detail` as `from=<key>` so the switch is greppable
/// in BOTH directions (grep `SWITCH self-adb` for the destination, `from=shizuku` for the source). Typed
/// both-provider event the single-provider [`append_inu_event`] can't express. FAIL-OPEN (through
/// [`append_inu_event`]).
pub fn append_provider_switch(path: &Path, now_ms: i64, from: InuProvider, to: InuProvider) {
    let detail = format!("from={}", from.key());
    append_inu_event(path, now_ms, InuEvent::ProviderSwitch.label(), to, &detail);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_is_deterministic_and_greppable() {
        assert_eq!(
            format_inu_line(
                1_751_300_000_123,
                "GRANT",
                InuProvider::SelfAdb,
                "always_on_vpn=held"
            ),
            "1751300000123 GRANT self-adb always_on_vpn=held"
        );
        assert_eq!(
            format_inu_line(10, "PAIR", InuProvider::Shizuku, "ok"),
            "10 PAIR shizuku ok"
        );
    }

    #[test]
    fn tokens_are_sanitized_no_torn_schema() {
        // A detail with embedded whitespace can never split into extra fields.
        assert_eq!(
            format_inu_line(5, "FAIL", InuProvider::None, "read back mismatch\nboom"),
            "5 FAIL none read_back_mismatch_boom"
        );
        // Empty event/detail collapse to `-` (never a blank field).
        assert_eq!(format_inu_line(7, "", InuProvider::Stub, ""), "7 - stub -");
    }

    #[test]
    fn round_trips_through_log_tier() {
        // The #133 substrate: append event lines, read them back through the SAME log_tier tailer (the
        // shared write→read path that proves the per-pillar log is wired to the substrate).
        let mut p = std::env::temp_dir();
        p.push(format!(
            "torta-inu-log-roundtrip-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);

        append_inu_event(&p, 100, "ELEVATE", InuProvider::SelfAdb, "uid=2000");
        append_inu_event(&p, 101, "GRANT", InuProvider::SelfAdb, "lockdown=held");

        let got = crate::log_tier::log_tail_recent(&p.to_string_lossy(), 10);
        assert!(
            got.contains("ELEVATE self-adb uid=2000"),
            "the elevate line round-trips through log_tier: {got}"
        );
        assert!(
            got.contains("GRANT self-adb lockdown=held"),
            "the grant line round-trips through log_tier: {got}"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn provider_switch_line_names_from_and_to() {
        // The role-named Shizuku↔self-adb switch: the `to` is the provider field, the `from` is in detail —
        // greppable both directions, round-tripped through the SAME log_tier substrate.
        let mut p = std::env::temp_dir();
        p.push(format!("torta-inu-switch-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&p);

        append_provider_switch(&p, 200, InuProvider::Shizuku, InuProvider::SelfAdb);
        let got = crate::log_tier::log_tail_recent(&p.to_string_lossy(), 10);
        assert_eq!(
            got, "200 SWITCH self-adb from=shizuku",
            "the provider switch frames to-provider + from=<src>: {got}"
        );
        let _ = std::fs::remove_file(&p);
    }
}
