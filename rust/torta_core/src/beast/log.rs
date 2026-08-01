/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! `query-beast.log` — the Beast's per-pillar, human-legible EVENT feed, written through the shared
//! RAM⊗NAND [`crate::log_tier`] substrate (#133, the `query-warden.log` / `query-fortress.log` precedent).
//!
//! ## Why a per-pillar log (the Socio's review channel)
//! The same way dnscrypt-proxy's `query.log` feeds the resolver dashboard and F6's `query-fortress.log`
//! feeds the DNSSEC card, the Beast writes ONE line per live event — a periodic THROUGHPUT tick, a YeAH
//! MODE transition (SLOW-START→YEAH→COMPETING→RECOVERY), an AQM SHED, or a basin OVERFLOW — to
//! `query-beast.log`. A greppable, human-legible record of the flow engine's behaviour (the Tortä×YeAH
//! congestion story made visible), the tail of which feeds the Beast Tab's `RECENT TICKS` list.
//!
//! ## The RAM⊗NAND + hot-path law (load-bearing)
//! The Beast hot path ([`super::Beast::apply_sample`] / [`super::Beast::apply_udp_sample`] /
//! [`super::Beast::enqueue_probe`] / [`super::Beast::dispatch`]) stays LOCK-HELD, ZERO-IO — the
//! no-`std::fs`-on-the-hot-path law. This log is emitted ONLY from the EXPLICIT review-channel seam
//! ([`super::Beast::log_event`]), driven by the Kotlin control plane on its own cadence (it holds the
//! [`super::BeastMetricSink`] push stream and observes each mode-shift there — the caller decides WHEN to
//! log, exactly like the Warden's datapath decides when to call `dns_verdict_logged`). The write goes
//! through [`crate::log_tier::log_append`] (the durable NAND source, bounded by a line-boundary tail-rewrite
//! at 256 KiB — the T20 bounded-ring covenant, NEVER an unbounded event history). FAIL-OPEN: any IO error is
//! a silent no-op inside `log_append` — a debug log must NEVER break the flow engine.
//!
//! ## Clock-injected + host-supplied identity (the invariants)
//! The formatter is PURE + deterministic (unit-testable to the exact byte): the wall clock is INJECTED as
//! `now_ms`, and the resolver `relay` name is HOST-SUPPLIED (the Beast Object holds no relay name — a
//! [`super::ProbeRequest`] carries only `endpoint_idx`; the human name is the host's to provide, `-` when
//! absent). Every rendered number is a field of the live [`super::BeastSnapshot`] the host already received
//! from the push callback — never a fabricated metric.

use std::path::Path;

use super::BeastSnapshot;

/// The Beast log event class — the review-channel token (like Warden's `ALLOW`/`DENY`): a periodic
/// THROUGHPUT `tick`, a YeAH MODE `shift`, an AQM `shed`, or a basin `over`flow. The host classifies the
/// event it observes on the [`super::BeastMetricSink`] stream and passes the matching kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BeastLogKind {
    Tick,
    ModeShift,
    Shed,
    Overflow,
}

/// The per-pillar log filename — joined to the Beast's bound log dir by
/// [`super::Beast::query_beast_log_path`] (the `query-<pillar>.log` convention, #133).
pub const QUERY_BEAST_LOG_NAME: &str = "query-beast.log";

/// The short kind token for the log line's second field.
fn kind_token(kind: BeastLogKind) -> &'static str {
    match kind {
        BeastLogKind::Tick => "tick",
        BeastLogKind::ModeShift => "shift",
        BeastLogKind::Shed => "shed",
        BeastLogKind::Overflow => "over",
    }
}

/// Format ONE `query-beast.log` line for a live Beast event. PURE + deterministic (the `now_ms` clock is
/// INJECTED). Schema (single-space-separated key=value, greppable + timestamp-correlatable with the other
/// `query-*.log` feeds — a SUPERSET of the `log_tier` seed line `beast tick cwnd=1 aqm=44 relay=cloudflare`):
///
/// ```text
/// <ts_ms> <kind> mode=<MODE> cwnd=<n>/<max> rtt=<base>ms udp=<udp>ms pace=<r>/s
///         pipe=<depth> q=<crit>/<high>/<norm> valve=<max> shed=<shed> aqm=<aqm> sparse=<drr> relay=<relay>
/// ```
///
/// Every field is a member of the live [`BeastSnapshot`] (the host-received push snapshot), so the log line
/// reflects EXACTLY the state the dashboard renders. `relay` is the host-supplied resolver name, trimmed;
/// `-` if blank (never a torn field). No PII — counts + labels only, device-local + bounded (the T20 ring).
pub fn format_beast_line(
    now_ms: u64,
    kind: BeastLogKind,
    s: &BeastSnapshot,
    relay: &str,
) -> String {
    let relay = relay.trim();
    let relay = if relay.is_empty() { "-" } else { relay };
    format!(
        "{now_ms} {} mode={} cwnd={}/{} rtt={:.1}ms udp={:.1}ms pace={:.1}/s pipe={} q={}/{}/{} valve={:.4} shed={} aqm={} sparse={} relay={relay}",
        kind_token(kind),
        s.mode,
        s.cwnd,
        s.window_max,
        s.base_rtt_ms,
        s.udp_base_rtt_ms,
        s.pacing_rate,
        s.pipeline_depth,
        s.queue_critical,
        s.queue_high,
        s.queue_normal,
        s.valve_prob,
        s.shed_dropped,
        s.aqm_dropped,
        s.drr_sparse_served,
    )
}

/// Append ONE Beast event line to `path` (the Beast's `query-beast.log`) through the shared
/// [`crate::log_tier`] substrate (#133). FAIL-OPEN inside `log_append` (a no-op on any IO error). The path is
/// the Beast's bound log dir + [`QUERY_BEAST_LOG_NAME`]; an UNBOUND Beast never calls this (no dir → no path
/// → no log). `create_dir_all` first (the app-private dir always exists in production, but the bind does no
/// IO — the same fail-open belt the Warden's log wears).
pub fn append_beast_event(
    path: &Path,
    now_ms: u64,
    kind: BeastLogKind,
    s: &BeastSnapshot,
    relay: &str,
) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    crate::log_tier::log_append(
        &path.to_string_lossy(),
        &format_beast_line(now_ms, kind, s, relay),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beast::{TortaProfile, YeahMode, YeahProfile};

    /// A representative live snapshot (every field) — the pure formatter's fixture. The formatter renders
    /// only the salient subset; the added typed/per-tin/profile fields keep the fixture a complete
    /// `BeastSnapshot` (so this construction site compiles against the widened Record — Chroma F10).
    fn sample_snapshot() -> BeastSnapshot {
        BeastSnapshot {
            cwnd: 12,
            window_max: 16,
            mode: "YEAH".to_string(),
            mode_kind: YeahMode::Yeah,
            slow_start_active: false,
            base_rtt_ms: 30.4,
            rtt_base_floor_ms: 28.0,
            q_packets: 0.0,
            reno_count: 0,
            fast_mode: false,
            adaptive_timeout_ms: 576,
            pacing_rate: 394.7,
            yeah_profile: YeahProfile::Canonical,
            udp_base_rtt_ms: 22.1,
            // Deliberately DIFFERENT from `mode_kind` above: the UDP organism runs its own state
            // machine, so a fixture echoing the TCP phase could not catch a formatter that renders
            // the wrong lane.
            udp_mode_kind: YeahMode::Competing,
            // #3-EXT (twin-RTT cure) — the TCP display lane rides the fixture too: a dial-fed EWMA
            // distinct from base_rtt_ms, so the formatter provably ignores what it does not render.
            tcp_base_rtt_ms: 26.8,
            tcp_floor_ms: 25.0,
            // ★ #52 — the shaped plane rides the fixture with its OWN distinct values (steady-state
            // RTT is deliberately unlike both base_rtt_ms and the dial lane above), so the formatter
            // provably ignores what it does not render.
            shaped_rtt_ms: 51.3,
            shaped_cwnd_last: 7,
            shaped_cwnd_mean: 5.5,
            shaped_samples: 4,
            shaped_losses: 1,
            q_smooth: 0.0,
            udp_floor_ms: 0.0,
            zeta_streak: 0,
            shed_streak: 0,
            doing_reno_now: 0,
            fair_cwnd: 0,
            pipeline_depth: 5,
            queue_critical: 1,
            queue_high: 2,
            queue_normal: 2,
            valve_prob: 0.0025,
            valve_critical: 0.0,
            valve_high: 0.0025,
            valve_normal: 0.001,
            valve_streak: 0,
            soft_memory: 0,
            shed_dropped: 3,
            aqm_dropped: 3,
            drr_sparse_served: 7,
            overload_sheds: 0,
            outage_absorbed: 0,
            sched_profile: TortaProfile::Baseline,
        }
    }

    #[test]
    fn format_beast_line_is_deterministic() {
        // A live YEAH tick: the injected clock, the kind token, and every snapshot field byte-exact.
        let line = format_beast_line(
            1_751_300_000_123,
            BeastLogKind::Tick,
            &sample_snapshot(),
            "cloudflare",
        );
        assert_eq!(
            line,
            "1751300000123 tick mode=YEAH cwnd=12/16 rtt=30.4ms udp=22.1ms pace=394.7/s \
             pipe=5 q=1/2/2 valve=0.0025 shed=3 aqm=3 sparse=7 relay=cloudflare"
        );
    }

    #[test]
    fn kind_tokens_are_distinct_and_greppable() {
        let s = sample_snapshot();
        assert!(format_beast_line(1, BeastLogKind::Tick, &s, "r").starts_with("1 tick "));
        assert!(format_beast_line(2, BeastLogKind::ModeShift, &s, "r").starts_with("2 shift "));
        assert!(format_beast_line(3, BeastLogKind::Shed, &s, "r").starts_with("3 shed "));
        assert!(format_beast_line(4, BeastLogKind::Overflow, &s, "r").starts_with("4 over "));
    }

    #[test]
    fn blank_relay_renders_dash() {
        // A degenerate relay (whitespace) collapses to `-` — never a torn/blank trailing field.
        let line = format_beast_line(5, BeastLogKind::ModeShift, &sample_snapshot(), "   ");
        assert!(
            line.starts_with("5 shift mode=YEAH"),
            "kind + snapshot: {line}"
        );
        assert!(
            line.ends_with("relay=-"),
            "blank relay collapses to a dash: {line}"
        );
    }

    #[test]
    fn round_trips_through_log_tier() {
        // The #133 substrate: append event lines, read them back through the SAME log_tier tailer (the
        // shared write→read path proving the per-pillar log is wired to the substrate, not a bespoke file).
        let mut p = std::env::temp_dir();
        p.push(format!(
            "torta-beast-log-roundtrip-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);

        append_beast_event(
            &p,
            100,
            BeastLogKind::Tick,
            &sample_snapshot(),
            "cloudflare",
        );
        append_beast_event(&p, 101, BeastLogKind::Shed, &sample_snapshot(), "quad9");

        let got = crate::log_tier::log_tail_recent(&p.to_string_lossy(), 10);
        assert!(
            got.contains("100 tick mode=YEAH"),
            "the tick line round-trips: {got}"
        );
        assert!(
            got.contains("101 shed mode=YEAH"),
            "the shed line round-trips: {got}"
        );
        assert!(got.contains("relay=quad9"), "the host relay carried: {got}");
        let _ = std::fs::remove_file(&p);
    }
}
