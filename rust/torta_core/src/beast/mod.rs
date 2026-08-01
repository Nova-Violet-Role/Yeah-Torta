/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! THE BEAST — the pure-Rust Tortä scheduler + Tortä RTT Fqodel + YeAH TCP/UDP congestion engine (the Socio's flagship IP).
//!
//! This is the FULL-POWER Beast: the entire Tortä/YeAH TCP/UDP hot math lives in Rust, exposed to Kotlin
//! through a stateful [`Beast`] Object + a [`BeastMetricSink`] callback interface. Kotlin holds a handle,
//! feeds RTT samples + probe enqueues, and receives live metrics via the callback (NO polling, NO Kotlin
//! in the hot path). This closes the milestone gap (69 flat fns, ZERO Objects/Records/callbacks): the
//! Beast is the FIRST `#[derive(uniffi::Object)]` + the FIRST callback in the crate.
//!
//! FAITHFUL PORT — the Kotlin originals are the SPEC:
//! - `YeahController.kt:35-328` -> [`yeah::YeahController`] (LEGACY + CANONICAL brains).
//! - `CakeScheduler.kt:1-563` -> [`scheduler::TortaScheduler`] (Tortä AQM + DRR++ + SFQ stride + set-assoc).
//!
//! Hard constraints honored: `#![forbid(unsafe_code)]` (module-inner), ring-only (no new deps — the
//! whole engine is pure arithmetic + `std::collections`), allocation-light hot path, faithful to the
//! Socio's algorithms (each port cites the Kotlin file:line).

#![forbid(unsafe_code)]

pub mod scheduler;
pub mod yeah;

/// `query-beast.log` — the Beast's per-pillar, human-legible EVENT feed written through the shared RAM⊗NAND
/// [`crate::log_tier`] substrate (#133, the `query-warden.log` / `query-fortress.log` precedent). Emitted
/// ONLY from the explicit review-channel seam ([`Beast::log_event`]) — never the hot dispatch/apply path.
pub mod log;

#[cfg(test)]
mod beastsim;
#[cfg(test)]
#[cfg(test)]
mod linksim;
#[cfg(test)]
mod spec_binding;
mod tests;

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use scheduler::TortaScheduler;
use yeah::YeahController;

// ---- Enums + Records (the full-power UniFFI type surface) ----

/// YeAH brain selector (YeahProfile.kt:24).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum YeahProfile {
    Legacy = 0,
    Canonical = 1,
    LineRate = 2,
}

/// Tortä AQM mechanism selector (CakeProfile.kt:21).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TortaProfile {
    Legacy = 0,
    Baseline = 1,
    /// Rung B — Soft-cake AQM + Mochi-Dango valve (SAIMONOKUMA 2026): the surpassing law over the
    /// original COBALT/BLUE (sch_cake.c) and the Kotlin-pinned Baseline rail. Rust-only until the
    /// Android window reopens (adds to the parked UniFFI `.kt` regen drift).
    SoftCake = 2,
}

/// YeAH congestion-control phases (YeahMode.kt:13-18). `label` preserves the original display string
/// for the Beast Tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum YeahMode {
    SlowStart,
    Yeah,
    Competing,
    Recovery,
}

impl YeahMode {
    /// The original wire/display label (YeahMode.kt:14-17): "SLOW-START", "YEAH", "COMPETING", "RECOVERY".
    pub fn label(self) -> &'static str {
        match self {
            YeahMode::SlowStart => "SLOW-START",
            YeahMode::Yeah => "YEAH",
            YeahMode::Competing => "COMPETING",
            YeahMode::Recovery => "RECOVERY",
        }
    }
}

/// Tortä tins, highest first (DnsProbeRequest.kt:25). `ordinal` is the tin index (0=Critical .. 2=Normal).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProbePriority {
    Critical = 0,
    High = 1,
    Normal = 2,
}

/// Probe transport (DnsProbeRequest.kt:28).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProbeProtocol {
    Tcp,
    Udp,
}

/// One DNS probe queued in a Tortä tin (DnsProbeRequest.kt:17-23). `endpoint_idx` + `domain` key the
/// 8-way set-associative flow buckets; `enqueued_at_ms` is the CoDel sojourn timestamp.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ProbeRequest {
    pub domain: String,
    pub priority: ProbePriority,
    pub endpoint_idx: i32,
    pub protocol: ProbeProtocol,
    pub enqueued_at_ms: i64,
}

impl ProbeRequest {
    /// Construct with defaults matching the Kotlin data-class defaults (endpoint 0, TCP, enqueued 0).
    pub fn new(domain: String, priority: ProbePriority) -> Self {
        Self {
            domain,
            priority,
            endpoint_idx: 0,
            protocol: ProbeProtocol::Tcp,
            enqueued_at_ms: 0,
        }
    }
}

/// One live Beast snapshot — the COMPLETE metric surface the Beast Tab renders. It reaches Kotlin two ways,
/// BOTH derived from the ONE [`Beast::snapshot_of`] reader so the paths can NEVER drift: PUSHED via
/// [`BeastMetricSink::on_metrics`] (the callback, no polling) OR PULLED via [`Beast::snapshot`] (the
/// poll-free full-metric read the dashboard polls with no attached sink).
///
/// Full-power typed surface (every field a real engine read, never a fabricated metric): the YeAH window
/// brain (cwnd/mode + the typed [`YeahMode`] + the canonical backlog/reno/fast/floor + the first-ever
/// UDP-YeAH base-RTT + the live [`YeahProfile`]) and the Tortä AQM queue state (per-tin depth + the
/// aggregate AND per-tin adaptive valve + the CoDel/AQM sheds + the DRR++ fairness witness + the live
/// [`TortaProfile`]).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct BeastSnapshot {
    // ---- YeAH window brain ----
    pub cwnd: i32,
    pub window_max: i32,
    /// The YeAH phase display label ("SLOW-START"/"YEAH"/"COMPETING"/"RECOVERY", [`YeahMode::label`]).
    pub mode: String,
    /// The SAME phase as a typed enum (the full-power surface — a typed [`YeahMode`], not only the flat
    /// label). Carried ALONGSIDE `mode` so the dashboard keeps its display string while the host reads a type.
    pub mode_kind: YeahMode,
    pub slow_start_active: bool,
    pub base_rtt_ms: f64,
    /// The CANONICAL true-min RTT floor ([`yeah::YeahController::rtt_base_floor`]) — the variable the canonical
    /// brain actually decides on (distinct from the EWMA `base_rtt_ms`, which never drives canonical decisions).
    /// 0 under the Legacy brain (which never seeds it).
    pub rtt_base_floor_ms: f64,
    pub q_packets: f64,
    pub reno_count: i32,
    pub fast_mode: bool,
    pub adaptive_timeout_ms: i32,
    pub pacing_rate: f64,
    /// Which YeAH brain is live ([`yeah::YeahController::profile`]) — the dashboard gates the canonical
    /// telemetry (backlog/reno/fast) on this so a Legacy brain's inert 0s never read as live metrics.
    pub yeah_profile: YeahProfile,
    // ---- UDP (the first-ever UDP YeAH; the engine tracks UDP base_rtt separately) ----
    pub udp_base_rtt_ms: f64,
    /// The UDP organism's phase, typed ([`yeah::YeahController::udp_mode`]) — the twin of
    /// `mode_kind`, which reports the TCP side only.
    ///
    /// WIRED 2026-07-31 to close an A1 dead-code item BY WIRING rather than by deletion.
    /// `udp_mode()` was live in tests (`beast/tests.rs:1695`) and dead in every release build, which
    /// is the honest signature of an accessor that was written for a display lane nobody ever
    /// connected. Under LineRate the UDP family runs its OWN state machine with its own true-min
    /// floor (no cross-family floor poisoning), so a dashboard showing only `mode_kind` reports the
    /// TCP organism's phase while the UDP organism may be in a completely different one — the exact
    /// blind spot that made "the Beast looks frozen" hard to attribute.
    pub udp_mode_kind: YeahMode,
    // ---- TCP display lane (#3-EXT — the netstack forwarder's REAL dial RTTs) ----
    /// TCP-family base RTT EWMA — the `udp_base_rtt_ms` twin, fed by the forwarder's TCP dial
    /// elapsed (SYN→established = the TCP network RTT, the exact twin of the DNS query RTT).
    /// 0 until the netstack forwarder dials its first TCP flow — the two families can NEVER
    /// render identical values off one shared estimator again (the twin-RTT bug's cure).
    pub tcp_base_rtt_ms: f64,
    /// TCP-family true-min RTT floor (display lane, the FLOOR_LEAK leaky-bucket law) — the
    /// `udp_floor_ms` twin, from the same dial samples. 0 until the forwarder dials.
    pub tcp_floor_ms: f64,
    // ---- ★ #52 SHAPED PLANE (the per-flow FlowShaper return leg) ----
    /// EWMA of REAL steady-state flow RTT — every sample is a completed transaction or write-drain
    /// on a live forwarded flow, NOT a handshake. 0 until the forwarder shapes its first flow.
    /// This is the RTT the congestion engine is actually reacting to, which `tcp_base_rtt_ms`
    /// (dial-only) can never show.
    pub shaped_rtt_ms: f64,
    /// The window of the most recent shaped sample (segments).
    pub shaped_cwnd_last: i32,
    /// Arithmetic mean window across every shaped sample this session. Near 1 ⇒ the real plane is
    /// pinned in slow-start or collapsing; climbing ⇒ it is cruising. 0 when nothing has been shaped.
    pub shaped_cwnd_mean: f64,
    /// Count of shaped samples — the HONESTY GATE. `shaped_rtt_ms`/`shaped_cwnd_mean` are only
    /// meaningful when this is non-zero, so the panel can distinguish "no flow shaped yet" from
    /// "shaped, and the answer is genuinely zero" (the #98 law: name which cause you assert).
    pub shaped_samples: i64,
    /// YeAH loss reactions on REAL flows — the congestion REACTION count, not the I/O stall count.
    pub shaped_losses: i64,
    // ---- YeAH TCP/UDP LineRate telemetry (Rung C) — all four stay 0/0.0 under Legacy/Canonical ----
    /// Multi-sample queue memory (`q_smooth` EWMA, [`yeah::LR_Q_EWMA_ALPHA`]) — the LineRate loss
    /// rule's actual input ([`yeah::YeahController::q_smooth`]).
    pub q_smooth: f64,
    /// UDP-family true-min RTT floor ([`yeah::YeahController::udp_floor`]) — under LineRate each
    /// family judges delay against its OWN floor (`rtt_base_floor_ms` doubles as the TCP floor).
    pub udp_floor_ms: f64,
    /// ZETA hysteresis streak — consecutive FAST samples toward [`yeah::LR_ZETA`]; the competition
    /// memory (`reno_count`) survives until it fills ([`yeah::YeahController::fast_streak`]).
    pub zeta_streak: i32,
    /// Shed-confirmation streak — consecutive over-threshold samples toward
    /// [`yeah::LR_SHED_CONFIRM`]; one spike holds the window ([`yeah::YeahController::congest_streak`]).
    pub shed_streak: i32,
    /// ★ #22 slice 3 — consecutive congested samples (the kernel `doing_reno_now`, tcp_yeah.c:35);
    /// 0 the instant any non-congested sample lands ([`yeah::YeahController::doing_reno_now`]).
    /// Distinct from `reno_count` (the competition MEMORY that survives): this is the LIVE streak.
    pub doing_reno_now: i32,
    /// Rung C+ fair-share estimate (`fair_cwnd`, tcp_yeah.c:37) — the window this flow can defend
    /// while competing ([`yeah::YeahController::fair_cwnd`]); 0 = unlearned. Read beside `cwnd` it
    /// shows whether the flow is holding its fair share or being squeezed.
    pub fair_cwnd: i32,
    // ---- Tortä AQM ----
    pub pipeline_depth: i32,
    pub queue_critical: i32,
    pub queue_high: i32,
    pub queue_normal: i32,
    /// Valve drop-probability of the BUSIEST tin (max across tins, [`scheduler::TortaScheduler::valve_prob`]);
    /// `[0, VALVE_CAP]`.
    pub valve_prob: f64,
    /// Per-tin adaptive-valve state (the advanced-depth surface, [`scheduler::TortaScheduler::valve_prob_tin`]) —
    /// Critical/High/Normal, each `[0, VALVE_CAP]`; all 0 under the Legacy AQM (no adaptive valve runs).
    pub valve_critical: f64,
    pub valve_high: f64,
    pub valve_normal: f64,
    // ---- Soft-cake / Mochi-Dango telemetry (Rung B) — both stay 0 under Legacy/Baseline ----
    /// Mochi-Dango escalation streak of the hottest tin ([`scheduler::TortaScheduler::valve_streak`]) —
    /// `[0, MOCHI_STREAK_CAP]`; sustained failure scales the valve step up to streak×.
    pub valve_streak: i32,
    /// Soft-cake count memory of the hottest tin ([`scheduler::TortaScheduler::soft_memory`]) — the
    /// CoDel drop-rate remembered at the last dropping-exit, resumed on re-entry inside the window.
    pub soft_memory: i32,
    pub shed_dropped: i32,
    pub aqm_dropped: i32,
    pub drr_sparse_served: i32,
    /// ★ #22 slice 3 · Rung E — heads shed by the GLOBAL-OVERLOAD law
    /// ([`scheduler::TortaScheduler::overload_sheds`], the 5th sch_cake gap: cake_drop parity +
    /// stalest-head tie-break). 0 under Legacy/Baseline and in normal SoftCake operation — a
    /// non-zero here means the AQM capacity ceiling actually fired (the honest-zero tile).
    pub overload_sheds: i32,
    /// ★ #22 slice 3 · Rung E — heads absorbed by the outage law
    /// ([`scheduler::TortaScheduler::outage_absorbed`]). The twin of `overload_sheds`: that one counts
    /// what capacity REFUSED, this counts what an outage SWALLOWED. Honest zero in normal operation —
    /// a non-zero means the path actually went away under us.
    pub outage_absorbed: i32,
    /// Which Tortä AQM brain is live ([`scheduler::TortaScheduler::profile`]) — the dashboard gates the
    /// valve/shed cards on this (the Legacy AQM keeps valve/shed at 0 by design).
    pub sched_profile: TortaProfile,
}

/// Callback interface: Rust STREAMS live Beast metrics to Kotlin (push, not poll). Kotlin implements
/// this and attaches an instance via [`Beast::attach_sink`]; Rust calls `on_metrics` once per cycle.
///
/// `with_foreign` lets the foreign (Kotlin) side provide the implementation — this is the
/// `callback_interface` that closes the milestone's "zero callbacks" gap.
#[uniffi::export(with_foreign)]
pub trait BeastMetricSink: Send + Sync {
    fn on_metrics(&self, snapshot: BeastSnapshot);
}

/// The Beast's ONE guarded world (D22 — the five sibling `Mutex`es collapsed into a single
/// `Mutex<BeastInner>`): fewer lock acquisitions per sample (one, was up to four) AND an ATOMIC
/// snapshot — the old `udp`→`yeah`→`sched` cross-lock read could observe a torn state between the
/// three acquisitions; one guard now reads one coherent world. The guarded state is plain,
/// always-valid arithmetic data, so lock-poison RECOVERY (`unwrap_or_else(|e| e.into_inner())`,
/// the crate-wide idiom — resolver ×23, blocklist ×19, pool, dnscrypt, mirror) is strictly safe:
/// a panicked writer can never leave a torn invariant here, and recovery self-heals instead of
/// poison-bricking every subsequent Beast call into a permanent FFI exception storm.
struct BeastInner {
    yeah: YeahController,
    sched: TortaScheduler,
    sink: Option<Arc<dyn BeastMetricSink>>,
    /// UDP RTT tracked separately (the first-ever UDP YeAH: cwnd is shared, base_rtt is per-protocol).
    udp_base_rtt: f64,
    /// #3-EXT — TCP dial-RTT display pair (base EWMA + true-min floor): the `udp_base_rtt` twin, fed
    /// by the netstack forwarder's real handshake RTTs. Display lane ONLY — never drives the window
    /// brain or the shared adaptive-timeout EWMA (per-flow dial samples must not steer DNS pacing).
    tcp_base_rtt: f64,
    tcp_floor: f64,
    /// ★ #52 — THE SHAPED PLANE (the per-flow `FlowShaper` return leg).
    ///
    /// The dial pair above carries SYN→established handshake RTT only. These carry the STEADY-STATE
    /// truth: every `FlowShaper::sample` is a real transaction/write-drain RTT measured on a live
    /// forwarded flow, and `cwnd` is the window that flow's OWN YeAH brain converged on. Until #52
    /// the entire shaping plane was invisible to the pillar that owns the algorithm — the Beast
    /// displayed handshake latency forever and never RTT under load.
    ///
    /// DISPLAY LANE ONLY, exactly like the dial pair: a forwarded flow's RTT must never steer the
    /// DNS-probe window (that is what the per-family floors exist to prevent). Each flow already has
    /// its own controller; this is the aggregate the dashboard reads, never a control input.
    shaped_rtt: f64,
    /// Window of the most recent shaped sample — "where the real plane is right now".
    shaped_cwnd_last: i32,
    /// Running sum + count of observed windows ⇒ mean. A mean near MIN_WINDOW=1 means the real plane
    /// is pinned in slow-start/collapse; a mean climbing toward the ceiling means it is cruising.
    /// Kept as sum+count (not an EWMA) so the mean is arithmetic and cannot be argued with.
    shaped_cwnd_sum: i64,
    shaped_cwnd_n: i64,
    /// YeAH loss reactions fired on REAL flows (`FlowShaper::on_stall`). Distinct from
    /// `ForwarderStats::stalls`, which counts the I/O event; this counts the CONGESTION REACTION.
    shaped_losses: i64,
    /// The app-private durable dir for query-beast.log (slice: the per-pillar log seam, #133). `None` until
    /// Kotlin calls `bind_log_dir(filesDir)`; while `None` the review-channel seam is a silent no-op.
    log_dir: Option<std::path::PathBuf>,
}

/// THE BEAST — the stateful Rust congestion/AQM engine. Kotlin constructs it once, holds the `Arc`
/// handle, feeds samples + probes, drives the AQM tick, and receives metrics via the attached sink.
#[derive(uniffi::Object)]
pub struct Beast {
    inner: Mutex<BeastInner>,
}

/// #16 THE BEAST — the PROCESS-GLOBAL live congestion engine the running DNS datapath feeds (one per
/// process, lazily built). The resolver pushes ONE measured RTT per live-forwarded resolve into it
/// ([`feed_live_rtt`], laid at the `LAST_WINNER_FAMILY` seam the design reserved for exactly this), and
/// the ENGINE dashboard reads its [`snapshot`](Beast::snapshot) across the `.so` bridge
/// (`beast_live_snapshot` -> `TortaPillarBridge.liveBeastStats`). Built with the SURPASSING brains
/// (LineRate YeAH + SoftCake AQM) so a UDP-family DNSCrypt RTT is a FIRST-CLASS congestion input that
/// actually drives the window (under Legacy/Canonical `apply_udp` is a cwnd no-op — only LineRate makes
/// the DNS RTT stream move cwnd/slow-start/the UDP floor). This is a SEPARATE brain from the per-session
/// forwarder `YeahController` (`forwarder::shape`): that one shapes full-device netstack flows; this one
/// learns from the always-present DNS resolve stream, so the dashboard populates from ordinary DNS
/// traffic without requiring the emulator-hostile full-device capture.
static LIVE_BEAST: std::sync::OnceLock<Arc<Beast>> = std::sync::OnceLock::new();

/// The process-global live Beast (lazily built with the LineRate + SoftCake brains). The one the DNS
/// datapath feeds and the dashboard snapshots — see [`LIVE_BEAST`]. On first build it ALSO spawns the
/// Soft-cake AQM dispatch pump ([`spawn_aqm_pump`]) so the tins the datapath fills actually drain at the
/// governed cwnd (and their session high-water is retained — the CLEAR CONDITION 4 layer below).
pub fn live_beast() -> &'static Arc<Beast> {
    LIVE_BEAST.get_or_init(|| {
        let beast = Beast::new(YeahProfile::LineRate, TortaProfile::SoftCake);
        spawn_aqm_pump(Arc::clone(&beast));
        beast
    })
}

// ---- #49 THE BEAST SETTINGS · the LIVE per-flow tune broadcast -------------------------------------
// [`LIVE_BEAST`] is the probe-plane / telemetry congestion controller; the REAL bulk datapath runs a
// SEPARATE [`crate::forwarder::shape::FlowShaper`] with its OWN YeAH window PER FLOW, born LineRate. For
// the user's SETTINGS pick to govern the real shaping (not merely the dashboard Beast), the module-level
// `beast_set_*` edges ALSO broadcast the chosen brain + Expert tunables here, and [`FlowShaper::new`] reads
// them so every NEW flow is born on the user's profile with the user's window/threshold overrides. Fail-
// open + guarded: the defaults are byte-identical to the old hard-wired LineRate (profile 2, tunables 0 =
// don't-clobber), so an untouched install shapes exactly as before. Existing flows keep their controller (a
// congestion window is per-connection; DNS flows are short-lived, so a new tune lands within a query or
// two). ONLY the settings-apply / restore path writes these — the BeastTuneBrain thermometer + the tests
// never do (they build their own throwaway Beasts, which must not corrupt the live per-flow tune).
static TUNE_YEAH_PROFILE: AtomicI32 = AtomicI32::new(2); // 2 = LineRate (the born default)
static TUNE_MAX_WINDOW: AtomicI32 = AtomicI32::new(0); // 0 = leave the profile default (don't-clobber)
static TUNE_FREE_MILLI: AtomicI32 = AtomicI32::new(0);
static TUNE_COMPETE_MILLI: AtomicI32 = AtomicI32::new(0);

/// Broadcast the user's chosen YeAH brain to every FUTURE [`crate::forwarder::shape::FlowShaper`]. Called
/// by [`crate::beast_set_yeah_profile`] on the settings-apply / restore path (NEVER the thermometer).
pub(crate) fn store_live_yeah_profile(id: i32) {
    TUNE_YEAH_PROFILE.store(id, Ordering::Relaxed);
}

/// Broadcast the user's live Expert tunables (each 0 = leave the profile default). Called by
/// [`crate::beast_set_tunables`] on the settings-apply / restore path.
pub(crate) fn store_live_tunables(
    max_window: i32,
    free_thresh_milli: i32,
    compete_thresh_milli: i32,
) {
    TUNE_MAX_WINDOW.store(max_window, Ordering::Relaxed);
    TUNE_FREE_MILLI.store(free_thresh_milli, Ordering::Relaxed);
    TUNE_COMPETE_MILLI.store(compete_thresh_milli, Ordering::Relaxed);
}

/// The user's chosen YeAH brain for a NEW flow — defaults to LineRate (the born state) on any unknown
/// ordinal. Read by [`crate::forwarder::shape::FlowShaper::new`] (the sole consumer lives behind the
/// `netstack` forwarder, so this reader is gated with it — the `store_*` writers stay ungated because the
/// base uniffi `beast_set_*` exports always call them).
#[cfg(feature = "netstack")]
pub(crate) fn live_yeah_profile() -> YeahProfile {
    match TUNE_YEAH_PROFILE.load(Ordering::Relaxed) {
        0 => YeahProfile::Legacy,
        1 => YeahProfile::Canonical,
        _ => YeahProfile::LineRate,
    }
}

/// Apply the user's live Expert tunables onto a freshly-built flow controller (each 0 = no override — the
/// [`YeahController::set_tunables`] don't-clobber law). Read by [`FlowShaper::new`] right after
/// `with_profile`, so the window ceiling + free/compete thresholds the user pinned in SETTINGS ride the
/// real bulk datapath, not just the telemetry Beast. `netstack`-gated with its sole consumer.
#[cfg(feature = "netstack")]
pub(crate) fn apply_live_tune(yeah: &mut YeahController) {
    yeah.set_tunables(
        TUNE_MAX_WINDOW.load(Ordering::Relaxed),
        TUNE_FREE_MILLI.load(Ordering::Relaxed),
        TUNE_COMPETE_MILLI.load(Ordering::Relaxed),
    );
}

/// The Soft-cake AQM dispatch-pump cadence. The three DiffServ tins accumulate real classified arrivals
/// ([`feed_live_aqm`]) and this pump drains each tin at the governed cwnd every `AQM_PUMP_MS` — the
/// Android edition of the nautilus governor's continuous dispatch pump (beast_gov.rs). Fast enough that a
/// page-load burst shows real backlog depth then drains (sojourn stays realistic — tens of ms under load,
/// not the seconds a slow drain would fabricate), ~0 when idle. The DASHBOARD polls the tins far slower
/// (~500 ms), so this pump is ALSO the only observer quick enough to catch the instantaneous DRR++ depth a
/// real burst raises — it retains that high-water into [`LIVE_RETENTION`] before draining.
const AQM_PUMP_MS: u64 = 100;

/// Process-monotonic milliseconds — the SAME clock stamps a probe's `enqueued_at_ms` ([`feed_live_aqm`])
/// and the dispatch `now_ms` (the AQM pump), so the scheduler's CoDel sojourn is a true elapsed wait.
/// Wall-clock is deliberately avoided (a clock step would corrupt the sojourn). Mirrors nautilus
/// `beast_gov::now_ms`.
fn now_ms_monotonic() -> i64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as i64
}

/// Session high-water / lifetime RETENTION for the live Beast's Soft-cake AQM — the Android edition of
/// the nautilus governor's `AqmRetention` (its "CLEAR CONDITION 4" layer). WHY it exists (root cause,
/// not a broken wire): the tins' `queue_*` depths are INSTANTANEOUS DRR++ occupancy — the 100 ms
/// [`spawn_aqm_pump`] drains each tin almost as fast as a real burst fills it, so the ~500 ms dashboard
/// poll catches the depth at 0 essentially always, even while the datapath is genuinely classifying and
/// routing traffic. WHAT it does (honest — it RETAINS, never fabricates): a lifetime per-tin throughput
/// tally (every real classified query counted) + a session-peak of each tin's depth and each transient
/// YeAH streak (the max ever reached this run, via `fetch_max`). No synthetic load — real transient
/// activity just leaves a visible mark, so the pane shows "now / peak / N served" and a page-load flight
/// of A/AAAA queries PROVES the tin filled instead of vanishing between two polls.
struct AqmRetention {
    /// Lifetime count of real classified queries per tin, indexed [Critical, High, Normal].
    thru: [AtomicU64; 3],
    /// Session-peak instantaneous tin depth per tin, indexed [Critical, High, Normal].
    peak_depth: [AtomicU64; 3],
    /// Session-peak YeAH ZETA (FAST) streak.
    peak_zeta: AtomicU64,
    /// Session-peak YeAH shed-confirmation streak.
    peak_shed: AtomicU64,
    /// Session-peak YeAH proven-contention (reno) count — resets on a zeta-fill, so the peak is the only
    /// durable witness that contention was ever reached.
    peak_reno: AtomicU64,
}

impl AqmRetention {
    const fn new() -> Self {
        Self {
            thru: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            peak_depth: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            peak_zeta: AtomicU64::new(0),
            peak_shed: AtomicU64::new(0),
            peak_reno: AtomicU64::new(0),
        }
    }

    /// Tin index for a priority — Critical=0, High=1, Normal=2 (the SAME top-to-bottom order the Beast
    /// pane's three tin rows render, so the getters map straight to the display).
    fn idx(priority: ProbePriority) -> usize {
        match priority {
            ProbePriority::Critical => 0,
            ProbePriority::High => 1,
            ProbePriority::Normal => 2,
        }
    }

    /// Count one real classified query into its tin's lifetime throughput.
    fn record(&self, priority: ProbePriority) {
        self.thru[Self::idx(priority)].fetch_add(1, Ordering::Relaxed);
    }

    /// Retain the session high-water of each tin's instantaneous depth (called each pump tick BEFORE the
    /// drain). `fetch_max` keeps the peak without clobbering it; a 0/negative sample is ignored (a quiet
    /// tick never lowers a peak).
    fn sample_depth(&self, critical: i32, high: i32, normal: i32) {
        for (slot, v) in self.peak_depth.iter().zip([critical, high, normal]) {
            if v > 0 {
                slot.fetch_max(v as u64, Ordering::Relaxed);
            }
        }
    }

    /// Retain the session high-water of each transient YeAH metric (zeta streak · shed streak · reno
    /// count) — same `fetch_max`, same ignore-non-positive discipline.
    fn sample_yeah(&self, zeta: i32, shed: i32, reno: i32) {
        if zeta > 0 {
            self.peak_zeta.fetch_max(zeta as u64, Ordering::Relaxed);
        }
        if shed > 0 {
            self.peak_shed.fetch_max(shed as u64, Ordering::Relaxed);
        }
        if reno > 0 {
            self.peak_reno.fetch_max(reno as u64, Ordering::Relaxed);
        }
    }

    /// Lifetime per-tin throughput [Critical, High, Normal].
    fn throughput(&self) -> [u64; 3] {
        [
            self.thru[0].load(Ordering::Relaxed),
            self.thru[1].load(Ordering::Relaxed),
            self.thru[2].load(Ordering::Relaxed),
        ]
    }

    /// Session-peak per-tin depth [Critical, High, Normal].
    fn peak_depth(&self) -> [u64; 3] {
        [
            self.peak_depth[0].load(Ordering::Relaxed),
            self.peak_depth[1].load(Ordering::Relaxed),
            self.peak_depth[2].load(Ordering::Relaxed),
        ]
    }

    /// Session-peak YeAH triple (zeta streak, shed streak, reno count).
    fn peak_yeah(&self) -> (u64, u64, u64) {
        (
            self.peak_zeta.load(Ordering::Relaxed),
            self.peak_shed.load(Ordering::Relaxed),
            self.peak_reno.load(Ordering::Relaxed),
        )
    }
}

/// The process-global retention for [`LIVE_BEAST`]'s Soft-cake AQM — const-init (all atomics start 0),
/// so a probe/smoke process that never feeds the datapath reads honest zeros.
static LIVE_RETENTION: AqmRetention = AqmRetention::new();

/// The Soft-cake AQM dispatch pump for the live Beast — the Android edition of the nautilus governor's
/// AQM pump (`beast_gov.rs`). Spawned ONCE alongside [`LIVE_BEAST`]; every [`AQM_PUMP_MS`] it (1) samples
/// each tin's instantaneous depth + the transient YeAH streaks into [`LIVE_RETENTION`] (the session
/// high-water the dashboard reads), then (2) dispatches — draining up to cwnd probes at the monotonic
/// clock, advancing the CoDel/DRR++/valve state over the real query stream. The drained batch is
/// discarded (the query was already answered by the datapath; this only advances the AQM law). A
/// dispatch over empty tins is a no-op, so the pump self-idles when no traffic flows. Pure Rust — it
/// never touches JNI, so it is safe to run for the process life.
fn spawn_aqm_pump(beast: Arc<Beast>) {
    let spawned = std::thread::Builder::new()
        .name("torta-beast-aqm-pump".into())
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(AQM_PUMP_MS));
            let snap = beast.snapshot();
            LIVE_RETENTION.sample_depth(snap.queue_critical, snap.queue_high, snap.queue_normal);
            LIVE_RETENTION.sample_yeah(snap.zeta_streak, snap.shed_streak, snap.reno_count);
            let _ = beast.dispatch(now_ms_monotonic());
        });
    // A failed spawn is non-fatal: the tins simply will not drain (they cap at the scheduler's tin
    // limits) — the datapath + dashboard keep working, only the AQM movement rests.
    debug_assert!(spawned.is_ok(), "torta-beast-aqm-pump failed to spawn");
    let _ = spawned;
}

/// The Soft-cake DiffServ classifier — a served DNS query's qtype into its Tortä AQM tin, mirroring the
/// nautilus governor's classifier (`beast_gov::classify_priority`). Critical (floor-protected, never
/// shed — the interactive address lookups a browser blocks on): A/AAAA/HTTPS/SVCB. High (control/records
/// that matter but tolerate a little delay): NS/CNAME/SOA/PTR/MX/TXT/SRV. Normal (bulk/unknown, the first
/// to shed under CoDel pressure): everything else.
pub(crate) fn classify_priority(qtype: u16) -> ProbePriority {
    match qtype {
        1 | 28 | 65 | 64 => ProbePriority::Critical, // A, AAAA, HTTPS, SVCB
        2 | 5 | 6 | 12 | 15 | 16 | 33 => ProbePriority::High, // NS, CNAME, SOA, PTR, MX, TXT, SRV
        _ => ProbePriority::Normal,
    }
}

/// #16 THE BEAST (AQM datapath) — account ONE real served DNS query through the live Beast's Soft-cake
/// AQM so the dashboard's CAKE tins + CoBALT valves populate from the REAL query stream (not the
/// synthetic 5 s liveness probes the Kotlin `MonokumaDnsEngine` feeds its OWN Beast). Classify by qtype
/// into a DiffServ tin, enqueue a `ProbeRequest` (raising that tin's `queue_*` depth), tally the lifetime
/// retention, and move the tin's adaptive CoBALT valve on the real outcome (`on_success` decays it,
/// `on_timeout_or_fail` raises it + drives the Mochi-Dango escalation streak). The [`spawn_aqm_pump`]
/// pump drains the tins at the governed cwnd. Mirrors nautilus `beast_gov::record_aqm` beat-for-beat.
/// FAIL-OPEN + in-RAM alongside [`feed_live_rtt`]: it can never change — or panic — the answer it rides.
pub fn feed_live_aqm(qtype: u16, domain: &str, is_udp: bool, ok: bool) {
    feed_aqm_into(live_beast(), &LIVE_RETENTION, qtype, domain, is_udp, ok);
}

/// The pure core of [`feed_live_aqm`], taking an explicit Beast + retention so the tin classification +
/// valve move are unit-testable without mutating the process-globals [`LIVE_BEAST`]/[`LIVE_RETENTION`].
fn feed_aqm_into(
    beast: &Beast,
    retain: &AqmRetention,
    qtype: u16,
    domain: &str,
    is_udp: bool,
    ok: bool,
) {
    let priority = classify_priority(qtype);
    retain.record(priority);
    beast.enqueue_probe(ProbeRequest {
        domain: domain.to_string(),
        priority,
        endpoint_idx: 0,
        protocol: if is_udp {
            ProbeProtocol::Udp
        } else {
            ProbeProtocol::Tcp
        },
        enqueued_at_ms: now_ms_monotonic(),
    });
    if ok {
        beast.on_success(priority);
    } else {
        beast.on_timeout_or_fail(priority);
    }
}

/// #16 THE BEAST — the live Soft-cake AQM retention witness the dashboard overlays onto the CAKE tin rows
/// so a query burst leaves a durable, honest mark (lifetime throughput + session-peak depth) despite the
/// 100 ms pump drain. Fixed 9-slot order the flat bridge wire maps positionally:
/// `[thru_c, thru_h, thru_n, peak_c, peak_h, peak_n, peak_zeta, peak_shed, peak_reno]`. `[0; 9]` before
/// any traffic. See [`AqmRetention`].
pub fn live_beast_aqm_retention() -> Vec<i64> {
    let thru = LIVE_RETENTION.throughput();
    let peak = LIVE_RETENTION.peak_depth();
    let (zeta, shed, reno) = LIVE_RETENTION.peak_yeah();
    vec![
        thru[0] as i64,
        thru[1] as i64,
        thru[2] as i64,
        peak[0] as i64,
        peak[1] as i64,
        peak[2] as i64,
        zeta as i64,
        shed as i64,
        reno as i64,
    ]
}

/// #16 — feed ONE live-forward DNS RTT sample (ms) into the process-global live Beast, routed by the
/// winner family the resolver just published (`resolver::last_winner_family`): 1 = UDP family
/// (DNSCrypt/Do53) -> the UDP-YeAH lane ([`Beast::apply_udp_samples`], a first-class congestion input
/// under LineRate); 2 = TCP/QUIC family (DoH/DoH3/ODoH) -> the shared window lane
/// ([`Beast::apply_samples`]). Any other family (0 = cache-hit/synth/block/miss) carries no network RTT
/// and is ignored. A non-finite or negative sample is dropped. FAIL-OPEN by construction: a poisoned
/// Beast lock self-heals inside `apply_*` (the D22 idiom), so a Beast sample can never change — or
/// panic — the resolve it rides alongside (the same law as the sibling `underground::feed`).
pub fn feed_live_rtt(family: i32, rtt_ms: f64) {
    feed_rtt_into(live_beast(), family, rtt_ms);
}

/// #3-EXT — feed the LIVE Beast's TCP display lane with ONE netstack-forwarder dial RTT (ms):
/// the SYN→established elapsed of a real outbound TCP flow, the TCP-family network RTT. Rides
/// [`Beast::fold_tcp_display_samples`] (display lane only — never the window brain), so the
/// dashboard's `base RTT (TCP)` + TCP floor light up from REAL per-flow handshakes while DNS
/// pacing stays untouched. The sample gate inside the fold drops non-finite/non-positive values.
pub fn feed_live_tcp_dial(rtt_ms: f64) {
    live_beast().fold_tcp_display_samples(vec![rtt_ms]);
}

/// ★ #52 — feed the LIVE Beast's SHAPED PLANE with ONE real-flow observation: the steady-state RTT
/// a [`crate::forwarder::shape::FlowShaper`] just measured and the window it converged on.
///
/// This is the RETURN LEG of the shaper↔engine bridge. The outbound leg already existed
/// ([`live_yeah_profile`] + [`apply_live_tune`] arm every new `FlowShaper` with the user's chosen
/// brain); until #52 nothing came back, so the Beast pillar could show the DNS-probe plane and the
/// forwarder's HANDSHAKE RTTs but never what its own algorithm was doing to real traffic under load.
///
/// Called at the two `FlowShaper::sample` sites (`forwarder::run` — the UDP transaction pair and the
/// TCP write-drain). Cost is one Beast lock per completed transaction, the same price the dial lane
/// already pays per flow — not per packet.
pub fn feed_live_flow_shape(rtt_ms: f64, cwnd: i32) {
    live_beast().fold_shaped_sample(rtt_ms, cwnd);
}

/// ★ #52 — record ONE YeAH loss reaction taken on a real forwarded flow. Called at the
/// `FlowShaper::on_stall` sites so the dashboard can show that the engine is REACTING to real
/// congestion, not merely that an I/O error occurred.
pub fn feed_live_flow_loss() {
    live_beast().fold_shaped_loss();
}

/// The pure routing core of [`feed_live_rtt`], taking an explicit Beast so the family fan-out is
/// unit-testable without mutating the process-global [`LIVE_BEAST`]. family: 1 = UDP lane
/// ([`Beast::apply_udp_samples`]), 2 = shared/TCP lane ([`Beast::apply_samples`]), anything else = no
/// network RTT, ignored. A non-finite or negative sample is dropped before it can poison an EWMA.
fn feed_rtt_into(beast: &Beast, family: i32, rtt_ms: f64) {
    if !(rtt_ms.is_finite() && rtt_ms >= 0.0) {
        return;
    }
    match family {
        1 => beast.apply_udp_samples(vec![rtt_ms]),
        2 => beast.apply_samples(vec![rtt_ms]),
        _ => {}
    }
}

/// ★ THE MISSING LEG — feed ONE real forwarded-flow RTT into the WINDOW BRAIN.
///
/// # Why this exists
///
/// Before this, the window brain (`apply_samples` / `apply_udp_samples`) had exactly ONE
/// reachable caller in the entire crate: [`feed_live_rtt`], from `resolver/mod.rs:1662`. The
/// netstack forwarder — which carries every browser TCP and UDP flow — reached only DISPLAY
/// lanes:
///
/// | sink | lands in | steers? |
/// |---|---|---|
/// | [`feed_live_tcp_dial`] | `fold_tcp_display_samples` | no — "display lane only" (`:638`) |
/// | [`feed_live_flow_shape`] | `fold_shaped_sample` | no — "it steers nothing" (`forwarder/run.rs:836`) |
/// | [`feed_live_flow_loss`] | `fold_shaped_loss` | no |
///
/// So on a device whose DNS is served by the EXTERNAL dnscrypt-proxy (`relay=dnscrypt-proxy`
/// in `query-beast.log`), `resolver/mod.rs` never runs, the brain never receives a sample, and
/// the window sits at `cwnd=1/16` for all 102 logged ticks — while `rtt=222.9ms udp=215.7ms`
/// reads LIVE in the same line, because the display lanes ARE fed. Every number in that log
/// line is explained by reach, not by the controller.
///
/// `beastsim::the_resolver_path_does_move_the_window` measured the controller itself as healthy:
/// `before=1 after_enqueue_only=1 after_samples=16` — it saturates to `MAX_WINDOW` in 64
/// acknowledged samples. Nothing was wrong with it. It was simply never spoken to.
///
/// # Faithfulness
///
/// The family fan-out and the sample guard are IDENTICAL to [`feed_rtt_into`] — deliberately, so
/// a forwarded flow and a resolver query enter the brain through the same door under the same
/// rules. `is_udp` maps to the family the resolver already uses: `1` = UDP lane, `2` = shared /
/// TCP lane. A non-finite or negative sample is dropped before it can poison an EWMA.
///
/// FAIL-OPEN, like every sibling `feed_live_*`: a poisoned Beast lock self-heals inside
/// `apply_*` (the D22 idiom), so this can never change — or panic — the flow it rides.
pub fn feed_live_flow_rtt(rtt_ms: f64, is_udp: bool) {
    feed_rtt_into(live_beast(), if is_udp { 1 } else { 2 }, rtt_ms);
}

#[uniffi::export]
impl Beast {
    /// Construct the Beast with a YeAH profile + a Tortä scheduler profile.
    #[uniffi::constructor]
    pub fn new(yeah_profile: YeahProfile, sched_profile: TortaProfile) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(BeastInner {
                yeah: YeahController::with_profile(yeah_profile),
                sched: TortaScheduler::with_profile(sched_profile),
                sink: None,
                udp_base_rtt: 0.0,
                tcp_base_rtt: 0.0,
                tcp_floor: 0.0,
                // ★ #52 — all five are the HONEST ZERO: no flow has been shaped yet. The dashboard
                // gates on `shaped_cwnd_n > 0` so an unshaped session reads "—", never a fake window.
                shaped_rtt: 0.0,
                shaped_cwnd_last: 0,
                shaped_cwnd_sum: 0,
                shaped_cwnd_n: 0,
                shaped_losses: 0,
                log_dir: None,
            }),
        })
    }

    /// Feed a TCP RTT sample (ms) into the YeAH window algorithm. Drives `apply(rtt)`; the new cwnd
    /// paces the next dispatch. Pushes a snapshot to the attached sink if any.
    pub fn apply_sample(&self, rtt_ms: f64) {
        let mut inner = self.lock_inner();
        inner.yeah.apply(rtt_ms);
        // Rung D — the same live RTT drives the SoftCake CoDel clock (RFC 8289 interval ≈ RTT).
        inner.sched.observe_rtt(rtt_ms);
        Self::push_metrics(inner);
    }

    /// D12 — the BATCH entry: feed a whole cycle's TCP RTT samples in ONE call, pushing ONE snapshot
    /// after the batch (was: one FFI crossing + one full snapshot push PER SAMPLE — up to `cwnd`
    /// pushes per 5-s cycle where the dashboard renders only the last). The per-sample
    /// [`apply_sample`](Self::apply_sample) stays for compatibility; both derive from the one
    /// [`snapshot_of`](Self::snapshot_of) reader, so the push/pull no-drift law is preserved.
    /// An empty batch is a no-op (nothing changed ⇒ nothing pushed).
    pub fn apply_samples(&self, rtt_ms: Vec<f64>) {
        if rtt_ms.is_empty() {
            return;
        }
        let mut inner = self.lock_inner();
        for rtt in rtt_ms {
            inner.yeah.apply(rtt);
            inner.sched.observe_rtt(rtt); // Rung D — RTT-coupled CoDel clock
        }
        Self::push_metrics(inner);
    }

    /// Feed a UDP RTT sample (ms). The YeAH cwnd is unified across TCP+UDP (YeahCongestionView.kt:74-75);
    /// the UDP base_rtt is tracked separately for the dual-line dashboard.
    pub fn apply_udp_sample(&self, rtt_ms: f64) {
        let mut inner = self.lock_inner();
        Self::fold_udp_sample(&mut inner, rtt_ms);
        // ★ Rung D — EVERY profile now runs an INDEPENDENT UDP congestion algorithm on its own
        // window: Legacy's threshold machine, Canonical's Little's-law backlog, LineRate's
        // kernel-hysteresis brain. A UDP sample never touches the TCP window on any of them
        // (`Proofs/YeahUdpIndependence.lean::the_split_design_is_independent`). The old comment
        // here said "a UDP sample does not drive the cwnd (apply_udp is a no-op)" on
        // Legacy/Canonical — true before the split, false now, and the two profiles were the ones
        // with no UDP congestion control at all.
        inner.yeah.apply_udp(rtt_ms);
        inner.sched.observe_rtt(rtt_ms); // Rung D — RTT-coupled CoDel clock
        Self::push_metrics(inner);
    }

    /// D12 — the UDP twin of [`apply_samples`](Self::apply_samples): fold a whole cycle's UDP RTT
    /// samples into the EWMA in ONE call, ONE snapshot push after the batch. Empty batch ⇒ no-op.
    pub fn apply_udp_samples(&self, rtt_ms: Vec<f64>) {
        if rtt_ms.is_empty() {
            return;
        }
        let mut inner = self.lock_inner();
        for rtt in rtt_ms {
            Self::fold_udp_sample(&mut inner, rtt);
            inner.yeah.apply_udp(rtt);
            inner.sched.observe_rtt(rtt); // Rung D — RTT-coupled CoDel clock
        }
        Self::push_metrics(inner);
    }

    /// Signal a loss/timeout to the YeAH controller (the H2/M1 canonical reaction or the Legacy penalty).
    pub fn on_loss(&self) {
        let mut inner = self.lock_inner();
        inner.yeah.on_loss_or_timeout();
        Self::push_metrics(inner);
    }

    /// Hard failover (relay switch) — collapse the window + re-learn the floor.
    pub fn on_failover(&self) {
        let mut inner = self.lock_inner();
        inner.yeah.apply_failover_penalty();
        Self::push_metrics(inner);
    }

    /// Enqueue a probe into the Tortä scheduler.
    pub fn enqueue_probe(&self, req: ProbeRequest) {
        self.lock_inner().sched.enqueue(req);
    }

    /// Drive the Tortä dispatch: drain up to `cwnd` probes at wall-clock `now_ms`. Returns the batch.
    /// One guard covers the cwnd read AND the drain — the window and the dispatch it paces can never
    /// tear apart (the old two-lock read could race a concurrent `apply_sample` between them).
    pub fn dispatch(&self, now_ms: i64) -> Vec<ProbeRequest> {
        let mut inner = self.lock_inner();
        let cwnd = inner.yeah.cwnd();
        inner.sched.dispatch(cwnd, now_ms)
    }

    /// Notify the adaptive valve of a timeout/fail for a tin (the Kotlin `onTimeoutOrFail`).
    pub fn on_timeout_or_fail(&self, priority: ProbePriority) {
        self.lock_inner().sched.on_timeout_or_fail(priority);
    }

    /// Notify the adaptive valve of a success for a tin (the Kotlin `onSuccess`).
    pub fn on_success(&self, priority: ProbePriority) {
        self.lock_inner().sched.on_success(priority);
    }

    /// The current YeAH congestion window (1..16) — pacing for the next dispatch.
    pub fn cwnd(&self) -> i32 {
        self.lock_inner().yeah.cwnd()
    }

    /// ★ Rung D — the INDEPENDENT UDP congestion window (1..16), computed from UDP samples alone
    /// on every profile. Proof of the law it obeys: `Proofs/YeahUdpIndependence.lean`.
    pub fn udp_cwnd(&self) -> i32 {
        self.lock_inner().yeah.udp_cwnd()
    }

    /// The UDP family's own fair-share estimate.
    pub fn udp_fair_cwnd(&self) -> i32 {
        self.lock_inner().yeah.udp_fair_cwnd()
    }

    /// The adaptive read timeout (ms) given a jitter estimate.
    pub fn adaptive_timeout_ms(&self, jitter_ms: f64) -> i32 {
        self.lock_inner().yeah.adaptive_timeout_ms(jitter_ms)
    }

    /// THE POLL-FREE PULL — read the complete live [`BeastSnapshot`] on demand (no attached sink required),
    /// complementing the [`BeastMetricSink`] push callback. The dashboard PULLS this when it polls; both
    /// paths return the IDENTICAL Record because both derive from the one
    /// [`snapshot_of`](Self::snapshot_of) reader (no push↔pull drift). Pure surface — no engine math.
    pub fn snapshot(&self) -> BeastSnapshot {
        Self::snapshot_of(&self.lock_inner())
    }

    /// Attach (or replace) the metric sink. Rust will call `on_metrics` once per cycle after this.
    pub fn attach_sink(&self, sink: Arc<dyn BeastMetricSink>) {
        self.lock_inner().sink = Some(sink);
    }

    /// Bind the app-private durable dir for `query-beast.log` (Kotlin passes `filesDir`). Interior-mutable
    /// (`&self` + `Mutex`, the Beast pattern) so the host can bind after construction. Until bound, the
    /// review-channel seam [`log_event`](Self::log_event) is a silent no-op (no dir → no path → no log).
    pub fn bind_log_dir(&self, dir: String) {
        self.lock_inner().log_dir = Some(std::path::PathBuf::from(dir));
    }

    /// THE EXPLICIT REVIEW-CHANNEL SEAM (#133) — append ONE `query-beast.log` line for a live Beast event.
    /// OFF the hot path: the Kotlin control plane calls this on its cadence (it holds the
    /// [`BeastMetricSink`] push stream and classifies each event — a periodic `tick`, a `mode` shift, a
    /// `shed`, a basin `over`flow), passing the `snapshot` it just received and the `relay` name it knows
    /// (the Beast Object holds no relay name — [`ProbeRequest`] carries only `endpoint_idx`). `now_ms` is
    /// the injected wall clock. FAIL-OPEN + no-op when UNBOUND (never a panic, never touches the engine).
    /// The guard is dropped BEFORE the file append — the engine lock never spans IO.
    pub fn log_event(
        &self,
        now_ms: u64,
        kind: log::BeastLogKind,
        snapshot: BeastSnapshot,
        relay: String,
    ) {
        if let Some(path) = self.query_beast_log_path() {
            log::append_beast_event(&path, now_ms, kind, &snapshot, &relay);
        }
    }
}

// Non-exported helpers (private types like `MutexGuard`/`Option<PathBuf>` are NOT UniFFI-lowerable, so
// they live OUTSIDE the `#[uniffi::export] impl` block — the same split the Warden uses for
// `query_warden_log_path`).
impl Beast {
    /// THE ONE lock acquisition — poison-RECOVERY (`into_inner`), the crate-wide idiom (D22). The
    /// guarded state is always-valid arithmetic data, so recovering a poisoned guard is strictly safe;
    /// panicking here instead would poison-brick EVERY subsequent Beast call (a permanent
    /// InternalException storm into the Kotlin engine loop) rather than self-healing.
    fn lock_inner(&self) -> MutexGuard<'_, BeastInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---- #49 THE BEAST SETTINGS · the LIVE write-edge setters -----------------------------------------
    // These take only UniFFI-lowerable i32s, so they COULD sit in the exported impl — but they must NOT.
    // The ONLY caller is the module-level free-function trio ([`crate::beast_set_yeah_profile`] et al) that
    // the Kotlin bridge invokes; nothing in Kotlin ever holds a `Beast` handle. Exporting them as Beast
    // object methods too would widen the Android `.kt` UniFFI surface with unreachable dead methods (a
    // `_fn_method_beast_set_*` phantom beside the real `_fn_func_beast_set_*`). Non-exported here = ONE
    // honest write edge per knob — the #14 minimal-bridge law.

    /// #49 — swap the YeAH brain (congestion profile) LIVE (the Beast SETTINGS "brain" control). Re-seeds the
    /// controller to the new profile's constants: cwnd collapses to MIN_WINDOW and the learned base_rtt resets
    /// (this IS the "a rebuild resets cwnd + RTT" the settings pane warns of). Out-of-range id -> Legacy
    /// (fail-safe). Pushes a fresh snapshot so the dashboard reflects the reset at once.
    pub fn set_yeah_profile(&self, id: i32) {
        let profile = match id {
            1 => YeahProfile::Canonical,
            2 => YeahProfile::LineRate,
            _ => YeahProfile::Legacy,
        };
        let mut inner = self.lock_inner();
        inner.yeah = YeahController::with_profile(profile);
        Self::push_metrics(inner);
    }

    /// #49 — swap the CAKE queue (scheduler AQM profile) LIVE (the Beast SETTINGS "queue" control). The pane
    /// offers a 2-way choice (0 Legacy-AQM / 1 CoBALT); CoBALT maps to the surpassing SoftCake + Mochi-Dango
    /// law ([`TortaProfile::SoftCake`]). Re-seeds the scheduler (the in-flight tin backlog is dropped — the
    /// honest cost of a queue swap). Any other id -> Legacy.
    pub fn set_cake_profile(&self, id: i32) {
        let profile = match id {
            1 => TortaProfile::SoftCake,
            _ => TortaProfile::Legacy,
        };
        let mut inner = self.lock_inner();
        inner.sched = TortaScheduler::with_profile(profile);
        Self::push_metrics(inner);
    }

    /// #49 — override the YeAH tunables LIVE (the Beast SETTINGS Expert reveal). Delegates to
    /// [`YeahController::set_tunables`] under the one lock; each 0 keeps the profile default, a positive value
    /// bites the next window step. cycle-ms (the CoDel control interval) is deliberately NOT applied here — it
    /// is a scheduler const passed per-cycle with no live setter yet; the host persists it staged until that
    /// seam lands. Pushes a fresh snapshot.
    pub fn set_tunables(&self, max_window: i32, free_thresh_milli: i32, compete_thresh_milli: i32) {
        let mut inner = self.lock_inner();
        inner
            .yeah
            .set_tunables(max_window, free_thresh_milli, compete_thresh_milli);
        Self::push_metrics(inner);
    }

    /// Fold one UDP RTT sample into the EWMA (same alpha as the TCP estimator; first sample seeds).
    fn fold_udp_sample(inner: &mut BeastInner, rtt_ms: f64) {
        // HARDENING — a NaN would poison this EWMA permanently (0.85·NaN + x = NaN forever);
        // the exported apply_udp_sample(s) paths reach here with the raw FFI value.
        if !(rtt_ms.is_finite() && rtt_ms > 0.0) {
            return;
        }
        if inner.udp_base_rtt <= 0.0 {
            inner.udp_base_rtt = rtt_ms;
        } else {
            inner.udp_base_rtt =
                (1.0 - yeah::EWMA_ALPHA) * inner.udp_base_rtt + yeah::EWMA_ALPHA * rtt_ms;
        }
    }

    /// CP-Feed-Both (host-only — no `#[uniffi::export]`, so ZERO Android .kt UniFFI drift) — light the
    /// dual-line dashboard's UDP lane (udp_base_rtt EWMA + udp_floor true-min) for a cycle's UDP samples
    /// WITHOUT driving the window brain. The host feeds these SAME UDP RTTs into the shared window via
    /// [`apply_samples`](Self::apply_samples), restoring the pre-CP-Attribution "visible organism":
    /// Q/Q-SMOOTH/mode/cwnd move because the real network RTTs are judged against the shared low floor.
    /// This keeps the UDP display fields alive for the second dashboard line without a SECOND,
    /// conflicting window update. Empty batch ⇒ no-op (no push). ONE snapshot push after the batch (D12).
    pub fn fold_udp_display_samples(&self, rtt_ms: Vec<f64>) {
        if rtt_ms.is_empty() {
            return;
        }
        let mut inner = self.lock_inner();
        for rtt in rtt_ms {
            Self::fold_udp_sample(&mut inner, rtt);
            inner.yeah.observe_udp_floor(rtt);
        }
        Self::push_metrics(inner);
    }

    /// #3-EXT · The TCP twin of [`fold_udp_display_samples`] (host-only — no `#[uniffi::export]`,
    /// zero Android .kt UniFFI drift): light the dual-line dashboard's TCP lane from the netstack
    /// forwarder's REAL dial RTTs (SYN→established elapsed — the TCP-family twin of the DNS query
    /// RTT) WITHOUT driving the window brain. Base EWMA (same alpha as every family estimator) +
    /// leaky-bucket true-min floor (the FLOOR_LEAK law). Display lane ONLY by design: per-flow dial
    /// samples must never steer the DNS window or the shared adaptive-timeout EWMA — the exact
    /// discipline `fold_udp_display_samples` documents for the opposite family. Non-finite /
    /// non-positive samples are dropped (the EWMA-poison gate). Empty batch ⇒ no-op; ONE snapshot
    /// push after the batch (D12).
    pub fn fold_tcp_display_samples(&self, rtt_ms: Vec<f64>) {
        if rtt_ms.is_empty() {
            return;
        }
        let mut inner = self.lock_inner();
        for rtt in rtt_ms {
            // ★ #22 slice 3 — the LR_LOCAL_ECHO_MS law: a sub-millisecond dial is a loopback
            // echo, not a wire RTT; one would poison the true-min floor forever (yeah.rs).
            if !(rtt.is_finite() && rtt >= yeah::LR_LOCAL_ECHO_MS) {
                continue;
            }
            if inner.tcp_base_rtt <= 0.0 {
                inner.tcp_base_rtt = rtt;
            } else {
                inner.tcp_base_rtt =
                    (1.0 - yeah::EWMA_ALPHA) * inner.tcp_base_rtt + yeah::EWMA_ALPHA * rtt;
            }
            if inner.tcp_floor <= 0.0 {
                inner.tcp_floor = rtt;
            } else {
                inner.tcp_floor = rtt.min(inner.tcp_floor * yeah::FLOOR_LEAK);
            }
        }
        Self::push_metrics(inner);
    }

    /// ★ #52 — fold ONE real-flow shaping observation into the SHAPED PLANE (host-only, no
    /// `#[uniffi::export]` — the `fold_tcp_display_samples` precedent, zero Android .kt drift).
    ///
    /// Called from the forwarder beside `FlowShaper::sample`, so `rtt_ms` is the SAME steady-state
    /// measurement the flow's own YeAH brain just consumed, and `cwnd` is the window that brain
    /// converged on immediately after. That pairing is the whole point: the panel shows the window
    /// AND the RTT it was learned from, never one without the other.
    ///
    /// DISPLAY LANE ONLY — it touches no controller and steers no window. The per-flow brains do the
    /// shaping; this only lets the Beast pillar SEE them.
    ///
    /// The `LR_LOCAL_ECHO_MS` poison gate applies exactly as it does to the dial lane: a
    /// sub-millisecond sample is a loopback echo, not a wire RTT, and would pin the EWMA forever.
    /// A rejected RTT still records its window — the window was really observed, and dropping it
    /// would bias the mean toward whichever flows happen to be slow.
    pub fn fold_shaped_sample(&self, rtt_ms: f64, cwnd: i32) {
        let mut inner = self.lock_inner();
        if rtt_ms.is_finite() && rtt_ms >= yeah::LR_LOCAL_ECHO_MS {
            if inner.shaped_rtt <= 0.0 {
                inner.shaped_rtt = rtt_ms;
            } else {
                inner.shaped_rtt =
                    (1.0 - yeah::EWMA_ALPHA) * inner.shaped_rtt + yeah::EWMA_ALPHA * rtt_ms;
            }
        }
        // A window is only meaningful at or above MIN_WINDOW; a non-positive cwnd would mean the
        // shaper was read before it was seeded, which is a caller bug, not a measurement.
        if cwnd > 0 {
            inner.shaped_cwnd_last = cwnd;
            inner.shaped_cwnd_sum = inner.shaped_cwnd_sum.saturating_add(cwnd as i64);
            inner.shaped_cwnd_n = inner.shaped_cwnd_n.saturating_add(1);
        }
        Self::push_metrics(inner);
    }

    /// ★ #52 — record ONE YeAH loss reaction on a real forwarded flow (host-only, no export).
    /// Counted separately from `ForwarderStats::stalls`: that counts the I/O event, this counts the
    /// CONGESTION REACTION the shaper took because of it. They can legitimately differ.
    pub fn fold_shaped_loss(&self) {
        let mut inner = self.lock_inner();
        inner.shaped_losses = inner.shaped_losses.saturating_add(1);
        Self::push_metrics(inner);
    }

    /// AQM TEETH read (host-only — NO `#[uniffi::export]`, so ZERO Android .kt UniFFI drift; the
    /// `fold_udp_display_samples` precedent). A PURE read of the scheduler's Normal-tin adaptive valve
    /// plus the scheduler's OWN probabilistic shed law (`pseudo_rand(now_ms) < valve_prob`): returns
    /// `true` iff a served Normal-tier query should be LOAD-SHED right now. The Normal tin is the LOWEST
    /// priority — Critical (A/AAAA/HTTPS/SVCB) and High (NS/MX/SOA/PTR/…) are floor-protected and are
    /// NEVER consulted here, so address + infra lookups are never shed. The valve is engaged only under
    /// sustained overload (it rises on real `on_timeout_or_fail`, decays on `on_success` + the idle
    /// half-life), so a quiet box (valve ≈ 0) never sheds. NEVER mutates — the valve moves only through
    /// the real `on_success`/`on_timeout_or_fail` outcome path.
    pub fn would_shed_normal(&self, now_ms: i64) -> bool {
        let valve = self
            .lock_inner()
            .sched
            .valve_prob_tin(ProbePriority::Normal);
        valve > 0.0 && crate::beast::scheduler::pseudo_rand(now_ms) < valve
    }

    /// Build + push a snapshot to the attached sink, CONSUMING the guard (no-op if no sink attached).
    /// The snapshot is built while the guard is still held — one ATOMIC world, no cross-lock skew —
    /// then the guard is dropped BEFORE the foreign `on_metrics` call, so Kotlin code NEVER runs under
    /// the engine lock (a re-entrant `snapshot()`/`log_event` from inside the callback cannot deadlock).
    fn push_metrics(inner: MutexGuard<'_, BeastInner>) {
        let Some(sink) = inner.sink.clone() else {
            return;
        };
        let snapshot = Self::snapshot_of(&inner);
        drop(inner);
        sink.on_metrics(snapshot);
    }

    /// THE ONE snapshot reader — the drift keystone. Reads the single coherent [`BeastInner`] world
    /// under its one guard (D22 killed the old udp→yeah→sched cross-lock read and its torn-state skew).
    /// Both [`push_metrics`](Self::push_metrics) and the pull [`snapshot`](Self::snapshot) call this,
    /// so the two paths report the IDENTICAL live state. Pure surface — reads only the engine's
    /// existing accessors + the pub `profile` fields; touches ZERO Tortä/YeAH algorithm.
    fn snapshot_of(inner: &BeastInner) -> BeastSnapshot {
        let y = &inner.yeah;
        let c = &inner.sched;
        BeastSnapshot {
            cwnd: y.cwnd(),
            window_max: y.max_window(),
            mode: y.mode().label().to_string(),
            mode_kind: y.mode(),
            slow_start_active: matches!(y.mode(), YeahMode::SlowStart),
            base_rtt_ms: y.base_rtt(),
            rtt_base_floor_ms: y.rtt_base_floor(),
            q_packets: y.q_packets(),
            reno_count: y.reno_count(),
            fast_mode: y.fast_mode(),
            adaptive_timeout_ms: y.adaptive_timeout_ms(0.0),
            pacing_rate: pacing_rate(y.cwnd(), y.base_rtt()),
            yeah_profile: y.profile,
            udp_base_rtt_ms: inner.udp_base_rtt,
            udp_mode_kind: y.udp_mode(),
            tcp_base_rtt_ms: inner.tcp_base_rtt,
            tcp_floor_ms: inner.tcp_floor,
            // ★ #52 — the shaped plane. The mean divides by the REAL count, and only when that count
            // is non-zero: an unshaped session reports 0.0 with `shaped_samples == 0`, so the panel
            // can say "nothing shaped yet" instead of "the window is zero" (two different claims).
            shaped_rtt_ms: inner.shaped_rtt,
            shaped_cwnd_last: inner.shaped_cwnd_last,
            shaped_cwnd_mean: if inner.shaped_cwnd_n > 0 {
                inner.shaped_cwnd_sum as f64 / inner.shaped_cwnd_n as f64
            } else {
                0.0
            },
            shaped_samples: inner.shaped_cwnd_n,
            shaped_losses: inner.shaped_losses,
            q_smooth: y.q_smooth(),
            udp_floor_ms: y.udp_floor(),
            zeta_streak: y.fast_streak(),
            shed_streak: y.congest_streak(),
            doing_reno_now: y.doing_reno_now(),
            fair_cwnd: y.fair_cwnd(),
            pipeline_depth: c.pipeline_depth() as i32,
            queue_critical: c.queue_depth(ProbePriority::Critical) as i32,
            queue_high: c.queue_depth(ProbePriority::High) as i32,
            queue_normal: c.queue_depth(ProbePriority::Normal) as i32,
            valve_prob: c.valve_prob(),
            valve_critical: c.valve_prob_tin(ProbePriority::Critical),
            valve_high: c.valve_prob_tin(ProbePriority::High),
            valve_normal: c.valve_prob_tin(ProbePriority::Normal),
            valve_streak: c.valve_streak() as i32,
            soft_memory: c.soft_memory() as i32,
            shed_dropped: c.shed_dropped() as i32,
            aqm_dropped: c.aqm_dropped() as i32,
            drr_sparse_served: c.drr_sparse_served() as i32,
            overload_sheds: c.overload_sheds() as i32,
            outage_absorbed: c.outage_absorbed() as i32,
            sched_profile: c.profile,
        }
    }

    /// The on-disk path of the per-pillar `query-beast.log` — the bound log dir + [`log::QUERY_BEAST_LOG_NAME`].
    /// `None` when UNBOUND (RAM-only; the engine still runs, it simply writes no review log — the fail-safe).
    fn query_beast_log_path(&self) -> Option<std::path::PathBuf> {
        self.lock_inner()
            .log_dir
            .as_ref()
            .map(|dir| dir.join(log::QUERY_BEAST_LOG_NAME))
    }
}

/// Pacing rate (probes/sec) = cwnd / base_rtt_seconds. 0 before any sample.
fn pacing_rate(cwnd: i32, base_rtt_ms: f64) -> f64 {
    if base_rtt_ms <= 0.0 {
        0.0
    } else {
        cwnd as f64 / (base_rtt_ms / 1000.0)
    }
}

/// Scheduler introspection — deliberately a SEPARATE `impl` block from the `#[uniffi::export]`ed
/// one above. These return tuples/arrays, which are not UniFFI types; the FFI shape is built in
/// `lib.rs` as typed Records instead. Putting them in the exported block makes the whole block fail
/// to compile, which is how this was found.
impl Beast {
    /// Per-tin WRR shape: `(configured, clamped, stride)` x 3.
    ///
    /// Configured and clamped differ exactly when a configuration was invalid — the only on-device
    /// evidence that a weight was RESCUED rather than honoured.
    ///
    /// The clamp keeps `STRIDE_UNIT / weight` from dividing by zero, which in Rust is a PANIC on
    /// the construction path. Proved for every `i64` including negatives in
    /// `D:\Lean\proofs\Proofs\TinStride.lean` (`clamp_ge_one` / `clamp_ne_zero`), together with
    /// `heavier_tin_never_waits_longer`.
    pub fn tin_weight_table(&self) -> [(i64, i64, i64); scheduler::TIN_COUNT] {
        self.lock_inner().sched.tin_weight_table()
    }

    /// DRR++ flow census `(live_flows, distinct_endpoints, queued_probes)`.
    ///
    /// `distinct_endpoints` separates "one upstream backing up" from "every upstream degrading at
    /// once" — two states that want opposite responses and look identical in a total-depth number.
    pub fn flow_census(&self) -> (usize, usize, usize) {
        self.lock_inner().sched.flow_census()
    }
}
