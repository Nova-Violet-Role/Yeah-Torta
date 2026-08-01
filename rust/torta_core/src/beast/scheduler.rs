/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Tortä scheduler — 3 priority tins (Critical/High/Normal) with per-tin depth limits and
//! AQM (CoDel-on-sojourn + adaptive valve) drop, plus paced dispatch capped at the YeAH window per cycle.
//!
//! FAITHFUL 1:1 PORT of `CakeScheduler.kt:1-563` (the Socio's Kotlin original). Pure logic — no
//! sockets, no Android — so the pinned `CakeSchedulerTest.kt` corpus ports 1:1 to Rust unit tests.
//!
//! Two profiles (CakeScheduler.kt:19-37):
//! - [`TortaProfile::Legacy`] (default): strict-priority tins with the original overflow/tail-drop AQM.
//! - [`TortaProfile::Baseline`]: the full Tortä scheduler. Per-tin AQM = CoDel on queue sojourn
//!   (sojourn = now - enqueued_at_ms, NOT RTT) with target/interval + an adaptive valve. DRR++ deficit
//!   fairness over 8-way set-associative flow buckets keyed (endpoint_idx, qname). DiffServ tins
//!   served by WRR shares ~[100,50,12] realized as SFQ stride scheduling (the H4 cross-tin fix).
//!   Drops are SHED/SERVFAIL-fast, NEVER silent: the CRITICAL tin is floor-protected.
//!
//! Thread-safety in Kotlin was `@Synchronized` on the AQM path (CakeScheduler.kt:191,267,442,447).
//! In Rust the whole [`Beast`](super::Beast) state lives behind one `Mutex`, so this scheduler is
//! single-threaded logic operated under that lock.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};

use crate::beast::{ProbePriority, ProbeRequest, TortaProfile};

// ---- Constants (CakeScheduler.kt:51-77, verbatim) ----

/// Per-tin max depth, indexed by `ProbePriority` ordinal: Critical=4, High=8, Normal=16
/// (CakeScheduler.kt:53 `TIN_MAX_DEPTH`).
pub const TIN_MAX_DEPTH: [usize; 3] = [4, 8, 16];

/// THE HONEST FILL DENOMINATOR for a tin basin, per profile — the ONE source of truth the UI must
/// use instead of hand-copying the ladder.
///
/// # The defect this replaces
///
/// `torta_ui/src/lib.rs` declared `const TIN_CAPS: [f32; 3] = [4.0, 8.0, 16.0]` twice (`:3550`,
/// `:3627`) and drew every basin as `(depth / TIN_CAPS[i]).clamp(0.0, 1.0)` on ALL profiles. On
/// the AQM path that ladder is not the governing bound at all:
///
/// * the per-tin trim at `:947` lives ONLY in `dispatch_legacy`; `dispatch_aqm` never references
///   `TIN_MAX_DEPTH`;
/// * `TortaProfile::SoftCake` is bounded at ENQUEUE by [`AQM_GLOBAL_CAP`] (`:861`) — a GLOBAL
///   total, not a per-tin cap;
/// * `Proofs/TinCapacity.lean::the_ladder_is_the_wrong_denominator_on_the_aqm_path` proves
///   `128 ≠ 28`, and `the_global_cap_does_not_imply_the_per_tin_caps` proves `128 > 28`.
///
/// So an AQM-path tin legitimately sitting above its ladder entry rendered as a bar pinned at
/// 100% — permanently OVERFLOW-red on a datapath behaving exactly as designed. Measured
/// (`beastsim.rs`): SoftCake drove CRITICAL to 49 against a ladder entry of 4.
///
/// # Why the AQM denominator is the GLOBAL cap
///
/// On the AQM path any single tin may legitimately hold up to the whole global budget — nothing
/// reserves a per-tin share, and the WRR weights govern DISPATCH order, not occupancy. So
/// `AQM_GLOBAL_CAP` is the smallest denominator that can never render a false overflow, which is
/// proved: `Proofs/TinCapacity.lean::the_aqm_denominator_never_renders_a_false_overflow`.
///
/// Legacy keeps the ladder, because there the per-tin trim really is the governing bound.
pub const fn fill_denominator(profile: TortaProfile, tin: usize) -> i64 {
    match profile {
        TortaProfile::Legacy => TIN_MAX_DEPTH[tin] as i64,
        // Baseline has NO bound at all (proved: `baseline_has_no_bound`), so the global cap is
        // used as the reference scale there too — a bar over 1.0 on Baseline is TRUE information
        // (the queue really is past anything SoftCake would allow), not a rendering artefact.
        _ => AQM_GLOBAL_CAP,
    }
}

/// ★ #22 slice 3 · Rung E — GLOBAL AQM capacity (probes) for [`TortaProfile::SoftCake`], the 5TH
/// sch_cake gap. The AQM enqueue path had NO bound at all (sojourn drops fire only at DISPATCH —
/// a burst faster than dispatch grew `tin_buckets` unbounded in RAM, on a phone); LEGACY's
/// dispatch-time tail-trim never covered it. sch_cake bounds memory at ENQUEUE (`buffer_used >
/// buffer_limit`, sch_cake.c:2025-2033) and sheds via `cake_drop` (:1605-1667): the arriving
/// packet is NEVER rejected — the FATTEST queue's head pays. 128 = 8 full MAX_WINDOW dispatch
/// bursts of standing backlog: ample sparse-boost headroom, bounded RAM.
pub const AQM_GLOBAL_CAP: i64 = 128;

/// DiffServ WRR shares ~[100,50,12] (CakeScheduler.kt:56 `DEFAULT_TIN_WEIGHTS`).
pub const DEFAULT_TIN_WEIGHTS: [i64; 3] = [100, 50, 12];

pub const DEFAULT_QUANTUM: i32 = 1;
pub const DEFAULT_SET_ASSOC_WAYS: usize = 8;
pub const DEFAULT_CODEL_TARGET_MS: i64 = 5;
pub const DEFAULT_CODEL_INTERVAL_MS: i64 = 20;
/// M3: after this many consecutive new-flow serves, yield a turn to old-flows (CakeScheduler.kt:62).
pub const NEW_FLOW_BURST: i32 = 8;
/// Adaptive-valve increment on timeout/fail and its cap (CakeScheduler.kt:64-66).
pub const VALVE_INC: f64 = 0.0025;
pub const VALVE_DECAY: f64 = 0.0025;
pub const VALVE_CAP: f64 = 0.25;
/// H4 — STRIDE numerator for the SFQ virtual-time cross-tin scheduler (CakeScheduler.kt:76).
pub const STRIDE_UNIT: i64 = 1_000_000;

// ---- Rung B constants — Soft-cake + Mochi-Dango (TortaProfile::SoftCake, SAIMONOKUMA 2026) ----
//
// Surpassed prior art, measured from the original deprecated CAKE source (sch_cake.c):
// COBALT = CoDel + BLUE in parallel (sch_cake.c:277-281); BLUE incremented p_drop by a FIXED
// p_inc = 1/256 and decayed by p_dec = 1/4096 (sch_cake.c:2423-2424) ONLY on queue-full/queue-empty
// service events (cobalt_queue_full :459-478, cobalt_queue_empty :483-509) — an idle queue got NO
// decay events, so a saturated valve stayed stuck; and cobalt_should_drop (:560-642) had MTU floors
// but NO staleness ceiling. Soft-cake + Mochi-Dango close all three gaps, deterministically.
//
// The original's whole observable AQM state was {COBALT_COUNT, DROPPING, DROP_NEXT_US, P_DROP,
// BLUE_TIMER_US} (pkt_sched.h:899-903) — TinAqm models all five and ADDS the Rung B memory fields.
// The kernel's other BLUE descendant, SFB, likewise used FIXED Q0.16 increment/decrement steps
// (pkt_sched.h:638-651): the entire kernel BLUE family is fixed-step, no escalation, no idle heal.

/// Soft-cake HARD STALENESS CEILING: a head with sojourn >= this multiple of target is shed
/// IMMEDIATELY, bypassing the CoDel grace interval — a hopelessly stale DNS answer is worse than
/// SERVFAIL-fast. Exists in neither the original cobalt_should_drop (sch_cake.c:587-589, MTU
/// floors only) nor the Baseline rail.
pub const SOFT_HARD_SHED_MULT: i64 = 20;

/// Soft-cake WINDOWED COUNT MEMORY: on re-entering dropping within this many intervals of the
/// last exit, resume from (remembered count - 2) instead of 1. Restores COBALT's memory property
/// (sch_cake.c:603-628 kept `count` across exits, decaying it gradually) which the Kotlin-pinned
/// Baseline dropped — deterministic + bounded instead of the original's unbounded while-loop decay.
pub const SOFT_COUNT_MEMORY_INTERVALS: i64 = 8;

/// Mochi-Dango FREEZE WINDOW: fails landing inside one window count ONCE (correlated-burst
/// absorption — one upstream outage produces N timeouts but ONE congestion signal). The original
/// BLUE's increment gate was `now - blue_timer > target` (sch_cake.c:465-471); Baseline has none.
pub const MOCHI_FREEZE_MS: i64 = 50;

/// Mochi-Dango ESCALATION CAP: consecutive distinct-window fails scale the valve increment
/// 1x, 2x, .. up to this cap — sustained failure opens the valve faster than the original's fixed
/// p_inc (sch_cake.c:2423) while correlated bursts (frozen) don't.
pub const MOCHI_STREAK_CAP: i64 = 8;

/// Mochi-Dango IDLE HALF-LIFE: the valve halves per elapsed window of wall-clock, healing WITHOUT
/// service events. The original BLUE decayed only inside cobalt_queue_empty (sch_cake.c:483-509),
/// so an idle queue's saturated valve stayed stuck; Baseline likewise decays only on successes.
pub const MOCHI_HALF_LIFE_MS: i64 = 250;

/// Mochi-Dango VALVE FLOOR: below this the decaying valve snaps to exactly 0.0 (and the fail
/// streak resets) so the tin returns to the pure-CoDel regime.
pub const MOCHI_VALVE_FLOOR: f64 = 1e-4;

// ---- Rung D constants — the FOURTH gap + the RTT-coupled clock (SAIMONOKUMA 2026) ----
//
// The #3 study audited sch_cake.c for a queue-management edge CAKE never handled and found TWO:
// (a) a qdisc structurally cannot tell an upstream OUTAGE from queue congestion — when the path
//     dies, every service class fails at once and COBALT/BLUE punish the (innocent) queue for it
//     (cobalt_queue_full, sch_cake.c:459-478, fires per-flow with no cross-tin view at all);
// (b) the CoDel interval is a static config preset (cake's rtt presets are set once at qdisc
//     creation), never coupled to the LIVE RTT the traffic is actually seeing — while CoDel's own
//     law (RFC 8289 §4.2) says interval should be on the order of the worst-case RTT.
// A DNS engine sees both signals natively: the three DiffServ tins fail together only on an
// upstream outage, and the YeAH brains measure the live RTT every sample.

/// Dango-Daikazoku OUTAGE WINDOW (Rung D, gap 4): a fail landing within this many ms of a fail on
/// a DIFFERENT tin is a correlated upstream outage — one skewer, many dangos. The FIRST fail of
/// the burst moves its tin's valve normally; the cross-tin echoes are absorbed (counted, never
/// valve-moving) so an upstream death doesn't open all three valves against innocent queues while
/// the YeAH failover machinery owns the real problem. Wider than [`MOCHI_FREEZE_MS`] (which is
/// same-tin): infrastructure failures correlate across service classes on a longer horizon.
pub const DANGO_OUTAGE_WINDOW_MS: i64 = 100;

/// Soft-cake RTT-COUPLED CODEL CLOCK ceiling (Rung D, live telemetry): the effective CoDel
/// interval is `clamp(live_rtt_ceiling, codel_interval_ms, this)` — never below the configured
/// interval (the pinned floor), never above CoDel's canonical internet default of 100 ms
/// (RFC 8289 §4.2).
pub const SOFT_RTT_INTERVAL_CAP_MS: i64 = 100;

/// Leaky-CEILING decay for the live worst-case-RTT estimator: each sample takes
/// `max(sample, ceiling * this)` — the mirror image of the YeAH floors' `FLOOR_LEAK` law (a
/// true-min that drifts UP x1.02 there; a true-max that drifts DOWN x0.98 here). Deterministic,
/// no wall-clock dependency.
pub const SOFT_RTT_CEIL_DECAY: f64 = 0.98;

/// Number of tins (= number of priorities).
pub const TIN_COUNT: usize = 3;

/// One DRR++ flow = a (endpoint_idx, qname) tuple's queued probes + deficit + list membership
/// (CakeScheduler.kt:462-467).
#[derive(Debug, Clone)]
pub struct Flow {
    // Faithful 1:1 Kotlin field parity (`Flow(val key, val endpointIdx)`). `key` drives the
    // set-associative bucket + list lookup; `endpoint_idx` is retained for diagnostics/metrics.
    pub key: i64,
    pub endpoint_idx: i32,
    pub queue: VecDeque<ProbeRequest>,
    pub deficit: i32,
    pub in_new: bool,
    pub in_old: bool,
}

impl Flow {
    fn new(key: i64, endpoint_idx: i32) -> Self {
        Self {
            key,
            endpoint_idx,
            queue: VecDeque::new(),
            deficit: 0,
            in_new: false,
            in_old: false,
        }
    }
}

/// Per-tin AQM controller: CoDel state machine over queue sojourn + an adaptive drop-prob valve
/// (CakeScheduler.kt:470-562).
#[derive(Debug, Clone)]
pub struct TinAqm {
    pub valve_prob: f64,
    dropping: bool,
    // CoDel virtual clock, driven by WALL-CLOCK TIME (Nichols/Jacobson), NOT summed sojourn-excess
    // (CakeScheduler.kt:474-484).
    first_above_time: i64,
    drop_next: i64,
    count: i64,
    // ---- Rung B (Soft-cake / Mochi-Dango) state — inert under Legacy/Baseline (soft = false) ----
    /// Profile switch: false = pinned Baseline law (byte-identical); true = Soft-cake + Mochi-Dango.
    soft: bool,
    /// Soft-cake count memory: the CoDel `count` held at the last dropping-exit (+ when it happened).
    exit_count: i64,
    exit_at_ms: i64,
    /// Mochi-Dango valve state: consecutive distinct-window fail streak, last counted fail instant,
    /// and the last instant the valve moved (the idle half-life anchor). i64::MIN = "never" sentinel
    /// (0 would collide with legitimate now_ms = 0 in the deterministic corpus).
    /// Crate-visible so the A5 budget guard can read the streak DIRECTLY. The observable proxy
    /// (`valve_prob`) is clamped at `VALVE_CAP` (see `on_fail_at`), so it cannot distinguish a
    /// saturated streak from a runaway one -- exactly the breach this cap exists to prevent.
    pub(crate) fail_streak: i64,
    last_fail_ms: i64,
    last_valve_ms: i64,
}

impl TinAqm {
    pub fn new() -> Self {
        Self {
            valve_prob: 0.0,
            dropping: false,
            first_above_time: 0,
            drop_next: 0,
            count: 0,
            soft: false,
            exit_count: 0,
            exit_at_ms: 0,
            fail_streak: 0,
            last_fail_ms: i64::MIN,
            last_valve_ms: i64::MIN,
        }
    }

    /// Rung B constructor — the Soft-cake + Mochi-Dango law (TortaProfile::SoftCake).
    pub fn new_soft() -> Self {
        Self {
            soft: true,
            ..Self::new()
        }
    }

    /// Canonical CoDel on queue sojourn, wall-clock control law (CakeScheduler.kt:494-532).
    /// Returns true to SHED this head.
    pub fn should_shed(
        &mut self,
        sojourn: i64,
        now_ms: i64,
        target_ms: i64,
        interval_ms: i64,
    ) -> bool {
        if self.soft {
            return self.should_shed_soft(sojourn, now_ms, target_ms, interval_ms);
        }

        // Valve: an active adaptive valve sheds probabilistically regardless of CoDel timing (CakeScheduler.kt:496).
        if self.valve_prob > 0.0 && sojourn > target_ms && pseudo_rand(now_ms) < self.valve_prob {
            return true;
        }

        if sojourn < target_ms {
            // Queue drained below target -> leave dropping, disarm the virtual clock (:498-504).
            self.dropping = false;
            self.first_above_time = 0;
            self.count = 0;
            return false;
        }
        let interval = interval_ms.max(1);
        if !self.dropping {
            if self.first_above_time == 0 {
                // First instant above target -> schedule earliest first drop one full interval out (:510-511).
                self.first_above_time = now_ms + interval;
                return false;
            }
            if now_ms < self.first_above_time {
                // Still inside the grace interval -> standing queue not yet proven (:513-515).
                return false;
            }
            // Stayed above target for a full interval -> enter dropping, shed this head (:519-521).
            self.dropping = true;
            self.count = self.count.max(1);
            self.drop_next =
                now_ms + ((interval as f64 / (self.count as f64).sqrt()) as i64).max(1);
            return true;
        }
        // Already dropping: shed only when wall-clock reaches the paced drop_next (:525-529).
        if now_ms >= self.drop_next {
            self.count += 1;
            let step = ((interval as f64 / (self.count as f64).sqrt()) as i64).max(1);
            self.drop_next = now_ms + step;
            return true;
        }
        false
    }

    /// Rung B — the Soft-cake shed law (same CoDel spine, three surpassing deltas: hard staleness
    /// ceiling, windowed count memory, Mochi-Dango idle decay run inline).
    fn should_shed_soft(
        &mut self,
        sojourn: i64,
        now_ms: i64,
        target_ms: i64,
        interval_ms: i64,
    ) -> bool {
        self.mochi_idle_decay(now_ms);

        // Soft-cake HARD STALENESS CEILING — shed a hopelessly stale head immediately, no grace.
        // Orthogonal to the CoDel clocks (dropping/first_above/drop_next untouched).
        if sojourn >= target_ms.saturating_mul(SOFT_HARD_SHED_MULT) {
            return true;
        }

        // Valve — same law as Baseline (Mochi-Dango changes how valve_prob MOVES, not how it fires).
        if self.valve_prob > 0.0 && sojourn > target_ms && pseudo_rand(now_ms) < self.valve_prob {
            return true;
        }

        if sojourn < target_ms {
            // Leave dropping — but REMEMBER the drop rate (Soft-cake count memory) before resetting.
            if self.count > 0 {
                self.exit_count = self.count;
                self.exit_at_ms = now_ms;
            }
            self.dropping = false;
            self.first_above_time = 0;
            self.count = 0;
            return false;
        }
        let interval = interval_ms.max(1);
        if !self.dropping {
            if self.first_above_time == 0 {
                self.first_above_time = now_ms + interval;
                return false;
            }
            if now_ms < self.first_above_time {
                return false;
            }
            // Entering dropping: resume from the remembered rate if the exit was recent (windowed),
            // else start at 1 like Baseline. remembered = exit_count - 2 mirrors COBALT's "back off
            // two steps" re-entry flavor (sch_cake.c:603-628), deterministic + bounded.
            let remembered = if self.exit_count > 2
                && now_ms.saturating_sub(self.exit_at_ms)
                    <= interval.saturating_mul(SOFT_COUNT_MEMORY_INTERVALS)
            {
                self.exit_count - 2
            } else {
                1
            };
            self.dropping = true;
            self.count = self.count.max(remembered).max(1);
            self.drop_next =
                now_ms + ((interval as f64 / (self.count as f64).sqrt()) as i64).max(1);
            return true;
        }
        if now_ms >= self.drop_next {
            self.count += 1;
            let step = ((interval as f64 / (self.count as f64).sqrt()) as i64).max(1);
            self.drop_next = now_ms + step;
            return true;
        }
        false
    }

    /// A good/undroppable packet was seen — reset the CoDel clock if sojourn fell below target
    /// (CakeScheduler.kt:534-540).
    pub fn on_good_or_undroppable(&mut self, sojourn: i64, target_ms: i64) {
        if sojourn < target_ms {
            self.dropping = false;
            self.first_above_time = 0;
            self.count = 0;
        }
    }

    /// M2: a tin draining to empty resets the CoDel virtual clock (CakeScheduler.kt:544-549).
    pub fn on_drained(&mut self) {
        self.dropping = false;
        self.first_above_time = 0;
        self.drop_next = 0;
        self.count = 0;
    }

    pub fn on_fail(&mut self) {
        self.valve_prob = (self.valve_prob + VALVE_INC).min(VALVE_CAP);
    }

    pub fn on_success(&mut self) {
        self.valve_prob = (self.valve_prob - VALVE_DECAY).max(0.0);
    }

    /// Rung B clocked twin of [`Self::on_good_or_undroppable`]: under SoftCake, a below-target good
    /// packet also RECORDS the count memory before the reset. Baseline path delegates byte-identical.
    pub fn on_good_or_undroppable_at(&mut self, sojourn: i64, target_ms: i64, now_ms: i64) {
        if !self.soft {
            self.on_good_or_undroppable(sojourn, target_ms);
            return;
        }
        self.mochi_idle_decay(now_ms);
        if sojourn < target_ms {
            if self.count > 0 {
                self.exit_count = self.count;
                self.exit_at_ms = now_ms;
            }
            self.dropping = false;
            self.first_above_time = 0;
            self.count = 0;
        }
    }

    /// Rung B clocked twin of [`Self::on_drained`]: Soft-cake records the count memory so the drop
    /// rate survives a full drain (COBALT kept count across exits, sch_cake.c:603-628; Baseline's M2
    /// forgets). Then the M2 reset itself is identical.
    pub fn on_drained_at(&mut self, now_ms: i64) {
        if self.soft && self.count > 0 {
            self.exit_count = self.count;
            self.exit_at_ms = now_ms;
        }
        self.on_drained();
    }

    /// Rung B clocked twin of [`Self::on_fail`] — the Mochi-Dango valve law: freeze window (a
    /// correlated burst counts ONCE) + streak escalation (sustained failure opens the valve up to
    /// MOCHI_STREAK_CAP x faster than the original's fixed p_inc, sch_cake.c:2423).
    pub fn on_fail_at(&mut self, now_ms: i64) {
        if !self.soft {
            self.on_fail();
            return;
        }
        self.mochi_idle_decay(now_ms);
        // saturating_sub handles the i64::MIN "never" sentinel (first fail is never frozen).
        if now_ms.saturating_sub(self.last_fail_ms) < MOCHI_FREEZE_MS {
            return;
        }
        self.fail_streak = (self.fail_streak + 1).min(MOCHI_STREAK_CAP);
        self.valve_prob = (self.valve_prob + VALVE_INC * self.fail_streak as f64).min(VALVE_CAP);
        self.last_fail_ms = now_ms;
        self.last_valve_ms = now_ms;
    }

    /// Rung B clocked twin of [`Self::on_success`] — same decay step as Baseline (recovery by real
    /// successes is never slower), plus the streak reset.
    pub fn on_success_at(&mut self, now_ms: i64) {
        if !self.soft {
            self.on_success();
            return;
        }
        self.mochi_idle_decay(now_ms);
        self.fail_streak = 0;
        if self.valve_prob > 0.0 {
            self.valve_prob = (self.valve_prob - VALVE_DECAY).max(0.0);
            self.last_valve_ms = now_ms;
        }
    }

    /// Mochi-Dango TIME-BASED IDLE DECAY: halve the valve once per elapsed half-life, snap to 0.0
    /// below the floor. This is the "stuck valve" fix: the original BLUE decayed only on
    /// serviced-but-empty events (cobalt_queue_empty, sch_cake.c:483-509) — pure wall-clock here.
    fn mochi_idle_decay(&mut self, now_ms: i64) {
        if self.valve_prob <= 0.0 {
            self.last_valve_ms = now_ms;
            return;
        }
        if self.last_valve_ms == i64::MIN {
            self.last_valve_ms = now_ms;
            return;
        }
        let steps = now_ms.saturating_sub(self.last_valve_ms) / MOCHI_HALF_LIFE_MS;
        if steps <= 0 {
            return;
        }
        for _ in 0..steps.min(64) {
            self.valve_prob *= 0.5;
        }
        if self.valve_prob < MOCHI_VALVE_FLOOR {
            self.valve_prob = 0.0;
            self.fail_streak = 0;
        }
        self.last_valve_ms += steps * MOCHI_HALF_LIFE_MS;
    }
}

impl Default for TinAqm {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic, cheap pseudo-random in [0,1) from the clock — xorshift64* (CakeScheduler.kt:555-561).
/// No allocation, test-stable. DO NOT swap for a real RNG.
pub(crate) fn pseudo_rand(now_ms: i64) -> f64 {
    // FAITHFUL to Kotlin CakeScheduler.kt:555-559 — ALL shifts are `ushr` (LOGICAL / zero-fill). Doing the
    // xorshift in u64 makes every `>>` logical (matching ushr). The prior i64 form used ARITHMETIC shifts,
    // which SIGN-EXTENDED negative intermediates and corrupted the adaptive valve: pseudo_rand returned values
    // up to ~2048 instead of [0,1), so `pseudo_rand < valve_prob` was always false on negative-product
    // cycles — silently neutering the adaptive-valve AQM ~half the time (R-Beast SEAL-LOOP fix
    // 2026-06-27; caught by the algorithm-faithful verifier + hand-read). u64 fixes all three shifts.
    let mut x: u64 = now_ms as u64;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    let v = x.wrapping_mul((-0x61c8864680b583eb_i64) as u64) >> 11;
    v as f64 / (1u64 << 53) as f64
}

/// Tortä scheduler (CakeScheduler.kt:38-563).
#[derive(Debug, Clone)]
pub struct TortaScheduler {
    pub profile: TortaProfile,
    /// Configured WRR shares (CakeScheduler.kt:41). Retained for diagnostics/metrics parity; stride
    /// (the derived per-tin value actually used by the SFQ scheduler) is the field the hot path reads.
    tin_weights: [i64; TIN_COUNT],
    quantum: i32,
    set_assoc_ways: usize,
    codel_target_ms: i64,
    codel_interval_ms: i64,

    // LEGACY state (lock-free ConcurrentLinkedQueue in Kotlin; here a plain VecDeque under the Beast mutex).
    tins: [VecDeque<ProbeRequest>; TIN_COUNT],
    aqm_dropped_counter: i64,

    // AQM state.
    aqm: [TinAqm; TIN_COUNT],
    /// Per-tin set-associative flow buckets; each bucket is an ordered map key -> Flow (CakeScheduler.kt:97).
    tin_buckets: Vec<Vec<HashMap<i64, Flow>>>,
    /// DRR++ new-flows (sparse, served ahead) + old-flows (round-robin), per tin (CakeScheduler.kt:99-100).
    new_flows: [VecDeque<i64>; TIN_COUNT], // holds flow keys (the Flow lives in tin_buckets)
    old_flows: [VecDeque<i64>; TIN_COUNT],
    /// M3 anti-starvation: per-tin consecutive-new-flow run (CakeScheduler.kt:107).
    new_flow_run: [i32; TIN_COUNT],
    /// H4 — clamped weights (>=1) (CakeScheduler.kt:114). Retained for parity; `stride` below is the
    /// derived field the hot path reads.
    tin_weights_clamped: [i64; TIN_COUNT],
    /// H4 — stride per tin = STRIDE_UNIT / weight (CakeScheduler.kt:121).
    stride: [i64; TIN_COUNT],
    /// H4 — per-tin virtual finish time / SFQ start-tag (CakeScheduler.kt:142). Persisted across dispatch.
    pass_: [i64; TIN_COUNT],
    /// H4 — SFQ system virtual time: the monotone non-decreasing service frontier (CakeScheduler.kt:150).
    vtime: i64,
    aqm_depth: i64,
    shed_dropped_counter: i64,
    sparse_served_counter: i64,
    /// Rung B — deterministic clock shadow for the clockless FFI valve hooks (`on_timeout_or_fail`/
    /// `on_success` cross the Beast API without a timestamp). Monotone max of every now_ms/enqueue
    /// instant this scheduler has seen; Mochi-Dango reads it as "now".
    last_now_ms: i64,
    // ---- Rung D state — inert under Legacy/Baseline ----
    /// Live worst-case-RTT estimator (leaky ceiling, [`SOFT_RTT_CEIL_DECAY`]). 0.0 = never fed —
    /// the configured `codel_interval_ms` rules alone (every pinned corpus run stays byte-identical
    /// until the host actually feeds RTT).
    rtt_ceil_ms: f64,
    /// Dango-Daikazoku: per-tin last-fail instant (the cross-tin correlation memory).
    /// `i64::MIN` = "never" sentinel (same law as `TinAqm::last_fail_ms`).
    tin_last_fail_ms: [i64; TIN_COUNT],
    /// Cross-tin fails absorbed as upstream-outage echoes (counted, never valve-moving).
    outage_absorbed_counter: i64,
    // ---- ★ #22 slice 3 · Rung E — the 5TH sch_cake gap (global-overload law) ----
    /// Heads shed by [`Self::overload_shed`] under global overload (counted, never silent).
    overload_shed_counter: i64,
}

impl TortaScheduler {
    /// Default construction — Legacy profile (the Kotlin no-arg path).
    pub fn new() -> Self {
        Self::with_profile(TortaProfile::Legacy)
    }

    /// Construct with a profile + the original tunables (CakeScheduler.kt:38-50).
    pub fn with_profile(profile: TortaProfile) -> Self {
        Self::with_tunables(
            profile,
            DEFAULT_TIN_WEIGHTS,
            DEFAULT_QUANTUM,
            DEFAULT_SET_ASSOC_WAYS,
            DEFAULT_CODEL_TARGET_MS,
            DEFAULT_CODEL_INTERVAL_MS,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_tunables(
        profile: TortaProfile,
        tin_weights: [i64; TIN_COUNT],
        quantum: i32,
        set_assoc_ways: usize,
        codel_target_ms: i64,
        codel_interval_ms: i64,
    ) -> Self {
        // CakeScheduler.kt:79-87 — G5 + AIOOBE guard: validate tin_weights length up front.
        // (Static [i64; TIN_COUNT] makes this trivially true; the check is preserved as intent.)

        let tin_weights_clamped = [
            tin_weights[0].max(1),
            tin_weights[1].max(1),
            tin_weights[2].max(1),
        ];
        let stride = [
            STRIDE_UNIT / tin_weights_clamped[0],
            STRIDE_UNIT / tin_weights_clamped[1],
            STRIDE_UNIT / tin_weights_clamped[2],
        ];

        // tin_buckets: [tin][way] -> HashMap<key, Flow>
        let tin_buckets = (0..TIN_COUNT)
            .map(|_| (0..set_assoc_ways).map(|_| HashMap::new()).collect())
            .collect();

        Self {
            profile,
            tin_weights,
            quantum,
            set_assoc_ways,
            codel_target_ms,
            codel_interval_ms,
            tins: [const { VecDeque::new() }; TIN_COUNT],
            aqm_dropped_counter: 0,
            aqm: if profile == TortaProfile::SoftCake {
                [TinAqm::new_soft(), TinAqm::new_soft(), TinAqm::new_soft()]
            } else {
                [TinAqm::new(), TinAqm::new(), TinAqm::new()]
            },
            tin_buckets,
            new_flows: [const { VecDeque::new() }; TIN_COUNT],
            old_flows: [const { VecDeque::new() }; TIN_COUNT],
            new_flow_run: [0; TIN_COUNT],
            tin_weights_clamped,
            stride,
            pass_: [0; TIN_COUNT],
            vtime: 0,
            aqm_depth: 0,
            shed_dropped_counter: 0,
            sparse_served_counter: 0,
            last_now_ms: 0,
            rtt_ceil_ms: 0.0,
            tin_last_fail_ms: [i64::MIN; TIN_COUNT],
            outage_absorbed_counter: 0,
            overload_shed_counter: 0,
        }
    }

    /// Per-tin WRR shape: `(configured_weight, clamped_weight, stride)` for each of the 3 tins.
    ///
    /// Reports the CONFIGURED weight alongside the CLAMPED one deliberately. They differ exactly
    /// when a configuration was invalid (`≤ 0`), and that difference is the only on-device evidence
    /// that a config was rescued rather than honoured. Reporting only the clamped value would make
    /// a broken config indistinguishable from a deliberate one — the operator would see a working
    /// scheduler and never learn their weight was ignored.
    ///
    /// The clamp is what keeps `STRIDE_UNIT / weight` from dividing by zero, which in Rust is a
    /// PANIC on the Beast's construction path. That it holds for every `i64` — including negatives
    /// — is proved in `D:\Lean\proofs\Proofs\TinStride.lean` (`clamp_ge_one`, `clamp_ne_zero`),
    /// together with the direction property that a heavier tin never waits longer
    /// (`heavier_tin_never_waits_longer`).
    pub fn tin_weight_table(&self) -> [(i64, i64, i64); TIN_COUNT] {
        [
            (
                self.tin_weights[0],
                self.tin_weights_clamped[0],
                self.stride[0],
            ),
            (
                self.tin_weights[1],
                self.tin_weights_clamped[1],
                self.stride[1],
            ),
            (
                self.tin_weights[2],
                self.tin_weights_clamped[2],
                self.stride[2],
            ),
        ]
    }

    /// DRR++ flow census: `(live_flows, distinct_endpoints, queued_probes)` across every tin.
    ///
    /// Reads `Flow::key` and `Flow::endpoint_idx`, which the scheduler carries for exactly this
    /// purpose. `distinct_endpoints` answers a question no aggregate depth can: whether the queue
    /// is one upstream backing up, or every upstream degrading at once. Those two states want
    /// opposite responses and look identical in a total-depth number.
    pub fn flow_census(&self) -> (usize, usize, usize) {
        let mut flows = 0usize;
        let mut queued = 0usize;
        let mut endpoints: Vec<i32> = Vec::new();
        for tin in &self.tin_buckets {
            for way in tin {
                for flow in way.values() {
                    flows += 1;
                    queued += flow.queue.len();
                    // `key` is the set-associative identity; `endpoint_idx` is the upstream it
                    // belongs to. Distinctness is over the endpoint, not the key: many flows can
                    // share one upstream, and that is precisely the case worth surfacing.
                    let _ = flow.key;
                    if !endpoints.contains(&flow.endpoint_idx) {
                        endpoints.push(flow.endpoint_idx);
                    }
                }
            }
        }
        (flows, endpoints.len(), queued)
    }

    // ---- Public read accessors (CakeScheduler.kt:155-167) ----
    pub fn aqm_dropped(&self) -> i64 {
        if self.profile == TortaProfile::Legacy {
            self.aqm_dropped_counter
        } else {
            self.shed_dropped_counter
        }
    }
    pub fn shed_dropped(&self) -> i64 {
        self.shed_dropped_counter
    }
    pub fn drr_sparse_served(&self) -> i64 {
        self.sparse_served_counter
    }
    /// Current valve drop probability of the busiest tin (max across tins) — for the dashboard.
    pub fn valve_prob(&self) -> f64 {
        if self.profile == TortaProfile::Legacy {
            0.0
        } else {
            self.aqm
                .iter()
                .map(|c| c.valve_prob)
                .fold(0.0_f64, f64::max)
        }
    }
    /// The valve drop-probability of ONE tin (the per-tin valve state for the advanced-depth dashboard).
    /// A pure READ of the pub [`TinAqm::valve_prob`] through the private `aqm` array — never a
    /// valve-logic change. 0.0 under the Legacy AQM (no adaptive valve runs).
    pub fn valve_prob_tin(&self, priority: ProbePriority) -> f64 {
        if self.profile == TortaProfile::Legacy {
            0.0
        } else {
            self.aqm[priority as usize].valve_prob
        }
    }
    /// Mochi-Dango escalation streak of the HOTTEST tin (max across tins) — the consecutive
    /// distinct-window fail streak that scales the valve step, `[0, MOCHI_STREAK_CAP]`. A pure
    /// READ; 0 under Legacy/Baseline (only the Mochi-Dango valve law counts a streak).
    pub fn valve_streak(&self) -> i64 {
        if self.profile == TortaProfile::SoftCake {
            self.aqm.iter().map(|c| c.fail_streak).max().unwrap_or(0)
        } else {
            0
        }
    }
    /// Soft-cake count memory of the HOTTEST tin (max across tins) — the CoDel drop-rate `count`
    /// remembered at the last dropping-exit (resumed on re-entry inside the memory window). A pure
    /// READ; 0 under Legacy/Baseline (only the Soft-cake law records it).
    pub fn soft_memory(&self) -> i64 {
        if self.profile == TortaProfile::SoftCake {
            self.aqm.iter().map(|c| c.exit_count).max().unwrap_or(0)
        } else {
            0
        }
    }
    /// Rung D — cross-tin fails absorbed as upstream-outage echoes (the Dango-Daikazoku law). A
    /// pure READ; 0 under Legacy/Baseline (only SoftCake runs the outage discrimination).
    /// ★ #22 slice 3 · Rung E — heads shed by the global-overload law (0 = never overloaded;
    /// honest zero in normal operation). The Beast dashboard's OVERLOAD tile reads this.
    pub fn overload_sheds(&self) -> i64 {
        self.overload_shed_counter
    }

    pub fn outage_absorbed(&self) -> i64 {
        self.outage_absorbed_counter
    }

    /// Rung D — feed a live RTT sample (ms) into the worst-case-RTT leaky ceiling that couples the
    /// CoDel interval to the path the traffic actually rides (RFC 8289 §4.2: interval on the order
    /// of a worst-case RTT; sch_cake only ever had static rtt presets fixed at qdisc creation).
    /// SoftCake-only by design: Legacy has no CoDel, and the pinned Baseline corpus must stay
    /// byte-identical.
    pub fn observe_rtt(&mut self, rtt_ms: f64) {
        if self.profile != TortaProfile::SoftCake || rtt_ms <= 0.0 {
            return;
        }
        self.rtt_ceil_ms = rtt_ms.max(self.rtt_ceil_ms * SOFT_RTT_CEIL_DECAY);
    }

    /// Rung D — the CoDel interval the shed law actually runs on: the configured value until RTT
    /// telemetry flows, then `clamp(ceiling, configured, SOFT_RTT_INTERVAL_CAP_MS)`. The Soft-cake
    /// count-memory window (`interval * SOFT_COUNT_MEMORY_INTERVALS`) rides the same value, so the
    /// drop-rate memory horizon scales with the path RTT too.
    fn effective_interval_ms(&self) -> i64 {
        if self.profile != TortaProfile::SoftCake || self.rtt_ceil_ms <= 0.0 {
            return self.codel_interval_ms;
        }
        (self.rtt_ceil_ms as i64).clamp(self.codel_interval_ms, SOFT_RTT_INTERVAL_CAP_MS)
    }

    pub fn pipeline_depth(&self) -> i64 {
        if self.profile == TortaProfile::Legacy {
            self.tins.iter().map(|q| q.len() as i64).sum()
        } else {
            self.aqm_depth
        }
    }
    pub fn queue_depth(&self, priority: ProbePriority) -> i64 {
        let tin = priority as usize;
        if self.profile == TortaProfile::Legacy {
            self.tins[tin].len() as i64
        } else {
            self.tin_depth(tin) as i64
        }
    }

    fn tin_depth(&self, tin: usize) -> usize {
        self.tin_buckets[tin]
            .iter()
            .map(|b| b.values().map(|f| f.queue.len()).sum::<usize>())
            .sum()
    }

    fn tin_has_work(&self, tin: usize) -> bool {
        !self.new_flows[tin].is_empty() || !self.old_flows[tin].is_empty()
    }

    // ============================ ENQUEUE (CakeScheduler.kt:183-230) ============================

    pub fn enqueue(&mut self, request: ProbeRequest) {
        if self.profile == TortaProfile::Legacy {
            self.tins[request.priority as usize].push_back(request);
            return;
        }
        self.enqueue_aqm(request);
    }

    fn enqueue_aqm(&mut self, request: ProbeRequest) {
        /// The flow-list transition decided under the ONE flow borrow, applied after it ends
        /// (the list deques need `&mut self`, which the live `&mut Flow` borrow excludes).
        enum ListMove {
            PromoteNew,
            DemoteOld,
            Stay,
        }

        // Rung B — advance the deterministic clock shadow (monotone).
        self.last_now_ms = self.last_now_ms.max(request.enqueued_at_ms);
        let tin = request.priority as usize;
        // H4 — SFQ RE-BASE ON ACTIVATION (CakeScheduler.kt:194-211). MUST be evaluated BEFORE we add
        // the probe (otherwise the tin is already "busy").
        let tin_was_idle = !self.tin_has_work(tin);
        let key = flow_key(request.endpoint_idx, &request.domain);
        let way = key.rem_euclid(self.set_assoc_ways as i64) as usize;

        // ONE bucket lookup (D37 — was three: `entry`, then a `get_mut` re-lookup, then ANOTHER
        // `get_mut` after `remove_new`, each guarded by an invariant-`expect`). Insert/lookup the
        // flow (Kotlin `getOrPut` semantics), push the probe, and decide + apply the flag
        // transition (CakeScheduler.kt:212-229) while the SAME `&mut Flow` borrow is live; the
        // list-membership deques are touched after the borrow ends. Semantics byte-identical.
        let flow = self.tin_buckets[tin][way]
            .entry(key)
            .or_insert_with(|| Flow::new(key, request.endpoint_idx));
        let had_backlog = !flow.queue.is_empty();
        flow.queue.push_back(request);
        let mv = if !flow.in_new && !flow.in_old {
            // DRR++ fast path: idle flow that just got a single query is "sparse" -> new-flows list.
            flow.deficit = 0;
            flow.in_new = true;
            ListMove::PromoteNew
        } else if had_backlog && flow.in_new {
            // A flow building a backlog (>=2 queued) is BULK: demote new->old.
            flow.in_new = false;
            flow.in_old = true;
            flow.deficit = 0;
            ListMove::DemoteOld
        } else {
            ListMove::Stay
        };

        self.aqm_depth += 1;
        if tin_was_idle {
            self.pass_[tin] = self.pass_[tin].max(self.vtime);
        }
        match mv {
            ListMove::PromoteNew => self.new_flows[tin].push_back(key),
            ListMove::DemoteOld => {
                self.remove_new(tin, key);
                self.old_flows[tin].push_back(key);
            }
            ListMove::Stay => {}
        }

        // ★ #22 slice 3 · Rung E — the global-overload law (SoftCake-only; Baseline stays the
        // faithful Kotlin-pinned port). Enforced AT ENQUEUE like sch_cake.c:2025-2033.
        if self.profile == TortaProfile::SoftCake && self.aqm_depth > AQM_GLOBAL_CAP {
            self.overload_shed();
        }
    }

    /// ★ #22 slice 3 · Rung E — THE 5TH sch_cake GAP: overload shed. `cake_drop` parity
    /// (sch_cake.c:1605-1667): the arrival is never rejected — the FATTEST flow's HEAD pays, and
    /// the shed tin's BLUE ramp gets the queue-full signal (cobalt_queue_full, :1640-1641 ⇒ our
    /// [`TinAqm::on_fail_at`]). THE SURPASS — a queue-management edge CAKE never handled: CAKE's
    /// overflow heap compares RAW BYTE BACKLOG alone (cake_heapify), so under overload it may
    /// shed from a fat-but-FRESH queue while an ancient head rots in one probe shorter; Tortä
    /// TIE-BREAKS equal-length flows by OLDEST HEAD SOJOURN — reclaiming memory AND latency in
    /// one stroke, deterministically. DROPPABILITY: only droppable heads are scanned (the
    /// CRITICAL floor-protection law); if every head is floor-protected the fattest flow pays
    /// regardless — RAM exhaustion kills the whole engine, worse than one SERVFAIL-fast.
    /// Flows emptied here are lazily retired by dispatch (`retire_flow_if_empty`).
    fn overload_shed(&mut self) {
        while self.aqm_depth > AQM_GLOBAL_CAP {
            // Scan pass 1: fattest flow with a DROPPABLE head; tie-break oldest head.
            // Scan pass 2 (only if pass 1 found nothing): fattest regardless of droppability.
            let mut pick: Option<(usize, i64, usize, i64)> = None; // (tin, key, len, head_ms)
            for droppable_only in [true, false] {
                for tin in 0..TIN_COUNT {
                    for bucket in &self.tin_buckets[tin] {
                        for (key, flow) in bucket {
                            let Some(head) = flow.queue.front() else {
                                continue;
                            };
                            if droppable_only && !is_droppable(head) {
                                continue;
                            }
                            let len = flow.queue.len();
                            let head_ms = head.enqueued_at_ms;
                            let better = match &pick {
                                None => true,
                                Some((_, _, plen, pms)) => {
                                    len > *plen || (len == *plen && head_ms < *pms)
                                }
                            };
                            if better {
                                pick = Some((tin, *key, len, head_ms));
                            }
                        }
                    }
                }
                if pick.is_some() {
                    break;
                }
            }
            let Some((tin, key, _, _)) = pick else {
                break; // no heads anywhere — depth bookkeeping says otherwise, stop rather than spin
            };
            if self.pop_head_of_flow(tin, key).is_none() {
                break;
            }
            self.aqm_depth -= 1;
            self.overload_shed_counter += 1;
            // BLUE queue-full parity (sch_cake.c:1640-1641 `cobalt_queue_full`).
            let now = self.last_now_ms;
            self.aqm[tin].on_fail_at(now);
        }
    }

    // ============================ DISPATCH (CakeScheduler.kt:234-344) ============================

    /// Drain up to `cwnd` probes. LEGACY = strict priority + overflow drop. Baseline = WRR/DRR++/sojourn.
    /// Uses an explicit `now_ms` for deterministic AQM sojourn (the Kotlin `dispatchAt` test seam).
    pub fn dispatch(&mut self, cwnd: i32, now_ms: i64) -> Vec<ProbeRequest> {
        if self.profile == TortaProfile::Legacy {
            return self.dispatch_legacy(cwnd);
        }
        self.dispatch_aqm(cwnd, now_ms)
    }

    fn dispatch_legacy(&mut self, cwnd: i32) -> Vec<ProbeRequest> {
        let cap = cwnd.max(0) as usize;
        let mut dispatched = Vec::with_capacity(cap);
        // Index is load-bearing: addresses parallel arrays self.tins + TIN_MAX_DEPTH.
        #[allow(clippy::needless_range_loop)]
        for tin_idx in 0..TIN_COUNT {
            if dispatched.len() >= cap {
                break;
            }
            while dispatched.len() < cap {
                let Some(probe) = self.tins[tin_idx].pop_front() else {
                    break;
                };
                // CakeScheduler.kt:257 — overflow/tail-drop: if REMAINING depth still exceeds limit, drop.
                if self.tins[tin_idx].len() > TIN_MAX_DEPTH[tin_idx] {
                    self.aqm_dropped_counter += 1;
                    continue;
                }
                dispatched.push(probe);
            }
        }
        dispatched
    }

    fn dispatch_aqm(&mut self, cwnd: i32, now_ms: i64) -> Vec<ProbeRequest> {
        // Rung B — advance the deterministic clock shadow (monotone).
        self.last_now_ms = self.last_now_ms.max(now_ms);
        let cap = (cwnd.max(0)) as usize;
        let mut dispatched = Vec::with_capacity(cap);
        if cap == 0 {
            return dispatched;
        }

        // H4 — STRIDE / virtual-time SFQ scheduling (CakeScheduler.kt:273-344). The commentary there
        // is the canonical record: a monotone global vtime, min-pass busy tin chosen (tie -> lower
        // index = priority), vtime = max(vtime, pass[chosen]) sampled BEFORE the serve, pass advances
        // by stride after a real dispatch. A returning idle tin is re-based UP to max(pass, vtime)
        // (enqueue_aqm) — never DOWN onto a starved tin's stale-low value.
        let mut busy_this_dispatch = [false; TIN_COUNT];
        while dispatched.len() < cap {
            // Pick the min virtual finish time among busy, not-yet-exhausted-this-dispatch tins
            // (tie -> lower tin index = priority). -1 => no servable tin left.
            let mut chosen: i32 = -1;
            // Index is load-bearing: addresses parallel arrays busy_this_dispatch + self.pass_.
            #[allow(clippy::needless_range_loop)]
            for tin in 0..TIN_COUNT {
                if busy_this_dispatch[tin] || !self.tin_has_work(tin) {
                    continue;
                }
                if chosen == -1 || self.pass_[tin] < self.pass_[chosen as usize] {
                    chosen = tin as i32;
                }
            }
            if chosen == -1 {
                break;
            }
            let chosen = chosen as usize;
            // SFQ: advance vtime to the start tag of the tin we are about to serve (monotone, max-guarded).
            self.vtime = self.vtime.max(self.pass_[chosen]);
            let probe = self.serve_one_from_tin(chosen, now_ms);
            if probe.is_none() {
                // Everything servable shed/empty this turn -> exclude for the rest of THIS dispatch;
                // pass NOT advanced (no virtual time charged for a non-dispatch).
                busy_this_dispatch[chosen] = true;
                continue;
            }
            // Real dispatch -> advance the chosen tin's start tag by its stride.
            self.pass_[chosen] += self.stride[chosen];
            dispatched.push(probe.unwrap());
        }

        // M2 (CakeScheduler.kt:327-342): reset the CoDel clock of every fully-drained tin so the next
        // standing queue starts with its full interval of grace; clear the consecutive-new-flow run.
        // SFQ NOTE — the drained tin's pass is DELIBERATELY NOT re-based here (frozen; corrected by the
        // max(pass,vtime) activation re-base on refill). Freezing is what eliminates cwnd=1 starvation.
        for t in 0..TIN_COUNT {
            if self.tin_depth(t) == 0 {
                self.aqm[t].on_drained_at(now_ms);
                self.new_flow_run[t] = 0;
            }
        }
        dispatched
    }

    /// DRR++ within one tin (CakeScheduler.kt:356-407): serve head of new-flows first (sparse fast path),
    /// else round-robin old-flows. the AQM sheds a head whose sojourn exceeds target once drop_next is due
    /// — but only droppable probes (CRITICAL real queries are floor-protected).
    fn serve_one_from_tin(&mut self, tin: usize, now_ms: i64) -> Option<ProbeRequest> {
        // Bound the inner work: at most the current tin depth + 1 of shed/skip attempts per call.
        let mut guard = self.tin_depth(tin) + 1;
        while guard > 0 {
            guard -= 1;

            let has_new = !self.new_flows[tin].is_empty();
            let has_old = !self.old_flows[tin].is_empty();
            // DRR++ flow selection: prefer sparse new-flows, BUT force a turn to old-flows once
            // NEW_FLOW_BURST consecutive new-flow serves happened and old work waits (M3).
            let sparse = has_new && !(has_old && self.new_flow_run[tin] >= NEW_FLOW_BURST);
            let head_key = if sparse {
                *self.new_flows[tin].front()?
            } else {
                *self.old_flows[tin].front()?
            };
            let way = head_key.rem_euclid(self.set_assoc_ways as i64) as usize;

            // Peek ONLY the two fields the sojourn/shed decision reads (D37 — the head used to be
            // `cloned()` whole, heap-copying its `domain: String` per iteration just to read a
            // timestamp + a priority; the clone was then discarded). No borrow held across the shed path.
            let head_probe = {
                let Some(flow) = self.tin_buckets[tin][way].get(&head_key) else {
                    // Flow was retired out-of-band — purge the stale list entry and continue.
                    self.purge_stale_list_entry(tin, head_key, sparse);
                    if !self.tin_has_work(tin) {
                        return None;
                    }
                    continue;
                };
                flow.queue
                    .front()
                    .map(|p| (p.enqueued_at_ms, is_droppable(p)))
            };

            let Some((head_enqueued_at_ms, droppable)) = head_probe else {
                // Flow drained -> retire it from whichever list it sits on (CakeScheduler.kt:370-374).
                self.retire_flow_if_empty(tin, head_key);
                if !self.tin_has_work(tin) {
                    return None;
                }
                continue;
            };

            // ---- AQM sojourn check (CakeScheduler.kt:376-388) ----
            let sojourn = (now_ms - head_enqueued_at_ms).max(0);
            // Rung D — the RTT-coupled clock: = codel_interval_ms until live RTT flows (SoftCake).
            let interval_ms = self.effective_interval_ms();
            let should_shed = {
                let cd = &mut self.aqm[tin];
                if droppable {
                    cd.should_shed(sojourn, now_ms, self.codel_target_ms, interval_ms)
                } else {
                    cd.on_good_or_undroppable_at(sojourn, self.codel_target_ms, now_ms);
                    false
                }
            };
            if droppable && should_shed {
                // SHED / SERVFAIL-fast, counted (never silent) (CakeScheduler.kt:381-385).
                let dropped = self.pop_head_of_flow(tin, head_key);
                if dropped.is_some() {
                    self.aqm_depth -= 1;
                    self.shed_dropped_counter += 1;
                }
                // If the flow is now empty, retire it.
                let empty = self.tin_buckets[tin][way]
                    .get(&head_key)
                    .map(|f| f.queue.is_empty())
                    .unwrap_or(true);
                if empty {
                    self.retire_flow_if_empty(tin, head_key);
                }
                continue; // try the next packet/flow
            }

            // ---- DRR++ deficit (CakeScheduler.kt:390-404) ----
            let out = self.pop_head_of_flow(tin, head_key);
            if out.is_none() {
                continue;
            }
            let out = out.unwrap();
            self.aqm_depth -= 1;
            // Grant a quantum on first visit; pay the serve cost (packet mode, cost = 1).
            {
                let flow = self.tin_buckets[tin][way]
                    .get_mut(&head_key)
                    .expect("flow present");
                if flow.deficit <= 0 {
                    flow.deficit += self.quantum;
                }
                flow.deficit -= 1;
            }
            if sparse {
                self.sparse_served_counter += 1;
                self.new_flow_run[tin] += 1; // M3: track the consecutive-new-flow run.
            } else {
                self.new_flow_run[tin] = 0; // an old-flow turn breaks the new-flow run.
            }

            // Rotate flow lists (CakeScheduler.kt:403, advanceFlow :413-429).
            self.advance_flow(tin, head_key, sparse);
            return Some(out);
        }
        None
    }

    /// Pop the head probe off a flow's queue (returns None if flow/queue absent).
    fn pop_head_of_flow(&mut self, tin: usize, key: i64) -> Option<ProbeRequest> {
        let way = key.rem_euclid(self.set_assoc_ways as i64) as usize;
        let flow = self.tin_buckets[tin][way].get_mut(&key)?;
        flow.queue.pop_front()
    }

    /// `advanceFlow` (CakeScheduler.kt:413-429): a served sparse flow becomes an old-flow; old-flows
    /// round-robin. Still-backlogged served flows demote to the tail of old-flows.
    fn advance_flow(&mut self, tin: usize, key: i64, was_sparse: bool) {
        // Remove the served entry from whichever list it was on (CakeScheduler.kt:414-420).
        if was_sparse {
            self.remove_new(tin, key);
        } else {
            self.remove_old(tin, key);
        }

        let way = key.rem_euclid(self.set_assoc_ways as i64) as usize;
        // Read + update the flow's flags + queue state (CakeScheduler.kt:421-428).
        let still_backlogged = match self.tin_buckets[tin][way].get_mut(&key) {
            None => false, // flow gone (retired out-of-band) — nothing to demote
            Some(flow) => {
                if was_sparse {
                    flow.in_new = false;
                } else {
                    flow.in_old = false;
                }
                if flow.queue.is_empty() {
                    false
                } else {
                    // Still has packets -> demote to the tail of old-flows (fair round-robin).
                    flow.deficit = 0;
                    flow.in_old = true;
                    true
                }
            }
        };

        if still_backlogged {
            self.old_flows[tin].push_back(key);
        } else {
            self.retire_flow_if_empty(tin, key);
        }
    }

    /// `retireFlowIfEmpty` (CakeScheduler.kt:431-438): remove an empty flow from its lists + bucket.
    fn retire_flow_if_empty(&mut self, tin: usize, key: i64) {
        let way = key.rem_euclid(self.set_assoc_ways as i64) as usize;
        let needs_removal = self.tin_buckets[tin][way]
            .get(&key)
            .map(|f| f.queue.is_empty())
            .unwrap_or(true);
        if !needs_removal {
            return;
        }
        // Clear list membership.
        let in_new = self.tin_buckets[tin][way]
            .get(&key)
            .map(|f| f.in_new)
            .unwrap_or(false);
        let in_old = self.tin_buckets[tin][way]
            .get(&key)
            .map(|f| f.in_old)
            .unwrap_or(false);
        if in_new {
            self.remove_new(tin, key);
        }
        if in_old {
            self.remove_old(tin, key);
        }
        // Drop the now-empty flow from its set-associative bucket so the way frees up.
        self.tin_buckets[tin][way].remove(&key);
    }

    fn remove_new(&mut self, tin: usize, key: i64) {
        if let Some(pos) = self.new_flows[tin].iter().position(|&k| k == key) {
            self.new_flows[tin].remove(pos);
        }
    }
    fn remove_old(&mut self, tin: usize, key: i64) {
        if let Some(pos) = self.old_flows[tin].iter().position(|&k| k == key) {
            self.old_flows[tin].remove(pos);
        }
    }

    fn purge_stale_list_entry(&mut self, tin: usize, key: i64, from_new: bool) {
        if from_new {
            self.remove_new(tin, key);
        } else {
            self.remove_old(tin, key);
        }
    }

    /// Adaptive-valve hooks (CakeScheduler.kt:442-451): a real timeout/fail raises the tin's valve_prob.
    ///
    /// Rung D — the Dango-Daikazoku OUTAGE LAW runs first under SoftCake: a fail landing within
    /// [`DANGO_OUTAGE_WINDOW_MS`] of a fail on a DIFFERENT tin is a correlated upstream outage
    /// (one skewer, many dangos) — absorbed (counted, never valve-moving). The first fail of the
    /// burst already moved its own tin's valve; punishing the other tins' innocent queues for an
    /// infrastructure death is the edge a qdisc could never see (sch_cake.c:459-478 fires per-flow
    /// with no cross-class view) and the YeAH failover machinery owns the real problem.
    pub fn on_timeout_or_fail(&mut self, priority: ProbePriority) {
        if self.profile == TortaProfile::Legacy {
            return;
        }
        let tin = priority as usize;
        if self.profile == TortaProfile::SoftCake {
            let now = self.last_now_ms;
            // saturating_sub handles the i64::MIN "never" sentinel (diff saturates to i64::MAX).
            let correlated = self
                .tin_last_fail_ms
                .iter()
                .enumerate()
                .any(|(t, &at)| t != tin && now.saturating_sub(at) < DANGO_OUTAGE_WINDOW_MS);
            self.tin_last_fail_ms[tin] = now;
            if correlated {
                self.outage_absorbed_counter += 1;
                return;
            }
        }
        self.aqm[tin].on_fail_at(self.last_now_ms);
    }
    pub fn on_success(&mut self, priority: ProbePriority) {
        if self.profile == TortaProfile::Legacy {
            return;
        }
        self.aqm[priority as usize].on_success_at(self.last_now_ms);
    }
}

impl Default for TortaScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// (endpoint_idx, qname) -> 64-bit flow key (CakeScheduler.kt:454-459). FNV-ish, exact.
fn flow_key(endpoint_idx: i32, qname: &str) -> i64 {
    let mut h: i64 = 1125899906842597; // FNV-ish seed
    h = 31i64.wrapping_mul(h).wrapping_add(endpoint_idx as i64);
    for c in qname.chars() {
        h = 31i64.wrapping_mul(h).wrapping_add(c as i64);
    }
    h
}

/// Mirrors the Kotlin `isDroppable` (CakeScheduler.kt:410-411): a probe (liveness ping / non-CRITICAL)
/// is droppable; a CRITICAL real query is floor-protected.
fn is_droppable(req: &ProbeRequest) -> bool {
    req.priority != ProbePriority::Critical
}

/// The tin-weight clamp and the flow census.
///
/// The clamp law these pin is PROVED for every `i64` in `D:\Lean\proofs\Proofs\TinStride.lean`
/// (`clamp_ge_one`, `clamp_ne_zero`, `heavier_tin_never_waits_longer`). These tests exist to keep
/// the Rust and the model from drifting apart: a proof about a function the code no longer computes
/// is worse than no proof, because it still reads as a guarantee.
#[cfg(test)]
mod tin_weight_clamp_tests {
    use super::*;

    fn sched_with(weights: [i64; TIN_COUNT]) -> TortaScheduler {
        TortaScheduler::with_tunables(TortaProfile::SoftCake, weights, 1024, 8, 5, 100)
    }

    /// A ZERO weight would divide by zero and PANIC without the clamp. This test reaching its
    /// assertions at all is the evidence.
    #[test]
    fn a_zero_weight_does_not_panic_and_clamps_to_one() {
        let s = sched_with([0, 50, 12]);
        let t = s.tin_weight_table();
        assert_eq!(t[0].0, 0, "the CONFIGURED weight is reported unchanged");
        assert_eq!(
            t[0].1, 1,
            "the clamp floors it at 1 -- this is what averts the panic"
        );
        assert_eq!(
            t[0].2, STRIDE_UNIT,
            "a rescued weight gets the MAXIMUM stride: de-prioritised, never dropped"
        );
    }

    /// Negative weights are reachable from configuration too.
    #[test]
    fn negative_weights_clamp_to_one() {
        let s = sched_with([-1, -9_999_999, i64::MIN]);
        for (i, (configured, clamped, stride)) in s.tin_weight_table().into_iter().enumerate() {
            assert!(configured <= 0, "tin {i} was configured non-positive");
            assert_eq!(clamped, 1, "tin {i} clamps to 1");
            assert_eq!(stride, STRIDE_UNIT, "tin {i} gets the maximum stride");
        }
    }

    /// The clamp does NOT rewrite a valid configuration -- it only rescues a broken one.
    #[test]
    fn valid_weights_pass_through_untouched() {
        let s = sched_with([100, 50, 12]);
        let t = s.tin_weight_table();
        assert_eq!((t[0].0, t[0].1), (100, 100));
        assert_eq!((t[1].0, t[1].1), (50, 50));
        assert_eq!((t[2].0, t[2].1), (12, 12));
    }

    /// The direction property: a heavier tin never waits longer. Proved for all integers in Lean;
    /// pinned here on the shipped shares so the two cannot drift.
    #[test]
    fn heavier_tins_never_wait_longer() {
        let s = sched_with([100, 50, 12]);
        let t = s.tin_weight_table();
        assert!(
            t[0].2 <= t[1].2 && t[1].2 <= t[2].2,
            "stride must be non-increasing in weight, got {:?}",
            [t[0].2, t[1].2, t[2].2]
        );
        assert!(
            t[0].2 < t[2].2,
            "NON-VACUITY: the strides genuinely differ, so the ordering above is not comparing \
             three equal numbers"
        );
    }

    /// An idle scheduler reports an honestly empty census, never a fabricated one.
    #[test]
    fn an_idle_scheduler_reports_an_empty_census() {
        let s = sched_with([100, 50, 12]);
        assert_eq!(s.flow_census(), (0, 0, 0));
    }
}
