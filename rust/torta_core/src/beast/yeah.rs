/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! YeAH congestion control over the probe-concurrency window (cwnd, 1..16).
//!
//! FAITHFUL 1:1 PORT of `YeahController.kt:35-328` (the Socio's Kotlin original, itself a port of
//! `MonokumaTcpDnsEngine.ApplyYeahTcp`). Pure logic — no sockets, no Android — so it is unit-testable
//! against the exact Kotlin/C# state transitions (the pinned `YeahControllerTest.kt` corpus ports 1:1).
//!
//! Phases: SLOW-START (cwnd doubles on free bandwidth) -> first competition halves cwnd and leaves
//! slow-start -> YEAH (additive +1 on free bandwidth) <-> COMPETING (halve on congestion) -> RECOVERY
//! (+0.5/cycle back toward YEAH). EWMA-smoothed base_rtt; thresholds relative to it.
//!
//! Three brains share one struct:
//! - [`YeahProfile::Legacy`] (default): the original state machine UNCHANGED — byte-identical to the
//!   Kotlin no-arg path. The pinned transitions + `adaptive_timeout_ms` math run exactly this.
//! - [`YeahProfile::Canonical`]: the real YeAH brain — a separate true-min `rtt_base_floor` feeds
//!   `Q = (rtt - floor) * (cwnd / rtt)` (Little's law backlog), fast/slow gating on PHI,
//!   precautionary decongestion (shed BEFORE loss when `Q > cwnd * Q_MAX_FRAC`), and a
//!   gentle-when-isolated / full-halve-only-under-contention `on_loss_or_timeout`.
//! - [`YeahProfile::LineRate`] (Rung C — "YeAH TCP/UDP LineRate", SAIMONOKUMA 2026): the surpassing
//!   brain. UDP RTT samples become FIRST-CLASS congestion inputs (per-family true-min floors, no
//!   cross-family floor poisoning, half-weight STCP growth) — the Socio's original YeAH TCP/UDP idea
//!   made structural. Kernel-grade hysteresis (`tcp_yeah_vegas.c`): competition memory survives until
//!   `LR_ZETA` consecutive fast samples (:191-196), a precautionary shed needs `LR_SHED_CONFIRM`
//!   consecutive over-threshold samples (:143), and loss keeps HALF the memory (:233). The loss rule
//!   is the whitepaper's, direction-correct: `cwnd -= clamp(Q_smooth, cwnd>>LR_DELTA_SHIFT, cwnd>>1)`
//!   (YeAH-TCP paper §3; tcp_yeah_vegas.c:223-228) — a random loss with an empty queue costs cwnd/8,
//!   a loss on a self-built queue drains a full half.
//!
//! Thread-safety in Kotlin was `@Synchronized` (`YeahController.kt:127,273,299,308`). In Rust the
//! whole [`Beast`](super::Beast) scheduler state lives behind one `Mutex` (the AQM path is stateful
//! across calls), so this controller itself is single-threaded logic operated under that lock.

#![forbid(unsafe_code)]

use crate::beast::{YeahMode, YeahProfile};

// ---- Constants (YeahController.kt:48-80, verbatim) ----
pub const MIN_WINDOW: i32 = 1;
pub const MAX_WINDOW: i32 = 16;
pub const EWMA_ALPHA: f64 = 0.125;
pub const YEAH_FREE_THRESH: f64 = 1.05;
pub const YEAH_COMPETE_THRESH: f64 = 1.25;
pub const FAILOVER_THRESH: f64 = 3.0;

// Canonical YeAH params (YeahController.kt:56-79). Legacy never reads these.
pub const PHI: f64 = 8.0;
pub const Q_MAX_FRAC: f64 = 0.5;
pub const GAMMA: f64 = 1.0;
pub const EPSILON_SHIFT: u32 = 3;
pub const RHO: i32 = 16;
pub const STCP_AI: i32 = 8;
pub const FLOOR_LEAK: f64 = 1.02;

// LineRate params (Rung C — "YeAH TCP/UDP LineRate", SAIMONOKUMA 2026). Legacy/Canonical never
// read these.
/// Consecutive FAST samples before the competition memory (`reno_count`) resets — the kernel ZETA
/// law (tcp_yeah_vegas.c:23,191-196; kernel ZETA=50 per-RTT, scaled to per-sample cadence over the
/// 16-probe window).
pub const LR_ZETA: i32 = 16;
/// Consecutive over-threshold samples before a precautionary shed fires — the kernel never judged
/// on fewer than 3 RTT samples (tcp_yeah_vegas.c:143); one spike holds the window.
pub const LR_SHED_CONFIRM: i32 = 2;
/// EWMA weight for `q_smooth` — the multi-sample queue memory feeding the loss rule (the kernel's
/// `lastQ` was a whole-RTT min-filter, tcp_yeah_vegas.c:158,201; Canonical degraded it to one raw
/// sample).
pub const LR_Q_EWMA_ALPHA: f64 = 0.25;
/// Minimum loss reduction shift: `cwnd >> 3` = cwnd/8 (kernel DELTA=3, tcp_yeah_vegas.c:19,228).
pub const LR_DELTA_SHIFT: u32 = 3;
/// UDP fast samples feed the STCP growth counter every Nth sample (half weight) — UDP dominates a
/// DNSCrypt engine's traffic, so it drives the window, but gently.
pub const LR_UDP_GROWTH_INTERVAL: i32 = 2;
/// ★ #22 slice 3 — LOCAL-ECHO GATE (ms): a sample below this is a LOOPBACK/local-path echo
/// (resolver cache hit ~0.2ms, localhost dial), not a network measurement. The kernel never
/// needed this — TCP-stack RTTs are always wire RTTs; a DNS app's samples can be local echoes.
/// The poison asymmetry: base-RTT EWMAs recover from one echo, but a TRUE-MIN FLOOR never does —
/// one 0.2ms echo into `udp_floor` and every real 20ms answer reads delay 19.8, L≈100 ⇒ permanent
/// congestion verdict. Android's radio/Wi-Fi path never legitimately beats 1ms; localhost does.
pub const LR_LOCAL_ECHO_MS: f64 = 1.0;

/// Rung C+ FAIR-SHARE floor minimum — the kernel's `reno_count` fair-share estimate never sits
/// below 2 once learned (tcp_yeah.c:51 init, :154 seed gate, :204 loss floor). Below this value
/// our `fair_cwnd` means UNLEARNED (0) — no competition evidence yet, no floor in force.
pub const LR_FAIR_MIN: i32 = 2;

/// Which traffic family produced an RTT sample — LineRate judges each against its OWN true-min
/// floor (UDP is structurally cheaper than a TCP transaction; one shared floor would poison the
/// slower family's delay estimate).
#[derive(Clone, Copy)]
enum SampleFamily {
    Tcp,
    Udp,
}

/// YeAH congestion controller — the probe-concurrency window state machine.
///
/// Every field mirrors a Kotlin field 1:1 (cwnd, mode, base_rtt, cwnd_frac, slow_start, plus the
/// canonical-only rtt_base_floor / q_packets / reno_count / fast_mode / cwnd_cnt).
#[derive(Debug, Clone)]
pub struct YeahController {
    pub max_window: i32,
    pub free_thresh: f64,
    pub compete_thresh: f64,
    pub profile: YeahProfile,
    // Canonical-only tunables (ignored on Legacy).
    q_max_frac: f64,
    rho: i32,
    phi: f64,
    gamma: f64,
    epsilon_shift: u32,
    stcp_ai: i32,

    // Shared state (YeahController.kt:82-95).
    cwnd: i32,
    mode: YeahMode,
    base_rtt: f64,
    cwnd_frac: f64,
    slow_start: bool,

    // Canonical-only state (YeahController.kt:97-125). Untouched on Legacy.
    rtt_base_floor: f64,
    q_packets: f64,
    reno_count: i32,
    fast_mode: bool,
    cwnd_cnt: i32,

    // LineRate-only state (Rung C). Untouched on Legacy/Canonical.
    fast_streak: i32,
    congest_streak: i32,
    /// ★ #22 slice 3 — the kernel's FIRST variable verbatim (tcp_yeah.c:35 `doing_reno_now`):
    /// CONSECUTIVE congested samples, +1 saturating at 0xffffff (:159-160), snapped to 0 by ANY
    /// non-congested sample (:169 — one clean RTT and the streak is gone). Distinct from BOTH
    /// `reno_count` (ZETA-memory: survives fast gaps < LR_ZETA) and `congest_streak` (shed
    /// confirmation: consumed/reset when a shed fires). This is the RHO STRICTNESS gate the loss
    /// rule reads (:194 `doing_reno_now < TCP_YEAH_RHO` ⇒ surgical, else Reno halve) — sustained
    /// UNINTERRUPTED competition alone earns the halving; intermittent congestion, however much
    /// of it the ZETA memory holds, takes the measured-queue backoff. The kernel's SECOND use —
    /// growth-mode selector (tcp_yeah.c:72, ns-3 yeah.cc:207: STCP only while `!doing_reno_now`,
    /// Reno-linear otherwise) — holds STRUCTURALLY here: STCP fires only in the fast branch where
    /// this is by construction 0; the middle zone's +1 IS the linear fallback. LineRate-only.
    doing_reno_now: i32,
    /// Rung C+ — the FAIR-SHARE estimate (the kernel's true second variable, tcp_yeah.c:37
    /// `reno_count`, distinct from `doing_reno_now`): the window this flow can defend while
    /// competing. Seeded at `cwnd/2` on first congestion evidence (:154-155), creeps +1 per
    /// congested sample (:157), floors every PRECAUTIONARY shed (:147-148 — a real loss still
    /// bites to `MIN_WINDOW`; the kernel floors loss at absolute 2, never at the fair share),
    /// halves on loss (:204), unlearns (0) on ZETA-fill/failover. LineRate-only.
    fair_cwnd: i32,
    q_smooth: f64,
    udp_floor: f64,
    udp_tick: i32,
    /// ★ THE INDEPENDENT UDP WINDOW (Rung D). The UDP family's OWN congestion brain — not a view of
    /// the TCP one, not a rate-limited co-driver of it. Before this field existed, a UDP sample grew
    /// and shed `self.cwnd`, the window TCP was using; `Proofs/YeahUdpIndependence.lean` proves that
    /// design is NOT independent (`the_shared_design_is_not_independent`: one UDP grow moves a TCP
    /// window from 1 to 2) and proves this one IS, for every interleaving of samples in any order
    /// (`the_split_design_is_independent`). LineRate-only: Legacy and Canonical never read it.
    udp_brain: Brain,
}

/// One family's complete congestion brain — every field a LineRate decision writes.
///
/// The TCP family's brain is the flat `YeahController` fields (so Legacy, Canonical, every accessor
/// and every snapshot see exactly what they saw before); the UDP family's is `udp_brain`. The split
/// is what makes YeAH TCP/UDP the name it claims to be: `Proofs/YeahUdpIndependence.lean` names this
/// exact set as the state that must be duplicated — "the whole window brain, not just the floor".
#[derive(Clone, Copy, Debug, PartialEq)]
struct Brain {
    cwnd: i32,
    cwnd_cnt: i32,
    cwnd_frac: f64,
    /// The family's OWN smoothed baseline. Legacy and Canonical judge every sample against this, so
    /// without a per-family copy those two profiles could not have an independent UDP algorithm at
    /// all — a UDP sample would move the baseline TCP is judged against.
    base_rtt: f64,
    mode: YeahMode,
    slow_start: bool,
    q_packets: f64,
    q_smooth: f64,
    reno_count: i32,
    fast_mode: bool,
    fast_streak: i32,
    congest_streak: i32,
    doing_reno_now: i32,
    fair_cwnd: i32,
}

impl Brain {
    /// The same starting state a fresh controller gives the TCP family (`with_profile`).
    const fn fresh() -> Self {
        Self {
            cwnd: MIN_WINDOW,
            cwnd_cnt: 0,
            cwnd_frac: 1.0,
            base_rtt: 0.0,
            mode: YeahMode::SlowStart,
            slow_start: true,
            q_packets: 0.0,
            q_smooth: 0.0,
            reno_count: 0,
            fast_mode: false,
            fast_streak: 0,
            congest_streak: 0,
            doing_reno_now: 0,
            fair_cwnd: 0,
        }
    }
}

impl YeahController {
    /// Default construction — Legacy profile, original constants (the Kotlin no-arg path).
    pub fn new() -> Self {
        Self::with_profile(YeahProfile::Legacy)
    }

    /// Construct with a profile + the original tunables (YeahController.kt:35-47).
    pub fn with_profile(profile: YeahProfile) -> Self {
        Self {
            max_window: MAX_WINDOW,
            free_thresh: YEAH_FREE_THRESH,
            compete_thresh: YEAH_COMPETE_THRESH,
            profile,
            q_max_frac: Q_MAX_FRAC,
            rho: RHO,
            phi: PHI,
            gamma: GAMMA,
            epsilon_shift: EPSILON_SHIFT,
            stcp_ai: STCP_AI,
            cwnd: MIN_WINDOW,
            mode: YeahMode::SlowStart,
            base_rtt: 0.0,
            cwnd_frac: 1.0,
            slow_start: true,
            rtt_base_floor: 0.0,
            q_packets: 0.0,
            reno_count: 0,
            fast_mode: false,
            cwnd_cnt: 0,
            fast_streak: 0,
            congest_streak: 0,
            doing_reno_now: 0,
            fair_cwnd: 0,
            q_smooth: 0.0,
            udp_floor: 0.0,
            udp_tick: 0,
            udp_brain: Brain::fresh(),
        }
    }

    /// Load a family's brain. TCP's lives in the flat fields; UDP's in `udp_brain`.
    fn load_brain(&self, family: SampleFamily) -> Brain {
        match family {
            SampleFamily::Tcp => Brain {
                cwnd: self.cwnd,
                cwnd_cnt: self.cwnd_cnt,
                cwnd_frac: self.cwnd_frac,
                base_rtt: self.base_rtt,
                mode: self.mode,
                slow_start: self.slow_start,
                q_packets: self.q_packets,
                q_smooth: self.q_smooth,
                reno_count: self.reno_count,
                fast_mode: self.fast_mode,
                fast_streak: self.fast_streak,
                congest_streak: self.congest_streak,
                doing_reno_now: self.doing_reno_now,
                fair_cwnd: self.fair_cwnd,
            },
            SampleFamily::Udp => self.udp_brain,
        }
    }

    /// Store a family's brain back. Load/store is the IDENTITY on the TCP side, which is why the
    /// TCP path's behaviour is bit-for-bit what it was before the split.
    fn store_brain(&mut self, family: SampleFamily, b: Brain) {
        match family {
            SampleFamily::Tcp => {
                self.cwnd = b.cwnd;
                self.cwnd_cnt = b.cwnd_cnt;
                self.cwnd_frac = b.cwnd_frac;
                self.base_rtt = b.base_rtt;
                self.mode = b.mode;
                self.slow_start = b.slow_start;
                self.q_packets = b.q_packets;
                self.q_smooth = b.q_smooth;
                self.reno_count = b.reno_count;
                self.fast_mode = b.fast_mode;
                self.fast_streak = b.fast_streak;
                self.congest_streak = b.congest_streak;
                self.doing_reno_now = b.doing_reno_now;
                self.fair_cwnd = b.fair_cwnd;
            }
            SampleFamily::Udp => self.udp_brain = b,
        }
    }

    /// ★ The INDEPENDENT UDP congestion window. On LineRate this is computed from UDP samples
    /// alone — `Proofs/YeahUdpIndependence.lean::split_udp_is_udp_alone` proves it equals what a
    /// UDP-only controller would compute with no TCP flow in existence. On Legacy/Canonical, where
    /// no independent UDP brain runs, it reports the shared window so callers see one truth.
    pub fn udp_cwnd(&self) -> i32 {
        self.udp_brain.cwnd
    }

    /// The UDP family's phase, on whichever profile is active. -/
    pub fn udp_mode(&self) -> YeahMode {
        self.udp_brain.mode
    }

    /// #49 — override the live YeAH tunables (the Beast SETTINGS Expert knobs). Each 0 leaves that field at
    /// its profile default; a positive value bites the NEXT `apply()` (all three are read live in the window
    /// algorithm — `max_window` caps every cwnd growth, `free_thresh`/`compete_thresh` gate the phase logic).
    /// The free-flow / competing thresholds arrive in milli-units from the host (beast_clamp field 2/3) so a
    /// whole-number stepper can carry the 1.05 / 1.25 ratios as 1050 / 1250.
    pub fn set_tunables(
        &mut self,
        max_window: i32,
        free_thresh_milli: i32,
        compete_thresh_milli: i32,
    ) {
        if max_window > 0 {
            self.max_window = max_window;
        }
        if free_thresh_milli > 0 {
            self.free_thresh = free_thresh_milli as f64 / 1000.0;
        }
        if compete_thresh_milli > 0 {
            self.compete_thresh = compete_thresh_milli as f64 / 1000.0;
        }
    }

    // ---- Read accessors (the @Volatile var ... private set surface) ----
    pub fn max_window(&self) -> i32 {
        self.max_window
    }
    pub fn cwnd(&self) -> i32 {
        self.cwnd
    }
    pub fn mode(&self) -> YeahMode {
        self.mode
    }
    pub fn base_rtt(&self) -> f64 {
        self.base_rtt
    }
    /// Canonical true-min RTT floor (YeahController.kt:103). Exposed for tests + the Beast snapshot;
    /// gated by `dead_code` because the non-test lib build only reads it via the canonical path.
    pub fn rtt_base_floor(&self) -> f64 {
        self.rtt_base_floor
    }
    pub fn q_packets(&self) -> f64 {
        self.q_packets
    }
    pub fn reno_count(&self) -> i32 {
        self.reno_count
    }
    pub fn fast_mode(&self) -> bool {
        self.fast_mode
    }

    // ---- LineRate-only read accessors (Rung C telemetry — the Wiring dashboard surface). ----
    // All four are typed pass-throughs of real state fields; they stay 0/0.0 under
    // Legacy/Canonical (which never write the LineRate state).

    /// Multi-sample queue memory (`q_smooth` EWMA, [`LR_Q_EWMA_ALPHA`]) — the LineRate loss
    /// rule's actual input.
    pub fn q_smooth(&self) -> f64 {
        self.q_smooth
    }
    /// UDP-family true-min RTT floor — under LineRate each family judges delay against its OWN
    /// floor (`rtt_base_floor` doubles as the TCP floor).
    pub fn udp_floor(&self) -> f64 {
        self.udp_floor
    }
    /// ZETA hysteresis streak — consecutive FAST samples toward [`LR_ZETA`]; the competition
    /// memory (`reno_count`) survives until it fills.
    pub fn fast_streak(&self) -> i32 {
        self.fast_streak
    }
    /// Shed-confirmation streak — consecutive over-threshold samples toward [`LR_SHED_CONFIRM`];
    /// one spike holds the window.
    pub fn congest_streak(&self) -> i32 {
        self.congest_streak
    }

    /// ★ #22 slice 3 — consecutive congested samples (the kernel `doing_reno_now`, tcp_yeah.c:35);
    /// 0 the instant any non-congested sample lands. The #25 Beast dashboard lift will consume this.
    pub fn doing_reno_now(&self) -> i32 {
        self.doing_reno_now
    }
    /// Rung C+ fair-share estimate (`fair_cwnd`) — the window this flow can defend while
    /// competing (tcp_yeah.c:37); 0 = unlearned. WIRED: carried by `BeastSnapshot::fair_cwnd`.
    pub fn fair_cwnd(&self) -> i32 {
        self.fair_cwnd
    }

    /// ★ Rung D — the UDP family's OWN fair-share estimate. Learned from UDP congestion evidence
    /// alone, so it can never be seeded or floored by what the TCP flow saw.
    pub fn udp_fair_cwnd(&self) -> i32 {
        self.udp_brain.fair_cwnd
    }

    /// `apply(rtt)` — the per-sample window update (YeahController.kt:127-177 legacy, :186-262
    /// canonical). Samples arriving here are TCP-family (probe transactions).
    pub fn apply(&mut self, rtt: f64) {
        // HARDENING — NaN/±inf never enter the brains: every inner guard is `rtt <= 0.0`,
        // which NaN sails PAST (IEEE comparisons with NaN are false), and ONE NaN sample
        // poisons the q_smooth EWMA permanently (0.75·NaN + x = NaN forever). ±inf same.
        if !rtt.is_finite() {
            return;
        }
        self.apply_family(rtt, SampleFamily::Tcp);
    }

    /// ★ Rung D — the profile dispatch, PER FAMILY. Every profile now runs its own formulae on the
    /// sample's own brain, so all three have an independent UDP congestion algorithm — Legacy's
    /// threshold state machine, Canonical's Little's-law backlog, LineRate's kernel-hysteresis
    /// brain. The formulae differ; the independence law is the same one, proved once for all of
    /// them in `Proofs/YeahUdpIndependence.lean` (the verdict is abstract there precisely so the
    /// result does not depend on WHICH profile computed it).
    fn apply_family(&mut self, rtt: f64, family: SampleFamily) {
        match self.profile {
            YeahProfile::Canonical => {
                self.apply_canonical_family(rtt, family);
                return;
            }
            YeahProfile::LineRate => {
                self.apply_linerate(rtt, family);
                return;
            }
            YeahProfile::Legacy => {}
        }
        // ---- LEGACY (the original ApplyYeahTcp, YeahController.kt:134-176) ----
        let mut b = self.load_brain(family);
        if b.base_rtt <= 0.0 {
            b.base_rtt = rtt;
            b.mode = YeahMode::SlowStart;
            b.slow_start = true;
            self.store_brain(family, b);
            return;
        }

        if b.slow_start {
            if rtt < b.base_rtt * self.compete_thresh {
                // Free bandwidth -> exponential growth (YeahController.kt:145-147)
                b.cwnd = (b.cwnd * 2).min(self.max_window);
                b.mode = YeahMode::SlowStart;
                b.base_rtt = (1.0 - EWMA_ALPHA) * b.base_rtt + EWMA_ALPHA * rtt;
            } else {
                // First congestion -> exit slow-start (YeahController.kt:149-153)
                b.slow_start = false;
                b.cwnd_frac = b.cwnd as f64 / 2.0;
                b.cwnd = (b.cwnd_frac as i32).max(MIN_WINDOW);
                b.mode = YeahMode::Competing;
            }
            self.store_brain(family, b);
            return;
        }

        if rtt < b.base_rtt * self.free_thresh {
            if b.mode == YeahMode::Recovery {
                b.cwnd_frac = (b.cwnd_frac + 0.5).min(self.max_window as f64);
                b.cwnd = b.cwnd_frac as i32;
                if b.cwnd_frac >= b.cwnd as f64 {
                    b.mode = YeahMode::Yeah;
                }
            } else {
                b.cwnd = (b.cwnd + 1).min(self.max_window);
                b.mode = YeahMode::Yeah;
            }
            b.base_rtt = (1.0 - EWMA_ALPHA) * b.base_rtt + EWMA_ALPHA * rtt;
        } else if rtt > b.base_rtt * self.compete_thresh {
            b.cwnd_frac = b.cwnd as f64 / 2.0;
            b.cwnd = (b.cwnd_frac as i32).max(MIN_WINDOW);
            b.mode = YeahMode::Competing;
        } else {
            // Stable zone: hold mode (COMPETING settles into RECOVERY), smooth baseRtt
            // (YeahController.kt:173-176)
            if b.mode == YeahMode::Competing {
                b.mode = YeahMode::Recovery;
            }
            b.base_rtt = (1.0 - EWMA_ALPHA) * b.base_rtt + EWMA_ALPHA * rtt;
        }
        self.store_brain(family, b);
    }

    /// ★ Rung D — Canonical, PER FAMILY. Same formulae as before (Little's-law backlog, PHI gating,
    /// precautionary decongestion), now computed against the sample's own floor and written to the
    /// sample's own window. Canonical therefore has an independent UDP congestion algorithm too, not
    /// just LineRate — the formulae differ between profiles, the independence law does not.
    fn apply_canonical_family(&mut self, rtt: f64, family: SampleFamily) {
        if rtt <= 0.0 {
            return;
        }
        let mut b = self.load_brain(family);
        // Seed both estimators on the very first sample (YeahController.kt:190-198).
        if self.family_floor(family) <= 0.0 {
            self.set_family_floor(family, rtt);
            b.base_rtt = rtt;
            b.mode = YeahMode::SlowStart;
            b.slow_start = true;
            b.q_packets = 0.0;
            b.fast_mode = false;
            b.reno_count = 0;
            self.store_brain(family, b);
            return;
        }

        // Leaky-bucket true-min (YeahController.kt:203): drop to a new min, else drift up x1.02.
        let floor = rtt.min(self.family_floor(family) * FLOOR_LEAK);
        self.set_family_floor(family, floor);
        // Keep the EWMA base_rtt alive for timeouts/metrics — never drives canonical decisions.
        b.base_rtt = (1.0 - EWMA_ALPHA) * b.base_rtt + EWMA_ALPHA * rtt;

        let delay = (rtt - floor).max(0.0);
        let l = delay / floor;
        let q = delay * (b.cwnd as f64 / rtt);
        b.q_packets = q;

        let q_threshold = b.cwnd as f64 * self.q_max_frac;

        // ---- Slow-start (YeahController.kt:217-231) ----
        if b.slow_start {
            if q < q_threshold && l < 1.0 / self.phi {
                b.cwnd = (b.cwnd * 2).min(self.max_window);
                b.mode = YeahMode::SlowStart;
                b.reno_count = 0;
            } else {
                b.slow_start = false;
                b.cwnd_frac = b.cwnd as f64 / 2.0;
                b.cwnd = (b.cwnd_frac as i32).max(MIN_WINDOW);
                b.mode = YeahMode::Competing;
                b.reno_count += 1;
            }
            b.fast_mode = q < q_threshold && l < 1.0 / self.phi;
            self.store_brain(family, b);
            return;
        }

        if q < q_threshold && l < 1.0 / self.phi {
            // FAST: STCP scalable increase (YeahController.kt:235-246).
            b.fast_mode = true;
            b.reno_count = 0;
            let period = (b.cwnd.max(1)).min(self.stcp_ai);
            b.cwnd_cnt += 1;
            if b.cwnd_cnt >= period {
                b.cwnd = (b.cwnd + 1).min(self.max_window);
                b.cwnd_cnt = 0;
            }
            b.mode = YeahMode::Yeah;
        } else if q > q_threshold {
            // PRECAUTIONARY DECONGESTION (YeahController.kt:248-254): shed BEFORE any loss.
            b.fast_mode = false;
            b.reno_count += 1;
            let shed = (q / self.gamma).min((b.cwnd >> self.epsilon_shift) as f64);
            b.cwnd = ((b.cwnd as f64 - shed) as i32).max(MIN_WINDOW);
            b.mode = YeahMode::Competing;
        } else {
            // SLOW/RECOVERY (YeahController.kt:256-261).
            b.fast_mode = false;
            b.cwnd = (b.cwnd + 1).min(self.max_window);
            b.mode = if b.mode == YeahMode::Competing {
                YeahMode::Recovery
            } else {
                YeahMode::Yeah
            };
        }
        self.store_brain(family, b);
    }

    /// The floor belonging to a family — `rtt_base_floor` for TCP, `udp_floor` for UDP.
    /// The SHARED metric baseline, fed by BOTH families.
    ///
    /// Independence is about DECISIONS, not about observation. `base_rtt` drives no window decision
    /// on any profile any more (each family decides against its own `Brain::base_rtt`), but it does
    /// drive `adaptive_timeout_ms` and the dashboard — and a timeout that ignored every UDP answer
    /// would be measuring half the traffic. So the metric keeps seeing everything while the
    /// algorithms stay separate. Feeding it is the LAST thing a UDP sample does, after its own brain
    /// is stored, so it can never re-enter a decision.
    fn feed_metric_base_rtt(&mut self, rtt: f64) {
        if self.base_rtt <= 0.0 {
            self.base_rtt = rtt;
        } else {
            self.base_rtt = (1.0 - EWMA_ALPHA) * self.base_rtt + EWMA_ALPHA * rtt;
        }
    }

    fn family_floor(&self, family: SampleFamily) -> f64 {
        match family {
            SampleFamily::Tcp => self.rtt_base_floor,
            SampleFamily::Udp => self.udp_floor,
        }
    }

    fn set_family_floor(&mut self, family: SampleFamily, v: f64) {
        match family {
            SampleFamily::Tcp => self.rtt_base_floor = v,
            SampleFamily::Udp => self.udp_floor = v,
        }
    }

    /// `apply_udp(rtt)` — feed a UDP RTT sample into the window brain (Rung C).
    ///
    /// Legacy/Canonical: a deliberate no-op — on those profiles UDP samples only refresh the
    /// dashboard EWMA (the pre-Rung-C law; see `Beast::fold_udp_sample`). LineRate: the full brain —
    /// UDP is the dominant traffic of a DNSCrypt engine, so its samples are first-class congestion
    /// inputs, judged against their OWN true-min floor.
    pub fn apply_udp(&mut self, rtt: f64) {
        // HARDENING — same non-finite gate as `apply` (NaN would poison q_smooth forever).
        if !rtt.is_finite() {
            return;
        }
        // ★ Rung D — EVERY profile, not just LineRate. A UDP sample runs the active profile's own
        // formulae on the UDP brain: Legacy's threshold machine, Canonical's backlog estimate, or
        // LineRate's hysteresis brain. Before this, Legacy and Canonical dropped UDP samples on the
        // floor entirely and LineRate fed them into the TCP window — neither is an independent UDP
        // congestion algorithm. Now all three are.
        self.apply_family(rtt, SampleFamily::Udp);
        // Observation is shared; decisions are not. See `feed_metric_base_rtt`.
        self.feed_metric_base_rtt(rtt);
    }

    /// DISPLAY-ONLY UDP floor observation (CP-Feed-Both) — track the UDP family's true-min floor for
    /// the dual-line dashboard WITHOUT running the window brain. The host feeds the real UDP RTTs into
    /// the SHARED window via `apply` (so Q/Q-SMOOTH/mode/cwnd see them, judged against the shared low
    /// floor — the pre-CP-Attribution "visible organism" the Socio watched); this keeps `udp_floor`
    /// lit for the dashboard's UDP line without a SECOND, conflicting window update. Leaky-bucket
    /// true-min, the FLOOR_LEAK law (identical to the Udp branch of `apply_linerate`, but nothing else).
    pub fn observe_udp_floor(&mut self, rtt: f64) {
        if !rtt.is_finite() || rtt < LR_LOCAL_ECHO_MS {
            return; // ★ #22 slice 3 — local echoes never touch the true-min floor (poison law)
        }
        if self.udp_floor <= 0.0 {
            self.udp_floor = rtt;
        } else {
            self.udp_floor = rtt.min(self.udp_floor * FLOOR_LEAK);
        }
    }

    /// LINERATE brain (Rung C — "YeAH TCP/UDP LineRate", SAIMONOKUMA 2026): the whitepaper-faithful
    /// surpass of Canonical, hardened by the kernel's hysteresis (tcp_yeah_vegas.c) and elevated to
    /// TWO first-class sample families. The five formulae vs Canonical:
    /// 1. UDP ELEVATION — UDP samples drive the shared window (Canonical: telemetry-only).
    /// 2. PER-FAMILY FLOORS — delay/L/Q judged against the sample's OWN true-min floor.
    /// 3. ZETA HYSTERESIS — `reno_count` survives until `LR_ZETA` consecutive fast samples
    ///    (tcp_yeah_vegas.c:191-196; Canonical forgets on ANY single fast sample).
    /// 4. SHED CONFIRMATION — a precautionary shed needs `LR_SHED_CONFIRM` consecutive
    ///    over-threshold samples (tcp_yeah_vegas.c:143); one spike holds the window.
    /// 5. Q MEMORY — `q_smooth` (EWMA) feeds the direction-correct loss rule in
    ///    `on_loss_linerate` (Canonical feeds one raw sample into an inverted clamp).
    fn apply_linerate(&mut self, rtt: f64, family: SampleFamily) {
        // ★ #22 slice 3 — local echoes are not network evidence: never floor material, never
        // window evidence (the LR_LOCAL_ECHO_MS poison law; subsumes the old <= 0.0 gate).
        if rtt < LR_LOCAL_ECHO_MS {
            return;
        }
        // First sample while NO family floor is alive (fresh start or post-failover hard reset):
        // seed this family's floor + the shared estimators (the canonical seed law,
        // YeahController.kt:190-198), then return — nothing to judge against yet.
        if self.rtt_base_floor <= 0.0 && self.udp_floor <= 0.0 {
            match family {
                SampleFamily::Tcp => self.rtt_base_floor = rtt,
                SampleFamily::Udp => self.udp_floor = rtt,
            }
            self.base_rtt = rtt;
            self.udp_tick = 0;
            // ★ Rung D — the seed lands on THIS family's brain. A first UDP sample arms the UDP
            // window; a first TCP sample arms the TCP window. Seeding the other family's estimators
            // from a sample it never saw is precisely the cross-talk independence forbids.
            let mut seeded = self.load_brain(family);
            seeded.mode = YeahMode::SlowStart;
            seeded.slow_start = true;
            seeded.q_packets = 0.0;
            seeded.q_smooth = 0.0;
            seeded.fast_mode = false;
            seeded.reno_count = 0;
            seeded.fast_streak = 0;
            seeded.congest_streak = 0;
            seeded.doing_reno_now = 0; // ★ #22 slice 3 — a fresh path has no consecutive streak
            seeded.fair_cwnd = 0; // Rung C+ — a fresh path has no competition evidence
            self.store_brain(family, seeded);
            return;
        }
        // A family's own FIRST sample seeds its floor and returns; after that, leaky-bucket
        // true-min per family (the FLOOR_LEAK law, per floor — no cross-family poisoning).
        let floor = match family {
            SampleFamily::Tcp => {
                if self.rtt_base_floor <= 0.0 {
                    self.rtt_base_floor = rtt;
                    return;
                }
                self.rtt_base_floor = rtt.min(self.rtt_base_floor * FLOOR_LEAK);
                self.rtt_base_floor
            }
            SampleFamily::Udp => {
                if self.udp_floor <= 0.0 {
                    self.udp_floor = rtt;
                    return;
                }
                self.udp_floor = rtt.min(self.udp_floor * FLOOR_LEAK);
                self.udp_floor
            }
        };
        // Shared EWMA base_rtt stays alive for timeouts/metrics — never drives LineRate decisions.
        self.base_rtt = (1.0 - EWMA_ALPHA) * self.base_rtt + EWMA_ALPHA * rtt;

        // ★ Rung D — THE FAMILY'S OWN BRAIN. Every window decision below reads and writes `b`, the
        // brain belonging to THIS sample's family, and is stored back to that family alone. On the
        // TCP side load/store is the identity over the flat fields, so TCP behaviour is unchanged;
        // on the UDP side this is the independent congestion algorithm YeAH TCP/UDP is named for.
        // Spec + proof: `Proofs/YeahUdpIndependence.lean::the_split_design_is_independent`.
        let mut b = self.load_brain(family);

        let delay = (rtt - floor).max(0.0);
        let l = delay / floor;
        let q = delay * (b.cwnd as f64 / rtt);
        b.q_packets = q; // raw last-Q surfaced (snapshot parity with Canonical)
                         // Formula 5 — multi-sample queue memory for the loss rule.
        b.q_smooth = (1.0 - LR_Q_EWMA_ALPHA) * b.q_smooth + LR_Q_EWMA_ALPHA * q;

        let q_threshold = b.cwnd as f64 * self.q_max_frac;
        let fast = q < q_threshold && l < 1.0 / self.phi;

        // ---- Slow-start (the canonical law, now run PER FAMILY) ----
        if b.slow_start {
            if fast {
                b.cwnd = (b.cwnd * 2).min(self.max_window);
                b.mode = YeahMode::SlowStart;
            } else {
                b.slow_start = false;
                b.cwnd_frac = b.cwnd as f64 / 2.0;
                b.cwnd = (b.cwnd_frac as i32).max(MIN_WINDOW);
                b.mode = YeahMode::Competing;
                b.reno_count += 1;
                // ★ #22 slice 3 — the slow-start exit IS the first congested sample (kernel: the
                // congested branch runs wherever the evidence lands, tcp_yeah.c:159).
                b.doing_reno_now = (b.doing_reno_now + 1).min(0xff_ffff);
            }
            b.fast_mode = fast;
            self.store_brain(family, b);
            return;
        }

        if fast {
            // FAST — STCP scalable growth (Formulae 1+3): UDP feeds the counter at half weight;
            // competition memory survives until LR_ZETA consecutive fast samples (kernel ZETA law).
            b.fast_mode = true;
            b.congest_streak = 0;
            // ★ #22 slice 3 — ONE clean sample snaps the consecutive streak (tcp_yeah.c:169);
            // `reno_count` (ZETA memory) deliberately survives — two different kernel variables.
            b.doing_reno_now = 0;
            b.fast_streak += 1;
            if b.fast_streak >= LR_ZETA {
                b.reno_count = 0;
                b.fast_streak = 0;
                // Rung C+ — a full ZETA of fast samples proves the competition left (tcp_yeah.c:
                // 164-167 resets the estimate to its floor); ours unlearns fully — a standing
                // floor of 2 on a proven-free path would be a behavior change at MIN_WINDOW=1.
                b.fair_cwnd = 0;
            }
            let grow = match family {
                SampleFamily::Tcp => true,
                SampleFamily::Udp => {
                    self.udp_tick += 1;
                    if self.udp_tick >= LR_UDP_GROWTH_INTERVAL {
                        self.udp_tick = 0;
                        true
                    } else {
                        false
                    }
                }
            };
            if grow {
                let period = (b.cwnd.max(1)).min(self.stcp_ai);
                b.cwnd_cnt += 1;
                if b.cwnd_cnt >= period {
                    b.cwnd = (b.cwnd + 1).min(self.max_window);
                    b.cwnd_cnt = 0;
                }
            }
            b.mode = YeahMode::Yeah;
        } else if q > q_threshold {
            // PRECAUTIONARY DECONGESTION with confirmation (Formula 4): one spike holds the
            // window; the shed fires on the LR_SHED_CONFIRM-th consecutive over-threshold sample.
            b.fast_mode = false;
            b.fast_streak = 0;
            b.reno_count += 1;
            b.congest_streak += 1;
            // ★ #22 slice 3 — the consecutive counter, saturating at the kernel cap
            // (tcp_yeah.c:159-160 `min(doing_reno_now + 1, 0xffffff)`).
            b.doing_reno_now = (b.doing_reno_now + 1).min(0xff_ffff);
            // Rung C+ Formula 7 — LEARN the fair share (tcp_yeah.c:154-157): first congestion
            // evidence seeds it at half the window; each further congested sample creeps it +1
            // ONLY while below half the LIVE window. The kernel's creep is glacial relative to
            // its hundred-packet windows; at our 16-cap an uncapped creep would overtake the
            // window (2 congested samples per shed vs +1 each) and the floor would pin the shed.
            if b.fair_cwnd < LR_FAIR_MIN {
                b.fair_cwnd = (b.cwnd >> 1).max(LR_FAIR_MIN);
            } else if b.fair_cwnd < (b.cwnd >> 1) {
                b.fair_cwnd += 1;
            }
            if b.congest_streak >= LR_SHED_CONFIRM {
                let shed = (q / self.gamma).min((b.cwnd >> self.epsilon_shift) as f64);
                // Rung C+ Formula 8 — the fair-share FLOOR (tcp_yeah.c:147-148): a precautionary
                // shed never cuts below the share this flow can defend. Unlearned (0) degrades to
                // the plain MIN_WINDOW floor; `.min(cwnd)` keeps the floor from ever GROWING the
                // window on a shed (defensive — the learning cap upholds fair ≤ cwnd anyway).
                let fair_floor = b.fair_cwnd.min(b.cwnd).max(MIN_WINDOW);
                b.cwnd = ((b.cwnd as f64 - shed) as i32).max(fair_floor);
                b.congest_streak = 0; // the next shed requires fresh confirmation
            }
            b.mode = YeahMode::Competing;
        } else {
            // SLOW/RECOVERY (the canonical law); both streaks reset — the middle zone proves neither.
            b.fast_mode = false;
            b.fast_streak = 0;
            b.congest_streak = 0;
            // ★ #22 slice 3 — CONSECUTIVE means uninterrupted: a middle-zone sample is not
            // congestion evidence, so the RHO streak snaps (the kernel's two-branch world has no
            // middle; anything short of the congested branch resets, tcp_yeah.c:169).
            b.doing_reno_now = 0;
            b.cwnd = (b.cwnd + 1).min(self.max_window);
            b.mode = if b.mode == YeahMode::Competing {
                YeahMode::Recovery
            } else {
                YeahMode::Yeah
            };
        }
        self.store_brain(family, b);
    }

    /// Canonical loss/timeout reaction (YeahController.kt:273-296) — the H2/M1 fix.
    pub fn on_loss_or_timeout(&mut self) {
        if self.profile == YeahProfile::Legacy {
            self.apply_timeout_penalty();
            return;
        }
        if self.profile == YeahProfile::LineRate {
            self.on_loss_linerate();
            return;
        }
        if self.rtt_base_floor <= 0.0 {
            return;
        }
        if self.reno_count > self.rho {
            // Proven contention -> full Reno halve.
            self.cwnd = (self.cwnd / 2).max(MIN_WINDOW);
        } else {
            // Isolated loss -> gentle clamp(Q, cwnd>>1, cwnd): never below half, never above current.
            let lo = (self.cwnd >> 1).max(MIN_WINDOW);
            let hi = self.cwnd.max(MIN_WINDOW);
            let target = (self.q_packets as i32).clamp(lo, hi);
            self.cwnd = target;
        }
        self.reno_count = 0;
        self.fast_mode = false;
        self.cwnd_cnt = 0;
        self.mode = YeahMode::Competing;
    }

    /// LINERATE loss rule (Rung C) — the whitepaper's, direction-correct:
    /// `cwnd -= clamp(Q_smooth, cwnd>>LR_DELTA_SHIFT, cwnd>>1)` (YeAH-TCP paper §3;
    /// tcp_yeah_vegas.c:223-228). A random loss with an empty queue costs cwnd/8; a loss on a
    /// self-built queue drains up to a full half. Canonical's clamp is INVERTED (bigger queue =>
    /// HIGHER post-loss window) — kept there untouched, its pins depend on it; the fix lives here.
    fn on_loss_linerate(&mut self) {
        self.on_loss_linerate_family(SampleFamily::Tcp);
    }

    /// ★ Rung D — the loss rule, per family. A UDP loss reduces the UDP window; a TCP loss reduces
    /// the TCP window. Before this, EITHER loss halved the one shared window, which is the same
    /// cross-talk on the way down that `udp_tick` growth was on the way up.
    fn on_loss_linerate_family(&mut self, family: SampleFamily) {
        // No family floor alive yet — nothing measured, nothing to react to.
        if self.rtt_base_floor <= 0.0 && self.udp_floor <= 0.0 {
            return;
        }
        let mut b = self.load_brain(family);
        // ★ #22 slice 3 — KERNEL RHO STRICTNESS (tcp_yeah.c:194): the Reno halve is earned by
        // `doing_reno_now` — RHO consecutive UNINTERRUPTED congested samples immediately behind
        // the loss — never by the ZETA memory (`reno_count`), which accumulates across fast gaps
        // and previously let intermittent congestion panic-halve on a random loss the kernel
        // treats surgically. One clean sample anywhere in the run ⇒ the surgical branch.
        if b.doing_reno_now >= self.rho {
            // Proven sustained contention -> full Reno halve (tcp_yeah.c:200-201).
            b.cwnd = (b.cwnd / 2).max(MIN_WINDOW);
        } else {
            let lo = (b.cwnd >> LR_DELTA_SHIFT).max(1);
            let hi = (b.cwnd >> 1).max(1);
            let reduction = (b.q_smooth as i32).clamp(lo, hi);
            b.cwnd = (b.cwnd - reduction).max(MIN_WINDOW);
        }
        // Keep HALF the competition memory (tcp_yeah_vegas.c:233 `reno_count >> 1`;
        // Canonical resets to 0 = instant amnesia).
        b.reno_count >>= 1;
        // Rung C+ — the fair-share estimate decays with the loss too (tcp_yeah.c:204
        // `reno_count = max(reno_count>>1, 2)`); unlearned (0) stays unlearned.
        if b.fair_cwnd >= LR_FAIR_MIN {
            b.fair_cwnd = (b.fair_cwnd >> 1).max(LR_FAIR_MIN);
        }
        b.fast_mode = false;
        b.cwnd_cnt = 0;
        b.fast_streak = 0;
        b.congest_streak = 0;
        // ★ #22 slice 3 — `doing_reno_now` SURVIVES the loss (kernel ssthresh tcp_yeah.c:188-207
        // never touches it): under genuinely sustained competition a second immediate loss also
        // halves; the next non-congested sample is what snaps the streak.
        b.mode = YeahMode::Competing;
        self.store_brain(family, b);
    }

    /// ★ Rung D — a UDP loss or timeout, reacted to by the UDP window ALONE. This is the public
    /// entry the host calls for the UDP path; `on_loss_or_timeout` remains the TCP entry.
    /// On Legacy/Canonical, where no independent UDP brain runs, it defers to the shared reaction so
    /// no profile silently ignores a loss.
    pub fn on_udp_loss_or_timeout(&mut self) {
        if self.profile == YeahProfile::LineRate {
            self.on_loss_linerate_family(SampleFamily::Udp);
        } else {
            self.on_loss_or_timeout();
        }
    }

    /// Timeout penalty (YeahController.kt:299-305) — Legacy signals competition.
    pub fn apply_timeout_penalty(&mut self) {
        if self.profile != YeahProfile::Legacy {
            self.on_loss_or_timeout();
            return;
        }
        if self.base_rtt > 0.0 {
            self.apply(self.base_rtt * self.compete_thresh + 1.0);
        }
    }

    /// Hard failover penalty (YeahController.kt:308-321) — relay-switch hard reset.
    pub fn apply_failover_penalty(&mut self) {
        if self.profile != YeahProfile::Legacy {
            self.cwnd = MIN_WINDOW;
            self.slow_start = true;
            self.reno_count = 0;
            self.fast_mode = false;
            self.cwnd_cnt = 0;
            self.rtt_base_floor = 0.0;
            // LineRate-only state — a failover invalidates BOTH family floors and every streak
            // (zeros are no-ops on Canonical, whose brain never reads these).
            self.fast_streak = 0;
            self.congest_streak = 0;
            self.doing_reno_now = 0; // ★ #22 slice 3 — new path, no consecutive evidence
            self.q_smooth = 0.0;
            self.udp_floor = 0.0;
            self.udp_tick = 0;
            self.fair_cwnd = 0; // Rung C+ — the NEW upstreams owe this flow no learned share
            self.mode = YeahMode::SlowStart;
            // ★ Rung D — the INDEPENDENT UDP brain is invalidated by the same event. A relay switch
            // replaces the path under BOTH families, so the UDP window's learned share, streaks and
            // queue memory are as stale as the TCP window's. Independence means UDP keeps its own
            // state, NOT that it survives an event that invalidated the path it measured.
            self.udp_brain = Brain::fresh();
            return;
        }
        if self.base_rtt > 0.0 {
            self.apply(self.base_rtt * FAILOVER_THRESH + 1.0);
        }
    }

    /// Adaptive read timeout = max(500, base_rtt*2.5 + jitter*2); 2000ms before any sample
    /// (YeahController.kt:324-327).
    pub fn adaptive_timeout_ms(&self, jitter_ms: f64) -> i32 {
        if self.base_rtt <= 0.0 {
            return 2000;
        }
        ((self.base_rtt * 2.5 + jitter_ms * 2.0) as i32).max(500)
    }
}

impl Default for YeahController {
    fn default() -> Self {
        Self::new()
    }
}
