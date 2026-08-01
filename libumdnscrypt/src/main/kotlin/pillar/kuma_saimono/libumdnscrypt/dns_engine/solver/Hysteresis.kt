/*
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2

    Yeah! Tortä
    Copyright 2026 Saimonokuma

    This file is part of Yeah! Tortä, dual-licensed at your option under
    EITHER the GNU Affero General Public License, version 3 or later (see
    agpl-3.0.md), OR the European Union Public Licence, version 1.2 or later
    (see EUPL-LICENSE.txt).

    Distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
    PARTICULAR PURPOSE.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.solver

/**
 * Monster Plan §7 (Stage E) — **the anti-thrash gate**: the load-bearing guard that stops the self-healer
 * from FLAPPING. The plan names this the refute-swarm's prime target verbatim — *"thrashing (hysteresis /
 * dwell-time / cost-of-switching — a self-healer that flaps is a new bug)"* (`MONSTER_ENHANCEMENT_PLAN.md:88`,
 * risk row `:94-95`). A binding that ping-pongs between two near-equal upstreams every cycle would be a NEW
 * defect worse than the obstruction it answers, so the live solve gates on THIS decision passing.
 *
 * **The complete anti-thrash state machine.** [observe] is the all-in-one re-solve gate the live manager
 * drives each tick; [decideSwitch] is the cost-of-switching margin applied to a raced winner; [applySolve]
 * stamps the dwell + cooldown windows after a solve resolves. The sibling [Solver.detectObstruction] feeds
 * the obstruction `signal`; the sibling [Solver.shouldTrigger] is a thin ENTER-only convenience over the same
 * Schmitt+debounce logic for managers that want the trigger split out — both reason about the identical bands.
 *
 * **The six anti-thrash invariants (each a NAMED, refute-swarm-tested guarantee):**
 *  - **I1 · HYSTERESIS (Schmitt band):** two thresholds, [HysteresisConfig.triggerEnter] >
 *    [HysteresisConfig.triggerExit]. A signal oscillating inside the dead-band `(exit, enter)` never
 *    re-triggers — only a rise past enter arms a solve, and the armed latch only clears below exit.
 *  - **I2 · DWELL-TIME (min residency):** once a binding is committed it is held ≥ [HysteresisConfig.dwellMs]
 *    regardless of new obstruction — a fresh spike during dwell is suppressed, not acted on.
 *  - **I3 · COST-OF-SWITCHING (min-improvement margin):** a candidate replaces the incumbent ONLY if it is
 *    strictly better by ≥ a margin ([HysteresisConfig.switchMargin]) OR the incumbent is dead. A tied or
 *    marginally-better candidate does NOT switch — the headline "no flap on a wash" rule ([decideSwitch]).
 *  - **I4 · COOLDOWN (refractory):** after ANY solve (switch OR a no-switch race) no new solve for
 *    [HysteresisConfig.cooldownMs] — bounds solves-per-minute to ≤ `60000/cooldownMs` regardless of signal.
 *  - **I5 · DEBOUNCE (confirm-before-act):** a trigger requires [HysteresisConfig.confirmSamples] consecutive
 *    over-enter ticks — a single transient spike never triggers.
 *  - **I6 · FINGERPRINT STICKINESS** (the sibling [BindingCache.lookup] → [CacheResult.Hit], enforced BEFORE
 *    this gate is asked): a known-good network instant-reuses its cached binding with NO race at all.
 *
 * Composite law: a commit can happen at most once per `max(dwellMs, cooldownMs)`, only on a confirmed,
 * sustained, hysteresis-cleared obstruction whose race winner strictly beats the incumbent — so the binding
 * physically CANNOT flap.
 *
 * **Pure decision core — the deferred-live boundary.** Side-effect-free: every step is a pure
 * `(state, …, nowMs) → outcome` with the holder ([HysteresisState]) returned anew, **no clock of its own, no
 * RNG, no Android, no IO** (the [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationSelector] precedent —
 * JUnit-on-metal). The caller supplies the wall-clock; this decides *whether* a solve is warranted and
 * *whether* its winner is worth committing. The LIVE race + enforce is DEFERRED; a flapping bug is caught
 * HERE, in tests, before any real query is ever steered.
 *
 * Score convention: **lower score = better binding** (the §4 governor blend `blend(p95,loss,cwnd,jitter)`
 * where low latency/loss/jitter is good — matching [LockedBinding.score] and the sibling [SolverBinding.score]
 * mapping). [decideSwitch] therefore swaps when the candidate's score is sufficiently BELOW the incumbent's.
 */
object Hysteresis {

    /**
     * The anti-thrash dials. All raw values live behind the ONE Expert toggle (`DNS_ENGINE_EXPERT`,
     * `TortaeKeys.java:152`) per SIMPLE-UX — a non-geek never sees them; the defaults are the safe,
     * flap-proof posture. Every default is chosen so the composite law holds with comfortable margin.
     *
     * @param triggerEnter  obstruction ≥ this (for [confirmSamples] consecutive ticks) ARMS a solve. The HIGH
     *                      Schmitt rail. Range [0,1].
     * @param triggerExit   obstruction < this CLEARS the armed state. The LOW Schmitt rail. MUST be strictly
     *                      < [triggerEnter] (the dead-band that defeats oscillation); enforced in init.
     * @param confirmSamples consecutive over-[triggerEnter] ticks required before a trigger fires (debounce I5).
     *                      ≥ 1; a value of 1 means "act on the first over-threshold tick" (no debounce).
     * @param dwellMs       minimum residency of a committed binding (I2). ≥ 0.
     * @param cooldownMs    refractory window after ANY solve (I4). ≥ 0.
     * @param switchMargin  fractional min-improvement to switch (I3). A candidate replaces the incumbent only
     *                      if `candidateScore ≤ incumbentScore × (1 − switchMargin)` (lower=better). 0.0 would
     *                      allow a tie-swap (flap risk); the default 0.15 demands a real ≥15% win. ≥ 0.
     */
    data class HysteresisConfig(
        val triggerEnter: Double = DEFAULT_TRIGGER_ENTER,
        val triggerExit: Double = DEFAULT_TRIGGER_EXIT,
        val confirmSamples: Int = DEFAULT_CONFIRM_SAMPLES,
        val dwellMs: Long = DEFAULT_DWELL_MS,
        val cooldownMs: Long = DEFAULT_COOLDOWN_MS,
        val switchMargin: Double = DEFAULT_SWITCH_MARGIN,
    ) {
        init {
            require(triggerEnter > triggerExit) {
                "Hysteresis requires triggerEnter ($triggerEnter) > triggerExit ($triggerExit) — a dead-band"
            }
            require(triggerEnter in 0.0..1.0 && triggerExit in 0.0..1.0) {
                "Hysteresis thresholds must be in [0,1] (enter=$triggerEnter exit=$triggerExit)"
            }
            require(confirmSamples >= 1) { "confirmSamples must be >= 1 (was $confirmSamples)" }
            require(dwellMs >= 0L) { "dwellMs must be >= 0 (was $dwellMs)" }
            require(cooldownMs >= 0L) { "cooldownMs must be >= 0 (was $cooldownMs)" }
            require(switchMargin >= 0.0) { "switchMargin must be >= 0 (was $switchMargin)" }
        }
    }

    /**
     * The immutable hysteresis bookkeeping carried between ticks. Returned anew by [observe] (no hidden
     * mutation) so the whole gate is a pure fold — a test feeds a sequence of (signal, nowMs) and asserts the
     * exact decision/state at every step, fully deterministically.
     *
     * @param armed         true once a confirmed obstruction has crossed [HysteresisConfig.triggerEnter] and
     *                      NOT yet fallen below [HysteresisConfig.triggerExit] (the Schmitt latch, I1).
     * @param confirmRun    consecutive over-enter ticks seen so far (debounce counter, I5).
     * @param dwellUntilMs  a committed binding is held until at least this wall-clock (I2). 0 = no binding held.
     * @param cooldownUntilMs no new solve may start before this wall-clock (refractory, I4). 0 = free.
     * @param lastCommitMs  wall-clock of the last committed solve (provenance; spacing-between-commits proof).
     */
    data class HysteresisState(
        val armed: Boolean = false,
        val confirmRun: Int = 0,
        val dwellUntilMs: Long = 0L,
        val cooldownUntilMs: Long = 0L,
        val lastCommitMs: Long = 0L,
    )

    /** The gate's verdict for one tick. */
    enum class Decision {
        /** Steady — obstruction below the action band, or armed-but-blocked by dwell/cooldown/debounce. Do nothing. */
        HOLD,
        /** A confirmed, hysteresis-cleared, dwell/cooldown-permitted obstruction — START a race (then [decideSwitch]). */
        SOLVE,
    }

    /**
     * One observation tick. PURE. Folds the obstruction [signal] (normalized [0,1]; the sibling
     * [Solver.detectObstruction] verdict score) against the Schmitt band + debounce + dwell + cooldown and
     * returns the [Decision] plus the next [HysteresisState]. Calling this NEVER commits or switches anything —
     * a [Decision.SOLVE] only means "a race is warranted now"; the *switch* itself is gated by [decideSwitch]
     * (cost-of-switching I3), and the dwell/cooldown windows are stamped by [applySolve].
     *
     * The logic, in order (each clause is an invariant):
     *  1. **I1 Schmitt latch:** raise `armed` only when `signal ≥ triggerEnter`; lower it only when
     *     `signal < triggerExit`. In the dead-band `[exit, enter)` the latch HOLDS its prior value — an
     *     oscillation there can neither arm nor disarm (the core anti-flap).
     *  2. **I5 debounce:** the consecutive-over-enter run must reach `confirmSamples`; a sub-threshold tick
     *     resets the run to 0. A transient ≤ confirmSamples never reaches SOLVE.
     *  3. **I2 dwell:** if a binding is held (`nowMs < dwellUntilMs`) → HOLD regardless of obstruction.
     *  4. **I4 cooldown:** if within the refractory window (`nowMs < cooldownUntilMs`) → HOLD.
     *  5. Otherwise, an armed + confirmed + dwell-free + cooldown-free obstruction → **SOLVE**.
     *
     * @param state  the prior bookkeeping (start from [HysteresisState] defaults on first tick).
     * @param signal the obstruction score in [0,1] (clamped defensively); higher = more obstructed.
     * @param nowMs  the caller-supplied wall-clock.
     * @param config the dials.
     */
    fun observe(
        state: HysteresisState,
        signal: Double,
        nowMs: Long,
        config: HysteresisConfig = HysteresisConfig(),
    ): Pair<Decision, HysteresisState> {
        val s = signal.coerceIn(0.0, 1.0)

        // --- I1: Schmitt latch. Dead-band holds the prior armed value (this is the anti-oscillation core). ---
        val armed = when {
            s >= config.triggerEnter -> true
            s < config.triggerExit -> false
            else -> state.armed // inside [exit, enter): HOLD — no arm, no disarm.
        }

        // --- I5: debounce. Count consecutive over-enter ticks; any sub-enter tick breaks the run. ---
        val confirmRun = if (s >= config.triggerEnter) (state.confirmRun + 1) else 0

        val next = state.copy(armed = armed, confirmRun = confirmRun)

        // Not (yet) a confirmed, latched obstruction → HOLD. The dead-band + a not-yet-confirmed run both land here.
        if (!armed || confirmRun < config.confirmSamples) {
            return Decision.HOLD to next
        }

        // --- I2: dwell. A held binding is honored even under fresh obstruction (a storm during dwell ⇒ no solve). ---
        if (nowMs < state.dwellUntilMs) return Decision.HOLD to next

        // --- I4: cooldown. The refractory window bounds solves-per-minute irrespective of the signal. ---
        if (nowMs < state.cooldownUntilMs) return Decision.HOLD to next

        // Confirmed, latched, dwell-free, cooldown-free obstruction → a race is warranted.
        return Decision.SOLVE to next
    }

    /**
     * The outcome of evaluating a raced candidate against the incumbent — the **cost-of-switching gate (I3)**.
     * SWITCH only when the candidate is *strictly better by the margin* OR the incumbent is dead; otherwise
     * KEEP. Both outcomes are still a "solve event" for cooldown purposes (a no-switch race consumed effort),
     * which [applySolve] reflects.
     */
    enum class SwitchOutcome {
        /** The raced winner strictly beats the incumbent by ≥ the margin (or the incumbent is dead) — switch. */
        SWITCH,
        /** The winner is tied / only marginally better — KEEP the incumbent (the no-flap-on-a-wash rule). */
        KEEP,
    }

    /**
     * The cost-of-switching decision (I3), PURE. Lower score = better.
     *
     * - If there is no incumbent ([incumbentScore] null) → SWITCH (first binding on this network).
     * - If [incumbentDead] → SWITCH (a dead path must be replaced even by a marginal winner).
     * - Else SWITCH iff `candidateScore ≤ incumbentScore × (1 − switchMargin)` — a strict ≥ margin improvement.
     *   A tie or a sub-margin gain → KEEP (this is the clause an oscillating measurement cannot defeat: two
     *   near-equal upstreams never swap because neither ever clears the other's margin).
     *
     * @param candidateScore the race winner's blended score (lower=better; [LockedBinding.score]).
     * @param incumbentScore the currently-locked binding's score, or null if none.
     * @param incumbentDead  the incumbent binding is proven unreachable/dead (force replace).
     * @param config         the dials (the [HysteresisConfig.switchMargin]).
     */
    fun decideSwitch(
        candidateScore: Double,
        incumbentScore: Double?,
        incumbentDead: Boolean = false,
        config: HysteresisConfig = HysteresisConfig(),
    ): SwitchOutcome {
        if (incumbentScore == null) return SwitchOutcome.SWITCH
        if (incumbentDead) return SwitchOutcome.SWITCH
        // Strict margin: the candidate must be at least switchMargin fraction BELOW the incumbent (lower=better).
        val threshold = incumbentScore * (1.0 - config.switchMargin)
        return if (candidateScore <= threshold) SwitchOutcome.SWITCH else SwitchOutcome.KEEP
    }

    /**
     * Stamp the bookkeeping after a solve event RESOLVED (whether it SWITCHED or KEPT) — arm the dwell window
     * on the now-current binding (I2) and the cooldown refractory (I4), and reset the debounce/latch so the
     * next obstruction must re-confirm and re-cross the enter rail from scratch. PURE.
     *
     * Call this once per [Decision.SOLVE] that completed a race (both [SwitchOutcome.SWITCH] and
     * [SwitchOutcome.KEEP] count — a no-switch race still consumed a solve and must respect cooldown, the I4
     * "solves-per-minute is cooldown-bounded, not tick-bounded" guarantee).
     *
     * @param state  the bookkeeping returned by the [observe] that yielded SOLVE.
     * @param nowMs  the caller's wall-clock at commit.
     * @param config the dials (dwell + cooldown windows).
     */
    fun applySolve(
        state: HysteresisState,
        nowMs: Long,
        config: HysteresisConfig = HysteresisConfig(),
    ): HysteresisState = state.copy(
        armed = false,            // latch reset: the obstruction was answered; a new one must re-cross enter.
        confirmRun = 0,           // debounce reset: re-confirm from scratch.
        dwellUntilMs = nowMs + config.dwellMs,
        cooldownUntilMs = nowMs + config.cooldownMs,
        lastCommitMs = nowMs,
    )

    // ---- Defaults (the flap-proof posture; Expert-overridable). ----

    /** Arm a solve at obstruction ≥ 0.70 (a clearly degraded path). Matches the sibling [SolverThresholds.triggerEnter]. */
    const val DEFAULT_TRIGGER_ENTER = 0.70
    /** Clear the armed state only below 0.40 — a 0.30-wide dead-band that swallows oscillation (I1). */
    const val DEFAULT_TRIGGER_EXIT = 0.40
    /** Demand 3 consecutive over-enter ticks before triggering — a 1–2 tick spike never solves (I5). */
    const val DEFAULT_CONFIRM_SAMPLES = 3
    /** Hold a committed binding ≥ 30 s before another switch can commit (I2). */
    const val DEFAULT_DWELL_MS = 30_000L
    /** No new solve within 20 s of the last (I4) — caps solves to ≤ 3/min under any signal. */
    const val DEFAULT_COOLDOWN_MS = 20_000L
    /** A candidate must be ≥ 15% better (lower score) than the incumbent to switch (I3) — no wash-swap. */
    const val DEFAULT_SWITCH_MARGIN = 0.15
}

/**
 * Monster Plan §7 — the **obstruction score blend**: fold the per-cycle obstruction signals the solver READS
 * (it does not invent telemetry) into a single normalized [0,1] where higher = more obstructed. PURE. This is
 * the canonical blend the sibling [Solver.detectObstruction] COMPOSES over (`Solver.kt:96-102`) — kept here as
 * a sibling of the gate so the cache/decision core is a complete, self-contained, JUnit-testable unit; the
 * live signal *capture* (folding the real CAKE/governor gauges) is the future SolverManager's job.
 *
 * The signals (all already computed elsewhere per cycle):
 *  - CAKE COBALT sojourn (the Rust Beast `beast/cake.rs` sojourn = now − enqueuedAtMs, surfaced as
 *    sojournP95 §6 via the pushed `BeastSnapshot`) — queue wait blowing past the CoDel target is the headline obstruction.
 *  - BLUE drop probability (the Rust Beast `beast/cake.rs` `blue_prob`, surfaced via the pushed
 *    `BeastSnapshot.blueProb`) — the loss/timeout valve.
 *  - per-upstream score collapse (the §4 governor `blend(p95,loss,cwnd,jitter)`) — normalized "how bad is the
 *    best available upstream" in [0,1].
 *  - YeAH COMPETING / failover pressure (the Rust Beast `beast/yeah.rs` mode, surfaced via the pushed
 *    `BeastSnapshot.mode == "COMPETING"`; `MonokumaDnsEngine.failovers`) — a boolean.
 *  - a captive-portal / hard-block signature is a HARD 1.0 (an unconditional obstruction).
 */
object ObstructionScore {

    /**
     * Blend the signals → [0,1]. PURE. The contract the sibling [Solver.detectObstruction] composes over
     * (`Solver.kt:96-102`): the caller hands in the sojourn + score sub-signals ALREADY scaled by their
     * Solver weights, the RAW blueProb (this object scales it internally against [BLUE_FULL] × the blue
     * weight), and the competing boolean (this object applies the bounded [COMPETING_LIFT]). The blend is a
     * **bounded weighted SUM** then clamped to [0,1] — so any one strong signal lifts the score and several
     * together saturate it. (Pinned by `SolverTest`: a competing-only snapshot scores 0.075; a fully-blown
     * combined snapshot scores 0.925.)
     *
     * @param sojournRatio   the sojourn sub-signal contribution, already weighted by the caller (in [0,1]).
     * @param blueProb       the RAW BLUE drop probability in [0, ~0.25]; scaled here to its weighted band.
     * @param scoreCollapse  the score-collapse sub-signal contribution, already weighted by the caller.
     * @param yeahCompeting  the window is in COMPETING/backoff under contention — adds [COMPETING_LIFT].
     * @param captive        a captive-portal / hard-block signature — an unconditional hard 1.0.
     */
    fun of(
        sojournRatio: Double,
        blueProb: Double,
        scoreCollapse: Double = 0.0,
        yeahCompeting: Boolean = false,
        captive: Boolean = false,
    ): Double {
        if (captive) return 1.0
        val sojourn = sojournRatio.coerceIn(0.0, 1.0)
        val blue = (blueProb / BLUE_FULL).coerceIn(0.0, 1.0) * BLUE_WEIGHT
        val collapse = scoreCollapse.coerceIn(0.0, 1.0)
        val competing = if (yeahCompeting) COMPETING_LIFT else 0.0
        val blended = sojourn + blue + collapse + competing
        return blended.coerceIn(0.0, 1.0)
    }

    /** blueProb is capped at 0.25 in CAKE (the Rust Beast `beast/cake.rs` `BLUE_CAP`); 0.25 maps to a full BLUE sub-signal. */
    const val BLUE_FULL = 0.25
    /** The BLUE sub-signal's weight in the blend (a fully-blown BLUE valve contributes this much). */
    const val BLUE_WEIGHT = 0.25
    /** Attribution scale for the score-collapse sub-signal (used by the dominant-signal pick). */
    const val COLLAPSE_WEIGHT = 0.5
    /** A COMPETING/backoff window adds this bounded lift to the blend. */
    const val COMPETING_LIFT = 0.075
}
