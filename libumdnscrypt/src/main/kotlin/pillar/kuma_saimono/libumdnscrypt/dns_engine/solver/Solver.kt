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

import uniffi.torta_core.TortaProfile

/**
 * Stage-E **SOLVER core** (Monster Plan §7) — the obstruction-triggered self-healing reflex, authored as
 * PURE, side-effect-free, Android-free Kotlin so it runs under plain JUnit on the metal (the
 * [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationSelector] /
 * [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationPing] precedent).
 *
 * **FlareSolverr's PRINCIPLE, ZERO of its machinery.** FlareSolverr races a real browser at an
 * obstruction; we keep ONLY the principle — *on obstruction, escalate from steady-state control to an
 * ACTIVE race-then-lock discovery* — and implement it with pure networking signals the engine already
 * computes. **NO browser / WebView / Chromium / Cloudflare / OkHttp-to-anywhere is touched here.** The
 * Solver never opens a socket: the LIVE race is INJECTED via a measurement function and DEFERRED to the
 * live `SolverManager` (gated on the per-upstream governor map landing, Stage-B Shadow).
 *
 * **The four Stage-E verbs (Monster Plan §7) — this object owns them; the anti-thrash COMMIT side + the
 * cache are the sibling units (convergence, not fork):**
 *  1. **OBSTRUCTION DETECT** — [detectObstruction] blends the signals the engine already produces (CAKE
 *     COBALT `sojournP95` & `blueProb` — `beast/cake.rs` BLUE/CoDel getters, surfaced via the
 *     `BeastSnapshot` the Rust Beast PUSHES; the per-upstream §4 governor `score` collapse; YeAH
 *     COMPETING / failovers — `MonokumaDnsEngine`, the Rust Beast `BeastSnapshot.mode`; a captive
 *     signature) into an [ObstructionVerdict] with a normalized score in `[0,1]`. The Solver READS
 *     telemetry; it never invents it.
 *  2. **RE-SOLVE TRIGGER (the ENTER side, anti-thrash I1 + I5)** — [shouldTrigger] is the debounced +
 *     hysteresis (Schmitt) gate that decides whether an obstruction is *worth* a solve. A single spike
 *     never triggers; a signal oscillating in the dead-band never re-triggers. The COMMIT side (dwell I2,
 *     cooldown I4, cost-of-switching I3) is the sibling [Hysteresis] (`Hysteresis.gateSolve` /
 *     `decideSwitch` / `applySolve`); the fingerprint stickiness short-circuit (I6) is the sibling
 *     [BindingCache.lookup]. The Solver's verdict ([detectObstruction]) is precisely the `signal` they
 *     consume — the spine is split across disjoint owner files, never duplicated.
 *  3. **RACE ORCHESTRATION** — [enumerateRace] enumerates the `transport × resolver × relay` candidate
 *     axes (the Plan §7 cross-product); [pickRaceWinner] is the PURE pick over the measured candidates
 *     (the live measurement is injected, never opened here). Mirrors
 *     [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationPing.rankByRtt] — drop unreachable, fastest-first,
 *     deterministic tiebreak.
 *  4. **BINDING SELECTION** — [solveBinding] picks the optimal binding AND derives the tuned `cwnd` / CAKE
 *     params for that link, returning a [SolverBinding]; [toLockedBinding] converts it into the sibling
 *     cache's [LockedBinding] so the race output drops straight into [BindingCache.commit] (and the live
 *     lock — `TortaCore.configureResolver` re-called never re-authored — once Stage C+ lands).
 *
 * **LAW compliance (load-bearing):**
 *  - **LEGACY byte-identical.** Nothing here is wired into the live datapath — a brand-new package behind
 *    the `DNS_ENGINE_SOLVER` flag (a default-ON switch today — `TortaeKeys.java:193`), but SHADOW-only
 *    until `DNS_ENGINE_GOVERN` (default OFF — `TortaeKeys.java:182`) + Stage-C arm (#85): no live heal
 *    yet. A solver-absent / governor-absent build is the EXACT 6-probe path of today
 *    (`MonokumaDnsEngine.runCycle`, `MonokumaDnsEngine.kt:133-171`, is never touched).
 *  - **PURE-TESTABLE.** No clock, no RNG, no Android, no socket, no coroutine. The measurement source is
 *    injected. Deterministic → reproducible tests.
 *  - **REUSE not fork.** It COMPOSES an injected YeAH brain (the Rust [`Beast`] on the live path; a
 *    deterministic stub in tests) for the tuned cwnd, the sibling [Hysteresis] (COMMIT side),
 *    [BindingCache]/[LockedBinding] (the cache) and the [TransportKind] enum — it re-declares none of them.
 *  - **ANTI-THRASH is load-bearing.** [shouldTrigger] is provably hysteretic (a sustained over-`enter`
 *    crossing AND debounce); a self-healer that flaps is a NEW bug.
 */
object Solver {

    // =====================================================================================
    // 1 · OBSTRUCTION DETECT — blend the engine's existing signals → a normalized verdict.
    // =====================================================================================

    /**
     * Map the per-cycle engine snapshot ([input]) onto the SIBLING [ObstructionScore.of] (REUSE — the
     * canonical blend lives there, `Hysteresis.kt:276-312`) and attribute the dominant sub-signal. Pure:
     * same input → same output, no clock/RNG. A captive-portal/throttle signature is a HARD override
     * (score = 1.0) because no amount of window tuning fixes a portal — only a transport/resolver race can.
     *
     * Each engine signal is normalized to `[0,1]` via the [SolverThresholds] SCALES (sojournTargetMs /
     * blueProbCeil / scoreHealthy..scoreCollapsed), then the Solver applies its sub-signal WEIGHTS
     * (wSojourn / wScore) before the sibling [ObstructionScore.of] — which is a weighted SUM expecting its
     * sojourn/collapse args "already weighted by the caller" (`Hysteresis.kt:287-289`). BLUE is weighted
     * INSIDE the sibling (BLUE_WEIGHT) so the RAW prob is handed over; competing is the sibling's fixed
     * COMPETING_LIFT. The Solver never re-implements the SUM — that math is the sibling's alone:
     *  - **sojourn** — CAKE COBALT queue-wait P95 vs [SolverThresholds.sojournTargetMs] (the CoDel target).
     *  - **blueProb** — CAKE BLUE drop probability of the busiest tin, scaled by [SolverThresholds.blueProbCeil].
     *  - **scoreCollapse** — the per-upstream §4 governor `score` (lower-better); a collapse means even the
     *    best upstream is bad. `null` (no governor map yet — Stage-B not landed) ⇒ contributes 0.
     *  - **competing** — YeAH COMPETING and/or mounting failovers: the controller cannot grow the window.
     *
     * @return the [ObstructionVerdict] whose [ObstructionVerdict.score] feeds [shouldTrigger] (the ENTER
     *   side) and whose [ObstructionVerdict.dominantSignal] feeds the dashboard reason (the attribution a
     *   bare [ObstructionScore.of] Double cannot carry).
     */
    fun detectObstruction(
        input: SolverInput,
        thresholds: SolverThresholds = SolverThresholds(),
    ): ObstructionVerdict {
        // HARD override: a captive portal / throttle is a full obstruction regardless of the queue numbers.
        if (input.captiveSignature) {
            return ObstructionVerdict(score = 1.0, dominantSignal = ObstructionSignal.CAPTIVE)
        }

        // Normalize each engine signal to [0,1] (the Solver's SCALES), then apply the Solver's sub-signal
        // WEIGHTS for sojourn/score before the sibling blend — the sibling [ObstructionScore.of] is a
        // weighted SUM that expects its sojourn/collapse args "already weighted by the caller"
        // (`Hysteresis.kt:287-289`); BLUE is weighted internally (BLUE_WEIGHT) so we hand it the RAW prob,
        // and competing is the sibling's fixed COMPETING_LIFT. No duplicate blend — the sibling owns the SUM.
        val sojournNorm = ratioNorm(input.sojournP95Ms.toDouble(), thresholds.sojournTargetMs.toDouble())
        val blueNorm = ratioNorm(input.blueProb, thresholds.blueProbCeil)
        val scoreNorm = scoreCollapseNorm(input.bestUpstreamScore, thresholds)
        val competing = input.yeahCompeting || input.failovers > 0

        val sojournContribution = sojournNorm * thresholds.wSojourn
        val scoreContribution = scoreNorm * thresholds.wScore

        val score = ObstructionScore.of(
            sojournRatio = sojournContribution,
            blueProb = input.blueProb,
            scoreCollapse = scoreContribution,
            yeahCompeting = competing,
            captive = false,
        )

        // Attribute the dominant sub-signal (the dashboard reason) by each component's weighted contribution
        // to the sibling blend (the same terms the SUM adds).
        val blueContribution = blueNorm * ObstructionScore.BLUE_WEIGHT
        val dominant = listOf(
            ObstructionSignal.SOJOURN to sojournContribution,
            ObstructionSignal.BLUE to blueContribution,
            ObstructionSignal.SCORE_COLLAPSE to scoreContribution,
            ObstructionSignal.COMPETING to (if (competing) ObstructionScore.COMPETING_LIFT else 0.0),
        ).maxByOrNull { it.second }?.takeIf { it.second > 0.0 }?.first ?: ObstructionSignal.NONE

        return ObstructionVerdict(score = score, dominantSignal = if (score <= 0.0) ObstructionSignal.NONE else dominant)
    }

    /** value/target clamped to `[0,1]` (target>0); 0 when value ≤ 0. The basic "how far over the line". */
    private fun ratioNorm(value: Double, target: Double): Double {
        if (target <= 0.0 || value <= 0.0) return 0.0
        return (value / target).coerceIn(0.0, 1.0)
    }

    /**
     * Score-collapse normalization. The §4 governor `score = blend(p95,loss,cwnd,jitter)` is LOWER-better.
     * A "collapse" is the BEST available upstream score sitting far above the healthy floor: even our best
     * option is bad. Mapped 0 at/below [SolverThresholds.scoreHealthy] → 1 at/above
     * [SolverThresholds.scoreCollapsed]. A `null`/NaN best-score contributes 0 (no false obstruction).
     */
    private fun scoreCollapseNorm(bestScore: Double?, t: SolverThresholds): Double {
        val s = bestScore ?: return 0.0
        if (s.isNaN() || s.isInfinite()) return 0.0
        val span = t.scoreCollapsed - t.scoreHealthy
        if (span <= 0.0) return 0.0
        return ((s - t.scoreHealthy) / span).coerceIn(0.0, 1.0)
    }

    // =====================================================================================
    // 2 · RE-SOLVE TRIGGER (ENTER side) — the debounced Schmitt gate (anti-thrash I1 & I5).
    // =====================================================================================

    /**
     * The ENTER-side anti-thrash gate (the half the sibling [Hysteresis] defers here, `Hysteresis.kt:20-22`):
     * decide whether a fresh [verdict] (with its running debounce/hysteresis counters) warrants a solve.
     * PURE — returns the *decision* and the *next* counter state; the caller (the live `SolverManager`)
     * holds the counters and, on a `trigger`, asks the sibling [Hysteresis.gateSolve] (the COMMIT side,
     * I2/I4) before racing.
     *
     *  - **I5 DEBOUNCE (confirm-before-act):** an obstruction must hold `score ≥ enter` for
     *    [SolverThresholds.confirmSamples] CONSECUTIVE ticks. A 1-tick spike never triggers.
     *  - **I1 HYSTERESIS (Schmitt two-band):** `enter > exit`. Once armed it disarms only below `exit`; a
     *    signal sawtoothing inside the dead-band `(exit, enter)` never re-triggers. The "armed" latch in
     *    [TriggerState] encodes the crossing so two triggers never straddle a single dead-band crossing.
     *
     * @return a [TriggerDecision]: `trigger` = fire a solve THIS tick; `next` = the carried counter state.
     */
    fun shouldTrigger(
        verdict: ObstructionVerdict,
        state: TriggerState,
        thresholds: SolverThresholds = SolverThresholds(),
    ): TriggerDecision {
        // Hysteresis low band: below exit → fully cleared, disarm, reset the confirm run.
        if (verdict.score < thresholds.triggerExit) {
            return TriggerDecision(trigger = false, next = TriggerState(armed = false, confirmRun = 0))
        }

        // Dead-band (exit ≤ score < enter): hold the latch; never (re)trigger here; reset the confirm run.
        if (verdict.score < thresholds.triggerEnter) {
            return TriggerDecision(trigger = false, next = state.copy(confirmRun = 0))
        }

        // Over the enter threshold: accumulate consecutive over-threshold ticks (debounce).
        val run = state.confirmRun + 1

        // Already armed from a still-unbroken high episode: do NOT re-fire (I1 — one trigger per crossing).
        if (state.armed) {
            return TriggerDecision(trigger = false, next = state.copy(confirmRun = run))
        }

        // Not yet armed: fire only once the debounce is satisfied; arming latches the crossing.
        return if (run >= thresholds.confirmSamples) {
            TriggerDecision(trigger = true, next = TriggerState(armed = true, confirmRun = run))
        } else {
            TriggerDecision(trigger = false, next = state.copy(confirmRun = run))
        }
    }

    // =====================================================================================
    // 3 · RACE ORCHESTRATION — enumerate transport×resolver×relay, pick the measured winner.
    // =====================================================================================

    /**
     * Is this transport composable with an anonymizing relay? DNSCrypt has anonymized relays (and ODoH-
     * style relaying); plain DoH/DoH3/DoQ do not in this engine, so they only race relay-less. Kept as a
     * local fact (not an enum field) so the shared sibling [TransportKind] stays untouched.
     */
    fun isRelayCapable(transport: TransportKind): Boolean = transport == TransportKind.DNSCRYPT

    /**
     * Enumerate the `transport × resolver × relay` candidate axes (Monster Plan §7). PURE: produces the
     * cross-product of the supplied axes WITHOUT measuring anything — the live measurement is injected
     * separately and DEFERRED to the live manager.
     *
     * Relay axis semantics: a `null` entry in [relays] means "direct, no relay" — always included so a
     * transport/resolver can be raced relay-less. An empty [relays] list is treated as `[null]` (direct
     * only). Each resolver carries the transports IT supports; the cross-product only pairs a resolver with
     * a transport it advertises (never an impossible binding). A non-relay-capable transport
     * ([isRelayCapable] false) pairs only with the direct (`null`) relay.
     *
     * The result is bounded and deterministic (stable order by transport ordinal, resolver id, relay id)
     * so a live racer measures a predictable, capped set (no unbounded fan-out at an obstruction).
     */
    fun enumerateRace(
        resolvers: List<RaceResolver>,
        relays: List<RaceRelay?>,
    ): List<RaceCandidate> {
        if (resolvers.isEmpty()) return emptyList()
        val relayAxis = if (relays.isEmpty()) listOf<RaceRelay?>(null) else relays
        val out = ArrayList<RaceCandidate>()
        for (r in resolvers) {
            for (t in r.transports) {
                for (relay in relayAxis) {
                    if (relay != null && !isRelayCapable(t)) continue
                    out.add(RaceCandidate(transport = t, resolver = r, relay = relay))
                }
            }
        }
        return out.sortedWith(
            compareBy({ it.transport.ordinal }, { it.resolver.id }, { it.relay?.id ?: "" })
        )
    }

    /**
     * PURE pick of the race winner from MEASURED candidates (mirrors
     * [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationPing.rankByRtt]). Drops unreachable measurements
     * (`rttMs < 0`), then maximizes [raceScore] (lower RTT wins; trusted props add a bounded tiebreak; a
     * stable composite key breaks exact ties). Returns `null` when no candidate is reachable — the caller's
     * fail-safe to KEEP the current binding (never lock onto an all-dead race), exactly the
     * [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationSelector.select] → `null` contract.
     */
    fun pickRaceWinner(
        measured: List<RaceMeasurement>,
        thresholds: SolverThresholds = SolverThresholds(),
    ): RaceMeasurement? {
        val reachable = measured.filter { it.reachable }
        if (reachable.isEmpty()) return null
        return reachable.maxWithOrNull(
            compareBy<RaceMeasurement> { raceScore(it, thresholds) }
                .thenByDescending { it.candidate.stableKey }
        )
    }

    /**
     * Race score (higher = picked). RTT dominates via `RTT_WEIGHT_BASE / (1 + rttMs)` (the
     * [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationSelector.score] shape, kept consistent so the Solver
     * ranks on the SAME curve the rest of the app trusts). Trust props (no-log / DNSSEC) and a preferred
     * transport add small, bounded bonuses that only break near-ties — they never let a much slower binding
     * leapfrog a much faster one. Unreachable candidates never reach here.
     *
     * NOTE: this is the *race-pick* score (higher = better, for the winner selection). The COMMIT-side
     * incumbent-to-beat score ([SolverBinding.score] / [LockedBinding.score]) is the inverse, LOWER-better
     * (the §4 governor convention the sibling [Hysteresis.decideSwitch] uses) — [tuneBinding] derives that
     * separately from the measured RTT so the two conventions never get crossed.
     */
    fun raceScore(m: RaceMeasurement, t: SolverThresholds = SolverThresholds()): Double {
        val rtt = m.rttMs.coerceAtLeast(0)
        val rttWeight = RTT_WEIGHT_BASE / (1.0 + rtt)
        var bonus = 0.0
        if (m.candidate.resolver.noLog) bonus += NOLOG_BONUS
        if (m.candidate.resolver.dnssec) bonus += DNSSEC_BONUS
        bonus += t.transportBonus(m.candidate.transport)
        return rttWeight + bonus
    }

    // =====================================================================================
    // 4 · BINDING SELECTION — pick optimal + derive tuned cwnd / CAKE params for the link.
    // =====================================================================================

    /**
     * The whole Stage-E solve, composed PURELY: enumerate → (inject the measurement) → pick → tune.
     * Returns the [SolverBinding] the live lock WOULD commit (DEFERRED — no swap is performed here), or
     * `null` when nothing reachable wins (KEEP the current binding — the fail-safe).
     *
     * The measurement is INJECTED: [measureFn] maps each enumerated [RaceCandidate] to a [RaceMeasurement].
     * In tests this is a synthetic table (deterministic, on-metal); in the live manager it is the existing
     * off-pool ping seam (`RotationPing.rankCandidates`), never a new pinger. This keeps the LIVE race
     * deferred while the orchestration is fully tested now.
     *
     * **K2 — the tune brain is INJECTED ([tuneBrain]), REQUIRED (no Kotlin default).** The Rust
     * [`Beast`] is the SOLE cwnd brain now (Socio mandate 2026-06-27/2026-06-29 — no Kotlin congestion
     * math anywhere, hot path AND self-heal); the Kotlin canonicals (`YeahController.kt`/`CakeScheduler.kt`)
     * are RETIRED. There is NO default Kotlin brain anymore — every caller MUST inject one. The LIVE path
     * (R-Beast-Wire.4 Stage-C, LANDED) injects [pillar.kuma_saimono.libumdnscrypt.dns_engine.beast.BeastTuneBrain]
     * — the Rust-`Beast`-backed brain that warms a fresh `Beast(CANONICAL, COBALT)` with the winner's RTT
     * and reads back its cwnd; tests inject a deterministic stub. This makes the Rust Beast the only brain
     * on BOTH the hot path (`MonokumaDnsEngine` → `Beast.cwnd()`) and the Solver self-heal/rotation path,
     * with ZERO Kotlin hot-math — the Solver is pure orchestration, it owns no brain.
     *
     * @param resolvers  the resolver axis (each with its supported transports + trust props).
     * @param relays     the relay axis (`null` allowed = direct). Empty ⇒ direct-only.
     * @param thresholds tuning band for the race score + the cwnd/CAKE derivation.
     * @param tuneBrain  the REQUIRED injected YeAH brain `(rttMs, warmupSamples) -> cwnd`, forwarded to
     *                   [tuneBinding]. Live = the Rust Beast; tests = a deterministic stub.
     * @param measureFn  the injected per-candidate measurement (the deferred-live boundary) — LAST param
     *                   so it can be passed as the trailing lambda at the call site.
     */
    fun solveBinding(
        resolvers: List<RaceResolver>,
        relays: List<RaceRelay?>,
        thresholds: SolverThresholds = SolverThresholds(),
        tuneBrain: (rttMs: Double, warmupSamples: Int) -> Int,
        measureFn: (RaceCandidate) -> RaceMeasurement,
    ): SolverBinding? {
        val candidates = enumerateRace(resolvers, relays)
        if (candidates.isEmpty()) return null
        val measured = candidates.map(measureFn)
        val winner = pickRaceWinner(measured, thresholds) ?: return null
        return tuneBinding(winner, thresholds, tuneBrain)
    }

    /**
     * Derive the tuned `cwnd` + CAKE params for a won binding from its measured RTT. PURE: it asks an
     * injected YeAH brain for a healthy window at this RTT — the Solver does not invent a window, it asks
     * the brain. CAKE's CoDel interval scales with RTT (`max(20ms, baseRtt)`, Monster Plan §3.1), so the
     * locked binding carries link-tuned AQM, not a one-size value. [SolverBinding.score] is set to the
     * measured RTT (LOWER-better — the sibling [Hysteresis.decideSwitch] incumbent-to-beat convention).
     *
     * **K2 — the brain is INJECTED ([tuneBrain]), REQUIRED (no Kotlin default), exactly like
     * [solveBinding]'s [measureFn].** The Rust [`Beast`] is the SOLE cwnd brain now; the Kotlin
     * canonicals are RETIRED. There is NO default Kotlin brain — the Solver owns no congestion math.
     * The LIVE path (R-Beast-Wire.4 Stage-C, LANDED) injects
     * [pillar.kuma_saimono.libumdnscrypt.dns_engine.beast.BeastTuneBrain] — the Rust-`Beast`-backed brain
     * `(rtt, warmup) -> cwnd` that warms a fresh `Beast(CANONICAL, COBALT)` and reads back its cwnd;
     * tests inject a deterministic stub. This keeps the Solver pure+testable AND makes the Rust Beast
     * the only brain — no Kotlin hot-math remains anywhere.
     *
     * @param winner    the measured race winner (its RTT primes the brain).
     * @param thresholds tuning band for the cwnd/CAKE derivation.
     * @param tuneBrain the REQUIRED injected YeAH brain `(rttMs, warmupSamples) -> cwnd`. Live = the Rust
     *                  Beast; tests = a deterministic stub.
     */
    fun tuneBinding(
        winner: RaceMeasurement,
        thresholds: SolverThresholds = SolverThresholds(),
        tuneBrain: (rttMs: Double, warmupSamples: Int) -> Int,
    ): SolverBinding {
        val rtt = winner.rttMs.coerceAtLeast(1).toDouble()

        // Ask the injected brain for a healthy window at this RTT (REUSE — no parallel control law).
        val tunedCwnd = tuneBrain(rtt, thresholds.tuneWarmupSamples)

        val codelTargetMs = thresholds.sojournTargetMs
        val codelIntervalMs = maxOf(thresholds.codelIntervalFloorMs, rtt.toLong())

        return SolverBinding(
            transport = winner.candidate.transport,
            resolverId = winner.candidate.resolver.id,
            relayId = winner.candidate.relay?.id,
            measuredRttMs = winner.rttMs,
            tunedCwnd = tunedCwnd,
            tunedCodelTargetMs = codelTargetMs,
            tunedCodelIntervalMs = codelIntervalMs,
            cakeProfile = TortaProfile.BASELINE,
            score = winner.rttMs.coerceAtLeast(0).toDouble(), // LOWER-better (Hysteresis incumbent convention)
        )
    }

    /**
     * Convert a solved [SolverBinding] into the sibling cache's [LockedBinding] for [BindingCache.commit]
     * (REUSE the cache type — no parallel record). Both scores are LOWER-better, so [SolverBinding.score]
     * passes straight through as the cache/[Hysteresis] incumbent-to-beat.
     *
     * @param nowMs caller-supplied wall-clock for [LockedBinding.lockedAtMs] / [LockedBinding.lastHealthyAtMs].
     */
    fun toLockedBinding(binding: SolverBinding, nowMs: Long): LockedBinding = LockedBinding(
        transport = binding.transport,
        resolverId = binding.resolverId,
        relayId = binding.relayId,
        tunedCwnd = binding.tunedCwnd,
        tunedCodelTargetMs = binding.tunedCodelTargetMs,
        score = binding.score,
        lockedAtMs = nowMs,
        lastHealthyAtMs = nowMs,
    )

    // ---- Race-score weights (kept in lockstep with RotationSelector's curve). ----

    /** RTT weight numerator — at 0 ms a binding weighs this; falls off as `BASE / (1 + rttMs)`. */
    const val RTT_WEIGHT_BASE = 1000.0

    /** Bounded tiebreak bonus for a no-log resolver (privacy is the headline reason to solve). */
    const val NOLOG_BONUS = 5.0

    /** Bounded tiebreak bonus for a DNSSEC-validating resolver. */
    const val DNSSEC_BONUS = 3.0
}
