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
 * Pure, immutable data types for the Stage-E [Solver] core (Monster Plan §7). Zero Android / socket /
 * coroutine deps → JUnit-on-metal clean.
 *
 * **Convergence note (REUSE, not fork).** The transport axis ([TransportKind]), the per-network cache
 * ([BindingCache] / [LockedBinding] / [NetworkFingerprint]) and the COMMIT-side anti-thrash gate
 * ([Hysteresis] — dwell I2 / cooldown I4 / cost-of-switching I3) are the SIBLING owner files in this
 * package — this file does NOT re-declare any of them. It carries the types unique to the [Solver]:
 *  - the **obstruction-detect** input/output ([SolverInput] → [ObstructionVerdict]);
 *  - the **ENTER-side** re-solve-trigger state ([TriggerState] / [TriggerDecision]) — invariants I1 + I5,
 *    the half of the anti-thrash spine the sibling [Hysteresis] explicitly defers to the [Solver]
 *    (`Hysteresis.kt:20-22`);
 *  - the **race** types ([RaceResolver] / [RaceRelay] / [RaceCandidate] / [RaceMeasurement]) + the solved
 *    [SolverBinding];
 *  - the [SolverThresholds] band (the ENTER-side dials + the obstruction/race/tuning dials; the COMMIT-side
 *    dials live on the sibling [Hysteresis.CommitConfig]).
 */

/**
 * The five obstruction sub-signals the [Solver.detectObstruction] blend reads (all already computed
 * per-cycle by the engine — the Solver invents no telemetry). [ObstructionVerdict.dominantSignal] names
 * which one drove the verdict (for the dashboard `solverLastSwitchReason`, Monster Plan §6).
 */
enum class ObstructionSignal {
    /** No obstruction (score 0). */
    NONE,

    /** CAKE COBALT sojourn P95 over the CoDel target — the AQM is shedding. */
    SOJOURN,

    /** CAKE BLUE drop probability climbing — timeouts/fails on the busiest tin. */
    BLUE,

    /** The per-upstream §4 governor score collapsed — even the best upstream is bad. */
    SCORE_COLLAPSE,

    /** YeAH is COMPETING / failovers mounting — the controller can't grow the window. */
    COMPETING,

    /** A captive-portal / throttle signature — a HARD obstruction (only a race fixes it). */
    CAPTIVE,
}

/**
 * The immutable per-cycle snapshot the engine folds for the Solver (Monster Plan §4/§6 signals). Every
 * field is something the engine ALREADY produces; the Solver only reads it.
 *
 * @param sojournP95Ms     CAKE COBALT queue-wait P95 in ms (the Rust Beast `beast/cake.rs` sojourn, `0` on LEGACY).
 * @param blueProb         CAKE BLUE drop probability of the busiest tin (the Rust Beast `beast/cake.rs`
 *                         `blue_prob`, surfaced via the pushed `BeastSnapshot.blueProb`); `[0,0.25]`, `0.0` on LEGACY.
 * @param bestUpstreamScore the LOWEST (best) per-upstream §4 governor score, lower-better; `null` when no
 *                         governor map exists yet (Stage-B not landed) ⇒ contributes no obstruction.
 * @param yeahCompeting    any governed upstream is in `YeahMode.COMPETING` (the Rust Beast `beast/yeah.rs` mode,
 *                         surfaced via the pushed `BeastSnapshot.mode == "COMPETING"`).
 * @param failovers        engine failover count this window (`MonokumaDnsEngine.failovers`,
 *                         `MonokumaDnsEngine.kt:98`).
 * @param fingerprint      opaque network fingerprint key (hashed SSID/gateway/linkType — the sibling
 *                         [NetworkFingerprint] produces it; the sibling [BindingCache] keys on it). Empty
 *                         ⇒ unknown network.
 * @param captiveSignature a captive-portal / throttle was detected (live producer is the Android manager).
 */
data class SolverInput(
    val sojournP95Ms: Long = 0L,
    val blueProb: Double = 0.0,
    val bestUpstreamScore: Double? = null,
    val yeahCompeting: Boolean = false,
    val failovers: Int = 0,
    val fingerprint: String = "",
    val captiveSignature: Boolean = false,
)

/**
 * The obstruction-detector output. [score] is normalized to `[0,1]`. [dominantSignal] is the strongest
 * contributor (for the dashboard reason). [score] feeds the ENTER-side [Solver.shouldTrigger] (I1 + I5);
 * if that fires, the COMMIT-side sibling [Hysteresis.gateSolve] / [Hysteresis.decideSwitch] take over.
 */
data class ObstructionVerdict(
    val score: Double,
    val dominantSignal: ObstructionSignal,
)

/**
 * The carried re-solve-trigger counter state (the ENTER-side anti-thrash latch, [Solver.shouldTrigger]).
 * Held by the live `SolverManager`; the [Solver] returns the NEXT state (pure, no mutation).
 *
 * @param armed      latched true once a high-band crossing has fired; cleared only below the EXIT band
 *                  (I1 hysteresis — one trigger per dead-band crossing).
 * @param confirmRun consecutive over-`enter` ticks (I5 debounce — confirm before act).
 */
data class TriggerState(
    val armed: Boolean = false,
    val confirmRun: Int = 0,
)

/** The trigger decision + the next [TriggerState] to carry. [trigger] = fire a solve THIS tick. */
data class TriggerDecision(
    val trigger: Boolean,
    val next: TriggerState,
)

/**
 * A resolver in the race pool. Pure data — every field is something the live manager already has from the
 * existing stamp reader (props bits — `DnsServerItem.java:76-84`) and the rotation seam. The Solver never
 * re-parses a stamp.
 *
 * @param id          stable resolver id (the `public-resolvers.md` name; the swap JSON `id`).
 * @param transports  the transports THIS resolver advertises (the cross-product only pairs supported ones).
 * @param noLog       stamp props bit1 — keeps no logs (a race-score privacy tiebreak).
 * @param dnssec      stamp props bit0 — validates DNSSEC (a race-score tiebreak).
 */
data class RaceResolver(
    val id: String,
    val transports: List<TransportKind>,
    val noLog: Boolean = false,
    val dnssec: Boolean = false,
)

/** A relay in the race pool (DNSCrypt anonymized relay / ODoH). `null` in the axis = direct (no relay). */
data class RaceRelay(
    val id: String,
)

/**
 * One enumerated race candidate: a `transport × resolver × relay` triple (Monster Plan §7). [relay] is
 * `null` for a direct binding. [stableKey] is the deterministic tiebreak key (so the same race always
 * yields the same winner on an exact-tie — reproducible, churn-free).
 */
data class RaceCandidate(
    val transport: TransportKind,
    val resolver: RaceResolver,
    val relay: RaceRelay?,
) {
    /** Deterministic identity for tiebreaks + dedup: `transport|resolverId|relayId`. */
    val stableKey: String get() = "${transport.name}|${resolver.id}|${relay?.id ?: ""}"
}

/**
 * A MEASURED race candidate (the injected/deferred-live boundary). [rttMs] is the measured latency in ms
 * from the existing off-pool ping seam (`RotationPing`); `< 0` (the seam's `NO_CONNECTION = -1`) means
 * unreachable → excluded from the pick. In tests this is a synthetic table; in the live manager it is the
 * real ping — the Solver itself opens nothing.
 */
data class RaceMeasurement(
    val candidate: RaceCandidate,
    val rttMs: Int,
) {
    /** Reachable iff the measurement returned a real, non-negative latency. */
    val reachable: Boolean get() = rttMs >= 0
}

/**
 * The solved, optimal binding the live lock WOULD commit (DEFERRED — no swap is performed by the [Solver]).
 * It carries the won transport/resolver/relay AND the link-tuned `cwnd` + CAKE params, so the live
 * `SolverManager` can hand it straight to the atomic swap (`TortaCore.configureResolver`, re-called never
 * re-authored, `RotationManager.kt:48-58`) once GOVERN + SOLVER + the Shadow governor map all land.
 *
 * [score] is **lower-better** (the §4 governor blend convention the sibling [Hysteresis.decideSwitch]
 * reasons about) so a solved binding's score drops straight in as the incumbent-to-beat. It maps onto the
 * sibling cache's [LockedBinding] via [Solver.toLockedBinding].
 */
data class SolverBinding(
    val transport: TransportKind,
    val resolverId: String,
    val relayId: String?,
    val measuredRttMs: Int,
    val tunedCwnd: Int,
    val tunedCodelTargetMs: Long,
    val tunedCodelIntervalMs: Long,
    val cakeProfile: TortaProfile,
    val score: Double,
)

/**
 * The Solver tuning band — every raw dial behind the ONE Expert toggle (`pref_engine_expert`,
 * `TortaeKeys.java:166`) per SIMPLE-UX; the noob "self-heal DNS" master switch
 * (`DNS_ENGINE_SOLVER`, a default-ON switch that ships today — `TortaeKeys.java:193`) only flips
 * the whole Solver on/off. NOTE: ON ≠ live — the Solver runs SHADOW-only (renders state, configure is
 * a no-op) until `DNS_ENGINE_GOVERN` (default OFF, `TortaeKeys.java:182`) + Stage-C arm (#85).
 * Defaults are the safe, anti-thrash-first posture.
 *
 * **ENTER-side anti-thrash (I1 + I5; the half the sibling [Hysteresis] defers here, `Hysteresis.kt:49-51`):**
 * @param triggerEnter  Schmitt HIGH band: obstruction must reach this to (eventually) trigger. `> exit`.
 * @param triggerExit   Schmitt LOW band: obstruction must drop below this to clear/disarm. `< enter`.
 *                     The dead-band `(exit, enter)` is where a flapping signal is ABSORBED (I1).
 * @param confirmSamples consecutive over-`enter` ticks required before a trigger fires (I5 debounce).
 *
 * **Sub-signal scales** (the Solver's normalization of each engine signal to the `[0,1]` the sibling
 * [ObstructionScore] blend expects; the BLEND WEIGHTING is the sibling's own — not re-applied here):
 * @param sojournTargetMs  CoDel target the sojourn ratio normalizes against (Monster Plan §3.1: 5ms).
 * @param blueProbCeil     BLUE prob that maps to a full sub-signal (the Rust Beast `beast/cake.rs` caps blueProb at 0.25).
 * @param scoreHealthy     governor score at/below which score-collapse is 0 (lower-better).
 * @param scoreCollapsed   governor score at/above which score-collapse is 1.
 *
 * **Binding tuning:**
 * @param tuneWarmupSamples  free/fast samples fed to the injected YeAH brain (the Rust Beast on the live
 *                          path) to read a healthy window for the won link (REUSE — the Solver asks the
 *                          brain, not invents).
 * @param codelIntervalFloorMs  CoDel interval floor (Monster Plan §3.1: `max(20ms, baseRtt)`).
 * @param preferredTransport an optional small race-score nudge toward a transport (e.g. DoH3 on a good
 *                          link); `null` = no transport preference. NEVER outweighs RTT.
 */
data class SolverThresholds(
    // ENTER-side anti-thrash (Schmitt + debounce). MUST satisfy triggerEnter > triggerExit.
    val triggerEnter: Double = 0.70,
    val triggerExit: Double = 0.40,
    val confirmSamples: Int = 3,
    // Obstruction blend weights — applied by the Solver to the sojourn/score sub-signals BEFORE the sibling
    // [ObstructionScore.of] (which expects "already weighted by the caller", Hysteresis.kt:287-289). The BLUE
    // weight (BLUE_WEIGHT) and the competing lift (COMPETING_LIFT) live on the sibling; defaults here sum with
    // them to the canonical 0.35+0.25+0.25+0.075 = 0.925 saturated snapshot.
    val wSojourn: Double = 0.35,
    val wScore: Double = 0.25,
    // Sub-signal scales (the normalization the Solver applies before weighting).
    val sojournTargetMs: Long = 5L,
    val blueProbCeil: Double = 0.25,
    val scoreHealthy: Double = 20.0,
    val scoreCollapsed: Double = 200.0,
    // Binding tuning.
    val tuneWarmupSamples: Int = 8,
    val codelIntervalFloorMs: Long = 20L,
    val preferredTransport: TransportKind? = null,
) {
    /** Bounded preferred-transport bonus for the race score (small — never outweighs RTT). */
    fun transportBonus(t: TransportKind): Double =
        if (preferredTransport != null && t == preferredTransport) TRANSPORT_PREF_BONUS else 0.0

    companion object {
        /** The preferred-transport tiebreak bonus — same bounded scale as the props bonuses. */
        const val TRANSPORT_PREF_BONUS = 2.0
    }
}
