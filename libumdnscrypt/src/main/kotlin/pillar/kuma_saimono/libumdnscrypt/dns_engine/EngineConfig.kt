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

package pillar.kuma_saimono.libumdnscrypt.dns_engine

/**
 * The Beast tunables — the documented algorithm constants the Rust Beast (`beast/{yeah,cake}.rs`) was
 * ported from, mirrored here as standalone Kotlin values so [EngineConfig] + the Expert settings UI +
 * [EnginePreset] keep their shape WITHOUT depending on the retired Kotlin canonicals
 * (`YeahController.kt` / `CakeScheduler.kt`, K2-retired — the Rust Beast is the sole engine now).
 *
 * GROUND_TRUTH: every value is MEASURED from the Rust source of truth
 * (`rust/torta_core/src/beast/yeah.rs:28-42`, `rust/torta_core/src/beast/cake.rs:28-45`), byte-identical
 * to the retired Kotlin canonicals (the faithful port). These are the documented algorithm constants;
 * the Rust Beast owns the live math. Cite the Rust file when in doubt, never re-derive.
 */
object BeastTunables {
    // ---- YeAH (`beast/yeah.rs:28-42`) ----
    const val MIN_WINDOW: Int = 1
    const val MAX_WINDOW: Int = 16
    const val YEAH_FREE_THRESH: Double = 1.05
    const val YEAH_COMPETE_THRESH: Double = 1.25
    const val Q_MAX_FRAC: Double = 0.5
    const val RHO: Int = 16

    // ---- CAKE (`beast/cake.rs:28-45`) ----
    val TIN_MAX_DEPTH: IntArray = intArrayOf(4, 8, 16)
    val DEFAULT_TIN_WEIGHTS: IntArray = intArrayOf(100, 50, 12)
    const val DEFAULT_QUANTUM: Int = 1
    const val DEFAULT_SET_ASSOC_WAYS: Int = 8
    const val DEFAULT_CODEL_TARGET_MS: Long = 5L
    const val DEFAULT_CODEL_INTERVAL_MS: Long = 20L
}

/**
 * Tunables for the CAKE/YeAH engine. The defaults reproduce the original hardcoded "Standard" beast
 * exactly (cycle 5 s, cwnd cap 16, FREE 1.05, COMPETE 1.25) — so an untouched install, and every
 * existing unit test, behaves identically to before the engine became configurable.
 *
 * - [cycleMs]       how often a probe cycle fires (lower = fresher relay pick, a touch more battery).
 * - [maxWindow]     YeAH concurrency cap (higher = more parallel probes / throughput, more load).
 * - [freeThresh]    "free bandwidth" RTT multiplier vs baseRtt — below it, YeAH grows the window.
 * - [competeThresh] "congestion" RTT multiplier vs baseRtt — above it, YeAH halves the window.
 *
 * Monster Plan §3/§4 knobs. Every default below maps to the Rust Beast's Canonical YeAH × CoBALT CAKE
 * profile (the flagship profiles the live Beast is constructed with at `MonokumaDnsEngine.kt:331`);
 * they are carried so the Expert settings UI + [EnginePreset] keep their shape + the prefs round-trip
 * stays stable, but they are INERT on the live engine path (the Rust Beast is constructed with its own
 * Canonical/CoBALT profiles regardless of these fields, and only [cycleMs] still drives the live engine
 * — the probe cadence). The Rust Beast (`beast/{yeah,cake}.rs`) is the sole engine (K2 — the Kotlin
 * canonicals `YeahController.kt`/`CakeScheduler.kt` are retired, no live instantiation holds the
 * cwnd/AQM brain anymore).
 *
 * - [yeahProfile]   LEGACY (default) / CANONICAL / LINERATE — which YeAH brain the Rust Beast ran.
 * - [cakeProfile]   LEGACY (default) / COBALT — which CAKE/AQM mechanism the Rust Beast ran.
 * - [qMaxFrac]      canonical Q backlog fraction: precautionary decongestion fires when Q > cwnd·frac.
 * - [rho]           canonical loss reaction: renoCount > rho ⇒ full Reno halve, else gentle clamp.
 * - [codelTargetMs] COBALT CoDel target sojourn (ms) — below it the queue is "free", nothing sheds.
 * - [tinWeights]    DiffServ WRR shares per tin ~[100,50,12] (Interactive/Background/Bulk).
 * - [quantum]       DRR++ per-round deficit credit granted to each served flow.
 * - [setAssocWays]  8-way set-associative flow hashing — number of buckets per tin.
 * - [pacingMode]    how the derived pacing rate cwnd/(baseRtt/1000) is applied (Stage B+ seam).
 *
 * @param yeahProfile the YeAH brain selector (LEGACY/CANONICAL/LINERATE). INERT on the live engine —
 *   the Rust Beast is always constructed CANONICAL. Kept for the Expert UI + prefs round-trip.
 * @param cakeProfile the CAKE/AQM selector (LEGACY/COBALT). INERT on the live engine — the Rust Beast is
 *   always constructed COBALT. Kept for the Expert UI + prefs round-trip.
 */
data class EngineConfig(
    val cycleMs: Long = MonokumaDnsEngine.CYCLE_MS,
    val maxWindow: Int = BeastTunables.MAX_WINDOW,
    val freeThresh: Double = BeastTunables.YEAH_FREE_THRESH,
    val competeThresh: Double = BeastTunables.YEAH_COMPETE_THRESH,
    val yeahProfile: uniffi.torta_core.YeahProfile = uniffi.torta_core.YeahProfile.LEGACY,
    val cakeProfile: uniffi.torta_core.TortaProfile = uniffi.torta_core.TortaProfile.LEGACY,
    val qMaxFrac: Double = BeastTunables.Q_MAX_FRAC,
    val rho: Int = BeastTunables.RHO,
    val codelTargetMs: Long = BeastTunables.DEFAULT_CODEL_TARGET_MS,
    val tinWeights: IntArray = BeastTunables.DEFAULT_TIN_WEIGHTS,
    val quantum: Int = BeastTunables.DEFAULT_QUANTUM,
    val setAssocWays: Int = BeastTunables.DEFAULT_SET_ASSOC_WAYS,
    val pacingMode: PacingMode = PacingMode.PROBE,
) {
    init {
        // Defense-in-depth (completeness finding): the Rust Beast (the sole live engine) is constructed
        // CoBALT and never reads config.tinWeights, so this is dead-code-safe. The guard exists so a
        // malformed config can NEVER reach a COBALT scheduler (where tinWeights indexes stride[tin]
        // / pass[tin] and a wrong length AIOOBEs). Mirrors the Rust Beast's own length contract
        // (`beast/cake.rs:48 TIN_COUNT`); the default [100,50,12] satisfies it.
        require(tinWeights.size == 3) {
            "tinWeights must have exactly 3 entries (Critical/High/Normal), was ${tinWeights.size}"
        }
    }

    /**
     * Defense-in-depth (completeness finding): the clamped view of [tinWeights] — every entry coerced to
     * ≥1. Mirrors the Rust Beast's constructor clamp (`beast/cake.rs` — a 0/negative weight is a
     * divide-by-zero in stride = UNIT/weight). Read this, not the raw field, when handing weights to a
     * COBALT scheduler so a malformed config can never reach it. The default [100,50,12] is unchanged.
     */
    val tinWeightsNormalized: IntArray
        get() = IntArray(tinWeights.size) { tinWeights[it].coerceAtLeast(1) }

    // A data class with an IntArray member needs structural equals/hashCode by content, not identity,
    // so two default configs (or two read from the same prefs) compare equal as callers expect.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EngineConfig) return false
        return cycleMs == other.cycleMs &&
            maxWindow == other.maxWindow &&
            freeThresh == other.freeThresh &&
            competeThresh == other.competeThresh &&
            yeahProfile == other.yeahProfile &&
            cakeProfile == other.cakeProfile &&
            qMaxFrac == other.qMaxFrac &&
            rho == other.rho &&
            codelTargetMs == other.codelTargetMs &&
            tinWeights.contentEquals(other.tinWeights) &&
            quantum == other.quantum &&
            setAssocWays == other.setAssocWays &&
            pacingMode == other.pacingMode
    }

    override fun hashCode(): Int {
        var result = cycleMs.hashCode()
        result = 31 * result + maxWindow
        result = 31 * result + freeThresh.hashCode()
        result = 31 * result + competeThresh.hashCode()
        result = 31 * result + yeahProfile.hashCode()
        result = 31 * result + cakeProfile.hashCode()
        result = 31 * result + qMaxFrac.hashCode()
        result = 31 * result + rho
        result = 31 * result + codelTargetMs.hashCode()
        result = 31 * result + tinWeights.contentHashCode()
        result = 31 * result + quantum
        result = 31 * result + setAssocWays
        result = 31 * result + pacingMode.hashCode()
        return result
    }
}

/**
 * How the YeAH window is turned into a real send rate. Stage A is internals-only: [PROBE] = today's
 * 6-probe-per-cycle path (the default, no traffic change). [PACED] = the future derived
 * cwnd/(baseRtt/1000) qps pacing wired to the resolver semaphore in Stage B+.
 */
enum class PacingMode { PROBE, PACED }

/**
 * Noob-friendly presets — each maps a plain-language goal onto the real tunables, so a user who
 * never opens Expert mode still gets a sensible beast. [DEFAULT] is the Standard build: balanced and
 * low-latency, the one we recommend for gaming (snappy ping without starving throughput).
 *
 * The "ping / bandwidth / upload / download" language is the user's metaphor for what the window +
 * cadence + thresholds actually do: a small fast window minimises latency, a large tolerant window
 * maximises concurrency. Honest mapping, friendly name.
 *
 * NOTE (K2): the [yeahProfile]/[cakeProfile] fields are INERT on the live engine (the Rust Beast is
 * always constructed Canonical×CoBALT); the presets still carry [cycleMs]/[maxWindow]/[freeThresh]/
 * [competeThresh] so the Expert UI shape + prefs round-trip stay stable.
 */
enum class EnginePreset(val key: String, val config: EngineConfig) {
    /** ⚖️ Balanced, as built — recommended for gaming (low latency without starving throughput). */
    DEFAULT("default", EngineConfig()),

    /** 🏓 Latency-first: small window, fast cadence, tight backoff → the lowest possible ping. */
    FAST_PING(
        "ping",
        EngineConfig(cycleMs = 3000L, maxWindow = 8, freeThresh = 1.02, competeThresh = 1.15)
    ),

    /** 🌊 Throughput-first: large window, tolerant thresholds → maximum concurrency / bandwidth. */
    OMEGA_BANDWIDTH(
        "bandwidth",
        EngineConfig(cycleMs = 5000L, maxWindow = 32, freeThresh = 1.10, competeThresh = 1.50)
    ),

    /** 🚀 Big window + brisk cadence, moderate backoff → fast upload feel, faster downloads. */
    UPLOAD_DOWNLOAD(
        "upload_download",
        EngineConfig(cycleMs = 4000L, maxWindow = 24, freeThresh = 1.05, competeThresh = 1.40)
    );

    companion object {
        /** The pick an untouched install lands on. */
        val DEFAULT_PRESET = DEFAULT

        fun fromKey(key: String?): EnginePreset =
            entries.firstOrNull { it.key == key } ?: DEFAULT
    }
}
