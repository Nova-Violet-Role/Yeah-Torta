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

@file:Suppress(
    "PackageNaming"
) // pillar.kuma_saimono is the app-wide namespace convention (every file); detekt's default regex
  // dislikes the underscore.

package pillar.kuma_saimono.libumdnscrypt.dns_engine.beast

import java.util.concurrent.atomic.AtomicLong
import javax.inject.Inject
import javax.inject.Singleton
import pillar.kuma_saimono.libumdnscrypt.data.dns_engine_metrics.DnsEngineMetricsRepository
import pillar.kuma_saimono.libumdnscrypt.dns_engine.PillarLog
import pillar.kuma_saimono.libumdnscrypt.dns_engine.metrics.DnsEngineMetrics
import pillar.kuma_saimono.libumdnscrypt.dns_engine.metrics.SolverPhase
import pillar.kuma_saimono.libumdnscrypt.dns_engine.metrics.SolverSnapshot
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.Solver
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.SolverInput
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import uniffi.torta_core.Beast
import uniffi.torta_core.BeastLogKind
import uniffi.torta_core.BeastMetricSink
import uniffi.torta_core.BeastSnapshot

/**
 * R-Beast-Wire — the Kotlin [BeastMetricSink] callback implementation.
 *
 * THE BEAST IS PURE RUST (Socio mandate 2026-06-27). The CAKE/YeAH/CoBALT hot math lives in the
 * Rust [`Beast`] Object; Kotlin only FEEDS samples + RECEIVES metrics via this push callback (no
 * polling, no Kotlin in the hot path). This class is the Kotlin face of that push seam: the Rust
 * engine calls [onMetrics] once per feed BATCH (D12 — `apply_samples`/`apply_udp_samples` push ONE
 * snapshot per batch; `on_loss`/`on_failover` push per event; beast/mod.rs `push_metrics`), and this
 * sink converts the [`BeastSnapshot`] into the immutable [DnsEngineMetrics] the dashboard already
 * renders — then publishes it into the shared [@Singleton] [DnsEngineMetricsRepository] so EVERY
 * Beast consumer ([BeastDashboardFragment] + [BeastSummaryCard]) becomes push-driven through the
 * same StateFlow they already collect. The Kotlin `MonokumaDnsEngine.emitMetrics()` poll RETIRES —
 * the Rust Beast owns the cwnd/AQM now, and the dashboard's source-of-truth is this callback.
 *
 * The snapshot is a 1:1 mirror of the [`BeastSnapshot`] Record (Rust beast/mod.rs:115-139): the
 * YeAH window state (cwnd/windowMax/mode/slowStartActive/baseRttMs/qPackets/renoCount/fastMode/
 * adaptiveTimeoutMs/pacingRate) + the UDP base_rtt (the first-ever UDP YeAH) + the CAKE/CoBALT
 * queue state (pipelineDepth/queueCritical/queueHigh/queueNormal/blueProb/cobaltDropped/aqmDropped/
 * drrSparseServed). The #121 Solver obstruction is re-derived LIVE from the Rust Beast's `blueProb`
 * (the COBALT BLUE valve) so the dashboard's self-heal card keeps its real signal.
 *
 * **CRASH-PROOF.** The callback runs on the Rust→Kotlin foreign-call thread. Any throw here would
 * propagate back into the Rust FFI boundary; every conversion is guarded so a malformed snapshot
 * degrades to "no publish this tick" (the dashboard keeps its last value), NEVER crashes the
 * engine. The [BeastMetricSink] `with_foreign` trait is implemented by THIS class — Kotlin passes
 * an instance to `beast.attachSink(...)` and Rust holds it as an `Arc<dyn BeastMetricSink>`.
 *
 * **HONEST BOUNDARY (the binding regen).** The [`BeastSnapshot`] / [BeastMetricSink] types are the
 * FIRST `#[derive(uniffi::Record)]` + FIRST `with_foreign` callback in the crate; the generated
 * `uniffi/torta_core/torta_core.kt` binding is REGEN'D by the Socio's gradle/ndk step
 * (`uniffi-bindgen generate` + `cargo-ndk -o src/main/jniLibs`). Until that regen lands this class
 * will not compile — that is the Socio's gated step, flagged here, not hidden.
 *
 * @see uniffi.torta_core.Beast the Rust engine Object (constructed once by [MonokumaDnsEngine])
 * @see MonokumaDnsEngine the engine that attaches this sink + feeds samples
 */
@Singleton
class BeastMetricSinkImpl
@Inject
constructor(
    private val repository: DnsEngineMetricsRepository,
    private val pathVars: dagger.Lazy<PathVars>,
) : BeastMetricSink {

    /**
     * D40 — the Beast handle for the CANON log seam: where a Rust pillar-log seam exists it is
     * canonical, so the latched cadence below drives `beast.logEvent` (the Rust `log_tier`
     * substrate writes `query-beast.log`) instead of the retired Kotlin PillarLog BEAST tag.
     * Bound by [buildBeastOrNull] right after construction; nulled by the manager on engine stop.
     */
    @Volatile private var beast: Beast? = null

    /** D12 — the last NAND log-write wall-clock ms (the min-interval latch's CAS anchor). */
    private val lastLogWriteMs = AtomicLong(0L)

    /** D12 — the last LOGGED YeAH mode (a mode CHANGE bypasses the latch — signal, not noise). */
    @Volatile private var lastLoggedMode: String? = null

    /** D40 — the last logged shed total (cobalt+aqm); a rise classifies the event as a SHED. */
    @Volatile private var lastLoggedShedTotal = -1L

    /** D40 — bind (or clear) the Beast handle the canon log seam writes through. */
    fun bindBeast(beast: Beast?) {
        this.beast = beast
    }

    /**
     * ★ E-FIX r3 — the ENGINE-LAYER context folded into every push. The [BeastSnapshot] carries the
     * Rust cwnd/AQM brain's fields, but the probe tallies / pool state / preferred endpoint /
     * jitter+p95 rings / failover count are ENGINE-layer facts the Rust Beast never sees. After the
     * R-Beast-Wire migration retired `emitMetrics()`, nothing folded them in — so the dashboard's
     * Success sat at 0% forever, Base-RTT-adjacent stats and Pool/Relay rendered "—", and the ticker
     * FROZE (its dedupe marker is `probesTotal + udpProbesTotal`, eternally 0+0). Witnessed live on
     * the AVD (round 3). [MonokumaDnsEngine] refreshes this once per cycle BEFORE feeding samples;
     * the manager clears it on engine stop.
     */
    @Volatile private var engineContext: EngineContext? = null

    /** ★ E-FIX r3 — refresh (or clear, on stop) the engine-layer context folded into each push. */
    fun updateEngineContext(context: EngineContext?) {
        engineContext = context
    }

    /**
     * The Rust Beast PUSHES a fresh [`BeastSnapshot`] here once per BATCH (D12 — the engine feeds
     * the cycle's samples through `applySamples`/`applyUdpSamples`, so this fires ~once per feed
     * batch + once per loss/failover, no longer once per sample). Convert it to [DnsEngineMetrics],
     * publish into the [@Singleton] repository so every dashboard consumer receives it through the
     * same StateFlow they already collect (RAM StateFlow — every push, correct), AND drive the
     * LATCHED #133 per-pillar event logs (D12 — the NAND writes are min-interval gated). Fail-open:
     * any fault logs + skips this tick (the dashboard keeps its last snapshot), never throws back
     * into the Rust FFI boundary.
     */
    @Suppress(
        "TooGenericExceptionCaught"
    ) // FFI boundary: ANY throw back into Rust is catastrophic — catch broad, log, skip the tick.
    override fun onMetrics(snapshot: BeastSnapshot) {
        try {
            // ★ E-FIX r3 — fold the live engine-layer context (probe tallies / pool / endpoint /
            // jitter+p95 / failovers) into the Rust snapshot before publishing; null (engine
            // stopped / not yet cycled) publishes the Rust fields with the honest defaults.
            val metrics = snapshot.toDnsEngineMetrics().foldEngineContext(engineContext)
            repository.publish(metrics)
            writePillarLogs(snapshot, metrics)
        } catch (e: Exception) {
            loge("BeastMetricSinkImpl onMetrics — skipping this tick", e)
        }
    }

    /**
     * #133 per-pillar event logs, D12-LATCHED: at most one NAND write burst per
     * [LOG_MIN_INTERVAL_MS] (15 s), EXCEPT a YeAH mode CHANGE which bypasses the latch (a mode
     * shift is the signal the review log exists for). This kills the metrics amplification the
     * old shape carried (three unconditional file appends per push × up to cwnd pushes per 5-s
     * cycle — the RAM⊗NAND axis's only live hot-path-write breach); the RAM StateFlow publish in
     * [onMetrics] stays per-push, untouched.
     *
     * D40 — ONE write path per file: BEAST goes through the Rust canon seam
     * ([Beast.logEvent] → the `log_tier` substrate, the same writer the SLINT Beast Tab's
     * RECENT-TICKS tail reads), classified TICK / MODE-SHIFT / SHED from the live snapshot;
     * SOLVER + DNSMASQ (no Rust twin exists) stay on the Kotlin [PillarLog]. Operational fields
     * only — no qname/PII (T20). Bounded + fail-open at every layer.
     */
    @Suppress(
        "TooGenericExceptionCaught"
    ) // pathVars.get() can throw any Dagger/Lazy provision fault — catch broad, degrade, never
      // crash the push.
    private fun writePillarLogs(pushed: BeastSnapshot, m: DnsEngineMetrics) {
        val now = System.currentTimeMillis()
        val modeChanged = m.mode != lastLoggedMode
        if (!acquireLogLatch(modeChanged, now)) return

        // ★ THE LOG WAS SHOWING A DIFFERENT BEAST THAN THE APP (found checkpoint 98, MEASURED).
        //
        // There are TWO Beasts in this process and they are not the same object:
        //
        //   * the LIVE one — `beast/mod.rs:328` `LIVE_BEAST` (LineRate x SoftCake), the process-
        //     global telemetry controller the DATAPATH feeds: one measured RTT per live-forwarded
        //     resolve (`resolver/mod.rs:1641`), every forwarder dial (`forwarder/run.rs:719/765/812`)
        //     and every shaped flow (`:419/:837`), plus its own AQM pump.
        //   * the one THIS sink is attached to — built fresh in `MonokumaDnsEngine.buildBeastOrNull`
        //     (`:461`) and fed ONLY by the engine's endpoint-probe cycle (`:258-259`).
        //
        // The ENGINE tab already renders the LIVE one (`TortaPillarBridge.liveBeastStats` ->
        // `beastLiveSnapshot()`), but this log wrote the PUSHED one — so `query-beast.log` reported
        // `rtt=0.0ms udp=0.0ms pace=0.0/s valve=0.0000` across 195 consecutive lines while the app's
        // own card showed the true window. The probe plane is currently dead (`RotationPing
        // filterRoutableRelays: 0/365 relays probed reachable -- FAIL-OPEN`), so the pushed snapshot
        // has no RTT to report and never will until that is fixed.
        //
        // The docstring above promised this file is "the same writer the SLINT Beast Tab's
        // RECENT-TICKS tail reads". That promise was FALSE for every RTT field. Reading the live
        // snapshot here makes it true: ONE source of truth per pillar, the same one the UI renders.
        //
        // FAIL-OPEN: any throw from the FFI keeps the pushed snapshot, so a native fault degrades the
        // log's fidelity instead of killing the push (the sink's contract everywhere else).
        val snapshot: BeastSnapshot =
            try {
                uniffi.torta_core.beastLiveSnapshot()
            } catch (e: Throwable) {
                loge("BeastMetricSinkImpl — beastLiveSnapshot failed, logging the pushed snapshot", e)
                pushed
            }

        // D40 — query-beast.log through the Rust canon seam, event-classified from the snapshot.
        // BEFORE the pathVars fetch: the Rust seam holds its own bound dir, so a PathVars fault
        // can only cost the two Kotlin-substrate writes, never the canon log.
        val shedTotal = snapshot.shedDropped.toLong() + snapshot.aqmDropped.toLong()
        val kind =
            when {
                modeChanged && lastLoggedMode != null -> BeastLogKind.MODE_SHIFT
                lastLoggedShedTotal in 0 until shedTotal -> BeastLogKind.SHED
                else -> BeastLogKind.TICK
            }
        lastLoggedMode = m.mode
        lastLoggedShedTotal = shedTotal
        try {
            beast?.logEvent(now.toULong(), kind, snapshot, m.preferredEndpoint)
        } catch (e: Exception) {
            loge("BeastMetricSinkImpl writePillarLogs — beast logEvent failed", e)
        }

        val appDataDir =
            try {
                pathVars.get().appDataDir
            } catch (e: Exception) {
                loge("BeastMetricSinkImpl writePillarLogs — no appDataDir, skipping", e)
                return
            }

        val s = m.solver
        PillarLog.event(
            appDataDir,
            PillarLog.Pillar.SOLVER,
            "state",
            "phase" to s.phase,
            "enabled" to s.enabled,
            "heals" to s.solveCount,
            "obstruction" to s.obstructionScore,
            "reason" to s.lastSwitchReason,
        )
        // #133 — query-dnsmasq.log: the P12 dnsmasq/resolver aggregate counters sampled per latch
        // burst. resolverStats is an in-memory read + "no qname ever" (T20) — counts, never a domain.
        PillarLog.event(
            appDataDir,
            PillarLog.Pillar.DNSMASQ,
            "stats",
            "json" to TortaCore.resolverStats(),
        )
    }

    /**
     * D12 — the latch: a mode CHANGE bypasses; otherwise ≥ [LOG_MIN_INTERVAL_MS] must have passed
     * since the last write burst. The CAS makes the latch race-safe across concurrent pushes (one
     * winner per interval; a loser simply skips — its state lands on the next winning burst).
     */
    private fun acquireLogLatch(modeChanged: Boolean, now: Long): Boolean {
        val last = lastLogWriteMs.get()
        if (!modeChanged && now - last < LOG_MIN_INTERVAL_MS) return false
        return lastLogWriteMs.compareAndSet(last, now)
    }

    private companion object {
        /**
         * D12 — the NAND log min-interval (dossier spec: a 5–30 s latch). 15 s ⇒ steady-state flash
         * writes drop from up to `cwnd × 3` appends per 5-s cycle to ≤ 3 per 15 s, while a mode
         * shift still lands immediately (the bypass) — cadence changes, signal does not.
         */
        const val LOG_MIN_INTERVAL_MS = 15_000L
    }
}

/**
 * ★ E-FIX r3 — the engine-layer facts the Rust [`BeastSnapshot`] cannot carry (they live in the
 * Kotlin feeder: real probe results, the TCP pool, the endpoint scan, the RTT rings). One immutable
 * value per cycle, REAL measurements only — never fabricated (a stopped engine clears it to null and
 * the dashboard returns to the honest defaults).
 */
data class EngineContext(
    val poolUtilizationPct: Double,
    val connectionsAlive: Int,
    val failovers: Int,
    val probesTotal: Int,
    val probesSuccess: Int,
    val udpProbesTotal: Int,
    val udpProbesSuccess: Int,
    val jitterMs: Double,
    val p95RttMs: Double,
    val udpJitterMs: Double,
    val udpP95RttMs: Double,
    val preferredEndpoint: String,
)

/**
 * ★ E-FIX r3 — fold the engine-layer context onto a Rust-snapshot-derived metrics value. Null
 * context (engine stopped / pre-first-cycle) = the input unchanged (the honest-defaults contract of
 * [toDnsEngineMetrics] holds). Pure — a `copy`, never a mutation.
 */
internal fun DnsEngineMetrics.foldEngineContext(context: EngineContext?): DnsEngineMetrics {
    if (context == null) return this
    return copy(
        poolUtilizationPct = context.poolUtilizationPct,
        connectionsAlive = context.connectionsAlive,
        failovers = context.failovers,
        probesTotal = context.probesTotal,
        probesSuccess = context.probesSuccess,
        udpProbesTotal = context.udpProbesTotal,
        udpProbesSuccess = context.udpProbesSuccess,
        jitterMs = context.jitterMs,
        p95RttMs = context.p95RttMs,
        udpJitterMs = context.udpJitterMs,
        udpP95RttMs = context.udpP95RttMs,
        preferredEndpoint = context.preferredEndpoint,
    )
}

/**
 * The faithful 1:1 map [`BeastSnapshot`] (Rust) → [DnsEngineMetrics] (the Kotlin dashboard model).
 *
 * Every YeAH + CAKE/CoBALT field the Rust Beast pushes maps onto the field the dashboard already
 * renders — the Kotlin [DnsEngineMetrics] WAS the mirror of this shape (it was hand-kept
 * byte-identical to the Kotlin brain's getters; now the Rust Beast is the source so the mirror is
 * exact by construction). The non-Beast fields (pool utilization, probe tallies, endpoint name) are
 * NOT in the snapshot — they stay at their honest defaults here; ★ E-FIX r3: the engine layer NOW
 * folds its live context over this value via [foldEngineContext] (the sink applies it in
 * [BeastMetricSinkImpl.onMetrics]) — real measurements when the engine cycles, the honest zero
 * defaults otherwise, never fabricated.
 *
 * The #121 Solver obstruction is re-derived LIVE from the Rust Beast's `blueProb` so the
 * dashboard's self-heal card keeps its real COBALT-BLUE signal (the same signal the Kotlin
 * `emitMetrics` used).
 */
internal fun BeastSnapshot.toDnsEngineMetrics(): DnsEngineMetrics {
    // #121 — re-derive the LIVE obstruction the Solver watches, from the REAL Beast signal exposed
    // here: the COBALT BLUE valve (`blueProb`, which rises on actual timeouts/fails). The
    // sojourn-p95
    // + upstream-score inputs are not in the snapshot, so they take honest zero defaults (the
    // verdict
    // simply weights the present signal). The switching machinery stays DORMANT (phase STEADY) —
    // the
    // dashboard shows "Self-Heal is watching; obstruction = <score>", never a fabricated solve.
    // The Beast snapshot carries blueProb (the COBALT signal) but NOT the failover count — the
    // engine
    // layer owns that. failovers defaults to 0 in SolverInput, so the verdict weights only the
    // present
    // BLUE signal (honest, never fabricated).
    val obstruction = Solver.detectObstruction(SolverInput(blueProb = valveProb))
    return DnsEngineMetrics(
        // ---- YeAH (the Rust Beast owns these now) ----
        mode = mode,
        congestionWindow = cwnd,
        windowMax = windowMax,
        baseRttMs = baseRttMs,
        slowStartActive = slowStartActive,
        pacingRate = pacingRate,
        adaptiveTimeoutMs = adaptiveTimeoutMs,
        // ---- CAKE / CoBALT (the Rust Beast owns these now) ----
        pipelineDepth = pipelineDepth,
        queueCritical = queueCritical,
        queueHigh = queueHigh,
        queueNormal = queueNormal,
        aqmDropped = aqmDropped,
        // ---- The COBALT globals the deep dashboard renders ----
        blueProb = valveProb,
        cobaltDropped = shedDropped,
        drrSparseServed = drrSparseServed,
        cwndTotal = cwnd,
        inflightTotal = pipelineDepth,
        pacingRateQps = pacingRate,
        // ---- UDP (the first-ever UDP YeAH base_rtt, tracked separately in the Rust Beast) ----
        udpBaseRttMs = udpBaseRttMs,
        // ---- #121 Solver snapshot — LIVE obstruction, DORMANT phase (no fabricated solve) ----
        solver =
            SolverSnapshot(
                phase = SolverPhase.STEADY,
                obstructionScore = obstruction.score,
                lastSwitchReason =
                    if (obstruction.score > 0.0) {
                        obstruction.dominantSignal.name.lowercase()
                    } else {
                        "—"
                    },
            ),
        // ---- Engine-context fields NOT in the Beast snapshot — honest defaults ----
        // (pool utilization, probe tallies, endpoint name, jitter/p95 rings, failover count, the
        // per-upstream governor map, the governed/would-send accounting). The Rust Beast is the
        // cwnd/AQM brain; these are engine-layer context the dashboard does not read off the Beast
        // path. They surface as zeros/defaults here — never fabricated.
    )
}
