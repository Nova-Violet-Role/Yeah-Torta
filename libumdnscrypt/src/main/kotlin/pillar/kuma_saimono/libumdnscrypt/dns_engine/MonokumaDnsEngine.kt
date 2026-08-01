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

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import pillar.kuma_saimono.libumdnscrypt.dns_engine.core.DnsEndpoint
import pillar.kuma_saimono.libumdnscrypt.dns_engine.core.ProbeProtocol
import pillar.kuma_saimono.libumdnscrypt.dns_engine.socket.ConnectionPool
import pillar.kuma_saimono.libumdnscrypt.dns_engine.socket.UdpProber
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import uniffi.torta_core.Beast
import uniffi.torta_core.TortaProfile
import uniffi.torta_core.ProbePriority
import uniffi.torta_core.ProbeProtocol as BeastProtocol
import uniffi.torta_core.ProbeRequest
import uniffi.torta_core.YeahProfile
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.max

import pillar.kuma_saimono.libumdnscrypt.dns_engine.beast.BeastMetricSinkImpl
import pillar.kuma_saimono.libumdnscrypt.dns_engine.beast.EngineContext

/**
 * The Monster: CAKE + YeAH over a real upstream datapath. Each 5 s cycle it (1) UDP-scans every
 * candidate endpoint to pick the lowest-latency relay, (2) enqueues a CAKE batch of TCP+UDP probes
 * across liveness domains, (3) sizes the TCP pool to the YeAH window and dispatches up to cwnd, then
 * (4) feeds every measured RTT back into the Rust Beast (unified cwnd) and per-protocol jitter.
 *
 * **R-Beast-Wire + K2 — THE BEAST IS THE SOLE ENGINE, PURE RUST (Socio mandate 2026-06-27/2026-06-29).**
 * The CAKE/YeAH/CoBALT hot math lives in the Rust [`Beast`] Object; this engine is its FEEDER + PACER
 * only. The Kotlin canonicals `YeahController.kt`/`CakeScheduler.kt` are DELETED (K2 — the Rust Beast is
 * the faithful 1:1 port; no redundant Kotlin math remains anywhere, hot path AND self-heal). The engine
 * constructs nothing congestion-related itself — it receives the [`Beast`] handle from
 * [MonokumaDnsEngineManager] (which built it ONCE + attached the [BeastMetricSinkImpl] that publishes
 * metrics to the dashboard), feeds RTT samples (`applySample`/`applyUdpSample`/`onLoss`/`onFailover`),
 * enqueues probes (`enqueueProbe`), and dispatches (`dispatch` — the Beast reads cwnd internally).
 * The metrics no longer flow through this engine's own StateFlow — the Rust Beast PUSHES them via the
 * sink callback (push, not poll).
 *
 * **DEGRADED MODE (the UnsatisfiedLinkError law).** The Beast handle is held as a nullable
 * [beast]; if construction failed (a stale `.so` before the Socio's binding regen + `cargo-ndk`
 * redeploy, or a native fault), the engine runs a CONSERVATIVE degraded path: a fixed cwnd
 * ([DEGRADED_CWND]), a fixed timeout ([DEGRADED_TIMEOUT_MS]), and direct probing without AQM. **The
 * Kotlin congestion math is NOT resurrected as a fallback** (the mandate: the Rust Beast owns cwnd/AQM
 * now, no Kotlin fallback in the hot path) — degraded means honest defaults, never a silent second
 * brain. The manager logs the construction failure at start.
 */
class MonokumaDnsEngine(
    private val beast: Beast?,
    endpoints: List<DnsEndpoint> = DEFAULT_ENDPOINTS,
    private val config: EngineConfig = EngineConfig(),
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    // ★ E-FIX r3 — the sink the engine-layer telemetry folds through (probe tallies / pool /
    // endpoint / jitter+p95 / failovers). Nullable so tests + the degraded path stay unchanged;
    // the manager passes the @Singleton BeastMetricSinkImpl and clears its context on stop.
    private val sink: BeastMetricSinkImpl? = null,
) {
    companion object {
        const val CYCLE_MS = 5000L
        private const val SELECT_ALPHA = 0.2
        private const val SELECT_TIMEOUT_MS = 1000
        private const val UNREACHABLE = 9999.0

        /** Degraded-mode cwnd when the Rust Beast is unavailable (conservative, single-stream pacing). */
        private const val DEGRADED_CWND = 4

        /** Degraded-mode read timeout (ms) when the Rust Beast is unavailable. */
        private const val DEGRADED_TIMEOUT_MS = 2000

        /**
         * ★ E-FIX r3 — the standing-backlog ceiling, in multiples of the live cwnd: while the CAKE
         * queue already holds ≥ this × cwnd probes, the cycle enqueues nothing (the window drains
         * first). 3× keeps a full window of headroom in flight + queued without the runaway spiral.
         */
        private const val ENQUEUE_BACKLOG_FACTOR = 3

        val PROBE_DOMAINS = listOf(
            "resolver1.opendns.com",
            "resolver2.opendns.com",
            "whoami.akamai.net",
            "o-o.myaddr.l.google.com",
        )

        /** Real public anycast resolvers (TCP+UDP/53) — replaced by live DNSCrypt relays in P3 datapath wiring. */
        val DEFAULT_ENDPOINTS = listOf(
            DnsEndpoint("cloudflare", "1.1.1.1"),
            DnsEndpoint("quad9", "9.9.9.9"),
            DnsEndpoint("google", "8.8.8.8"),
        )
    }

    private val tcpRtt = java.util.ArrayDeque<Double>()
    private val udpRtt = java.util.ArrayDeque<Double>()

    private val endpointList = endpoints.toList()
    private val endpointEwma = DoubleArray(endpointList.size) { 0.0 }

    @Volatile
    private var preferredIdx = 0

    @Volatile
    private var pool = ConnectionPool(endpointList[0].host, endpointList[0].port, scope)

    private val udpIdCounter = AtomicInteger(0)

    private var probeRotation = 0
    private var failovers = 0

    // ★ E-FIX r3 — cumulative REAL probe tallies (the engine-layer facts the Rust snapshot cannot
    // carry). These feed the sink's EngineContext each cycle: Success %, the ticker's tcp=x/y
    // udp=a/b, and the ticker's dedupe marker (frozen forever at 0+0 before this fold existed).
    private var probesTotal = 0
    private var probesSuccess = 0
    private var udpProbesTotal = 0
    private var udpProbesSuccess = 0

    @Volatile
    private var job: Job? = null

    fun start() {
        if (job?.isActive == true) return
        if (beast == null) {
            logi("MonokumaDnsEngine starting in DEGRADED mode — Rust Beast unavailable (cwnd=$DEGRADED_CWND)")
        }
        job = scope.launch {
            pool.warm()
            while (isActive) {
                try {
                    runCycle()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    // a bad cycle must not kill the engine
                }
                delay(config.cycleMs)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        pool.shutdown()
        // D10 — RELEASE-ALL-CAPS (the MONSTER plan §5 stop law): the engine is gone, so restore the
        // resolver's configure-time deadline + uncap the window. A stale Beast budget must never
        // keep throttling live DNS after the governor that computed it has stopped.
        if (beast != null) {
            try {
                TortaCore.resolverSetPoolBudget(0, 0L, 0.0)
            } catch (e: Exception) {
                loge("MonokumaDnsEngine stop — budget release failed", e)
            }
        }
    }

    private suspend fun runCycle() = coroutineScope {
        selectBestEndpoint()
        enqueueBatch()

        // The Rust Beast owns cwnd + the CAKE dispatch (it reads cwnd internally + drains ≤cwnd). On
        // the degraded path (Beast unavailable), skip the queue entirely + probe a fixed batch.
        val cwnd = if (beast != null) beast.cwnd() else DEGRADED_CWND
        val timeoutMs = if (beast != null) {
            beast.adaptiveTimeoutMs(jitterStdOf(tcpRtt))
        } else {
            DEGRADED_TIMEOUT_MS
        }

        pool.resize(max(ConnectionPool.MIN_SLOTS, cwnd / 2))
        val ep = endpointList[preferredIdx]

        pushResolverBudget(cwnd, timeoutMs)

        // Dispatch the CAKE batch (Beast path) or build a degraded fixed batch.
        val batch = if (beast != null) {
            val nowMs = System.currentTimeMillis()
            val dispatched = beast.dispatch(nowMs)
            dispatched.map { req ->
                BeastProbe(
                    domain = req.domain,
                    protocol = if (req.protocol == BeastProtocol.UDP) ProbeProtocol.UDP else ProbeProtocol.TCP,
                )
            }
        } else {
            degradedBatch()
        }

        val results = batch.map { probe ->
            async {
                when (probe.protocol) {
                    ProbeProtocol.TCP -> ProbeResult(true, pool.sendProbe(probe.domain, timeoutMs))
                    ProbeProtocol.UDP -> ProbeResult(
                        false,
                        UdpProber.probe(ep.host, ep.port, probe.domain, nextUdpId(), timeoutMs),
                    )
                }
            }
        }.awaitAll()

        // Feed the cycle's measured RTTs back into the Rust Beast (unified cwnd). D12 — BATCHED:
        // the whole cycle's TCP samples go through ONE applySamples call and the UDP samples
        // (the first-ever UDP YeAH — beast/mod.rs tracks udp_base_rtt separately) through ONE
        // applyUdpSamples call, so the Beast pushes ONE BeastSnapshot per batch instead of one per
        // sample (up to cwnd×2 pushes per cycle where the dashboard renders only the last — the
        // metrics-amplification fix). Losses stay per-event: a loss is a mode-moving signal the
        // YeAH brain reacts to individually. The dashboard still receives every push via the
        // sink's publish into the @Singleton repository (no Kotlin emitMetrics poll anymore).
        val tcpSamples = ArrayList<Double>(results.size)
        val udpSamples = ArrayList<Double>(results.size)
        var losses = 0
        for (r in results) {
            // ★ E-FIX r3 — tally EVERY real probe outcome (success and loss) per protocol; these are
            // the Success-% / ticker facts the dashboard renders via the sink's EngineContext fold.
            if (r.tcp) probesTotal++ else udpProbesTotal++
            if (r.rtt >= 0.0) {
                if (r.tcp) {
                    probesSuccess++
                    pushRtt(tcpRtt, r.rtt)
                    tcpSamples.add(r.rtt)
                } else {
                    udpProbesSuccess++
                    pushRtt(udpRtt, r.rtt)
                    udpSamples.add(r.rtt)
                }
            } else {
                losses++
            }
        }
        // ★ E-FIX r3 — refresh the engine-layer context BEFORE feeding the Beast: the pushes the
        // feeds trigger (one snapshot per batch + one per loss) then fold the FRESH cycle context.
        publishEngineContext(ep.name)
        if (tcpSamples.isNotEmpty()) beast?.applySamples(tcpSamples)
        if (udpSamples.isNotEmpty()) beast?.applyUdpSamples(udpSamples)
        repeat(losses) { beast?.onLoss() }
    }

    /**
     * ★ E-FIX r3 — hand the cycle's REAL engine-layer measurements to the sink (which folds them
     * into every Rust push): cumulative probe tallies, the live TCP-pool state, the preferred
     * endpoint's NAME, the failover count, and the jitter/p95 derived from the actual RTT rings.
     * Witnessed gap (AVD round 3): Success pinned at 0%, p95/Jitter/Pool/Relay stuck at "—", and the
     * card's ticker frozen at its first line — all because nothing folded these after the
     * R-Beast-Wire migration retired `emitMetrics()`. Degraded path (no Beast) publishes nothing —
     * no pushes flow there anyway, and the dashboard honestly rests.
     */
    private fun publishEngineContext(endpointName: String) {
        val s = sink ?: return
        if (beast == null) return
        s.updateEngineContext(
            EngineContext(
                poolUtilizationPct = 100.0 * pool.aliveCount / ConnectionPool.MAX_SLOTS,
                connectionsAlive = pool.aliveCount,
                failovers = failovers,
                probesTotal = probesTotal,
                probesSuccess = probesSuccess,
                udpProbesTotal = udpProbesTotal,
                udpProbesSuccess = udpProbesSuccess,
                jitterMs = jitterStdOf(tcpRtt),
                p95RttMs = p95Of(tcpRtt),
                udpJitterMs = jitterStdOf(udpRtt),
                udpP95RttMs = p95Of(udpRtt),
                preferredEndpoint = endpointName,
            ),
        )
    }

    /**
     * D10 — the Beast governs the PRODUCTION datapath, not only its own probes: push the
     * Beast-derived budget (cwnd cap + adaptive timeout + the pacing witness) into the live Rust
     * resolver once per cycle (control-plane, 2 FFI reads per 5 s, NEVER per-query; the resolver's
     * slot gate is fail-open by construction). Degraded path: no Beast ⇒ no push (the resolver
     * keeps its configure-time defaults). [stop] pushes the release-all `(0, 0, 0.0)`.
     */
    @Suppress(
        "TooGenericExceptionCaught"
    ) // FFI façade call — any native fault degrades to "no budget this cycle", never a dead engine.
    private fun pushResolverBudget(cwnd: Int, timeoutMs: Int) {
        val b = beast ?: return
        try {
            TortaCore.resolverSetPoolBudget(cwnd, timeoutMs.toLong(), b.snapshot().pacingRate)
        } catch (e: Exception) {
            loge("MonokumaDnsEngine budget push — Beast/resolver call failed", e)
        }
    }

    /** UDP-scan every candidate, refresh its EWMA, and retarget the pool if a faster relay emerges. */
    private suspend fun selectBestEndpoint() = coroutineScope {
        val scanned = endpointList.indices.map { idx ->
            async {
                val ep = endpointList[idx]
                idx to UdpProber.probe(ep.host, ep.port, PROBE_DOMAINS[0], nextUdpId(), SELECT_TIMEOUT_MS)
            }
        }.awaitAll()

        for ((idx, rtt) in scanned) {
            endpointEwma[idx] = when {
                rtt >= 0.0 && endpointEwma[idx] <= 0.0 -> rtt
                rtt >= 0.0 -> (1 - SELECT_ALPHA) * endpointEwma[idx] + SELECT_ALPHA * rtt
                endpointEwma[idx] <= 0.0 -> UNREACHABLE
                else -> minOf(endpointEwma[idx] * 1.5, UNREACHABLE) // decay unreachable upward
            }
        }

        val best = endpointEwma.indices.minByOrNull { endpointEwma[it] } ?: 0
        if (best != preferredIdx) {
            preferredIdx = best
            failovers++
            retargetPool()
        }
    }

    private suspend fun retargetPool() {
        val old = pool
        val ep = endpointList[preferredIdx]
        pool = ConnectionPool(ep.host, ep.port, scope)
        old.shutdown()
        // A relay switch resets the congestion estimate — signal the Rust Beast (window collapse +
        // re-learn the floor). Degraded path: no-op (nothing to reset).
        try {
            beast?.onFailover()
        } catch (e: Exception) {
            loge("MonokumaDnsEngine onFailover — Beast call failed", e)
        }
        pool.warm()
    }

    /**
     * Enqueue a CAKE batch into the Rust Beast (3 TCP + 3 UDP probes across the 3 tins). The Beast's
     * `dispatch` drains ≤cwnd of these next cycle. Degraded path: no-op (the cycle builds its own
     * fixed batch). The `ProbeRequest` Record carries the priority + protocol + enqueued-at-ms the
     * CoBALT CoDel sojourn + the 8-way set-assoc flow buckets key on.
     *
     * ★ E-FIX r3 — TWO feeder laws, both witnessed broken on the AVD (pipeline 67→339 monotonic,
     * cwnd pinned at 1, base-RTT never fed):
     *  1. **Backlog gate.** Enqueueing 6/cycle while `dispatch` drains ≤cwnd is a guaranteed
     *     backlog spiral at low cwnd: sojourns explode, CoDel enters sustained drop, and the queue
     *     grows forever. Skip the enqueue while the standing backlog already covers what the window
     *     can drain ([ENQUEUE_BACKLOG_FACTOR] × cwnd) — the queue then breathes with the window.
     *  2. **Protocol interleave.** TCP×3-then-UDP×3 made every TCP entry OLDER than its cycle's UDP
     *     entries, so a saturated CoDel systematically dropped the TCP heads first → zero TCP
     *     samples → YeAH (TCP-fed) never left slow-start → cwnd stayed 1 → the spiral locked.
     *     Alternating TCP/UDP removes the systematic age bias.
     */
    private fun enqueueBatch() {
        val b = beast ?: return
        val priorities = listOf(ProbePriority.CRITICAL, ProbePriority.HIGH, ProbePriority.NORMAL)
        try {
            val snap = b.snapshot()
            val backlogCap = max(1, snap.cwnd) * ENQUEUE_BACKLOG_FACTOR
            if (snap.pipelineDepth >= backlogCap) return // let the window drain — no new batch
            val nowMs = System.currentTimeMillis()
            for (p in priorities) {
                for (proto in listOf(BeastProtocol.TCP, BeastProtocol.UDP)) {
                    val domain = PROBE_DOMAINS[(probeRotation++) % PROBE_DOMAINS.size]
                    b.enqueueProbe(
                        ProbeRequest(
                            domain = domain,
                            priority = p,
                            endpointIdx = preferredIdx,
                            protocol = proto,
                            enqueuedAtMs = nowMs,
                        ),
                    )
                }
            }
        } catch (e: Exception) {
            loge("MonokumaDnsEngine enqueueBatch — Beast call failed", e)
        }
    }

    /** A fixed conservative batch for degraded mode (no CAKE queue; 3 TCP + 3 UDP across the domains). */
    private fun degradedBatch(): List<BeastProbe> {
        val out = ArrayList<BeastProbe>(6)
        for (i in 0 until 6) {
            val domain = PROBE_DOMAINS[(probeRotation++) % PROBE_DOMAINS.size]
            val proto = if (i < 3) ProbeProtocol.TCP else ProbeProtocol.UDP
            out.add(BeastProbe(domain, proto))
        }
        return out
    }

    private fun nextUdpId(): Int = udpIdCounter.incrementAndGet() and 0xFFFF

    private data class BeastProbe(val domain: String, val protocol: ProbeProtocol)

    private data class ProbeResult(val tcp: Boolean, val rtt: Double)
}

/** ★ E-FIX r3 — the p95 quantile of the RTT rings the dashboard's p95 fields render. */
private const val P95_QUANTILE = 0.95

/** The bounded RTT-ring capacity (the last N measured samples feed jitter/p95). */
private const val RTT_RING_CAP = 64

/** Push one measured RTT into a bounded ring (evicts the oldest past [RTT_RING_CAP]). */
private fun pushRtt(ring: java.util.ArrayDeque<Double>, value: Double) {
    if (ring.size >= RTT_RING_CAP) ring.removeFirst()
    ring.addLast(value)
}

/**
 * ★ E-FIX r3 — the shared std-dev jitter estimate over a measured RTT ring (TCP + UDP both feed the
 * sink's EngineContext fold; the TCP value also drives the Beast's adaptive_timeout_ms jitter input).
 */
private fun jitterStdOf(ring: java.util.ArrayDeque<Double>): Double {
    if (ring.size < 2) return 0.0
    val mean = ring.sum() / ring.size
    val variance = ring.fold(0.0) { acc, v -> acc + (v - mean) * (v - mean) } / ring.size
    return kotlin.math.sqrt(variance)
}

/** ★ E-FIX r3 — the p95 of a measured RTT ring (0.0 while empty — the dashboard renders "—"). */
private fun p95Of(ring: java.util.ArrayDeque<Double>): Double {
    if (ring.isEmpty()) return 0.0
    val sorted = ring.sorted()
    val idx = (kotlin.math.ceil(sorted.size * P95_QUANTILE).toInt() - 1).coerceIn(0, sorted.size - 1)
    return sorted[idx]
}

/**
 * The Beast construction + attachment helper. The [MonokumaDnsEngineManager] calls this ONCE at engine
 * start to build the Rust [`Beast`] (Canonical YeAH + CoBALT CAKE — the flagship profiles), attach the
 * [BeastMetricSinkImpl] (so the Rust Beast's per-cycle `push_metrics` flows to the dashboard), bind the
 * D40 log canon, and hand the handle to the engine. When [logDir] is non-null the Beast's
 * `query-beast.log` dir is bound (the Rust `log_tier` seam becomes the ONE writer of that file) and the
 * sink receives the handle so its latched cadence drives `logEvent` (the retired Kotlin PillarLog BEAST
 * tag's successor). Returns `null` on every failure mode (a stale `.so` before the binding regen +
 * `cargo-ndk` redeploy, an `UnsatisfiedLinkError`, or a native fault) — the engine then runs in its
 * conservative DEGRADED mode (never a Kotlin-brain fallback).
 */
internal fun buildBeastOrNull(sink: BeastMetricSinkImpl, logDir: String? = null): Beast? {
    return try {
        // The FIRST #[derive(uniffi::Object)] + FIRST with_foreign callback — the generated factory is
        // `Beast(yeahProfile, cakeProfile)` (UniFFI 0.31 proc-macro; regen'd by the Socio's gradle step).
        val beast = Beast(YeahProfile.CANONICAL, TortaProfile.BASELINE)
        beast.attachSink(sink)
        // D40 — the log canon: bind the Rust query-beast.log seam at boot; the sink drives logEvent.
        if (logDir != null) beast.bindLogDir(logDir)
        sink.bindBeast(beast)
        logi("Rust Beast constructed + sink attached — Canonical YeAH × CoBALT CAKE (the flagship)")
        beast
    } catch (e: Throwable) {
        // UnsatisfiedLinkError on a stale/base .so (the Beast Object symbol absent until the regen +
        // cargo-ndk redeploy), or any native fault. The engine degrades — the Kotlin brain stays retired.
        loge("buildBeastOrNull — Rust Beast unavailable, engine will run DEGRADED", e)
        null
    }
}
