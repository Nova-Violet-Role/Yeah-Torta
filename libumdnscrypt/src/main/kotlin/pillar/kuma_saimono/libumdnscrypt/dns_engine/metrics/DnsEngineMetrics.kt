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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.metrics

/**
 * Immutable snapshot of the CAKE/YeAH engine state, emitted fresh into a StateFlow each cycle and
 * rendered by the dashboard. Presentation (colors/icons/formatting) lives in the UI layer, not here
 * (the C# TcpEngineMetrics mixed them in; we keep the model pure).
 */
data class DnsEngineMetrics(
    // YeAH
    val mode: String = "INIT",
    val congestionWindow: Int = 1,
    val windowMax: Int = 16,
    val baseRttMs: Double = 0.0,
    val jitterMs: Double = 0.0,
    val p95RttMs: Double = 0.0,
    val adaptiveTimeoutMs: Int = 2000,
    val slowStartActive: Boolean = true,
    val pacingRate: Double = 0.0,
    // CAKE / pool
    val poolUtilizationPct: Double = 0.0,
    val connectionsAlive: Int = 0,
    val pipelineDepth: Int = 0,
    val queueCritical: Int = 0,
    val queueHigh: Int = 0,
    val queueNormal: Int = 0,
    val aqmDropped: Int = 0,
    val failovers: Int = 0,
    val probesTotal: Int = 0,
    val probesSuccess: Int = 0,
    val preferredEndpoint: String = "—",
    // UDP
    val udpBaseRttMs: Double = 0.0,
    val udpJitterMs: Double = 0.0,
    val udpP95RttMs: Double = 0.0,
    val udpProbesTotal: Int = 0,
    val udpProbesSuccess: Int = 0,
    // ── MONSTER §6 enrichment (Stage B+) — ALL default-constructed so a governor/solver-absent
    // build
    //    emits the exact single-upstream snapshot of today (LEGACY byte-identical). The dashboard
    //    rendering of these is Design-Finale; this is the DATA fold only.
    //
    // §4 per-upstream governor map (SHADOW). Empty when GOVERN is OFF (the default) → the dashboard
    // renders nothing new; the single-upstream YeAH fields above stay authoritative.
    val perUpstream: List<UpstreamMetric> = emptyList(),
    // §6 globals — folded from the Rust Beast COBALT getters (`beast/cake.rs`, pushed via BeastSnapshot)
    // + the shadow governor map. 0.0/0 on the LEGACY/COBALT-off path (the Beast getters return 0 there).
    val sojournP50Ms: Double = 0.0,
    val sojournP95Ms: Double = 0.0,
    val blueProb: Double = 0.0,
    val cobaltDropped: Int = 0,
    val drrSparseServed: Int = 0,
    val realQps: Double = 0.0,
    val inflightTotal: Int = 0,
    val cwndTotal: Int = 0,
    val pacingRateQps: Double = 0.0,
    // SHADOW accounting: what the governors WOULD have paced vs the unthrottled live send. Equal
    // while
    // shadow/live-deferred; their divergence is the proof the governor would have shaped (no real
    // throttle yet).
    val governedQps: Double = 0.0,
    val wouldHaveSentQps: Double = 0.0,
    // True while the resolver/governor stats are absent and the engine is on the 6-probe fallback
    // (the resolver-absent = today guarantee, surfaced so the dashboard can say "probe mode").
    val probeFallbackActive: Boolean = false,
    // §7 self-healing Solver. Default INACTIVE/SHADOW → no rendering change on an untouched
    // install.
    val solver: SolverSnapshot = SolverSnapshot(),
) {
    val successRatePct: Int
        get() = if (probesTotal > 0) probesSuccess * 100 / probesTotal else 0

    val udpSuccessRatePct: Int
        get() = if (udpProbesTotal > 0) udpProbesSuccess * 100 / udpProbesTotal else 0
}

/**
 * One row of the per-upstream governor map (MONSTER §4/§6). Pure data, no Android/socket deps —
 * folded additively into [DnsEngineMetrics.perUpstream]. The list is empty when DNS_ENGINE_GOVERN
 * is OFF (the default), so a governor-absent snapshot is byte-identical to today's single-upstream
 * shape.
 *
 * `mode` mirrors the YeAH mode (FREE/COMPETING/…); `score` is the lower-is-better
 * blend(p95,loss,cwnd,jitter) the §4 governor uses for selection (and the future P8 trust feed).
 * `governedCwnd`/`pacingRateQps` are the SHADOW would-be caps (derived metrics, never a live
 * throttle until Stage C).
 */
data class UpstreamMetric(
    val name: String = "—",
    val protocol: String = "—",
    val cwnd: Int = 1,
    val inflight: Int = 0,
    val baseRttMs: Double = 0.0,
    val jitterMs: Double = 0.0,
    val p95RttMs: Double = 0.0,
    val mode: String = "INIT",
    val sent: Int = 0,
    val ok: Int = 0,
    val fail: Int = 0,
    val timeout: Int = 0,
    val qps: Double = 0.0,
    val score: Double = 0.0,
    // SHADOW would-be cap (no live throttle until Stage C).
    val governedCwnd: Int = 0,
    val pacingRateQps: Double = 0.0,
) {
    val successRatePct: Int
        get() = if (sent > 0) ok * 100 / sent else 0
}

/**
 * Solver lifecycle state (MONSTER §7). Mirrors the pure SolverStateMachine enum; STEADY = dormant.
 */
enum class SolverPhase {
    STEADY,
    TRIGGERED,
    RACING,
    LOCKED,
    COOLDOWN,
}

/**
 * Immutable dashboard view of the self-healing Solver (MONSTER §7). Pure data — folded into
 * [DnsEngineMetrics.solver]. Default = STEADY/empty so a solver-absent (or solver-OFF) snapshot
 * renders nothing new. The live commit is DEFERRED (shadow-rendered) until GOVERN + Stage-C land;
 * until then `lockedBinding` describes the would-be lock the state machine reached, never a live
 * swap.
 */
data class SolverSnapshot(
    val phase: SolverPhase = SolverPhase.STEADY,
    // Whether the noob "auto-heal" master is ON (default ON) — lets the dashboard distinguish OFF
    // from idle.
    val enabled: Boolean = false,
    // Shadow until live: true once the state machine reaches LOCKED but the live commit is
    // deferred.
    val shadow: Boolean = true,
    val solveCount: Int = 0,
    val lastSwitchReason: String = "—",
    val cacheHits: Int = 0,
    val cacheSize: Int = 0,
    val obstructionScore: Double = 0.0,
    val networkFingerprint: String = "—",
    val lockedBinding: LockedBindingView? = null,
)

/**
 * Dashboard view of the Solver's committed (or would-be) binding (MONSTER §7 LockedBinding,
 * presentation subset). Pure data; `null` in [SolverSnapshot.lockedBinding] when no binding is
 * held/raced yet.
 */
data class LockedBindingView(
    val transport: String = "—",
    val resolverId: String = "—",
    val relayId: String? = null,
    val tunedCwnd: Int = 0,
    val tunedCodelTargetMs: Long = 0L,
    val score: Double = 0.0,
    val ageMs: Long = 0L,
)

/**
 * P12 dnsmasq-completion pillar snapshot (the EIDOLON metrics surface). Pure data — parsed from the
 * crash-proof `TortaCore.resolverStats()` JSON (the "no qname ever" T20 facade, TortaCore.kt:459),
 * NOT a new JNI fn. Sibling of [SolverSnapshot]/[UpstreamMetric]: all fields default-constructed so
 * an unconfigured resolver (or a base `.so` returning "unavailable") yields honest ZEROS and
 * `configured=false` — the card renders "—"/zero, never a fabricated value.
 *
 * Field origin (GROUND_TRUTH, measured against `resolver/mod.rs stats()`): ✓ = rides a stats() key
 * live TODAY (configured/cache/cache_hits/queries/rebind_rejected). ⊕ = a P12 dnsmasq counter ADDED
 * to stats() (mod.rs Stats + the format!): honest DEAD-ZERO until the owning Rust gap
 * (R2/R4/R5/N1/N3 + cache-2e serve-stale/neg-cache) wires its bump — class-b honest.
 *
 * PRIVACY LAW (T20): every field is a COUNT or boolean — NEVER a qname/domain/IP. The card surfaces
 * "23 names kept local" / "filter strips: 0" — counts only.
 */
data class DnsmasqSnapshot(
    val configured: Boolean = false, // ✓ stats.configured (mod.rs:604)
    val cacheEntries: Int = 0, // ✓ stats.cache (mod.rs:606)
    val cacheHits: Long = 0L, // ✓ stats.cache_hits (mod.rs:609)
    val queries: Long = 0L, // ✓ stats.queries (mod.rs:607)
    val rebindRejected: Long = 0L, // ✓ stats.rebind_rejected (mod.rs:615)
    val negCacheEntries: Int = 0, // ⊕ stats.neg_cache (cache 2e neg-cache gauge)
    val serveStaleServed: Long = 0L, // ⊕ stats.serve_stale_served (cache 2e RFC8767)
    val neverForwardStops: Long = 0L, // ⊕ stats.never_forward_stops (no-egress, names kept local)
    val bogusPrivStops: Long = 0L, // ⊕ stats.bogus_priv_stops (R5)
    val cloakActions: Long = 0L, // ⊕ stats.cloak_actions (R2)
    val filterRrDrops: Long = 0L, // ⊕ stats.filter_rr_drops (N1)
    val localRecordHits: Long = 0L, // ⊕ stats.local_record_hits (R4)
    val adBitPassThrough: Long = 0L, // ⊕ stats.ad_bit_pass_through (N3)
) {
    /**
     * UI-computed cache hit-rate % (mirrors [DnsEngineMetrics.successRatePct] — derived, never
     * stored).
     */
    val cacheHitRatePct: Int
        get() = if (queries > 0L) (cacheHits * 100L / queries).toInt() else 0
}
