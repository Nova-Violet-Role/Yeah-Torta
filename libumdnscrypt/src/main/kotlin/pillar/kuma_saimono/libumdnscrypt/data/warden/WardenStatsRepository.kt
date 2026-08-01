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

package pillar.kuma_saimono.libumdnscrypt.data.warden

import android.content.SharedPreferences
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.vpn.service.WardenDatapathGate
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import javax.inject.Inject
import javax.inject.Named
import javax.inject.Singleton
import kotlin.coroutines.coroutineContext

/**
 * Immutable snapshot of THE WARDEN's aggregate **block-wins verdict stream** (W6 slice-1). Pure model — no
 * presentation, exactly like [pillar.kuma_saimono.libumdnscrypt.data.trust.TrustState] /
 * [pillar.kuma_saimono.libumdnscrypt.dns_engine.metrics.DnsEngineMetrics].
 *
 * **AGGREGATE COUNTS ONLY — the "no qname ever" privacy law (T20).** These are running tallies of the
 * Warden's verdicts: how many connections it allowed, how many it denied, and — the load-bearing W6
 * surface — the **block-wins gate split** (which gate said no: the firewall half vs the blocklist half).
 * There is NO qname, NO domain, NO UID, NO per-connection history here — the Rust core records nothing but
 * counters at the `verdict_at` resolve point, so nothing else can ever reach this model or the UI.
 *
 * **The block-wins compose (warden.rs).** A connection passes only if BOTH the firewall half allows it AND
 * the blocklist half allows it; otherwise it is denied. On a deny the Rust core attributes the cause
 * deterministically (block-wins precedence: blocklist-first when both halves deny), so
 * [denyByFirewall] + [denyByBlocklist] account for every [deny]. ([denyByFirewall] + [denyByBlocklist] == [deny].)
 *
 * **[configured] is the honest "armed?" headline.** DOC DRIFT FIXED (e-fix round 2, GROUND_TRUTH):
 * `WARDEN_NATIVE_ENABLED` is default-**TRUE** (the Socio all-ON contract 2026-06-24 — the XML default,
 * `ModulesStarterHelper.applyWardenNativeFromPref` and the `FIREWALL_ENABLED` alias all read
 * `getBoolean(…, true)`), and the datapath consult (`VpnRulesHolder.isAllowedByWarden`) rides the
 * `firewallEnabled` gate — so the verdict path IS reached on every non-special packet while the VPN
 * datapath runs. [configured] maps the Object snapshot's `policy_loaded` (constant true once
 * constructed, allow-by-default); the card's OFF headline is therefore driven by `allow+deny == 0`
 * (nothing judged yet — engine not running), not by a disarmed engine.
 *
 * @param configured     true once a Warden policy is installed (the verdict path is live); false = inert/off.
 * @param allow          connections the Warden ALLOWED (firewall allowed AND blocklist allowed).
 * @param deny           connections the Warden DENIED (firewall denied OR blocklist denied; block-wins).
 * @param denyByFirewall denials attributed to the firewall half (app/network policy said no).
 * @param denyByBlocklist denials attributed to the blocklist half (a blocked domain; precedence on both-deny).
 */
data class WardenStats(
    val configured: Boolean,
    val allow: Long,
    val deny: Long,
    val denyByFirewall: Long,
    val denyByBlocklist: Long,
)

/**
 * Cross-graph bridge + self-driving poller for THE WARDEN's aggregate verdict stats (W6 slice-1 — the data
 * the W6 dashboard card reads). Cloned from the sanctioned cross-graph bridge shape
 * ([pillar.kuma_saimono.libumdnscrypt.data.dns_engine_metrics.DnsEngineMetricsRepository] /
 * [pillar.kuma_saimono.libumdnscrypt.data.trust.TrustRepository]): a root-graph [Singleton] with a concrete
 * `@Inject` ctor (auto-provided everywhere), so the dashboard hub injects it as a Dagger MEMBER field
 * (`@Inject lateinit … dagger.Lazy<WardenStatsRepository>`) — **NO AppComponent accessor needed**, exactly
 * like the Trust/metrics repos.
 *
 * Unlike those two PASSIVE bridges (a `@ModulesServiceScope` manager pushes snapshots into them), this
 * repository **owns its own gentle poll loop**: on [start] it reads [WardenDatapathGate.snapshot] on the
 * dashboard metrics cadence and publishes a [WardenStats] (or `null`). **D02 — the split-brain kill:** it
 * reads the LIVE typed [uniffi.torta_core.WardenSnapshot] of the SAME `WardenObject` instance the datapath
 * queries ([WardenDatapathGate]), NOT the permanently-disarmed flat `warden_stats` global (whose singleton
 * is armed only by dead test code, so it reported `configured:false`, all-zeros forever). No more JSON
 * hand-parse — the typed Record is mapped directly. The read is CHEAP (an in-memory counter read on the
 * Rust side, no IO) and AGGREGATE-ONLY, so polling it on the same cadence the engine metrics use costs
 * nothing on the hot path. [stop] cancels the loop and publishes the idle sentinel. start/stop are
 * `@Synchronized` and idempotent so a lifecycle owner can call them on any transition edge without races.
 *
 * **Idle / fail-safe.** `null` means "not polling / unavailable" → a subscriber renders its idle state. A
 * native fault, a missing `.so`, or a disarmed Warden never throws and never fabricates a number: an
 * "unavailable" read publishes `null`, and a parsed `configured:false` publishes a zeroed-but-present
 * [WardenStats] so the card can distinguish "off (engine inert)" from "no data yet (idle)".
 */
@Singleton
class WardenStatsRepository @Inject constructor(
    @Named(CoroutinesModule.DISPATCHER_IO)
    private val dispatcherIo: CoroutineDispatcher,
    @Named(DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: SharedPreferences,
) {

    private val coroutineScope by lazy {
        CoroutineScope(
            SupervisorJob() +
                    dispatcherIo +
                    CoroutineName("WardenStatsRepository") +
                    CoroutineExceptionHandler { _, t ->
                        loge("WardenStatsRepository uncaught exception", t)
                    }
        )
    }

    private val _stats = MutableStateFlow<WardenStats?>(null)

    /** The latest aggregate Warden verdict snapshot, or `null` while idle/unavailable. */
    val stats: StateFlow<WardenStats?> = _stats.asStateFlow()

    /**
     * The live poll loop, or `null` while stopped. @Volatile because [start]/[stop] may run on a different
     * thread than the loop's launch context.
     */
    @Volatile
    private var pollJob: Job? = null

    /**
     * Begin polling [WardenDatapathGate.snapshot] on the dashboard metrics cadence. Idempotent: a second
     * [start] while a loop is live is a no-op. Off the caller thread (the native ensure-load is best kept
     * off any lifecycle/state-loop thread). Publishes a first read immediately, then every cadence tick.
     */
    @Synchronized
    fun start() {
        try {
            if (pollJob?.isActive == true) return
            pollJob = coroutineScope.launch { pollLoop() }
        } catch (e: Exception) {
            loge("WardenStatsRepository start", e)
        }
    }

    /** Stop polling and publish the idle sentinel (`null`). Idempotent. */
    @Synchronized
    fun stop() {
        try {
            pollJob?.cancel()
            pollJob = null
            _stats.value = null
        } catch (e: Exception) {
            loge("WardenStatsRepository stop", e)
        }
    }

    /** True while the poll loop is live. Symmetric with the sibling managers' `isRunning()`. */
    fun isRunning(): Boolean = pollJob?.isActive == true

    /**
     * Poll once immediately, then once per cadence period. A read/parse failure is a counted non-event:
     * publish `null` (idle) and keep the loop alive — a single bad read never stops future ticks. The
     * cadence is the same expert knob the engine metrics use ([TortaeKeys.DNS_ENGINE_CADENCE_MS]).
     *
     * Loops on the coroutine's OWN [isActive] (not the parent scope's), so [stop]'s `pollJob.cancel()`
     * cleanly ends the loop — `delay` honors cancellation by throwing, and the guard short-circuits the
     * next iteration either way.
     */
    private suspend fun pollLoop() {
        while (coroutineContext.isActive) {
            _stats.value = readStatsOrNull()
            delay(readCadenceMs())
        }
    }

    /**
     * D02 — read the LIVE typed [uniffi.torta_core.WardenSnapshot] of the SAME instance the datapath
     * queries ([WardenDatapathGate.snapshot]) and map it to a [WardenStats], or `null` when the engine is
     * unreachable. Crash-proof: never throws (the gate already returns null on any native fault; this adds a
     * guard on top). NEVER reads a qname/domain/UID — the snapshot carries only aggregate counts (T20).
     * This REPLACES the old flat-`warden_stats`-JSON hand-parse that read the permanently-disarmed global.
     */
    private fun readStatsOrNull(): WardenStats? = try {
        mapSnapshot(WardenDatapathGate.snapshot())
    } catch (e: Exception) {
        loge("WardenStatsRepository readStats — staying idle", e)
        null
    }

    /**
     * Map the typed [uniffi.torta_core.WardenSnapshot] to the card's [WardenStats]. `null` snapshot (engine
     * unreachable / disarmed) → `null` (idle). The card's block-wins split is preserved: [denyByFirewall]
     * folds the three FIREWALL tiers (universal-toggle + per-app + universal-rule), [denyByBlocklist] is the
     * TIER-5 `dns_blocked` seam. [configured] is the Object's `policy_loaded` (always true once
     * constructed — allow-by-default), so the card lights up the moment the first verdict lands (the
     * card's `active = configured && allow+deny > 0` contract).
     */
    private fun mapSnapshot(snap: uniffi.torta_core.WardenSnapshot?): WardenStats? {
        if (snap == null) return null
        return WardenStats(
            configured = snap.policyLoaded,
            allow = snap.allow,
            deny = snap.deny,
            denyByFirewall = snap.denyByUniversalToggle + snap.denyByApp + snap.denyByUniversalRule,
            denyByBlocklist = snap.denyByBlocklist,
        )
    }

    /**
     * The poll cadence in millis — the SAME expert knob the engine metrics ride
     * ([TortaeKeys.DNS_ENGINE_CADENCE_MS], default [DEFAULT_CADENCE_MS]), clamped to a sane band so a
     * malformed pref can never spin the loop tight. Pure pref read; a fault degrades to the default.
     */
    private fun readCadenceMs(): Long = try {
        defaultPreferences.getInt(TortaeKeys.DNS_ENGINE_CADENCE_MS, DEFAULT_CADENCE_MS)
            .coerceIn(MIN_CADENCE_MS, MAX_CADENCE_MS)
            .toLong()
    } catch (e: Exception) {
        DEFAULT_CADENCE_MS.toLong()
    }

    companion object {
        /** Default poll cadence: the engine-metrics 5s tick (mirrors MonokumaDnsEngineManager's default). */
        const val DEFAULT_CADENCE_MS = 5000

        /** Cadence clamp — mirror the engine config band so the card never polls faster than the metrics. */
        const val MIN_CADENCE_MS = 1000
        const val MAX_CADENCE_MS = 60000
    }
}
