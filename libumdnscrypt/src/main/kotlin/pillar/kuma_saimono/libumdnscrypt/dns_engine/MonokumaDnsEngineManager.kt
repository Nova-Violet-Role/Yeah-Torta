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

import android.content.SharedPreferences
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import pillar.kuma_saimono.libumdnscrypt.dns_engine.beast.BeastMetricSinkImpl
import pillar.kuma_saimono.libumdnscrypt.rust.BlocklistRuntime
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.data.dns_engine_metrics.DnsEngineMetricsRepository
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.dns_engine.core.DnsEndpoint
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import javax.inject.Inject
import javax.inject.Named

/**
 * ModulesService-scoped owner of the CAKE/YeAH engine (the Monster). Mirrors NflogManager's
 * lifecycle: started when DNSCrypt goes RUNNING, stopped when it stops (see ModulesStateLoop).
 *
 * No root: the engine is pure app-level java.net probing. start/stop are idempotent and guarded
 * so the state-loop can call them on any transition edge without races.
 */
@ModulesServiceScope
@ExperimentalCoroutinesApi
class MonokumaDnsEngineManager @Inject constructor(
    @Named(CoroutinesModule.DISPATCHER_IO)
    private val dispatcherIo: CoroutineDispatcher,
    private val metricsRepository: DnsEngineMetricsRepository,
    private val beastSink: BeastMetricSinkImpl,
    private val pathVars: dagger.Lazy<PathVars>,
    @Named(DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: SharedPreferences,
) {
    private val coroutineScope by lazy {
        CoroutineScope(
            SupervisorJob() +
                    dispatcherIo +
                    CoroutineName("MonokumaDnsEngine") +
                    CoroutineExceptionHandler { _, t ->
                        loge("MonokumaDnsEngineManager uncaught exception", t)
                    }
        )
    }

    @Volatile
    private var engine: MonokumaDnsEngine? = null

    @Synchronized
    fun startEngine() {
        if (engine != null) return
        try {
            // Master gate (independent of DNSCrypt): the user can switch the beast off entirely and
            // still run DNSCrypt. Default ON, so an untouched install behaves exactly as before.
            if (!defaultPreferences.getBoolean(TortaeKeys.DNS_ENGINE_ENABLED, true)) {
                logi("MonokumaDnsEngine disabled by user — skipping start")
                return
            }
            val config = readEngineConfig()

            // When DNSCrypt is RUNNING, probe the local dnscrypt-proxy listener (the real relay
            // datapath). When it is NOT (standalone engine), that loopback port is dead — so probe
            // public anycast instead, so the engine measures a real path rather than timing out.
            val dnsCryptRunning =
                ModulesStatus.getInstance().dnsCryptState == ModuleState.RUNNING
            val endpoints = if (dnsCryptRunning) {
                val port = pathVars.get().dnsCryptPort.toIntOrNull() ?: 5354
                listOf(DnsEndpoint("dnscrypt-proxy", "127.0.0.1", port))
            } else {
                MonokumaDnsEngine.DEFAULT_ENDPOINTS
            }
            // D40 — the log canon: where a Rust pillar-log seam exists it is CANONICAL. Bind the
            // Beast's query-beast.log dir (beside DnsCrypt.log, the #133 location) at build so the
            // Rust log_tier substrate is the ONE writer of that file; the overlapping Kotlin
            // PillarLog BEAST tag retired with it (BeastMetricSinkImpl drives beast.logEvent).
            val beastLogDir = try {
                pathVars.get().appDataDir + "/logs"
            } catch (e: Exception) {
                loge("MonokumaDnsEngineManager startEngine — no appDataDir for the Beast log", e)
                null
            }
            val started = MonokumaDnsEngine(
                beast = buildBeastOrNull(beastSink, beastLogDir),
                endpoints = endpoints,
                config = config,
                scope = coroutineScope,
                // ★ E-FIX r3 — the engine folds its per-cycle telemetry (probe tallies / pool /
                // endpoint / jitter+p95 / failovers) through the sink into every Rust push.
                sink = beastSink,
            )
            engine = started
            started.start()
            // R-Beast-Wire — the metrics no longer flow through a poll tap. The Rust Beast PUSHES a
            // BeastSnapshot to the attached BeastMetricSinkImpl on every sample feed; the sink converts
            // it to DnsEngineMetrics + publishes into the @Singleton repository (so every dashboard
            // consumer receives it via the StateFlow they already collect) AND writes the #133
            // per-pillar event logs (BEAST/SOLVER/DNSMASQ). The Kotlin emitMetrics poll RETIRED.
            logi(ENGINE_DEDICATION)
            logi(
                "MonokumaDnsEngine started — Rust Beast datapath probing " +
                        "(cycle=${config.cycleMs}ms cwndMax=${config.maxWindow} " +
                        "free=${config.freeThresh} compete=${config.competeThresh})"
            )
        } catch (e: Exception) {
            loge("MonokumaDnsEngineManager startEngine", e)
        }
    }

    /**
     * Build the live [EngineConfig] from the user's choices in the default SharedPreferences (the
     * same store the cake-themed Engine settings screen writes to). Expert mode reads the raw,
     * clamped knobs; otherwise a noob-friendly [EnginePreset] supplies them. Defaults reproduce the
     * original "Standard" beast exactly.
     */
    private fun readEngineConfig(): EngineConfig = try {
        val p = defaultPreferences
        if (p.getBoolean(TortaeKeys.DNS_ENGINE_EXPERT, false)) {
            EngineConfig(
                cycleMs = p.getInt(TortaeKeys.DNS_ENGINE_CADENCE_MS, 5000)
                    .coerceIn(1000, 60000).toLong(),
                maxWindow = p.getInt(TortaeKeys.DNS_ENGINE_MAX_WINDOW, 16)
                    .coerceIn(2, 64),
                freeThresh = p.getInt(TortaeKeys.DNS_ENGINE_FREE_THRESH, 1050)
                    .coerceIn(1000, 2000) / 1000.0,
                competeThresh = p.getInt(TortaeKeys.DNS_ENGINE_COMPETE_THRESH, 1250)
                    .coerceIn(1010, 3000) / 1000.0,
            )
        } else {
            EnginePreset.fromKey(
                p.getString(TortaeKeys.DNS_ENGINE_PRESET, EnginePreset.DEFAULT_PRESET.key)
            ).config
        }
    } catch (e: Exception) {
        loge("MonokumaDnsEngineManager readEngineConfig — falling back to defaults", e)
        EngineConfig()
    }

    /**
     * Compile the on-disk DNSCrypt blacklist into the Rust matcher (P7 Wave 1, live). Independent of
     * the engine on/off gate — the blocklist intelligence loads whenever DNSCrypt runs. Off the main
     * thread; failures are swallowed (the matcher just stays empty).
     */
    fun loadBlocklist() {
        try {
            val pv = pathVars.get()
            val paths = listOf(
                pv.dnsCryptBlackListPath,
                pv.dnsCryptLocalBlackListPath,
                pv.dnsCryptRemoteBlackListPath,
            )
            coroutineScope.launch { BlocklistRuntime.compileFromFiles(paths) }
        } catch (e: Exception) {
            loge("MonokumaDnsEngineManager loadBlocklist", e)
        }
    }

    @Synchronized
    fun stopEngine() {
        val running = engine ?: return
        try {
            running.stop()
            logi("MonokumaDnsEngine stopped")
        } catch (e: Exception) {
            loge("MonokumaDnsEngineManager stopEngine", e)
        } finally {
            engine = null
            beastSink.bindBeast(null) // D40 — drop the canon-log handle with the engine
            beastSink.updateEngineContext(null) // ★ E-FIX r3 — a stopped engine folds nothing
            metricsRepository.publish(null) // dashboard returns to idle
        }
    }

    /** Is the engine running? The module-state loop reads this to keep ModulesService alive. */
    fun isRunning(): Boolean = engine != null

    /** DNSCrypt reached RUNNING: (re)start the engine — restart retargets a standalone engine onto
     *  the loopback now that dnscrypt-proxy is up — then refresh the blocklist. */
    fun onDnsCryptStarted() {
        if (isRunning()) restartEngine() else startEngine()
        loadBlocklist()
    }

    /** DNSCrypt stopped → its VpnService comes down → the engine FOLLOWS THE VPN DOWN.
     *  2-DRIVE-ENGINE-VPN: the engine on-state is keyed strictly off the DNSCrypt VpnService now — it
     *  NEVER runs without the tunnel. The old standalone branch (keep the engine alive on its own,
     *  which forced the access-log / always-on-VPN keep-alive crutch) is retired: DNSCrypt is the sole
     *  VPN gatekeeper and the OS-protected VpnService FGS keeps the engine alive while the VPN is up. */
    fun onDnsCryptStopped() {
        stopEngine()
    }

    /**
     * Restart so the engine re-selects its endpoint (loopback vs public anycast) for the CURRENT
     * DNSCrypt state — used when DNSCrypt comes up or goes down while the engine stays on standalone.
     */
    @Synchronized
    fun restartEngine() {
        if (engine == null) return
        stopEngine()
        startEngine()
    }

    companion object {
        /** Engine dedication, emitted on every start (the credits surface mirrors it for the user). */
        const val ENGINE_DEDICATION =
            "Yeah! Tortä engine — CAKE by Høiland-Jørgensen & Täht · " +
                    "YeAH-TCP by Baiocchi, Castellani & Vacirca · " +
                    "Android port, UDP probing & integration by Saimonokuma."
    }
}
