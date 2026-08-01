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

package pillar.kuma_saimono.libumdnscrypt.modules

import android.annotation.SuppressLint
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.widget.Toast

import androidx.preference.PreferenceManager

import dagger.Lazy
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.arp.ArpScanner
import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.DNSCryptInteractorInterface
import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.LogDataModel
import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.dnscrypt.OnDNSCryptLogUpdatedListener
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.installer.ChmodCommand
import pillar.kuma_saimono.libumdnscrypt.installer.DNSCryptExtractCommand
import pillar.kuma_saimono.libumdnscrypt.iptables.IptablesRules
import pillar.kuma_saimono.libumdnscrypt.iptables.ModulesIptablesRules
import pillar.kuma_saimono.libumdnscrypt.BuildConfig
import pillar.kuma_saimono.libumdnscrypt.dns_engine.CentauriArtifactManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.CentauriMirrorManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.SourceListUpdateManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.MonokumaDnsEngineManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.ResolverRuntime
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RuntimeTierManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.TrustManager
import pillar.kuma_saimono.libumdnscrypt.nflog.NflogManager
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.connectivitycheck.ConnectivityCheckManager
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.workers.UpdateIPsManager
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper
import pillar.kuma_saimono.libumdnscrypt.vpn.tunnel.TunnelController

import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPING
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.CONNECTION_LOGS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_READY_PREF
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNS_ENGINE_STANDALONE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.RESOLVER_NATIVE_ENABLED
import pillar.kuma_saimono.libumdnscrypt.rust.AppStateBridge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.VPN_SERVICE_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.FAULT
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RESTARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RUNNING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.UNDEFINED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.PROXY_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.ROOT_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.VPN_MODE

import javax.inject.Inject
import javax.inject.Named

class ModulesStateLoop(private val modulesService: ModulesService) : Runnable,
        OnDNSCryptLogUpdatedListener {

    @Inject
    lateinit var dnsCryptInteractor: DNSCryptInteractorInterface
    @Inject
    lateinit var preferenceRepository: Lazy<PreferenceRepository>
    @Inject
    @field:Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    lateinit var defaultPreferences: Lazy<SharedPreferences>
    @Inject
    lateinit var handler: Lazy<Handler>
    @Inject
    lateinit var pathVars: Lazy<PathVars>
    @Inject
    lateinit var nflogManager: Lazy<NflogManager>
    @Inject
    lateinit var monokumaDnsEngineManager: Lazy<MonokumaDnsEngineManager>
    @Inject
    lateinit var resolverRuntime: Lazy<ResolverRuntime>
    @Inject
    lateinit var trustManager: Lazy<TrustManager>
    @Inject
    lateinit var rotationManager: Lazy<RotationManager>
    @Inject
    lateinit var centauriArtifactManager: Lazy<CentauriArtifactManager>
    @Inject
    lateinit var sourceListUpdateManager: Lazy<SourceListUpdateManager>
    @Inject
    lateinit var centauriMirrorManager: Lazy<CentauriMirrorManager>
    @Inject
    lateinit var runtimeTierManager: Lazy<RuntimeTierManager>
    @Inject
    lateinit var connectivityCheckManager: Lazy<ConnectivityCheckManager>
    @Inject
    lateinit var modulesStatusBroadcaster: Lazy<ModulesStatusBroadcaster>
    @Inject
    lateinit var updateIPsManager: Lazy<UpdateIPsManager>
    @Inject
    lateinit var modulesVersions: Lazy<ModulesVersions>

    private var pendingStartGrace = 0

    private var iptablesUpdateTemporaryBlocked = false

    private val modulesStatus: ModulesStatus = ModulesStatus.getInstance()

    private val iptablesRules: IptablesRules = ModulesIptablesRules(modulesService)

    private val contextUIDUpdater: ContextUIDUpdater = ContextUIDUpdater(modulesService)

    private var savedDNSCryptState: ModuleState = UNDEFINED
    private var savedFirewallState: ModuleState = UNDEFINED

    private val sharedPreferences: SharedPreferences =
            PreferenceManager.getDefaultSharedPreferences(modulesService)

    private var savedIptablesCommandsHash = 0

    @Volatile
    private var nflogIsRunning = false

    init {
        App.instance
                .subcomponentsManager
                .initLogReaderDaggerSubcomponent()
                .inject(this)

        //Delay in sec before service can stop
        stopCounter = STOP_COUNTER_DELAY

        restoreModulesSavedState()
    }

    @Synchronized
    override fun run() {

        try {


            val operationMode = modulesStatus.mode

            val rootIsAvailable = modulesStatus.isRootAvailable
            val useModulesWithRoot = modulesStatus.isUseModulesWithRoot
            val contextUIDUpdateRequested = modulesStatus.isContextUIDUpdateRequested

            if (!(useModulesWithRoot && operationMode == ROOT_MODE)) {
                updateModulesState(modulesStatus.dnsCryptState)
            }

            updateFixTTLRules()

            updateIptablesRules(
                    modulesStatus.dnsCryptState,
                    modulesStatus.firewallState,
                    operationMode,
                    rootIsAvailable,
                    useModulesWithRoot
            )

            if (contextUIDUpdateRequested) {
                updateContextUID(modulesStatus.dnsCryptState)
            }

            // The engine is a first-class module (Tor/I2P slot): while it runs it resets stopCounter,
            // keeping ModulesService alive even with DNSCrypt + firewall stopped. Placed AFTER the
            // decrement so its vote is authoritative.
            updateEngineState()

            if (stopCounter <= 0) {
                denySystemDNS()
                if (modulesStatus.isRootAvailable) {
                    nflogManager.get().stopNflog()
                }
                modulesStatus.isContextUIDUpdateRequested = false
                App.instance.subcomponentsManager.releaseLogReaderScope()
                logi("ModulesStateLoop stopCounter is zero. Stop service.")
                safeStopModulesService()
                modulesStatus.setFirewallState(STOPPED, preferenceRepository.get())
            }

            slowDownModulesStateTimerIfRequired()

        } catch (e: Exception) {
            handler.get().post { Toast.makeText(modulesService, uniffi.torta_core.tortaText("wrong"), Toast.LENGTH_SHORT).show() }
            loge("ModulesStateLoop run()", e)
        }

    }

    private fun updateModulesState(dnsCryptState: ModuleState) {
        // ★ STAGE 2 (2026-07-04): DNSCrypt IS the pure-Rust tunnel now. The legacy gate keyed RUNNING on
        // a live dnsCryptThread (the Go dnscrypt-proxy process thread). That thread no longer blocks — the
        // starter runnable returns immediately (no binary to wait on), so it is never "alive" and DNSCrypt
        // decayed STARTING → STOPPING. The true liveness signal is the VPN tunnel.
        // ★ SPLIT-BRAIN CURE (#129 field bug 1): "the tunnel is up" must be measured, not remembered.
        // The old signal — the VPN_SERVICE_ENABLED pref — survives the process that earned it: a backup
        // restore / `pm install -r` resurrects it as `true` into a fresh process whose resolver pool was
        // never configured, so DNSCrypt was declared RUNNING (shielded crown) while every query
        // blackholed. TunnelController.isDatapathLive() is the Rust datapath's own live-holder — set at
        // spawn, cleared at stop, dead with the process — so RUNNING can no longer outlive the tunnel.
        val dnsCryptAlive = (dnsCryptThread != null && dnsCryptThread!!.isAlive)
                || TunnelController.isDatapathLive()
        if (dnsCryptAlive) {
            // ★ FRESH-INSTALL FIX (#5): the tunnel is live — the pending-start consent gap (if any) is
            // over, so release the grace budget for the next cold start.
            pendingStartGrace = 0
            // Recover to RUNNING from STOPPED/UNDEFINED/STOPPING *and STARTING* when the tunnel is up: in
            // the pure-Rust world there is no Go process to kill, so a starter thread that returns early
            // must not leave DNSCrypt stuck — the tunnel is the truth. STARTING is included because on a
            // fresh install the tunnel spawns while DNSCrypt is still labelled STARTING (the OS consent
            // dialog delayed it); without STARTING here that first-boot start would never be promoted to
            // RUNNING and the resolver-config edge would never fire (the #5 empty-pool bug). GATED ON USER
            // INTENT (the "DNSCrypt Running" pref): the stage-2 killer marks STOPPED and delegates the real
            // teardown to the all-modules-stopped leg in updateIptablesRules — an ungated promote trampled
            // that STOPPED while the tunnel was still up, so the teardown leg never saw it and the master
            // switch could not turn DNSCrypt OFF (the tunnel outlived every stop request). Promote only
            // while the user's last command was ON; after an OFF the state stays STOPPED and the tunnel
            // follows it down.
            if (dnsCryptState == STOPPED || dnsCryptState == UNDEFINED || dnsCryptState == STOPPING
                    || dnsCryptState == ModuleState.STARTING) {
                if (ModulesAux.isDnsCryptSavedStateRunning()) {
                    modulesStatus.dnsCryptState = ModuleState.RUNNING
                    stopCounter = STOP_COUNTER_DELAY
                }
            }
        } else {
            // ★ FRESH-INSTALL FIX (#5): the user asked DNSCrypt ON but the tunnel has not come up yet
            // (the Android VPN-consent dialog is still pending on a fresh install). Hold ModulesService
            // alive across the gap so the loop survives to observe the tunnel spawn above and fire the
            // RUNNING edge. Bounded by PENDING_START_GRACE so a denied/abandoned consent cannot pin the
            // foreground service alive forever; reset to a fresh budget whenever the user is OFF.
            if (ModulesAux.isDnsCryptSavedStateRunning()) {
                if (dnsCryptState != RUNNING && pendingStartGrace < PENDING_START_GRACE) {
                    pendingStartGrace++
                    stopCounter = STOP_COUNTER_DELAY
                }
            } else {
                pendingStartGrace = 0
            }
            if (dnsCryptState == RUNNING || dnsCryptState == UNDEFINED) {
                modulesStatus.dnsCryptState = STOPPED
            }
        }
    }

    // Mirrors updateModulesState for the engine module: while the engine runs, reflect RUNNING and
    // reset stopCounter (so the service survives with no other module); otherwise reflect STOPPED.
    private fun updateEngineState() {
        if (monokumaDnsEngineManager.get().isRunning()) {
            if (modulesStatus.engineState == STOPPED || modulesStatus.engineState == UNDEFINED) {
                modulesStatus.engineState = ModuleState.RUNNING
            }
            stopCounter = STOP_COUNTER_DELAY
        } else {
            if (modulesStatus.engineState == RUNNING) {
                modulesStatus.engineState = STOPPED
            }
        }
    }

    // Standalone engine start/stop, driven by ACTION_START_ENGINE / ACTION_STOP_ENGINE in ModulesService.
    fun startEngineStandalone() {
        modulesStatus.engineState = ModuleState.STARTING
        // ★ FIXED 2026-07-31 — THE PRECONDITION BELOW WAS ASSERTED BY A CLASS THAT DOES NOT EXIST.
        // The comment further down (and its twin in stopEngineStandalone) read "MainFragment persists
        // DNS_ENGINE_STANDALONE true BEFORE this ACTION_START_ENGINE". Measured on the tree:
        //   * `find libumdnscrypt/src -name "MainFragment*"` returns NOTHING — there is no such class;
        //   * NOTHING anywhere in src/main writes DNS_ENGINE_STANDALONE. Every reference is a read.
        // So the flag was permanently false, and onDnsCryptStopped() took its TEARDOWN branch on the
        // way *up*. Measured on the x86_64 AVD, engine armed via the harness receiver:
        //   ResolverRuntime shadow [DNSCrypt stopped] … {"configured":false,"transports":0,"upstreams":[]}
        //   ResolverRuntime shadow shut down
        //   SourceListUpdateManager — resolver not serving yet; skipping sweep (no plaintext fallback)
        // i.e. START_ENGINE performed a SHUTDOWN, no tun0 was ever raised, and DNSCrypt Ready stayed
        // false through 12 polls. Every downstream pillar gated on this flag (SourceListUpdateManager,
        // RotationManager, TrustManager, CentauriArtifact/Mirror, RuntimeTier — all `getBoolean(…, false)`)
        // was silently inert for the same reason.
        //
        // The fix is to make the action ESTABLISH the state it is named for rather than depend on an
        // absent caller: ACTION_START_ENGINE *is* the standalone start, so it owns the flag. apply() is
        // used deliberately — it updates the in-memory map synchronously, so the reads below see the new
        // value immediately, without blocking the state loop on disk I/O.
        defaultPreferences.get().edit().putBoolean(DNS_ENGINE_STANDALONE, true).apply()

        // ★ GAP-1 EXTENDED TO THE STANDALONE PATH (2026-07-31). The extract-if-missing that installs
        // the signed source lists from assets/dnscrypt.zip lived ONLY in
        // ModulesStarterHelper.startDNSCrypt (ModulesStarterHelper.kt:118-129) — i.e. on the
        // DNSCrypt-MODULE path. startEngineStandalone() never enters that path, so in standalone mode
        // the lists were never extracted. Measured on the x86_64 AVD immediately after the flag fix
        // landed and the flag was confirmed `true`:
        //     app_data/dnscrypt-proxy/  -> 0 files, through 10 polls / 2 minutes
        //     "configured":false, "transports":0, "upstreams":[]
        //     SourceListUpdateManager — resolver not serving yet; skipping sweep (no plaintext fallback)
        // which is a BOOTSTRAP DEADLOCK: the updater will not fetch the lists until the resolver
        // serves, and the resolver cannot serve without the lists. The bundled zip is what breaks the
        // cycle, so the standalone start has to extract it too.
        //
        // Identical semantics to the module path on purpose — same guard (missing OR zero-length),
        // same command, same chmod, same never-throw fallback — so the two entry points cannot drift
        // into disagreeing about what "configured" means. Idempotent: a second START is a no-op.
        try {
            val resolvers = java.io.File(pathVars.get().getDNSCryptPublicResolversPath())
            if (!resolvers.isFile || resolvers.length() == 0L) {
                DNSCryptExtractCommand(modulesService, pathVars.get().appDataDir).execute()
                ChmodCommand.dirChmod(pathVars.get().appDataDir + "/app_data/dnscrypt-proxy", false)
                logw("standalone engine: DNSCrypt config auto-extracted from assets/dnscrypt.zip "
                        + "(public-resolvers.md/relays.md/dnscrypt-proxy.toml) — the signed source "
                        + "lists are now live for the Rust pool derivation + 0x81 relay routing")
            }
        } catch (e: Exception) {
            loge("standalone engine: DNSCrypt config auto-extract failed "
                    + "(resolver will fall back to the 2-stamp floor)", e)
        }
        monokumaDnsEngineManager.get().startEngine()
        monokumaDnsEngineManager.get().loadBlocklist()
        // P8 Wave B1: the standalone engine loads the blocklist too, so score+publish its trust here as
        // well (idempotent; null-on-stop in stopEngineStandalone). No-egress read, runs in release.
        trustManager.get().start()
        // P10: the standalone engine runs the resolver against the public set, so arm rotation here too
        // (idempotent; stopped in stopEngineStandalone). INERT unless opted in; swaps fail SAFE.
        rotationManager.get().start()
        // P8 Wave C3: the standalone engine keeps the blocklist active, so the OPT-IN remote channel runs
        // here too (inert by default via the governance flag; verify-signature-first when enabled).
        centauriArtifactManager.get().start()
        // Task #19: the standalone engine resolves against the public set, so keep the resolver/relay/ODoH
        // lists fresh here too (minisign-verified, atomic-write, throttled). DEFAULT ON; fail-safe.
        sourceListUpdateManager.get().start()
        // Centauri Local Mirror: the standalone engine serves the local mirror too (OPT-IN, loopback-only;
        // native gated under the `mirror` feature ⇒ inert on a base .so).
        centauriMirrorManager.get().start()
        // THE WARDEN W5: the standalone engine runs the same NEW-durable pillars (resolver/metrics/attest),
        // so rehydrate their RAM⊗NAND tier here too. ADDITIVE + inert (gated only by DNS_ENGINE_ENABLED; the
        // native seam is inert on a base .so). Off the hot path, app-private, fail-safe.
        runtimeTierManager.get().start()
        // P7 Wave 3 Stage-0: in standalone mode there is NO loopback dnscrypt-proxy to shadow, so this is
        // the resolver's stopped-edge primitive: onDnsCryptStopped() retargets the shadow to the public
        // DNSCrypt default set when DNS_ENGINE_STANDALONE is set (MainFragment persists it true BEFORE this
        // ACTION_START_ENGINE), keeping the shadow on a real measurable path instead of a dead loopback.
        // DEBUG runs the shadow; the Stage-1 native arm (RESOLVER_NATIVE_ENABLED, default false) ALSO enters
        // so a release-armed standalone engine configures/retargets the pool. Un-armed release ⇒ not entered.
        if (BuildConfig.DEBUG || isNativeResolverArmed()) {
            resolverRuntime.get().onDnsCryptStopped()
        }
        stopCounter = STOP_COUNTER_DELAY
    }

    fun stopEngineStandalone() {
        // ★ FIXED 2026-07-31 — the symmetric half of the start-side fix above. The teardown branch of
        // onDnsCryptStopped() is the one that must run here, and it is selected by this flag being
        // FALSE. It was already false (nothing ever set it), so the stop path worked BY ACCIDENT — it
        // would have broken the moment the start side was fixed without this line. Set it explicitly so
        // the pair is coherent rather than accidentally correct.
        defaultPreferences.get().edit().putBoolean(DNS_ENGINE_STANDALONE, false).apply()
        monokumaDnsEngineManager.get().stopEngine()
        trustManager.get().stop()
        // P10: the engine is going down entirely — stop the rotation cadence (idempotent, never throws).
        rotationManager.get().stop()
        centauriArtifactManager.get().stop()
        // Task #19: the engine is going down entirely — the verified lists stay on disk; nothing to unwind.
        sourceListUpdateManager.get().stop()
        // Centauri Local Mirror: the engine is going down entirely — clear the mirror guard
        // (idempotent, never throws). INERT by default; only an opted-in install ever armed it.
        centauriMirrorManager.get().stop()
        // THE WARDEN W5: the engine is going down entirely — clear the runtime-tier rehydrate guard
        // (idempotent, never throws). The durable NAND tier persists; a later start/reboot re-rehydrates.
        runtimeTierManager.get().stop()
        // P7 Wave 3 Stage-0: the engine is going down entirely. MainFragment persists DNS_ENGINE_STANDALONE
        // false BEFORE this ACTION_STOP_ENGINE, so onDnsCryptStopped() takes its teardown branch
        // (shutdownResolver, configured=false) — no leaked native resolver after the engine stops.
        // DEBUG runs the shadow teardown; the Stage-1 native arm (RESOLVER_NATIVE_ENABLED, default false) ALSO
        // enters so an armed release tears the pool down. Un-armed release ⇒ both false ⇒ not entered.
        if (BuildConfig.DEBUG || isNativeResolverArmed()) {
            resolverRuntime.get().onDnsCryptStopped()
        }
        modulesStatus.engineState = ModuleState.STOPPED
        ModulesAux.makeModulesStateExtraLoop(modulesService)
    }

    /**
     * #2 nerd "Rotate Now" — fire ONE immediate resolver rotation off the cadence so a tester can watch a
     * swap right away instead of waiting a whole period. Routed here (not into ModulesService) because the
     * {@code @ModulesServiceScope} {@link RotationManager} lives in THIS subcomponent — same legitimate
     * holder that drives start()/stop()/onDnsCryptStarted(). {@link RotationManager#rotateNow()} is itself
     * guarded (no-op unless the cadence is armed) + never-throws; this wrapper adds the usual fail-open log.
     */
    fun rotateResolversNow() {
        try {
            rotationManager.get().rotateNow()
        } catch (e: Exception) {
            loge("ModulesStateLoop rotateResolversNow", e)
        }
    }

    /**
     * P7 Wave 3 Stage-1 — is the native Rust resolver ARMED? Reads the Stage-1 keystone
     * {@code RESOLVER_NATIVE_ENABLED} (TortaeKeys.java:165, DEFAULT true — the Default-ON #85 keystone). This is the SAME pref
     * {@link pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils#setResolverNativeEnabled(boolean)} (via
     * ModulesStarterHelper) pushes to the C-side {@code g_resolver_native_enabled} flag, so the C/UDP-53
     * bridge and the {@link ResolverRuntime} pool-config seam read ONE source of truth: armed ⇒ udp.c calls
     * {@code torta_resolve} AND the pool is configured here, so the arm actually resolves.
     * <p>
     * It gates only the {@link ResolverRuntime#onDnsCryptStarted()}/{@link ResolverRuntime#onDnsCryptStopped()}
     * pool-config edges so a <b>release</b> arm reaches the configure (debug already does via
     * {@code BuildConfig.DEBUG}). DEFAULT true ⇒ this reads armed by default (the Default-ON #85 keystone), so
     * the pool-config runs; the live arm stays governed by the #85 release-arm guard + the native fail-safe.
     * The duplicate-egress debug shadow
     * harness inside {@code onDnsCryptStarted} stays strictly {@code BuildConfig.DEBUG}-gated (ResolverRuntime.kt:221).
     * Crash-safe: a pref-read fault degrades to false (un-armed ⇒ pool stays empty ⇒ torta_resolve returns 0
     * ⇒ udp.c falls through to the unchanged sendto ⇒ DNS never breaks).
     */
    private fun isNativeResolverArmed(): Boolean {
        return try {
            defaultPreferences.get().getBoolean(RESOLVER_NATIVE_ENABLED, true)
        } catch (e: Exception) {
            false
        }
    }

    private fun updateFixTTLRules() {
        if (modulesStatus.isFixTTLRulesUpdateRequested()) {

            modulesStatus.setFixTTLRulesUpdateRequested(false)

            if (!modulesStatus.isIptablesRulesUpdateRequested()) {
                iptablesRules.refreshFixTTLRules()
            }
        }
    }

    private fun updateIptablesRules(
            dnsCryptState: ModuleState,
            firewallState: ModuleState,
            operationMode: OperationMode?,
            rootIsAvailable: Boolean,
            useModulesWithRoot: Boolean) {

        if (dnsCryptState != savedDNSCryptState
                || firewallState != savedFirewallState
                || modulesStatus.isIptablesRulesUpdateRequested()) {
            logi(String.format("DNSCrypt is %s Firewall is %s\n" +
                            "Operation mode %s Use modules with Root %s",
                    dnsCryptState, firewallState,
                    operationMode, useModulesWithRoot))

            if (dnsCryptState == RESTARTING) {
                setDNSCryptReady(false)

                dnsCryptInteractor.addOnDNSCryptLogUpdatedListener(this)
            }

            if (dnsCryptState != STOPPED && dnsCryptState != RUNNING) {
                return
            } else if (iptablesUpdateTemporaryBlocked) {
                return
            }

            var nflogStop = false

            if (savedDNSCryptState != dnsCryptState) {

                saveDNSCryptState(dnsCryptState)

                if (dnsCryptState == RUNNING) {
                    runningEdgeFiredThisProcess = true
                    dnsCryptInteractor.addOnDNSCryptLogUpdatedListener(this)
                    modulesStatusBroadcaster.get().broadcastDNSCryptRunning()
                    monokumaDnsEngineManager.get().onDnsCryptStarted()
                    // P8 Wave B1: score the installed blocklist's trust and publish to the cross-graph
                    // bridge (P10 RotationManager subscribes). NOT debug-gated (unlike resolverRuntime):
                    // a pure, no-egress read of the already-installed matcher fingerprint — runs in release.
                    trustManager.get().onDnsCryptStarted()
                    // P10: arm the periodic resolver rotation cadence (privacy by upstream diversity). NOT
                    // debug-gated — rotation is a real release feature; it is INERT unless the user opts in
                    // (RESOLVER_ROTATION_ENABLED default OFF), and every swap fails SAFE to the current set,
                    // so it can never break a live resolution. Re-calls TortaCore.configureResolver (the
                    // existing atomic pool swap); never a parallel resolver path.
                    rotationManager.get().onDnsCryptStarted()
                    // P8 Wave C3: check the OPT-IN Centauri signed-artifact channel. INERT by default
                    // (governance flag OFF ⇒ immediate no-op, no fetch); when enabled it verifies the
                    // minisign signature FIRST, then installs additively. Release-safe like trustManager.
                    centauriArtifactManager.get().onDnsCryptStarted()
                    // Task #19: DNSCrypt is up, so name resolution for the upstream list hosts goes through
                    // the live tunnel — sweep the source lists (throttled to the 72 h refresh window). Each
                    // list is minisign-verified against the pinned dnscrypt.info key BEFORE it is atomically
                    // written; a bad sig / rollback / network fault keeps the current list. DEFAULT ON, but a
                    // fresh install within 72 h of the last write no-ops. Off the hot path (IO), fail-safe.
                    sourceListUpdateManager.get().onDnsCryptStarted()
                    // Centauri Local Mirror: start the OPT-IN in-app loopback content-addressed CDN. INERT by
                    // default (CENTAURI_MIRROR_ENABLED OFF ⇒ immediate no-op); native is gated under the Rust
                    // `mirror` cargo feature, so a base .so has no symbol and the facade stays inert (never an
                    // UnsatisfiedLinkError). Loopback-only (no egress) ⇒ release-safe like the others.
                    centauriMirrorManager.get().onDnsCryptStarted()
                    // THE WARDEN W5: boot-rehydrate the shared RAM⊗NAND runtime tier so a power-off/reboot
                    // loses nothing. This is the SAME edge boot lands on (BootCompleteManager → runDNSCrypt →
                    // DNSCrypt RUNNING). It drives the (b) REHYDRATE-FROM-SIGNED-SOURCE pillars
                    // (blocklist←.tblk, Centauri←.tcat) from their app-private W5 durable pairs
                    // via the verify-sig-FIRST exports (TortaCore.rehydrate*FromSigned) — re-verify+re-install
                    // the SIGNED bytes, never a raw NAND dump. (The (a) NEW-durable pillars — resolver
                    // rotation/RTT, Fortress attest, metrics — write-through + rehydrate INSIDE their own Rust
                    // seams via the runtime_tier::DurableTier facility, so they need no orchestration here.)
                    // ADDITIVE + inert: gated only by the master DNS_ENGINE_ENABLED switch (no new flag, no UI
                    // switch); each export is verify-sig-FIRST + fail-safe + panic-firewalled, and an absent
                    // staged pair (the default until BuildCapture stages it) is a cold-start no-op ⇒
                    // byte-identical today. Even a Warden install does NOT enforce by itself (the W3 C seam
                    // still gates). Off the hot path (runs on IO), app-private filesDir, no egress ⇒
                    // release-safe like the others.
                    runtimeTierManager.get().onDnsCryptStarted()
                    // P7 Wave 3 Stage-0/1: arm the shadow resolver against the local dnscrypt-proxy listener.
                    // DEBUG runs the shadow harness (the duplicate-egress qname tail is itself DEBUG-gated
                    // inside onDnsCryptStarted, ResolverRuntime.kt:221, so release never double-resolves).
                    // The Stage-1 native arm (RESOLVER_NATIVE_ENABLED, default false) ALSO enters so the
                    // release-armed torta_resolve has a live pool. Un-armed release ⇒ both false ⇒ not entered
                    // ⇒ BYTE-IDENTICAL (no pool, no egress) — exactly as today.
                    if (BuildConfig.DEBUG || isNativeResolverArmed()) {
                        resolverRuntime.get().onDnsCryptStarted()
                    }
                    startNflogIfRootMode()
                } else {
                    dnsCryptInteractor.removeOnDNSCryptLogUpdatedListener(this)
                    modulesStatusBroadcaster.get().broadcastDNSCryptStopped()
                    monokumaDnsEngineManager.get().onDnsCryptStopped()
                    // P8 Wave B1: clear the trust verdict (publish null = idle), or keep it live if the
                    // engine runs standalone (the blocklist stays installed). Mirrors the engine's edge.
                    trustManager.get().onDnsCryptStopped()
                    // P10: stop the rotation cadence (or keep rotating against the public set if the engine
                    // runs standalone). Mirrors the trust/engine standalone-aware stop edge; never gated.
                    rotationManager.get().onDnsCryptStopped()
                    // P8 Wave C3: clear the remote-artifact idempotency guard (or keep it live if the
                    // engine runs standalone). Mirrors the trust/engine standalone-aware stop edge.
                    centauriArtifactManager.get().onDnsCryptStopped()
                    // Task #19: keep the channel armed if the engine runs standalone, else idle. The verified
                    // lists persist on disk across the stop. Mirrors the standalone-aware stop edge.
                    sourceListUpdateManager.get().onDnsCryptStopped()
                    // Centauri Local Mirror: clear the mirror guard (or re-arm if the engine runs
                    // standalone). Mirrors the trust/engine standalone-aware stop edge.
                    centauriMirrorManager.get().onDnsCryptStopped()
                    // THE WARDEN W5: clear the runtime-tier rehydrate guard (or keep it live if the engine runs
                    // standalone). The durable NAND tier persists across the stop (the Rust side write-throughs
                    // gently while running); clearing the guard only means a later RUNNING edge / reboot
                    // re-rehydrates. Mirrors the trust/engine standalone-aware stop edge.
                    runtimeTierManager.get().onDnsCryptStopped()
                    // P7 Wave 3 Stage-0/1: retarget/stop the shadow resolver to match DNSCrypt going down.
                    // Mirror the start gate (DEBUG shadow OR the Stage-1 native arm) so an armed release tears
                    // down/retargets the pool symmetrically. Un-armed release ⇒ both false ⇒ not entered.
                    if (BuildConfig.DEBUG || isNativeResolverArmed()) {
                        resolverRuntime.get().onDnsCryptStopped()
                    }
                    setDNSCryptReady(false)
                    denySystemDNS()
                    if (modulesStatus.firewallState != RUNNING) {
                        stopNflogIfRootMode()
                        nflogStop = true
                    }
                }
            }

            if (savedFirewallState != firewallState) {
                saveFirewallState(firewallState)
                if (firewallState == STARTING || firewallState == RUNNING) {
                    modulesStatusBroadcaster.get().broadcastFirewallRunning()
                    if (modulesStatus.dnsCryptState != RUNNING) {
                        startNflogIfRootMode()
                    }
                } else if (firewallState == STOPPED) {
                    modulesStatusBroadcaster.get().broadcastFirewallStopped()
                    if (!nflogStop && modulesStatus.dnsCryptState != RUNNING) {
                        stopNflogIfRootMode()
                    }
                }
            }

            if (modulesStatus.isIptablesRulesUpdateRequested()) {
                modulesStatus.setIptablesRulesUpdateRequested(false)
            }

            // ★ SPLIT-BRAIN CURE (#129 field bug 1): every leg below asks "is the VPN tunnel actually
            // up" (tear down an orphan, reload live rules, or raise it). The VPN_SERVICE_ENABLED pref
            // is a MEMORY of that fact and survives the process that made it true — a stale `true`
            // (backup restore, `pm install -r`) made the stop-leg below see "tunnel up + all modules
            // stopped" and enqueue a poison STOP that Android delivered right after the next REAL
            // start, killing the fresh tunnel seconds after the resolver pool configured. Measure the
            // datapath instead: TunnelController's live-holder cannot outlive the process.
            val vpnServiceEnabled = TunnelController.isDatapathLive()

            // `iptablesRules != null` was dropped here: the field is non-nullable, so the compiler
            // proved that term constant. rootIsAvailable and ROOT_MODE are the REAL gate and stay.
            if (rootIsAvailable && operationMode == ROOT_MODE) {
                var commands = iptablesRules.configureIptables(
                        dnsCryptState,
                        firewallState
                )
                val hashCode = commands.hashCode()

                if (hashCode == savedIptablesCommandsHash && !iptablesRules.isLastIptablesCommandsReturnError()) {
                    commands = iptablesRules.fastUpdate()
                }

                savedIptablesCommandsHash = hashCode

                iptablesRules.sendToRootExecService(commands)

                logi("Iptables rules updated")

                stopCounter = STOP_COUNTER_DELAY
            } else if (operationMode == VPN_MODE) {

                if (vpnServiceEnabled &&
                        dnsCryptState == STOPPED
                        // 2-DRIVE-ENGINE-VPN: the engine rides the DNSCrypt VpnService — it never holds the TUN
                        // up on its own, so the tunnel tears down once DNSCrypt and the firewall are stopped.
                        && (firewallState == STOPPED || firewallState == STOPPING)) {
                    ServiceVPNHelper.stop("All modules stopped", modulesService)
                    modulesVersions.get().refreshVersions(modulesService)
                } else if (vpnServiceEnabled) {
                    ServiceVPNHelper.reload("Modules state changed", modulesService)
                } else {
                    startVPNService()
                }

                stopCounter = STOP_COUNTER_DELAY
            }

            if (isFixTTL()) {
                if ((dnsCryptState == STOPPED || useModulesWithRoot) && vpnServiceEnabled) {
                    ServiceVPNHelper.stop("All modules stopped", modulesService)
                } else if (vpnServiceEnabled
                        /*Do not reload service during ARP attack to prevent loop*/
                        && !ArpScanner.dhcpGatewayAttackDetected
                        && !ArpScanner.arpAttackDetected) {
                    ServiceVPNHelper.reload("TTL is fixed", modulesService)
                } else {
                    startVPNService()
                }
            } else if ((operationMode == ROOT_MODE || operationMode == PROXY_MODE) && vpnServiceEnabled) {
                ServiceVPNHelper.stop("TTL stop fixing", modulesService)
            }

            //Avoid too frequent iptables update
            // `handler != null` dropped -- non-nullable field, constant term. The STOPPED check is
            // the throttle's actual condition and is untouched.
            if (dnsCryptState != STOPPED) {
                iptablesUpdateTemporaryBlocked = true
                handler.get().postDelayed({
                    iptablesUpdateTemporaryBlocked = false
                    ModulesAux.makeModulesStateExtraLoop(modulesService)
                }, 8000L)
            }

        } else if (useModulesWithRoot && operationMode == ROOT_MODE) {

            if (dnsCryptState != STOPPED && dnsCryptState != RUNNING && dnsCryptState != FAULT) {
                return
            } else if (modulesStatus.isContextUIDUpdateRequested) {
                return
            } else if (dnsCryptState == RUNNING && !modulesStatus.isDnsCryptReady) {
                return
            }

            stopCounter--
        } else if ((dnsCryptState == STOPPED || dnsCryptState == FAULT)
                && (firewallState == STOPPING || firewallState == STOPPED)) {
            stopCounter--
        }

    }

    private fun updateContextUID(dnsCryptState: ModuleState) {

        if (!modulesStatus.isRootAvailable) {
            modulesStatus.isContextUIDUpdateRequested = false
            logw("Modules Selinux context and UID not updated. Root is Not Available")
            return
        }

        if (dnsCryptState != STOPPED) {
            ModulesAux.stopModulesIfRunning(modulesService)
            return
        }

        modulesStatus.isContextUIDUpdateRequested = false

        contextUIDUpdater.updateModulesContextAndUID()

        logi("Modules Selinux context and UID updated for "
                + (if (modulesStatus.isUseModulesWithRoot) "Root" else "No Root"))
    }

    private fun restoreModulesSavedState() {
        // #21 G7-RESIDUAL: the token reads from the Rust `app-state` DurableTier record
        // (AppStateBridge — legacy-prefs fallback inside), not SharedPreferences.
        val savedDNSCryptStateStr = AppStateBridge.savedDnsCryptState()
        if (!savedDNSCryptStateStr.isEmpty()) {
            savedDNSCryptState = ModuleState.valueOf(savedDNSCryptStateStr)
            // ★ SPLIT-BRAIN CURE (#129 field bug 1): the restore exists to suppress duplicate edge work
            // across ModulesService restarts — valid only while the process (and with it the resolver
            // pool) survived. An active state restored into a process where the RUNNING edge never fired
            // came from a DEAD process (backup restore, `pm install -r`, force-kill relaunch); honoring
            // it makes the first genuine RUNNING observation edge-less, so the pool configure and the
            // running broadcast are skipped — shielded crown, every query blackholed. Demote to STOPPED
            // so that first observation IS the edge and the restore self-heals into a real start.
            if (!runningEdgeFiredThisProcess
                    && (savedDNSCryptState == RUNNING
                    || savedDNSCryptState == STARTING
                    || savedDNSCryptState == RESTARTING)) {
                logw("ModulesStateLoop restored saved DNSCrypt state " + savedDNSCryptState
                        + " from a dead process — demoting to STOPPED so the next RUNNING fires the edge")
                savedDNSCryptState = STOPPED
            }
        }
    }

    private fun startVPNService() {

        //Start VPN service if it is not started by modules presenters

        // The `handler != null` wrapper and the three `!= null` terms below were dropped: all four
        // fields are non-nullable, so the compiler proved every one of them constant. What decides
        // whether the VPN starts -- the stored flag, the module states, and VpnService.prepare() --
        // is untouched, and the 10 s delay still applies.
        handler.get().postDelayed({
            if (!sharedPreferences.getBoolean(VPN_SERVICE_ENABLED, false)
                        // 2-DRIVE-ENGINE-VPN: DNSCrypt is the SOLE VPN gatekeeper. The Tortä engine is no
                        // longer a first-class VPN trigger — it rides the DNSCrypt VpnService (an OS-protected
                        // FGS), so only DNSCrypt / the Warden firewall raise the tunnel. The engine never needs
                        // the Always-on-VPN + access-log keep-alive to survive; it lives while the VPN is up.
                    && (modulesStatus.dnsCryptState == RUNNING
                    || modulesStatus.firewallState == STARTING
                    || modulesStatus.firewallState == RUNNING)
                    && VpnService.prepare(modulesService) == null) {
                sharedPreferences.edit().putBoolean(VPN_SERVICE_ENABLED, true).apply()
                ServiceVPNHelper.start("ModulesStateLoop start VPN service", modulesService)
            }
        }, 10000L)
    }

    private fun safeStopModulesService() {
        handler.get().post {

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                modulesService.stopForeground(true)
            }

            modulesService.stopSelf()
        }
    }

    fun setDnsCryptThread(dnsCryptThread: Thread) {
        Companion.dnsCryptThread = dnsCryptThread
    }

    fun clearIptablesCommandHash() {
        savedIptablesCommandsHash = 0
    }

    fun removeHandlerTasks() {
        iptablesRules.unregisterReceiver()

        handler.get().removeCallbacksAndMessages(null)
    }

    override fun onDNSCryptLogUpdated(dnsCryptLogData: LogDataModel) {
        if (dnsCryptLogData.startedSuccessfully
                && modulesStatus.dnsCryptState == RUNNING) {
            setDNSCryptReady(true)
            denySystemDNS()
            dnsCryptInteractor.removeOnDNSCryptLogUpdatedListener(this)
        }
    }

    private fun saveDNSCryptState(dnsCryptState: ModuleState) {
        savedDNSCryptState = dnsCryptState
        // #21: write-through to the Rust `app-state` record (control-plane — a state edge).
        AppStateBridge.setSavedDnsCryptState(dnsCryptState.toString())
    }

    private fun setDNSCryptReady(ready: Boolean) {

        val savedReady = modulesStatus.isDnsCryptReady

        preferenceRepository.get().setBoolPreference(DNSCRYPT_READY_PREF, ready)
        modulesStatus.isDnsCryptReady = ready
        if (ready) {
            modulesStatusBroadcaster.get().broadcastDNSCryptReady()
        }

        if (ready && !savedReady) {
            connectivityCheckManager.get().refreshConnectivityCheckIPs()
        }
    }

    @Synchronized
    private fun denySystemDNS() {

        if (modulesStatus.isSystemDNSAllowed) {
            if (modulesStatus.mode == ROOT_MODE) {
                modulesStatus.isSystemDNSAllowed = false
                ModulesIptablesRules.denySystemDNS(modulesService, pathVars.get())
            }

            if (modulesStatus.mode == VPN_MODE || isFixTTL()) {
                modulesStatus.isSystemDNSAllowed = false
                ServiceVPNHelper.reload("DNSCrypt Deny system DNS", modulesService)
            }
        }
    }

    private fun saveFirewallState(firewallState: ModuleState) {
        savedFirewallState = firewallState
        if (firewallState == RUNNING) {
            ModulesAux.saveFirewallStateRunning(true)
        } else if (firewallState == STOPPED) {
            ModulesAux.saveFirewallStateRunning(false)
        }
    }

    override fun isActive(): Boolean {
        return ModulesService.serviceIsRunning
    }

    private fun isFixTTL(): Boolean {
        return modulesStatus.isFixTTL && (modulesStatus.mode == ROOT_MODE)
                && !modulesStatus.isUseModulesWithRoot
    }

    private fun slowDownModulesStateTimerIfRequired() {
        if (!modulesStatus.isUseModulesWithRoot
                && modulesStatus.dnsCryptState == RUNNING && modulesStatus.isDnsCryptReady
                && !App.instance.isAppForeground) {
            modulesService.slowdownTimer()
        }
    }

    @SuppressLint("UnsafeOptInUsageWarning")
    private fun startNflogIfRootMode() {
        if (!nflogIsRunning && modulesStatus.mode == ROOT_MODE
                && !modulesStatus.isUseModulesWithRoot
                && defaultPreferences.get().getBoolean(CONNECTION_LOGS, true)) {
            nflogIsRunning = true
            nflogManager.get().startNflog()
        }
    }

    @SuppressLint("UnsafeOptInUsageWarning")
    private fun stopNflogIfRootMode() {
        if (nflogIsRunning || modulesStatus.mode == ROOT_MODE && !modulesStatus.isFixTTL) {
            nflogManager.get().stopNflog()
            nflogIsRunning = false
            modulesVersions.get().refreshVersions(modulesService)
        }
    }

    companion object {

        //Depends on timer, currently 10 sec
        private const val STOP_COUNTER_DELAY = 10

        //Delay in sec before service can stop
        private var stopCounter = STOP_COUNTER_DELAY

        // ★ FRESH-INSTALL FIX (#5 first-boot empty pool): a bounded grace that keeps ModulesService alive
        // across the Android VPN-consent gap. On a FRESH install the first DNSCrypt start blocks on the OS
        // consent dialog; the pure-Rust tunnel (TunnelController.isDatapathLive — the true RUNNING signal on
        // this build) only spawns AFTER the user taps OK, often well past STOP_COUNTER_DELAY seconds. The
        // idle STOPPED countdown has usually already drained stopCounter to zero by the time the switch is
        // flipped, and the STARTING phase early-returns without resetting it — so the service STOPS during the
        // gap, BEFORE the tunnel comes up. The loop is then dead when DNSCrypt finally reaches RUNNING, so the
        // STARTING→RUNNING promotion (updateModulesState) and the onDnsCryptStarted resolver-config edge
        // (updateIptablesRules) never fire → the pool is never configured → every query MISSes until the user
        // manually toggles OFF→ON (which, on a now-warm install, skips the consent dialog and wins the race).
        // This grace holds the loop alive while the user's ON intent is pending and the tunnel is not yet up,
        // bounded by PENDING_START_GRACE iterations so a denied or abandoned consent cannot pin the foreground
        // service alive forever. Instance (not static) — a fresh loop for each ModulesService gets a fresh budget.
        private const val PENDING_START_GRACE = 90

        private var dnsCryptThread: Thread? = null

        // ★ SPLIT-BRAIN CURE (#129 field bug 1): true once the DNSCrypt RUNNING-edge work (resolver pool
        // configure, broadcast, trust/rotation/tier managers) has fired in THIS process. Static on purpose —
        // it survives a ModulesService restart exactly like the in-process resolver pool it tracks, and dies
        // with the process exactly like that pool. restoreModulesSavedState() consults it: a persisted
        // savedDNSCryptState=RUNNING restored into a process where no edge ever fired is a stale claim from a
        // dead process (backup restore, `pm install -r`), and honoring it suppresses the edge that would
        // configure the pool — the shielded-crown-but-every-query-blackholes wedge.
        @Volatile
        private var runningEdgeFiredThisProcess = false
    }
}
