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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu

import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.BootReapplyPolicy
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.PowerCatalogue
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.PowerId
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.PowerOp
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.toInuPowerId
import uniffi.torta_core.InuBootDurability
import uniffi.torta_core.InuElevationStatus
import uniffi.torta_core.InuEvent
import uniffi.torta_core.InuPowerFlag
import uniffi.torta_core.InuProvider
import uniffi.torta_core.InuStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Orchestrates the no-root, on-device wireless-ADB self-elevation (Shizuku-style).
 *
 * Live now (Wave A): the [android.net.nsd.NsdManager] discovery that finds the system's randomly
 * chosen `_adb-tls-pairing._tcp` port, and the whole [WireCakeInuUiState] flow. Pending ([AdbElevation],
 * Wave B): the SPAKE2/TLS pairing handshake and the privileged shell. Until that engine is wired,
 * a [StubAdbElevation] makes pairing fail honestly rather than fake success.
 *
 * Kotlin-Inject wired (the Dagger→KI migration): constructed by [WireCakeInuComponent] — the setup
 * screen + the notification service each pull a fresh one and dispose it in onDestroy. The
 * [AdbElevation] engine ([LibAdbElevation]) and the durable [InuStore] (RAM⊗NAND power/pair state,
 * replacing SharedPreferences) are constructor-supplied — no hand-`new`, no default-arg construction.
 */
class WireCakeInuManager(
    private val appContext: Context,
    private val elevation: AdbElevation,
    private val inuStore: InuStore,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private val _state = MutableStateFlow<WireCakeInuUiState>(
        if (supported) WireCakeInuUiState.Idle else WireCakeInuUiState.Unsupported
    )
    val state: StateFlow<WireCakeInuUiState> = _state.asStateFlow()

    /** True once a real pairing engine is plugged in — the UI uses it to be honest about Wave B. */
    val engineReady: Boolean get() = elevation.isImplemented

    /** Persisted across launches (Rust RAM⊗NAND, was WIRELESS_DEBUG_GRANTED): granted before? */
    fun isProtected(): Boolean =
        try { inuStore.rehydrate().paired } catch (e: Exception) { false }

    /** Epoch millis of the last successful grant (0 if never; was WIRELESS_DEBUG_GRANTED_AT). */
    fun protectedSince(): Long =
        try { inuStore.rehydrate().grantedAt } catch (e: Exception) { 0L }

    private val nsdManager: NsdManager? by lazy {
        appContext.getSystemService(Context.NSD_SERVICE) as? NsdManager
    }
    private var discoveryListener: NsdManager.DiscoveryListener? = null

    @Volatile private var pairHost: String? = null
    @Volatile private var pairPort: Int = -1
    @Volatile private var pendingCode: String? = null

    /** Discover the pairing port and, once found, pair with [code] and elevate — one call. */
    fun pairAndElevate(code: String) {
        if (!supported) {
            _state.value = WireCakeInuUiState.Unsupported
            return
        }
        pendingCode = code
        startDiscovery()
    }

    /**
     * Pair against the endpoint already located by [startDiscovery] (the always-on notification path,
     * #7). The Shizuku-style service discovers the port FIRST, surfaces an in-shade code entry, then
     * calls this with the typed code — so we pair the known [pairHost]/[pairPort] directly WITHOUT
     * re-running discovery (which would re-fire [WireCakeInuUiState.Found] and re-show the entry).
     * If the endpoint is not known yet (e.g. the service process was restarted mid-input and lost its
     * in-memory state), fall back to the full discover-then-pair path so the code is never dropped.
     */
    fun pairWithDiscovered(code: String) {
        if (!supported) {
            _state.value = WireCakeInuUiState.Unsupported
            return
        }
        val host = pairHost
        val port = pairPort
        if (host == null || port <= 0) {
            pairAndElevate(code)
            return
        }
        scope.launch { doPair(host, port, code) }
    }

    /** Re-run connect + grant against an already-paired endpoint (Wave B). */
    fun retryGrant() {
        if (!supported) return
        scope.launch { elevate() }
    }

    fun startDiscovery() {
        if (!supported) {
            _state.value = WireCakeInuUiState.Unsupported
            return
        }
        val nsd = nsdManager ?: run {
            _state.value = WireCakeInuUiState.Error("Network Service Discovery unavailable")
            return
        }
        stopDiscovery()
        _state.value = WireCakeInuUiState.Discovering
        val listener = buildDiscoveryListener(nsd)
        discoveryListener = listener
        try {
            nsd.discoverServices(SERVICE_PAIRING, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            _state.value = WireCakeInuUiState.Error(e.message ?: "discovery failed to start")
        }
    }

    fun stopDiscovery() {
        val listener = discoveryListener ?: return
        try {
            nsdManager?.stopServiceDiscovery(listener)
        } catch (_: Exception) {
            // already stopped / never started
        }
        discoveryListener = null
    }

    fun dispose() {
        stopDiscovery()
        scope.cancel()
    }

    private fun buildDiscoveryListener(nsd: NsdManager) = object : NsdManager.DiscoveryListener {
        override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) {
            _state.value = WireCakeInuUiState.Error("discovery start failed ($errorCode)")
        }

        override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) {}

        override fun onDiscoveryStarted(serviceType: String?) {}

        override fun onDiscoveryStopped(serviceType: String?) {}

        override fun onServiceFound(serviceInfo: NsdServiceInfo) {
            if (serviceInfo.serviceType?.contains("adb-tls-pairing") == true) {
                resolve(nsd, serviceInfo)
            }
        }

        override fun onServiceLost(serviceInfo: NsdServiceInfo?) {}
    }

    @Suppress("DEPRECATION")
    private fun resolve(nsd: NsdManager, serviceInfo: NsdServiceInfo) {
        val resolveListener = object : NsdManager.ResolveListener {
            override fun onResolveFailed(info: NsdServiceInfo?, errorCode: Int) {
                _state.value = WireCakeInuUiState.Error("could not resolve pairing port ($errorCode)")
            }

            override fun onServiceResolved(info: NsdServiceInfo) {
                // NsdServiceInfo.host is deprecated at API 34 in favour of hostAddresses, which is a
                // LIST because one service can advertise several addresses (v4 and v6). Taking the
                // first preserves the previous single-address behaviour exactly.
                //
                // The safety property does NOT rest on which address is picked: isOwnDeviceAddress
                // below is what rejects a foreign host advertising a fake _adb-tls-pairing, and it
                // runs on whichever address this yields, on both branches.
                val host = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    info.hostAddresses.firstOrNull()?.hostAddress ?: return
                } else {
                    @Suppress("DEPRECATION")
                    info.host?.hostAddress ?: return
                }
                // The adb pairing service is on THIS device — but on a real phone NsdManager resolves it to
                // the device's own LAN/Wi-Fi address (e.g. 192.168.x.x), NOT the literal loopback. So accept
                // the device's OWN addresses (loopback + every local-interface IP) and reject only a
                // genuinely-foreign host (a rogue on the LAN advertising a fake _adb-tls-pairing). Fixes the
                // "pairing endpoint is not on this device (must be 127.0.0.1) — refused for safety" self-pair bug.
                if (!isOwnDeviceAddress(host)) {
                    _state.value = WireCakeInuUiState.Error(
                        uniffi.torta_core.tortaText("wd_err_not_loopback")
                    )
                    return
                }
                val port = info.port
                onPairingEndpoint(host, port)
            }
        }
        try {
            nsd.resolveService(serviceInfo, resolveListener)
        } catch (e: Exception) {
            _state.value = WireCakeInuUiState.Error(e.message ?: "resolve failed")
        }
    }

    /**
     * True iff [host] is one of THIS device's own addresses — loopback (the literal 127.0.0.0/8 block + ::1
     * + localhost) OR any address bound to a local network interface (the Wi-Fi/LAN IP the adb pairing mDNS
     * actually resolves to on a real phone). Rejects a genuinely-foreign host (a rogue LAN advertiser).
     * Fail-closed: any error / no match → false. The fix for the 127.0.0.1-only self-pair refusal.
     */
    private fun isOwnDeviceAddress(host: String): Boolean {
        val h = host.trim().removePrefix("[").removeSuffix("]").substringBefore('%').lowercase()
        if (h.isEmpty()) return false
        if (h == "localhost" || h == "::1" || h == "0:0:0:0:0:0:0:1" ||
            h.startsWith("127.") || h.startsWith("::ffff:127.")
        ) {
            return true
        }
        return try {
            java.net.NetworkInterface.getNetworkInterfaces().asSequence().any { ni ->
                ni.inetAddresses.asSequence().any { addr ->
                    addr.hostAddress?.substringBefore('%')?.lowercase() == h
                }
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun onPairingEndpoint(host: String, port: Int) {
        pairHost = host
        pairPort = port
        _state.value = WireCakeInuUiState.Found(host, port)
        stopDiscovery()
        val code = pendingCode
        if (code != null) {
            pendingCode = null
            scope.launch { doPair(host, port, code) }
        }
    }

    private suspend fun doPair(host: String, port: Int, code: String) {
        _state.value = WireCakeInuUiState.Pairing
        val result = elevation.pair(host, port, code)
        if (result.isFailure) {
            _state.value = WireCakeInuUiState.Error(
                result.exceptionOrNull()?.message ?: "pairing failed"
            )
            return
        }
        elevate()
    }

    private suspend fun elevate() {
        val host = pairHost ?: run {
            _state.value = WireCakeInuUiState.Error("no paired endpoint")
            return
        }
        _state.value = WireCakeInuUiState.Connecting
        // Wave B refines this to the discovered `_adb-tls-connect._tcp` endpoint.
        val shellResult = elevation.connect(host, pairPort)
        val shell = shellResult.getOrElse {
            _state.value = WireCakeInuUiState.Error(it.message ?: "connect failed")
            return
        }
        _state.value = WireCakeInuUiState.Connected
        // #8A — fire the FULL hardening batch (Tier-1 defaults + Tier-3 Expert powers: WRITE_SECURE_SETTINGS,
        // READ_LOGS, appops, doze, Data-Saver bypass) over the SAME [PowerCatalogue] + [PowerCatalogue.isHeld]
        // as the Expert keep-alive card. We DON'T route through GrantEngine here: LibAdbShell.exec already
        // wraps each command with AdbSentinel + parses it (LibAdbElevation.kt:64), and GrantEngine wraps
        // AGAIN — the double-wrap mangled the read-back so NOTHING landed (measured live: "Granting…" then 0
        // powers set). So replicate the engine's verify→set→verify per op against the shell's native
        // single-wrap exec. Best-effort per power; never throws on one ROM quirk.
        val pkg = appContext.packageName
        val appUid = android.os.Process.myUid()
        val ops = PowerCatalogue.build(pkg, appUid)
        val held = mutableListOf<PowerId>()
        try {
            _state.value = WireCakeInuUiState.Granting("no-root powers")
            // Run the WHOLE catalogue + the keystone read-back in ONE shell stream. The libadb `shell:`
            // connection does not survive multiple separate streams here (measured live: the per-op
            // verify→set→verify dropped after 2 powers with "connection terminated: read failed", and even a
            // single follow-up verify stream HUNG after the batch). So everything rides one stream: all the
            // set commands (sh runs each even if a prior fails), then an inline read-back of the always-on
            // VPN keystone tagged `__VPN__::<value>` that we parse out of the same output.
            val out = shell.exec(buildGrantBatch(ops))
            // Honest "protected" gate: the always-on VPN keystone (the OS-enforced tunnel) MUST read back as
            // our package — never assumed. The other powers ran in the same batch (best-effort enhancements).
            val vpnValue = parseVpnKeystone(out.value)
            if (vpnValue != pkg) {
                _state.value = WireCakeInuUiState.Error("always-on VPN not granted")
                return
            }
            held.addAll(ops.map { it.id })
        } catch (e: Exception) {
            _state.value = WireCakeInuUiState.Error(e.message ?: "grant failed")
            return
        } finally {
            shell.close()
        }
        // Persist to the SHARED Rust InuState (RAM⊗NAND) so the keep-alive card + boot re-apply reflect
        // the same grant — folds the former WIRELESS_DEBUG_GRANTED/_AT booleans + the power map into ONE
        // typed record (ZERO SharedPreferences). Control-plane write (never a poll); best-effort +
        // never-throws so one ROM quirk cannot fail the grant.
        runCatching {
            val now = System.currentTimeMillis()
            val current = inuStore.rehydrate()
            inuStore.persist(
                current.copy(
                    paired = true,
                    grantedAt = now,
                    provider = InuProvider.SELF_ADB,
                    elevationStatus = InuElevationStatus.ELEVATED,
                    powers = buildPowerFlags(ops, held.toSet(), now),
                )
            )
            // The ACTIVE elevation channel just moved (e.g. Shizuku/none -> self-ADB). That transition is a
            // both-provider fact `logEvent` structurally cannot express — it carries ONE provider field —
            // which is exactly why `logProviderSwitch(from, to, now)` exists (object.rs:151). This grant is
            // the only place the active channel changes, so without this line the SWITCH lane of
            // `query-inu.log` is never written and the dashboard's recent-events rail silently omits an
            // entire event class. Guarded: a re-grant on the SAME channel is not a switch. Emitted BEFORE
            // the GRANT line so the log reads chronologically — channel moved, then the grant landed.
            if (current.provider != InuProvider.SELF_ADB) {
                inuStore.logProviderSwitch(current.provider, InuProvider.SELF_ADB, now)
            }
            inuStore.logEvent(InuEvent.GRANT, InuProvider.SELF_ADB, "held=${held.size}/${ops.size}", now)
        }
        notifyProtected()
        _state.value = WireCakeInuUiState.Done(held.map { it.name })
    }

    // ---- shared grant primitives (elevate + boot re-apply ride the SAME single-stream batch) -------

    /**
     * The whole-catalogue single-stream batch: every set command joined with `;` (sh runs each even if
     * a prior fails), then an inline read-back of the always-on VPN keystone tagged `__VPN__::<value>`.
     * ONE stream on purpose — the libadb `shell:` connection does not survive multiple separate streams
     * here (measured live: per-op verify dropped after 2 powers; a follow-up verify stream HUNG).
     */
    private fun buildGrantBatch(ops: List<PowerOp>): String {
        val vpn = ops.first { it.id == PowerId.ALWAYS_ON_VPN }
        val keystoneRead = vpn.readBackCmd ?: "settings get secure always_on_vpn_app"
        return ops.joinToString(" ; ") { it.setCmd } + " ; echo \"__VPN__::\$($keystoneRead)\""
    }

    /** Pull the `__VPN__::<value>` keystone out of the batch output (empty if the tag never appeared). */
    private fun parseVpnKeystone(output: String): String =
        output.lineSequence()
            .firstOrNull { it.startsWith("__VPN__::") }
            ?.substringAfter("__VPN__::")?.trim() ?: ""

    /** Map the applied catalogue into the durable per-power flags (denormalized durability + read-back). */
    private fun buildPowerFlags(ops: List<PowerOp>, held: Set<PowerId>, now: Long): List<InuPowerFlag> =
        ops.mapNotNull { op ->
            val inuId = op.id.toInuPowerId() ?: return@mapNotNull null
            InuPowerFlag(
                id = inuId,
                desired = true,
                lastVerified = now,
                lastResult = op.id in held,
                durability = if (op.driftProne) InuBootDurability.DRIFT_PRONE else InuBootDurability.DURABLE,
            )
        }

    /**
     * Silent boot-time re-apply (P11 §3 consumer — closes the [BootReapplyPolicy] + `INU_BOOT_REAPPLY`
     * orphan). On a protected device, RECONNECT codelessly (the persisted ADB key/cert drive
     * [AdbElevation.connect] → autoConnect, NO pairing code — LibAdbElevation.kt:50) and re-run the power
     * batch so the drift-prone app-standby bucket the OS demoted over the downtime is re-established and
     * the durable powers re-verified. NEVER re-pairs, NEVER nags, NEVER posts the celebratory
     * notification: a quiet re-arm. Consumes [BootReapplyPolicy.decide] so it opens NO ADB connection
     * unless there is real, previously-verified protection to re-establish.
     *
     * Returns true only when a real re-apply landed (VPN keystone re-verified); false on "nothing to do"
     * or a graceful reconnect failure (e.g. Wireless Debugging off at boot) — the caller stops silently.
     */
    suspend fun reapplyOnBoot(): Boolean {
        if (!supported) return false
        val current = try { inuStore.rehydrate() } catch (e: Exception) { return false }
        if (!current.paired) return false
        val plan = BootReapplyPolicy.decide(
            isProtected = current.elevationStatus == InuElevationStatus.ELEVATED,
            powers = current.powers.map { flag ->
                BootReapplyPolicy.PowerState(
                    id = flag.id.name,
                    durability = if (flag.durability == InuBootDurability.DRIFT_PRONE)
                        BootReapplyPolicy.Durability.DRIFT_PRONE
                    else
                        BootReapplyPolicy.Durability.DURABLE,
                    lastVerified = flag.lastResult,
                )
            },
        )
        if (!plan.shouldReconnect) return false
        android.util.Log.i(
            BOOT_TAG,
            "reapplyOnBoot: protected -> reconnect (reapply=${plan.toReapply.size} reverify=${plan.toReverify.size})"
        )
        // Codeless reconnect: LibAdbElevation.connect ignores host/port and drives autoConnect off the
        // persisted key/cert. A failure here = Wireless Debugging off / endpoint gone at boot → degrade
        // quietly (no nag); the live reconnect is the tracked device-only witness.
        val shell = elevation.connect(pairHost ?: "", if (pairPort > 0) pairPort else 0)
            .getOrElse {
                android.util.Log.i(BOOT_TAG, "reapplyOnBoot: reconnect failed (${it.message}) -> quiet skip")
                inuStore.logEvent(
                    InuEvent.FAIL, InuProvider.SELF_ADB,
                    "boot reconnect: ${it.message}", System.currentTimeMillis()
                )
                return false
            }
        val pkg = appContext.packageName
        val appUid = android.os.Process.myUid()
        val ops = PowerCatalogue.build(pkg, appUid)
        val held = mutableListOf<PowerId>()
        try {
            val out = shell.exec(buildGrantBatch(ops))
            if (parseVpnKeystone(out.value) == pkg) held.addAll(ops.map { it.id })
        } catch (e: Exception) {
            android.util.Log.i(BOOT_TAG, "reapplyOnBoot: batch threw (${e.message})")
            inuStore.logEvent(
                InuEvent.FAIL, InuProvider.SELF_ADB,
                "boot reapply: ${e.message}", System.currentTimeMillis()
            )
            return false
        } finally {
            shell.close()
        }
        // Persist the re-verified posture. PRESERVE the original grantedAt (this is a re-arm, not a fresh
        // grant — "protected since" must not reset every reboot) and stay ELEVATED.
        runCatching {
            val now = System.currentTimeMillis()
            inuStore.persist(
                current.copy(
                    elevationStatus = InuElevationStatus.ELEVATED,
                    powers = buildPowerFlags(ops, held.toSet(), now),
                )
            )
            inuStore.logEvent(InuEvent.DRIFT_REAPPLY, InuProvider.SELF_ADB, "held=${held.size}/${ops.size}", now)
        }
        android.util.Log.i(BOOT_TAG, "reapplyOnBoot: done held=${held.size}/${ops.size}")
        return held.isNotEmpty()
    }

    /**
     * The celebratory "The Soft-Cäke is now officially baked" notification on a successful pair+grant
     * (fired for BOTH the wizard and the notification paths). Tortä-branded icon + a "Bring me a slice of
     * tortä" action that bounces through [TortaSliceActivity] back to Tortä with the 10s "YEAH!!" toast.
     * Best-effort: guarded by try/catch (a POST_NOTIFICATIONS denial is swallowed — the in-app status card
     * still shows the grant). Lint cannot follow that guard, so it is suppressed.
     */
    @SuppressLint("MissingPermission")
    private fun notifyProtected() {
        try {
            val nm = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                nm.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ID,
                        uniffi.torta_core.tortaText("menu_wire_cake_inu"),
                        NotificationManager.IMPORTANCE_DEFAULT
                    )
                )
            }
            val sliceIntent = android.content.Intent(appContext, TortaSliceActivity::class.java)
                .addFlags(
                    android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                        android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP
                )
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
            else
                android.app.PendingIntent.FLAG_UPDATE_CURRENT
            val slicePending = android.app.PendingIntent.getActivity(appContext, 7031, sliceIntent, flags)
            val notification = NotificationCompat.Builder(appContext, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_torta_notification)
                .setContentTitle(uniffi.torta_core.tortaText("wd_notif_baked_title"))
                .setContentText(uniffi.torta_core.tortaText("wd_notif_baked_body"))
                .setAutoCancel(true)
                .addAction(0, uniffi.torta_core.tortaText("wd_notif_slice_btn"), slicePending)
                .build()
            NotificationManagerCompat.from(appContext).notify(NOTIF_ID, notification)
        } catch (_: Exception) {
            // notifications disabled / no permission — the in-app status card still shows it
        }
    }

    private val supported: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

    companion object {
        /** logcat tag for the silent boot re-arm path (the device-only reconnect witness). */
        private const val BOOT_TAG = "WireCakeInuBoot"
        const val SERVICE_PAIRING = "_adb-tls-pairing._tcp"
        const val SERVICE_CONNECT = "_adb-tls-connect._tcp"
        private const val CHANNEL_ID = "yeah_torta_protection"
        private const val NOTIF_ID = 7021

        /** Human-readable elevation steps; the actual shell commands are finalized in Wave B. */
        val GRANT_PLAN = listOf("always-on VPN", "lockdown kill-switch")

        private val PKG = "app.torta.yeah"

        /** Intended shell command per step (run as UID 2000 once the engine is wired). */
        fun commandFor(step: String): String = when (step) {
            "always-on VPN" -> "settings put secure always_on_vpn_app $PKG"
            "lockdown kill-switch" -> "settings put secure always_on_vpn_lockdown 1"
            else -> "true"
        }
    }
}
