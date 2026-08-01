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

package pillar.kuma_saimono.libumdnscrypt.vpn.service

import android.annotation.TargetApi
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.NetworkInfo
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import androidx.annotation.Keep
import dagger.Lazy
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.BootCompleteReceiver
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.dns_engine.ResolverRuntime
import pillar.kuma_saimono.libumdnscrypt.domain.connection_checker.ConnectionCheckerInteractor
import pillar.kuma_saimono.libumdnscrypt.domain.connection_checker.OnInternetConnectionCheckedListener
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionData
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionProtocol
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.DnsRecord
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.PacketRecord
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesReceiver
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesService
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceNotificationManager
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.modules.savedMessage
import pillar.kuma_saimono.libumdnscrypt.modules.savedTitle
import pillar.kuma_saimono.libumdnscrypt.modules.startTime
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData
import pillar.kuma_saimono.libumdnscrypt.utils.Constants
import pillar.kuma_saimono.libumdnscrypt.utils.Utils
import pillar.kuma_saimono.libumdnscrypt.utils.bootcomplete.BootCompleteManager
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.enums.VPNCommand
import pillar.kuma_saimono.libumdnscrypt.utils.executors.CoroutineExecutor
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.vpn.Allowed
import pillar.kuma_saimono.libumdnscrypt.vpn.Packet
import pillar.kuma_saimono.libumdnscrypt.vpn.ResourceRecord
import pillar.kuma_saimono.libumdnscrypt.vpn.Usage
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils
import pillar.kuma_saimono.libumdnscrypt.vpn.tunnel.TunnelController
import java.net.IDN
import java.net.InetSocketAddress
import java.util.Collections
import java.util.Locale
import java.util.Objects
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentSkipListSet
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.inject.Inject
import javax.inject.Named
import javax.inject.Provider

class ServiceVPN : VpnService(), OnInternetConnectionCheckedListener {
    // Task 4C: the legacy `static { System.loadLibrary("invizible"); }` block is GONE — the pure-Rust
    // tunnel engine (UniFFI `TunnelController`, loaded as `libtorta_core.so`) replaces `libinvizible.so`.
    // No JNI, no C, no native library to load here. The UniFFI Kotlin bindings load the Rust .so lazily
    // on first `uniffi.torta_core.*` access; a missing .so throws `UnsatisfiedLinkError` there, not here.

    @Inject
    lateinit var preferenceRepository: Lazy<PreferenceRepository>
    @Inject
    @field:Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    lateinit var defaultPreferences: Lazy<SharedPreferences>
    @Inject
    lateinit var pathVars: Lazy<PathVars>
    @Inject
    lateinit var connectionCheckerInteractor: Lazy<ConnectionCheckerInteractor>
    @Inject
    lateinit var handler: Lazy<Handler>
    @Inject
    lateinit var executor: Lazy<CoroutineExecutor>
    @Inject
    lateinit var vpnPreferenceHolder: Provider<VpnPreferenceHolder>
    @Volatile
    var vpnPreferences: VpnPreferenceHolder? = null
    @Inject
    lateinit var vpnRulesHolder: Lazy<VpnRulesHolder>
    @Inject
    lateinit var resolverRuntime: Lazy<ResolverRuntime>
    // Stage-2 Rust tunnel engine (S2-RUST-TUNNEL-ENGINE-SPEC §1 piece 4 + §"LOCKED DECISIONS" 3):
    // the Kotlin-Inject owner of the pure-Rust tun-packet-loop. ServiceVPN hands it the detached fd
    // (R1) + the R2 ProtectCallback; it drives the UniFFI TunnelController Object's start/stop.
    @Inject
    lateinit var tunnelController: Lazy<TunnelController>

    var notificationManager: NotificationManager? = null
    private var serviceNotificationManager: ModulesServiceNotificationManager? = null
    // Task 4C: `jni_lock` / `jni_context` / `service_jni_context` GONE — there is no native context to
    // hold. The Rust `TunnelController` (UniFFI Object) owns its own state inside the .so; ServiceVPN
    // drives it via `tunnelController.get().start(...)` / `.stop()` and never touches a native pointer.

    @Volatile
    private var savedInternetAvailable = false

    @Volatile
    var vpn: ParcelFileDescriptor? = null

    private val lock = ReentrantReadWriteLock(true)
    private val connectionDataRecords = ConcurrentHashMap<ConnectionData, Long>(
        16,
        0.75f,
        2
    )

    @Volatile
    private var commandLooper: Looper? = null
    @Volatile
    private var commandHandler: ServiceVPNHandler? = null

    // Task 4C: `tunnelThread` GONE — the loop thread is spawned and joined INSIDE the Rust
    // `TunnelController` (UniFFI Object). ServiceVPN never holds a reference to it; lifecycle is
    // `tunnelController.get().start()` / `.stop()`.

    @Volatile
    var canFilter = true

    @Volatile
    var reloading = false

    @Volatile
    private var blockCheckingTorConnection = false

    private val dnsRebindHosts: MutableSet<Int> = ConcurrentSkipListSet()

    private val binder = VPNBinder()

    // Task 4C: ALL TEN legacy `native` declarations GONE — jni_init / jni_start / jni_run / jni_stop /
    // jni_clear / jni_get_mtu / jni_socks5_for_tor / jni_socks5_for_proxy / jni_internet_is_available /
    // jni_done. The pure-Rust tunnel engine (UniFFI `TunnelController`) replaces the entire `libinvizible.so`
    // surface: the loop (`jni_run`), the SOCKS5/Tor state machine (`jni_socks5_*` — Tor is not shipped),
    // the MTU knob (`jni_get_mtu` — the loop clamps 1500 internally; VpnBuilder now sets it directly),
    // the internet-availability signal (`jni_internet_is_available` — Rust reads connectivity itself),
    // and the native context lifecycle (`jni_init`/`stop`/`clear`/`done`). No JNI, no C, no Go.

    @Synchronized
    fun startNative(vpn: ParcelFileDescriptor, listAllowed: List<String>) {

        vpnPreferences = vpnPreferenceHolder.get()

        // Stage-2 Rust tunnel engine (S2-RUST-TUNNEL-ENGINE-SPEC §1.4 + §"LOCKED DECISIONS").
        // The legacy C packet loop (jni_run + udp.c) and its Go fallback are gone; the Rust
        // tunnel::TunnelController (UniFFI Object, task 1B) owns the read/parse/resolve/write loop.
        //
        // R1 fd-handoff: detachFd() EXACTLY ONCE — Rust dups into OwnedFd and closes the DUP on
        // stop(); neither side closes the original int. After this call `vpn` no longer owns the fd.
        // virtualDnsIp = "10.1.10.1" (the tun-subnet DNS IP, VpnBuilder.java:137 — NOT loopback;
        // Android rejects addDnsServer(127.0.0.1)). MTU 1500 is the Ethernet default the Rust loop
        // clamps internally (tunnel/mod.rs:258 .max(64)); the read buffer is sized from it.
        // rcode/lan come from vpnPreferences (the same knobs udp.c consumed via jni_run).
        // R1 fd-handoff: TunnelController.start owns detachFd() EXACTLY ONCE (Kotlin-side); ServiceVPN
        // hands the live ParcelFileDescriptor + this (the VpnService for R2 protect). virtualDnsIp is
        // the tun-subnet DNS IP (VpnBuilder.VPN_VIRTUAL_DNS_IP — NOT loopback; Android rejects
        // addDnsServer(127.0.0.1)). MTU 1500 is the Ethernet default the Rust loop clamps internally
        // (tunnel/mod.rs .max(64)); rcode/lan come from vpnPreferences (the knobs udp.c consumed).
        tunnelController.get().start(
            vpn,
            1500,
            "10.1.10.1",
            vpnPreferences!!.dnsBlockedResponseCode,
            vpnPreferences!!.lan,
            this
        )
        logi("VPN Rust tunnel start requested")

        // DEFAULTS-ON WARDEN ARM (the datapath-wiring re-open, Task #10). The Warden native enforce bit
        // was armed by ModulesStarterHelper.applyWardenNativeFromPref — but STAGE-2's de-Go left that call
        // ORPHANED: getDNSCryptStarterRunnable now `return@Runnable`s before the dead /* exec */ block that
        // held it, so on the pure-Rust path NOTHING mirrored the pref into the engine and the firewall came
        // up DISARMED regardless of WARDEN_NATIVE_ENABLED (only the dashboard ARM chip could arm it, in-UI).
        // The correct seam is HERE — the tunnel bring-up IS the datapath, single-process, so the canonical
        // WardenObject the loop consults per-packet lives in this same address space. Read the live pref
        // and mirror it; re-asserted on every establish.
        // Crash-proof (WardenDatapathGate catches everything; an unreachable .so leaves the tunnel on its
        // legacy allow-all consult). setWardenNativeEnabled == WardenDatapathGate.setEnforced + hold() mint.
        //
        // CORRECTION. This comment read "default-ON, the Socio all-ON contract 2026-06-24" while the line
        // below has passed `false` since d36a30c0 ("disable Warden by default"). The default IS OFF and
        // that is deliberate: a firewall that arms itself on first tunnel bring-up can black-hole a device
        // before the user has seen a single rule.
        //
        // The stale comment was not cosmetic. It described the OPPOSITE of the shipping behaviour, so the
        // next person to read `pref=false` in the log would diagnose it as a persistence bug and "fix" the
        // default back to true -- silently arming the firewall on every existing install at upgrade. A
        // comment that misdescribes a security default is a loaded gun pointed at the next change.
        //
        // Read as: default OFF, armed only by the user (WARDEN dashboard ARM chip, warden.slint:533),
        // re-asserted on every establish once they have.
        val wardenArmed = defaultPreferences.get().getBoolean(TortaeKeys.WARDEN_NATIVE_ENABLED, false)
        val wardenLanded = VpnUtils.setWardenNativeEnabled(wardenArmed)
        logi("Warden datapath arm-on-tunnel: pref=$wardenArmed landed=$wardenLanded")
    }

    @Synchronized
    fun stopNative() {
        logi("VPN Stop native (Rust tunnel)")
        // Stage-2: the Rust TunnelController.stop() signals the cancel token, joins the loop thread,
        // and drops the OwnedFd (closes the dup — R1: the ORIGINAL detached int stays untouched).
        // Idempotent; safe to call when no loop is running.
        tunnelController.get().stop()
    }

    // Task 4C: the four `@Keep` JNI callbacks GONE — nativeExit / nativeError / logPacket / dnsResolved.
    //
    // nativeExit / nativeError → replaced by a UniFFI callback-interface (task 4D will wire the Rust
    //   `TunnelController` lifecycle-callback trait; the Kotlin impl lands there). The legacy C engine
    //   invoked these from `jni/invizible/*.c`; that caller is deleted, so the methods are dead today.
    //   A missing exit/error surface is honest in the interim — the Rust loop logs its own panic/exit
    //   paths through `loge` on the Kotlin side via the callback-interface when 4D lands.
    //
    // logPacket → DROPPED on the hot path. Packet-level logging is observability-only; the Rust loop
    //   surfaces counts-only telemetry via `TunnelController.snapshot()` (T20: no qname, no IP). The
    //   `Packet`/`Usage` records were a C-engine concern; with no C engine, no caller remains.
    //
    // dnsResolved → DROPPED on the hot path. The DNS rebind guard, the P7 blocklist observe, and the
    //   shadow-compare seam were挂在 the JNI callback fired by the C `dns_resolved` bridge. With the
    //   C engine gone AND the resolver answering inline from Rust, the live paths are:
    //     • query.log / connection records — fed by `ResolverRuntime.resolve_logged` (the resolver
    //       itself), NOT by this callback.
    //     • shadow-compare — `ResolverRuntime.shadowCompare(qname, returnCode)` fires from
    //       `ResolverRuntime.resolve` (dns_engine/ResolverRuntime.kt:214), independent of this callback.
    //     • blocklist verdict — the Rust tunnel `torta_firewall_verdict` answers inline.
    //   The C-bridge-fired `BlocklistRuntime.observe(rr.QName)` was the ONLY `.observe()` call site;
    //   it is intentionally retired with this callback (the Rust loop owns verdicts inline now).

    private fun addDnsToConnectionRecords(rr: ResourceRecord) {

        if (!vpnPreferences!!.connectionLogsEnabled || reloading) {
            return
        }

        val dnsRecord = DnsRecord(
            System.currentTimeMillis(),
            // The five `!= null` tests here were constant: ResourceRecord.kt:36-48 declares every
            // one of these as a NON-NULLABLE `String = ""`, so null is unrepresentable and the
            // `else ""` arms were unreachable. Dropping them is behaviour-identical even for the
            // empty record -- IDN.toUnicode("") is "" and "".trim() is "", exactly what the dead
            // else arms returned. The empty-string default lives in ResourceRecord, not here.
            IDN.toUnicode(rr.QName.trim().lowercase(Locale.getDefault()), IDN.ALLOW_UNASSIGNED),
            IDN.toUnicode(rr.AName.trim().lowercase(Locale.getDefault()), IDN.ALLOW_UNASSIGNED),
            IDN.toUnicode(rr.CName.trim().lowercase(Locale.getDefault()), IDN.ALLOW_UNASSIGNED),
            rr.HInfo.trim(),
            rr.Rcode,
            rr.Resource.trim()
        )

        //Remove entry to update key time
        val creationTime = connectionDataRecords.remove(dnsRecord)
        //Use value creation time to keep DNS records order
        connectionDataRecords.put(
            dnsRecord,
            if (creationTime != null) creationTime else SystemClock.elapsedRealtimeNanos()
        )


        if (connectionDataRecords.size >= LINES_IN_DNS_QUERY_RAW_RECORDS) {
            freeSpaceInConnectionRecords()
        }
    }

    private fun freeSpaceInConnectionRecords() {
        val connectionDataList = getSortedConnectionDataByTime()
        for (i in 0 until connectionDataList.size / 3) {
            connectionDataRecords.remove(connectionDataList[i])
        }
    }

    private fun getSortedConnectionDataByTime(): List<ConnectionData> {
        val connectionDataList = ArrayList(connectionDataRecords.keys)
        Collections.sort(connectionDataList) { o1, o2 -> (o1.time - o2.time).toInt() }
        return connectionDataList
    }

    // Called from native code
    @Keep
    fun isDomainBlocked(name: String?): Boolean {

        if (name == null) {
            return true
        }

        try {
            if (vpnPreferences!!.dnsRebindProtection && dnsRebindHosts.contains(name.hashCode())) {
                return true
            }
        } catch (e: Exception) {
            loge("ServiseVPN isDomainBlocked exception", e)
        }

        return false
    }

    // Called from native code
    @Keep
    fun isRedirectToTor(uid: Int, destAddress: String?, destPort: Int): Boolean {
        // Tor stripped: never redirect to Tor.
        return false
    }

    // Called from native code
    @Keep
    fun isRedirectToProxy(uid: Int, destAddress: String?, destPort: Int): Boolean {

        if (destAddress == null) {
            return false
        }

        if ((vpnPreferences!!.fixTTL && !vpnPreferences!!.useProxy)
            || (vpnPreferences!!.compatibilityMode && uid == ApplicationData.SPECIAL_UID_KERNEL)
        ) {
            return false
        }

        if (vpnPreferences!!.lan || uid == Constants.NETWORK_STACK_DEFAULT_UID) {
            if (VpnUtils.isIpInLanRange(destAddress)) {
                return false
            }
        }

        if (uid == 1000 && destPort == ApplicationData.SPECIAL_PORT_NTP) {
            return !(vpnRulesHolder.get().uidSpecialAllowed.contains(ApplicationData.SPECIAL_UID_NTP)
                    || vpnRulesHolder.get().setUidAllowed.contains(1000))
        }

        return !vpnPreferences!!.setBypassProxy.contains(uid.toString())
    }

    private fun isIpInDNSRebindRange(destAddress: String): Boolean {
        return VpnUtils.isIpInLanRange(destAddress)
    }

    // Called from native code
    @Keep
    @TargetApi(Build.VERSION_CODES.Q)
    fun getUidQ(version: Int, protocol: Int, saddr: String?, sport: Int, daddr: String?, dport: Int): Int {
        var protocol = protocol
        var sport = sport
        var dport = dport
        if (saddr == null || daddr == null) {
            return Process.INVALID_UID
        }

        //Workaround for ICMP
        if (protocol == ConnectionProtocol.ICMPv4 || protocol == ConnectionProtocol.ICMPv6) {
            sport = 0
            dport = 0
            protocol = ConnectionProtocol.UDP
        } else if (protocol != ConnectionProtocol.TCP && protocol != ConnectionProtocol.UDP) {
            return Process.INVALID_UID
        }

        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager?
        if (cm == null)
            return Process.INVALID_UID

        val local = InetSocketAddress(saddr, sport)
        val remote = InetSocketAddress(daddr, dport)

        return cm.getConnectionOwnerUid(protocol, local, remote)
    }

    // Called from native code
    @Keep
    fun protectSocket(socket: Int): Boolean {
        return protect(socket)
    }

    // Called from native code
    @Keep
    fun isAddressAllowed(packet: Packet): Allowed? {
        return vpnRulesHolder.get().isAddressAllowed(this, packet)
    }

    // Called from native code
    @Keep
    fun suspectTorConnectionUnavailable(): Boolean {
        // Tor stripped: nothing to check.
        return false
    }

    private fun unlockCheckingTorConnectionDelayed() {
        handler.get().postDelayed(
            { blockCheckingTorConnection = false },
            CHECK_TOR_CONNECTION_DELAY_SEC * 1000L
        )
    }

    // Called from native code
    @Keep
    fun accountUsage(usage: Usage) {
        //logi(usage.toString());
    }

    override fun onCreate() {

        logi("VPN Create version="
                + VpnUtils.getSelfVersionName(this)
                + "/"
                + VpnUtils.getSelfVersionCode(this)
                + "/"
                + this.hashCode())

        VpnUtils.canFilterAsynchronous(this)

        // Task 4C: native context init/teardown GONE — no `jni_init`, no `jni_context`. The Rust
        // `TunnelController` (UniFFI Object) is constructed lazily inside `TunnelController.start` on
        // first VPN-establish; nothing to do at service-create time.

        super.onCreate()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            var title = uniffi.torta_core.tortaText("app_name")
            var message = uniffi.torta_core.tortaText("notification_text")
            if (!savedTitle.isEmpty() && !savedMessage.isEmpty()) {
                title = savedTitle
                message = savedMessage
            }

            serviceNotificationManager = ModulesServiceNotificationManager.getManager(this)
            serviceNotificationManager!!.createNotificationChannel(this)
            serviceNotificationManager!!.sendNotification(
                this,
                title,
                message,
                startTime
            )
        }

        App.instance.subcomponentsManager.modulesServiceSubcomponent().inject(this)

        val commandThread = HandlerThread(
            "VPN handler thread",
            Process.THREAD_PRIORITY_FOREGROUND
        )
        commandThread.start()

        commandLooper = commandThread.looper

        commandHandler = ServiceVPNHandler.getInstance(commandLooper!!, this)

        connectionCheckerInteractor.get().addListener(this)

        sendRevokeBroadcast(false)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        var intent = intent

        val prefs = defaultPreferences.get()
        val vpnEnabled = prefs.getBoolean(TortaeKeys.VPN_SERVICE_ENABLED, false)

        if (intent != null && Objects.equals(intent.action, ModulesServiceActions.ACTION_STOP_SERVICE_FOREGROUND)) {

            try {
                notificationManager!!.cancel(ModulesService.DEFAULT_NOTIFICATION_ID)
                stopForeground(true)
            } catch (e: Exception) {
                loge("VPNService stop Service foreground1 exception", e)
            }
        }

        val showNotification: Boolean
        if (intent != null) {
            showNotification = intent.getBooleanExtra("showNotification", true)
        } else {
            showNotification = Utils.isShowNotification(this)
        }

        if (showNotification) {
            var title = uniffi.torta_core.tortaText("app_name")
            var message = uniffi.torta_core.tortaText("notification_text")
            if (!savedTitle.isEmpty()
                && !savedMessage.isEmpty()) {
                title = savedTitle
                message = savedMessage
            }

            if (serviceNotificationManager == null) {
                serviceNotificationManager = ModulesServiceNotificationManager
                    .getManager(this)
                serviceNotificationManager!!.sendNotification(
                    this,
                    title,
                    message,
                    startTime
                )
            }
        }

        logi("VPN Received " + intent)

        if (intent != null && Objects.equals(intent.action, ModulesServiceActions.ACTION_STOP_SERVICE_FOREGROUND)) {

            try {
                notificationManager!!.cancel(ModulesService.DEFAULT_NOTIFICATION_ID)
                stopForeground(true)
            } catch (e: Exception) {
                loge("VPNService stop Service foreground2 exception", e)
            }

            stopSelf(startId)

            return Service.START_NOT_STICKY
        }

        // Handle service restart
        if (intent == null) {
            logi("VPN OnStart Restart")

            if (vpnEnabled) {
                val starterIntent = Intent(this, BootCompleteReceiver::class.java)
                starterIntent.setAction(BootCompleteManager.ALWAYS_ON_VPN)
                sendBroadcast(starterIntent)
                stopSelf(startId)
                return Service.START_NOT_STICKY
            } else {
                // Recreate intent
                intent = Intent(this, ServiceVPN::class.java)
                intent.putExtra(EXTRA_COMMAND, VPNCommand.STOP)
            }
        }

        val cmd = intent.getSerializableExtra(EXTRA_COMMAND) as VPNCommand?

        if (cmd == null) {
            logi("VPN OnStart ALWAYS_ON_VPN")

            if (vpnEnabled) {
                val starterIntent = Intent(this, BootCompleteReceiver::class.java)
                starterIntent.setAction(BootCompleteManager.ALWAYS_ON_VPN)
                sendBroadcast(starterIntent)
                stopSelf(startId)
                return Service.START_NOT_STICKY
            } else {
                intent.putExtra(EXTRA_COMMAND, VPNCommand.STOP)
            }
        }

        val reason = intent.getStringExtra(EXTRA_REASON)
        logi("VPN Start intent="
                + intent
                + " command="
                + cmd
                + " reason="
                + reason
                + " vpn="
                + (vpn != null)
                + " user="
                + (pathVars.get().appUid / 100000))

        commandHandler!!.queue(intent)

        return Service.START_STICKY
    }

    override fun onRevoke() {
        logi("VPN Revoke")

        val prefs = defaultPreferences.get()
        prefs.edit().putBoolean(TortaeKeys.VPN_SERVICE_ENABLED, false).apply()

        sendRevokeBroadcast(true)

        super.onRevoke()
    }

    private fun sendRevokeBroadcast(revoked: Boolean) {
        val intent = Intent(ModulesReceiver.VPN_REVOKE_ACTION)
        // Explicit to this app: VPN_REVOKE_ACTION is an internal broadcast consumed only by
        // ModulesReceiver. Scoping the package avoids the implicit-intent launch lint/security risk.
        intent.setPackage(packageName)
        intent.putExtra(ModulesReceiver.VPN_REVOKED_EXTRA, revoked)
        sendBroadcast(intent)
    }

    override fun onDestroy() {

        logi("VPN Destroy " + this.hashCode())

        commandLooper!!.quit()

        for (command in VPNCommand.values())
            commandHandler!!.removeMessages(command.ordinal)

        if (VpnBuilder.vpnDnsSet != null) {
            VpnBuilder.vpnDnsSet!!.clear()
        }

        connectionCheckerInteractor.get().removeListener(this)
        handler.get().removeCallbacksAndMessages(null)

        val modulesStatus = ModulesStatus.getInstance()
        if (modulesStatus.mode == OperationMode.VPN_MODE
            || modulesStatus.mode == OperationMode.PROXY_MODE) {
            ModulesStatus.getInstance().setFirewallState(ModuleState.STOPPED, preferenceRepository.get())
        }

        // Task 4C: no native context to tear down — no `service_jni_context`, no `jni_done`. The Rust
        // loop is joined inside `stopNative()` (→ `TunnelController.stop()` → `rust.stop()`); the
        // UniFFI Object is owned by the `@ModulesServiceScope` DI graph and dropped with it.
        executor.get().submit("ServiceVPN onDestroy") {

            try {
                if (vpn != null) {
                    stopNative()
                    commandHandler!!.stopVPN(vpn!!)
                    vpn = null
                    vpnRulesHolder.get().unPrepare()
                }
            } catch (ex: Throwable) {
                loge("VPN Destroy", ex, true)
            }
        }

        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? {
        logi("ServiceVPN onBind")

        var action: String? = null
        if (intent != null) {
            action = intent.action
        }

        if (VpnService.SERVICE_INTERFACE == action) {
            return super.onBind(intent)
        }

        return binder
    }

    override fun onUnbind(intent: Intent?): Boolean {
        logi("ServiceVPN onUnbind " + this.hashCode())
        return true
    }

    override fun onRebind(intent: Intent?) {
        logi("ServiceVPN onRebind " + this.hashCode())
        super.onRebind(intent)
    }

    override fun onConnectionChecked(available: Boolean) {
        // Task 4C: `jni_internet_is_available(available)` GONE — the Rust resolver reads connectivity
        // itself (it does not depend on a native push from Java). The reload-on-reconnect behavior below
        // is preserved; only the JNI signal to the (deleted) C engine is removed.
        if (available) {
            if (!savedInternetAvailable) {
                ServiceVPNHelper.reload("VPN - Internet is available due to confirmation.", this)
            }
        } else {
            logi("VPN - Internet is not available due to confirmation.")
        }
        savedInternetAvailable = available
    }

    val isNetworkAvailable: Boolean
        get() = connectionCheckerInteractor.get().getNetworkConnectionResult()

    val isInternetAvailable: Boolean
        get() = connectionCheckerInteractor.get().getInternetConnectionResult()

    override fun isActive(): Boolean {
        return true
    }

    inner class VPNBinder : Binder() {
        val service: ServiceVPN
            get() = this@ServiceVPN
    }

    val dnsQueryRawRecords: ConcurrentHashMap<ConnectionData, Long>
        get() = connectionDataRecords

    fun clearDnsQueryRawRecords() {
        executor.get().submit("ServiceVPN clearDnsQueryRawRecords") {
            try {
                lock.writeLock().lockInterruptibly()

                if (!connectionDataRecords.isEmpty()) {
                    connectionDataRecords.clear()
                }

            } catch (e: Exception) {
                loge("ServiceVPN clearDnsQueryRawRecords", e)
            } finally {
                if (lock.isWriteLockedByCurrentThread) {
                    lock.writeLock().unlock()
                }
            }
        }
    }

    fun addUIDtoDNSQueryRawRecords(
        uid: Int,
        destinationAddress: String?,
        destinationPort: Int,
        sourceAddress: String?,
        allowed: Boolean,
        protocol: Int
    ) {

        if (!vpnPreferences!!.connectionLogsEnabled || reloading) {
            return
        }

        try {

            if (uid != 0 || destinationPort != Constants.PLAINTEXT_DNS_PORT) {

                val packetRecord = PacketRecord(
                    System.currentTimeMillis(),
                    uid,
                    sourceAddress!!,
                    destinationAddress!!,
                    destinationPort,
                    protocol,
                    allowed
                )

                //Remove entry to update key time
                connectionDataRecords.remove(packetRecord)
                connectionDataRecords.put(packetRecord, SystemClock.elapsedRealtimeNanos())

                if (connectionDataRecords.size > LINES_IN_DNS_QUERY_RAW_RECORDS) {
                    freeSpaceInConnectionRecords()
                }
            }

        } catch (e: Exception) {
            loge("ServiceVPN addUIDtoDNSQueryRawRecords", e)
        }

    }

    override fun onLowMemory() {
        clearDnsQueryRawRecords()
        dnsRebindHosts.clear()
        loge("ServiceVPN low memory")
    }

    override fun onTaskRemoved(rootIntent: Intent?) {

        loge("VPN service task removed " + this.hashCode())

        val vpnEnabled = defaultPreferences.get().getBoolean(TortaeKeys.VPN_SERVICE_ENABLED, false)
        if (vpnEnabled) {
            val starterIntent = Intent(this, BootCompleteReceiver::class.java)
            starterIntent.setAction(BootCompleteManager.ALWAYS_ON_VPN)
            sendBroadcast(starterIntent)
        }

        super.onTaskRemoved(rootIntent)
    }

    inner class BuilderVPN : Builder() {
        private var networkInfo: NetworkInfo? = null
        private var mtu = 0
        private val listAddress: MutableList<String> = ArrayList()
        private val listRoute: MutableList<String> = ArrayList()
        private val listDns: MutableList<java.net.InetAddress> = ArrayList()
        private val listDisallowed: MutableList<String> = ArrayList()
        private val listAllowed: MutableList<String> = ArrayList()
        private var performAllowedOrDisallowed = ""
        private var fixTTL = false

        init {
            val cm = this@ServiceVPN.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager?
            if (cm != null) {
                networkInfo = cm.activeNetworkInfo
            }
        }

        override fun setMtu(mtu: Int): VpnService.Builder {
            this.mtu = mtu
            super.setMtu(mtu)
            return this
        }

        override fun addAddress(address: String, prefixLength: Int): BuilderVPN {
            listAddress.add(address + "/" + prefixLength)
            super.addAddress(address, prefixLength)
            return this
        }

        override fun addRoute(address: String, prefixLength: Int): BuilderVPN {
            listRoute.add(address + "/" + prefixLength)
            super.addRoute(address, prefixLength)
            return this
        }

        override fun addRoute(address: java.net.InetAddress, prefixLength: Int): BuilderVPN {
            listRoute.add(address.hostAddress + "/" + prefixLength)
            super.addRoute(address, prefixLength)
            return this
        }

        override fun addDnsServer(address: java.net.InetAddress): BuilderVPN {
            listDns.add(address)
            super.addDnsServer(address)
            return this
        }

        @Throws(android.content.pm.PackageManager.NameNotFoundException::class)
        override fun addDisallowedApplication(packageName: String): BuilderVPN {
            listDisallowed.add(packageName)
            performAllowedOrDisallowed = "disallowed"
            super.addDisallowedApplication(packageName)
            return this
        }

        @Throws(android.content.pm.PackageManager.NameNotFoundException::class)
        override fun addAllowedApplication(packageName: String): VpnService.Builder {
            listAllowed.add(packageName)
            performAllowedOrDisallowed = "allowed"
            super.addAllowedApplication(packageName)
            return this
        }

        fun setFixTTL(fixTTL: Boolean) {
            this.fixTTL = fixTTL
        }

        override fun equals(other: Any?): Boolean {

            if (other == null) {
                return false
            }

            if (this.javaClass != other.javaClass) {
                return false
            }

            val other = other as BuilderVPN

            if (this.networkInfo == null || other.networkInfo == null ||
                this.networkInfo!!.type != other.networkInfo!!.type) {
                return false
            }

            if (this.mtu != other.mtu) {
                return false
            }

            if (this.performAllowedOrDisallowed != other.performAllowedOrDisallowed) {
                return false
            }

            if (this.fixTTL != other.fixTTL) {
                return false
            }

            if (this.listAddress.size != other.listAddress.size) {
                return false
            }

            if (this.listRoute.size != other.listRoute.size) {
                return false
            }

            if (this.listDns.size != other.listDns.size) {
                return false
            }

            if (this.listDisallowed.size != other.listDisallowed.size) {
                return false
            }

            if (this.listAllowed.size != other.listAllowed.size) {
                return false
            }

            for (address in this.listAddress) {
                if (!other.listAddress.contains(address)) {
                    return false
                }
            }

            for (route in this.listRoute) {
                if (!other.listRoute.contains(route)) {
                    return false
                }
            }

            for (dns in this.listDns) {
                if (!other.listDns.contains(dns)) {
                    return false
                }
            }

            for (pkg in this.listDisallowed) {
                if (!other.listDisallowed.contains(pkg)) {
                    return false
                }
            }

            for (pkg in this.listAllowed) {
                if (!other.listAllowed.contains(pkg)) {
                    return false
                }
            }

            return true
        }

        override fun hashCode(): Int {
            return Objects.hash(networkInfo, mtu, listAddress, listRoute, listDns, listDisallowed, listAllowed, performAllowedOrDisallowed, fixTTL)
        }
    }

    companion object {
        const val LINES_IN_DNS_QUERY_RAW_RECORDS = 512
        private const val CHECK_TOR_CONNECTION_DELAY_SEC = 300

        const val EXTRA_COMMAND = "Command"
        const val EXTRA_REASON = "Reason"
    }
}
