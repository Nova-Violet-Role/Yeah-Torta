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

import android.content.Context.CONNECTIVITY_SERVICE
import android.content.Intent
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Message
import android.os.ParcelFileDescriptor
import android.widget.Toast
import androidx.annotation.RequiresApi
import dagger.Lazy
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.arp.ArpScanner
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.connection_checker.ConnectionCheckerInteractor
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.iptables.ModulesIptablesRules
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesAux
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesService
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.NetworkChecker
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RUNNING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.ROOT_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.enums.VPNCommand
import pillar.kuma_saimono.libumdnscrypt.utils.enums.VPNCommand.STOP
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.APPS_ALLOW_GSM_PREF
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.APPS_ALLOW_ROAMING
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.APPS_ALLOW_WIFI_PREF
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ARP_SPOOFING_DETECTION
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FAST_NETWORK_SWITCHING
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FIREWALL_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.VPN_SERVICE_ENABLED
import pillar.kuma_saimono.libumdnscrypt.vpn.Rule
import java.io.IOException
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList
import javax.inject.Inject
import javax.inject.Named

class ServiceVPNHandler private constructor(
    looper: Looper,
    private val serviceVPN: ServiceVPN?
) : Handler(looper) {

    @Inject
    lateinit var preferenceRepository: Lazy<PreferenceRepository>
    @Inject
    @field:Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    lateinit var defaultSharedPreferences: Lazy<SharedPreferences>
    @Inject
    lateinit var pathVars: Lazy<PathVars>
    @Inject
    lateinit var vpnBuilder: Lazy<VpnBuilder>
    @Inject
    lateinit var handler: Lazy<Handler>

    private val listRule: MutableList<Rule> = CopyOnWriteArrayList()
    private var last_builder: VpnService.Builder? = null

    init {
        App.instance.daggerComponent.inject(this)
    }

    fun queue(intent: Intent) {
        val cmd = intent.getSerializableExtra(ServiceVPN.EXTRA_COMMAND) as VPNCommand?
        val msg = obtainMessage()
        msg.obj = intent
        if (cmd != null) {
            msg.what = cmd.ordinal
            removeMessages(msg.what)
            if (cmd != STOP) {
                removeMessages(STOP.ordinal)
                sendMessage(msg)
            } else {
                sendMessageDelayed(msg, 3000L)
            }
        }
    }

    override fun handleMessage(msg: Message) {
        try {
            handleIntent(msg.obj as Intent)
        } catch (ex: Throwable) {
            loge("ServiceVPNHandler handleMessage", ex, true)
        }
    }

    private fun handleIntent(intent: Intent) {

        if (serviceVPN == null) {
            return
        }

        val prefs = defaultSharedPreferences.get()

        val cmd = intent.getSerializableExtra(ServiceVPN.EXTRA_COMMAND) as VPNCommand?
        val reason = intent.getStringExtra(ServiceVPN.EXTRA_REASON)

        logi("VPN Handler Executing intent=" + intent + " command=" + cmd + " reason=" + reason +
                " vpn=" + (serviceVPN.vpn != null) + " user=" + (pathVars.get().appUid / 100000))

        try {
            if (cmd != null) {
                when (cmd) {
                    VPNCommand.START -> start()
                    VPNCommand.RELOAD -> reload()
                    // ★ FIXED 2026-07-31 — the symmetric partner of the true-write in start().
                    // Setting the flag true on a successful establish made stop() REACHABLE (it is
                    // guarded by the flag at ServiceVPNHelper.kt:103-109), but the tunnel still did
                    // not come down: `VPN Stop native (Rust tunnel)` and `VPN Handler Stopping` both
                    // ran, and tun0 survived 8 polls. The reason is :144-148 below — stopServiceVPN()
                    // fires only when the flag is FALSE, and nothing on the STOP path cleared it. The
                    // one false-write at :172 sits on an EXCEPTION branch, so an ordinary, successful
                    // stop never reached it.
                    //
                    // So the flag has to be cleared by the STOP command itself. Doing it here, before
                    // stop(), rather than inside stop(): the check at :144 runs in this same
                    // handleIntent pass, so the value must already be false by the time control
                    // reaches it.
                    VPNCommand.STOP -> {
                        defaultSharedPreferences.get().edit()
                            .putBoolean(VPN_SERVICE_ENABLED, false).apply()
                        stop()
                    }
                    else -> loge("VPN Handler Unknown command=" + cmd)
                }
            }

            // Stop service if needed
            if (!hasMessages(VPNCommand.START.ordinal) &&
                !hasMessages(VPNCommand.RELOAD.ordinal) &&
                !prefs.getBoolean(VPN_SERVICE_ENABLED, false)
            )
                stopServiceVPN()

            // Request garbage collection
            System.gc()
        } catch (ex: Throwable) {
            loge("ServiceVPNHandler handleIntent", ex, true)

            serviceVPN.reloading = false

            if (cmd == VPNCommand.START || cmd == VPNCommand.RELOAD) {
                if (VpnService.prepare(serviceVPN) == null) {
                    logw("VPN Handler prepared connected=" + serviceVPN.isNetworkAvailable)
                    if (serviceVPN.isNetworkAvailable && ex !is StartFailedException) {
                        serviceVPN.handler.get().post {
                            Toast.makeText(serviceVPN, uniffi.torta_core.tortaText("vpn_mode_error"), Toast.LENGTH_SHORT).show()
                        }
                    }
                    // Retried on connectivity change
                } else {
                    serviceVPN.handler.get().post {
                        Toast.makeText(serviceVPN, uniffi.torta_core.tortaText("vpn_mode_error"), Toast.LENGTH_SHORT).show()
                    }
                    // Disable firewall
                    if (ex !is StartFailedException) {
                        prefs.edit().putBoolean(VPN_SERVICE_ENABLED, false).apply()
                    }
                }
            }
        }
    }

    private fun start() {

        if (serviceVPN == null) {
            return
        }

        if (serviceVPN.vpn == null) {

            listRule.clear()
            listRule.addAll(Rule.getRules(serviceVPN))
            val listAllowed = getAllowedRules()

            last_builder = vpnBuilder.get().getBuilder(serviceVPN, listAllowed, listRule)
            serviceVPN.vpn = startVPN(last_builder!!)

            if (serviceVPN.vpn == null) {
                throw StartFailedException("VPN Handler Start VPN Service Failed")
            }

            // ★ FIXED 2026-07-31 — THE TUNNEL COULD BE RAISED BUT NOT LOWERED.
            // We are past the null check, so the interface is ESTABLISHED. VPN_SERVICE_ENABLED was
            // never set here; its only writer was ModulesReceiver.startVPNService()
            // (ModulesReceiver.kt:1071-1077), a narrow revoke-recovery path. On the ordinary start
            // path the flag therefore stayed FALSE while tun0 was UP — measured on the x86_64 AVD:
            //     ip -o addr    -> tun0 inet 10.1.10.1/32, VPN agent InterfaceName: tun0
            //     shared_prefs  -> VPNServiceEnabled" value="false"
            // and ServiceVPNHelper.stopVpnService() is guarded by exactly that flag
            // (ServiceVPNHelper.kt:103-109), so every stop() was a SILENT NO-OP: it returns normally
            // having sent nothing. Measured: DISARM left the tunnel up across 5 polls, with
            // always_on_vpn_app cleared first so the system's own always-on restart could not be
            // mistaken for the app ignoring the request.
            //
            // The asymmetry fails in the dangerous direction — a VPN that cannot be turned off. The
            // flag must describe REALITY (an interface exists) rather than one code path's opinion,
            // so it is set at the only place that knows the establish succeeded. The false-write at
            // :172 is its symmetric partner and stays.
            defaultSharedPreferences.get().edit()
                .putBoolean(VPN_SERVICE_ENABLED, true).apply()

            serviceVPN.startNative(serviceVPN.vpn!!, listAllowed)

            val modulesStatus = ModulesStatus.getInstance()
            if (modulesStatus.mode == OperationMode.VPN_MODE
                && serviceVPN.vpnPreferences!!.firewallEnabled
            ) {
                modulesStatus.setFirewallState(RUNNING, preferenceRepository.get())
            } else {
                modulesStatus.setFirewallState(STOPPED, preferenceRepository.get())
            }
        }
    }

    private fun reload() {

        if (serviceVPN == null) {
            return
        }

        serviceVPN.reloading = true

        // ★ STAGE 2: when true, the same-builder connectivity reload leaves the live Rust tunnel loop
        // running (no stopNative/startNative) — see the "Native restart — SKIPPED" branch below.
        var skipNativeRestart = false

        val modulesStatus = ModulesStatus.getInstance()
        val fixTTL = modulesStatus.isFixTTL && (modulesStatus.mode == ROOT_MODE)
                && !modulesStatus.isUseModulesWithRoot

        var oldVpnInterfaceName = ""
        if (fixTTL) {
            oldVpnInterfaceName = ModulesIptablesRules.blockTethering(serviceVPN, pathVars.get())
        }

        listRule.clear()
        listRule.addAll(Rule.getRules(serviceVPN))
        val listAllowed = getAllowedRules()

        val builder: VpnService.Builder = vpnBuilder.get().getBuilder(serviceVPN, listAllowed, listRule)

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) {
            last_builder = builder
            logi("VPN Handler Legacy restart")

            if (serviceVPN.vpn != null) {
                serviceVPN.stopNative()
                stopVPN(serviceVPN.vpn!!)
                serviceVPN.vpn = null
                try {
                    Thread.sleep(500L)
                } catch (ignored: InterruptedException) {
                }
            }
            serviceVPN.vpn = startVPN(last_builder!!)

        } else {
            if (serviceVPN.vpn != null && builder == last_builder) {
                // ★ STAGE 2 (2026-07-04): the VPN config is UNCHANGED (same builder) — this is the
                // connectivity-confirm reload (ServiceVPN.onConnectionChecked → "Internet is available").
                // In the pure-Rust world the tunnel::TunnelController loop keeps SERVING across a
                // connectivity change (it reads connectivity itself; the resolver::resolve singleton is
                // unchanged). The legacy stopNative→startNative here KILLED the live Rust loop 0.6s after
                // it started serving (measured: RX 4/TX 10 then dead), so a query never completed. SKIP
                // the redundant tunnel restart: just refresh the underlying network and leave the loop
                // running. (topology change → the else branch below still does a full handover.)
                logi("VPN Handler Native restart — SKIPPED (pure-Rust loop persists across same-builder reload)")
                skipNativeRestart = true

                // Set underlying network
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    setUnderlyingNetwork()
                }

            } else {
                last_builder = builder

                val prefs = defaultSharedPreferences.get()
                val handover = prefs.getBoolean("VPN handover", true)
                logi("VPN Handler restart handover=" + handover)

                if (handover) {
                    // Attempt seamless handover
                    var prev: ParcelFileDescriptor? = serviceVPN.vpn
                    serviceVPN.vpn = startVPN(builder)

                    if (prev != null && serviceVPN.vpn == null) {
                        logw("VPN Handler Handover failed")
                        serviceVPN.stopNative()
                        stopVPN(prev)
                        prev = null
                        try {
                            Thread.sleep(3000L)
                        } catch (ignored: InterruptedException) {
                        }
                        serviceVPN.vpn = startVPN(last_builder!!)
                        if (serviceVPN.vpn == null)
                            throw IllegalStateException("VPN Handler Handover failed")
                    }

                    if (prev != null) {
                        serviceVPN.stopNative()
                        stopVPN(prev)
                    }
                } else {
                    if (serviceVPN.vpn != null) {
                        serviceVPN.stopNative()
                        stopVPN(serviceVPN.vpn!!)
                    }

                    serviceVPN.vpn = startVPN(builder)
                }
            }
        }

        if (serviceVPN.vpn == null)
            throw StartFailedException("VPN Handler Start VPN Service Failed")

        // ★ STAGE 2: skip re-spawning the Rust tunnel loop on a same-builder connectivity reload — the
        // loop is still running and serving (we never stopped it). A fresh start would kill+respawn it.
        if (!skipNativeRestart) {
            serviceVPN.startNative(serviceVPN.vpn!!, listAllowed)
        } else {
            logi("VPN Handler startNative — SKIPPED (Rust tunnel loop already serving; same-builder reload)")
        }

        if (fixTTL) {
            val finalOldVpnInterfaceName = oldVpnInterfaceName
            postDelayed({
                modulesStatus.setFixTTLRulesUpdateRequested(serviceVPN, true)
                ModulesIptablesRules.allowTethering(serviceVPN, pathVars.get(), finalOldVpnInterfaceName)
            }, 1000L)
        }

        serviceVPN.reloading = false

        if (modulesStatus.mode == OperationMode.VPN_MODE) {
            if (modulesStatus.firewallState == STARTING) {
                modulesStatus.setFirewallState(RUNNING, preferenceRepository.get())
            } else if (modulesStatus.firewallState == STOPPING) {
                modulesStatus.setFirewallState(STOPPED, preferenceRepository.get())
            }
        } else {
            modulesStatus.setFirewallState(STOPPED, preferenceRepository.get())
        }

        if (defaultSharedPreferences.get().getBoolean(ARP_SPOOFING_DETECTION, false)) {
            try {
                ArpScanner.getArpComponent().get().reset(
                    serviceVPN.isNetworkAvailable || serviceVPN.isInternetAvailable
                )
            } catch (e: Exception) {
                loge("ServiceVPNHandler Arp Scanner reset exception", e)
            }
        }
    }

    private fun stop() {

        //This prevents the ModulesService from sending a stop signal when the service is already stopping
        handler.get().post {
            defaultSharedPreferences.get()
                .edit()
                .putBoolean(VPN_SERVICE_ENABLED, false)
                .commit()
        }

        if (serviceVPN != null && serviceVPN.vpn != null) {
            // ★ TUN-LEAK — the retraction must be UNCONDITIONAL.
            //
            // MEASURED on the AVD: tun0 AND tun1 both existed, dumpsys named tun1 live, and the
            // DEAD tun0 still held the whole default-route split (0.0.0.0/1, 128.0.0.0/2, ::/1).
            // A dead tun that owns a default route is a black hole: traffic is routed into an
            // interface no process services. It also made every byte-counter reading a lie -- 0/0
            // read as "no traffic flows" when it meant "this interface is abandoned".
            //
            // The old shape leaked by construction: `serviceVPN.vpn = null` sat AFTER two calls
            // that can throw, so one failure in stopNative() or stopVPN() left the previous claim
            // still referenced -- and the next start added a second one on top of it.
            //
            // PROVED for ANY number of engine cycles in
            // D:/Lean/proofs/Proofs/TunLeakInvariant.lean (504ccac):
            //   leaky_grows_with_every_cycle / leaky_violates_the_invariant -- the old shape breaks
            //     the invariant from the SECOND cycle, so one reconnect is enough;
            //   leaky_is_unbounded -- a long session diverges from safety rather than settling;
            //   tight_satisfies_the_invariant / tight_holds_exactly_one_after_any_cycle -- with the
            //     claim retracted first, exactly one interface is ever default-routed;
            //   retracting_the_route_removes_the_black_hole -- teardown must NOT depend on a
            //     process that may already have died, which is why this is a `finally`.
            // M78 (the fix leaks too) = 6 kills, M79 = 6.
            try {
                serviceVPN.stopNative()
                stopVPN(serviceVPN.vpn!!)
                serviceVPN.vpnRulesHolder.get().unPrepare()
                listRule.clear()
            } catch (e: Exception) {
                loge("ServiceVPNHandler stop()", e)
            } finally {
                // Dropped whatever happened above. A reference we keep after a failed teardown is
                // the leak: the next establish() would stack a second default-routed tun on it.
                serviceVPN.vpn = null
            }
        }

        stopServiceVPN()
    }

    private fun getAllowedRules(): List<String> {
        val listAllowed: MutableList<String> = ArrayList()

        if (serviceVPN == null) {
            return listAllowed
        }

        //Update connected state
        val interactor = serviceVPN.connectionCheckerInteractor.get()
        interactor.checkNetworkConnection()

        //Request disconnected state confirmation in case of Always on VPN is enabled
        if (!serviceVPN.isInternetAvailable) {
            interactor.checkInternetConnection()
        }

        //if (serviceVPN.isNetworkAvailable() || serviceVPN.isInternetAvailable()) {

        val preferences = preferenceRepository.get()

        if (!preferences.getBoolPreference(FIREWALL_ENABLED)
            || ModulesStatus.getInstance().mode == ROOT_MODE
        ) {
            for (rule in listRule) {
                listAllowed.add(rule.uid.toString())
            }
        } else if (NetworkChecker.isWifiActive(serviceVPN) || NetworkChecker.isEthernetActive(serviceVPN)) {
            listAllowed.addAll(preferences.getStringSetPreference(APPS_ALLOW_WIFI_PREF))
        } else if (NetworkChecker.isRoaming(serviceVPN)) {
            listAllowed.addAll(preferences.getStringSetPreference(APPS_ALLOW_ROAMING))
        } else if (NetworkChecker.isCellularActive(serviceVPN)) {
            listAllowed.addAll(preferences.getStringSetPreference(APPS_ALLOW_GSM_PREF))
        }
        //}

        logi("VPN Handler Allowed " + listAllowed.size + " of " + listRule.size)
        return listAllowed
    }

    private fun startVPN(builder: VpnService.Builder): ParcelFileDescriptor? {
        try {
            val pfd = builder.establish()

            // Set underlying network
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                setUnderlyingNetwork()
            }

            return pfd
        } catch (ex: SecurityException) {
            throw ex
        } catch (ex: Throwable) {
            loge("ServiceVPNHandler startVPN", ex, true)
            return null
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun setUnderlyingNetwork() {

        if (serviceVPN == null) {
            return
        }

        val cm = serviceVPN.getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        val networks = NetworkChecker.getAvailableNetworksSorted(serviceVPN)
        if (networks.size > 1
            && defaultSharedPreferences.get().getBoolean(FAST_NETWORK_SWITCHING, true)
            && !(Build.VERSION.SDK_INT >= 36 && Build.BRAND.lowercase(Locale.ROOT) == "google")
        ) {
            serviceVPN.setUnderlyingNetworks(networks)
            for (network in networks) {
                logi("VPN Handler Setting underlying network=" + cm.getNetworkInfo(network))
            }
        }/* else if (!serviceVPN.isNetworkAvailable() && !serviceVPN.isInternetAvailable()) {
            Unfortunately, this code causes the Telegram messenger always connecting.
            logi("VPN Handler Setting underlying network=empty");
            serviceVPN.setUnderlyingNetworks(new Network[]{});
        }*/ else {
            logi("VPN Handler Setting underlying network=default")
            serviceVPN.setUnderlyingNetworks(null)
        }
    }

    fun stopVPN(pfd: ParcelFileDescriptor) {
        logi("VPN Handler Stopping")
        try {
            pfd.close()
        } catch (ex: IOException) {
            loge("ServiceVPNHandler stopVPN", ex, true)
        } catch (ex: RuntimeException) {
            // Catching only IOException let a RuntimeException escape and abort the caller's
            // teardown mid-way, which is one of the ways the tun survived its own stop(). Closing
            // the descriptor is the RETRACTION -- it must never be skipped because of the kind of
            // exception it raised. See TunLeakInvariant.retracting_the_route_removes_the_black_hole.
            loge("ServiceVPNHandler stopVPN (non-IO)", ex, true)
        }
    }

    private fun stopServiceVPN() {

        if (serviceVPN == null) {
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && serviceVPN.notificationManager != null) {
            try {
                serviceVPN.notificationManager!!.cancel(ModulesService.DEFAULT_NOTIFICATION_ID)
                serviceVPN.stopForeground(true)
            } catch (e: Exception) {
                loge("ServiceVPNHandler stopServiceVPN", e)
            }
        }

        defaultSharedPreferences.get().edit().putBoolean(VPN_SERVICE_ENABLED, false).apply()

        serviceVPN.stopSelf()

        val modulesStatus = ModulesStatus.getInstance()
        if (modulesStatus.mode == OperationMode.VPN_MODE
            || modulesStatus.mode == OperationMode.PROXY_MODE
        ) {
            modulesStatus.setFirewallState(STOPPED, preferenceRepository.get())
        }
        val dnsCryptState = modulesStatus.dnsCryptState

        //If modules are running start ModulesService Foreground, which is background because of serviceVPN.stopSelf() with same notification id
        if (dnsCryptState != STOPPED) {
            ModulesAux.requestModulesStatusUpdate(serviceVPN)
        }
    }

    private class StartFailedException(msg: String) : IllegalStateException(msg)

    fun getAppsList(): List<Rule> {
        return listRule
    }

    companion object {

        @JvmStatic
        fun getInstance(looper: Looper, serviceVPN: ServiceVPN?): ServiceVPNHandler {
            return ServiceVPNHandler(looper, serviceVPN)
        }
    }
}
