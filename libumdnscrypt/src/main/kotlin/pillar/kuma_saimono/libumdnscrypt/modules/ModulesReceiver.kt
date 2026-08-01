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
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.IntentCompat
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.PowerManager
import android.text.TextUtils

import java.io.Serializable
import java.net.InetAddress
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeUnit
import java.util.regex.Matcher
import java.util.regex.Pattern

import javax.inject.Inject
import javax.inject.Named
import javax.inject.Provider

import dagger.Lazy
import kotlinx.coroutines.Job
import pillar.kuma_saimono.libumdnscrypt.arp.ArpScanner
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.connection_checker.ConnectionCheckerInteractor
import pillar.kuma_saimono.libumdnscrypt.domain.connection_checker.OnInternetConnectionCheckedListener
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants
import pillar.kuma_saimono.libumdnscrypt.utils.ap.InternetSharingChecker
import pillar.kuma_saimono.libumdnscrypt.utils.apps.InstalledAppNamesStorage
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.NetworkChecker
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.executors.CoroutineExecutor
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileManager
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.utils.privatedns.PrivateDnsProxyManager
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper.reload

import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.NetworkChecker.getActiveNetworkHash
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.NetworkChecker.isActiveNetwork
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.NetworkChecker.isVpnNetwork
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.NetworkChecker.networkToId
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.UNKNOWN_NETWORK_HASH
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RUNNING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.PROXY_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.ROOT_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.UNDEFINED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.VPN_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ARP_SPOOFING_DETECTION
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_BLOCK_IPv6
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_DNS64
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_DNS64_PREFIX
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FIREWALL_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.GSM_ON_REQUESTED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.KILL_SWITCH
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PREVENT_DNS_LEAKS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.REFRESH_RULES
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.VPN_SERVICE_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.WIFI_ACCESS_POINT_IS_ON
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.WIFI_ON_REQUESTED
import pillar.kuma_saimono.libumdnscrypt.utils.stringListExtraCompat

class ModulesReceiver @Inject constructor(
        private val preferenceRepository: Lazy<PreferenceRepository>,
        @Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
        private val defaultPreferences: Lazy<SharedPreferences>,
        private val connectionCheckerInteractor: Lazy<ConnectionCheckerInteractor>,
        private val internetSharingChecker: Provider<InternetSharingChecker>,
        private val executor: CoroutineExecutor,
        private val handler: Lazy<Handler>,
        private val installedAppNamesStorage: Lazy<InstalledAppNamesStorage>,
        private val pathVars: Lazy<PathVars>
) : BroadcastReceiver(), OnInternetConnectionCheckedListener {

    private var context: Context? = null
    @Volatile
    private var commonNetworkCallback: Any? = null

    /**
     * The VPN-transport NetworkCallback, non-null only while the API 23+ path is registered.
     * Typed as Any? for the same reason [commonNetworkCallback] is: the class it refers to did not
     * exist at this module minSdk, so naming it in a field type is not portable.
     */
    private var vpnNetworkCallback: Any? = null
    @Volatile
    private var vpnConnectivityReceiver: BroadcastReceiver? = null
    private val modulesStatus = ModulesStatus.getInstance()
    @Volatile
    private var savedOperationMode: OperationMode? = UNDEFINED
    @Volatile
    private var commonReceiversRegistered = false
    @Volatile
    private var rootReceiversRegistered = false
    @Volatile
    private var rootVpnReceiverRegistered = false
    @Volatile
    private var lock = false
    @Volatile
    private var checkTetheringTask: Job? = null
    @Volatile
    private var vpnRevoked = false

    override fun onReceive(context: Context?, intent: Intent?) {

        if (intent == null) {
            return
        }

        val action = intent.action

        if (action == null) {
            return
        }

        val extras = intent.extras
        if (!action.equals(SCREEN_ON_ACTION, ignoreCase = true)
                && !action.equals(SCREEN_OFF_ACTION, ignoreCase = true)) {
            if (extras != null) {
                logi("ModulesReceiver received " + intent
                        + (if (extras.isEmpty) "" else " " + extras))
            } else {
                logi("ModulesReceiver received " + intent)
            }
        }

        if (this.context == null) {
            logw("ModulesReceiver context is null")
            return
        }

        val pendingResult = goAsync()

        executor.submit("ModulesReceiver onReceive") {
            try {
                intentOnReceive(intent, action)
            } catch (e: Exception) {
                loge("ModulesReceiver onReceive", e, true)
            } finally {
                if (pendingResult != null) {
                    pendingResult.finish()
                }
            }
        }


    }

    private fun intentOnReceive(intent: Intent, action: String) {

        val mode = modulesStatus.mode
        if (savedOperationMode != mode) {
            savedOperationMode = mode

            unregisterReceivers()

            registerReceivers(context!!)
        }

        if (action.equals(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED, ignoreCase = true)) {
            idleStateChanged()
        } else if (action.equals(LEGACY_CONNECTIVITY_ACTION, ignoreCase = true)) {
            connectivityStateChanged(intent)
        } else if (action.equals(Intent.ACTION_PACKAGE_ADDED, ignoreCase = true)
                || action.equals(Intent.ACTION_PACKAGE_REMOVED, ignoreCase = true)) {
            packageChanged(intent)
        } else if (action.equals(SCREEN_ON_ACTION, ignoreCase = true)
                || action.equals(SCREEN_OFF_ACTION, ignoreCase = true)) {
            interactiveStateChanged(intent)
        } else if (isRootMode() && (action.equals(AP_STATE_FILTER_ACTION, ignoreCase = true)
                || action.equals(TETHER_STATE_FILTER_ACTION, ignoreCase = true))) {
            checkInternetSharingState(intent)
        } else if (isRootMode() && (action.equals(POWER_OFF_FILTER_ACTION, ignoreCase = true)
                || action.equals(SHUTDOWN_FILTER_ACTION, ignoreCase = true)
                || action.equals(REBOOT_FILTER_ACTION, ignoreCase = true))) {
            powerOFFDetected()
        } else if (isVpnMode() && action == VPN_REVOKE_ACTION) {
            vpnRevoked(intent.getBooleanExtra(VPN_REVOKED_EXTRA, false))
        }
    }

    fun registerReceivers(context: Context) {

        if (this.context == null) {
            this.context = context
        }

        savedOperationMode = modulesStatus.mode

        if (!commonReceiversRegistered) {
            registerIdleStateChanged()
            registerConnectivityChanges()
            registerPackageChanged()
            registerInteractiveStateReceiver()
            registerVpnRevokeReceiver()
        }

        if (isRootMode() && !rootReceiversRegistered) {
            registerAPisOn()
            registerUSBModemIsOn()
            registerPowerOFF()
        }

        if (isRootMode() && !modulesStatus.isUseModulesWithRoot) {
            if (rootVpnReceiverRegistered && modulesStatus.isFixTTL) {
                unlistenVpnConnectivityChanges()
                rootVpnReceiverRegistered = false
            } else if (!rootVpnReceiverRegistered && !modulesStatus.isFixTTL) {
                listenVpnConnectivityChanges()
                rootVpnReceiverRegistered = true
            }
        } else if (rootVpnReceiverRegistered) {
            unlistenVpnConnectivityChanges()
            rootVpnReceiverRegistered = false
        }

    }

    fun unregisterReceivers() {

        if (context == null) {
            return
        }

        if (commonReceiversRegistered) {
            try {
                context!!.unregisterReceiver(this)
            } catch (e: Exception) {
                logw("ModulesReceiver unregisterReceivers", e)
            }
            commonReceiversRegistered = false
            rootReceiversRegistered = false
        }

        if (commonNetworkCallback != null) {
            unlistenNetworkChanges()
            commonNetworkCallback = null
        }

        // Either registration counts. Checking only the receiver LEAKED the NetworkCallback on
        // every device from API 23 up, because that path never sets vpnConnectivityReceiver.
        if (vpnConnectivityReceiver != null || vpnNetworkCallback != null) {
            unlistenVpnConnectivityChanges()
            vpnRevoked = false
        }
    }

    private fun registerIdleStateChanged() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val ifIdle = IntentFilter()
            ifIdle.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
            context!!.registerReceiver(this, ifIdle)
            commonReceiversRegistered = true
        }
    }

    private fun registerConnectivityChanges() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                listenNetworkChanges()
            } catch (e: Exception) {
                logw("ModulesReceiver registerConnectivityChanges", e)
                listenConnectivityChanges()
            }
        } else {
            listenConnectivityChanges()
        }
    }

    private fun registerAPisOn() {
        val apStateChanged = IntentFilter()
        apStateChanged.addAction(AP_STATE_FILTER_ACTION)
        context!!.registerReceiver(this, apStateChanged)
        rootReceiversRegistered = true
    }

    private fun registerUSBModemIsOn() {
        val apStateChanged = IntentFilter()
        apStateChanged.addAction(TETHER_STATE_FILTER_ACTION)
        context!!.registerReceiver(this, apStateChanged)
        rootReceiversRegistered = true
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    private fun registerPowerOFF() {
        val powerOFF = IntentFilter()
        powerOFF.addAction(SHUTDOWN_FILTER_ACTION)
        powerOFF.addAction(POWER_OFF_FILTER_ACTION)
        powerOFF.addAction(REBOOT_FILTER_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context!!.registerReceiver(this, powerOFF, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context!!.registerReceiver(this, powerOFF)
        }
        rootReceiversRegistered = true
    }

    private fun registerPackageChanged() {
        val ifPackage = IntentFilter()
        ifPackage.addAction(Intent.ACTION_PACKAGE_ADDED)
        ifPackage.addAction(Intent.ACTION_PACKAGE_REMOVED)
        ifPackage.addDataScheme("package")
        context!!.registerReceiver(this, ifPackage)
        commonReceiversRegistered = true
    }

    private fun listenNetworkChanges() {

        logi("ModulesReceiver start listening to network changes")

        val cm = context!!.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager?
        val builder = NetworkRequest.Builder()
        builder.addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
                .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)

        if (isVpnMode()) {
            builder.removeTransportType(NetworkCapabilities.TRANSPORT_VPN)
        } else {
            builder.addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                    .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            builder.removeCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }

        val nc: ConnectivityManager.NetworkCallback = object : ConnectivityManager.NetworkCallback() {
            @Volatile
            private var connected: Boolean? = null
            private val validated: MutableSet<Int> = HashSet()
            private val networkToDns: MutableMap<Int, List<InetAddress>> = HashMap()
            private val networkToNat64: MutableMap<Int, String> = HashMap()
            @Volatile
            private var dnsChanged = false
            @Volatile
            private var activeNetwork = 0
            private val networks: MutableSet<Int> = HashSet()
            @Volatile
            private var restartLocked = false

            override fun onAvailable(network: Network) {

                val lastConnected = connected

                if (isVpnNetwork(cm, network)) {
                    logi("ModulesReceiver available VPN network=" + network + " connected=" + lastConnected)
                    return
                } else {
                    logi("ModulesReceiver available network=" + network + " connected=" + lastConnected)
                }

                val lastActiveNetwork = activeNetwork
                if (networks.isEmpty()
                        || !networks.contains(lastActiveNetwork)
                        || isActiveNetwork(cm, network)
                        || networkToId(cm, network) < activeNetwork) {
                    activeNetwork = networkToId(cm, network)
                }

                if (lastActiveNetwork != activeNetwork) {
                    manageNat64AndDns(
                            networkToNat64[activeNetwork],
                            networkToDns[activeNetwork],
                            networkToDns[lastActiveNetwork]
                    )
                }

                setNetworkAvailable(true)

                if (lastConnected == null || !lastConnected) {
                    if (isVpnMode() || isRootMode()) {
                        setInternetAvailable(true)
                    }
                }

                connected = true

                if (isVpnMode() && !vpnRevoked) {
                    reload("Network available", context!!)
                } else if (isRootMode()) {
                    updateIptablesRules(false)
                    resetArpScanner(true)
                } else if (isProxyMode() || vpnRevoked) {
                    resetArpScanner(true)
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && !networks.contains(networkToId(cm, network))) {
                    PrivateDnsProxyManager.checkPrivateDNSAndProxy(
                            context!!, null, isPreventDnsLeaks()
                    )
                }

                networks.add(networkToId(cm, network))
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {

                logi("ModulesReceiver changed link properties=" + linkProperties)

                if (isVpnNetwork(cm, network)) {
                    return
                }

                if (networks.isEmpty() || isActiveNetwork(cm, network)) {
                    activeNetwork = networkToId(cm, network)
                    connected = true
                }

                setNetworkAvailable(true)

                // Make sure the right DNS servers are being used
                val dns = linkProperties.dnsServers

                var nat64 = ""
                if (isRootMode() || isDNSCryptBlockIPv6()) {
                    nat64 = ""
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
                        && linkProperties.nat64Prefix != null) {
                    nat64 = linkProperties.nat64Prefix.toString()
                } else if (linkProperties.toString().contains("Nat64Prefix:")) {
                    val pattern = Pattern.compile("Nat64Prefix: +(" + Constants.IPv6_REGEX_NO_BOUNDS + "/\\d+)")
                    val matcher = pattern.matcher(linkProperties.toString())
                    if (matcher.find()) {
                        nat64 = matcher.group(1) ?: ""
                    }
                }

                var lastNat64 = networkToNat64[networkToId(cm, network)]
                if (lastNat64 == null) {
                    lastNat64 = ""
                }
                networkToNat64[networkToId(cm, network)] = nat64

                var lastDns = networkToDns[networkToId(cm, network)]
                if (lastDns == null) {
                    lastDns = ArrayList()
                }
                networkToDns[networkToId(cm, network)] = dns

                networks.add(networkToId(cm, network))

                if (networkToId(cm, network) == activeNetwork &&
                        (!networks.contains(networkToId(cm, network))
                        || !same(lastDns, dns)
                        || lastNat64 != nat64)
                        || Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {

                    logi("DNS cur: " + TextUtils.join(",", dns) +
                            " prv: " + TextUtils.join(",", lastDns) +
                            " NAT64 cur: " + nat64 + " prev: " + lastNat64)

                    if (isActiveNetwork(cm, network)) {
                        manageNat64AndDns(nat64, dns, lastDns)
                    }

                    if (isRootMode()) {
                        updateIptablesRules(false)
                    }

                    if (isVpnMode() && !vpnRevoked) {
                        setInternetAvailable(false)
                        reload("Link properties changed", context!!)
                    } else if (isRootMode() || vpnRevoked) {
                        resetArpScanner()
                        checkInternetConnection()
                    } else if (isProxyMode()) {
                        resetArpScanner()
                    }

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        PrivateDnsProxyManager.checkPrivateDNSAndProxy(
                                context!!, linkProperties, isPreventDnsLeaks()
                        )
                    }
                }

            }

            private fun manageNat64AndDns(
                    nat64: String?,
                    dns: List<InetAddress>?,
                    lastDns: List<InetAddress>?
            ) {

                val nat64f = nat64 ?: ""
                val dnsf = dns ?: ArrayList()
                val lastDnsf = lastDns ?: ArrayList()

                var restartRequested = false
                if (nat64f.isEmpty() && isNat64Active()) {
                    restartRequested = true
                } else if (nat64f.isNotEmpty() && (!isNat64Active() || nat64f != getSavedNat64Prefix())) {
                    restartRequested = true
                }

                if (isRestartNeeded(lastDnsf, dnsf)) {
                    dnsChanged = true
                    restartRequested = true
                }

                if (restartRequested && !restartLocked) {
                    restartLocked = true
                    handler.get().postDelayed({
                        if (nat64f.isEmpty() && isNat64Active()) {
                            updateDNSCryptNat64Prefix(false, getSavedNat64Prefix())
                            restartDNSCryptIfRunning()
                        } else if (nat64f.isNotEmpty() && (!isNat64Active() || nat64f != getSavedNat64Prefix())) {
                            updateDNSCryptNat64Prefix(true, nat64f)
                            restartDNSCryptIfRunning()
                        } else if (dnsChanged) {
                            restartDNSCryptIfRunning()
                        }
                        restartLocked = false
                        dnsChanged = false
                    }, RESTART_DNSCRYPT_DELAY_SEC * 1000L)

                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {

                if (isVpnNetwork(cm, network)) {
                    return
                }

                if (networks.isEmpty() || isActiveNetwork(cm, network)) {
                    activeNetwork = networkToId(cm, network)
                    connected = true
                }

                val lastConnected = connected

                setNetworkAvailable(true)

                var networkValidated = false
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    networkValidated = networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                }

                val validatedNetworksCount = validated.size
                if (networkValidated) {
                    validated.add(networkToId(cm, network))
                } else {
                    validated.remove(networkToId(cm, network))
                }

                if ((lastConnected == null || !lastConnected || validatedNetworksCount != validated.size)
                        && isActiveNetwork(cm, network)) {

                    if (isVpnMode()) {
                        if (vpnRevoked) {
                            resetArpScanner()
                            checkInternetConnection()
                        } else {
                            setInternetAvailable(false)
                            reload("Connected state changed", context!!)
                        }
                        logi("ModulesReceiver changed capabilities=" + network)
                    } else if (isRootMode()) {
                        updateIptablesRules(false)
                        resetArpScanner()
                        checkInternetConnection()
                        logi("ModulesReceiver changed capabilities=" + network)
                    } else if (isProxyMode()) {
                        resetArpScanner()
                        logi("ModulesReceiver changed capabilities=" + network)
                    }
                }

                networks.add(networkToId(cm, network))

            }

            override fun onLost(network: Network) {

                if (isVpnNetwork(cm, network)) {
                    logi("ModulesReceiver lost VPN network=" + network + " connected=false")
                    return
                } else {
                    logi("ModulesReceiver lost network=" + network + " connected=false")
                }

                networks.remove(networkToId(cm, network))
                val lastActiveNetwork = activeNetwork
                if (networks.size == 1) {
                    activeNetwork = networks.iterator().next()
                } else {
                    val hash = getActiveNetworkHash(cm)
                    if (hash != UNKNOWN_NETWORK_HASH) {
                        activeNetwork = getActiveNetworkHash(cm)
                    }
                }
                connected = networks.isNotEmpty()
                setNetworkAvailable(false)

                if (isNetworkAvailable() && networks.isNotEmpty() && lastActiveNetwork != activeNetwork) {
                    manageNat64AndDns(
                            networkToNat64[activeNetwork],
                            networkToDns[activeNetwork],
                            networkToDns[lastActiveNetwork]
                    )
                }

                if (isVpnMode() && !vpnRevoked) {
                    setInternetAvailable(false)
                    reload("Network lost", context!!)
                } else if (isVpnMode() && vpnRevoked) {
                    setInternetAvailable(false)
                    resetArpScanner(false)
                } else if (isRootMode()) {
                    setInternetAvailable(false)
                    updateIptablesRules(false)
                    resetArpScanner(false)
                } else if (isProxyMode()) {
                    resetArpScanner(false)
                }
            }

            fun same(last: List<InetAddress>?, current: List<InetAddress>?): Boolean {
                if (last == null || current == null)
                    return false
                if (last.size != current.size)
                    return false

                for (i in current.indices)
                    if (last[i] != current[i])
                        return false

                return true
            }

            fun isRestartNeeded(last: List<InetAddress>?, current: List<InetAddress>?): Boolean {
                //Do not restart after the app start or if the network does not propagate DNS
                if (last == null || current == null) {
                    return false
                }
                //Do not restart if network just advertises additional DNS
                for (address in current) {
                    if (last.contains(address)) {
                        return false
                    }
                }
                if (last.size != current.size) {
                    return true
                }
                return !HashSet(last).containsAll(current)
            }

            fun isNat64Active(): Boolean {
                return defaultPreferences.get().getBoolean(DNSCRYPT_DNS64, false)
            }

            fun saveNat64Active(active: Boolean) {
                defaultPreferences.get().edit().putBoolean(DNSCRYPT_DNS64, active).apply()
            }

            fun getSavedNat64Prefix(): String {
                return defaultPreferences.get().getString(DNSCRYPT_DNS64_PREFIX, "64:ff9b::/96") ?: "64:ff9b::/96"
            }

            fun saveNat64Prefix(prefix: String) {
                defaultPreferences.get().edit().putString(DNSCRYPT_DNS64_PREFIX, prefix).apply()
            }

            fun isDNSCryptBlockIPv6(): Boolean {
                return defaultPreferences.get().getBoolean(DNSCRYPT_BLOCK_IPv6, false)
            }

            fun updateDNSCryptNat64Prefix(active: Boolean, prefix: String) {
                executor.submit("ModulesReceiver updateDNSCryptNat64Prefix") {
                    var consumed = false
                    val pattern = Pattern.compile("#?prefix ?= ?\\['" + Constants.IPv6_REGEX_NO_BOUNDS + "/\\d+']")
                    val conf = FileManager.readTextFileSynchronous(
                            context!!,
                            pathVars.get().dnscryptConfPath
                    )
                    val prefixLine: String = if (active) {
                        "prefix = ['" + prefix + "']"
                    } else {
                        "#prefix = ['" + prefix + "']"
                    }
                    if (!pattern.matcher(prefixLine).matches()) {
                        return@submit
                    }
                    for (i in conf.indices) {
                        val line = conf[i]
                        if (pattern.matcher(line).matches() && line != prefixLine) {
                            conf[i] = prefixLine
                            consumed = true
                            break
                        }
                    }

                    if (consumed) {
                        saveNat64Active(active)
                        saveNat64Prefix(prefix)

                        FileManager.writeTextFileSynchronous(
                                context!!,
                                pathVars.get().dnscryptConfPath,
                                conf
                        )
                    }
                }
            }

            private fun restartDNSCryptIfRunning() {
                // FIX (2026-06-24, AVD-reproduced): in no-root VPN mode the VPN's OWN bringup is seen as a
                // "network DNS change", which restarts a perfectly-running DNSCrypt — but the no-root kill of
                // libdnscrypt-proxy.so fails ("Kill ... without root: result false" / "ModulesKiller cannot
                // stop DNSCrypt"), so the restart never completes and DNSCrypt loops on RESTARTING forever
                // (the "launching dnscrypt" hang → 0% Beast metrics → permanent Slow-Start). In VPN mode
                // DNSCrypt serves on the loopback (127.0.0.1:5354) regardless of the upstream system DNS, and
                // dnscrypt-proxy reconnects its encrypted upstreams on a real network change internally — so
                // this system-DNS-change restart is unnecessary AND harmful here. Honor it ONLY in root mode
                // (where dnscrypt rides iptables + the system resolver and the kill actually succeeds).
                if (modulesStatus.mode == VPN_MODE) {
                    return
                }
                if (modulesStatus.dnsCryptState == RUNNING && isNetworkAvailable()) {
                    logi("Restart DNSCrypt on network DNS change")
                    ModulesRestarter.restartDNSCrypt(context!!)
                }
            }
        }

        if (cm != null) {
            setNetworkAvailable(false)
            cm.registerNetworkCallback(builder.build(), nc)
            commonNetworkCallback = nc
        }
    }

    private fun isPreventDnsLeaks(): Boolean {
        return defaultPreferences.get().getBoolean(PREVENT_DNS_LEAKS, false)
    }

    private fun unlistenNetworkChanges() {
        val cm = context!!.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager?
        if (cm != null) {
            cm.unregisterNetworkCallback(commonNetworkCallback as ConnectivityManager.NetworkCallback)
            setNetworkAvailable(false)
        }
    }

    private fun listenConnectivityChanges() {
        logi("ModulesReceiver start listening to connectivity changes")
        setNetworkAvailable(false)
        val ifConnectivity = IntentFilter()
        ifConnectivity.addAction(LEGACY_CONNECTIVITY_ACTION)
        context!!.registerReceiver(this, ifConnectivity)
        commonReceiversRegistered = true
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    private fun registerVpnRevokeReceiver() {
        val intentFilter = IntentFilter()
        intentFilter.addAction(VPN_REVOKE_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context!!.registerReceiver(this, intentFilter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context!!.registerReceiver(this, intentFilter)
        }
    }

    /**
     * The reaction to a VPN network appearing or disappearing, shared by both implementations
     * below so the two paths cannot drift apart.
     */
    private fun onVpnTransportChanged() {
        if (isVpnMode()) {
            checkVpnRestoreAfterRevoke()
        } else if (isRootMode()
            && !modulesStatus.isUseModulesWithRoot
            && !modulesStatus.isFixTTL
        ) {
            connectivityStateChanged(Intent("VPN connectivity changed"))
        }
    }

    /**
     * WHY THIS ONE WAS MIGRATED AND THE OTHER LEGACY PATH WAS NOT.
     *
     * `registerConnectivityChanges()` already picks a NetworkCallback on API 23+ and only falls
     * back to the CONNECTIVITY_ACTION broadcast below M (or if the modern registration throws), so
     * its deprecated code is genuinely unreachable on a modern device.
     *
     * This function was NOT gated at all. It is called from the root-mode branch
     * (`ModulesReceiver.kt:237`) on every API level, so the deprecated broadcast really did run on
     * current Android -- and it is the deprecated mechanism, not merely a deprecated constant:
     * CONNECTIVITY_ACTION is the thing Google replaced.
     *
     * It now mirrors the SAME shape the file already uses ten lines up: NetworkCallback on 23+,
     * broadcast below. That symmetry is deliberate -- a second, different fallback strategy in one
     * class is how the two get out of step.
     *
     * EQUIVALENCE, stated so it can be checked rather than trusted: the old code fired when a
     * CONNECTIVITY_ACTION carried EXTRA_NETWORK_TYPE == TYPE_VPN, i.e. "a VPN network changed
     * state". The request below asks for exactly TRANSPORT_VPN, so onAvailable/onLost fire when a
     * VPN network appears or goes away. Both funnel into [onVpnTransportChanged], which is the
     * unchanged original body.
     *
     * NOT PROVED, MEASURED-BY-COMPILATION ONLY: the timing differs. onAvailable fires when the
     * network is USABLE, whereas the broadcast fired on any state transition including CONNECTING.
     * On a real device that means this reacts marginally later and marginally less often. That is
     * a behaviour change and it needs a device to confirm; it is written down rather than glossed.
     */
    private fun listenVpnConnectivityChanges() {

        logi("ModulesReceiver start listening to vpn connectivity changes")

        val cm = context!!.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && cm != null) {
            try {
                val callback = object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        onVpnTransportChanged()
                    }

                    override fun onLost(network: Network) {
                        onVpnTransportChanged()
                    }
                }
                val request = NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                    .build()
                cm.registerNetworkCallback(request, callback)
                vpnNetworkCallback = callback
                return
            } catch (e: Exception) {
                // Same failure discipline as registerConnectivityChanges: if the modern
                // registration is refused, fall through to the broadcast rather than silently
                // watching nothing.
                logw("ModulesReceiver listenVpnConnectivityChanges callback", e)
                vpnNetworkCallback = null
            }
        }

        vpnConnectivityReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent) {
                // Pre-M fallback only. The deprecated extras ARE the payload of the deprecated
                // broadcast -- there is nothing modern to read here, so the suppression is scoped
                // to the expression that must use them.
                val networkType = intent.getIntExtra(
                    LEGACY_EXTRA_NETWORK_TYPE,
                    LEGACY_TYPE_DUMMY
                )
                if (networkType == LEGACY_TYPE_VPN) {
                    onVpnTransportChanged()
                }
            }
        }

        val ifConnectivity = IntentFilter()
        ifConnectivity.addAction(LEGACY_CONNECTIVITY_ACTION)
        context!!.registerReceiver(vpnConnectivityReceiver, ifConnectivity)
    }

    private fun unlistenVpnConnectivityChanges() {

        // BOTH registrations must be undone, and independently. Only one is ever active, but
        // making this an if/else on SDK_INT would leak the receiver in the case that matters most:
        // a device on 23+ whose callback registration threw and fell back to the broadcast. Each
        // branch is guarded by its own non-null field, so the inactive one is simply skipped.
        val callback = vpnNetworkCallback
        if (callback != null) {
            logi("ModulesReceiver stop listening to vpn connectivity changes (callback)")
            try {
                val cm = context!!.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                // `as?` not `as`: the field is Any?, and an unchecked cast here would turn a
                // type confusion into a crash during teardown -- the worst moment for one, since
                // the caller is already unwinding. A null simply skips, and the field is cleared
                // in `finally` either way so nothing is retried forever.
                (callback as? ConnectivityManager.NetworkCallback)?.let {
                    cm?.unregisterNetworkCallback(it)
                }
            } catch (e: Exception) {
                logw("ModulesReceiver unlistenVpnConnectivityChanges callback", e)
            } finally {
                vpnNetworkCallback = null
            }
        }

        if (vpnConnectivityReceiver != null) {
            logi("ModulesReceiver stop listening to vpn connectivity changes")
            try {
                context!!.unregisterReceiver(vpnConnectivityReceiver!!)
            } catch (e: Exception) {
                logw("ModulesReceiver unlistenVpnConnectivityChanges", e)
            } finally {
                vpnConnectivityReceiver = null
            }
        }
    }

    private fun registerInteractiveStateReceiver() {
        val screenIntentFilter = IntentFilter()
        screenIntentFilter.addAction(SCREEN_ON_ACTION)
        screenIntentFilter.addAction(SCREEN_OFF_ACTION)
        context!!.registerReceiver(this, screenIntentFilter)
        commonReceiversRegistered = true
    }

    private fun idleStateChanged() {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return
        }

        val pm = context!!.getSystemService(Context.POWER_SERVICE) as PowerManager?
        if (pm != null) {
            logi("ModulesReceiver device idle=" + pm.isDeviceIdleMode)
        }

        if (pm != null && !pm.isDeviceIdleMode) {
            if (isVpnMode() && !vpnRevoked) {
                setInternetAvailable(false)
                reload("Idle state changed", context!!)
            } else if (isVpnMode() && vpnRevoked) {
                resetArpScanner()
                checkInternetConnection()
            } else if (isRootMode()) {
                updateIptablesRules(false)
                resetArpScanner()
                checkInternetConnection()
            } else if (isProxyMode()) {
                resetArpScanner()
            }
        }
    }

    /**
     * The handler for the PRE-M connectivity broadcast.
     *
     * @Suppress is on the whole function because the whole function is legacy: its argument is
     * an Intent whose payload is the deprecated NetworkInfo, and there is nothing modern to read
     * from it. Reaching for ConnectivityManager here instead would be WRONG, not modern -- the
     * extra describes the network THE BROADCAST IS ABOUT, while a fresh query describes now, and
     * during a connectivity change those are routinely different.
     *
     * It is also reachable on modern devices via onVpnTransportChanged(), but only with a
     * synthetic Intent that carries no extras -- so the NetworkInfo branches below do not fire
     * there.
     */
    @Suppress("DEPRECATION")
    private fun connectivityStateChanged(intent: Intent?) {

        if (intent == null) {
            return
        }

        logi("ModulesReceiver connectivityStateChanged received " + intent)

        // The EXTRA is a NetworkInfo -- fixed by the legacy broadcast, no modern replacement --
        // but the deprecated single-argument READER does have one. IntentCompat performs the
        // API-33 class-checked split internally.
        val network = IntentCompat.getParcelableExtra(
            intent, LEGACY_EXTRA_NETWORK_INFO, android.net.NetworkInfo::class.java
        )

        if (isVpnMode()) {
            // Filter VPN connectivity changes
            val networkType = intent.getIntExtra(LEGACY_EXTRA_NETWORK_TYPE, LEGACY_TYPE_DUMMY)
            if (networkType == LEGACY_TYPE_VPN)
                return

            if (network is android.net.NetworkInfo) {
                setNetworkAvailable(network.isConnectedOrConnecting)
            }

            if (vpnRevoked) {
                resetArpScanner()
                checkInternetConnection()
            } else {
                setInternetAvailable(false)
                reload("Connectivity changed", context!!)
            }

        } else if (isRootMode()) {
            if (network is android.net.NetworkInfo) {
                setNetworkAvailable(network.isConnectedOrConnecting)
            }
            updateIptablesRules(false)
            resetArpScanner()
            checkInternetConnection()
        } else if (isProxyMode()) {
            if (network is android.net.NetworkInfo) {
                setNetworkAvailable(network.isConnectedOrConnecting)
            }
            resetArpScanner()
        }
    }

    private fun interactiveStateChanged(intent: Intent) {

        if (SCREEN_ON_ACTION == intent.action) {

            modulesStatus.isDeviceInteractive = true

            val interactor = connectionCheckerInteractor.get()
            if (!interactor.getNetworkConnectionResult()) {
                interactor.checkNetworkConnection()
            }
            if (!interactor.getInternetConnectionResult()) {
                interactor.checkInternetConnection()
            }
        } else if (SCREEN_OFF_ACTION == intent.action) {
            modulesStatus.isDeviceInteractive = false
        }
    }

    @Suppress("UNCHECKED_CAST")
    @Synchronized
    private fun checkInternetSharingState(intent: Intent) {

        if (checkTetheringTask != null && !checkTetheringTask!!.isCompleted) {
            if (TETHER_STATE_FILTER_ACTION == intent.action) {
                checkTetheringTask!!.cancel(CancellationException())
            } else {
                return
            }
        }

        checkTetheringTask = executor.execute(name = "ModulesReceiver checkTetheringTask") {
            var wifiAccessPointOn = false
            var usbTetherOn = false
            val action = intent.action

            try {

                // One call, not two: the old code fetched and deserialized the same extra twice
                // (once to test it was a List, once to cast it), so a large tether list crossed
                // the Binder boundary and was rebuilt twice per broadcast for no benefit.
                val tetherList: List<String>? = intent.stringListExtraCompat(EXTRA_ACTIVE_TETHER)

                TimeUnit.SECONDS.sleep(DELAY_BEFORE_CHECKING_INTERNET_SHARING_SEC.toLong())

                val checker = internetSharingChecker.get()
                if (tetherList != null) {
                    checker.setTetherInterfaceName(tetherList)
                } else if (TETHER_STATE_FILTER_ACTION == action) {
                    checker.setTetherInterfaceName(null)
                }
                checker.updateData()
                wifiAccessPointOn = checker.isApOn
                usbTetherOn = checker.isUsbTetherOn

            } catch (ignored: InterruptedException) {
                logi("ModulesReceiver checkInternetSharingState action " + action + " interrupted")
            } catch (e: Exception) {
                loge("ModulesReceiver checkInternetSharingState exception", e)
            }

            val preferences = preferenceRepository.get()

            if (wifiAccessPointOn && !preferences.getBoolPreference(WIFI_ACCESS_POINT_IS_ON)) {
                preferences.setBoolPreference(WIFI_ACCESS_POINT_IS_ON, true)
                modulesStatus.setIptablesRulesUpdateRequested(context!!, true)
            } else if (!wifiAccessPointOn && preferences.getBoolPreference(WIFI_ACCESS_POINT_IS_ON)) {
                preferences.setBoolPreference(WIFI_ACCESS_POINT_IS_ON, false)
                modulesStatus.setIptablesRulesUpdateRequested(context!!, true)
            }

            if (usbTetherOn && !preferences.getBoolPreference(TortaeKeys.USB_MODEM_IS_ON)) {
                preferences.setBoolPreference(TortaeKeys.USB_MODEM_IS_ON, true)
                ModulesStatus.getInstance().setIptablesRulesUpdateRequested(context!!, true)
            } else if (!usbTetherOn && preferences.getBoolPreference(TortaeKeys.USB_MODEM_IS_ON)) {
                preferences.setBoolPreference(TortaeKeys.USB_MODEM_IS_ON, false)
                ModulesStatus.getInstance().setIptablesRulesUpdateRequested(context!!, true)
            }

            logi("ModulesReceiver " +
                    "WiFi Access Point state is " + (if (wifiAccessPointOn) "ON" else "OFF") + "\n"
                    + " USB modem state is " + (if (usbTetherOn) "ON" else "OFF"))
        }
    }

    private fun powerOFFDetected() {

        val killSwitch = defaultPreferences.get().getBoolean(KILL_SWITCH, false)
        if (killSwitch) {

            val commands = ArrayList<String>(2)
            commands.add("svc wifi disable")
            commands.add("svc data disable")

            var networkAvailable = false

            if (NetworkChecker.isWifiActive(context!!, true)) {
                networkAvailable = true
                preferenceRepository.get().setBoolPreference(WIFI_ON_REQUESTED, true)
                logi("Disabling WiFi due to a kill switch")
            }
            if (NetworkChecker.isCellularActive(context!!, true)) {
                networkAvailable = true
                preferenceRepository.get().setBoolPreference(GSM_ON_REQUESTED, true)
                logi("Disabling GSM due to a kill switch")
            }

            if (networkAvailable) {
                RootCommands.execute(context!!, commands, RootCommandsMark.NULL_MARK)
            }
        }

        ModulesAux.saveDNSCryptStateRunning(false)

        ModulesAux.stopModulesIfRunning(context!!)
    }

    private fun packageChanged(intent: Intent) {

        logi("ModulesReceiver packageChanged " + intent)

        if (isVpnMode()) {
            if (Intent.ACTION_PACKAGE_ADDED == intent.action) {
                reload("Package added", context!!)
            } else if (Intent.ACTION_PACKAGE_REMOVED == intent.action) {
                reload("Package deleted", context!!)
            }
        } else if (isRootMode()) {

            updateIptablesRules(true)

            if (!modulesStatus.isFixTTL) {
                installedAppNamesStorage.get().updateAppUidToNames()
            }
        }
    }

    private fun vpnRevoked(vpnRevoked: Boolean) {
        this.vpnRevoked = vpnRevoked

        if (vpnRevoked) {
            listenVpnConnectivityChanges()
            resetArpScanner()
        } else {
            unlistenVpnConnectivityChanges()
        }
    }

    private fun checkVpnRestoreAfterRevoke() {
        handler.get().postDelayed({
            if (vpnRevoked && !NetworkChecker.isVpnActive(context!!)) {
                startVPNService()
            }
        }, DELAY_BEFORE_STARTING_VPN_SEC * 1000L)
    }

    private fun startVPNService() {

        if (!defaultPreferences.get().getBoolean(VPN_SERVICE_ENABLED, false)
                && (modulesStatus.dnsCryptState == RUNNING
                || modulesStatus.firewallState == STARTING
                || modulesStatus.firewallState == RUNNING)
                && VpnService.prepare(context!!) == null
        ) {
            defaultPreferences.get().edit().putBoolean(VPN_SERVICE_ENABLED, true).apply()
            ServiceVPNHelper.start(
                    "ModulesReceiver start VPN service after revoke",
                    context!!
            )
        }
    }

    private fun updateIptablesRules(forceUpdate: Boolean) {

        val refreshRules = defaultPreferences.get().getBoolean(REFRESH_RULES, false)
        val fixTTL = modulesStatus.isFixTTL

        if (!refreshRules && !forceUpdate && !fixTTL && !isFirewallEnabled()) {
            return
        }

        if (modulesStatus.mode == ROOT_MODE
                && !modulesStatus.isUseModulesWithRoot
                && !lock) {

            executor.submit("ModulesReceiver updateIptablesRules") {
                if (!lock) {

                    lock = true

                    try {
                        TimeUnit.SECONDS.sleep(DELAY_BEFORE_UPDATING_IPTABLES_RULES_SEC.toLong())
                    } catch (e: InterruptedException) {
                        logw("ModulesReceiver sleep interruptedException " + e.message)
                    }

                    if (modulesStatus.mode == ROOT_MODE && !modulesStatus.isUseModulesWithRoot) {
                        modulesStatus.setIptablesRulesUpdateRequested(context!!, true)
                    }

                    lock = false
                }
            }
        }
    }

    private fun resetArpScanner(connectionAvailable: Boolean) {
        if (defaultPreferences.get().getBoolean(ARP_SPOOFING_DETECTION, false)) {
            try {
                ArpScanner.getArpComponent().get().reset(connectionAvailable)
            } catch (e: Exception) {
                loge("ModulesReceiver resetArpScanner", e)
            }
        }
    }

    private fun resetArpScanner() {
        if (context != null && defaultPreferences.get().getBoolean(ARP_SPOOFING_DETECTION, false)) {
            val interactor = connectionCheckerInteractor.get()
            interactor.checkNetworkConnection()
            try {
                ArpScanner.getArpComponent().get().reset(interactor.getNetworkConnectionResult())
            } catch (e: Exception) {
                loge("ModulesReceiver resetArpScanner", e)
            }
        }
    }

    private fun setInternetAvailable(available: Boolean) {
        val interactor = connectionCheckerInteractor.get()
        interactor.setInternetConnectionResult(available)
        interactor.checkNetworkConnection()
        interactor.checkInternetConnection()
    }

    private fun checkInternetConnection() {
        val interactor = connectionCheckerInteractor.get()
        interactor.setInternetConnectionResult(false)
        interactor.checkInternetConnection()
    }

    @SuppressLint("UnsafeOptInUsageWarning")
    override fun onConnectionChecked(available: Boolean) {

        if (isVpnMode()) {
            return
        }

        if (available) {
            logi("ModulesReceiver - Internet is available due to confirmation.")
        } else {
            logi("ModulesReceiver - Internet is not available due to confirmation.")
        }
    }

    override fun isActive(): Boolean {
        return true
    }

    private fun isVpnMode(): Boolean {
        return modulesStatus.mode == VPN_MODE
    }

    private fun isRootMode(): Boolean {
        return modulesStatus.mode == ROOT_MODE
    }

    private fun isProxyMode(): Boolean {
        return modulesStatus.mode == PROXY_MODE
    }

    private fun isNetworkAvailable(): Boolean {
        connectionCheckerInteractor.get().checkNetworkConnection()
        return connectionCheckerInteractor.get().getNetworkConnectionResult()
    }

    private fun setNetworkAvailable(available: Boolean) {
        connectionCheckerInteractor.get().setNetworkConnectionResult(available)
    }

    private fun isFirewallEnabled(): Boolean {
        return preferenceRepository.get().getBoolPreference(FIREWALL_ENABLED)
    }

    companion object {

        /**
         * THE PRE-M CONNECTIVITY API, NAMED ONCE.
         *
         * Every constant below is deprecated, and every one of them is still REQUIRED: this
         * module ships minSdkVersion 21 (build.gradle:67) while ConnectivityManager.NetworkCallback
         * needs API 23. registerConnectivityChanges() uses the callback on 23+ and falls back to
         * this broadcast below M -- or if the modern registration throws, which is why the
         * fallback cannot simply be deleted even if minSdk rose tomorrow.
         *
         * ROUTING THEM THROUGH NAMED ALIASES rather than sprinkling @Suppress at ten call sites
         * is a deliberate choice about what the suppression COVERS. A file-level or
         * function-level annotation would also silence the NEXT API that goes stale nearby,
         * which is exactly how this module ended up with 33 warnings hidden behind 20 blanket
         * suppressions -- measured earlier this session: 47 reported, 80 real. These five
         * aliases suppress five named constants and nothing else, and the LEGACY_ prefix states
         * at every use site which era of the API is being spoken.
         */
        @Suppress("DEPRECATION")
        private val LEGACY_CONNECTIVITY_ACTION: String = ConnectivityManager.CONNECTIVITY_ACTION

        @Suppress("DEPRECATION")
        private val LEGACY_EXTRA_NETWORK_TYPE: String = ConnectivityManager.EXTRA_NETWORK_TYPE

        @Suppress("DEPRECATION")
        private val LEGACY_EXTRA_NETWORK_INFO: String = ConnectivityManager.EXTRA_NETWORK_INFO

        @Suppress("DEPRECATION")
        private val LEGACY_TYPE_DUMMY: Int = ConnectivityManager.TYPE_DUMMY

        @Suppress("DEPRECATION")
        private val LEGACY_TYPE_VPN: Int = ConnectivityManager.TYPE_VPN


        const val VPN_REVOKE_ACTION = "pillar.kuma_saimono.libumdnscrypt.VPN_REVOKE_ACTION"
        const val VPN_REVOKED_EXTRA = "pillar.kuma_saimono.libumdnscrypt.VPN_REVOKED_EXTRA"

        private const val AP_STATE_FILTER_ACTION = "android.net.wifi.WIFI_AP_STATE_CHANGED"
        private const val TETHER_STATE_FILTER_ACTION = "android.net.conn.TETHER_STATE_CHANGED"
        private const val SHUTDOWN_FILTER_ACTION = "android.intent.action.ACTION_SHUTDOWN"
        private const val REBOOT_FILTER_ACTION = "android.intent.action.REBOOT"
        private const val POWER_OFF_FILTER_ACTION = "android.intent.action.QUICKBOOT_POWEROFF"
        private const val SCREEN_ON_ACTION = "android.intent.action.SCREEN_ON"
        private const val SCREEN_OFF_ACTION = "android.intent.action.SCREEN_OFF"

        private const val DELAY_BEFORE_CHECKING_INTERNET_SHARING_SEC = 5
        private const val DELAY_BEFORE_UPDATING_IPTABLES_RULES_SEC = 5
        private const val DELAY_BEFORE_STARTING_VPN_SEC = 1
        private const val EXTRA_ACTIVE_TETHER = "tetherArray"

        private const val RESTART_DNSCRYPT_DELAY_SEC = 5
    }
}
