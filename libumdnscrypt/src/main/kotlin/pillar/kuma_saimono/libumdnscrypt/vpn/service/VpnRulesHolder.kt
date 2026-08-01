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

import android.annotation.SuppressLint
import android.content.SharedPreferences
import dagger.Lazy
import pillar.kuma_saimono.libumdnscrypt.arp.ArpScanner
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.connection_checker.ConnectionCheckerInteractor
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.iptables.Tethering
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData.Companion.SPECIAL_PORT_AGPS1
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData.Companion.SPECIAL_PORT_AGPS2
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData.Companion.SPECIAL_PORT_NTP
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData.Companion.SPECIAL_UID_AGPS
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData.Companion.SPECIAL_UID_CONNECTIVITY_CHECK
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData.Companion.SPECIAL_UID_KERNEL
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData.Companion.SPECIAL_UID_NTP
import pillar.kuma_saimono.libumdnscrypt.utils.Constants
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.DNS_OVER_TLS_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.LAN_DOMAIN_ENDINGS
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.LOOPBACK_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.LOOPBACK_ADDRESS_IPv6
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.NETWORK_STACK_DEFAULT_UID
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.PLAINTEXT_DNS_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.apps.InstalledApplicationsManager
import pillar.kuma_saimono.libumdnscrypt.utils.connectivitycheck.ConnectivityCheckManager
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RESTARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RUNNING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.ROOT_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.APPS_ALLOW_LAN_PREF
import pillar.kuma_saimono.libumdnscrypt.vpn.Allowed
import pillar.kuma_saimono.libumdnscrypt.vpn.Forward
import pillar.kuma_saimono.libumdnscrypt.vpn.Packet
import pillar.kuma_saimono.libumdnscrypt.vpn.Rule
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils.isIpInLanRange
import java.util.concurrent.ConcurrentSkipListMap
import java.util.concurrent.ConcurrentSkipListSet
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.inject.Inject
import javax.inject.Named

class VpnRulesHolder @Inject constructor(
    @Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: SharedPreferences,
    private val preferenceRepository: PreferenceRepository,
    private val pathVars: PathVars,
    private val connectivityCheckManager: Lazy<ConnectivityCheckManager>,
    private val connectionCheckerInteractor: Lazy<ConnectionCheckerInteractor>
) {

    private val lock = ReentrantReadWriteLock(true)

    @SuppressLint("UseSparseArrays")
    @JvmField
    val setUidAllowed: MutableSet<Int> = ConcurrentSkipListSet()

    @SuppressLint("UseSparseArrays")
    private val setUidKnown: MutableSet<Int> = ConcurrentSkipListSet()

    @SuppressLint("UseSparseArrays")
    private val mapForwardPort: MutableMap<Int, Forward> = ConcurrentSkipListMap()
    private val mapForwardAddress: MutableMap<String, Forward> = ConcurrentSkipListMap()
    private val uidLanAllowed: MutableSet<Int> = ConcurrentSkipListSet()

    @JvmField
    val uidSpecialAllowed: MutableSet<Int> = ConcurrentSkipListSet()
    private val uidSpecialLanAllowed: MutableSet<Int> = ConcurrentSkipListSet()

    private val connectivityCheckIps: MutableSet<String> = ConcurrentSkipListSet()

    @Volatile
    private var captivePortalDetected = false

    private val lanDomainEndings: MutableSet<String> = ConcurrentSkipListSet()

    private val modulesStatus = ModulesStatus.getInstance()

    fun isAddressAllowed(vpn: ServiceVPN, packet: Packet): Allowed? {

        if (packet.saddr == null
            || packet.daddr == null
            || vpn.vpnPreferences == null
        ) {
            return null
        }

        val fixTTLForPacket = isFixTTLForPacket(packet)

        val dnsCryptIsRunning = modulesStatus.dnsCryptState == RUNNING
                || modulesStatus.dnsCryptState == STARTING
                || modulesStatus.dnsCryptState == RESTARTING

        lock.readLock().lock()

        val vpnPreferences = vpn.vpnPreferences!!

        var redirectToProxy = false
        if (vpnPreferences.useProxy) {
            redirectToProxy = vpn.isRedirectToProxy(packet.uid, packet.daddr, packet.dport)
        }

        val networkAvailable = connectionCheckerInteractor.get().getNetworkConnectionResult()

        packet.allowed = false
        // https://android.googlesource.com/platform/system/core/+/master/include/private/android_filesystem_config.h
        if ((!vpn.canFilter) && isSupported(packet.protocol)) {
            packet.allowed = true
        } else if (!isSupported(packet.protocol)) {
            logw("Protocol not supported " + packet)
        } else if (packet.dport == DNS_OVER_TLS_PORT
            && vpnPreferences.preventDnsLeaks
            && dnsCryptIsRunning
        ) {
            logw("Block DNS over TLS " + packet)
        } else if (VpnBuilder.vpnDnsSet!!.contains(packet.daddr)
            && packet.dport != PLAINTEXT_DNS_PORT
            && vpnPreferences.preventDnsLeaks
            && packet.uid != vpnPreferences.ownUID
            && dnsCryptIsRunning
        ) {
            logw("Block DNS over HTTPS " + packet)
        } else if (packet.uid == vpnPreferences.ownUID
            || vpnPreferences.compatibilityMode
            && packet.uid == SPECIAL_UID_KERNEL
            && !fixTTLForPacket
        ) {
            packet.allowed = true

            if (!vpnPreferences.compatibilityMode) {
                logw("Allowing self " + packet)
            }
        } else if (vpnPreferences.arpSpoofingDetection
            && vpnPreferences.blockInternetWhenArpAttackDetected
            && (ArpScanner.arpAttackDetected
                    || ArpScanner.dhcpGatewayAttackDetected)
        ) {
            // MITM attack detected
            logw("Block due to mitm attack " + packet)
        } else if (packet.uid == NETWORK_STACK_DEFAULT_UID
            && isIpInLanRange(packet.daddr!!)
        ) {
            //Allow NetworkStack to connect to LAN to determine connection status
            packet.allowed = true
        } else if (vpn.reloading) {
            // Reload service
            logi("Block due to reloading " + packet)
        } else if ((modulesStatus.dnsCryptState != STOPPED &&
                    vpnPreferences.blockIPv6DnsCrypt
                    || fixTTLForPacket
                    || (vpnPreferences.useProxy
                    && (vpnPreferences.proxyAddress != LOOPBACK_ADDRESS
                    || vpnPreferences.blockIPv6DnsCrypt)))
            && (packet.saddr!!.contains(":") || packet.daddr!!.contains(":"))
        ) {
            logi("Block ipv6 " + packet)
        } else if (vpnPreferences.blockHttp && packet.dport == 80
            && !isIpInLanRange(packet.daddr!!)
        ) {
            logw("Block http " + packet)
        } else if (packet.uid <= 2000 &&
            (fixTTLForPacket
                    || vpnPreferences.compatibilityMode) &&
            !setUidKnown.contains(packet.uid)
            && (vpnPreferences.fixTTL
                    || !vpnPreferences.useProxy
                    || packet.protocol == 6 && packet.dport == PLAINTEXT_DNS_PORT)
        ) {

            // Allow unknown system traffic
            packet.allowed = true
            if (!fixTTLForPacket && !vpnPreferences.compatibilityMode) {
                logw("Allowing unknown system " + packet)
            }
        } else if (vpnPreferences.useProxy
            && packet.protocol != 6
            && packet.dport != PLAINTEXT_DNS_PORT
            && redirectToProxy
        ) {
            logw("Disallowing non tcp traffic to proxy " + packet)
        } else if (vpnPreferences.firewallEnabled
            && isIpInLanRange(packet.daddr!!)
        ) {
            if (isDestinationInSpecialRange(packet.uid, packet.daddr!!, packet.dport)) {
                packet.allowed = isSpecialAllowed(
                    uidLanAllowed,
                    uidSpecialLanAllowed,
                    packet.uid,
                    packet.daddr!!,
                    packet.dport
                )
            } else if (vpnPreferences.blockLanOnFreeWiFi
                && captivePortalDetected
                && !getCaptivePortalUids().isEmpty()
                && !getCaptivePortalUids().contains(packet.uid) && packet.uid != SPECIAL_UID_KERNEL
                && packet.daddr != LOOPBACK_ADDRESS && packet.daddr != LOOPBACK_ADDRESS_IPv6
                && packet.dport != 53
                && !redirectToProxy
            ) {
                packet.allowed = false
                logw("Disallowing traffic to lan when a captive portal is detected " + packet)
            } else {
                // Re-pointed: the per-app LAN firewall decision now comes from the native Warden
                // pure-firewall verdict (allow-by-default additive-block) instead of the Garmatin
                // LAN allow-set.
                packet.allowed = isAllowedByWarden(packet)
            }
        } else if (vpnPreferences.firewallEnabled
            && isDestinationInSpecialRange(packet.uid, packet.daddr!!, packet.dport)
        ) {
            packet.allowed = isSpecialAllowed(
                setUidAllowed,
                uidSpecialAllowed,
                packet.uid,
                packet.daddr!!,
                packet.dport
            )
        } else if (vpnPreferences.firewallEnabled
            && packet.dport == PLAINTEXT_DNS_PORT
            && uidLanAllowed.contains(packet.uid)
        ) {
            packet.allowed = true
        } else if (vpnPreferences.firewallEnabled) {

            if (isAllowedByWarden(packet)) {
                // Re-pointed: the per-app firewall decision now comes from the native Warden
                // pure-firewall verdict (allow-by-default additive-block) instead of the Garmatin
                // per-UID allow-set.
                packet.allowed = true
            } else if (packet.dport == PLAINTEXT_DNS_PORT
                && packet.uid < 2000 && packet.uid != SPECIAL_UID_KERNEL
            ) {
                //Allow connection check for system apps
                packet.allowed = true
            } else {
                logw("UID is not allowed by the Warden firewall for " + packet)
            }
        } else {
            packet.allowed = true
        }

        var allowed: Allowed? = null
        if (packet.allowed) {
            if (packet.uid == vpnPreferences.ownUID
                && (packet.dport != PLAINTEXT_DNS_PORT || vpnPreferences.compatibilityMode)
                || vpnPreferences.compatibilityMode
                && isPacketAllowedForCompatibilityMode(packet, fixTTLForPacket)
            ) {
                allowed = Allowed()
            } else if (mapForwardPort.containsKey(packet.dport)) {
                val fwd = mapForwardPort[packet.dport]
                if (fwd != null && networkAvailable) {
                    allowed = Allowed(fwd.raddr, fwd.rport)
                    packet.data = "> " + fwd.raddr + "/" + fwd.rport
                }
            } else if (mapForwardAddress.containsKey(packet.daddr!!)) {
                val fwd = mapForwardAddress[packet.daddr!!]
                if (fwd != null && networkAvailable) {
                    allowed = Allowed(fwd.raddr, fwd.rport)
                    packet.data = "> " + fwd.raddr + "/" + fwd.rport
                }
            } else {
                allowed = Allowed()
            }
        }

        lock.readLock().unlock()

        if (packet.uid != vpn.vpnPreferences!!.ownUID) {
            vpn.addUIDtoDNSQueryRawRecords(
                packet.uid,
                packet.daddr,
                //Unknown incoming packet or Multicast DNS
                if ((packet.uid == -1 || packet.uid == 0 || packet.uid == 1020 || packet.uid == 9999) && packet.sport < packet.dport) packet.sport else packet.dport,
                packet.saddr,
                packet.allowed,
                packet.protocol
            )
        }

        return allowed
    }

    private fun isFixTTLForPacket(packet: Packet): Boolean {
        var apAddresses = Constants.STANDARD_AP_INTERFACE_RANGE
        if (Tethering.wifiAPAddressesRange.contains(".")) {
            apAddresses = Tethering.wifiAPAddressesRange
                .substring(0, Tethering.wifiAPAddressesRange.lastIndexOf("."))
        }

        var usbModemAddresses = Constants.STANDARD_USB_MODEM_INTERFACE_RANGE
        if (Tethering.usbModemAddressesRange.contains(".")) {
            usbModemAddresses = Tethering.usbModemAddressesRange
                .substring(0, Tethering.usbModemAddressesRange.lastIndexOf("."))
        }

        return modulesStatus.isFixTTL && (modulesStatus.mode == ROOT_MODE)
                && !modulesStatus.isUseModulesWithRoot
                && (Tethering.apIsOn && packet.saddr!!.contains(apAddresses)
                || Tethering.usbTetherOn && packet.saddr!!.contains(usbModemAddresses)
                || Tethering.ethernetOn && packet.saddr!!.contains(Tethering.addressLocalPC))
    }

    private fun isSupported(protocol: Int): Boolean {
        return (protocol == 1 /* ICMPv4 */ ||
                protocol == 58 /* ICMPv6 */ ||
                protocol == 6 /* TCP */ ||
                protocol == 17 /* UDP */)
    }

    private fun isDestinationInSpecialRange(uid: Int, destIp: String, destPort: Int): Boolean {
        return uid == 0 && destPort == PLAINTEXT_DNS_PORT
                || uid == SPECIAL_UID_KERNEL
                || destPort == SPECIAL_PORT_NTP
                || destPort == SPECIAL_PORT_AGPS1
                || destPort == SPECIAL_PORT_AGPS2
                || connectivityCheckIps.contains(destIp)
    }

    private fun isSpecialAllowed(
        uidAllowed: Set<Int>,
        specialUidAllowed: Set<Int>,
        uid: Int,
        destIp: String,
        destPort: Int
    ): Boolean {
        var allow = false
        if (uid == 0 && destPort == PLAINTEXT_DNS_PORT) {
            allow = true
        } else if (uid == SPECIAL_UID_KERNEL) {
            allow = specialUidAllowed.contains(SPECIAL_UID_KERNEL)
        } else if (uid == 1000 && destPort == SPECIAL_PORT_NTP) {
            allow = specialUidAllowed.contains(SPECIAL_UID_NTP)
        } else if (destPort == SPECIAL_PORT_AGPS1 || destPort == SPECIAL_PORT_AGPS2) {
            allow = specialUidAllowed.contains(SPECIAL_UID_AGPS)
        } else if (connectivityCheckIps.contains(destIp)) {
            allow = specialUidAllowed.contains(SPECIAL_UID_CONNECTIVITY_CHECK)
        }
        return allow || uidAllowed.contains(uid)
    }

    /**
     * The per-app firewall decision, re-pointed onto the native Warden pure-firewall verdict
     * (REPOINT-1). Replaces the deleted Garmatin per-UID allow-set lookup: an ALLOW verdict (or an
     * unavailable / abstaining engine) means allowed; an explicit Warden DENY means blocked. The
     * network axis is LAN for a LAN-range destination, else the VPN tunnel-egress axis (this is the
     * VPN datapath). Crash-proof: a missing .so / native fault degrades to allow-by-default, never a
     * brick — matching the reworked engine's allow-by-default additive-block posture.
     */
    private fun isAllowedByWarden(packet: Packet): Boolean {
        val net = if (isIpInLanRange(packet.daddr!!))
            WardenDatapathGate.NET_LAN
        else
            WardenDatapathGate.NET_VPN
        val verdict = WardenDatapathGate.verdict(
            packet.uid, packet.daddr!!, packet.dport, packet.protocol, net
        )
        return verdict == WardenDatapathGate.VERDICT_ALLOW
                || verdict == WardenDatapathGate.VERDICT_ABSTAIN
    }

    private fun isPacketAllowedForCompatibilityMode(packet: Packet, fixTTLForPacket: Boolean): Boolean {
        val dnsCryptState = modulesStatus.dnsCryptState
        val dnsCryptReady = modulesStatus.isDnsCryptReady
        val systemDNSAllowed = modulesStatus.isSystemDNSAllowed

        if (packet.uid == SPECIAL_UID_KERNEL && !fixTTLForPacket
            && (packet.dport != PLAINTEXT_DNS_PORT && packet.dport != 0
                    || systemDNSAllowed
                    && (dnsCryptState == RUNNING
                    || dnsCryptState == STARTING
                    || dnsCryptState == RESTARTING) && !dnsCryptReady)
        ) {
            logi("Packet will not be redirected due to compatibility mode " + packet)
            return true
        }

        return false
    }

    fun prepareUidAllowed(
        listAllowed: List<String?>,
        listRule: List<Rule>
    ) {
        lock.writeLock().lock()

        setUidAllowed.clear()
        uidSpecialAllowed.clear()
        for (uid in listAllowed) {
            if (uid != null && uid.matches("\\d+".toRegex())) {
                setUidAllowed.add(uid.toInt())
            } else if (uid != null && uid.matches("-\\d+".toRegex())) {
                uidSpecialAllowed.add(uid.toInt())
            }
        }

        setUidKnown.clear()
        for (rule in listRule) {
            if (rule.uid >= 0) {
                setUidKnown.add(rule.uid)
            }
        }

        uidLanAllowed.clear()
        uidSpecialLanAllowed.clear()
        for (uid in preferenceRepository.getStringSetPreference(APPS_ALLOW_LAN_PREF)) {
            if (uid.matches("\\d+".toRegex())) {
                uidLanAllowed.add(uid.toInt())
            } else if (uid.matches("-\\d+".toRegex())) {
                uidSpecialLanAllowed.add(uid.toInt())
            }
        }

        connectivityCheckIps.clear()
        connectivityCheckIps.addAll(connectivityCheckManager.get().getConnectivityCheckIps())

        captivePortalDetected = connectionCheckerInteractor.get().isFreeWiFiAccessPointDetected()

        lock.writeLock().unlock()
    }

    fun prepareForwarding() {
        lock.writeLock().lock()
        mapForwardPort.clear()
        mapForwardAddress.clear()

        val dnsCryptState = modulesStatus.dnsCryptState
        val firewallState = modulesStatus.firewallState

        val ownUID = pathVars.appUid

        var dnsCryptPort = 5354
        try {
            dnsCryptPort = pathVars.dnsCryptPort.toInt()
        } catch (e: Exception) {
            loge("VPN Redirect Ports Parse Exception", e)
        }

        val dnsCryptReady = modulesStatus.isDnsCryptReady

        if (dnsCryptState == RUNNING && dnsCryptReady) {
            forwardDnsToDnsCrypt(dnsCryptPort, ownUID)
        } else if (dnsCryptState != STOPPED) {
            forwardDnsToDnsCrypt(dnsCryptPort, ownUID)
        } else if (firewallState == STARTING || firewallState == RUNNING) {
            logi("Firewall only operation")
        } else {
            forwardDnsToDnsCrypt(dnsCryptPort, ownUID)
        }

        lock.writeLock().unlock()
    }

    private fun forwardDnsToDnsCrypt(dnsCryptPort: Int, ownUID: Int) {
        addForwardPortRule(17, PLAINTEXT_DNS_PORT, LOOPBACK_ADDRESS, dnsCryptPort, ownUID)
        addForwardPortRule(6, PLAINTEXT_DNS_PORT, LOOPBACK_ADDRESS, dnsCryptPort, ownUID)
    }

    @Suppress("SameParameterValue")
    private fun addForwardPortRule(protocol: Int, dport: Int, raddr: String, rport: Int, ruid: Int) {
        val fwd = Forward()
        fwd.protocol = protocol
        fwd.dport = dport
        fwd.raddr = raddr
        fwd.rport = rport
        fwd.ruid = ruid
        mapForwardPort[fwd.dport] = fwd
        logi("VPN Forward " + fwd)
    }

    @Suppress("SameParameterValue")
    private fun addForwardAddressRule(protocol: Int, daddr: String, raddr: String, rport: Int, ruid: Int) {
        val fwd = Forward()
        fwd.protocol = protocol
        fwd.daddr = daddr
        fwd.raddr = raddr
        fwd.rport = rport
        fwd.ruid = ruid
        mapForwardAddress[fwd.daddr!!] = fwd
        logi("VPN Forward " + fwd)
    }

    fun unPrepare() {
        lock.writeLock().lock()
        setUidAllowed.clear()
        setUidKnown.clear()
        uidLanAllowed.clear()
        uidSpecialLanAllowed.clear()
        uidSpecialAllowed.clear()
        mapForwardPort.clear()
        mapForwardAddress.clear()
        lock.writeLock().unlock()
    }

    private fun getCaptivePortalUids(): Set<Int> {
        return InstalledApplicationsManager.getCaptivePortalUids()
    }

    //https://datatracker.ietf.org/doc/html/rfc6762
    fun isLanDomain(domain: String): Boolean {
        if (lanDomainEndings.isEmpty()) {
            lanDomainEndings.addAll(LAN_DOMAIN_ENDINGS.split(", ?".toRegex()))
        }
        for (ending in lanDomainEndings) {
            if (domain.endsWith(ending)) {
                return true
            }
        }
        return false
    }
}
