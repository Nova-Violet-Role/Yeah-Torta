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

package pillar.kuma_saimono.libumdnscrypt.iptables

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.iptables.IptablesConstants.FILTER_FORWARD_CORE
import pillar.kuma_saimono.libumdnscrypt.iptables.IptablesConstants.FILTER_OUTPUT_CORE
import pillar.kuma_saimono.libumdnscrypt.iptables.IptablesConstants.NAT_PREROUTING_CORE
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.HTTP_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv4_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.QUAD_DNS_41
import pillar.kuma_saimono.libumdnscrypt.utils.ap.InternetSharingChecker
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.ROOT_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import javax.inject.Inject
import javax.inject.Named
import javax.inject.Provider

class Tethering(private val context: Context) {

    @Inject
    lateinit var pathVarsLazy: dagger.Lazy<PathVars>
    @Inject
    @field:Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    lateinit var defaultSharedPreferences: dagger.Lazy<SharedPreferences>
    @Inject
    lateinit var preferenceRepository: dagger.Lazy<PreferenceRepository>
    @Inject
    lateinit var internetSharingChecker: Provider<InternetSharingChecker>

    private var iptables = "iptables "

    private val modulesStatus = ModulesStatus.getInstance()

    init {
        App.instance.daggerComponent.inject(this)
    }

    fun activateTethering(privacyMode: Boolean): List<String> {


        val pathVars = pathVarsLazy.get()

        iptables = pathVars.getIptablesPath()
        val ip6tables = pathVars.getIp6tablesPath()
        val busybox = pathVars.busyboxPath

        val shPref = defaultSharedPreferences.get()
        val preferences = preferenceRepository.get()
        val blockHotspotHttp = shPref.getBoolean("pref_common_block_http", false)
        addressLocalPC = shPref.getString("pref_common_local_eth_device_addr", Constants.STANDARD_ADDRESS_LOCAL_PC) ?: Constants.STANDARD_ADDRESS_LOCAL_PC
        val ttlFix = modulesStatus.isFixTTL && (modulesStatus.mode == ROOT_MODE) && !modulesStatus.isUseModulesWithRoot
        apIsOn = preferences.getBoolPreference(TortaeKeys.WIFI_ACCESS_POINT_IS_ON)

        setInterfaceNames()

        var blockHttpRuleForwardTCP = ""
        var blockHttpRuleForwardUDP = ""
        var blockHttpRulePreroutingTCPwifi = ""
        var blockHttpRulePreroutingUDPwifi = ""
        var blockHttpRulePreroutingTCPusb = ""
        var blockHttpRulePreroutingUDPusb = ""
        var blockHttpRulePreroutingTCPeth = ""
        var blockHttpRulePreroutingUDPeth = ""
        if (blockHotspotHttp) {
            blockHttpRuleForwardTCP = iptables + "-A " + FILTER_FORWARD_CORE + " -p tcp --dport " + HTTP_PORT + " -j REJECT"
            blockHttpRuleForwardUDP = iptables + "-A " + FILTER_FORWARD_CORE + " -p udp --dport " + HTTP_PORT + " -j REJECT"
            blockHttpRulePreroutingTCPwifi = iptables + "-t nat -A " + NAT_PREROUTING_CORE + " -i " + wifiAPInterfaceName + " -p tcp ! -d " + wifiAPAddressesRange + " --dport " + HTTP_PORT + " -j RETURN || true"
            blockHttpRulePreroutingUDPwifi = iptables + "-t nat -A " + NAT_PREROUTING_CORE + " -i " + wifiAPInterfaceName + " -p udp ! -d " + wifiAPAddressesRange + " --dport " + HTTP_PORT + " -j RETURN || true"
            blockHttpRulePreroutingTCPusb = iptables + "-t nat -A " + NAT_PREROUTING_CORE + " -i " + usbModemInterfaceName + " -p tcp ! -d " + usbModemAddressesRange + " --dport " + HTTP_PORT + " -j RETURN || true"
            blockHttpRulePreroutingUDPusb = iptables + "-t nat -A " + NAT_PREROUTING_CORE + " -i " + usbModemInterfaceName + " -p udp ! -d " + usbModemAddressesRange + " --dport " + HTTP_PORT + " -j RETURN || true"
            blockHttpRulePreroutingTCPeth = iptables + "-t nat -A " + NAT_PREROUTING_CORE + " -i " + ethernetInterfaceName + " -p tcp ! -d " + addressLocalPC + " --dport " + HTTP_PORT + " -j RETURN || true"
            blockHttpRulePreroutingUDPeth = iptables + "-t nat -A " + NAT_PREROUTING_CORE + " -i " + ethernetInterfaceName + " -p udp ! -d " + addressLocalPC + " --dport " + HTTP_PORT + " -j RETURN || true"
        }

        var tetheringCommands: MutableList<String> = ArrayList()
        val tetherIptablesRulesIsClean = preferences.getBoolPreference("TetherIptablesRulesIsClean")
        val ttlFixed = preferences.getBoolPreference("TTLisFixed")

        if (!isTetheringActive()) {

            if (tetherIptablesRulesIsClean) {
                return arrayListOf(
                    iptables + "-D FORWARD -j DROP 2> /dev/null || true",
                    iptables + "-I FORWARD -j DROP"
                )
            }

            preferences.setBoolPreference("TetherIptablesRulesIsClean", true)

            tetheringCommands = arrayListOf(
                ip6tables + "-D INPUT -j DROP 2> /dev/null || true",
                ip6tables + "-I INPUT -j DROP || true",
                ip6tables + "-D FORWARD -j DROP 2> /dev/null || true",
                ip6tables + "-I FORWARD -j DROP",
                iptables + "-D FORWARD -j DROP 2> /dev/null || true",
                iptables + "-I FORWARD -j DROP",
                iptables + "-t nat -F " + NAT_PREROUTING_CORE + " 2> /dev/null",
                iptables + "-F " + FILTER_FORWARD_CORE + " 2> /dev/null",
                iptables + "-t nat -D PREROUTING -j " + NAT_PREROUTING_CORE + " 2> /dev/null || true",
                iptables + "-D FORWARD -j " + FILTER_FORWARD_CORE + " 2> /dev/null || true"
            )

            if (ttlFixed) {
                tetheringCommands.addAll(unfixTTLCommands())
            }

        } else if (!privacyMode) {

            preferences.setBoolPreference("TetherIptablesRulesIsClean", false)

            tetheringCommands = arrayListOf(
                iptables + "-D FORWARD -j DROP 2> /dev/null || true",
                iptables + "-I FORWARD -j DROP",
                ip6tables + "-D INPUT -j DROP 2> /dev/null || true",
                ip6tables + "-I INPUT -j DROP || true",
                ip6tables + "-D FORWARD -j DROP 2> /dev/null || true",
                ip6tables + "-I FORWARD -j DROP",
                iptables + "-t nat -F " + NAT_PREROUTING_CORE + " 2> /dev/null",
                iptables + "-F " + FILTER_FORWARD_CORE + " 2> /dev/null",
                iptables + "-t nat -D PREROUTING -j " + NAT_PREROUTING_CORE + " 2> /dev/null || true",
                iptables + "-D FORWARD -j " + FILTER_FORWARD_CORE + " 2> /dev/null || true",
                busybox + "sleep 1 || true",
                iptables + "-t nat -N " + NAT_PREROUTING_CORE + " 2> /dev/null",
                iptables + "-N " + FILTER_FORWARD_CORE + " 2> /dev/null",
                iptables + "-t nat -A PREROUTING -j " + NAT_PREROUTING_CORE,
                iptables + "-A FORWARD -j " + FILTER_FORWARD_CORE,
                busybox + "sleep 1 || true",
                iptables + "-D " + FILTER_OUTPUT_CORE + " -p udp -m udp --dport 67 -j ACCEPT 2> /dev/null || true",
                iptables + "-D " + FILTER_OUTPUT_CORE + " -p udp -m udp --dport 68 -j ACCEPT 2> /dev/null || true",
                iptables + "-I " + FILTER_OUTPUT_CORE + " -p udp -m udp --dport 67 -j ACCEPT",
                iptables + "-I " + FILTER_OUTPUT_CORE + " -p udp -m udp --dport 68 -j ACCEPT",
                iptables + "-D " + FILTER_OUTPUT_CORE + " -p udp -m udp --sport 67 -j ACCEPT 2> /dev/null || true",
                iptables + "-D " + FILTER_OUTPUT_CORE + " -p udp -m udp --sport 68 -j ACCEPT 2> /dev/null || true",
                iptables + "-I " + FILTER_OUTPUT_CORE + " -p udp -m udp --sport 67 -j ACCEPT",
                iptables + "-I " + FILTER_OUTPUT_CORE + " -p udp -m udp --sport 68 -j ACCEPT",
                busybox + "sleep 1 || true",
                blockHttpRulePreroutingTCPwifi,
                blockHttpRulePreroutingUDPwifi,
                blockHttpRulePreroutingTCPusb,
                blockHttpRulePreroutingUDPusb,
                blockHttpRulePreroutingTCPeth,
                blockHttpRulePreroutingUDPeth,
                busybox + "sleep 1 || true",
                iptables + "-A " + FILTER_FORWARD_CORE + " -p tcp --dport 53 -j ACCEPT",
                iptables + "-A " + FILTER_FORWARD_CORE + " -p udp --dport 53 -j ACCEPT",
                blockHttpRuleForwardTCP,
                blockHttpRuleForwardUDP,
                iptables + "-D FORWARD -j DROP 2> /dev/null || true"
            )

            if (ttlFix) {
                tetheringCommands.addAll(fixTTLCommands())
            } else if (ttlFixed) {
                tetheringCommands.addAll(unfixTTLCommands())
            }

        } else {

            preferences.setBoolPreference("TetherIptablesRulesIsClean", false)

            if (tetherIptablesRulesIsClean) {
                return tetheringCommands
            }

            preferences.setBoolPreference("TetherIptablesRulesIsClean", true)

            tetheringCommands = arrayListOf(
                ip6tables + "-D INPUT -j DROP 2> /dev/null || true",
                ip6tables + "-I INPUT -j DROP || true",
                ip6tables + "-D FORWARD -j DROP 2> /dev/null || true",
                ip6tables + "-I FORWARD -j DROP",
                iptables + "-D FORWARD -j DROP 2> /dev/null || true",
                iptables + "-t nat -F " + NAT_PREROUTING_CORE + " 2> /dev/null",
                iptables + "-F " + FILTER_FORWARD_CORE + " 2> /dev/null",
                iptables + "-t nat -D PREROUTING -j " + NAT_PREROUTING_CORE + " 2> /dev/null || true",
                iptables + "-D FORWARD -j " + FILTER_FORWARD_CORE + " 2> /dev/null || true"
            )

            if (ttlFixed) {
                tetheringCommands.addAll(unfixTTLCommands())
            }

        }

        return cleanupCommands(tetheringCommands)
    }

    fun fastUpdate(): List<String> {
        val tetheringCommands: MutableList<String> = ArrayList()
        val tetherIptablesRulesIsClean = preferenceRepository.get()
            .getBoolPreference("TetherIptablesRulesIsClean")

        if (tetherIptablesRulesIsClean) {
            return tetheringCommands
        }

        val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        addressLocalPC = sharedPreferences.getString("pref_common_local_eth_device_addr",
            Constants.STANDARD_ADDRESS_LOCAL_PC) ?: Constants.STANDARD_ADDRESS_LOCAL_PC
        apIsOn = preferenceRepository.get().getBoolPreference(TortaeKeys.WIFI_ACCESS_POINT_IS_ON)

        setInterfaceNames()

        val ip6tables = pathVarsLazy.get().getIp6tablesPath()
        val busybox = pathVarsLazy.get().busyboxPath

        tetheringCommands.addAll(listOf(
            iptables + "-D FORWARD -j DROP 2> /dev/null || true",
            iptables + "-I FORWARD -j DROP",
            ip6tables + "-D INPUT -j DROP 2> /dev/null || true",
            ip6tables + "-I INPUT -j DROP || true",
            ip6tables + "-D FORWARD -j DROP 2> /dev/null || true",
            ip6tables + "-I FORWARD -j DROP",
            iptables + "-t nat -D PREROUTING -j " + NAT_PREROUTING_CORE + " 2> /dev/null || true",
            iptables + "-D FORWARD -j " + FILTER_FORWARD_CORE + " 2> /dev/null || true",
            busybox + "sleep 1",
            iptables + "-t nat -A PREROUTING -j " + NAT_PREROUTING_CORE,
            iptables + "-A FORWARD -j " + FILTER_FORWARD_CORE,
            iptables + "-D FORWARD -j DROP 2> /dev/null || true"
        ))

        return tetheringCommands
    }

    fun setInterfaceNames() {
        val checker = internetSharingChecker.get()
        checker.updateData()
        apIsOn = checker.isApOn
        usbTetherOn = checker.isUsbTetherOn
        ethernetOn = checker.isEthernetOn
        wifiAPAddressesRange = checker.wifiAPAddressesRange
        usbModemAddressesRange = checker.usbModemAddressesRange
        vpnInterfaceName = checker.vpnInterfaceName
        wifiAPInterfaceName = checker.wifiAPInterfaceName
        usbModemInterfaceName = checker.usbModemInterfaceName
        ethernetInterfaceName = checker.ethernetInterfaceName
    }

    fun fixTTLCommands(): List<String> {
        val pathVars = pathVarsLazy.get()

        preferenceRepository.get().setBoolPreference("TTLisFixed", true)

        var dnscryptBootstrapResolver = QUAD_DNS_41
        for (resolver in pathVars.dnsCryptFallbackRes.split(", ?".toRegex())) {
            if (resolver.matches(IPv4_REGEX.toRegex())) {
                dnscryptBootstrapResolver = resolver
                break
            }
        }

        val commands: MutableList<String> = arrayListOf(
            iptables + "-D FORWARD -j DROP 2> /dev/null || true",
            iptables + "-I FORWARD -j DROP",
            "echo 64 > /proc/sys/net/ipv4/ip_default_ttl 2> /dev/null || true",
            "ip rule delete from " + wifiAPAddressesRange + " lookup 63 2> /dev/null || true",
            "ip rule delete from " + usbModemAddressesRange + " lookup 62 2> /dev/null || true",
            "ip rule delete from " + addressLocalPC + " lookup 64 2> /dev/null || true",
            "ip route delete default dev " + vpnInterfaceName + " scope link table 63 2> /dev/null || true",
            "ip route delete default dev " + vpnInterfaceName + " scope link table 62 2> /dev/null || true",
            "ip route delete default dev " + vpnInterfaceName + " scope link table 64 2> /dev/null || true",
            "ip route delete " + wifiAPAddressesRange + " dev " + wifiAPInterfaceName + " scope link table 63 2> /dev/null || true",
            "ip route delete " + usbModemAddressesRange + " dev " + usbModemInterfaceName + " scope link table 62 2> /dev/null || true",
            "ip route delete " + addressLocalPC + " dev " + ethernetInterfaceName + " scope link table 64 2> /dev/null || true",
            "ip route delete broadcast 255.255.255.255 dev " + wifiAPInterfaceName + " scope link table 63 2> /dev/null || true",
            "ip route delete broadcast 255.255.255.255 dev " + usbModemInterfaceName + " scope link table 62 2> /dev/null || true",
            "ip route delete broadcast 255.255.255.255 dev " + ethernetInterfaceName + " scope link table 64 2> /dev/null || true",
            iptables + "-D FORWARD -j " + FILTER_FORWARD_CORE + " 2> /dev/null || true",
            //iptables + "-t nat -D POSTROUTING -o " + vpnInterfaceName + " -j MASQUERADE || true",
            iptables + "-t nat -D " + NAT_PREROUTING_CORE + " -i " + wifiAPInterfaceName + " -p tcp -m tcp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver + " 2> /dev/null || true",
            iptables + "-t nat -D " + NAT_PREROUTING_CORE + " -i " + wifiAPInterfaceName + " -p udp -m udp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver + " 2> /dev/null || true",
            iptables + "-t nat -D " + NAT_PREROUTING_CORE + " -i " + usbModemInterfaceName + " -p tcp -m tcp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver + " 2> /dev/null || true",
            iptables + "-t nat -D " + NAT_PREROUTING_CORE + " -i " + usbModemInterfaceName + " -p udp -m udp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver + " 2> /dev/null || true",
            iptables + "-t nat -D " + NAT_PREROUTING_CORE + " -i " + ethernetInterfaceName + " -p tcp -m tcp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver + " 2> /dev/null || true",
            iptables + "-t nat -D " + NAT_PREROUTING_CORE + " -i " + ethernetInterfaceName + " -p udp -m udp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver + " 2> /dev/null || true",
            iptables + "-t nat -I " + NAT_PREROUTING_CORE + " -i " + wifiAPInterfaceName + " -p tcp -m tcp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver,
            iptables + "-t nat -I " + NAT_PREROUTING_CORE + " -i " + wifiAPInterfaceName + " -p udp -m udp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver,
            iptables + "-t nat -I " + NAT_PREROUTING_CORE + " -i " + usbModemInterfaceName + " -p tcp -m tcp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver,
            iptables + "-t nat -I " + NAT_PREROUTING_CORE + " -i " + usbModemInterfaceName + " -p udp -m udp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver,
            iptables + "-t nat -I " + NAT_PREROUTING_CORE + " -i " + ethernetInterfaceName + " -p tcp -m tcp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver,
            iptables + "-t nat -I " + NAT_PREROUTING_CORE + " -i " + ethernetInterfaceName + " -p udp -m udp --dport 53 -j DNAT --to-destination " + dnscryptBootstrapResolver,
            iptables + "-D " + FILTER_FORWARD_CORE + " -m state --state ESTABLISHED,RELATED -j RETURN 2> /dev/null && "
                    + iptables + "-I " + FILTER_FORWARD_CORE + " -m state --state ESTABLISHED,RELATED -j ACCEPT 2> /dev/null || true",
            iptables + "-D " + FILTER_FORWARD_CORE + " -o !" + vpnInterfaceName + " -j REJECT 2> /dev/null || "
                    + iptables + "-D " + FILTER_FORWARD_CORE + " -o !tun0 -j REJECT 2> /dev/null || "
                    + iptables + "-D " + FILTER_FORWARD_CORE + " -o !tun1 -j REJECT 2> /dev/null",
            iptables + "-I " + FILTER_FORWARD_CORE + " -o !" + vpnInterfaceName + " -j REJECT",
            iptables + "-D " + FILTER_FORWARD_CORE + " -p all -j ACCEPT 2> /dev/null || true",
            iptables + "-A " + FILTER_FORWARD_CORE + " -p all -j ACCEPT 2> /dev/null",
            iptables + "-I FORWARD -j " + FILTER_FORWARD_CORE + " 2> /dev/null",
            //iptables + "-t nat -I POSTROUTING -o " + vpnInterfaceName + " -j MASQUERADE",
            "ip rule add from " + wifiAPAddressesRange + " lookup 63 2> /dev/null || true",
            "ip rule add from " + usbModemAddressesRange + " lookup 62 2> /dev/null || true",
            "ip rule add from " + addressLocalPC + " lookup 64 2> /dev/null || true",
            "ip route add default dev " + vpnInterfaceName + " scope link table 63 || true",
            "ip route add default dev " + vpnInterfaceName + " scope link table 62 || true",
            "ip route add default dev " + vpnInterfaceName + " scope link table 64 || true",
            "ip route add " + wifiAPAddressesRange + " dev " + wifiAPInterfaceName + " scope link table 63 || true",
            "ip route add " + usbModemAddressesRange + " dev " + usbModemInterfaceName + " scope link table 62 || true",
            "ip route add " + addressLocalPC + " dev " + ethernetInterfaceName + " scope link table 64 || true",
            "ip route add broadcast 255.255.255.255 dev " + wifiAPInterfaceName + " scope link table 63 || true",
            "ip route add broadcast 255.255.255.255 dev " + usbModemInterfaceName + " scope link table 62 || true",
            "ip route add broadcast 255.255.255.255 dev " + ethernetInterfaceName + " scope link table 64 || true",
            iptables + "-D FORWARD -j DROP 2> /dev/null || true"
            //iptables + "-D PREROUTING -t mangle -p udp --dport 53 -j MARK --set-mark 111 || true",
            //iptables + "-A PREROUTING -t mangle -p udp --dport 53 -j MARK --set-mark 111",
            //"ip rule add from " + wifiAPAddressesRange + " fwmark 111 lookup 62"
        )

        return cleanupCommands(commands)
    }

    private fun unfixTTLCommands(): List<String> {
        preferenceRepository.get().setBoolPreference("TTLisFixed", false)

        val commands: List<String> = if (ethernetOn) {
            arrayListOf(
                "ip rule delete from " + wifiAPAddressesRange + " lookup 63 2> /dev/null || true",
                "ip rule delete from " + usbModemAddressesRange + " lookup 62 2> /dev/null || true",
                "ip rule delete from " + addressLocalPC + " lookup 64 2> /dev/null || true"
            )
        } else {
            arrayListOf(
                "ip rule delete from " + wifiAPAddressesRange + " lookup 63 2> /dev/null || true",
                "ip rule delete from " + usbModemAddressesRange + " lookup 62 2> /dev/null || true"
                //iptables + "-D " + FILTER_FORWARD_CORE + " -o !" + vpnInterfaceName + " -j REJECT 2> /dev/null || true",
                //iptables + "-t nat -D POSTROUTING -o " + vpnInterfaceName + " -j MASQUERADE || true"
            )
        }

        return commands
    }

    private fun cleanupCommands(commands: MutableList<String>): List<String> {
        if (!usbTetherOn) {
            for (i in commands.indices) {
                val command = commands[i]
                if (command.contains(usbModemInterfaceName) || command.contains(usbModemAddressesRange) || command.contains("table 62")) {
                    commands[i] = ""
                }
            }
        }

        if (!apIsOn) {
            for (i in commands.indices) {
                val command = commands[i]
                if (command.contains(wifiAPInterfaceName) || command.contains(wifiAPAddressesRange) || command.contains("table 63")) {
                    commands[i] = ""
                }
            }
        }

        if (!ethernetOn || addressLocalPC.trim().isEmpty()) {
            for (i in commands.indices) {
                val command = commands[i]
                if (command.contains(ethernetInterfaceName) || command.contains(addressLocalPC) || command.contains("table 64")) {
                    commands[i] = ""
                }
            }
        }

        return commands
    }

    //Should be called after setInterfaceNames()
    fun isTetheringActive(): Boolean {
        return apIsOn || usbTetherOn
    }

    companion object {

        @Volatile
        @JvmField
        var apIsOn = false
        @Volatile
        @JvmField
        var usbTetherOn = false
        @Volatile
        @JvmField
        var ethernetOn = false

        @Volatile
        @JvmField
        var wifiAPAddressesRange = "192.168.43.0/24"
        @Volatile
        @JvmField
        var usbModemAddressesRange = "192.168.42.0/24"
        @JvmField
        var addressLocalPC = Constants.STANDARD_ADDRESS_LOCAL_PC

        @JvmField
        var vpnInterfaceName = Constants.STANDARD_VPN_INTERFACE_NAME
        @JvmField
        var wifiAPInterfaceName = Constants.STANDARD_WIFI_INTERFACE_NAME
        @JvmField
        var usbModemInterfaceName = Constants.STANDARD_USB_MODEM_INTERFACE_NAME

        private var ethernetInterfaceName = Constants.STANDARD_ETHERNET_INTERFACE_NAME
    }
}
