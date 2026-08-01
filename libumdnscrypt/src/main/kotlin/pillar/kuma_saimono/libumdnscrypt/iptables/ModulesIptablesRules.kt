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
import android.os.Handler
import android.text.TextUtils
import android.util.Pair
import androidx.preference.PreferenceManager
import dagger.Lazy
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.arp.ArpScanner
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.iptables.IptablesConstants.FILTER_FORWARD_CORE
import pillar.kuma_saimono.libumdnscrypt.iptables.IptablesConstants.FILTER_OUTPUT_BLOCKING
import pillar.kuma_saimono.libumdnscrypt.iptables.IptablesConstants.FILTER_OUTPUT_CORE
import pillar.kuma_saimono.libumdnscrypt.iptables.IptablesConstants.NAT_OUTPUT_CORE
import pillar.kuma_saimono.libumdnscrypt.iptables.IptablesConstants.NAT_PREROUTING_CORE
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.C_DNS_41
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.C_DNS_42
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.DNS_OVER_TLS_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.G_DNG_41
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.G_DNS_42
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.HTTP_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv4_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.LOOPBACK_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.NETWORK_STACK_DEFAULT_UID
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.NFLOG_GROUP
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.NFLOG_PREFIX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.QUAD_DNS_41
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RUNNING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.ROOT_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ARP_SPOOFING_BLOCK_INTERNET
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ARP_SPOOFING_DETECTION
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.BLOCK_HTTP
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.BYPASS_LAN
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.CONNECTION_LOGS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.GSM_ON_REQUESTED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.KILL_SWITCH
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PREVENT_DNS_LEAKS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.RUN_MODULES_WITH_ROOT
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.WIFI_ON_REQUESTED
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark.Companion.NULL_MARK
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils
import javax.inject.Inject
import javax.inject.Named

class ModulesIptablesRules(context: Context) : IptablesRulesSender(
    context,
    App.instance.daggerComponent.getPathVars().get()
) {

    @Inject
    lateinit var preferenceRepository: Lazy<PreferenceRepository>

    @Inject
    @field:Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    lateinit var defaultPreferences: Lazy<SharedPreferences>

    @Inject
    lateinit var handler: Lazy<Handler>

    @Inject
    lateinit var killSwitchNotification: Lazy<KillSwitchNotification>

    private var iptables = "iptables "
    private var ip6tables = "ip6tables "
    private var busybox = "busybox "

    init {
        App.instance.subcomponentsManager.modulesServiceSubcomponent().inject(this)
    }

    override fun configureIptables(
        dnsCryptState: ModuleState,
        firewallState: ModuleState
    ): List<String> {

        iptables = pathVars.getIptablesPath()
        ip6tables = pathVars.getIp6tablesPath()
        busybox = pathVars.busyboxPath

        val shPref = PreferenceManager.getDefaultSharedPreferences(context)
        val preferences = preferenceRepository.get()
        runModulesWithRoot = shPref.getBoolean(RUN_MODULES_WITH_ROOT, false)
        lan = shPref.getBoolean(BYPASS_LAN, true)
        blockHttp = shPref.getBoolean(BLOCK_HTTP, false)
        preventDnsLeaks = shPref.getBoolean(PREVENT_DNS_LEAKS, false)
        apIsOn = preferences.getBoolPreference(TortaeKeys.WIFI_ACCESS_POINT_IS_ON)
        modemIsOn = preferences.getBoolPreference(TortaeKeys.USB_MODEM_IS_ON)
        val showConnectionLogs = defaultPreferences.get().getBoolean(CONNECTION_LOGS, true)

        val modulesStatus = ModulesStatus.getInstance()

        val arpSpoofingDetection = shPref.getBoolean(ARP_SPOOFING_DETECTION, false)
        val blockInternetWhenArpAttackDetected = shPref.getBoolean(ARP_SPOOFING_BLOCK_INTERNET, false)
        val mitmDetected = ArpScanner.arpAttackDetected || ArpScanner.dhcpGatewayAttackDetected

        val killSwitch = shPref.getBoolean(KILL_SWITCH, false)

        var dnscryptBootstrapResolver = QUAD_DNS_41
        for (resolver in pathVars.dnsCryptFallbackRes.split(", ?".toRegex())) {
            if (resolver.matches(IPv4_REGEX.toRegex())) {
                dnscryptBootstrapResolver = resolver
                break
            }
        }

        var commands: MutableList<String> = ArrayList()

        var appUID = pathVars.appUidStr
        if (runModulesWithRoot) {
            appUID = "0"
        }

        val bypassLanNatToBypassLanFilter = getBypassLanRules()
        val bypassLanNat = bypassLanNatToBypassLanFilter.first
        val bypassLanFilter = bypassLanNatToBypassLanFilter.second

        var blockRejectAddressFilter = ""
        var blockHttpRuleNatTCP = ""
        var blockHttpRuleNatUDP = ""
        if (blockHttp) {
            blockRejectAddressFilter = iptables + "-A " + FILTER_OUTPUT_CORE + " -d " + rejectAddress + " -j REJECT"
            blockHttpRuleNatTCP = iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p tcp --dport " + HTTP_PORT + " -j DNAT --to-destination " + rejectAddress
            blockHttpRuleNatUDP = iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p udp --dport " + HTTP_PORT + " -j DNAT --to-destination " + rejectAddress
        }

        var blockTlsRuleNatTCP = ""
        var blockTlsRuleNatUDP = ""
        var blockGDNSNat = ""
        if (preventDnsLeaks) {
            if (!blockHttp) {
                blockRejectAddressFilter = iptables + "-A " + FILTER_OUTPUT_CORE + " -d " + rejectAddress + " -j REJECT"
            }
            blockTlsRuleNatTCP = iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p tcp --dport " + DNS_OVER_TLS_PORT + " -j DNAT --to-destination " + rejectAddress
            blockTlsRuleNatUDP = iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p udp --dport " + DNS_OVER_TLS_PORT + " -j DNAT --to-destination " + rejectAddress
            blockGDNSNat = iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p tcp -d " + G_DNG_41 + " ! --dport 53 -j DNAT --to-destination " + rejectAddress + "; " +
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p udp -d " + G_DNG_41 + " ! --dport 53 -j DNAT --to-destination " + rejectAddress + "; " +
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p tcp -d " + G_DNS_42 + " ! --dport 53 -j DNAT --to-destination " + rejectAddress + "; " +
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p udp -d " + G_DNS_42 + " ! --dport 53 -j DNAT --to-destination " + rejectAddress + "; " +
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p tcp -d " + C_DNS_41 + " ! --dport 53 -j DNAT --to-destination " + rejectAddress + "; " +
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p udp -d " + C_DNS_41 + " ! --dport 53 -j DNAT --to-destination " + rejectAddress + "; " +
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p tcp -d " + C_DNS_42 + " ! --dport 53 -j DNAT --to-destination " + rejectAddress + "; " +
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p udp -d " + C_DNS_42 + " ! --dport 53 -j DNAT --to-destination " + rejectAddress
        }

        val unblockHOTSPOT = iptables + "-D FORWARD -j DROP 2> /dev/null || true"
        var blockHOTSPOT = iptables + "-I FORWARD -j DROP"
        if (apIsOn || modemIsOn) {
            blockHOTSPOT = ""
        }

        val dnsCryptSystemDNSAllowed = modulesStatus.isSystemDNSAllowed

        //These rules will be removed after DNSCrypt is bootstrapped
        var dnsCryptSystemDNSAllowedNat = ""
        var dnsCryptSystemDNSAllowedFilter = ""
        var dnsCryptRootDNSAllowedNat = ""
        var dnsCryptRootDNSAllowedFilter = ""
        var dnsCryptDnsDaemonDNSAllowedNat = ""
        var dnsCryptDnsDaemonDNSAllowedFilter = ""
        if (dnsCryptSystemDNSAllowed) {
            dnsCryptSystemDNSAllowedFilter = iptables + "-A " + FILTER_OUTPUT_CORE + " -p udp --dport 53 -m owner --uid-owner " + appUID + " -j ACCEPT"
            dnsCryptSystemDNSAllowedNat = iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p udp --dport 53 -m owner --uid-owner " + appUID + " -j ACCEPT"
            if (!runModulesWithRoot) {
                dnsCryptRootDNSAllowedNat = iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p udp --dport 53 -m owner --uid-owner 0 -j ACCEPT"
                dnsCryptRootDNSAllowedFilter = iptables + "-A " + FILTER_OUTPUT_CORE + " -p udp --dport 53 -m owner --uid-owner 0 -j ACCEPT"
                dnsCryptDnsDaemonDNSAllowedNat = iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p udp --dport 53 -m owner --uid-owner 1051 -j ACCEPT"
                dnsCryptDnsDaemonDNSAllowedFilter = iptables + "-A " + FILTER_OUTPUT_CORE + " -p udp --dport 53 -m owner --uid-owner 1051 -j ACCEPT"
            }
        }

        val criticalUidsAllowed = getCriticalUidsAllowedRules()

        var nflogDns = ""
        val nflogPackets: String
        if (showConnectionLogs) {
            nflogDns = TextUtils.join("; ", listOf(
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -p udp -s " + LOOPBACK_ADDRESS + " --sport " + pathVars.dnsCryptPort + " -m limit --limit 1000/min -j NFLOG --nflog-prefix " + NFLOG_PREFIX + " --nflog-group " + NFLOG_GROUP + " 2> /dev/null || true",
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -p tcp -s " + LOOPBACK_ADDRESS + " --sport " + pathVars.dnsCryptPort + " -m limit --limit 1000/min -j NFLOG --nflog-prefix " + NFLOG_PREFIX + " --nflog-group " + NFLOG_GROUP + " 2> /dev/null || true"
            ))
            nflogPackets = TextUtils.join("; ", listOf(
                    iptables + "-t mangle -D OUTPUT -p all -m owner ! --uid-owner " + appUID + " -m limit --limit 1000/min -j NFLOG --nflog-prefix " + NFLOG_PREFIX + " --nflog-group " + NFLOG_GROUP + " 2> /dev/null || true",
                    iptables + "-t mangle -D OUTPUT -p all -m limit --limit 1000/min -j NFLOG --nflog-prefix " + NFLOG_PREFIX + " --nflog-group " + NFLOG_GROUP + " 2> /dev/null || true",
                    iptables + "-t mangle -I OUTPUT -p all -m limit --limit 1000/min -j NFLOG --nflog-prefix " + NFLOG_PREFIX + " --nflog-group " + NFLOG_GROUP + " 2> /dev/null || true"
            ))
        } else {
            nflogPackets = TextUtils.join("; ", listOf(
                    iptables + "-t mangle -D OUTPUT -p all -m owner ! --uid-owner " + appUID + " -m limit --limit 1000/min -j NFLOG --nflog-prefix " + NFLOG_PREFIX + " --nflog-group " + NFLOG_GROUP + " 2> /dev/null || true",
                    iptables + "-t mangle -D OUTPUT -p all -m limit --limit 1000/min -j NFLOG --nflog-prefix " + NFLOG_PREFIX + " --nflog-group " + NFLOG_GROUP + " 2> /dev/null || true"
            ))
        }

        if (arpSpoofingDetection && blockInternetWhenArpAttackDetected && mitmDetected) {

            commands = getBlockingRules(appUID, blockHOTSPOT, unblockHOTSPOT)

        } else if (killSwitch
                && dnsCryptState != RUNNING
                && firewallState != RUNNING && firewallState != STARTING) {

            showKillSwitchNotification()

            commands = getBlockingRules(appUID, blockHOTSPOT, unblockHOTSPOT)

            if (modulesStatus.mode == ROOT_MODE) {
                modulesStatus.setFirewallState(ModuleState.STOPPED, preferences)
            }

        } else if (dnsCryptState == RUNNING) {

            cancelKillSwitchNotificationIfNeeded()

            commands = arrayListOf(
                    iptables + "-F " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null",
                    iptables + "-D OUTPUT -j " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null || true",
                    iptables + "-N " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null",
                    iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -m state --state ESTABLISHED,RELATED -j RETURN",
                    iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -m owner --uid-owner " + appUID + " -j RETURN",
                    criticalUidsAllowed,
                    iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -j DROP",
                    iptables + "-I OUTPUT -j " + FILTER_OUTPUT_BLOCKING,
                    ip6tables + "-D OUTPUT -j DROP 2> /dev/null || true",
                    ip6tables + "-D OUTPUT -m owner --uid-owner " + appUID + " -j ACCEPT 2> /dev/null || true",
                    ip6tables + "-I OUTPUT -j DROP",
                    ip6tables + "-I OUTPUT -m owner --uid-owner " + appUID + " -j ACCEPT",
                    iptables + "-t nat -F " + NAT_OUTPUT_CORE + " 2> /dev/null",
                    iptables + "-t nat -D OUTPUT -j " + NAT_OUTPUT_CORE + " 2> /dev/null || true",
                    iptables + "-F " + FILTER_OUTPUT_CORE + " 2> /dev/null",
                    iptables + "-D OUTPUT -j " + FILTER_OUTPUT_CORE + " 2> /dev/null || true",
                    busybox + "sleep 1 || true",
                    iptables + "-t nat -N " + NAT_OUTPUT_CORE + " 2> /dev/null",
                    iptables + "-t nat -I OUTPUT -j " + NAT_OUTPUT_CORE,
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p all -d 127.0.0.1/32 -j RETURN",
                    dnsCryptSystemDNSAllowedNat,
                    dnsCryptRootDNSAllowedNat,
                    dnsCryptDnsDaemonDNSAllowedNat,
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p udp -d " + dnscryptBootstrapResolver + " --dport 53 -m owner --uid-owner " + appUID + " -j ACCEPT",
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:" + pathVars.dnsCryptPort,
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p tcp --dport 53 -j DNAT --to-destination 127.0.0.1:" + pathVars.dnsCryptPort,
                    blockHttpRuleNatTCP,
                    blockHttpRuleNatUDP,
                    blockTlsRuleNatTCP,
                    blockTlsRuleNatUDP,
                    blockGDNSNat,
                    iptables + "-N " + FILTER_OUTPUT_CORE + " 2> /dev/null",
                    nflogDns,
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -d 127.0.0.1/32 -p udp -m udp --dport " + pathVars.dnsCryptPort + " -j ACCEPT",
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -d 127.0.0.1/32 -p tcp -m tcp --dport " + pathVars.dnsCryptPort + " -j ACCEPT",
                    dnsCryptSystemDNSAllowedFilter,
                    dnsCryptRootDNSAllowedFilter,
                    dnsCryptDnsDaemonDNSAllowedFilter,
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -p udp -d " + dnscryptBootstrapResolver + " --dport 53 -m owner --uid-owner " + appUID + " -j ACCEPT",
                    blockRejectAddressFilter,
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -m state --state ESTABLISHED,RELATED -j RETURN",
                    iptables + "-I OUTPUT -j " + FILTER_OUTPUT_CORE,
                    nflogPackets,
                    unblockHOTSPOT,
                    blockHOTSPOT
            )

            val commandsTether = tethering.activateTethering(false)
            if (commandsTether.isNotEmpty()) {
                commands.addAll(commandsTether)
            }
            // Garmatin per-app firewall rules removed: the per-app firewall decision now lives in the
            // native Warden (VPN-mode datapath verdict). NAT/FILTER/DNS-redirect/kill-switch stay.
            commands.add(iptables + "-D OUTPUT -j " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null || true")
        } else if (dnsCryptState == STOPPED
                && (firewallState == STARTING || firewallState == RUNNING)) {

            cancelKillSwitchNotificationIfNeeded()

            commands = arrayListOf(
                    iptables + "-F " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null",
                    iptables + "-D OUTPUT -j " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null || true",
                    iptables + "-N " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null",
                    iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -m state --state ESTABLISHED,RELATED -j RETURN",
                    iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -m owner --uid-owner " + appUID + " -j RETURN",
                    criticalUidsAllowed,
                    iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -j DROP",
                    iptables + "-I OUTPUT -j " + FILTER_OUTPUT_BLOCKING,
                    ip6tables + "-D OUTPUT -j DROP 2> /dev/null || true",
                    ip6tables + "-D OUTPUT -m owner --uid-owner " + appUID + " -j ACCEPT 2> /dev/null || true",
                    ip6tables + "-I OUTPUT -j DROP",
                    ip6tables + "-I OUTPUT -m owner --uid-owner " + appUID + " -j ACCEPT",
                    iptables + "-t nat -F " + NAT_OUTPUT_CORE + " 2> /dev/null",
                    iptables + "-t nat -D OUTPUT -j " + NAT_OUTPUT_CORE + " 2> /dev/null || true",
                    iptables + "-F " + FILTER_OUTPUT_CORE + " 2> /dev/null",
                    iptables + "-D OUTPUT -j " + FILTER_OUTPUT_CORE + " 2> /dev/null || true",
                    busybox + "sleep 1 || true",
                    iptables + "-t nat -N " + NAT_OUTPUT_CORE + " 2> /dev/null",
                    iptables + "-t nat -I OUTPUT -j " + NAT_OUTPUT_CORE,
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -p all -d 127.0.0.1/32 -j RETURN",
                    blockHttpRuleNatTCP,
                    blockHttpRuleNatUDP,
                    iptables + "-N " + FILTER_OUTPUT_CORE + " 2> /dev/null",
                    nflogDns,
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -p udp -m udp --dport 53 -j ACCEPT",
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -p tcp -m tcp --dport 53 -j ACCEPT",
                    blockRejectAddressFilter,
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -m state --state ESTABLISHED,RELATED -j RETURN",
                    iptables + "-I OUTPUT -j " + FILTER_OUTPUT_CORE,
                    nflogPackets,
                    unblockHOTSPOT,
                    blockHOTSPOT
            )

            val commandsTether = tethering.activateTethering(false)
            if (commandsTether.isNotEmpty()) {
                commands.addAll(commandsTether)
            }
            // Garmatin per-app firewall rules removed: the per-app firewall decision now lives in the
            // native Warden (VPN-mode datapath verdict). NAT/FILTER/DNS-redirect/kill-switch stay.
            commands.add(iptables + "-D OUTPUT -j " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null || true")
        } else if (dnsCryptState == STOPPED) {

            cancelKillSwitchNotificationIfNeeded()

            commands = arrayListOf(
                    iptables + "-D OUTPUT -j " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null || true",
                    ip6tables + "-D OUTPUT -j DROP 2> /dev/null || true",
                    ip6tables + "-D OUTPUT -m owner --uid-owner " + appUID + " -j ACCEPT 2> /dev/null || true",
                    iptables + "-t nat -F " + NAT_OUTPUT_CORE + " 2> /dev/null || true",
                    iptables + "-t nat -D OUTPUT -j " + NAT_OUTPUT_CORE + " 2> /dev/null || true",
                    iptables + "-F " + FILTER_OUTPUT_CORE + " 2> /dev/null || true",
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -j RETURN 2> /dev/null || true",
                    iptables + "-D OUTPUT -j " + FILTER_OUTPUT_CORE + " 2> /dev/null || true",
                    iptables + "-t mangle -D OUTPUT -p all -m owner ! --uid-owner " + appUID + " -m limit --limit 1000/min -j NFLOG --nflog-prefix " + NFLOG_PREFIX + " --nflog-group " + NFLOG_GROUP + " 2> /dev/null || true",
                    unblockHOTSPOT
            )

            val commandsTether = tethering.activateTethering(false)
            if (commandsTether.isNotEmpty()) {
                commands.addAll(commandsTether)
            }
            // Garmatin per-app firewall clear removed (the legacy iptables-firewall class is gone);
            // the FILTER/NAT core teardown above already tears down the live chains.
        }

        return commands
    }

    fun getBlockingRules(appUID: String, blockHOTSPOT: String, unblockHOTSPOT: String): MutableList<String> {
        val bypassLanNatToBypassLanFilter = getBypassLanRules()
        val bypassLanFilter = bypassLanNatToBypassLanFilter.second
        val criticalUidsAllowed = getCriticalUidsAllowedRules()
        return arrayListOf(
                iptables + "-F " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null",
                iptables + "-D OUTPUT -j " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null || true",
                iptables + "-N " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null",
                iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -m state --state ESTABLISHED,RELATED -j RETURN",
                iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -m owner --uid-owner " + appUID + " -j RETURN",
                criticalUidsAllowed,
                iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -j DROP",
                iptables + "-I OUTPUT -j " + FILTER_OUTPUT_BLOCKING,
                ip6tables + "-D OUTPUT -j DROP 2> /dev/null || true",
                ip6tables + "-D OUTPUT -m owner --uid-owner " + appUID + " -j ACCEPT 2> /dev/null || true",
                ip6tables + "-I OUTPUT -j DROP",
                ip6tables + "-I OUTPUT -m owner --uid-owner " + appUID + " -j ACCEPT",
                iptables + "-t nat -F " + NAT_OUTPUT_CORE + " 2> /dev/null",
                iptables + "-t nat -D OUTPUT -j " + NAT_OUTPUT_CORE + " 2> /dev/null || true",
                iptables + "-F " + FILTER_OUTPUT_CORE + " 2> /dev/null",
                iptables + "-D OUTPUT -j " + FILTER_OUTPUT_CORE + " 2> /dev/null || true",
                busybox + "sleep 1 || true",
                iptables + "-N " + FILTER_OUTPUT_CORE + " 2> /dev/null",
                bypassLanFilter,
                iptables + "-A " + FILTER_OUTPUT_CORE + " -m owner ! --uid-owner " + appUID + " -j REJECT",
                iptables + "-I OUTPUT -j " + FILTER_OUTPUT_CORE,
                unblockHOTSPOT,
                blockHOTSPOT,
                iptables + "-D OUTPUT -j " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null || true"
        )
    }

    override fun fastUpdate(): List<String> {

        val shPref = PreferenceManager.getDefaultSharedPreferences(context)
        runModulesWithRoot = shPref.getBoolean(RUN_MODULES_WITH_ROOT, false)
        var appUID = pathVars.appUidStr
        if (runModulesWithRoot) {
            appUID = "0"
        }

        val unblockHOTSPOT = iptables + "-D FORWARD -j DROP 2> /dev/null || true"
        var blockHOTSPOT = iptables + "-I FORWARD -j DROP"
        if (apIsOn || modemIsOn) {
            blockHOTSPOT = ""
        }

        val criticalUidsAllowed = getCriticalUidsAllowedRules()

        val commands: MutableList<String> = arrayListOf(
                iptables + "-F " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null",
                iptables + "-D OUTPUT -j " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null || true",
                iptables + "-N " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null",
                iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -m state --state ESTABLISHED,RELATED -j RETURN",
                iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -m owner --uid-owner " + appUID + " -j RETURN",
                criticalUidsAllowed,
                iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -j DROP",
                iptables + "-I OUTPUT -j " + FILTER_OUTPUT_BLOCKING,
                ip6tables + "-D OUTPUT -j DROP 2> /dev/null || true",
                ip6tables + "-D OUTPUT -m owner --uid-owner " + appUID + " -j ACCEPT 2> /dev/null || true",
                ip6tables + "-I OUTPUT -j DROP",
                ip6tables + "-I OUTPUT -m owner --uid-owner " + appUID + " -j ACCEPT",
                iptables + "-t nat -D OUTPUT -j " + NAT_OUTPUT_CORE + " 2> /dev/null || true",
                iptables + "-D OUTPUT -j " + FILTER_OUTPUT_CORE + " 2> /dev/null || true",
                busybox + "sleep 1 || true",
                iptables + "-t nat -I OUTPUT -j " + NAT_OUTPUT_CORE,
                iptables + "-I OUTPUT -j " + FILTER_OUTPUT_CORE,
                unblockHOTSPOT,
                blockHOTSPOT
        )

        val commandsTether = tethering.fastUpdate()
        if (commandsTether.isNotEmpty()) {
            commands.addAll(commandsTether)
        }
        // Garmatin per-app firewall fast-update removed: the per-app firewall decision now lives in
        // the native Warden (VPN-mode datapath verdict). The kill-switch teardown below stays.
        commands.add(iptables + "-D OUTPUT -j " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null || true")

        return commands
    }

    override fun clearAll(): List<String> {
        val modulesStatus = ModulesStatus.getInstance()
        if (modulesStatus.isFixTTL) {
            modulesStatus.setIptablesRulesUpdateRequested(context, true)
        }

        cancelKillSwitchNotificationIfNeeded()

        val shPref = PreferenceManager.getDefaultSharedPreferences(context)
        runModulesWithRoot = shPref.getBoolean(RUN_MODULES_WITH_ROOT, false)
        var appUID = pathVars.appUidStr
        if (runModulesWithRoot) {
            appUID = "0"
        }

        val commands: MutableList<String> = arrayListOf(
                iptables + "-D OUTPUT -j " + FILTER_OUTPUT_BLOCKING + " 2> /dev/null || true",
                ip6tables + "-D OUTPUT -j DROP 2> /dev/null || true",
                ip6tables + "-D OUTPUT -m owner --uid-owner " + appUID + " -j ACCEPT 2> /dev/null || true",
                iptables + "-t nat -F " + NAT_OUTPUT_CORE + " 2> /dev/null || true",
                iptables + "-t nat -D OUTPUT -j " + NAT_OUTPUT_CORE + " 2> /dev/null || true",
                iptables + "-F " + FILTER_OUTPUT_CORE + " 2> /dev/null || true",
                iptables + "-A " + FILTER_OUTPUT_CORE + " -j RETURN 2> /dev/null || true",
                iptables + "-D OUTPUT -j " + FILTER_OUTPUT_CORE + " 2> /dev/null || true",

                ip6tables + "-D INPUT -j DROP 2> /dev/null || true",
                ip6tables + "-D FORWARD -j DROP 2> /dev/null || true",
                iptables + "-t nat -F " + NAT_PREROUTING_CORE + " 2> /dev/null || true",
                iptables + "-F " + FILTER_FORWARD_CORE + " 2> /dev/null || true",
                iptables + "-t nat -D PREROUTING -j " + NAT_PREROUTING_CORE + " 2> /dev/null || true",
                iptables + "-D FORWARD -j " + FILTER_FORWARD_CORE + " 2> /dev/null || true",
                iptables + "-D FORWARD -j DROP 2> /dev/null || true",

                iptables + "-t mangle -D OUTPUT -p all -m owner ! --uid-owner " + appUID + " -m limit --limit 1000/min -j NFLOG --nflog-prefix " + NFLOG_PREFIX + " --nflog-group " + NFLOG_GROUP + " 2> /dev/null || true",

                "ip rule delete from " + Tethering.wifiAPAddressesRange + " lookup 63 2> /dev/null || true",
                "ip rule delete from " + Tethering.usbModemAddressesRange + " lookup 62 2> /dev/null || true"
        )

        // Garmatin per-app firewall clear removed (the legacy iptables-firewall class is gone); the
        // FILTER/NAT/FORWARD core teardown above already tears down the live chains.

        return commands
    }

    override fun refreshFixTTLRules() {
        val savedVpnInterfaceName = Tethering.vpnInterfaceName
        val savedWifiAPInterfaceName = Tethering.wifiAPInterfaceName
        val savedUsbModemInterfaceName = Tethering.usbModemInterfaceName

        tethering.setInterfaceNames()

        if (Tethering.vpnInterfaceName != savedVpnInterfaceName
                || Tethering.wifiAPInterfaceName != savedWifiAPInterfaceName
                || Tethering.usbModemInterfaceName != savedUsbModemInterfaceName
                || isLastIptablesCommandsReturnError()) {

            sendToRootExecService(tethering.fixTTLCommands())

            logi("ModulesIptablesRules Refresh Fix TTL Rules vpnInterfaceName = " + Tethering.vpnInterfaceName)
        }
    }

    private fun removeRedundantSymbols(stringBuilder: StringBuilder): String {
        return if (stringBuilder.length > 2) {
            stringBuilder.substring(0, stringBuilder.length - 2)
        } else {
            ""
        }
    }

    private fun getBypassLanRules(): Pair<String, String> {
        val bypassLanNat: String
        val bypassLanFilter: String
        val nonTorRanges = StringBuilder()
        for (address in VpnUtils.nonTorList) {
            nonTorRanges.append(address).append(" ")
        }
        if (lan) {
            nonTorRanges.deleteCharAt(nonTorRanges.lastIndexOf(" "))

            bypassLanNat = "non_tor=\"" + nonTorRanges + "\"; " +
                    "for _lan in \$non_tor; do " +
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -d \$_lan -j RETURN; " +
                    "done"
            bypassLanFilter = "non_tor=\"" + nonTorRanges + "\"; " +
                    "for _lan in \$non_tor; do " +
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -d \$_lan -j RETURN; " +
                    "done"
        } else {
            bypassLanNat = "non_tor=\"" + nonTorRanges + "\"; " +
                    "for _lan in \$non_tor; do " +
                    iptables + "-t nat -A " + NAT_OUTPUT_CORE + " -m owner --uid-owner " + NETWORK_STACK_DEFAULT_UID + " -d \$_lan -j RETURN; " +
                    "done"
            bypassLanFilter = "non_tor=\"" + nonTorRanges + "\"; " +
                    "for _lan in \$non_tor; do " +
                    iptables + "-A " + FILTER_OUTPUT_CORE + " -m owner --uid-owner " + NETWORK_STACK_DEFAULT_UID + " -d \$_lan -j RETURN; " +
                    "done"
        }
        return Pair(bypassLanNat, bypassLanFilter)
    }

    private fun getCriticalUidsAllowedRules(): String {
        // Kill-switch critical-UID allowance: the network stack must keep reaching the net so a
        // captive-portal/connectivity check still resolves while the blocking chain is up. (The
        // Garmatin firewall's per-app critical-UID set only ever emitted NETWORK_STACK_DEFAULT_UID
        // here, so dropping the deleted legacy iptables-firewall dependency is behaviour-preserving.)
        val criticalUidsAllowedBuilder = StringBuilder()
        val criticalUids: MutableList<Int> = ArrayList()
        criticalUids.add(NETWORK_STACK_DEFAULT_UID)
        for (uid in criticalUids) {
            criticalUidsAllowedBuilder.append(iptables).append("-A " + FILTER_OUTPUT_BLOCKING + " -m owner --uid-owner ").append(uid).append(" -j RETURN; ")
        }

        return criticalUidsAllowedBuilder.toString() + iptables + "-A " + FILTER_OUTPUT_BLOCKING + " -p all -m owner ! --uid-owner 0:999999999 -j RETURN || true"
    }

    private fun showKillSwitchNotification() {
        killSwitchNotification.get().send()
        killSwitchActive = true
        logi("Kill switch activated")
    }

    private fun cancelKillSwitchNotificationIfNeeded() {
        if (killSwitchActive) {
            killSwitchNotification.get().cancel()
            killSwitchActive = false
            logi("Kill switch disabled")
        }
        enableInternetIfRequired()
    }

    private fun enableInternetIfRequired() {

        val preferences = preferenceRepository.get()
        val wifiOnRequested = preferences.getBoolPreference(WIFI_ON_REQUESTED)
        val gsmOnRequested = preferences.getBoolPreference(GSM_ON_REQUESTED)

        val commands: MutableList<String> = ArrayList(2)
        if (wifiOnRequested) {
            commands.add("svc wifi enable")
            preferences.setBoolPreference(WIFI_ON_REQUESTED, false)
            logi("Enabling WiFi due to a kill switch")
        }
        if (gsmOnRequested) {
            commands.add("svc data enable")
            preferences.setBoolPreference(GSM_ON_REQUESTED, false)
            logi("Enabling GSM due to a kill switch")
        }
        if (commands.isNotEmpty()) {
            handler.get().postDelayed({ RootCommands.execute(context, commands, NULL_MARK) },
                    (DELAY_ENABLING_INTERNET_SEC * 1000).toLong())
        }
    }

    companion object {
        private const val DELAY_ENABLING_INTERNET_SEC = 3

        private var killSwitchActive = false

        @JvmStatic
        fun denySystemDNS(context: Context, pathVars: PathVars) {

            val iptables = pathVars.getIptablesPath()

            val shPref = PreferenceManager.getDefaultSharedPreferences(context)
            val runModulesWithRoot = shPref.getBoolean(RUN_MODULES_WITH_ROOT, false)
            var appUID = pathVars.appUidStr
            if (runModulesWithRoot) {
                appUID = "0"
            }

            val commands: MutableList<String> = arrayListOf(
                    iptables + "-D " + FILTER_OUTPUT_CORE + " -p udp --dport 53 -m owner --uid-owner " + appUID + " -j ACCEPT 2> /dev/null || true",
                    iptables + "-t nat -D " + NAT_OUTPUT_CORE + " -p udp --dport 53 -m owner --uid-owner " + appUID + " -j ACCEPT 2> /dev/null || true"
            )

            if (!runModulesWithRoot) {
                val commandsNoRunModulesWithRoot = listOf(
                        iptables + "-D " + FILTER_OUTPUT_CORE + " -p udp --dport 53 -m owner --uid-owner 0 -j ACCEPT 2> /dev/null || true",
                        iptables + "-t nat -D " + NAT_OUTPUT_CORE + " -p udp --dport 53 -m owner --uid-owner 0 -j ACCEPT 2> /dev/null || true"
                )

                commands.addAll(commandsNoRunModulesWithRoot)
            }

            executeCommands(context, commands)
        }

        @JvmStatic
        fun blockTethering(context: Context, pathVars: PathVars): String {
            val iptables = pathVars.getIptablesPath()

            val commands = listOf(
                    iptables + "-I FORWARD -j DROP"
            )

            executeCommands(context, commands)

            return Tethering.vpnInterfaceName
        }

        @JvmStatic
        fun allowTethering(context: Context, pathVars: PathVars, oldVpnInterfaceName: String) {
            val iptables = pathVars.getIptablesPath()


            val commands: List<String>

            if (oldVpnInterfaceName == Tethering.vpnInterfaceName) {
                commands = listOf(
                        iptables + "-D FORWARD -j DROP 2> /dev/null || true"
                )
            } else {
                commands = listOf(
                        iptables + "-D FORWARD -j DROP 2> /dev/null || true",
                        iptables + "-D " + FILTER_FORWARD_CORE + " -o !" + oldVpnInterfaceName + " -j REJECT 2> /dev/null || true"
                )
            }

            executeCommands(context, commands)
        }

        private fun executeCommands(context: Context, commands: List<String>) {
            RootCommands.execute(context, commands, NULL_MARK)
        }
    }
}
