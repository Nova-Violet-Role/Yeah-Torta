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

package pillar.kuma_saimono.libumdnscrypt.arp

import android.content.Context
import android.net.wifi.WifiManager
import pillar.kuma_saimono.libumdnscrypt.di.arp.ArpScope
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import java.math.BigInteger
import java.net.InetAddress
import java.nio.ByteOrder
import java.util.regex.Pattern
import javax.inject.Inject
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build

private const val COMMAND_RULE_SHOW = "ip rule"
private const val COMMAND_ROUTE_SHOW = "ip route show table %s"

private val ethTablePattern by lazy { Pattern.compile("eth\\d lookup (\\w+)") }
private val defaultGatewayPattern by lazy { Pattern.compile("default via (([0-9*]{1,3}\\.){3}[0-9*]{1,3})") }

@ArpScope
class DefaultGatewayManager @Inject constructor(
    context: Context,
    private val connectionManager: ConnectionManager,
    private val commandExecutor: CommandExecutor,
    private val arpScannerHelper: ArpScannerHelper
) {

    private val wifiManager =
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

    // Resolved once in the initializer, exactly like wifiManager above: `context` is a constructor
    // PARAMETER, not a property, so it is not in scope from a method body. `as?` rather than `as`
    // because this one is optional -- a null here falls back to the DHCP path instead of throwing
    // during construction, which is the difference between a degraded ArpScanner and no app.
    private val connectivityManager =
        context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

    @Volatile
    var defaultGateway = ""

    @Volatile
    var savedDefaultGateway = ""

    @Volatile
    private var ethernetTable = ""

    /**
     * The Wi-Fi default gateway from the modern API, or null if it cannot be had there.
     *
     * `WifiManager.dhcpInfo` is deprecated at API 31 and is a poor source besides: it reports what
     * DHCP handed out, which is stale after a roam and simply absent on a statically-configured or
     * IPv6-only link. `LinkProperties.routes` reports what the kernel is ROUTING THROUGH right now,
     * which is the fact this class actually wants -- ArpScanner compares it against the gateway
     * seen in ARP replies, so a stale value is a false spoofing signal.
     *
     * THE TRANSPORT CHECK IS NOT OPTIONAL. This method is named ...WiFiGateway and its result is
     * compared against Wi-Fi ARP traffic. `activeNetwork` is whatever is currently default, which
     * may be cellular or another VPN; returning that gateway would compare two unrelated networks
     * and could report a spoof that is not there. If the active network is not Wi-Fi, this returns
     * null and the caller keeps whatever it had.
     *
     * API 23+ only, because `activeNetwork` starts there. Below that the DHCP path is the only
     * option, and it is still correct for the devices that use it.
     */
    private fun wifiGatewayFromRoutes(): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
        val cm = connectivityManager ?: return null
        val network = cm.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(network) ?: return null
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return null
        val props = cm.getLinkProperties(network) ?: return null
        for (route in props.routes) {
            // isDefaultRoute means destination 0.0.0.0/0 (or ::/0) -- the route a packet to an
            // arbitrary host takes, which is what "the gateway" means here.
            if (route.isDefaultRoute) {
                val gateway = route.gateway?.hostAddress?.trim()
                if (!gateway.isNullOrEmpty()) return gateway
            }
        }
        return null
    }

    fun updateDefaultWiFiGateway() {
        // Modern path first; it is both non-deprecated and a better answer. Falling through to DHCP
        // rather than returning early matters: on a device where the active network is momentarily
        // not Wi-Fi, the old behaviour (report the last DHCP lease) is still better than reporting
        // nothing, and it is what this class did before.
        wifiGatewayFromRoutes()?.let { gateway ->
            defaultGateway = gateway
            if (savedDefaultGateway.isEmpty()) {
                logi("ArpScanner defaultGateway is $defaultGateway")
                savedDefaultGateway = defaultGateway
            }
            return
        }

        @Suppress("DEPRECATION")
        val dhcp = wifiManager.dhcpInfo ?: return
        @Suppress("DEPRECATION")
        var ipAddress = dhcp.gateway
        ipAddress =
            if (ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN) Integer.reverseBytes(ipAddress) else ipAddress
        val ipAddressByte = BigInteger.valueOf(ipAddress.toLong()).toByteArray()
        try {
            val myAddr = InetAddress.getByAddress(ipAddressByte)

            defaultGateway = myAddr.hostAddress?.trim() ?: ""

            if (savedDefaultGateway.isEmpty()) {
                logi("ArpScanner defaultGateway is $defaultGateway")
                savedDefaultGateway = defaultGateway
            }
        } catch (e: Exception) {

            if (connectionManager.connectionAvailable
                && !connectionManager.cellularActive
                && !connectionManager.wifiActive
                && !connectionManager.ethernetActive
            ) {
                arpScannerHelper.makePause(true, resetInternalValues = true)
            } else {

                if (defaultGateway.isNotEmpty()) {
                    arpScannerHelper.resetArpScannerState()
                }

                loge("ArpScanner error getting default gateway", e)
            }
        }
    }

    fun requestRuleTable() {
        if (ethernetTable.isEmpty()) {
            try {
                logi("ArpScanner requestRuleTable")
                requestDefaultEthernetGateway(commandExecutor.execNormal(COMMAND_RULE_SHOW))
            } catch (e: Exception) {
                loge("ArpScanner requestRuleTable", e)
            }
        } else {
            requestDefaultEthernetGateway()
        }
    }

    private fun requestDefaultEthernetGateway(lines: MutableList<String>) {

        try {
            for (line: String in lines) {
                val matcher = ethTablePattern.matcher(line)

                if (matcher.find()) {

                    ethernetTable = matcher.group(1) ?: ""

                    logi("ArpScanner ethTable is $ethernetTable")

                    if (ethernetTable.isNotEmpty()) {
                        setDefaultEthernetGateway(
                            commandExecutor.execNormal(
                                String.format(
                                    COMMAND_ROUTE_SHOW,
                                    ethernetTable
                                )
                            )
                        )
                    }

                    break
                }
            }
        } catch (e: java.lang.Exception) {
            loge("ArpScanner requestDefaultEthernetGateway(lines)", e)
        }
    }

    private fun requestDefaultEthernetGateway() {
        try {
            if (ethernetTable.isNotEmpty()) {
                setDefaultEthernetGateway(
                    commandExecutor.execNormal(
                        String.format(
                            COMMAND_ROUTE_SHOW,
                            ethernetTable
                        )
                    )
                )
            }
        } catch (e: java.lang.Exception) {
            loge("ArpScanner requestDefaultEthernetGateway", e)
        }
    }

    private fun setDefaultEthernetGateway(lines: MutableList<String>) {

        try {
            for (line: String in lines) {
                val matcher = defaultGatewayPattern.matcher(line)

                if (matcher.find()) {

                    matcher.group(1)?.let { defaultGateway = it }

                    if (savedDefaultGateway.isEmpty()) {
                        logi("ArpScanner defaultGateway is $defaultGateway")
                        savedDefaultGateway = defaultGateway
                    }

                    break
                }
            }

        } catch (e: Exception) {
            if (defaultGateway.isNotEmpty()) {
                arpScannerHelper.resetArpScannerState()
            }

            loge("ArpScanner error getting default gateway", e)
        }
    }

    fun clearDefaultGateway() {
        defaultGateway = ""
        savedDefaultGateway = ""
        ethernetTable = ""
    }
}
