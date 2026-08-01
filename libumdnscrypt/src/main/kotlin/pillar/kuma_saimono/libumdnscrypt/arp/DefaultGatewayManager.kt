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

    @Volatile
    var defaultGateway = ""

    @Volatile
    var savedDefaultGateway = ""

    @Volatile
    private var ethernetTable = ""

    fun updateDefaultWiFiGateway() {
        val dhcp = wifiManager.dhcpInfo ?: return
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
