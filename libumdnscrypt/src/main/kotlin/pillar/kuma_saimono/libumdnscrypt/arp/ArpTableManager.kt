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

import android.os.Build
import pillar.kuma_saimono.libumdnscrypt.di.arp.ArpScope
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.regex.Pattern
import javax.inject.Inject

private const val COMMAND_ARP = "ip neigh" //"ip neighbour show"
private const val ARP_FILE_PATH = "/proc/net/arp"
private const val NOT_SUPPORTED_DELAY_COUNTER = 10
private const val zerosMac = "00:00:00:00:00:00"
private val macPattern by lazy { Pattern.compile("([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})") }

@ArpScope
class ArpTableManager @Inject constructor(
    private val commandExecutor: dagger.Lazy<CommandExecutor>,
    private val arpScannerHelper: dagger.Lazy<ArpScannerHelper>
) {

    @Volatile
    var gatewayMac = ""
    @Volatile
    var savedGatewayMac = ""

    var notSupportedCounter = NOT_SUPPORTED_DELAY_COUNTER
    private var notSupportedCounterFreeze = false

    private var arpTableAccessible: Boolean? = null
        get() = field ?: isArpTableAccessible().also { field = it }

    private fun isArpTableAccessible(): Boolean = try {
        File(ARP_FILE_PATH).let {
            it.isFile && it.canRead()
        }
    } catch (ignored: Exception) {
        false
    }


    fun updateGatewayMac(defaultGateway: String) {

        if (defaultGateway.isEmpty()) {
            return
        }

        if (arpTableAccessible == true) {
            updateGatewayMacUsingFile(defaultGateway)
        } else {
            updateGatewayMacUsingShell(defaultGateway)
        }
    }

    private fun updateGatewayMacUsingFile(defaultGateway: String) {
        try {
            tryUpdateGatewayMacUsingFile(defaultGateway)
        } catch (e: Exception) {
            loge("ArpScanner getArpStringFromFile", e)
        }
    }

    private fun tryUpdateGatewayMacUsingFile(defaultGateway: String) {

        BufferedReader(InputStreamReader(File(ARP_FILE_PATH).inputStream())).use { bufferedReader ->
            var line = bufferedReader.readLine()
            while (line != null) {
                if (line.contains("$defaultGateway ")) {

                    gatewayMac = getMacFromLine(line)

                    if (savedGatewayMac.isEmpty()
                        && gatewayMac.isNotBlank()
                        && gatewayMac != zerosMac) {
                        val macStared = gatewayMac.substring(0..gatewayMac.length - 7)
                            .replace(Regex("\\w+?"), "*")
                            .plus(gatewayMac.substring(gatewayMac.length - 6))
                        logi("ArpScanner gatewayMac is $macStared")
                        savedGatewayMac = gatewayMac
                    }
                    break
                } else {
                    line = bufferedReader.readLine()
                }
            }
        }
    }

    private fun updateGatewayMacUsingShell(defaultGateway: String) {
        try {
            tryUpdateGatewayMacUsingShell(defaultGateway)
        } catch (e: Exception) {
            loge("ArpScanner getArpStringFromShell", e)
        }
    }

    private fun tryUpdateGatewayMacUsingShell(defaultGateway: String) {

        val lines = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
            && arpScannerHelper.get().isRootAvailable()) {
            commandExecutor.get().execRoot(COMMAND_ARP)
        } else {
            commandExecutor.get().execNormal(COMMAND_ARP)
        }

        var containsNotEmptyLines = false

        for (line: String in lines) {
            if (line.trim().isNotEmpty() && !line.contains("-BOC-")) {
                containsNotEmptyLines = true
            }

            if (line.contains("$defaultGateway ")) {

                gatewayMac = getMacFromLine(line)

                if (savedGatewayMac.isEmpty()
                    && gatewayMac.isNotBlank()
                    && gatewayMac != zerosMac) {
                    val macStared = gatewayMac.substring(0..gatewayMac.length - 7)
                        .replace(Regex("\\w+?"), "*")
                        .plus(gatewayMac.substring(gatewayMac.length - 6))
                    logi("ArpScanner gatewayMac is $macStared")
                    savedGatewayMac = gatewayMac
                }

                notSupportedCounterFreeze = true

                break
            } else if (getMacFromLine(line).isNotEmpty()) {
                notSupportedCounterFreeze = true
            }
        }

        if (lines.isEmpty() && notSupportedCounter > 0
            || containsNotEmptyLines && !notSupportedCounterFreeze && notSupportedCounter > 0) {
            notSupportedCounter--
        }
    }

    private fun getMacFromLine(line: String): String {
        val matcher = macPattern.matcher(line)

        if (matcher.find()) {
            return matcher.group().trim()
        }

        return ""
    }

    fun clearGatewayMac() {
        gatewayMac = ""
        savedGatewayMac = ""
    }
}
