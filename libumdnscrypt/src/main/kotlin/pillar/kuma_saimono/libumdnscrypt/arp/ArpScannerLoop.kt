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

import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.di.arp.ArpScope
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import java.util.concurrent.ScheduledExecutorService
import javax.inject.Inject

private const val ARP_NOTIFICATION_ID = 110
private const val DHCP_NOTIFICATION_ID = 111

@ArpScope
class ArpScannerLoop @Inject constructor(
    private val arpWarningNotification: ArpWarningNotification,
    private val uiUpdater: ArpRelatedUiUpdater,
    private val arpTableManager: ArpTableManager,
    private val connectionManager: ConnectionManager,
    private val arpScannerHelper: ArpScannerHelper,
    private val defaultGatewayManager: DefaultGatewayManager,
    private val commandExecutor: CommandExecutor
) {

    @Volatile
    var stopping = false
    var paused = false

    fun checkArpAttack(scheduledExecutorService: ScheduledExecutorService?) {
        try {
            tryCheckArpAttack(scheduledExecutorService)
        } catch (e: Exception) {
            if (defaultGatewayManager.defaultGateway.isNotEmpty()) {
                arpScannerHelper.resetArpScannerState()
            }
            loge("ArpScanner executor", e, true)
        }
    }

    private fun tryCheckArpAttack(scheduledExecutorService: ScheduledExecutorService?) {

        if (stopping) {

            if (defaultGatewayManager.defaultGateway.isNotEmpty()) {
                arpScannerHelper.resetArpScannerState()
            }

            commandExecutor.closeRootCommandShell()

            scheduledExecutorService?.let {
                if (!it.isShutdown) {
                    logi("ArpScanner Stopped")
                    it.shutdownNow()
                }
            }

            return
        }

        if (paused) {
            return
        }

        if (connectionManager.wifiActive) {
            defaultGatewayManager.updateDefaultWiFiGateway()
        } else if (connectionManager.ethernetActive) {
            defaultGatewayManager.requestRuleTable()
        } else if (!connectionManager.cellularActive
            && connectionManager.connectionAvailable
        ) {
            defaultGatewayManager.updateDefaultWiFiGateway()
        }

        if (defaultGatewayManager.savedDefaultGateway.isNotEmpty()
            && defaultGatewayManager.defaultGateway.isNotEmpty()
        ) {

            if (defaultGatewayManager.savedDefaultGateway != defaultGatewayManager.defaultGateway) {
                loge("DHCPAttackDetected defaultGateway changed")
                logi(
                    "Upstream Network Saved default Gateway:${defaultGatewayManager.savedDefaultGateway}"
                )
                logi(
                    "Upstream Network Current default Gateway:${defaultGatewayManager.defaultGateway}"
                )

                if (!ArpScanner.dhcpGatewayAttackDetected) {
                    arpWarningNotification.send(
                        uniffi.torta_core.tortaText("reset_settings_title"),
                        uniffi.torta_core.tortaText("notification_rogue_dhcp"),
                        DHCP_NOTIFICATION_ID
                    )
                    uiUpdater.makeToast(uniffi.torta_core.tortaText("notification_rogue_dhcp"))
                    uiUpdater.updateMainActivityIcons()
                    arpScannerHelper.reloadIptablesWithRootMode()
                }

                ArpScanner.dhcpGatewayAttackDetected = true

                return
            } else if (ArpScanner.dhcpGatewayAttackDetected) {
                ArpScanner.dhcpGatewayAttackDetected = false
                uiUpdater.updateMainActivityIcons()
                arpScannerHelper.reloadIptablesWithRootMode()
            }
        }

        if (arpTableManager.notSupportedCounter > 0) {
            arpTableManager.updateGatewayMac(defaultGatewayManager.defaultGateway)
        }

        if (arpTableManager.savedGatewayMac.isNotEmpty()
            && arpTableManager.gatewayMac.isNotEmpty()
        ) {

            if (!arpScannerHelper.getArpSpoofingDetectionSupported()) {
                arpScannerHelper.saveArpSpoofingDetectionNotSupported(false)
            }

            if (arpTableManager.gatewayMac != arpTableManager.savedGatewayMac) {
                loge("ArpAttackDetected")
                logi(
                    "Upstream Network Saved default Gateway:${defaultGatewayManager.savedDefaultGateway} MAC:${arpTableManager.savedGatewayMac}"
                )
                logi(
                    "Upstream Network Current default Gateway:${defaultGatewayManager.defaultGateway} MAC:${arpTableManager.gatewayMac}"
                )


                if (!ArpScanner.arpAttackDetected) {
                    arpWarningNotification.send(
                        uniffi.torta_core.tortaText("reset_settings_title"),
                        uniffi.torta_core.tortaText("notification_arp_spoofing"),
                        ARP_NOTIFICATION_ID
                    )
                    uiUpdater.makeToast(uniffi.torta_core.tortaText("notification_arp_spoofing"))
                    uiUpdater.updateMainActivityIcons()
                    arpScannerHelper.reloadIptablesWithRootMode()
                }

                ArpScanner.arpAttackDetected = true

            } else if (ArpScanner.arpAttackDetected) {
                ArpScanner.arpAttackDetected = false
                uiUpdater.updateMainActivityIcons()
                arpScannerHelper.reloadIptablesWithRootMode()
            }
        }

        if (arpTableManager.notSupportedCounter == 0 && arpScannerHelper.getArpSpoofingDetectionSupported()) {
            arpScannerHelper.saveArpSpoofingDetectionNotSupported(true)
            logw("Arp Spoofing detection is not supported. Only rogue DHCP detection.")
            //uiUpdater.makeToast(uniffi.torta_core.tortaText("toast_arp_detection_not_supported"))
            //arpScanner.stop()
        }
    }
}
