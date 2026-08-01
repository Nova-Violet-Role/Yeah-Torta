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
import android.content.SharedPreferences
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.di.arp.ArpScope
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.executors.CoroutineExecutor
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ARP_SPOOFING_NOT_SUPPORTED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ARP_SPOOFING_DETECTION
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ARP_SPOOFING_BLOCK_INTERNET
import java.util.concurrent.locks.ReentrantLock
import javax.inject.Inject
import javax.inject.Named
import kotlin.concurrent.withLock

@ArpScope
class ArpScannerHelper @Inject constructor(
    private val context: Context,
    @Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    private val defaultSharedPreferences: SharedPreferences,
    private val appPreferenceRepository: PreferenceRepository,
    private val executor: CoroutineExecutor,
    private val defaultGatewayManager: dagger.Lazy<DefaultGatewayManager>,
    private val arpTableManager: dagger.Lazy<ArpTableManager>,
    private val arpScannerLoop: dagger.Lazy<ArpScannerLoop>,
    private val uiUpdater: dagger.Lazy<ArpRelatedUiUpdater>
) {

    val arpScannerReentrantLock = ReentrantLock()

    private val modulesStatus by lazy { ModulesStatus.getInstance() }

    fun makePause(makePause: Boolean, resetInternalValues: Boolean) {
        val attackDetected = ArpScanner.arpAttackDetected || ArpScanner.dhcpGatewayAttackDetected

        arpScannerLoop.get().paused = makePause

        if (resetInternalValues) {
            resetArpScannerState()
        }

        if (isArpDetectionDisabled() && !attackDetected) {
            return
        }

        if (makePause) {
            logi("ArpScanner is paused")
        } else {
            logi("ArpScanner is active")
        }

        if (attackDetected) {
            uiUpdater.get().updateMainActivityIcons()
            reloadIptablesWithRootMode()
        }
    }

    fun resetArpScannerState() {
        executor.submit("ArpScannerHelper resetArpScannerState") {
            arpScannerReentrantLock.withLock {
                ArpScanner.arpAttackDetected = false
                ArpScanner.dhcpGatewayAttackDetected = false

                defaultGatewayManager.get().clearDefaultGateway()

                arpTableManager.get().clearGatewayMac()
            }
        }

    }

    fun reloadIptablesWithRootMode() {
        if (isArpAttackConnectionBlockingDisabled()) return

        val modulesStatus = ModulesStatus.getInstance()
        if (modulesStatus.mode == OperationMode.ROOT_MODE) {
            modulesStatus.setIptablesRulesUpdateRequested(context, true)
        }
    }

    fun isArpDetectionDisabled(): Boolean =
        !defaultSharedPreferences.getBoolean(
            ARP_SPOOFING_DETECTION,
            false
        )

    private fun isArpAttackConnectionBlockingDisabled(): Boolean =
        !defaultSharedPreferences.getBoolean(
            ARP_SPOOFING_BLOCK_INTERNET,
            false
        )

    fun isRootAvailable(): Boolean = modulesStatus.isRootAvailable

    fun getArpSpoofingDetectionSupported() =
        !appPreferenceRepository.getBoolPreference(ARP_SPOOFING_NOT_SUPPORTED)

    fun saveArpSpoofingDetectionNotSupported(supported: Boolean) {
        appPreferenceRepository.setBoolPreference(ARP_SPOOFING_NOT_SUPPORTED, supported)
    }
}
