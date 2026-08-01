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

import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.di.arp.ArpScope
import pillar.kuma_saimono.libumdnscrypt.di.arp.ArpSubcomponent
import pillar.kuma_saimono.libumdnscrypt.utils.delegates.MutableLazy
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import kotlin.concurrent.withLock

const val MITM_ATTACK_WARNING = "pillar.kuma_saimono.libumdnscrypt.arp.mitm_attack_warning"

@ArpScope
class ArpScanner @Inject constructor(
    private val arpScannerLoop: dagger.Lazy<ArpScannerLoop>,
    private val arpScannerHelper: dagger.Lazy<ArpScannerHelper>,
    private val uiUpdater: dagger.Lazy<ArpRelatedUiUpdater>,
    private val connectionManager: dagger.Lazy<ConnectionManager>
) {

    @Volatile
    private var scheduledExecutorService: ScheduledExecutorService? = null

    fun start() {

        if (arpScannerHelper.get().isArpDetectionDisabled()) return

        val connections = connectionManager.get()

        connections.updateActiveNetworks()

        if (!connections.wifiActive
            && !connections.ethernetActive
            && (connections.cellularActive || !connections.connectionAvailable)
        ) {
            return
        }

        if (scheduledExecutorService == null || scheduledExecutorService?.isShutdown == true) {
            scheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
        } else {
            return
        }

        arpScannerHelper.get().makePause(false, resetInternalValues = true)

        logi("Start ArpScanner")

        scheduledExecutorService?.scheduleWithFixedDelay({

            val reentrantLock = arpScannerHelper.get().arpScannerReentrantLock

            if (!reentrantLock.tryLock(5, TimeUnit.SECONDS)) {
                TimeUnit.SECONDS.sleep(1)
                return@scheduleWithFixedDelay
            }

            arpScannerLoop.get().checkArpAttack(scheduledExecutorService)

            if (reentrantLock.isHeldByCurrentThread && reentrantLock.isLocked) {
                reentrantLock.unlock()
            }

        }, 1, 10, TimeUnit.SECONDS)

        if (!connections.isConnected() && !connections.connectionAvailable) {
            arpScannerHelper.get().makePause(true, resetInternalValues = true)
        }
    }

    fun reset(connectionAvailable: Boolean) {

        if (arpScannerHelper.get().isArpDetectionDisabled()) return

        val attackDetected = arpAttackDetected || dhcpGatewayAttackDetected

        val connections = connectionManager.get()

        connections.connectionAvailable = connectionAvailable

        if (arpScannerHelper.get().isArpDetectionDisabled() && !attackDetected) {
            return
        }

        connections.updateActiveNetworks()

        if (connectionAvailable
            && (connections.wifiActive
                    || connections.ethernetActive
                    || !connections.cellularActive)
        ) {
            if (scheduledExecutorService?.isShutdown == false) {
                arpScannerHelper.get().makePause(false, resetInternalValues = false)

                if (!attackDetected) {
                    arpScannerHelper.get().resetArpScannerState()
                }

                logi("ArpScanner reset due to connectivity changed")
            } else {
                start()
            }
        } else {
            arpScannerHelper.get().makePause(true, resetInternalValues = true)
        }
    }

    fun stop() {

        arpScannerHelper.get().arpScannerReentrantLock.withLock {
            try {

                arpScannerLoop.get().stopping = true

                connectionManager.get().clearActiveNetworks()

                val updateIcons = arpAttackDetected || dhcpGatewayAttackDetected

                arpScannerHelper.get().resetArpScannerState()

                if (updateIcons) {
                    uiUpdater.get().updateMainActivityIcons()
                } else {
                    uiUpdater.get().stopUpdates()
                }

                logi("Stopping ArpScanner")
            } catch (e: java.lang.Exception) {
                logw("ArpScanner stop exception ${e.message}\n${e.cause}\n${e.stackTrace}")
            }
        }

    }

    companion object {
        @Volatile
        @JvmStatic
        var arpAttackDetected = false

        @Volatile
        @JvmStatic
        var dhcpGatewayAttackDetected = false

        private var arpSubcomponent: ArpSubcomponent? by MutableLazy {
            App.instance.daggerComponent.arpSubcomponent().create()
        }

        @JvmStatic
        fun getArpComponent(): ArpSubcomponent {
            return arpSubcomponent!!
        }

        @JvmStatic
        fun releaseArpComponent() {
            arpSubcomponent = null
        }
    }

}
