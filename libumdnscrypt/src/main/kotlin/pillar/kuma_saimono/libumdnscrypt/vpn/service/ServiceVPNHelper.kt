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

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Handler
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.utils.Utils
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.enums.VPNCommand
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.VPN_SERVICE_ENABLED
import java.util.concurrent.locks.ReentrantLock

object ServiceVPNHelper {

    private val reentrantLock = ReentrantLock()

    @JvmStatic
    fun start(reason: String, context: Context) {
        val handler = getMainHandler(context)
        if (handler != null) {
            handler.post { startVpnService(reason, context) }
        } else {
            startVpnService(reason, context)
        }
    }

    private fun startVpnService(reason: String, context: Context) {
        val intent = Intent(context, ServiceVPN::class.java)
        intent.putExtra(ServiceVPN.EXTRA_COMMAND, VPNCommand.START)
        intent.putExtra(ServiceVPN.EXTRA_REASON, reason)
        sendIntent(context, intent, true)
    }

    @JvmStatic
    fun reload(reason: String, context: Context) {
        val handler = getMainHandler(context)
        if (handler != null) {
            handler.post { reloadVpnService(reason, context) }
        } else {
            reloadVpnService(reason, context)
        }
    }

    private fun reloadVpnService(reason: String, context: Context) {
        val modulesStatus = ModulesStatus.getInstance()
        val operationMode = modulesStatus.mode
        val dnsCryptState = modulesStatus.dnsCryptState
        val firewallState = modulesStatus.firewallState
        val vpnServiceEnabled = isVpnServiceEnabled(context)

        val fixTTL = modulesStatus.isFixTTL && (modulesStatus.mode == OperationMode.ROOT_MODE) &&
                !modulesStatus.isUseModulesWithRoot

        if (((operationMode == OperationMode.VPN_MODE) || fixTTL) &&
            vpnServiceEnabled &&
            (dnsCryptState == ModuleState.RUNNING ||
                    firewallState == ModuleState.RUNNING || firewallState == ModuleState.STARTING ||
                    // #17: the standalone Tortä Engine reloads the TUN too, so engine-only state changes
                    // (rotation, preset, pillar arm) re-apply on the live tunnel.
                    modulesStatus.engineState == ModuleState.RUNNING)
        ) {
            val intent = Intent(context, ServiceVPN::class.java)
            intent.putExtra(ServiceVPN.EXTRA_COMMAND, VPNCommand.RELOAD)
            intent.putExtra(ServiceVPN.EXTRA_REASON, reason)
            sendIntent(context, intent, false)
        }
    }

    @JvmStatic
    fun stop(reason: String, context: Context) {
        val handler = getMainHandler(context)
        if (handler != null) {
            handler.post { stopVpnService(reason, context) }
        } else {
            stopVpnService(reason, context)
        }
    }

    private fun stopVpnService(reason: String, context: Context) {
        val vpnServiceEnabled = isVpnServiceEnabled(context)
        if (vpnServiceEnabled) {
            val intent = Intent(context, ServiceVPN::class.java)
            intent.putExtra(ServiceVPN.EXTRA_COMMAND, VPNCommand.STOP)
            intent.putExtra(ServiceVPN.EXTRA_REASON, reason)
            sendIntent(context, intent, false)
        }
    }

    @JvmStatic
    fun prepareVPNServiceIfRequired(activity: Activity, modulesStatus: ModulesStatus) {

        val handler = getMainHandler(activity)
        if (handler == null || !reentrantLock.tryLock()) {
            return
        }

        handler.post {
            try {
                val operationMode = modulesStatus.mode

                val fixTTL = modulesStatus.isFixTTL && (modulesStatus.mode == OperationMode.ROOT_MODE) &&
                        !modulesStatus.isUseModulesWithRoot

                if (((operationMode == OperationMode.VPN_MODE) || fixTTL) &&
                    !isVpnServiceEnabled(activity)
                ) {
                    // SLINT is the UI now: the live surface hosts the one-time system VPN
                    // consent (fail-open no-op when no surface is visible).
                    TortaSlintActivity.requestVpnConsent()
                }
            } catch (e: Exception) {
                loge("ServiceVPNHelper prepareVPNServiceIfRequired", e)
            } finally {
                reentrantLock.unlock()
            }
        }
    }

    private fun sendIntent(context: Context, intent: Intent, showNotification: Boolean) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && showNotification) {
                intent.putExtra("showNotification", true)
                context.startForegroundService(intent)
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                intent.putExtra("showNotification", false)
                context.startService(intent)
            } else {
                intent.putExtra("showNotification", Utils.isShowNotification(context) && showNotification)
                context.startService(intent)
            }
        } catch (e: Exception) {
            loge("ServiceVPNHelper sendIntent", e, true)
        }
    }

    private fun isVpnServiceEnabled(context: Context): Boolean {
        val prefs: SharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        return prefs.getBoolean(VPN_SERVICE_ENABLED, false)
    }

    private fun getMainHandler(context: Context): Handler? {
        val looper = context.mainLooper
        if (looper != null) {
            return Handler(looper)
        }
        return null
    }
}
