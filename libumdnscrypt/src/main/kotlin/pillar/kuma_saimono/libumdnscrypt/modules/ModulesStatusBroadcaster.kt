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

package pillar.kuma_saimono.libumdnscrypt.modules

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.REMOTE_CONTROL
import javax.inject.Inject
import javax.inject.Named
import javax.inject.Singleton

@Singleton
class ModulesStatusBroadcaster @Inject constructor(
    private val context: Context,
    private val pathVars: PathVars,
    @Named(DEFAULT_PREFERENCES_NAME)
    defaultSharedPreferences: SharedPreferences
) {

    @Volatile
    private var remoteControlActive = defaultSharedPreferences
        .getBoolean(REMOTE_CONTROL, false)

    fun broadcastDNSCryptRunning() {
        if (remoteControlActive) {
            getDNSCryptIntent().also {
                it.putExtra(STATUS_ARG, STATUS_RUNNING)
                context.sendBroadcast(it)
                logi("Broadcast DNSCrypt running")
            }
        }
    }

    fun broadcastDNSCryptReady() {
        if (remoteControlActive) {
            getDNSCryptIntent().also {
                it.putExtra(STATUS_ARG, STATUS_READY)
                context.sendBroadcast(it)
                logi("Broadcast DNSCrypt ready")
            }
        }
    }

    fun broadcastDNSCryptStopped() {
        if (remoteControlActive) {
            getDNSCryptIntent().also {
                it.putExtra(STATUS_ARG, STATUS_STOPPED)
                context.sendBroadcast(it)
                logi("Broadcast DNSCrypt stopped")
            }
        }
    }

    fun broadcastFirewallRunning() {
        getFirewallIntent().also {
            it.putExtra(STATUS_ARG, STATUS_RUNNING)
            LocalBroadcastManager.getInstance(context).sendBroadcast(it)
        }
    }

    fun broadcastFirewallStopped() {
        getFirewallIntent().also {
            it.putExtra(STATUS_ARG, STATUS_STOPPED)
            LocalBroadcastManager.getInstance(context).sendBroadcast(it)
        }
    }

    private fun getDNSCryptIntent() =
        Intent().also {
            it.setAction(STATUS_ACTION)
            it.putExtra(MODULE_ARG, DNSCRYPT)
            it.putExtra(DNSCRYPT_DNS_PORT_ARG, pathVars.dnsCryptPort)
        }

    private fun getFirewallIntent() =
        Intent().also {
            it.setAction(STATUS_ACTION)
            it.putExtra(MODULE_ARG, FIREWALL)
        }

    fun broadcastRemoteControlDisabled() {
        Intent().also {
            it.setAction(STATUS_ACTION)
            it.putExtra(STATUS_ARG, STATUS_DISABLED)
            context.sendBroadcast(it)
        }
    }

    fun onRemoteControlChanged(enabled: Boolean) {
        remoteControlActive = enabled
    }

    companion object {
        const val STATUS_ACTION = "pillar.kuma_saimono.libumdnscrypt.STATUS_ACTION"

        const val STATUS_ARG = "STATUS"
        const val STATUS_RUNNING = "RUNNING"
        const val STATUS_READY = "READY"
        const val STATUS_STOPPED = "STOPPED"
        const val STATUS_DISABLED = "CONTROL_DISABLED"

        const val MODULE_ARG = "MODULE"
        const val DNSCRYPT = "DNSCRYPT"
        const val FIREWALL = "FIREWALL"

        const val DNSCRYPT_DNS_PORT_ARG = "DNSCRYPT_DNS_PORT"
    }

}
