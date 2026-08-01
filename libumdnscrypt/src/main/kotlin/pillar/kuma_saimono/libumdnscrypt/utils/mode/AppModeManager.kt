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

package pillar.kuma_saimono.libumdnscrypt.utils.mode

import android.content.Context
import android.content.SharedPreferences
import android.widget.Toast
import androidx.preference.PreferenceManager
import kotlinx.coroutines.ExperimentalCoroutinesApi
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.iptables.IptablesRules
import pillar.kuma_saimono.libumdnscrypt.iptables.ModulesIptablesRules
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesAux
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.nflog.NflogManager
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RESTARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RUNNING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.OPERATION_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.CONNECTION_LOGS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.RUN_MODULES_WITH_ROOT
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper
import javax.inject.Inject
import javax.inject.Named

@ExperimentalCoroutinesApi
class AppModeManager @Inject constructor(
    private val context: Context,
    private val preferenceRepository: dagger.Lazy<PreferenceRepository>,
    private val nflogManager: dagger.Lazy<NflogManager>,
    @Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: dagger.Lazy<SharedPreferences>
) {

    private val modulesStatus = ModulesStatus.getInstance()

    fun switchToRootMode(appModeManagerCallback: AppModeManagerCallback?) {

        preferenceRepository.get()
            .setStringPreference(OPERATION_MODE, OperationMode.ROOT_MODE.toString())
        logi("Root mode enabled")

        val fixTTL = modulesStatus.isFixTTL && !modulesStatus.isUseModulesWithRoot
        val operationMode: OperationMode? = modulesStatus.mode
        if (operationMode == OperationMode.VPN_MODE && !fixTTL) {
            ServiceVPNHelper.stop("Switch to root mode", context)
            Toast.makeText(context, uniffi.torta_core.tortaText("vpn_mode_off"), Toast.LENGTH_LONG)
                .show()
        } else if (operationMode == OperationMode.PROXY_MODE && fixTTL) {
            appModeManagerCallback?.prepareVPNService()
        }

        if (defaultPreferences.get().getBoolean(CONNECTION_LOGS, true)) {
            val dnsCryptState = modulesStatus.dnsCryptState
            val firewallState = modulesStatus.firewallState
            if (dnsCryptState == RUNNING || dnsCryptState == STARTING || dnsCryptState == RESTARTING
                || firewallState == RUNNING || firewallState == STARTING) {
                nflogManager.get().startNflog()
            }
        }

        //This start iptables adaptation
        modulesStatus.mode = OperationMode.ROOT_MODE
        ModulesAux.clearIptablesCommandsSavedHash(context)
        modulesStatus.setIptablesRulesUpdateRequested(true)

        appModeManagerCallback?.setFirewallNavigationItemVisible(true)
        appModeManagerCallback?.invalidateMenu()
    }

    fun switchToProxyMode(appModeManagerCallback: AppModeManagerCallback?) {

        preferenceRepository.get()
            .setStringPreference(OPERATION_MODE, OperationMode.PROXY_MODE.toString())
        logi("Proxy mode enabled")
        val operationMode: OperationMode? = modulesStatus.mode

        if (operationMode == OperationMode.ROOT_MODE) {
            nflogManager.get().stopNflog()
        }

        //This stop iptables adaptation
        modulesStatus.mode = OperationMode.PROXY_MODE
        modulesStatus.setFirewallState(ModuleState.STOPPED, preferenceRepository.get())
        if (modulesStatus.isRootAvailable && operationMode == OperationMode.ROOT_MODE) {
            val iptablesRules: IptablesRules = ModulesIptablesRules(context)
            val commands = iptablesRules.clearAll()
            iptablesRules.sendToRootExecService(commands)
            logi("Iptables rules removed")
        } else if (operationMode == OperationMode.VPN_MODE) {
            ServiceVPNHelper.stop("Switch to proxy mode", context)
            Toast.makeText(context, uniffi.torta_core.tortaText("vpn_mode_off"), Toast.LENGTH_LONG)
                .show()
        }

        appModeManagerCallback?.setFirewallNavigationItemVisible(false)
        appModeManagerCallback?.invalidateMenu()
    }

    fun switchToVPNMode(appModeManagerCallback: AppModeManagerCallback?) {

        preferenceRepository.get()
            .setStringPreference(OPERATION_MODE, OperationMode.VPN_MODE.toString())
        logi("VPN mode enabled")
        val operationMode: OperationMode? = modulesStatus.mode

        if (operationMode == OperationMode.ROOT_MODE) {
            nflogManager.get().stopNflog()
        }

        //This stop iptables adaptation
        modulesStatus.mode = OperationMode.VPN_MODE
        if (modulesStatus.isRootAvailable && operationMode == OperationMode.ROOT_MODE) {
            val iptablesRules: IptablesRules = ModulesIptablesRules(context)
            val commands = iptablesRules.clearAll()
            iptablesRules.sendToRootExecService(commands)
            logi("Iptables rules removed")
        }
        val dnsCryptState: ModuleState = modulesStatus.dnsCryptState
        val firewallState: ModuleState = modulesStatus.firewallState
        if (dnsCryptState != ModuleState.STOPPED
            || firewallState != ModuleState.STOPPED
        ) {
            if (modulesStatus.isUseModulesWithRoot) {
                Toast.makeText(context, "Stop modules...", Toast.LENGTH_LONG).show()
                disableUseModulesWithRoot(context, modulesStatus)
            } else {
                appModeManagerCallback?.prepareVPNService()
            }
        }
        if (dnsCryptState == ModuleState.STOPPED
            && modulesStatus.isUseModulesWithRoot
        ) {
            disableUseModulesWithRoot(context, modulesStatus)
        }

        appModeManagerCallback?.setFirewallNavigationItemVisible(true)
        appModeManagerCallback?.invalidateMenu()
    }

    private fun disableUseModulesWithRoot(context: Context, modulesStatus: ModulesStatus) {
        val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        sharedPreferences.edit().putBoolean(RUN_MODULES_WITH_ROOT, false).apply()
        ModulesAux.stopModulesIfRunning(context)
        modulesStatus.isUseModulesWithRoot = false
        modulesStatus.isContextUIDUpdateRequested = true
        ModulesAux.requestModulesStatusUpdate(context)
        logi("Switch to VPN mode, disable use modules with root option")
    }
}
