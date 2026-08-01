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
import android.os.Build
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FIREWALL_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FIREWALL_WAS_STARTED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.OPERATION_MODE

object ModulesAux {

    private const val DNSCRYPT_RUNNING_PREF = "DNSCrypt Running"
    private const val FIREWALL_RUNNING_PREF = "Firewall Running"

    @JvmStatic
    fun switchModes(rootIsAvailable: Boolean, runModulesWithRoot: Boolean, operationMode: OperationMode) {
        val modulesStatus = ModulesStatus.getInstance()

        modulesStatus.isRootAvailable = rootIsAvailable
        modulesStatus.isUseModulesWithRoot = runModulesWithRoot

        val preferences = App.instance.daggerComponent.getPreferenceRepository().get()

        if (operationMode != OperationMode.UNDEFINED && PathVars.isModulesInstalled(preferences)) {
            modulesStatus.mode = operationMode
        } else if (rootIsAvailable) {
            modulesStatus.mode = OperationMode.ROOT_MODE
            preferences.setStringPreference(OPERATION_MODE, OperationMode.ROOT_MODE.toString())
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            modulesStatus.mode = OperationMode.VPN_MODE
            preferences.setStringPreference(OPERATION_MODE, OperationMode.VPN_MODE.toString())
        } else {
            modulesStatus.mode = OperationMode.PROXY_MODE
            preferences.setStringPreference(OPERATION_MODE, OperationMode.PROXY_MODE.toString())
        }

    }

    @JvmStatic
    fun isDnsCryptSavedStateRunning(): Boolean {
        //synchronized (DNSCRYPT_RUNNING_PREF) {
        val preferences = App.instance.daggerComponent.getPreferenceRepository().get()
        return preferences.getBoolPreference(DNSCRYPT_RUNNING_PREF)
        //}
    }

    @JvmStatic
    fun saveDNSCryptStateRunning(running: Boolean) {
        //synchronized (DNSCRYPT_RUNNING_PREF) {
        val preferences = App.instance.daggerComponent.getPreferenceRepository().get()
        preferences.setBoolPreference(DNSCRYPT_RUNNING_PREF, running)
        //}
    }

    @JvmStatic
    fun isFirewallSavedStateRunning(): Boolean {
        val preferences = App.instance.daggerComponent.getPreferenceRepository().get()
        return preferences.getBoolPreference(FIREWALL_RUNNING_PREF)
                && preferences.getBoolPreference(FIREWALL_ENABLED)
                && preferences.getBoolPreference(FIREWALL_WAS_STARTED)
    }

    @JvmStatic
    fun saveFirewallStateRunning(running: Boolean) {
        val preferences = App.instance.daggerComponent.getPreferenceRepository().get()
        preferences.setBoolPreference(FIREWALL_RUNNING_PREF, running)
    }

    @JvmStatic
    fun stopModulesIfRunning(context: Context) {
        val dnsCryptRunning = isDnsCryptSavedStateRunning()

        if (dnsCryptRunning) {
            ModulesKiller.stopDNSCrypt(context)
        }

        ModulesStatus.getInstance().setFirewallState(
            ModuleState.STOPPED,
            App.instance.daggerComponent.getPreferenceRepository().get()
        )
        saveFirewallStateRunning(false)
        speedupModulesStateLoopTimer(context)
    }

    @JvmStatic
    fun stopModulesService(context: Context) {
        ModulesActionSender.sendIntent(context, ModulesServiceActions.ACTION_STOP_SERVICE)
    }

    @JvmStatic
    fun requestModulesStatusUpdate(context: Context) {
        ModulesActionSender.sendIntent(context, ModulesServiceActions.ACTION_UPDATE_MODULES_STATUS)
    }

    @JvmStatic
    fun recoverService(context: Context) {
        ModulesActionSender.sendIntent(context, ModulesServiceActions.ACTION_RECOVER_SERVICE)
    }

    @JvmStatic
    fun speedupModulesStateLoopTimer(context: Context) {
        ModulesActionSender.sendIntent(context, ModulesServiceActions.SPEEDUP_LOOP)
    }

    @JvmStatic
    fun slowdownModulesStateLoopTimer(context: Context) {
        ModulesActionSender.sendIntent(context, ModulesServiceActions.SLOWDOWN_LOOP)
    }

    @JvmStatic
    fun makeModulesStateExtraLoop(context: Context) {
        ModulesActionSender.sendIntent(context, ModulesServiceActions.EXTRA_LOOP)
    }

    @JvmStatic
    fun startArpDetection(context: Context) {
        ModulesActionSender.sendIntent(context, ModulesServiceActions.START_ARP_SCANNER)
    }

    @JvmStatic
    fun stopArpDetection(context: Context) {
        ModulesActionSender.sendIntent(context, ModulesServiceActions.STOP_ARP_SCANNER)
    }

    @JvmStatic
    fun clearIptablesCommandsSavedHash(context: Context) {
        ModulesActionSender.sendIntent(context, ModulesServiceActions.CLEAR_IPTABLES_COMMANDS_HASH)
    }
}
