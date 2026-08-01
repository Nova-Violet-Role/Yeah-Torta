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
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RUNNING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.UNDEFINED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FIREWALL_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FIREWALL_WAS_STARTED

class ModulesStatus private constructor() {

    @Volatile
    var dnsCryptState: ModuleState = UNDEFINED

    @Volatile
    var firewallState: ModuleState = STOPPED
        private set

    // CAKE/YeAH engine as a first-class module (the Tor/I2P slot): it can run alone or alongside
    // DNSCrypt, and while RUNNING it keeps ModulesService alive exactly as Tor/I2P used to.
    @Volatile
    var engineState: ModuleState = STOPPED

    @Volatile
    var isRootAvailable: Boolean = false

    @Volatile
    var isUseModulesWithRoot: Boolean = false

    @Volatile
    private var requestIptablesUpdate: Boolean = false

    @Volatile
    private var requestFixTTLRulesUpdate: Boolean = false

    @Volatile
    var isContextUIDUpdateRequested: Boolean = false

    @Volatile
    private var fixTTL: Boolean = false

    @Volatile
    var mode: OperationMode? = null

    @Volatile
    var isSystemDNSAllowed: Boolean = false

    @Volatile
    var isDnsCryptReady: Boolean = false

    @Volatile
    var isDeviceInteractive: Boolean = true

    fun setFirewallState(firewallState: ModuleState, preferenceRepository: PreferenceRepository) {
        val firewallEnabled = preferenceRepository.getBoolPreference(FIREWALL_ENABLED) &&
                preferenceRepository.getBoolPreference(FIREWALL_WAS_STARTED)
        this.firewallState = if (firewallEnabled &&
            (mode == OperationMode.VPN_MODE || mode == OperationMode.ROOT_MODE)
        ) {
            firewallState
        } else {
            STOPPED
        }
        if (this.firewallState == RUNNING) {
            ModulesAux.saveFirewallStateRunning(true)
        } else if (this.firewallState == STOPPING || this.firewallState == STOPPED) {
            ModulesAux.saveFirewallStateRunning(false)
        }
    }

    @Synchronized
    fun isIptablesRulesUpdateRequested(): Boolean {
        return requestIptablesUpdate
    }

    @Synchronized
    fun setIptablesRulesUpdateRequested(requestIptablesUpdate: Boolean) {
        this.requestIptablesUpdate = requestIptablesUpdate
    }

    @Synchronized
    fun setIptablesRulesUpdateRequested(context: Context, requestIptablesUpdate: Boolean) {
        this.requestIptablesUpdate = requestIptablesUpdate
        ModulesAux.makeModulesStateExtraLoop(context)
    }

    fun isFixTTLRulesUpdateRequested(): Boolean {
        return requestFixTTLRulesUpdate
    }

    fun setFixTTLRulesUpdateRequested(requestFixTTLRulesUpdate: Boolean) {
        this.requestFixTTLRulesUpdate = requestFixTTLRulesUpdate
    }

    fun setFixTTLRulesUpdateRequested(context: Context, requestFixTTLRulesUpdate: Boolean) {
        setFixTTLRulesUpdateRequested(requestFixTTLRulesUpdate)
        ModulesAux.makeModulesStateExtraLoop(context)
    }

    var isFixTTL: Boolean
        get() = fixTTL && isRootAvailable
        set(value) {
            fixTTL = value
        }

    companion object {

        @Volatile
        private var modulesStatus: ModulesStatus? = null

        @JvmStatic
        fun getInstance(): ModulesStatus {
            if (modulesStatus == null) {
                synchronized(ModulesStatus::class.java) {
                    if (modulesStatus == null) {
                        modulesStatus = ModulesStatus()
                    }
                }
            }
            return modulesStatus!!
        }
    }
}
