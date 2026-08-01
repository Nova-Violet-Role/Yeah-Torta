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

package pillar.kuma_saimono.libumdnscrypt.utils.bootcomplete

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Handler
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.BootCompleteReceiver.Companion.MY_PACKAGE_REPLACED
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesActionSender
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesAux
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesKiller
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesRunner
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.ACTION_STOP_SERVICE_FOREGROUND
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatusBroadcaster
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.ap.ApManager
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RUNNING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.ROOT_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.UNDEFINED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.VPN_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FIX_TTL
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.OPERATION_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PREVENT_DNS_LEAKS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.REMOTE_CONTROL
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ROOT_IS_AVAILABLE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.RUN_MODULES_WITH_ROOT
import pillar.kuma_saimono.libumdnscrypt.rust.AppStateBridge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.VPN_SERVICE_ENABLED
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper
import javax.inject.Inject
import javax.inject.Named

class BootCompleteManager @Inject constructor(
    @Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    private val defaultSharedPreferences: dagger.Lazy<SharedPreferences>,
    private val preferenceRepository: dagger.Lazy<PreferenceRepository>,
    private val handler: dagger.Lazy<Handler>,
    private val pathVars: dagger.Lazy<PathVars>,
    private val apManager: dagger.Lazy<ApManager>,
    private val modulesStatusBroadcaster: dagger.Lazy<ModulesStatusBroadcaster>
) {

    private lateinit var context: Context
    private var appDataDir: String? = null

    private val modulesStatus = ModulesStatus.getInstance()

    fun performAction(context: Context, intent: Intent) {

        this.context = context

        appDataDir = pathVars.get().appDataDir

        val defaultPreferences = defaultSharedPreferences.get()
        val preferences = preferenceRepository.get()

        val action = intent.action

        logi("Boot complete manager receive " + action)

        if (action == null) {
            return
        }

        if (action == SHELL_SCRIPT_CONTROL && !defaultPreferences.getBoolean(REMOTE_CONTROL, false)) {
            broadcastControlDisabled()
            return
        }

        preferences.setBoolPreference(TortaeKeys.WIFI_ACCESS_POINT_IS_ON, false)
        preferences.setBoolPreference(TortaeKeys.USB_MODEM_IS_ON, false)

        val tethering_autostart = defaultPreferences.getBoolean("pref_common_tethering_autostart", false)

        val rootIsAvailable = preferences.getBoolPreference(ROOT_IS_AVAILABLE)
        val runModulesWithRoot = defaultPreferences.getBoolean(RUN_MODULES_WITH_ROOT, false)
        val fixTTL = defaultPreferences.getBoolean(FIX_TTL, false)
        val operationMode = preferences.getStringPreference(OPERATION_MODE)

        var mode = UNDEFINED
        if (operationMode.isNotEmpty()) {
            mode = OperationMode.valueOf(operationMode)
        }

        ModulesAux.switchModes(rootIsAvailable, runModulesWithRoot, mode)

        var autoStartDNSCrypt = defaultPreferences.getBoolean("swAutostartDNS", false)

        val savedDNSCryptStateRunning = ModulesAux.isDnsCryptSavedStateRunning()
        val savedFirewallStateRunning = ModulesAux.isFirewallSavedStateRunning()

        var autoStartFirewall = autoStartDNSCrypt || savedFirewallStateRunning

        if (action.equals(MY_PACKAGE_REPLACED, ignoreCase = true) || action.equals(ALWAYS_ON_VPN, ignoreCase = true)) {
            autoStartDNSCrypt = savedDNSCryptStateRunning
            autoStartFirewall = autoStartDNSCrypt || savedFirewallStateRunning
        } else if (action == SHELL_SCRIPT_CONTROL) {
            val startDnsCrypt = intent.getIntExtra(MANAGE_DNSCRYPT_EXTRA, -1)

            if (startDnsCrypt < 0) {
                autoStartDNSCrypt = savedDNSCryptStateRunning
            } else {
                autoStartDNSCrypt = startDnsCrypt == 1
                broadcastDNSCryptState(autoStartDNSCrypt)
            }

            autoStartFirewall = autoStartDNSCrypt || savedFirewallStateRunning

            logi("SHELL_SCRIPT_CONTROL start: " +
                    "DNSCrypt " + autoStartDNSCrypt)
        } else {
            resetModulesSavedState(preferences)
        }

        if (savedDNSCryptStateRunning || savedFirewallStateRunning) {
            stopServicesForeground(context, mode, fixTTL)
        }

        val modulesStatus = ModulesStatus.getInstance()
        modulesStatus.isFixTTL = fixTTL

        if (tethering_autostart) {

            if (!action.equals(MY_PACKAGE_REPLACED, ignoreCase = true) && !action.equals(ALWAYS_ON_VPN, ignoreCase = true)
                    && action != SHELL_SCRIPT_CONTROL) {
                startHOTSPOT(preferences)
            }

        }

        if (autoStartDNSCrypt && !runModulesWithRoot
                && !defaultPreferences.getBoolean(PREVENT_DNS_LEAKS, false)
                && !action.equals(MY_PACKAGE_REPLACED, ignoreCase = true)
                && action != SHELL_SCRIPT_CONTROL) {
            modulesStatus.isSystemDNSAllowed = true
        }

        // Honor the user-configured boot delay on the NO-ROOT path. The root path applies
        // AUTO_START_DELAY inside RootExecutor.makeAutostartDelayIfRequired (RootExecutor.kt:197);
        // the no-root boot path had no such hook, leaving AUTO_START_DELAY inert (Pillar 13 §72.4).
        // FAITHFUL+MINIMAL+ADDITIVE: parse the same seconds string, and only on the no-root path
        // defer the arming sequence by that delay; the root path is untouched.
        val autoStartDNSCryptFinal = autoStartDNSCrypt
        val autoStartFirewallFinal = autoStartFirewall
        val modeFinal = mode
        val fixTTLFinal = fixTTL
        val actionFinal = action
        val defaultPreferencesFinal = defaultPreferences

        var autostartDelayMs = 0L
        if (!runModulesWithRoot) {
            autostartDelayMs = parseAutostartDelayMs(defaultPreferences)
        }

        val armModules = Runnable {
            armModulesOnBoot(
                autoStartDNSCryptFinal,
                autoStartFirewallFinal,
                modeFinal,
                fixTTLFinal,
                actionFinal,
                defaultPreferencesFinal
            )
        }

        if (autostartDelayMs > 0L) {
            logi("BootCompleteManager applying no-root autostart delay (ms): " + autostartDelayMs)
            handler.get().postDelayed(armModules, autostartDelayMs)
        } else {
            armModules.run()
        }
    }

    /**
     * Parse the user-configured boot delay (AUTO_START_DELAY, stored as a seconds string,
     * default "0"). Mirrors RootExecutor.makeAutostartDelayIfRequired (RootExecutor.kt:197-209):
     * "0"/null/blank -> no delay; otherwise seconds -> milliseconds. Never throws.
     */
    private fun parseAutostartDelayMs(defaultPreferences: SharedPreferences): Long {
        try {
            val delay = defaultPreferences.getString(TortaeKeys.AUTO_START_DELAY, "0")
            if (delay == null || delay.isEmpty() || delay == "0") {
                return 0L
            }
            return delay.trim().toLong() * 1000L
        } catch (e: Exception) {
            loge("BootCompleteManager parseAutostartDelayMs", e)
            return 0L
        }
    }

    /**
     * Re-arm the FGS/protection (and the Tortä Engine + VPN service) on boot. Extracted so the
     * no-root path can defer it behind AUTO_START_DELAY without altering the root path.
     */
    private fun armModulesOnBoot(
        autoStartDNSCrypt: Boolean,
        autoStartFirewall: Boolean,
        mode: OperationMode,
        fixTTL: Boolean,
        action: String,
        defaultPreferences: SharedPreferences
    ) {
        if (autoStartDNSCrypt) {
            startStopRestartModules(true, autoStartFirewall)
        } else {
            startStopRestartModules(false, autoStartFirewall)
        }

        // 2-DRIVE-ENGINE-VPN: the Tortä engine is NOT its own boot module — it rides the DNSCrypt
        // VpnService. When DNSCrypt auto-starts on boot it brings the engine up via onDnsCryptStarted;
        // there is no separate standalone engine boot-start (which would run the engine without the VPN
        // and force the access-log keep-alive). The engine follows the VPN, on boot as everywhere else.

        if ((autoStartDNSCrypt || autoStartFirewall)
                && (mode == VPN_MODE || fixTTL)) {
            val prepareIntent = VpnService.prepare(context)

            if (prepareIntent == null) {
                handler.get().postDelayed({
                    defaultPreferences.edit().putBoolean(VPN_SERVICE_ENABLED, true).apply()

                    val reason = when (action) {
                        MY_PACKAGE_REPLACED -> "MY_PACKAGE_REPLACED"
                        ALWAYS_ON_VPN -> "ALWAYS_ON_VPN"
                        SHELL_SCRIPT_CONTROL -> "SHELL_SCRIPT_CONTROL"
                        else -> "Boot complete"
                    }

                    ServiceVPNHelper.start(reason, context)
                }, 2000L)
            }
        }
    }

    private fun broadcastDNSCryptState(autoStartDNSCrypt: Boolean) {
        if (autoStartDNSCrypt && modulesStatus.dnsCryptState == RUNNING) {
            modulesStatusBroadcaster.get().broadcastDNSCryptRunning()
        }
        if (autoStartDNSCrypt && modulesStatus.isDnsCryptReady) {
            modulesStatusBroadcaster.get().broadcastDNSCryptReady()
        }
        if (!autoStartDNSCrypt && modulesStatus.dnsCryptState == STOPPED) {
            modulesStatusBroadcaster.get().broadcastDNSCryptStopped()
        }
    }

    private fun broadcastControlDisabled() {
        modulesStatusBroadcaster.get().broadcastRemoteControlDisabled()
        logw("BootCompleteReceiver received SHELL_CONTROL, but the appropriate option is disabled!")
    }

    private fun startHOTSPOT(preferences: PreferenceRepository) {

        preferences.setBoolPreference(TortaeKeys.WIFI_ACCESS_POINT_IS_ON, true)

        if (!apManager.get().configApState()) {
            val intent_tether = Intent(Intent.ACTION_MAIN, null as Uri?)
            intent_tether.addCategory(Intent.CATEGORY_LAUNCHER)
            val cn = ComponentName("com.android.settings", "com.android.settings.TetherSettings")
            intent_tether.setComponent(cn)
            intent_tether.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            try {
                context.startActivity(intent_tether)
            } catch (e: Exception) {
                loge("BootCompleteReceiver startHOTSPOT", e)
            }
        }
    }

    private fun startStopRestartModules(
        autoStartDNSCrypt: Boolean,
        autoStartFirewall: Boolean
    ) {

        val modulesStatus = ModulesStatus.getInstance()

        if (autoStartDNSCrypt) {
            runDNSCrypt()
            modulesStatus.setIptablesRulesUpdateRequested(true)
        } else if (ModulesAux.isDnsCryptSavedStateRunning()) {
            stopDNSCrypt()
        } else {
            modulesStatus.dnsCryptState = STOPPED
        }

        if (autoStartFirewall) {
            modulesStatus.setFirewallState(STARTING, preferenceRepository.get())
            if (!autoStartDNSCrypt) {
                ModulesAux.makeModulesStateExtraLoop(context)
            }
        } else {
            modulesStatus.setFirewallState(STOPPED, preferenceRepository.get())
        }

        saveModulesStateRunning(autoStartDNSCrypt)

    }

    private fun saveModulesStateRunning(saveDNSCryptRunning: Boolean) {
        ModulesAux.saveDNSCryptStateRunning(saveDNSCryptRunning)
    }

    private fun resetModulesSavedState(preferences: PreferenceRepository) {
        // #21 G7-RESIDUAL: the token lives in the Rust `app-state` record now (the [preferences]
        // param stays for signature stability at the call sites).
        AppStateBridge.setSavedDnsCryptState(ModuleState.UNDEFINED.toString())
        ModulesAux.saveFirewallStateRunning(false)
    }

    private fun runDNSCrypt() {
        ModulesRunner.runDNSCrypt(context)
    }

    private fun stopDNSCrypt() {
        ModulesKiller.stopDNSCrypt(context)
    }

    private fun stopServicesForeground(context: Context, mode: OperationMode, fixTTL: Boolean) {

        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (mode == VPN_MODE || mode == ROOT_MODE && fixTTL) {
                val stopVPNServiceForeground = Intent(context, VpnService::class.java)
                stopVPNServiceForeground.setAction(ACTION_STOP_SERVICE_FOREGROUND)
                stopVPNServiceForeground.putExtra("showNotification", true)
                if (App.instance.isAppForeground) {
                    try {
                        context.startService(stopVPNServiceForeground)
                    } catch (e: Exception) {
                        loge("BootCompleteReceiver stopServicesForeground", e)
                        context.startForegroundService(stopVPNServiceForeground)
                    }
                } else {
                    context.startForegroundService(stopVPNServiceForeground)
                }
            }

            ModulesActionSender.sendIntent(context, ACTION_STOP_SERVICE_FOREGROUND)

            logi("BootCompleteReceiver stop running services foreground")
        }
    }

    companion object {

        const val ALWAYS_ON_VPN = "pillar.kuma_saimono.libumdnscrypt.ALWAYS_ON_VPN"
        const val SHELL_SCRIPT_CONTROL = "pillar.kuma_saimono.libumdnscrypt.SHELL_SCRIPT_CONTROL"

        const val MANAGE_DNSCRYPT_EXTRA = "dnscrypt"
    }
}
