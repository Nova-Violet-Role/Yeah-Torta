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

package pillar.kuma_saimono.libumdnscrypt.tiles

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.service.quicksettings.Tile
import android.widget.Toast
import androidx.annotation.Keep
import androidx.annotation.RequiresApi
import androidx.core.os.postDelayed
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import kotlinx.coroutines.*
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.modules.*
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Utils
import pillar.kuma_saimono.libumdnscrypt.utils.Utils.isInterfaceLocked
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.rust.AppStateBridge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ROOT_IS_AVAILABLE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.OPERATION_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.VPN_SERVICE_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PREVENT_DNS_LEAKS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.RUN_MODULES_WITH_ROOT
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FIX_TTL
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark.Companion.DNSCRYPT_RUN_FRAGMENT_MARK
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootExecService.Companion.COMMAND_RESULT
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper
import javax.inject.Inject
import javax.inject.Named

@Keep
@RequiresApi(Build.VERSION_CODES.N)
class ModulesControlTileManager @Inject constructor(
    private val dispatcherMain: MainCoroutineDispatcher,
    @Named(CoroutinesModule.SUPERVISOR_JOB_IO_DISPATCHER_SCOPE)
    private val baseCoroutineScope: CoroutineScope,
    private val coroutineExceptionHandler: CoroutineExceptionHandler,
    private val context: Context,
    private val preferenceRepository: PreferenceRepository,
    @Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: SharedPreferences,
    private val handler: Handler,
    private val pathVars: PathVars
) {
    private val modulesStatus = ModulesStatus.getInstance()

    @Volatile
    private var task: Job? = null
    private var tile: Tile? = null

    private val coroutineScope by lazy { baseCoroutineScope + coroutineExceptionHandler }

    fun startUpdatingState(tile: Tile, manageTask: ManageTask) {

        this.tile = tile

        task?.cancel()

        task = (coroutineScope + CoroutineName("Update tile $manageTask")).launch {
            while (isActive) {
                updateTile(manageTask)
                delay(UPDATE_INTERVAL_SEC * 1000L)
            }
        }
    }

    fun stopUpdatingState() {
        task?.cancel()
        tile = null
    }

    private suspend fun updateTile(manageTask: ManageTask) {
        val tile = tile ?: return

        var moduleState = ModuleState.UNDEFINED

        val labelUpdated = when (manageTask) {
            ManageTask.MANAGE_DNSCRYPT -> {
                moduleState = modulesStatus.dnsCryptState
                updateDnsCryptTileLabel(moduleState)
            }
        }

        val iconUpdated = updateTileIconState(moduleState)

        if (labelUpdated || iconUpdated) {
            withContext(dispatcherMain) {
                tile.updateTile()
            }
        }
    }

    private fun updateDnsCryptTileLabel(moduleState: ModuleState): Boolean {
        val tile = tile ?: return false

        val savedTileLabel = tile.label

        val newTileLabel = when (moduleState) {
            ModuleState.STARTING, ModuleState.RESTARTING -> {
                uniffi.torta_core.tortaText("tvDNSStarting")
            }
            ModuleState.RUNNING -> {
                refreshModuleInterfaceIfAppLaunched(
                    DNSCRYPT_RUN_FRAGMENT_MARK,
                    ModulesService.DNSCRYPT_KEYWORD,
                    pathVars.dnsCryptPath
                )
                uniffi.torta_core.tortaText("tvDNSRunning")
            }
            ModuleState.STOPPING -> {
                uniffi.torta_core.tortaText("tvDNSStopping")
            }
            else -> {
                uniffi.torta_core.tortaText("tvDNSStop")
            }
        }

        if (savedTileLabel != newTileLabel) {
            tile.label = newTileLabel
            return true
        }
        return false
    }

    private fun updateTileIconState(moduleState: ModuleState): Boolean {
        val tile = tile ?: return false

        val savedTileState = tile.state

        val newTileState = when (moduleState) {
            ModuleState.RUNNING, ModuleState.STARTING, ModuleState.RESTARTING -> Tile.STATE_ACTIVE
            else -> Tile.STATE_INACTIVE
        }

        if (savedTileState != newTileState) {
            tile.state = newTileState
            return true
        }
        return false
    }

    fun manageModule(tile: Tile, manageTask: ManageTask) {

        (coroutineScope + CoroutineName("Manage tile $manageTask")).launch {
            withTimeout(MANAGE_MODULE_TIMEOUT_SEC * 1000L) {
                initActionsInCaseOfFirstStart()

                when (manageTask) {
                    ManageTask.MANAGE_DNSCRYPT -> manageDnsCrypt()
                }

                ModulesAux.speedupModulesStateLoopTimer(context)

                startVpnServiceIfRequired()
            }
        }

        if (tile.state == Tile.STATE_INACTIVE) {
            tile.state = Tile.STATE_ACTIVE
            tile.updateTile()
        } else if (tile.state == Tile.STATE_ACTIVE) {
            tile.state = Tile.STATE_INACTIVE
            tile.updateTile()
        }

        if (task?.isCompleted != false) {
            startUpdatingState(tile, manageTask)
        }
    }

    private fun initActionsInCaseOfFirstStart() {
        var mode = modulesStatus.mode ?: OperationMode.UNDEFINED

        if (mode != OperationMode.UNDEFINED) {
            return
        }

        resetModulesSavedState(preferenceRepository)

        val rootIsAvailable: Boolean = preferenceRepository.getBoolPreference(ROOT_IS_AVAILABLE)
        val runModulesWithRoot: Boolean =
            defaultPreferences.getBoolean(RUN_MODULES_WITH_ROOT, false)
        val operationMode: String = preferenceRepository.getStringPreference(OPERATION_MODE)

        if (operationMode.isNotEmpty()) {
            mode = OperationMode.valueOf(operationMode)
        }

        ModulesAux.switchModes(rootIsAvailable, runModulesWithRoot, mode)

        val fixTTL = defaultPreferences.getBoolean(FIX_TTL, false)
        modulesStatus.isFixTTL = fixTTL

        Utils.startAppExitDetectService(context)
    }

    private fun resetModulesSavedState(preferences: PreferenceRepository) {
        // #21 G7-RESIDUAL: the token lives in the Rust `app-state` record now (the [preferences]
        // param stays for signature stability at the call sites).
        AppStateBridge.setSavedDnsCryptState(ModuleState.UNDEFINED.toString())
    }

    private suspend fun manageDnsCrypt() {

        if (isInterfaceLocked(preferenceRepository)) {
            showInterfaceLockedToast()
            return
        }

        if (modulesStatus.dnsCryptState != ModuleState.RUNNING) {

            if (isStartingNotAllowed(modulesStatus.dnsCryptState)) {
                showPleaseWaitToast()
                return
            }

            runDNSCrypt()
        } else if (modulesStatus.dnsCryptState == ModuleState.RUNNING) {
            stopDNSCrypt()
        }
    }

    private fun runDNSCrypt() {
        allowSystemDNS()
        ModulesRunner.runDNSCrypt(context)
        ModulesAux.saveDNSCryptStateRunning(true)
    }

    private fun stopDNSCrypt() {
        ModulesKiller.stopDNSCrypt(context)
        ModulesAux.saveDNSCryptStateRunning(false)
    }

    private fun startVpnServiceIfRequired() {
        if (modulesStatus.mode != OperationMode.VPN_MODE && !modulesStatus.isFixTTL
            || defaultPreferences.getBoolean(VPN_SERVICE_ENABLED, false)
        ) {
            return
        }

        if (VpnService.prepare(context) == null) {
            handler.postDelayed(VPN_SERVICE_START_DELAY_SEC * 1000L) {
                defaultPreferences.edit().let {
                    it.putBoolean(VPN_SERVICE_ENABLED, true)
                    it.apply()
                }
                ServiceVPNHelper.start("Tile start", context)
            }
        }

    }

    private fun isStartingNotAllowed(moduleState: ModuleState): Boolean {
        return modulesStatus.isContextUIDUpdateRequested
                || !(moduleState == ModuleState.STOPPED
                || moduleState == ModuleState.FAULT
                || moduleState == ModuleState.UNDEFINED)
    }

    private fun allowSystemDNS() {
        if ((!modulesStatus.isRootAvailable || !modulesStatus.isUseModulesWithRoot)
            && !defaultPreferences.getBoolean(PREVENT_DNS_LEAKS, false)
        ) {
            modulesStatus.isSystemDNSAllowed = true
        }
    }

    private suspend fun showInterfaceLockedToast() {
        showToast(uniffi.torta_core.tortaText("action_mode_dialog_locked"))
    }

    private suspend fun showPleaseWaitToast() {
        showToast(uniffi.torta_core.tortaText("please_wait"))
    }

    private suspend fun showToast(message: String) = withContext(dispatcherMain) {
        Toast.makeText(context, message, Toast.LENGTH_LONG).show()
    }

    private fun refreshModuleInterfaceIfAppLaunched(
        moduleMark: Int,
        moduleKeyWord: String,
        binaryPath: String
    ) {
        val comResult = RootCommands(arrayListOf(moduleKeyWord, binaryPath))
        val intent = Intent(COMMAND_RESULT)
        intent.putExtra("CommandsResult", comResult)
        intent.putExtra("Mark", moduleMark)
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent)
    }

    enum class ManageTask {
        MANAGE_DNSCRYPT
    }

    companion object {
        const val UPDATE_INTERVAL_SEC = 1
        private const val VPN_SERVICE_START_DELAY_SEC = 2
        private const val MANAGE_MODULE_TIMEOUT_SEC = 3
    }
}
