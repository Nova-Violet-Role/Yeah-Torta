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

package pillar.kuma_saimono.libumdnscrypt.utils.root

import android.annotation.SuppressLint
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import javax.inject.Inject
import javax.inject.Named
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RUNNING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.OPERATION_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ROOT_IS_AVAILABLE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.VPN_SERVICE_ENABLED
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper

@SuppressLint("UnsafeOptInUsageWarning")
@Suppress("DEPRECATION")
class RootExecService : Service(),
    RootExecutor.OnCommandsProgressListener,
    RootExecutor.OnCommandsDoneListener {

    @Inject
    lateinit var rootExecutor: RootExecutor
    @Inject
    @field:Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    lateinit var defaultPreferences: dagger.Lazy<SharedPreferences>
    @Inject
    lateinit var preferenceRepository: dagger.Lazy<PreferenceRepository>

    private var systemNotificationManager: NotificationManager? = null
    private var serviceNotificationManager: RootServiceNotificationManager? = null


    override fun onCreate() {
        App.instance.daggerComponent.inject(this)
        super.onCreate()

        systemNotificationManager =
            this.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager?
        serviceNotificationManager = RootServiceNotificationManager(this, systemNotificationManager!!)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && systemNotificationManager != null) {
            serviceNotificationManager!!.createNotificationChannel()
        }

        rootExecutor.onCommandsDoneListener = this
        rootExecutor.onCommandsProgressListener = this
    }

    override fun onDestroy() {

        rootExecutor.onCommandsDoneListener = null
        rootExecutor.onCommandsProgressListener = null

        rootExecutor.stopExecutor()

        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {

        moveServiceToForeground()

        if (intent == null) {
            moveServiceToBackground()
            return START_NOT_STICKY
        }

        val action = intent.action

        if (action == null || action.isEmpty()) {

            moveServiceToBackground()
            return START_NOT_STICKY
        }

        if (action == RUN_COMMAND) {
            val rootCommands = intent.getSerializableExtra("Commands") as RootCommands?
            val mark = intent.getIntExtra("Mark", 0)

            // Only `rootCommands.commands != null` was dropped (the compiler proved THAT term
            // constant, col 41). `rootCommands != null` is a REAL check -- it arrives from an
            // Intent extra and can genuinely be absent -- so it stays.
            if (rootCommands != null) {
                rootExecutor.execute(
                    rootCommands.commands,
                    mark
                )
            }
        }

        return START_NOT_STICKY
    }

    private fun sendResult(commandsResult: List<String>?, mark: Int) {

        if (commandsResult == null || mark == RootCommandsMark.NULL_MARK) {
            return
        }

        if (commandsResult.isNotEmpty()
            && commandsResult[0] == RootConsoleClosedException.MESSAGE) {
            switchToVpnMode()
        }

        val comResult = RootCommands(commandsResult)
        val intent = Intent(COMMAND_RESULT)
        intent.putExtra("CommandsResult", comResult)
        intent.putExtra("Mark", mark)
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
    }

    override fun onBind(intent: Intent): IBinder? {
        return null
    }

    private fun moveServiceToForeground() {
        if (systemNotificationManager != null) {
            serviceNotificationManager!!.sendNotification(
                uniffi.torta_core.tortaText("notification_exec_root_commands"),
                ""
            )
        }
    }

    private fun moveServiceToBackground() {
        if (systemNotificationManager != null) {

            systemNotificationManager!!.cancel(RootServiceNotificationManager.DEFAULT_NOTIFICATION_ID)

            try {
                stopForeground(true)
            } catch (e: Exception) {
                loge("RootExecService moveServiceToBackground", e)
            }

            serviceNotificationManager!!.resetNotification()
        }
    }

    override fun onCommandsProgress(progress: Int) {
        updateNotificationProgress(progress)
    }

    private fun updateNotificationProgress(progress: Int) {
        if (systemNotificationManager != null) {
            serviceNotificationManager!!.updateNotification(
                uniffi.torta_core.tortaText("notification_exec_root_commands"),
                "",
                progress
            )
        }
    }

    override fun onCommandsDone(results: List<String>, mark: Int) {
        sendResult(results, mark)
        moveServiceToBackground()
    }

    override fun onTimeout(startId: Int) {
        moveServiceToBackground()
        super.onTimeout(startId)
    }

    private fun switchToVpnMode() {

        val prepareIntent = VpnService.prepare(this)
        val vpnServiceEnabled = defaultPreferences.get().getBoolean(VPN_SERVICE_ENABLED, false)
        if (prepareIntent != null || vpnServiceEnabled) {
            return
        }

        val modulesStatus = ModulesStatus.getInstance()
        modulesStatus.mode = OperationMode.VPN_MODE
        preferenceRepository.get()
            .setStringPreference(OPERATION_MODE, OperationMode.VPN_MODE.toString())
        logi("VPN mode enabled")


        if (modulesStatus.dnsCryptState == RUNNING
            || modulesStatus.firewallState == STARTING
            || modulesStatus.firewallState == RUNNING) {
            defaultPreferences.get().edit().putBoolean(VPN_SERVICE_ENABLED, true).apply()
            ServiceVPNHelper.start(
                "Root exec service start VPN service after root console failed",
                this
            )
        }
    }

    class RootConsoleClosedException : IllegalStateException(MESSAGE) {

        companion object {
            const val MESSAGE = "Root is not available!"
        }
    }

    companion object {

        const val RUN_COMMAND = "pillar.kuma_saimono.libumdnscrypt.action.RUN_COMMAND"
        const val COMMAND_RESULT = "pillar.kuma_saimono.libumdnscrypt.action.COMMANDS_RESULT"
        const val LOG_TAG = "pillar.kuma_saimono.TPDCLogs"

        @JvmStatic
        fun performAction(context: Context, intent: Intent?) {
            val preferences = App.instance.daggerComponent.getPreferenceRepository().get()

            val rootIsAvailable = preferences.getBoolPreference(ROOT_IS_AVAILABLE)

            if (intent == null || intent.action == "" || !rootIsAvailable) return


            logi("RootExecService Root = " + true + " performAction")

            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            } catch (e: Exception) {
                loge("RootExecService performAction", e, true)
            }
        }
    }
}
