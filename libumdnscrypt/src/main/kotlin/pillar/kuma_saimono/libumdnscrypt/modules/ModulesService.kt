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

import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.widget.Toast
import androidx.preference.PreferenceManager
import dagger.Lazy
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.TopFragmentState.DNSCryptVersion
import pillar.kuma_saimono.libumdnscrypt.arp.ArpScanner
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.connection_checker.ConnectionCheckerInteractor
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.ACTION_DISMISS_NOTIFICATION
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.ACTION_RECOVER_SERVICE
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.ACTION_RESTART_DNSCRYPT
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.ACTION_ROTATE_RESOLVERS_NOW
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.ACTION_START_DNSCRYPT
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.ACTION_START_ENGINE
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.ACTION_STOP_DNSCRYPT
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.ACTION_STOP_ENGINE
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.ACTION_STOP_SERVICE
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.ACTION_STOP_SERVICE_FOREGROUND
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.CLEAR_IPTABLES_COMMANDS_HASH
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.EXTRA_LOOP
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.SLOWDOWN_LOOP
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.SPEEDUP_LOOP
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.START_ARP_SCANNER
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions.STOP_ARP_SCANNER
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Utils
import pillar.kuma_saimono.libumdnscrypt.utils.ap.InternetSharingChecker
import pillar.kuma_saimono.libumdnscrypt.utils.apps.InstalledAppNamesStorage
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RESTARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RUNNING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.PROXY_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.ROOT_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.UNDEFINED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode.VPN_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.executors.CoroutineExecutor
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.portchecker.PortChecker
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ARP_SPOOFING_DETECTION
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FIX_TTL
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.OPERATION_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ROOT_IS_AVAILABLE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.RUN_MODULES_WITH_ROOT
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.VPN_SERVICE_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootExecService
import pillar.kuma_saimono.libumdnscrypt.utils.wakelock.WakeLocksManager
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper
import java.io.File
import java.io.IOException
import java.io.PrintWriter
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Named

class ModulesService : Service() {

    @Inject
    lateinit var preferenceRepository: Lazy<PreferenceRepository>

    @Inject
    @field:Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    lateinit var defaultSharedPreferences: Lazy<SharedPreferences>

    @Inject
    lateinit var internetCheckerInteractor: Lazy<ConnectionCheckerInteractor>

    @Inject
    lateinit var modulesReceiver: Lazy<ModulesReceiver>

    @Volatile
    @Inject
    lateinit var handler: Lazy<Handler>

    @Inject
    lateinit var pathVars: Lazy<PathVars>

    @Inject
    lateinit var executor: CoroutineExecutor

    @Inject
    lateinit var installedAppNamesStorage: Lazy<InstalledAppNamesStorage>

    @Inject
    lateinit var portChecker: Lazy<PortChecker>

    private val modulesStatus = ModulesStatus.getInstance()

    private var systemNotificationManager: NotificationManager? = null
    private var checkModulesThreadsTimer: ScheduledExecutorService? = null
    private var scheduledFuture: ScheduledFuture<*>? = null
    private var timerPeriod = TIMER_HIGH_SPEED
    private var checkModulesStateTask: ModulesStateLoop? = null
    private var modulesKiller: ModulesKiller? = null
    private var usageStatistic: UsageStatistic? = null
    private var arpScanner: ArpScanner? = null
    private var serviceNotificationManager: ModulesServiceNotificationManager? = null

    override fun onCreate() {
        super.onCreate()

        systemNotificationManager =
            getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager?

        usageStatistic = UsageStatistic(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            var title = uniffi.torta_core.tortaText("app_name")
            var message = uniffi.torta_core.tortaText("notification_text")
            if (usageStatistic!!.isStatisticAllowed()) {
                title = usageStatistic!!.getTitle()
                message = usageStatistic!!.getMessage(System.currentTimeMillis())
            }

            serviceNotificationManager = ModulesServiceNotificationManager.getManager(this)
            serviceNotificationManager!!.createNotificationChannel(this)
            serviceNotificationManager!!.sendNotification(this, title, message, startTime)
        }

        App.instance.daggerComponent.inject(this)

        serviceIsRunning = true

        modulesKiller = ModulesKiller(this, pathVars.get())

        startModulesThreadsTimer()

        if (defaultSharedPreferences.get().getBoolean(ARP_SPOOFING_DETECTION, false)) {
            startArpScanner()
        }
    }


    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {

        var intent = intent

        if (intent != null && intent.action == ACTION_STOP_SERVICE_FOREGROUND) {
            stopModulesServiceForeground()
        }

        val showNotification: Boolean
        showNotification = if (intent != null) {
            intent.getBooleanExtra("showNotification", true)
        } else {
            Utils.isShowNotification(this)
        }

        if (showNotification) {

            var title = uniffi.torta_core.tortaText("app_name")
            var message = uniffi.torta_core.tortaText("notification_text")
            if (usageStatistic!!.isStatisticAllowed()) {
                title = usageStatistic!!.getTitle()
                message = usageStatistic!!.getMessage(System.currentTimeMillis())
            }
            if (serviceNotificationManager == null) {
                serviceNotificationManager = ModulesServiceNotificationManager
                    .getManager(this)
            }
            serviceNotificationManager!!.sendNotification(
                this,
                title,
                message,
                startTime
            )
            usageStatistic!!.serviceNotification = serviceNotificationManager

            if (usageStatistic!!.isStatisticAllowed()) {
                usageStatistic!!.startUpdate()
            }
        }

        if (intent != null && intent.action == ACTION_STOP_SERVICE_FOREGROUND) {
            stopModulesServiceForeground(startId)
            return START_NOT_STICKY
        }

        if (intent == null) {
            intent = Intent(ACTION_RECOVER_SERVICE)
        }

        val action = intent.action

        if (action == null) {
            stopService(startId)
            return START_NOT_STICKY
        }

        manageWakelocks()

        when (action) {
            ACTION_START_DNSCRYPT -> startDNSCrypt()
            ACTION_STOP_DNSCRYPT -> stopDNSCrypt()
            ACTION_RESTART_DNSCRYPT -> restartDNSCrypt()
            ACTION_ROTATE_RESOLVERS_NOW -> rotateResolversNow()
            ACTION_START_ENGINE -> startEngineStandalone()
            ACTION_STOP_ENGINE -> stopEngineStandalone()
            ACTION_DISMISS_NOTIFICATION -> dismissNotification(startId)
            ACTION_RECOVER_SERVICE -> recoverAppState()
            SPEEDUP_LOOP -> speedupTimer()
            SLOWDOWN_LOOP -> slowdownTimer()
            EXTRA_LOOP -> makeExtraLoop()
            ACTION_STOP_SERVICE -> {
                stopModulesService()
                return START_NOT_STICKY
            }
            START_ARP_SCANNER -> startArpScanner()
            STOP_ARP_SCANNER -> stopArpScanner()
            CLEAR_IPTABLES_COMMANDS_HASH -> clearIptablesCommandsSavedHash()
        }

        setBroadcastReceiver()

        return START_STICKY

    }

    private fun startEngineStandalone() {
        if (checkModulesStateTask != null) {
            checkModulesStateTask!!.startEngineStandalone()
        }
    }

    private fun stopEngineStandalone() {
        if (checkModulesStateTask != null) {
            checkModulesStateTask!!.stopEngineStandalone()
        }
    }

    // #2 nerd "Rotate Now" — delegate to the state-loop, the legitimate @ModulesServiceScope holder of
    // RotationManager (this AppComponent-injected service cannot hold it directly). No-op if not yet built.
    private fun rotateResolversNow() {
        if (checkModulesStateTask != null) {
            checkModulesStateTask!!.rotateResolversNow()
        }
    }

    private fun startDNSCrypt() {

        if (modulesStatus.dnsCryptState == STOPPED) {
            modulesStatus.dnsCryptState = STARTING
        }

        Thread {

            if (!modulesStatus.isUseModulesWithRoot) {
                val previousDnsCryptThread = modulesKiller!!.getDnsCryptThread()

                if (previousDnsCryptThread != null && previousDnsCryptThread.isAlive) {
                    changeDNSCryptStatus(previousDnsCryptThread)
                    return@Thread
                }
            }

            try {
                val previousDnsCryptThread = checkPreviouslyRunningDNSCryptModule()

                if (previousDnsCryptThread != null && previousDnsCryptThread.isAlive) {
                    changeDNSCryptStatus(previousDnsCryptThread)
                    return@Thread
                }

                if (stopDNSCryptIfPortIsBusy()) {
                    changeDNSCryptStatus(modulesKiller!!.getDnsCryptThread())
                    return@Thread
                }

                cleanLogFileNoRootMethod(
                    pathVars.get().appDataDir + "/logs/DnsCrypt.log",
                    uniffi.torta_core.tortaText("tvDNSDefaultLog") + " " + DNSCryptVersion
                )

                val modulesStarterHelper = ModulesStarterHelper(
                    this@ModulesService.applicationContext, handler.get()
                )
                val dnsCryptThread = Thread(modulesStarterHelper.getDNSCryptStarterRunnable())
                dnsCryptThread.name = "DNSCryptThread"
                dnsCryptThread.isDaemon = false
                try {
                    dnsCryptThread.priority = Thread.NORM_PRIORITY
                } catch (e: SecurityException) {
                    loge("ModulesService startDNSCrypt", e)
                }
                dnsCryptThread.start()

                changeDNSCryptStatus(dnsCryptThread)

            } catch (e: Exception) {
                loge("DnsCrypt was unable to start", e)
                handler.get().post {
                    Toast.makeText(this@ModulesService, e.message, Toast.LENGTH_LONG).show()
                }
            }

        }.start()
    }

    private fun checkPreviouslyRunningDNSCryptModule(): Thread? {

        if (modulesStatus.isUseModulesWithRoot) {
            return null
        }

        var result: Thread? = null

        try {
            if (modulesStatus.dnsCryptState != RESTARTING) {
                result = findThreadByName("DNSCryptThread")
            }
        } catch (e: Exception) {
            loge("checkPreviouslyRunningDNSCryptModule exception", e)
        }

        return result
    }

    private fun changeDNSCryptStatus(dnsCryptThread: Thread?) {

        makeDelay(2)

        if (modulesStatus.isUseModulesWithRoot || dnsCryptThread!!.isAlive) {
            modulesStatus.dnsCryptState = RUNNING

            if (modulesKiller != null && !modulesStatus.isUseModulesWithRoot) {
                modulesKiller!!.setDnsCryptThread(dnsCryptThread)
            }

            if (checkModulesStateTask != null && !modulesStatus.isUseModulesWithRoot) {
                checkModulesStateTask!!.setDnsCryptThread(dnsCryptThread!!)
            }

            checkInternetConnection()
        } else {
            modulesStatus.dnsCryptState = STOPPED
        }
    }

    private fun stopDNSCryptIfPortIsBusy(): Boolean {
        val checker = portChecker.get()
        if (checker.isPortBusy(pathVars.get().dnsCryptPort)) {
            try {
                modulesStatus.dnsCryptState = RESTARTING

                val killerThread = Thread(modulesKiller!!.getDNSCryptKillerRunnable())
                killerThread.start()

                while (killerThread.isAlive) {
                    killerThread.join()
                }

                makeDelay(5)

                if (modulesStatus.dnsCryptState == RUNNING) {
                    return true
                }

                modulesStatus.dnsCryptState = STARTING

            } catch (e: InterruptedException) {
                loge("ModulesService restartDNSCrypt join interrupted!", e)
            }
        }
        return false
    }

    private fun stopDNSCrypt() {
        Thread(modulesKiller!!.getDNSCryptKillerRunnable()).start()
    }

    private fun restartDNSCrypt() {

        if (modulesStatus.dnsCryptState != RUNNING) {
            return
        }


        Thread {
            try {
                modulesStatus.dnsCryptState = RESTARTING

                val killerThread = Thread(modulesKiller!!.getDNSCryptKillerRunnable())
                killerThread.start()

                while (killerThread.isAlive) {
                    killerThread.join()
                }

                makeDelay(5)

                if (modulesStatus.dnsCryptState != RUNNING) {
                    startDNSCrypt()
                }

            } catch (e: InterruptedException) {
                loge("ModulesService restartDNSCrypt join interrupted!", e)
            }

        }.start()
    }

    private fun checkInternetConnection() {
        val interactor = internetCheckerInteractor.get()
        interactor.setInternetConnectionResult(false)
        interactor.checkInternetConnection()
    }

    private fun dismissNotification(startId: Int) {
        try {
            systemNotificationManager!!.cancel(DEFAULT_NOTIFICATION_ID)
            stopForeground(true)
        } catch (e: Exception) {
            loge("ModulesService dismissNotification exception", e)
        }

        stopSelf(startId)
    }

    private fun startModulesThreadsTimer() {
        checkModulesThreadsTimer = Executors.newSingleThreadScheduledExecutor()
        checkModulesStateTask = ModulesStateLoop(this)
        scheduledFuture = checkModulesThreadsTimer!!.scheduleWithFixedDelay(
            checkModulesStateTask!!, 1L, timerPeriod.toLong(), TimeUnit.MILLISECONDS
        )
    }

    private fun speedupTimer() {
        if (timerPeriod != TIMER_HIGH_SPEED && checkModulesThreadsTimer != null
            && !checkModulesThreadsTimer!!.isShutdown && checkModulesStateTask != null
        ) {

            timerPeriod = TIMER_HIGH_SPEED

            if (scheduledFuture != null && !scheduledFuture!!.isCancelled) {
                scheduledFuture!!.cancel(false)
            }

            scheduledFuture = checkModulesThreadsTimer!!.scheduleWithFixedDelay(
                checkModulesStateTask!!, 1L, timerPeriod.toLong(), TimeUnit.MILLISECONDS
            )

            logi("ModulesService speedUPTimer")
        }
    }

    fun slowdownTimer() {
        if (timerPeriod != TIMER_LOW_SPEED && checkModulesThreadsTimer != null
            && !checkModulesThreadsTimer!!.isShutdown && checkModulesStateTask != null
        ) {

            timerPeriod = TIMER_LOW_SPEED

            if (scheduledFuture != null && !scheduledFuture!!.isCancelled) {
                scheduledFuture!!.cancel(false)
            }

            scheduledFuture = checkModulesThreadsTimer!!.scheduleWithFixedDelay(
                checkModulesStateTask!!, 1L, timerPeriod.toLong(), TimeUnit.MILLISECONDS
            )

            logi("ModulesService slowDOWNTimer")
        }
    }

    private fun makeExtraLoop() {
        if (timerPeriod != TIMER_HIGH_SPEED && checkModulesStateTask != null) {
            executor.submit("ModulesService makeExtraLoop") {
                checkModulesStateTask!!.run()
            }
        }
    }

    private fun stopModulesThreadsTimer() {
        if (checkModulesThreadsTimer != null && !checkModulesThreadsTimer!!.isShutdown) {
            checkModulesThreadsTimer!!.shutdown()
            checkModulesThreadsTimer = null
        }
    }

    private fun stopVPNServiceIfRunning() {
        val operationMode = modulesStatus.mode
        val prefs = defaultSharedPreferences.get()
        if ((operationMode == VPN_MODE || modulesStatus.isFixTTL) && prefs.getBoolean(VPN_SERVICE_ENABLED, false)) {
            ServiceVPNHelper.stop("ModulesService is destroyed", this)
        }
    }

    private fun manageWakelocks() {
        val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this)
        val lock = sharedPreferences.getBoolean("swWakelock", false)

        wakeLocksManager = WakeLocksManager.getInstance()
        wakeLocksManager!!.managePowerWakelock(this, lock)
        wakeLocksManager!!.manageWiFiLock(this, lock)
    }

    private fun releaseWakelocks() {
        if (wakeLocksManager != null) {
            wakeLocksManager!!.stopPowerWakelock()
            wakeLocksManager!!.stopWiFiLock()
        }
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }

    override fun onDestroy() {

        unregisterModulesBroadcastReceiver()

        if (usageStatistic != null) {
            usageStatistic!!.stopUpdate()
        }

        ModulesServiceNotificationManager.stopManager(this)

        releaseWakelocks()

        if (checkModulesStateTask != null && modulesStatus.mode == VPN_MODE) {
            checkModulesStateTask!!.removeHandlerTasks()
        }

        stopModulesThreadsTimer()

        stopArpScanner()

        stopVPNServiceIfRunning()

        handler.get().removeCallbacksAndMessages(null)

        InternetSharingChecker.resetTetherInterfaceNames()

        serviceIsRunning = false

        stopRootExecServiceIfRequired()

        installedAppNamesStorage.get().clearAppUidToNames()

        App.instance.subcomponentsManager.releaseModulesServiceSubcomponent()

        super.onDestroy()
    }

    private fun stopService(startID: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                systemNotificationManager!!.cancel(DEFAULT_NOTIFICATION_ID)
                stopForeground(true)
            } catch (e: Exception) {
                loge("ModulesService stopService", e)
            }

        }

        stopSelf(startID)
    }

    private fun recoverAppState() {

        modulesStatus.dnsCryptState = STOPPED

        if (modulesStatus.mode != null && modulesStatus.mode != UNDEFINED) {
            return
        }

        loge("Restoring application state, possibly after the crash.")

        Utils.startAppExitDetectService(this)

        val defaultPreferences = defaultSharedPreferences.get()
        val preferences = preferenceRepository.get()

        val rootIsAvailable = preferences.getBoolPreference(ROOT_IS_AVAILABLE)
        val runModulesWithRoot = defaultPreferences.getBoolean(RUN_MODULES_WITH_ROOT, false)
        modulesStatus.isFixTTL = defaultPreferences.getBoolean(FIX_TTL, false)

        val operationMode = preferences.getStringPreference(OPERATION_MODE)

        if (operationMode.isNotEmpty()) {
            val mode = OperationMode.valueOf(operationMode)
            ModulesAux.switchModes(rootIsAvailable, runModulesWithRoot, mode)
        }

        val savedDNSCryptStateRunning = ModulesAux.isDnsCryptSavedStateRunning()

        if (savedDNSCryptStateRunning && !runModulesWithRoot) {
            modulesStatus.isSystemDNSAllowed = true
        }

        if (savedDNSCryptStateRunning) {
            startDNSCrypt()
        }

        saveModulesStateRunning(savedDNSCryptStateRunning)
    }

    private fun saveModulesStateRunning(saveDNSCryptRunning: Boolean) {
        ModulesAux.saveDNSCryptStateRunning(saveDNSCryptRunning)
    }

    private fun stopModulesService() {
        try {
            systemNotificationManager!!.cancel(DEFAULT_NOTIFICATION_ID)
            stopForeground(true)
        } catch (e: Exception) {
            loge("ModulesService stopModulesService", e)
        }

        stopSelf()
    }

    private fun stopModulesServiceForeground() {

        try {
            systemNotificationManager!!.cancel(DEFAULT_NOTIFICATION_ID)
            stopForeground(true)
        } catch (e: Exception) {
            loge("ModulesService stopModulesServiceForeground1", e)
        }
    }

    private fun stopModulesServiceForeground(startId: Int) {

        try {
            systemNotificationManager!!.cancel(DEFAULT_NOTIFICATION_ID)
            stopForeground(true)
        } catch (e: Exception) {
            loge("ModulesService stopModulesServiceForeground2", e)
        }

        stopSelf(startId)
    }

    private fun setBroadcastReceiver() {
        val receiver = modulesReceiver.get()
        val mode = modulesStatus.mode
        if (mode == VPN_MODE || mode == PROXY_MODE
            || mode == ROOT_MODE && !modulesStatus.isUseModulesWithRoot
        ) {
            receiver.registerReceivers(this)
            internetCheckerInteractor.get().addListener(receiver)
        } else {
            unregisterModulesBroadcastReceiver()
            internetCheckerInteractor.get().removeListener(receiver)
        }

    }

    private fun unregisterModulesBroadcastReceiver() {
        try {
            modulesReceiver.get().unregisterReceivers()
        } catch (e: Exception) {
            logw("ModulesService unregister receiver", e)
        }
    }

    private fun makeDelay(sec: Int) {
        try {
            TimeUnit.SECONDS.sleep(sec.toLong())
        } catch (e: InterruptedException) {
            loge("ModulesService makeDelay interrupted!", e)
        }
    }

    fun findThreadByName(threadName: String): Thread? {
        val currentThread = Thread.currentThread()
        val threadGroup = getRootThreadGroup(currentThread)
        val allActiveThreads = threadGroup!!.activeCount()
        val allThreads = arrayOfNulls<Thread>(allActiveThreads)
        threadGroup.enumerate(allThreads)

        for (thread in allThreads) {
            var name = ""
            if (thread != null) {
                name = thread.name
            }
            //logi("Current threads " + name);
            if (name == threadName) {
                logi("Found old module thread " + name)
                return thread
            }
        }

        return null
    }

    private fun getRootThreadGroup(thread: Thread): ThreadGroup? {
        var rootGroup = thread.threadGroup
        while (rootGroup != null) {
            val parentGroup = rootGroup.parent
            if (parentGroup == null) {
                break
            }
            rootGroup = parentGroup
        }
        return rootGroup
    }

    private fun cleanLogFileNoRootMethod(logFilePath: String, text: String) {
        try {
            val f = File(pathVars.get().appDataDir + "/logs")

            if (f.mkdirs() && f.setReadable(true) && f.setWritable(true)) {
                logi("log dir created")
            }

            val writer = PrintWriter(logFilePath, "UTF-8")
            writer.println(text)
            writer.close()
        } catch (e: IOException) {
            loge("Unable to create dnsCrypt log file", e)
        }
    }

    private fun startArpScanner() {
        if (arpScanner == null) {
            try {
                arpScanner = ArpScanner.getArpComponent().get()
                arpScanner!!.start()
            } catch (e: Exception) {
                loge("ModulesService startArpScanner", e)
            }
        }
    }

    private fun stopArpScanner() {
        if (arpScanner != null) {
            arpScanner!!.stop()
            arpScanner = null
            ArpScanner.releaseArpComponent()
        }
    }

    private fun clearIptablesCommandsSavedHash() {
        if (checkModulesStateTask != null) {
            checkModulesStateTask!!.clearIptablesCommandHash()
        }
    }

    private fun stopRootExecServiceIfRequired() {
        val intent = Intent(this, RootExecService::class.java)
        stopService(intent)
    }

    companion object {
        const val DEFAULT_NOTIFICATION_ID = 101102

        @JvmField
        @Volatile
        var serviceIsRunning = false

        private const val TIMER_HIGH_SPEED = 1000
        private const val TIMER_LOW_SPEED = 30000

        const val DNSCRYPT_KEYWORD = "checkDNSRunning"

        private var wakeLocksManager: WakeLocksManager? = null
    }
}
