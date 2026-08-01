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

package pillar.kuma_saimono.libumdnscrypt.nflog

import android.os.HandlerThread
import android.os.SystemClock
import com.jrummyapps.android.shell.Shell
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.domain.connection_checker.ConnectionCheckerInteractor
import pillar.kuma_saimono.libumdnscrypt.domain.connection_checker.OnInternetConnectionCheckedListener
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionData
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.DnsRecord
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.PacketRecord
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.NFLOG_GROUP
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.NFLOG_PREFIX
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPN
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Named

private const val ATTEMPTS_TO_OPEN_NFLOG = 5
private const val ATTEMPTS_TO_CLOSE_NFLOG = 5
private const val TIMEOUT_TO_CLOSE_NFLOG_SEC = 10
private const val NFLOG_LIB = "libnflog.so"
private const val NFLOG_PID_FILE_NAME = "nflog.pid"

@ModulesServiceScope
@ExperimentalCoroutinesApi
class NflogManager @Inject constructor(
    private val pathVars: dagger.Lazy<PathVars>,
    @Named(CoroutinesModule.DISPATCHER_IO)
    dispatcherIo: CoroutineDispatcher,
    private val nflogParser: NflogParser,
    private val checkConnectionInteractor: dagger.Lazy<ConnectionCheckerInteractor>
) : OnInternetConnectionCheckedListener {

    @Volatile
    private var nfLogStartFailed = false

    private val connectionDataRecords = ConcurrentHashMap<ConnectionData, Long>(
        16,
        0.75f,
        2
    )

    private val coroutineScope by lazy {
        CoroutineScope(
            SupervisorJob() +
                    dispatcherIo.limitedParallelism(2) +
                    CoroutineName("NflogManager") +
                    CoroutineExceptionHandler { _, throwable ->
                        loge("NflogManager uncaught exception", throwable, true)
                    }
        )
    }

    private val nflogMutableSharedFlow by lazy {
        MutableSharedFlow<NflogCommand>(
            replay = 1,
            extraBufferCapacity = 0,
            onBufferOverflow = BufferOverflow.DROP_OLDEST
        ).also { flow ->
            flow.onEach {
                when (it) {
                    NflogCommand.START -> startSequence()
                    NflogCommand.STOP -> stopSequence()
                }
            }.launchIn(coroutineScope)
        }
    }

    @Volatile
    private var nflogShell: Shell.Interactive? = null

    @Volatile
    private var handlerThread: HandlerThread? = null

    @Volatile
    private var nflogActive = false

    fun startNflog() = nflogMutableSharedFlow.tryEmit(NflogCommand.START)

    fun stopNflog() = nflogMutableSharedFlow.tryEmit(NflogCommand.STOP)

    private suspend fun startSequence() {
        try {

            if (nflogActive) {
                return
            }

            stopSequence()

            coroutineScope.launch {
                logi("Nflog running")
                openNflogShell()
            }
        } catch (e: Exception) {
            loge("NflogManager startNflog", e)
        }
    }

    private suspend fun stopSequence() {

        try {
            logi("Nflog stop")

            nflogActive = false

            killNflog()

            closeNflogShell() //Waits for the nflog to close and than releases resources

            stopNflogHandlerThread()

            clearRealTimeLogs()

            logi("Nflog stopped")
        } catch (e: Exception) {
            loge("NflogManager stopNflog", e)
        }

    }

    private suspend fun openNflogShell() {

        var attempts = 0

        if (nfLogStartFailed) {
            nfLogStartFailed = false
            unlistenConnectionChanges()
        }

        do {
            runCatching {

                if (attempts > 0) {
                    delay(attempts * 1000L)
                }

                startNfLogHandlerThread()

                delay(1000)

                val complete = nflogShell?.waitForIdle() //Waits for nflog to stop

                if (complete != false) {
                    attempts++
                }

                if (nflogActive && attempts < ATTEMPTS_TO_OPEN_NFLOG) {
                    closeNflogShell()
                    stopNflogHandlerThread()
                    loge("Attempt ${attempts + 1} to restart Nflog")
                }

            }.onFailure {
                attempts++
                loge("NflogManager openNflogShell", it)
            }
        } while (nflogActive && attempts < ATTEMPTS_TO_OPEN_NFLOG)

        if (nflogActive) {
            nfLogStartFailed = true
            listenConnectionChanges()
            loge("Attempts to start Nflog have ended")
        }

        nflogActive = false

    }

    //Waits for the nflog to close and than releases resources
    private suspend fun closeNflogShell() {
        try {
            nflogShell?.let { shell ->

                withTimeout(TIMEOUT_TO_CLOSE_NFLOG_SEC * 1000L) {
                    while (shell.isRunning && !shell.isIdle) {
                        delay(100)
                        killNflog()
                    }
                }

                if (shell.isIdle) {
                    shell.close()
                } else {
                    loge("NflogManager failed to close shell")
                }
            }
            nflogShell = null
        } catch (e: Exception) {
            loge("NflogManager closeNflogShell", e)
        }
    }

    private fun startNfLogHandlerThread() {
        handlerThread = object : HandlerThread("Nflog handler thread") {
            override fun run() {
                try {
                    nflogShell = Shell.Builder()
                        .setAutoHandler(true)
                        .useSU()
                        .setOnStdoutLineListener {
                            handleConnectionRecordLine(it)
                        }
                        .addCommand(getNflogStartCommand())
                        .open()
                    nflogActive = true
                } catch (e: Exception) {
                    loge("NflogManager startNfLogHandlerThread", e)
                } finally {
                    if (nflogShell?.isRunning != true || nflogShell?.isIdle != false) {
                        handlerThread?.quitSafely()
                    }
                }
            }

        }.also {
            it.start()
        }
    }

    private fun getNflogStartCommand(): String = with(pathVars.get()) {
        return "$nflogPath " +
                //"-ouid $appUid " +
                "-group $NFLOG_GROUP " +
                "-dport $dnsCryptPort " +
                "-prefix $NFLOG_PREFIX " +
                "-pidfile ${getPidFilePath()}"
    }

    private suspend fun killNflog() {

        val pid = readNflogPidFile()

        if (nflogShell?.isIdle != false && pid.isEmpty()) {
            return
        }

        var attempt = 0

        do {

            if (attempt > 0) {
                delay(attempt * 100L)
            }

            val command = if (attempt < 2) {
                getNflogKillCommand(pid, "").joinToString("; ")
            } else {
                getNflogKillCommand(pid, "SIGKILL").joinToString("; ")
            }

            val result = Shell.SU.run(command)

            attempt++

            if (nflogShell?.isIdle == false || result.stdout.contains(NFLOG_LIB)) {
                delay(attempt * 100L)
            }

            if ((nflogShell?.isIdle == false || result.stdout.contains(NFLOG_LIB))
                && attempt < ATTEMPTS_TO_CLOSE_NFLOG
            ) {
                logw("Attempt $attempt to kill nflog failed")
            }

        } while ((nflogShell?.isIdle == false || result.stdout.contains(NFLOG_LIB))
            && attempt < ATTEMPTS_TO_CLOSE_NFLOG
        )

        if (nflogShell?.isIdle == false) {
            loge("Failed to kill Nflog")
        }
    }

    private fun getNflogKillCommand(pid: String, signal: String) = mutableListOf<String>().apply {
        val nflog = pathVars.get().nflogPath
        val busybox = pathVars.get().busyboxPath.removeSuffix(" ")
        if (pid.isEmpty()) {
            if (signal.isEmpty()) {
                add("toybox pkill $nflog || true")
                add("pkill $nflog || true")
                add("$busybox pkill $nflog || true")
                add("$busybox kill $(pgrep $nflog) || true")
            } else {
                add("toybox pkill -$signal $nflog || true")
                add("pkill -$signal $nflog || true")
                add("$busybox pkill -$signal $nflog || true")
                add("$busybox kill -$signal $(pgrep $nflog) || true")
            }
        } else {
            if (signal.isEmpty()) {
                add("toolbox kill $pid || true")
                add("toybox kill $pid || true")
                add("kill $pid || true")
                add("$busybox kill $pid || true")
            } else {
                add("toolbox kill -s $signal $pid || true")
                add("toybox kill -s $signal $pid || true")
                add("kill -s $signal $pid || true")
                add("$busybox kill -s $signal $pid || true")
            }
        }
        add("$busybox sleep 1")
        add("$busybox pgrep -l $NFLOG_LIB || true")
    }

    private fun stopNflogHandlerThread() {
        if (handlerThread?.isAlive == true) {
            handlerThread?.quitSafely()
        }
    }

    private fun readNflogPidFile(): String = try {
        val filePath = getPidFilePath()
        File(filePath).let { file ->
            if (file.isFile) {
                Shell.SU.run("cat $filePath").stdout.first().trim()
            } else {
                logw("NflogManager was unable to read pid. The file does not exist.")
                ""
            }
        }
    } catch (e: Exception) {
        loge("NflogManager readNflogPidFile", e)
        ""
    }

    private fun getPidFilePath() = "${pathVars.get().appDataDir}/$NFLOG_PID_FILE_NAME"

    private fun handleConnectionRecordLine(line: String) {
        try {
            nflogParser.parse(line)?.let {
                when (it) {
                    is DnsRecord -> {
                        val creationTime = connectionDataRecords.remove(it)
                        connectionDataRecords.put(
                            it,
                            creationTime ?: SystemClock.elapsedRealtimeNanos()
                        )
                    }

                    is PacketRecord -> {
                        connectionDataRecords.remove(it)
                        connectionDataRecords.put(it, SystemClock.elapsedRealtimeNanos())
                    }
                }

            }

            if (connectionDataRecords.size >= ServiceVPN.LINES_IN_DNS_QUERY_RAW_RECORDS) {
                connectionDataRecords.keys
                    .sortedBy { it.time }
                    .take(ServiceVPN.LINES_IN_DNS_QUERY_RAW_RECORDS / 5)
                    .forEach { connectionDataRecords.remove(it) }
            }
        } catch (e: Exception) {
            loge("NflogManager parseLine $line", e)
        }
    }

    private enum class NflogCommand {
        START,
        STOP
    }

    fun getRealTimeLogs() = connectionDataRecords

    fun clearRealTimeLogs() {
        connectionDataRecords.clear()
    }

    override fun onConnectionChecked(available: Boolean) {
        if (available) {
            startNflog()
        }
    }

    override fun isActive(): Boolean = true

    private fun listenConnectionChanges() {
        checkConnectionInteractor.get().addListener(this)
    }

    private fun unlistenConnectionChanges() {
        checkConnectionInteractor.get().removeListener(this)
    }

}
