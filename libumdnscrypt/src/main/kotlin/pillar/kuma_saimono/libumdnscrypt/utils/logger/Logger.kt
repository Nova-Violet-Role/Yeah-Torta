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

package pillar.kuma_saimono.libumdnscrypt.utils.logger

import android.util.Log
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

private const val LOG_TAG = "TPDCLogs"
private const val MAX_LOG_LENGTH = 16000
private const val MAX_LOG_ENTRY_LENGTH = 4000

object Logger {

    private val coroutineScope by lazy {
        CoroutineScope(
            SupervisorJob() +
                    Dispatchers.IO +
                    CoroutineName("Logger") +
                    CoroutineExceptionHandler { _, throwable ->
                        Log.e(LOG_TAG, "Logger uncaught exception", throwable)
                    }
        )
    }

    private val logFlow by lazy {
        MutableSharedFlow<LogEntry>(
            replay = 0,
            extraBufferCapacity = 100,
            onBufferOverflow = BufferOverflow.DROP_OLDEST
        ).also { flow ->
            flow.distinctUntilChanged()
                .onEach {
                    truncateLog(it.level, it.message)
                }.launchIn(coroutineScope)
        }
    }

    private fun truncateLog(level: LogLevel, content: String?) {
        content ?: return
        if (content.length > MAX_LOG_LENGTH) {
            truncateLog(level, content.substring(0, MAX_LOG_LENGTH))
        } else if (content.length > MAX_LOG_ENTRY_LENGTH) {
            printLog(level, content.substring(0, MAX_LOG_ENTRY_LENGTH))
            truncateLog(level, content.substring(MAX_LOG_ENTRY_LENGTH))
        } else {
            printLog(level, content)
        }
    }

    private fun printLog(level: LogLevel, content: String) {
        when (level) {
            LogLevel.INFO -> Log.i(LOG_TAG, content)
            LogLevel.WARN -> Log.w(LOG_TAG, content)
            LogLevel.ERROR -> Log.e(LOG_TAG, content)
        }
    }

    @JvmStatic
    fun logi(message: String) {
        logFlow.tryEmit(LogEntry(LogLevel.INFO, message))
    }

    @JvmStatic
    fun logw(message: String) {
        logFlow.tryEmit(LogEntry(LogLevel.WARN, message))
    }

    @JvmStatic
    fun logw(message: String, e: Throwable) {
        logFlow.tryEmit(
            LogEntry(
                LogLevel.WARN,
                "$message ${e.javaClass.canonicalName} ${e.message} ${e.cause ?: ""}"
            )
        )
    }

    @JvmStatic
    fun loge(message: String, e: Throwable) {
        logFlow.tryEmit(
            LogEntry(
                LogLevel.ERROR,
                "$message ${e.javaClass.canonicalName} ${e.message} ${e.cause ?: ""}"
            )
        )
    }

    @JvmStatic
    fun loge(message: String, e: Throwable, printStackTrace: Boolean) {
        logFlow.tryEmit(
            LogEntry(
                LogLevel.ERROR,
                "$message ${e.javaClass.canonicalName} ${e.message} ${e.cause ?: ""}" +
                        if (printStackTrace) "\n" + Log.getStackTraceString(e) else ""
            )
        )
    }

    @JvmStatic
    fun loge(message: String) {
        logFlow.tryEmit(LogEntry(LogLevel.ERROR, message))
    }

    private data class LogEntry(
        val level: LogLevel,
        val message: String
    )

    private enum class LogLevel {
        INFO,
        WARN,
        ERROR,
    }
}
