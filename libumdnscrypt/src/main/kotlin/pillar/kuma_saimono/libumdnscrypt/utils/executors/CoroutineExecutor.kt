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

package pillar.kuma_saimono.libumdnscrypt.utils.executors

import kotlinx.coroutines.*
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import javax.inject.Inject
import javax.inject.Named

class CoroutineExecutor @Inject constructor(
    @Named(CoroutinesModule.SUPERVISOR_JOB_IO_DISPATCHER_SCOPE_SINGLETON)
    val baseCoroutineScope: CoroutineScope,
    val coroutineExceptionHandler: CoroutineExceptionHandler
) {
    inline fun submit(
        name: String,
        crossinline block: () -> Unit
    ): Job {
        val scope = baseCoroutineScope + CoroutineName(name) + coroutineExceptionHandler
        return scope.launch {
            runInterruptible(coroutineContext) {
                block()
            }
        }
    }

    @JvmOverloads
    inline fun <T> execute(
        maxExecutingTimeMinutes: Int = EXECUTE_TIMEOUT_MINUTES,
        name: String,
        crossinline block: () -> T
    ): Job {
        val scope = baseCoroutineScope + CoroutineName(name) + coroutineExceptionHandler
        return scope.launch {
            if (maxExecutingTimeMinutes == 0) {
                runInterruptible(coroutineContext) {
                    block()
                }
            } else {
                withTimeoutOrNull(maxExecutingTimeMinutes * 60 * 1000L) {
                    runInterruptible(coroutineContext) {
                        block()
                    }
                }
            }
        }
    }

    @JvmOverloads
    inline fun <T> repeat(
        times: Int,
        delaySec: Int,
        maxExecutingTimeMinutes: Int = EXECUTE_TIMEOUT_MINUTES,
        name: String,
        crossinline block: () -> T
    ): Job {
        val scope = baseCoroutineScope + CoroutineName(name) + coroutineExceptionHandler

        return scope.launch {
            var timesCount = 0
            while ((times == 0 || timesCount < times) && isActive) {
                delay(delaySec * 1000L)
                if (maxExecutingTimeMinutes == 0) {
                    runInterruptible(coroutineContext) {
                        block()
                    }
                } else {
                    withTimeoutOrNull(maxExecutingTimeMinutes * 60 * 1000L) {
                        runInterruptible(coroutineContext) {
                            block()
                        }
                    }
                }
                timesCount++
            }
        }
    }

    companion object {
        const val EXECUTE_TIMEOUT_MINUTES = 10
    }

}
