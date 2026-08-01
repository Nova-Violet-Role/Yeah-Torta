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

package pillar.kuma_saimono.libumdnscrypt.domain.log_reader

import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.ConnectionRecordsInteractor
import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.dnscrypt.DNSCryptInteractor
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import java.lang.Exception
import java.util.concurrent.locks.ReentrantLock

private const val TIMER_INITIAL_DELAY = 1L
private const val TIMER_INITIAL_PERIOD = 1L
private const val TIMER_MAIN_PERIOD = 5L
private const val COUNTER_STARTING = 30
private const val COUNTER_STOPPING = 5

class LogReaderLoop(
    dnsCryptInteractor: DNSCryptInteractor,
    private val connectionRecordsInteractor: ConnectionRecordsInteractor
) {
    private val reentrantLock = ReentrantLock()

    private val logReaderFacade = LogReaderFacade(
        dnsCryptInteractor,
        connectionRecordsInteractor
    )

    private var timer: ScheduledExecutor? = null
    private var displayPeriod: Long = 0

    private var counterStarting = COUNTER_STARTING
    private var counterStopping = COUNTER_STOPPING

    fun startLogsParser(period: Long = TIMER_INITIAL_PERIOD) {

        if (!reentrantLock.tryLock()) {
            return
        }

        try {
            startLoop(period)
        } catch (e: Exception) {
            loge("LogReaderLoop startLogsParser", e, true)
        } finally {
            if (reentrantLock.isHeldByCurrentThread) {
                reentrantLock.unlock()
            }
        }
    }

    private fun startLoop(period: Long) {
        if (timer?.isLooping() == true && period == displayPeriod) {
            return
        }

        logi("LogReaderLoop startLogsParser, period $period sec")

        displayPeriod = period

        timer?.stopExecutor()

        timer = ScheduledExecutor(TIMER_INITIAL_DELAY, period)

        timer?.execute { parseLogs() }
    }

    private fun stopLogsParser() {
        reentrantLock.lock()
        try {
            timer?.stopExecutor()
            timer = null
            connectionRecordsInteractor.stopConverter(true)
            //App.instance.subcomponentsManager.releaseLogReaderScope()
            logi("LogReaderLoop stopLogsParser")
        } catch (e: Exception) {
            loge("LogReaderLoop stopLogsParser", e)
        } finally {
            reentrantLock.unlock()
        }
    }

    private fun parseLogs() {
        if (logReaderFacade.isAnyListenerAvailable()) {
            counterStopping = COUNTER_STOPPING
        } else {
            counterStopping--
        }

        if (counterStopping <= 0) {
            stopLogsParser()
            return
        }

        logReaderFacade.parseDNSCryptLog()

        logReaderFacade.convertConnectionRecords()

        if (logReaderFacade.isModulesStateNotChanging()) {
            counterStarting--
        } else {
            counterStarting = COUNTER_STARTING
        }

        if (counterStarting == 0) {
            startLogsParser(TIMER_MAIN_PERIOD)
            counterStarting = COUNTER_STARTING
        }
    }
}
