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

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

class ScheduledExecutor(private val initialDelay: Long, private val period: Long) {
    @Volatile
    private var stopTimer = false

    private val timer: ScheduledExecutorService? = Executors.newScheduledThreadPool(0)

    fun execute(execute: () -> Unit) {
        timer?.scheduleWithFixedDelay({
            if (stopTimer) {
                if (!timer.isShutdown) {
                    timer.shutdown()
                }

                TimeUnit.SECONDS.sleep(5)

                if (!timer.isShutdown) {
                    timer.shutdownNow()
                }
            } else {
                execute()
            }
        }, initialDelay, period, TimeUnit.SECONDS)
    }

    fun stopExecutor() {
        stopTimer = true
    }

    fun isLooping(): Boolean {
        return timer?.isShutdown == false
    }
}
