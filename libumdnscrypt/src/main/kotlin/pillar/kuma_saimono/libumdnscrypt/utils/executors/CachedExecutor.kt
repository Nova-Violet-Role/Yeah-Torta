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

import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.Exception

@Singleton
class CachedExecutor @Inject constructor() {

    private val executorService: ExecutorService by lazy { Executors.newCachedThreadPool() }

    fun submit(block: Runnable): Future<*>? =
        try {
            executorService.submit(block)
        } catch (e: Exception) {
            loge("CachedExecutor submit", e)
            null
        }

    //For testing purposes
    @Suppress("unused")
    private fun checkTimeout(future: Future<*>) {
        executorService.submit {
            try {
                future.get(2, TimeUnit.MINUTES)
            } catch (e: TimeoutException) {
                loge("CachedExecutor checkTimeout", e)
            } catch (ignored: Exception) {
            }
        }
    }
}
