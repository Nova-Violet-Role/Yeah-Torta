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

package pillar.kuma_saimono.libumdnscrypt.utils.apps

import kotlinx.coroutines.*
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import javax.inject.Inject
import javax.inject.Named
import javax.inject.Singleton

private const val APPS_HANDLING_MAX_TIME_SEC = 60

@Singleton
class InstalledAppNamesStorage @Inject constructor(
    @Named(CoroutinesModule.DISPATCHER_IO)
    dispatcherIo: CoroutineDispatcher
) {

    private val coroutineScope = CoroutineScope(
        SupervisorJob() +
                dispatcherIo +
                CoroutineName("InstalledAppNamesStorage") +
                CoroutineExceptionHandler { _, throwable ->
                    loge("InstalledAppNamesStorage uncaught exception", throwable, true)
                }
    )

    private val inProgress = AtomicBoolean(false)

    private val appUidToNames = ConcurrentHashMap<Int, String>()

    fun getAppNameByUid(uid: Int): String? {
        if (appUidToNames.isEmpty()) {
            updateAppUidToNames()
        }
        return appUidToNames[uid]
    }

    fun updateAppUidToNames(apps: List<ApplicationData>) {
        apps.forEach {
            appUidToNames[it.uid] = it.names.joinToString(", ")
        }
    }

    fun clearAppUidToNames() {
        appUidToNames.clear()
    }

    fun updateAppUidToNames() {
        if (inProgress.compareAndSet(false, true)) {
            coroutineScope.launch {
                withTimeout(APPS_HANDLING_MAX_TIME_SEC * 1000L) {
                    try {
                        InstalledApplicationsManager.Builder()
                            .build()
                            .getInstalledApps()
                    } catch (e: Exception) {
                        loge("InstalledAppNamesStorage updateAppUidToNames", e)
                    } finally {
                        inProgress.getAndSet(false)
                    }
                }
            }
        }
    }

}
