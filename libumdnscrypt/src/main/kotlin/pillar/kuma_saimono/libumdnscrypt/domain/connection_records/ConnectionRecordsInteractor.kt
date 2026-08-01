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

package pillar.kuma_saimono.libumdnscrypt.domain.connection_records

import android.content.SharedPreferences
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.di.logreader.LogReaderScope
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionData
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionLogEntry
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.CONNECTION_LOGS
import java.lang.Exception
import java.lang.ref.WeakReference
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Named

@LogReaderScope
class ConnectionRecordsInteractor @Inject constructor(
    private val connectionRecordsRepository: ConnectionRecordsRepository,
    private val converter: dagger.Lazy<ConnectionRecordsConverter>,
    private var parser: ConnectionRecordsParser,
    @Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: dagger.Lazy<SharedPreferences>
) {
    private val applicationContext = App.instance.applicationContext
    private val listeners =
        ConcurrentHashMap<Class<*>, WeakReference<OnConnectionRecordsUpdatedListener>>()

    fun <T : OnConnectionRecordsUpdatedListener> addListener(listener: T?) {
        listener?.let { listeners[it.javaClass] = WeakReference(it) }
    }

    fun <T : OnConnectionRecordsUpdatedListener> removeListener(listener: T?) {
        listener?.let { listeners.remove(it.javaClass) }
        //stopConverter()
    }

    fun hasAnyListener(): Boolean {
        return listeners.isNotEmpty()
    }

    fun convertRecords() {
        try {
            convert()
        } catch (e: Exception) {
            loge("ConnectionRecordsInteractor", e, true)
        }
    }

    fun clearConnectionRecords() {
        connectionRecordsRepository.clearConnectionRawRecords()
    }

    fun stopConverter(forceStop: Boolean = false) {
        if (listeners.isEmpty() || forceStop) {
            connectionRecordsRepository.connectionRawRecordsNoMoreRequired()
            converter.get().onStop()
        }
    }

    private fun convert() {
        val context = applicationContext

        if (context == null || listeners.isEmpty() || isRealTimeLogsDisabled()) {
            return
        }

        var rawConnections: List<ConnectionData> = emptyList()

        try {
            rawConnections = connectionRecordsRepository.getRawConnectionRecords()
        } catch (e: Exception) {
            loge("ConnectionRecordsInteractor getRawConnectionRecords", e, true)
        }

        if (rawConnections.isEmpty()) {
            return
        }

        var connectionRecords: List<ConnectionLogEntry>? = emptyList()

        try {
            connectionRecords = converter.get().convertRecords(rawConnections)
                .sortedBy { it.time }
        } catch (e: Exception) {
            loge("ConnectionRecordsInteractor convertRecords", e, true)
        }

        if (connectionRecords?.isEmpty() == true) {
            return
        }

        var records: String? = ""
        try {
            records = parser.formatLines(connectionRecords ?: emptyList())
        } catch (e: Exception) {
            loge("ConnectionRecordsInteractor formatLines", e, true)
        }

        if (records.isNullOrBlank()) {
            return
        }

        listeners.forEach { listener ->
            if (listener.value.get()?.isActive() == true) {
                listener.value.get()?.onConnectionRecordsUpdated(records)
            } else {
                removeListener(listener.value.get())

            }
        }
    }

    private fun isRealTimeLogsDisabled() =
        !defaultPreferences.get().getBoolean(CONNECTION_LOGS, true)
}
