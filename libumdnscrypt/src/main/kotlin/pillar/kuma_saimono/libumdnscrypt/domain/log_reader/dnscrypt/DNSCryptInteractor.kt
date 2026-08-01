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

package pillar.kuma_saimono.libumdnscrypt.domain.log_reader.dnscrypt

import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.ModulesLogRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.lang.Exception
import java.lang.ref.WeakReference
import java.util.concurrent.ConcurrentHashMap

class DNSCryptInteractor(private val modulesLogRepository: ModulesLogRepository) {
    private val listeners =
        ConcurrentHashMap<Class<*>, WeakReference<OnDNSCryptLogUpdatedListener>>()
    private var parser: DNSCryptLogParser? = null
    private val modulesStatus = ModulesStatus.getInstance()

    fun <T : OnDNSCryptLogUpdatedListener> addListener(listener: T?) {
        listener?.let { listeners[it.javaClass] = WeakReference(it) }
    }

    fun <T : OnDNSCryptLogUpdatedListener> removeListener(listener: T?) {
        listener?.let { listeners.remove(it.javaClass) }

        if (listeners.isEmpty()) {
            resetParserState()
        }
    }

    fun hasAnyListener(): Boolean {
        return listeners.isNotEmpty()
    }

    fun parseDNSCryptLog() {
        try {
            parseLog()
        } catch (e: Exception) {
            loge("DNSCryptInteractor parseDNSCryptLog", e, true)
        }
    }

    fun resetParserState() {
        if (modulesStatus.dnsCryptState != ModuleState.RUNNING) {
            parser = null
        }
    }

    private fun parseLog() {
        if (listeners.isEmpty()) {
            return
        }

        resetParserState()

        parser = parser ?: DNSCryptLogParser(modulesLogRepository)

        val dnsCryptLogData = parser?.parseLog()

        listeners.forEach { listener ->
            if (listener.value.get()?.isActive() == true) {
                dnsCryptLogData?.let { listener.value.get()?.onDNSCryptLogUpdated(it) }
            } else {
                removeListener(listener.value.get())
            }
        }
    }
}
