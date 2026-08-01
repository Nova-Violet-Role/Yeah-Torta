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

import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.LogDataModel
import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.AbstractLogParser
import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.ModulesLogRepository
import pillar.kuma_saimono.libumdnscrypt.utils.session.AppSessionStore
import pillar.kuma_saimono.libumdnscrypt.utils.session.SessionKeys.DNSCRYPT_SERVERS_PING
import java.util.regex.Pattern
import javax.inject.Inject

private const val COUNT_DOWN_TIMER = 5

private val patternDnsCryptServerPing = Pattern.compile("^\\[.+] +\\[NOTICE] +- +(\\d+)ms +(.+)$")

class DNSCryptLogParser(
    private val modulesLogRepository: ModulesLogRepository
) : AbstractLogParser() {

    @Inject
    lateinit var sessionStore: AppSessionStore

    private var startedSuccessfully = false
    private var startedWithError = false
    private var linesSaved = listOf<String>()
    private var errorCountDownCounter = COUNT_DOWN_TIMER
    private var lastPingBlockStartFound = false
    private var lastPingBlockEndFound = false

    init {
        App.instance.daggerComponent.inject(this)
    }

    override fun parseLog(): LogDataModel {
        val lines = modulesLogRepository.getDNSCryptLog()
        lastPingBlockStartFound = false
        lastPingBlockEndFound = false

        var linesChanged = false
        if (lines.size != linesSaved.size) {
            linesChanged = true
            linesSaved = ArrayList(lines)
            sessionStore.clearMap(DNSCRYPT_SERVERS_PING)
        }

        for (i in lines.size - 1 downTo 0) {
            val line = lines[i]

            if (!linesChanged && startedSuccessfully) {
                break
            }

            if (linesChanged) {
                parseServersPing(line)
            }

            if (!startedSuccessfully) {
                if (line.contains(" OK ") || line.contains("lowest initial latency")) {
                    startedSuccessfully = true
                    startedWithError = false
                    errorCountDownCounter = COUNT_DOWN_TIMER
                    break
                } else if (line.contains("Stopped.")) {
                    startedSuccessfully = false
                    startedWithError = false
                    break
                } else if (line.contains("connect: connection refused")
                    || (line.contains("ERROR") && !line.contains("Unable to resolve"))
                    || (line.contains("[CRITICAL]") && !line.contains("Certificate hash"))
                    || line.contains("[FATAL]")
                ) {
                    if (errorCountDownCounter <= 0) {
                        startedSuccessfully = false
                        startedWithError = true
                        errorCountDownCounter = COUNT_DOWN_TIMER
                    } else {
                        errorCountDownCounter--
                    }

                    break
                }
            }
        }

        return LogDataModel(
            startedSuccessfully,
            startedWithError,
            -1,
            formatLines(linesSaved),
            linesSaved.size
        )
    }

    private fun parseServersPing(line: String) {
        if (line.contains("Server with the lowest initial latency:")) {
            lastPingBlockEndFound = true
        } else if (line.endsWith("Sorted latencies:")) {
            lastPingBlockStartFound = true
        } else if (lastPingBlockEndFound && !lastPingBlockStartFound) {
            var server = ""
            var ping = -1
            val matcher = patternDnsCryptServerPing.matcher(line)
            if (matcher.find()) {
                ping = matcher.group(1)?.toInt() ?: -1
                server = matcher.group(2) ?: ""
            }

            if (server.isNotEmpty() && ping >= 0) {
                with(sessionStore) {
                    restoreMap<String, Int>(DNSCRYPT_SERVERS_PING)
                        .toMutableMap()
                        .also {
                            it.put(server, ping)
                            save(DNSCRYPT_SERVERS_PING, it)
                        }
                }
            }
        }
    }
}
