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

import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData.Companion.SPECIAL_UID_KERNEL
import javax.inject.Inject

private const val SESSIONS_MAX_SIZE = 256

class NflogSessionsHolder @Inject constructor() {

    private val sessionToUids = HashMap<Session, Int>(SESSIONS_MAX_SIZE / 2)

    fun addSession(
        uid: Int,
        protocol: String,
        saddr: String,
        sport: Int,
        daddr: String,
        dport: Int
    ) {
        sessionToUids[Session(System.currentTimeMillis(), protocol, saddr, sport, daddr, dport)] =
            uid

        if (sessionToUids.size >= SESSIONS_MAX_SIZE) {
            clearOldSessions()
        }
    }

    fun getUid(
        protocol: String,
        saddr: String,
        sport: Int,
        daddr: String,
        dport: Int
    ): Int = sessionToUids[Session(0, protocol, saddr, sport, daddr, dport)] ?: SPECIAL_UID_KERNEL


    private fun clearOldSessions() {
        sessionToUids.keys.sortedBy { it.time }.forEachIndexed { index, session ->
            if (index < SESSIONS_MAX_SIZE / 3) {
                sessionToUids.remove(session)
            } else {
                return
            }
        }
    }

    private class Session(
        val time: Long,
        val protocol: String,
        val saddr: String,
        val sport: Int,
        val daddr: String,
        val dport: Int
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Session

            if (protocol != other.protocol) return false
            if (saddr != other.saddr) return false
            if (sport != other.sport) return false
            if (daddr != other.daddr) return false
            if (dport != other.dport) return false

            return true
        }

        override fun hashCode(): Int {
            var result = protocol.hashCode()
            result = 31 * result + saddr.hashCode()
            result = 31 * result + sport
            result = 31 * result + daddr.hashCode()
            result = 31 * result + dport
            return result
        }
    }
}
