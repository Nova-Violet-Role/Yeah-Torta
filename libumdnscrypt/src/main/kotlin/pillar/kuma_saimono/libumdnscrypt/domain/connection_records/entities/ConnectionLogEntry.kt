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

package pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities

import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionProtocol.UNDEFINED

sealed class ConnectionLogEntry(
    var time: Long = 0,
    var blocked: Boolean = false
)

data class DnsLogEntry(
    val domainsChain: MutableList<String>,
    val ips: MutableSet<String>,
    var visible: Boolean = true,
    var blockedByIpv6: Boolean = false
): ConnectionLogEntry()

data class PacketLogEntry(
    val uid: Int,
    val saddr: String,
    val daddr: String,
    val dport: Int,
    val protocol: Int = UNDEFINED,
    var reverseDns: String? = null,
    var dnsLogEntry: DnsLogEntry? = null
): ConnectionLogEntry()
