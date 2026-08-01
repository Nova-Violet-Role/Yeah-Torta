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

object ConnectionProtocol {
    const val UNDEFINED = -1
    const val TCP = 6
    const val UDP = 17
    const val ICMPv4 = 1
    const val ICMPv6 = 58
    const val IP = 0
    const val IGMP = 2
    const val IPIP = 4
    const val EGP = 8
    const val PUP = 12
    const val IDP = 22
    const val DCCP = 33
    const val RSVP = 46
    const val GRE = 47
    const val IPv6inIPv4 = 41
    const val ESP = 50
    const val AH = 51
    const val BEETPH = 94
    const val PIM = 103
    const val COMP = 108
    const val SCTP = 132
    const val UDPLITE = 136
    const val RAW = 255
    const val MAX = 256

    fun toString(protocol: Int) =  when (protocol) {
        TCP -> "TCP"
        UDP -> "UDP"
        ICMPv4 -> "ICMPv4"
        ICMPv6 -> "ICMPv6"
        IP -> "IP"
        IGMP -> "IGMP"
        IPIP -> "IPIP"
        EGP -> "EGP"
        PUP -> "PUP"
        IDP -> "IDP"
        DCCP -> "DCCP"
        RSVP -> "RSVP"
        GRE -> "GRE"
        IPv6inIPv4 -> "IPv6-in-IPv4"
        ESP -> "ESP"
        AH -> "AH"
        BEETPH -> "BEETPH"
        PIM -> "PIM"
        COMP -> "COMP"
        SCTP -> "SCTP"
        UDPLITE -> "UDPLITE"
        RAW -> "RAW"
        MAX -> "MAX"
        else -> ""
    }
}
