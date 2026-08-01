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

sealed class ConnectionData(val time: Long) {
    override fun toString(): String {
        return "ConnectionData(time=$time)"
    }
}

class DnsRecord(
    time: Long,
    val qName: String,
    val aName: String,
    val cName: String,
    val hInfo: String,
    val rCode: Int,
    val ip: String
): ConnectionData(time) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DnsRecord

        if (qName != other.qName) return false
        if (aName != other.aName) return false
        if (cName != other.cName) return false
        if (hInfo != other.hInfo) return false
        if (rCode != other.rCode) return false
        if (ip != other.ip) return false

        return true
    }

    override fun hashCode(): Int {
        var result = qName.hashCode()
        result = 31 * result + aName.hashCode()
        result = 31 * result + cName.hashCode()
        result = 31 * result + hInfo.hashCode()
        result = 31 * result + rCode
        result = 31 * result + ip.hashCode()
        return result
    }

    override fun toString(): String {
        return "DnsRecord(time='$time', qName='$qName', aName='$aName', cName='$cName', hInfo='$hInfo', rCode=$rCode, ip='$ip')"
    }


}

class PacketRecord(
    time: Long,
    val uid: Int,
    val saddr: String,
    val daddr: String,
    val dport: Int,
    val protocol: Int = UNDEFINED,
    val allowed: Boolean
): ConnectionData(time) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PacketRecord

        if (uid != other.uid) return false
        if (saddr != other.saddr) return false
        if (daddr != other.daddr) return false
        if (protocol != other.protocol) return false
        return allowed == other.allowed
    }

    override fun hashCode(): Int {
        var result = uid
        result = 31 * result + saddr.hashCode()
        result = 31 * result + daddr.hashCode()
        result = 31 * result + protocol.hashCode()
        result = 31 * result + allowed.hashCode()
        return result
    }

    override fun toString(): String {
        return "PacketRecord(time='$time', uid=$uid, saddr='$saddr', daddr='$daddr, protocol='$protocol', allowed='$allowed')"
    }


}
