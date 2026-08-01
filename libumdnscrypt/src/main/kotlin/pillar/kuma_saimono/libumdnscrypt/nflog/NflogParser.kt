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

import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionData
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionProtocol.UNDEFINED
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.DnsRecord
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.PacketRecord
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.net.IDN
import java.util.regex.Pattern
import javax.inject.Inject

class NflogParser @Inject constructor(
    private val nflogSessionsHolder: NflogSessionsHolder,
    pathVars: dagger.Lazy<PathVars>
) {

    private val packetPattern =
        Pattern.compile("PKT TIME:(\\d+?) UID:(-?\\d+?) ([^ ]+?) SIP:([^ ]*) SPT:(\\d+?) DIP:([^ ]*) DPT:(\\d+)")
    private val dnsPattern =
        Pattern.compile("DNS TIME:(\\d+?) QNAME:([^ ]*) ANAME:([^ ]*) CNAME:([^ ]*) HINFO:(.*?) RCODE:(\\d+?) IP:([^ ]*)")

    private val ownUid = pathVars.get().appUid

    fun parse(line: String): ConnectionData? =
        when {
            line.startsWith("PKT") -> parsePacket(line)
            line.startsWith("DNS") -> parseDNS(line)
            line.startsWith("ERR") -> parseError(line).let { null }
            else -> parseUnknown(line).let { null }
        }

    private fun parsePacket(line: String): PacketRecord? {
        val matcher = packetPattern.matcher(line)
        if (matcher.find()) {
            val time = (matcher.group(1) ?: "0").toLong()
                .takeIf { it > 0 } ?: System.currentTimeMillis()
            var uid = (matcher.group(2) ?: "-1").toLong()
            val protocol = matcher.group(3) ?: ""
            val saddr = matcher.group(4) ?: ""
            val sport = (matcher.group(5) ?: "0").toInt()
            val daddr = matcher.group(6) ?: ""
            val dport = (matcher.group(7) ?: "0").toInt()

            if (uid >= 0 && uid <= Int.MAX_VALUE) {
                nflogSessionsHolder.addSession(uid.toInt(), protocol, saddr, sport, daddr, dport)
            } else {
                uid = nflogSessionsHolder.getUid(protocol, saddr, sport, daddr, dport).toLong()
            }

            if (uid == ownUid.toLong() || uid > Int.MAX_VALUE) {
                return null
            }

            val protocolInt = when (protocol) {
                "TCP" -> 6
                "UDP" -> 17
                "ICMPv4" -> 1
                "ICMPv6" -> 58
                "IGMP" -> 2
                else -> UNDEFINED
            }

            return PacketRecord(
                time = time,
                uid = uid.toInt(),
                saddr = saddr,
                daddr = daddr,
                dport = if ((uid == -1L || uid == 0L || uid == 1020L || uid == 9999L) && sport < dport) sport else dport,
                protocol = protocolInt,
                allowed = true
            )
        } else {
            loge("NflogParser failed to parse line $line")
        }

        return null
    }

    private fun parseDNS(line: String): DnsRecord? {

        val matcher = dnsPattern.matcher(line)
        if (matcher.find()) {
            val time = (matcher.group(1) ?: "0").toLong()
                .takeIf { it > 0 } ?: System.currentTimeMillis()
            val qName = matcher.group(2)?.toUnicode()?.lowercase() ?: ""
            val aName = matcher.group(3)?.toUnicode()?.lowercase() ?: ""
            val cName = matcher.group(4)?.toUnicode()?.lowercase() ?: ""
            val hInfo = matcher.group(5) ?: ""
            val rCode = (matcher.group(6) ?: "0").toInt()
            val ip = matcher.group(7) ?: ""

            return DnsRecord(
                time = time,
                qName = qName,
                aName = aName,
                cName = cName,
                hInfo = hInfo,
                rCode = rCode,
                ip = ip
            )
        } else {
            loge("NflogParser failed to parse line $line")
        }

        return null
    }

    private fun parseError(line: String) {
        if (line.contains("unsupported yet")) {
            return
        }

        loge("NflogParser Nflog error. $line")
    }

    private fun parseUnknown(line: String) {
        loge("NflogParser unknown line $line")
    }

    private fun String.toUnicode(): String = IDN.toUnicode(this, IDN.ALLOW_UNASSIGNED)
}
