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

package pillar.kuma_saimono.libumdnscrypt.utils.dns

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.IDN

internal class DnsRequest : DnsMessage {

    val recordType: Int
    private val host: String

    constructor(messageId: Short, recordType: Int, host: String) :
            this(messageId, 0, 1, recordType, host)

    constructor(messageId: Short, opCode: Int, rd: Int, recordType: Int, host: String) {
        this.messageId = messageId
        this.opCode = opCode
        this.rd = rd
        this.recordType = recordType
        this.host = host
    }

    @Throws(IOException::class)
    fun toDnsQuestionData(): ByteArray {
        if (host.isEmpty()) {
            throw IOException("host can not empty")
        }

        if (opCode != DnsMessage.OpCodeQuery && opCode != DnsMessage.OpCodeIQuery
            && opCode != DnsMessage.OpCodeStatus && opCode != DnsMessage.OpCodeUpdate
        ) {
            throw IOException("opCode is not valid")
        }

        if (rd != 0 && rd != 1) {
            throw IOException("rd is not valid")
        }

        if (recordType != Record.TYPE_A
            && recordType != Record.TYPE_AAAA
            && recordType != Record.TYPE_CNAME
            && recordType != Record.TYPE_PTR
            && recordType != Record.TYPE_TXT
        ) {
            throw IOException("recordType is not valid")
        }

        val baos = ByteArrayOutputStream(512)
        val dos = DataOutputStream(baos)
        // 16 bit id
        dos.writeShort(messageId.toInt())
        // |00|01|02|03|04|05|06|07|
        // |QR|  OPCODE   |AA|TC|RD|
        dos.writeByte((opCode shl 3) + rd)
        // |00|01|02|03|04|05|06|07|
        // |RA|r1|r2|r3| RCODE     |
        dos.writeByte(0x00)
        dos.writeByte(0x00)
        dos.writeByte(0x01) // QDCOUNT (number of entries in the question section)
        dos.writeByte(0x00)
        dos.writeByte(0x00) // ANCOUNT
        dos.writeByte(0x00)
        dos.writeByte(0x00) // NSCOUNT
        dos.writeByte(0x00)
        dos.writeByte(0x00) // ARCOUNT

        for (s in host.split("[.。．｡]".toRegex()).dropLastWhile { it.isEmpty() }) {
            if (s.length > 63) {
                throw IOException("host part is too long")
            }
            val buffer = IDN.toASCII(s).toByteArray()
            dos.write(buffer.size)
            dos.write(buffer, 0, buffer.size)
        }
        dos.writeByte(0x00) /* terminating zero */
        dos.writeByte(0x00)
        dos.writeByte(recordType)
        dos.writeByte(0x00)
        dos.writeByte(0x01) /* IN - "the Internet" */

        return baos.toByteArray()
    }
}
