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

import java.io.IOException
import java.net.IDN
import java.net.InetAddress
import java.util.Date
import java.util.Locale

internal class DnsResponse
@Throws(IOException::class)
constructor(
    private val server: String,
    private val source: Int,
    private val request: DnsRequest,
    private val recordData: ByteArray
) : DnsMessage() {

    init {
        if (recordData.isEmpty()) {
            throw IOException("response data is empty")
        }
    }

    private val timestamp: Long = Date().time / 1000

    private var aa = 0
    private var rCode = 0
    private var answerArray: List<Record>? = null
    private var authorityArray: List<Record>? = null
    private var additionalArray: List<Record>? = null

    init {
        parse()
    }

    @Throws(IOException::class)
    private fun parse() {
        if (recordData.size < 12) {
            throw IOException("response data too small")
        }

        // Header
        parseHeader()

        // Question
        var index = parseQuestion()

        // Answer
        val answer = RecordResource("answer", readRecordDataInt16(6).toInt(), index)
        parseResourceRecord(answer)
        answerArray = answer.records
        index += answer.length

        // Authority
        val authority = RecordResource("authority", readRecordDataInt16(8).toInt(), index)
        parseResourceRecord(authority)
        authorityArray = authority.records
        index += authority.length

        // Additional
        val additional = RecordResource("additional", readRecordDataInt16(10).toInt(), index)
        parseResourceRecord(additional)
        additionalArray = additional.records
    }

    @Throws(IOException::class)
    private fun parseHeader() {
        messageId = readRecordDataInt16(0)

        if (messageId != request.messageId) {
            throw IOException("question id error")
        }

        // |00|01|02|03|04|05|06|07|
        // |QR|  OPCODE   |AA|TC|RD|
        val field0 = readRecordDataInt8(2)
        val qr = readRecordDataInt8(2) and 0x80
        // Non-dns response data
        if (qr == 0) {
            throw IOException("not a response data")
        }

        opCode = (field0 shr 3) and 0x07
        aa = (field0 shr 2) and 0x01
        rd = field0 and 0x01

        // |00|01|02|03|04|05|06|07|
        // |RA|r1|r2|r3| RCODE     |
        val field1 = readRecordDataInt8(3)
        ra = (field1 shr 7) and 0x01
        rCode = field1 and 0x0F
    }

    @Throws(IOException::class)
    private fun parseQuestion(): Int {
        var index = 12
        var qdCount = readRecordDataInt16(4).toInt()
        while (qdCount > 0) {
            val recordName = getNameFrom(index) ?: throw IOException("read Question error")
            index += recordName.skipLength + 4
            qdCount--
        }
        return index
    }

    @Throws(IOException::class)
    private fun parseResourceRecord(resource: RecordResource) {
        var index = resource.from
        var count = resource.count

        while (count > 0) {
            val recordName = getNameFrom(index)
                ?: throw IOException("read " + resource.name + " error")

            index += recordName.skipLength

            val type = readRecordDataInt16(index).toInt()
            index += 2
            val clazz = readRecordDataInt16(index).toInt()
            index += 2
            val ttl = readRecordDataInt32(index)
            index += 4
            val rdLength = readRecordDataInt16(index).toInt()
            index += 2
            val value = readData(type, index, rdLength)

            if (clazz == 0x01 && (type == Record.TYPE_CNAME || type == request.recordType)) {
                val record = Record(value, type, ttl, timestamp, source, server)
                resource.addRecord(record)
            }

            index += rdLength
            count--
        }
        resource.length = index - resource.from
    }

    @Throws(IOException::class)
    private fun getNameFrom(from: Int): RecordName? {
        var partLength = 0
        var index = from
        val name = StringBuilder()
        val recordName = RecordName()

        var maxLoop = 128
        do {
            partLength = readRecordDataInt8(index)
            if ((partLength and 0xc0) == 0xc0) {
                // name pointer
                if (recordName.skipLength < 1) {
                    recordName.skipLength = index + 2 - from
                }
                index = ((partLength and 0x3f) shl 8) or readRecordDataInt8(index + 1)
                continue
            } else if ((partLength and 0xc0) > 0) {
                return null
            } else {
                index++
            }

            if (partLength > 0) {
                if (name.isNotEmpty()) {
                    name.append(".")
                }

                val nameData = recordData.copyOfRange(index, index + partLength)
                name.append(IDN.toUnicode(String(nameData)))
                index += partLength
            }
        } while (partLength > 0 && (--maxLoop) > 0)

        recordName.name = name.toString()
        if (recordName.skipLength < 1) {
            recordName.skipLength = index - from
        }
        return recordName
    }

    @Throws(IOException::class)
    private fun readData(recordType: Int, from: Int, length: Int): String? {
        var dataString: String? = null
        when (recordType) {
            Record.TYPE_A -> {
                if (length == 4) {
                    val builder = StringBuilder()
                    builder.append(readRecordDataInt8(from))
                    for (i in 1 until 4) {
                        builder.append(".")
                        builder.append(readRecordDataInt8(from + i))
                    }
                    dataString = builder.toString()
                }
            }

            Record.TYPE_AAAA -> {
                if (length == 16) {
                    val data = readRecordDataInet6Address(from)
                    return InetAddress.getByAddress(data).hostAddress
                }
            }

            Record.TYPE_CNAME, Record.TYPE_PTR -> {
                if (length > 1) {
                    val name = getNameFrom(from)
                    if (name != null) {
                        dataString = name.name
                    }
                }
            }

            Record.TYPE_TXT -> {
                if (length > 0 && (from + length) < recordData.size) {
                    val data = recordData.copyOfRange(from, from + length)
                    val dataValue = String(data)
                    dataString = IDN.toUnicode(dataValue)
                }
            }

            else -> {
            }
        }
        return dataString
    }

    @Throws(IOException::class)
    private fun readRecordDataInet6Address(from: Int): ByteArray {
        if (from >= recordData.size) {
            throw IOException("read response data out of range")
        }
        val data = ByteArray(16)
        System.arraycopy(recordData, from, data, 0, 16)
        return data
    }

    @Throws(IOException::class)
    private fun readRecordDataInt8(from: Int): Int {
        if (from >= recordData.size) {
            throw IOException("read response data out of range")
        }
        return recordData[from].toInt() and 0xFF
    }

    @Throws(IOException::class)
    private fun readRecordDataInt16(from: Int): Short {
        if ((from + 1) >= recordData.size) {
            throw IOException("read response data out of range")
        }
        val b0 = (recordData[from].toInt() and 0xFF) shl 8
        val b1 = recordData[from + 1].toInt() and 0xFF
        return (b0 + b1).toShort()
    }

    @Throws(IOException::class)
    private fun readRecordDataInt32(from: Int): Int {
        if ((from + 3) >= recordData.size) {
            throw IOException("read response data out of range")
        }
        val b0 = (recordData[from].toInt() and 0xFF) shl 24
        val b1 = (recordData[from + 1].toInt() and 0xFF) shl 16
        val b2 = (recordData[from + 2].toInt() and 0xFF) shl 8
        val b3 = recordData[from + 3].toInt() and 0xFF
        return b0 + b1 + b2 + b3
    }

    fun getAA(): Int = aa

    fun getRCode(): Int = rCode

    fun getAnswerArray(): List<Record>? = answerArray

    fun getAdditionalArray(): List<Record>? = additionalArray

    fun getAuthorityArray(): List<Record>? = authorityArray

    override fun toString(): String =
        String.format(
            Locale.getDefault(),
            "{messageId:%d, rd:%d, ra:%d, aa:%d, rCode:%d, server:%s, request:%s, answerArray:%s, authorityArray:%s, additionalArray:%s}",
            messageId, rd, ra, aa, rCode, server, request, answerArray, authorityArray, additionalArray
        )

    private class RecordResource(
        val name: String,
        val count: Int,
        val from: Int
    ) {
        var length: Int = 0
        val records: MutableList<Record> = ArrayList()

        fun addRecord(record: Record?) {
            if (record != null) {
                records.add(record)
            }
        }
    }

    private class RecordName {
        var skipLength: Int = 0
        var name: String? = null
    }
}
