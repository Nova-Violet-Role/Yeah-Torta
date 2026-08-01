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

package pillar.kuma_saimono.libumdnscrypt.vpn

import androidx.annotation.Keep
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.io.Serializable
import java.text.DateFormat
import java.util.Date
import java.util.Objects

@Keep
class ResourceRecord : Serializable {
    @JvmField
    var Time: Long = 0

    @JvmField
    var QName: String = ""

    @JvmField
    var AName: String = ""

    @JvmField
    var CName: String = ""

    @JvmField
    var HInfo: String = ""

    @JvmField
    var Resource: String = ""

    @JvmField
    var Rcode: Int = 0

    fun deepCopy(): ResourceRecord? {
        var deepClone: ResourceRecord? = null
        try {
            ByteArrayOutputStream().use { bos ->
                ObjectOutputStream(bos).use { out ->

                    out.writeObject(this)

                    ByteArrayInputStream(bos.toByteArray()).use { bis ->
                        ObjectInputStream(bis).use { inp ->

                            deepClone = inp.readObject() as ResourceRecord

                        }
                    }
                }
            }
        } catch (ignored: IOException) {
        } catch (ignored: ClassNotFoundException) {
        }

        return deepClone
    }

    private fun trimToNotASCIISymbols(line: String): String {
        val result = StringBuilder()
        for (ch in line.toCharArray()) {
            if (ch.code < 128) {
                result.append(ch)
            } else {
                break
            }
        }

        return result.toString()
    }

    private fun rCodeToString(Rcode: Int): String {
        return when (Rcode) {
            0 -> "DNS Query completed successfully"
            1 -> "DNS Query Format Error"
            2 -> "Server failed to complete the DNS request"
            3 -> "Domain name does not exist"
            4 -> "Function not implemented"
            5 -> "The server refused to answer for the query"
            6 -> "Name that should not exist, does exist"
            7 -> "RRset that should not exist, does exist"
            8 -> "Server not authoritative for the zone"
            9 -> "Name not in zone"
            else -> ""
        }
    }

    override fun toString(): String {
        var result = ""

        if (CName.isNotEmpty()) {
            result = formatter.format(Date(Time).time) +
                    " QName " + QName +
                    " AName " + AName +
                    " CName " + CName +
                    " HINFO " + trimToNotASCIISymbols(HInfo) +
                    " " + rCodeToString(Rcode)
        } else if (Resource.isNotEmpty()) {
            result = formatter.format(Date(Time).time) +
                    " QName " + QName +
                    " AName " + AName +
                    " Resource " + Resource +
                    " HINFO " + trimToNotASCIISymbols(HInfo) +
                    " " + rCodeToString(Rcode)
        } else if (HInfo.isNotEmpty()) {
            result = formatter.format(Date(Time).time) +
                    " QName " + QName +
                    " AName " + AName +
                    " HINFO " + trimToNotASCIISymbols(HInfo) +
                    " " + rCodeToString(Rcode)
        }

        return result
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val that = o as ResourceRecord
        return Time == that.Time &&
                Rcode == that.Rcode &&
                QName == that.QName &&
                AName == that.AName &&
                CName == that.CName &&
                HInfo == that.HInfo
    }

    override fun hashCode(): Int {
        return Objects.hash(Time, QName, AName, CName, HInfo, Rcode)
    }

    companion object {
        private const val serialVersionUID: Long = 1L

        private val formatter: DateFormat = DateFormat.getDateTimeInstance()
    }
}
