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

import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.net.InetAddress
import java.net.UnknownHostException

object IPUtil {

    @JvmStatic
    @Throws(UnknownHostException::class)
    fun toCIDR(start: String, end: String): List<CIDR> {
        return toCIDR(InetAddress.getByName(start), InetAddress.getByName(end))
    }

    @JvmStatic
    fun toCIDR(start: InetAddress, end: InetAddress): List<CIDR> {
        val listResult = ArrayList<CIDR>()

        //logi("toCIDR(" + start.getHostAddress() + "," + end.getHostAddress() + ")");

        var from = inet2long(start)
        val to = inet2long(end)
        while (to >= from) {
            var prefix: Byte = 32
            while (prefix > 0) {
                val mask = prefix2mask(prefix - 1)
                if ((from and mask) != from)
                    break
                prefix--
            }

            val max = (32 - Math.floor(Math.log((to - from + 1).toDouble()) / Math.log(2.0))).toInt().toByte()
            if (prefix < max)
                prefix = max

            listResult.add(CIDR(long2inet(from), prefix.toInt()))

            from = (from + Math.pow(2.0, (32 - prefix).toDouble())).toLong()
        }

        return listResult
    }

    @JvmStatic
    fun minus1(addr: InetAddress?): InetAddress? {
        return long2inet(inet2long(addr) - 1)
    }

    @JvmStatic
    fun plus1(addr: InetAddress?): InetAddress? {
        return long2inet(inet2long(addr) + 1)
    }

    class CIDR : Comparable<CIDR> {
        @JvmField
        var address: InetAddress? = null

        @JvmField
        var prefix: Int = 0

        internal constructor(address: InetAddress?, prefix: Int) {
            this.address = address
            this.prefix = prefix
        }

        constructor(ip: String, prefix: Int) {
            try {
                this.address = InetAddress.getByName(ip)
                this.prefix = prefix
            } catch (ex: UnknownHostException) {
                loge("IPUtil CIDR", ex, true)
            }
        }

        fun getStart(): InetAddress? {
            return long2inet(inet2long(this.address) and prefix2mask(this.prefix))
        }

        fun getEnd(): InetAddress? {
            return long2inet((inet2long(this.address) and prefix2mask(this.prefix)) + (1L shl (32 - this.prefix)) - 1)
        }

        override fun toString(): String {
            return address!!.hostAddress + "/" + prefix + "=" + getStart()!!.hostAddress + "..." + getEnd()!!.hostAddress
        }

        override fun compareTo(other: CIDR): Int {
            val lcidr = inet2long(this.address)
            val lother = inet2long(other.address)
            return lcidr.compareTo(lother)
        }
    }
}

private fun prefix2mask(bits: Int): Long {
    return (0xFFFFFFFF00000000uL.toLong() shr bits) and 0xFFFFFFFFL
}

private fun inet2long(addr: InetAddress?): Long {
    var result: Long = 0
    if (addr != null)
        for (b in addr.address)
            result = (result shl 8) or (b.toLong() and 0xFF)
    return result
}

private fun long2inet(addr: Long): InetAddress? {
    var a = addr
    return try {
        val b = ByteArray(4)
        for (i in b.indices.reversed()) {
            b[i] = (a and 0xFF).toByte()
            a = a shr 8
        }
        InetAddress.getByAddress(b)
    } catch (ignore: UnknownHostException) {
        null
    }
}
