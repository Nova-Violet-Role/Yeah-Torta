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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_servers

import android.util.Base64
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.nio.charset.StandardCharsets
import java.util.Objects

class DnsServerItem @Throws(IllegalArgumentException::class) constructor(
    private var name: String,
    private val description: String,
    private val sdns: String,
    features: DnsServerFeatures
) : Comparable<DnsServerItem> {

    private var checked = false
    private var dnssec = false
    private var nolog = false
    private var nofilter = false
    private var protoDoH = false
    private var protoODoH = false
    private var protoDNSCrypt = false
    private var ipv6 = false
    private var visibility = true
    private var ownServer = false
    private var address: String? = null
    private var ping = 0
    private val routes = ArrayList<String>()

    init {
        if (sdns.length < 15) {
            throw IllegalArgumentException("Wrong sever type " + name)
        }

        val bin = Base64.decode(sdns.toByteArray(), Base64.URL_SAFE)
        if (bin[0].toInt() == 0x01) {
            protoDNSCrypt = true
        } else if (bin[0].toInt() == 0x02) {
            protoDoH = true
        } else if (bin[0].toInt() == 0x05) {
            protoODoH = true
        } else {
            throw IllegalArgumentException("Wrong sever type " + name)
        }

        if ((bin[1].toInt() and 1) == 1) {
            this.dnssec = true
        }
        if (((bin[1].toInt() shr 1) and 1) == 1) {
            this.nolog = true
        }
        if (((bin[1].toInt() shr 2) and 1) == 1) {
            this.nofilter = true
        }

        calculateAddress(bin)

        if (name.contains("v6") || name.contains("ip6") || name.endsWith("6")) {
            ipv6 = true
        }

        if (features.requireDnssec)
            this.visibility = this.dnssec

        if (features.requireNofilter)
            this.visibility = this.visibility && this.nofilter

        if (features.requireNolog)
            this.visibility = this.visibility && this.nolog

        if (!features.useDnsServers)
            this.visibility = this.visibility && !this.protoDNSCrypt

        if (!features.useDohServers)
            this.visibility = this.visibility && !this.protoDoH

        if (!features.useOdohServers)
            this.visibility = this.visibility && !this.protoODoH

        if (!features.useIPv4Servers)
            this.visibility = this.visibility && ipv6

        if (!features.useIPv6Servers)
            this.visibility = this.visibility && !ipv6

        if (ownServer)
            this.visibility = true
    }

    private fun calculateAddress(bin: ByteArray) {
        try {
            val binLen = bin.size
            var pos = 9
            val addrLen = bin[pos].toInt() and 0xFF
            if (1 + addrLen >= bin.size - pos) {
                throw IllegalArgumentException("Invalid sdns address " + name)
            }
            pos++
            var addr = String(bin, pos, addrLen, StandardCharsets.UTF_8)
            pos += addrLen
            if (protoDoH && addr.isBlank()) {
                // Hashes
                while (true) {
                    val vlen = bin[pos].toInt() and 0xFF
                    val lengthHash = vlen and 0x80.inv()
                    if (1 + lengthHash >= binLen - pos) {
                        throw IllegalArgumentException("Invalid sdns hash " + name)
                    }
                    pos++
                    pos += lengthHash
                    if ((vlen and 0x80) != 0x80) {
                        break
                    }
                }

                // Host name
                var length = bin[pos].toInt() and 0xFF
                if (1 + length >= binLen - pos) {
                    throw IllegalArgumentException("Invalid sdns host name " + name)
                }
                pos++
                if (addr.isEmpty()) {
                    addr = String(bin, pos, length, StandardCharsets.UTF_8)
                }
                pos += length

                // Path
                length = bin[pos].toInt() and 0xFF
                if (length >= binLen - pos) {
                    throw IllegalArgumentException("Invalid sdns path " + name)
                }
                pos++
                val path = String(bin, pos, length, StandardCharsets.UTF_8)
                pos += length

                if (pos != binLen) {
                    throw Exception("Invalid sdns (garbage after end) " + name)
                }

                if (addr.isEmpty() && path.contains("/") && path.indexOf("/") > 0) {
                    addr = path.substring(0, path.indexOf("/"))
                }
            }

            if (addr.isNotEmpty() && (!addr.contains(":") || !addr.matches(".+:\\d{1,5}$".toRegex()))) {
                addr += ":443"
            }
            address = addr
        } catch (e: Exception) {
            loge("DnsServerItem calculateAddressAndHost " + name, e)
        }
    }

    fun isChecked(): Boolean {
        return checked
    }

    fun setChecked(checked: Boolean) {
        this.checked = checked
    }

    fun isDnssec(): Boolean {
        return dnssec
    }

    fun isNolog(): Boolean {
        return nolog
    }

    fun isNofilter(): Boolean {
        return nofilter
    }

    fun isProtoDoH(): Boolean {
        return protoDoH
    }

    fun isProtoODoH(): Boolean {
        return protoODoH
    }

    fun isProtoDNSCrypt(): Boolean {
        return protoDNSCrypt
    }

    fun isVisible(): Boolean {
        return visibility
    }

    fun getName(): String {
        return name
    }

    fun setName(name: String) {
        this.name = name
    }

    fun getDescription(): String {
        return description
    }

    fun setOwnServer(ownServer: Boolean) {
        this.ownServer = ownServer
    }

    fun getOwnServer(): Boolean {
        return ownServer
    }

    fun getSDNS(): String {
        return sdns
    }

    fun getRoutes(): ArrayList<String> {
        return routes
    }

    fun setRoutes(routes: List<String>) {
        this.routes.clear()
        this.routes.addAll(routes)
    }

    fun isIpv6(): Boolean {
        return ipv6
    }

    fun getAddress(): String? {
        return address
    }

    fun getPing(): Int {
        return ping
    }

    fun setPing(ping: Int) {
        this.ping = ping
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || javaClass != other.javaClass) return false
        val that = other as DnsServerItem
        return dnssec == that.dnssec &&
                nolog == that.nolog &&
                nofilter == that.nofilter &&
                protoDoH == that.protoDoH &&
                protoODoH == that.protoODoH &&
                protoDNSCrypt == that.protoDNSCrypt &&
                name == that.name &&
                description == that.description &&
                sdns == that.sdns
    }

    override fun hashCode(): Int {
        return Objects.hash(dnssec, nolog, nofilter, protoDoH, protoODoH, protoDNSCrypt, name, description, sdns)
    }

    override fun toString(): String {
        return "DNSServerItem{" +
                "checked=" + checked +
                ", dnssec=" + dnssec +
                ", nolog=" + nolog +
                ", nofilter=" + nofilter +
                ", protoDoH=" + protoDoH +
                ", protoODoH=" + protoODoH +
                ", protoDNSCrypt=" + protoDNSCrypt +
                ", visibility=" + visibility +
                ", name='" + name + '\'' +
                ", description='" + description + '\'' +
                ", addr='" + address + '\'' +
                ", ping='" + ping + '\'' +
                ", routes=" + routes +
                '}'
    }

    override fun compareTo(other: DnsServerItem): Int {
        return if (!this.checked && other.checked) {
            1
        } else if (this.checked && !other.checked) {
            -1
        } else {
            this.name.compareTo(other.name)
        }
    }
}
