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

package pillar.kuma_saimono.libumdnscrypt.utils.parsers

import android.util.Base64
import javax.inject.Inject

class DnsCryptSDNSParser @Inject constructor() {

    fun getRelayAddress(sdns: String): String {
        val bin = Base64.decode(stripScheme(sdns).toByteArray(), Base64.URL_SAFE)
        return when (val type = bin[0].toInt() and 0xFF) {
            ProtoType.RELAY_DNSCRYPT.magic -> handleDnsCryptRelay(bin)
            ProtoType.RELAY_ODOH.magic -> handleODoHRelay(bin)
            else -> throw IllegalArgumentException("SDNS type $type handling is not implemented")
        }
    }

    private fun handleDnsCryptRelay(bin: ByteArray): String {

        var address = ""

        if (bin.size < 9) {
            throw IllegalArgumentException("Stamp is too short")
        }

        var pos = 1
        val length = bin[pos].toInt() and 0xFF
        val binLen = bin.size

        if (1 + length > binLen - pos) {
            throw IllegalArgumentException("Invalid stamp")
        }

        pos++
        address = bin.copyOfRange(pos, pos + length).toString(Charsets.UTF_8)
        pos += length

        if (pos != binLen) {
            throw IllegalArgumentException("Invalid stamp (garbage after end)")
        }

        return getAddressWithPort(address)
    }

    private fun handleODoHRelay(bin: ByteArray): String {

        var address = ""

        if (bin.size < 13) {
            throw IllegalArgumentException("Stamp is too short")
        }

        var pos = 9
        val binLen = bin.size

        var length = bin[pos].toInt() and 0xFF
        if (1 + length >= binLen - pos) {
            throw IllegalArgumentException("Invalid sdns address")
        }
        pos++
        address = bin.copyOfRange(pos, pos + length).toString(Charsets.UTF_8)
        pos += length

        // Hashes
        while (true) {
            val vlen = bin[pos].toInt() and 0xFF
            length = vlen and vlen.inv().shr(7) //vlen & ~0x80
            if (1 + length >= binLen - pos) {
                throw IllegalArgumentException("Invalid sdns hash")
            }
            pos++
            pos += length
            if (vlen and 0x80 != 0x80) {
                break
            }
        }

        //Host name
        length = bin[pos].toInt() and 0xFF
        if (1 + length >= binLen - pos) {
            throw IllegalArgumentException("Invalid sdns host name")
        }
        pos++
        if (address.isEmpty()) {
            address = bin.copyOfRange(pos, pos + length).toString(Charsets.UTF_8)
        }
        pos += length

        //Path
        length = bin[pos].toInt() and 0xFF
        if (length >= binLen - pos) {
            throw IllegalArgumentException("Invalid sdns path")
        }
        pos++
        val path = bin.copyOfRange(pos, pos + length).toString(Charsets.UTF_8)
        pos += length

        if (pos != binLen) {
            throw IllegalArgumentException("Invalid sdns (garbage after end)")
        }

        if (address.isEmpty() && path.contains("/") && path.indexOf("/") > 0) {
            address = path.substring(0, path.indexOf("/"))
        }

        return getAddressWithPort(address)
    }

    private fun getAddressWithPort(address: String): String =
        if (address.isIPv6Address() && !address.matches(Regex(".+:\\d{1,5}$"))
            || address.isNotEmpty() && !address.contains(":")
        ) {
            "$address:443"
        } else {
            address
        }

    private fun String.isIPv6Address() = contains("[") && contains("]")

    companion object {

        /** The canonical DNS-stamp URI scheme. A stamp from `relays.md` always carries it. */
        private const val SCHEME = "sdns://"

        /**
         * THE BUG THIS EXISTS TO FIX — the `sdns://` prefix was being base64-DECODED as if it were
         * stamp payload (found checkpoint 99, MEASURED on the AVD):
         *
         * ```text
         * RelaysPingRepository getAddressFromSDNS java.lang.IllegalArgumentException
         *     SDNS type 177 handling is not implemented          x264
         * RelaysPingInteractor no address for dnscry.pt-anon-yerevan-ipv4
         * RotationPing filterRoutableRelays: 0/365 relays probed reachable -- FAIL-OPEN
         * ```
         *
         * 177 is not a mystery, it is arithmetic, and it is the proof of the diagnosis. Decoding the
         * literal characters `sdns` as URL-safe base64 gives `s`=44, `d`=29, `n`=39, `s`=44, and the
         * first output byte is the top 6 bits of `s` plus the top 2 of `d`:
         *
         *     44 = 101100, 29 = 011101  ->  10110001 = 0xB1 = 177
         *
         * So EVERY relay stamp decoded to the same bogus type, no relay ever yielded an address, and
         * not one socket was ever opened. `filterRoutableRelays` then FAILED OPEN by design (a dead
         * probe plane must never thin the anonymization layer), so DNS kept working and nothing ever
         * screamed. That is why this survived: the only visible symptom was a Beast with no RTT
         * samples and a congestion window that never left `cwnd=1/16`.
         *
         * Pure + Android-free so it is unit-testable on the JVM (`android.util.Base64` is not).
         * Case-insensitive and whitespace-tolerant; a stamp with no scheme is returned untouched, so
         * an already-stripped caller keeps working.
         */
        fun stripScheme(sdns: String): String {
            val s = sdns.trim()
            return if (s.length >= SCHEME.length && s.regionMatches(0, SCHEME, 0, SCHEME.length, true)) {
                s.substring(SCHEME.length)
            } else {
                s
            }
        }
    }

    enum class ProtoType(val magic: Int) {
        RELAY_DNSCRYPT(0x81),
        RELAY_ODOH(0x85)
    }
}
