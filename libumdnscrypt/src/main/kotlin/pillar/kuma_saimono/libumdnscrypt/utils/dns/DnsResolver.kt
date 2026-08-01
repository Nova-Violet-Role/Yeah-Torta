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

import android.text.TextUtils
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv4_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv6_REGEX
import java.io.IOException

abstract class DnsResolver(
    private val server: String?,
    private val recordType: Int,
    timeout: Int
) : Resolver {

    protected val timeout: Int = if (timeout > 0) timeout else Resolver.DNS_DEFAULT_TIMEOUT_SEC

    @Throws(IOException::class)
    override fun resolve(domain: Domain): Array<Record>? {
        val response = lookupHost(domain.domain) ?: throw IOException("response is null")

        val answers = response.getAnswerArray()
        if (answers == null || answers.isEmpty()) {
            return null
        }

        val records: MutableList<Record> = ArrayList()
        for (record in answers) {
            if (record.isA || record.isCname || record.isAAAA) {
                records.add(record)
            }
        }
        return records.toTypedArray()
    }

    @Throws(IOException::class)
    override fun reverseResolve(ip: String): Array<Record>? {

        if (!ip.matches(IPv4_REGEX.toRegex()) && !ip.matches(IPv6_REGEX.toRegex())) {
            throw IllegalArgumentException("IP wrong format $ip")
        }

        val ptrRequest = ipToPointerRequest(ip)

        val response = lookupHost(ptrRequest) ?: throw IOException("response is null")

        val answers = response.getAnswerArray()
        if (answers == null || answers.isEmpty()) {
            return null
        }

        val records: MutableList<Record> = ArrayList()
        for (record in answers) {
            if (record.isPointer) {
                records.add(record)
            }
        }

        return records.toTypedArray()
    }

    private fun ipToPointerRequest(ip: String): String {
        return if (isIPv6Address(ip)) {
            val ipDecompressed = decompressIPv6Address(ip)
            val list = ipDecompressed.replace(":", "").map { it.toString() }.reversed()
            TextUtils.join(".", list) + PTR_SUFFIX_IPV6
        } else {
            val list = ip.split(".").dropLastWhile { it.isEmpty() }.reversed()
            TextUtils.join(".", list) + PTR_SUFFIX_IPV4
        }
    }

    private fun isIPv6Address(ip: String): Boolean {
        return ip.contains(":")
    }

    private fun decompressIPv6Address(ip: String): String {

        var address = ip

        // Store the location where you need add zeroes that were removed during decompression
        val tempCompressLocation = address.indexOf("::")

        //if address was compressed and zeroes were removed, remove that marker i.e "::"
        if (tempCompressLocation != -1) {
            address = address.substring(0, tempCompressLocation) + ":" +
                    address.substring(tempCompressLocation + 2)
        }

        //extract rest of the components by splitting them using ":"
        val addressComponents = address.split(":").dropLastWhile { it.isEmpty() }.toTypedArray()

        for (i in addressComponents.indices) {
            val decompressedComponent = StringBuilder()
            for (j in 0 until (4 - addressComponents[i].length)) {
                //add a padding of the ignored zeroes during compression if required
                decompressedComponent.append("0")
            }
            decompressedComponent.append(addressComponents[i])

            //replace the compressed component with the uncompressed one
            addressComponents[i] = decompressedComponent.toString()
        }


        //Iterate over the uncompressed address components to add the ignored "0000" components depending on position of "::"
        val decompressedAddressComponents = ArrayList<String>()

        for (i in addressComponents.indices) {
            if (i == tempCompressLocation / 4) {
                for (j in 0 until (8 - addressComponents.size)) {
                    decompressedAddressComponents.add("0000")
                }
            }
            decompressedAddressComponents.add(addressComponents[i])

        }

        //iterate over the decompressed components to append and produce a full address
        val decompressedAddress = StringBuilder()
        for (decompressedAddressComponent in decompressedAddressComponents) {
            decompressedAddress.append(decompressedAddressComponent)
            decompressedAddress.append(":")
        }
        decompressedAddress.deleteCharAt(decompressedAddress.length - 1)
        return decompressedAddress.toString()
    }

    @Throws(IOException::class)
    private fun lookupHost(host: String): DnsResponse? {
        return request(host, recordType)
    }

    @Throws(IOException::class)
    private fun request(host: String?, recordType: Int): DnsResponse? {
        if (server == null) {
            throw IOException("server can not empty")
        }

        if (host == null || host.isEmpty()) {
            throw IOException("host can not empty")
        }

        return request(server, host, recordType)
    }

    @Throws(IOException::class)
    internal abstract fun request(server: String, host: String, recordType: Int): DnsResponse?

    companion object {
        private const val PTR_SUFFIX_IPV4 = ".in-addr.arpa"
        private const val PTR_SUFFIX_IPV6 = ".ip6.arpa"
    }
}
