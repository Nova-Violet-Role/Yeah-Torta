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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.core

/**
 * Builds raw DNS A-queries with an explicit 16-bit query ID, for pipelined response matching.
 * Byte-for-byte port of the C# MonokumaTcpDnsEngine.BuildDnsQueryWithId. Pure, unit-testable.
 */
object DnsQueryBuilder {

    fun buildQuery(domain: String, queryId: Int): ByteArray {
        val header = byteArrayOf(
            (queryId shr 8).toByte(), (queryId and 0xFF).toByte(), // query ID
            0x01, 0x00,   // flags: RD = 1
            0x00, 0x01,   // QDCOUNT = 1
            0x00, 0x00,   // ANCOUNT
            0x00, 0x00,   // NSCOUNT
            0x00, 0x00    // ARCOUNT
        )
        val body = ArrayList<Byte>(domain.length + 8)
        for (label in domain.split('.')) {
            body.add(label.length.toByte())
            for (c in label) body.add(c.code.toByte()) // ASCII
        }
        body.add(0)                 // root label
        body.add(0x00); body.add(0x01) // QTYPE = A
        body.add(0x00); body.add(0x01) // QCLASS = IN
        return header + body.toByteArray()
    }
}
