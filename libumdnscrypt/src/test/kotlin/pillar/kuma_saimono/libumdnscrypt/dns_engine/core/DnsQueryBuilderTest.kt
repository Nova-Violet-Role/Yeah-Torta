/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

/*
    This file is part of Yeah! Tortä. GPL-3.0-or-later. Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.core

import org.junit.Assert.assertEquals
import org.junit.Test

class DnsQueryBuilderTest {

    @Test
    fun `builds a well-formed A query with the given id`() {
        val q = DnsQueryBuilder.buildQuery("a.bc", 0x1234)
        // header
        assertEquals(0x12.toByte(), q[0]); assertEquals(0x34.toByte(), q[1]) // id
        assertEquals(0x01.toByte(), q[2]); assertEquals(0x00.toByte(), q[3]) // flags RD=1
        assertEquals(0x00.toByte(), q[4]); assertEquals(0x01.toByte(), q[5]) // QDCOUNT=1
        // question: 1 'a' 2 'b' 'c' 0  QTYPE=A QCLASS=IN
        assertEquals(1.toByte(), q[12]); assertEquals('a'.code.toByte(), q[13])
        assertEquals(2.toByte(), q[14]); assertEquals('b'.code.toByte(), q[15]); assertEquals('c'.code.toByte(), q[16])
        assertEquals(0.toByte(), q[17]) // root
        assertEquals(0x00.toByte(), q[18]); assertEquals(0x01.toByte(), q[19]) // QTYPE A
        assertEquals(0x00.toByte(), q[20]); assertEquals(0x01.toByte(), q[21]) // QCLASS IN
        assertEquals(22, q.size)
    }

    @Test
    fun `id high and low bytes are split correctly`() {
        val q = DnsQueryBuilder.buildQuery("x", 0xABCD)
        assertEquals(0xAB.toByte(), q[0])
        assertEquals(0xCD.toByte(), q[1])
    }
}
