/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

/*
    This file is part of Yeah! Tortä. GPL-3.0-or-later. Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.AdbDiscovery.Endpoint

/**
 * Pins [AdbDiscovery]: the pairing/connect endpoint split (the confirmed P6 bug — pairing port fed to
 * connect) and the loopback/self-host security gate (plan §5.1 — reject a rogue-LAN fake endpoint).
 * Pure string logic — no Android NsdManager.
 */
class AdbDiscoveryTest {

    // ---- classify: pairing vs connect are DIFFERENT mDNS services on DIFFERENT ports ----

    @Test
    fun `classify recognizes the pairing service`() {
        assertEquals(Endpoint.PAIRING, AdbDiscovery.classify("_adb-tls-pairing._tcp"))
    }

    @Test
    fun `classify recognizes the connect service - the one P6 never discovered`() {
        assertEquals(Endpoint.CONNECT, AdbDiscovery.classify("_adb-tls-connect._tcp"))
    }

    @Test
    fun `classify tolerates trailing dots and the local suffix from different OEMs`() {
        assertEquals(Endpoint.PAIRING, AdbDiscovery.classify("_adb-tls-pairing._tcp."))
        assertEquals(Endpoint.CONNECT, AdbDiscovery.classify("_adb-tls-connect._tcp.local."))
    }

    @Test
    fun `classify is case-insensitive`() {
        assertEquals(Endpoint.PAIRING, AdbDiscovery.classify("_ADB-TLS-PAIRING._TCP"))
    }

    @Test
    fun `classify maps unknown, blank, and null service types to UNKNOWN`() {
        assertEquals(Endpoint.UNKNOWN, AdbDiscovery.classify("_http._tcp"))
        assertEquals(Endpoint.UNKNOWN, AdbDiscovery.classify(""))
        assertEquals(Endpoint.UNKNOWN, AdbDiscovery.classify(null))
    }

    // ---- isSelfHost: the security keystone — connect ONLY to this device ----

    @Test
    fun `isSelfHost accepts IPv4 loopback across the whole 127 block`() {
        assertTrue(AdbDiscovery.isSelfHost("127.0.0.1"))
        assertTrue(AdbDiscovery.isSelfHost("127.255.255.254"))
        assertTrue(AdbDiscovery.isSelfHost("127.7.7.8"))
    }

    @Test
    fun `isSelfHost accepts IPv6 loopback and its forms`() {
        assertTrue(AdbDiscovery.isSelfHost("::1"))
        assertTrue(AdbDiscovery.isSelfHost("0:0:0:0:0:0:0:1"))
        assertTrue(AdbDiscovery.isSelfHost("[::1]"))
        assertTrue(AdbDiscovery.isSelfHost("::ffff:127.0.0.1"))
    }

    @Test
    fun `isSelfHost accepts the localhost literal and strips an IPv6 zone id`() {
        assertTrue(AdbDiscovery.isSelfHost("localhost"))
        assertTrue(AdbDiscovery.isSelfHost("::1%wlan0"))
    }

    @Test
    fun `isSelfHost REJECTS LAN and public addresses - kills the rogue-LAN fake endpoint`() {
        assertFalse(AdbDiscovery.isSelfHost("192.168.1.50"))
        assertFalse(AdbDiscovery.isSelfHost("10.0.0.2"))
        assertFalse(AdbDiscovery.isSelfHost("8.8.8.8"))
        assertFalse(AdbDiscovery.isSelfHost("fe80::1234"))
        assertFalse(AdbDiscovery.isSelfHost("attacker.example.com"))
    }

    @Test
    fun `isSelfHost rejects garbage and a 128-dot-prefix near-miss`() {
        assertFalse(AdbDiscovery.isSelfHost(null))
        assertFalse(AdbDiscovery.isSelfHost(""))
        assertFalse(AdbDiscovery.isSelfHost("127.0.0"))        // too few octets
        assertFalse(AdbDiscovery.isSelfHost("127.0.0.1.5"))    // too many octets
        assertFalse(AdbDiscovery.isSelfHost("128.0.0.1"))      // adjacent block, NOT loopback
        assertFalse(AdbDiscovery.isSelfHost("1270.0.0.1"))     // octet out of range
        assertFalse(AdbDiscovery.isSelfHost("127.x.0.1"))      // non-numeric octet
    }

    // ---- Resolved.valid: endpoint + port range + self-host all together ----

    @Test
    fun `Resolved is valid only when endpoint known, port in range, and host is self`() {
        val good = AdbDiscovery.Resolved(Endpoint.CONNECT, "127.0.0.1", 37123)
        assertTrue(good.self)
        assertTrue(good.valid)
    }

    @Test
    fun `Resolved is INVALID for a non-self host even with a good endpoint and port`() {
        val rogue = AdbDiscovery.Resolved(Endpoint.PAIRING, "192.168.1.9", 5555)
        assertFalse(rogue.self)
        assertFalse(rogue.valid)
    }

    @Test
    fun `Resolved is invalid for an out-of-range port or unknown endpoint`() {
        assertFalse(AdbDiscovery.Resolved(Endpoint.CONNECT, "127.0.0.1", 0).valid)
        assertFalse(AdbDiscovery.Resolved(Endpoint.CONNECT, "127.0.0.1", 70000).valid)
        assertFalse(AdbDiscovery.Resolved(Endpoint.UNKNOWN, "127.0.0.1", 5555).valid)
    }
}
