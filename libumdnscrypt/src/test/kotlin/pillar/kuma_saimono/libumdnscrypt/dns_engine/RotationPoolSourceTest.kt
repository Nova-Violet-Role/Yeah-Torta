/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * D06/D30 — hermetic JVM assertions over [RotationPoolSource]'s PURE core (no android.util, no IO):
 * the signed-source `## name` + `sdns://` line scan, the byte-level DNS Stamp decode (props bits +
 * the LP(addr) `ip:port` pull the D30 warm-RTT ping dials), and the ONE shared require_* policy
 * read both the rotation pick and the MODE-2 derivation trust. These are the exact production
 * functions ([RotationManager.composeRotatedUpstreams] + `ResolverRuntime.deriveConfiguredUpstreams`
 * consume them) — never a copy.
 */
class RotationPoolSourceTest {

    // ---- the `## name` + `sdns://` scan ----

    @Test
    fun `scan pairs a name with its following stamp and keeps the first of several`() {
        val pairs = RotationPoolSource.scanNamedStamps(
            listOf(
                "# public-resolvers",
                "",
                "## quad9-dnscrypt-ip4-nofilter-pri",
                "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0Mw first-stamp-comment-tail",
                "sdns://SECOND-STAMP-SAME-ENTRY",
                "## adguard-dns",
                "some description line",
                "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQz",
            )
        )
        assertEquals(2, pairs.size)
        assertEquals("quad9-dnscrypt-ip4-nofilter-pri", pairs[0].first)
        // the trailing token after a space is cut; the FIRST stamp wins for a multi-stamp entry
        assertEquals("sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0Mw", pairs[0].second)
        assertEquals("adguard-dns", pairs[1].first)
    }

    @Test
    fun `scan skips a nameless stamp and a dirty token`() {
        val pairs = RotationPoolSource.scanNamedStamps(
            listOf(
                "sdns://ORPHAN-STAMP-NO-NAME",
                "## bad\"quote-name",
                "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0Mw",
                "## good-name",
                "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0Mw",
            )
        )
        assertEquals(listOf("good-name"), pairs.map { it.first })
    }

    // ---- the byte-level stamp decode (props bits + LP(addr)) ----

    /** Hand-build a DNSCrypt (0x01) stamp: proto | props u64 LE | LP(addr) | LP(pk) | LP(provider). */
    private fun dnscryptStamp(props: Long, addr: String): ByteArray {
        val addrBytes = addr.toByteArray(Charsets.UTF_8)
        val out = ArrayList<Byte>()
        out.add(0x01)
        for (i in 0 until 8) out.add(((props shr (8 * i)) and 0xFF).toByte())
        out.add(addrBytes.size.toByte())
        addrBytes.forEach { out.add(it) }
        // LP(pk) + LP(provider) — present in a real stamp; the decoder must not need them.
        out.add(1); out.add(0x2A)
        out.add(1); out.add('p'.code.toByte())
        return out.toByteArray()
    }

    @Test
    fun `decode reads the props bits the address and the dnscrypt proto`() {
        val sc = RotationPoolSource.decodeStampBytes(
            "quad9-dnscrypt", "sdns://x", dnscryptStamp(props = 0b011, addr = "9.9.9.9:8443")
        )
        checkNotNull(sc)
        assertTrue(sc.candidate.dnsCrypt)
        assertTrue(sc.candidate.dnssec)      // bit0
        assertTrue(sc.candidate.noLog)       // bit1
        assertFalse(sc.candidate.noFilter)   // bit2 clear
        assertEquals("quad9", sc.candidate.operatorFamily)
        assertEquals("9.9.9.9:8443", sc.address)
        assertEquals("sdns://x", sc.sdns)
    }

    @Test
    fun `decode defaults a portless address to 443 and handles ipv6 brackets`() {
        val v4 = RotationPoolSource.decodeStampBytes("a", "sdns://a", dnscryptStamp(0, "9.9.9.9"))
        assertEquals("9.9.9.9:443", checkNotNull(v4).address)
        val v6 = RotationPoolSource.decodeStampBytes("b", "sdns://b", dnscryptStamp(0, "[2620:fe::fe]"))
        assertEquals("[2620:fe::fe]:443", checkNotNull(v6).address)
        val v6Port = RotationPoolSource.decodeStampBytes("c", "sdns://c", dnscryptStamp(0, "[2620:fe::fe]:8443"))
        assertEquals("[2620:fe::fe]:8443", checkNotNull(v6Port).address)
    }

    @Test
    fun `decode marks a non-dnscrypt proto and never fabricates an address for it`() {
        val doh = RotationPoolSource.decodeStampBytes(
            "cloudflare-doh", "sdns://d", byteArrayOf(0x02, 0b101, 0, 0, 0, 0, 0, 0, 0)
        )
        checkNotNull(doh)
        assertFalse(doh.candidate.dnsCrypt) // requireDnsCrypt policy will drop it
        assertTrue(doh.candidate.dnssec)
        assertEquals("", doh.address)
    }

    @Test
    fun `decode is fail-safe on malformed input`() {
        assertNull(RotationPoolSource.decodeStampBytes("x", "sdns://x", byteArrayOf(0x01)))
        // LP(addr) length running past the buffer ⇒ no address, candidate still valid
        val truncated = byteArrayOf(0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x7F, 'a'.code.toByte())
        assertEquals("", checkNotNull(RotationPoolSource.decodeStampBytes("x", "sdns://x", truncated)).address)
        assertEquals("", RotationPoolSource.decodeDnscryptAddr(byteArrayOf(0x01, 0, 0, 0, 0, 0, 0, 0, 0)))
    }

    // ---- the address-FAMILY decode (the Kotlin port of torta_core::stamp_addr_family) ----

    @Test
    fun `familyOfAddr classifies v4 v6 bracketed hostname and empty`() {
        assertEquals(true to false, RotationPoolSource.familyOfAddr("9.9.9.9"))              // v4 literal
        assertEquals(true to false, RotationPoolSource.familyOfAddr("176.103.130.130:5443")) // v4 host:port
        assertEquals(false to true, RotationPoolSource.familyOfAddr("[2001:db8::1]:443"))    // bracketed v6
        assertEquals(false to true, RotationPoolSource.familyOfAddr("2606:4700:4700::1111")) // bare v6 (≥2 :)
        assertEquals(true to true, RotationPoolSource.familyOfAddr("dns.example.com"))       // hostname → Unknown
        assertEquals(true to true, RotationPoolSource.familyOfAddr("dns.example.com:443"))   // host:port → Unknown
        assertEquals(true to true, RotationPoolSource.familyOfAddr(""))                      // empty → Unknown
    }

    @Test
    fun `decode flags an ipv4 literal as ipv4-only family`() {
        val sc = checkNotNull(
            RotationPoolSource.decodeStampBytes("v4", "sdns://a", dnscryptStamp(0, "9.9.9.9:8443"))
        )
        assertTrue(sc.candidate.ipv4)
        assertFalse(sc.candidate.ipv6)
    }

    @Test
    fun `decode flags an ipv6 bracketed literal as ipv6-only family`() {
        val sc = checkNotNull(
            RotationPoolSource.decodeStampBytes("v6", "sdns://b", dnscryptStamp(0, "[2620:fe::fe]:443"))
        )
        assertFalse(sc.candidate.ipv4)
        assertTrue(sc.candidate.ipv6)
    }

    @Test
    fun `decode flags a hostname target as unknown family — never family-hidden (fail-open)`() {
        // An ODoH (0x05) target carries a hostname, not an IP literal ⇒ Unknown ⇒ (ipv4,ipv6)=(true,true),
        // so the family gate never hides it (only a BOTH-off toggle can) — the fail-open rule.
        val addr = "odoh.cloudflare-dns.com"
        val stamp = byteArrayOf(0x05, 0, 0, 0, 0, 0, 0, 0, 0) +
            byteArrayOf(addr.length.toByte()) + addr.toByteArray(Charsets.UTF_8)
        val sc = checkNotNull(RotationPoolSource.decodeStampBytes("odoh", "sdns://o", stamp))
        assertFalse(sc.candidate.dnsCrypt) // 0x05 ≠ 0x01
        assertTrue(sc.candidate.ipv4)
        assertTrue(sc.candidate.ipv6)
    }

    @Test
    fun `policyFromConfig carries the ipv4 ipv6 family gate, defaulting both open`() {
        val gated = RotationPoolSource.policyFromConfig(
            requireNolog = true, requireDnssec = false, requireNofilter = false,
            ipv4Servers = true, ipv6Servers = false,
        )
        assertTrue(gated.allowIpv4)
        assertFalse(gated.allowIpv6)
        // omitting the family args keeps BOTH allowed — backward-compatible with the legacy prefs path.
        val open = RotationPoolSource.policyFromConfig(false, false, false)
        assertTrue(open.allowIpv4)
        assertTrue(open.allowIpv6)
    }

    // ---- the ONE shared policy read ----

    @Test
    fun `policy mirrors the user require prefs and stays dnscrypt-only on the legacy path`() {
        val prefs = FakePrefs()
        val defaults = RotationPoolSource.policyFromPrefs(prefs)
        assertFalse(defaults.requireNoLog)
        assertFalse(defaults.requireDnssec)
        assertTrue(defaults.allowDnsCrypt)
        assertFalse(defaults.allowDoh)
        assertFalse(defaults.enforceDiversity)

        prefs.setBoolean(RotationPoolSource.REQUIRE_NOLOG_PREF, true)
        prefs.setBoolean(RotationPoolSource.REQUIRE_DNSSEC_PREF, true)
        val strict = RotationPoolSource.policyFromPrefs(prefs)
        assertTrue(strict.requireNoLog)
        assertTrue(strict.requireDnssec)
        assertTrue(strict.allowDnsCrypt)
        assertFalse(strict.allowDoh)
    }

    // ---- #22 s5A-ext: the PROTOCOL gate rides the typed-config server-type bits ----

    @Test
    fun `policyFromConfig maps the dnscrypt-doh server-type bits onto the protocol gate`() {
        val dohOnly = RotationPoolSource.policyFromConfig(
            requireNolog = false,
            requireDnssec = false,
            requireNofilter = false,
            dnscryptServers = false,
            dohServers = true,
        )
        assertFalse(dohOnly.allowDnsCrypt)
        assertTrue(dohOnly.allowDoh)

        // Legacy callers (no protocol args) keep the pre-s5A dnscrypt-only posture bit-exact.
        val legacy = RotationPoolSource.policyFromConfig(
            requireNolog = false,
            requireDnssec = false,
            requireNofilter = false,
        )
        assertTrue(legacy.allowDnsCrypt)
        assertFalse(legacy.allowDoh)

        // The ODoH-lane variant stays fail-open on protocol (was requireDnsCrypt=false).
        val odoh = RotationPoolSource.policyFromConfigOdoh(
            requireNolog = false,
            requireDnssec = false,
            requireNofilter = false,
        )
        assertTrue(odoh.allowDnsCrypt)
        assertTrue(odoh.allowDoh)
    }

    @Test
    fun `the shared policy plus filterTrusted drops what the user excluded`() {
        val prefs = FakePrefs()
        prefs.setBoolean(RotationPoolSource.REQUIRE_NOLOG_PREF, true)
        val policy = RotationPoolSource.policyFromPrefs(prefs)
        val logger = RotationPoolSource.decodeStampBytes("logger", "sdns://l", dnscryptStamp(0b001, "1.1.1.1"))
        val noLogger = RotationPoolSource.decodeStampBytes("private", "sdns://p", dnscryptStamp(0b011, "9.9.9.9"))
        val survivors = RotationSelector.filterTrusted(
            listOfNotNull(logger, noLogger).map { it.candidate }, policy
        )
        assertEquals(listOf("private"), survivors.map { it.id })
    }

    // ---- Fake (the RotationManagerGateTest pattern: only the touched surface is real). ----

    private class FakePrefs : SharedPreferences {
        private val booleans = HashMap<String, Boolean>()

        fun setBoolean(key: String, value: Boolean) { booleans[key] = value }

        override fun getBoolean(key: String?, defValue: Boolean): Boolean = booleans[key] ?: defValue

        override fun getAll(): MutableMap<String, *> = throw notImplemented()
        override fun getString(key: String?, defValue: String?): String? = throw notImplemented()
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
            throw notImplemented()
        override fun getInt(key: String?, defValue: Int): Int = throw notImplemented()
        override fun getLong(key: String?, defValue: Long): Long = throw notImplemented()
        override fun getFloat(key: String?, defValue: Float): Float = throw notImplemented()
        override fun contains(key: String?): Boolean = throw notImplemented()
        override fun edit(): SharedPreferences.Editor = throw notImplemented()
        override fun registerOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?
        ) = throw notImplemented()
        override fun unregisterOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?
        ) = throw notImplemented()

        private fun notImplemented() =
            UnsupportedOperationException("FakePrefs: only getBoolean is faked for the policy read")
    }
}
