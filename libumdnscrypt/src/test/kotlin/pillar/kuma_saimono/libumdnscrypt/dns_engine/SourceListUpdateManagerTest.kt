/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import android.content.SharedPreferences
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import java.io.File
import java.nio.file.Files

/**
 * Task #19 — the SOURCE-LIST auto-update PRODUCER, pure-JVM guards over the parts that carry the security
 * and correctness weight: the governance default, the anti-rollback timestamp parse, the mirror table, and
 * the atomic write. No Android runtime, no network — the manager's load-bearing helpers were deliberately
 * extracted `Context`-free (the [CentauriArtifactManagerGovernanceTest] idiom), so these exercise the REAL
 * production code against a tiny in-memory [SharedPreferences] fake.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SourceListUpdateManagerTest {

    // ---- Governance default (the freshness posture) ----

    /**
     * A default (untouched) install DOES auto-update — fresh resolvers are the app's core purpose. Safe by
     * default now the slice-2 private-resolve fetch is in place: the sweep resolves each CDN host through
     * DNSCrypt and fails closed if the resolver is not serving (never a system-resolver leak).
     */
    @Test
    fun `default install auto-updates the source lists`() {
        assertTrue(
            "An untouched install auto-updates the source lists (DEFAULT ON)",
            SourceListUpdateManager.shouldAutoUpdate(FakePrefs())
        )
    }

    /** The explicit kill-switch OFF is the only thing that silences the channel. */
    @Test
    fun `kill-switch OFF disables auto-update`() {
        val prefs = FakePrefs().apply { setBoolean(TortaeKeys.SOURCE_LIST_AUTOUPDATE_ENABLED, false) }
        assertFalse(
            "With the kill-switch OFF, no auto-update sweep runs",
            SourceListUpdateManager.shouldAutoUpdate(prefs)
        )
    }

    // ---- Anti-rollback: the minisign trusted-comment timestamp parse ----

    /**
     * The REAL dnscrypt `.minisig` 4-line shape — line 3 carries `timestamp:<unix>\tfile:<name>`. The parse
     * must recover exactly the UNIX seconds (this is the value the rollback guard compares).
     */
    @Test
    fun `parseTrustedTimestamp reads the real minisign trusted comment`() {
        val minisig = buildString {
            appendLine("untrusted comment: signature from minisign secret key")
            appendLine("RUQf6LRCGA9i5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx==")
            appendLine("trusted comment: timestamp:1771747983\tfile:public-resolvers.md")
            appendLine("rqmfJElSM6xJhsIydgr1kfpsX9q6sl6iXJjMVdmEYhPxnf4B6Jh95H7uTIDpQ47CBLK4ivTOgboWLTANRIlbBg==")
        }
        assertEquals(1771747983L, SourceListUpdateManager.parseTrustedTimestamp(minisig))
    }

    /** A `.minisig` with no parseable timestamp yields null (the guard then simply skips the rollback check). */
    @Test
    fun `parseTrustedTimestamp returns null on a malformed comment`() {
        val junk = "untrusted comment: x\nSIGLINE\ntrusted comment: no timestamp here\nGLOBALSIG\n"
        assertNull(SourceListUpdateManager.parseTrustedTimestamp(junk))
    }

    // ---- The private-resolve DNS answer codec (slice-2 — resolve via DNSCrypt, never system DNS) ----

    /**
     * The A-record parse over a REAL wire-format response (`example.com` → 93.184.216.34), including a name
     * COMPRESSION POINTER in the answer RR (0xC0 0x0C → the question's qname) — the exact shape a live
     * resolver returns. This codec is what turns [TortaCore.resolve]'s bytes into the IP the fetch dials, so
     * a parse bug would silently break every private fetch.
     */
    @Test
    fun `parseDnsAddresses extracts the A record from a real response wire`() {
        val wire = byteArrayOf(
            // header: id=0x1234, flags=0x8180 (QR/RD/RA, RCODE=0), qd=1, an=1, ns=0, ar=0
            0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // question: "example.com" A IN
            0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
            0x00, 0x01, 0x00, 0x01,
            // answer: name=ptr->0x0C, TYPE=A, CLASS=IN, TTL=256, RDLENGTH=4, RDATA=93.184.216.34
            0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04,
            0x5D, 0xB8.toByte(), 0xD8.toByte(), 0x22,
        )
        val a = SourceListUpdateManager.parseDnsAddresses(wire, 1)
        assertEquals("one A record parsed", 1, a.size)
        assertEquals("93.184.216.34", a[0].hostAddress)
        // Asking for AAAA over an A-only response yields nothing (type-selective).
        assertTrue(SourceListUpdateManager.parseDnsAddresses(wire, 28).isEmpty())
    }

    /** A non-zero RCODE (here SERVFAIL=2) yields NO addresses — the fetch then fails closed. */
    @Test
    fun `parseDnsAddresses returns empty on a non-NOERROR rcode`() {
        val servfail = byteArrayOf(
            0x12, 0x34, 0x81.toByte(), 0x82.toByte(), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
            0x00, 0x01, 0x00, 0x01,
        )
        assertTrue(SourceListUpdateManager.parseDnsAddresses(servfail, 1).isEmpty())
    }

    // ---- The mirror table (ground-truthed from dnscrypt-proxy-master [sources]) ----

    /** All four lists, each with the canonical v3 primary + fallbacks, and `.minisig` sidecar URLs. */
    @Test
    fun `LISTS covers the four v3 lists with canonical mirrors`() {
        val names = SourceListUpdateManager.LISTS.map { it.fileName }
        assertEquals(
            listOf("public-resolvers.md", "relays.md", "odoh-servers.md", "odoh-relays.md"),
            names
        )
        val pub = SourceListUpdateManager.LISTS.first { it.fileName == "public-resolvers.md" }
        assertEquals(
            "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md",
            pub.mdUrls.first()
        )
        assertTrue("has a download.dnscrypt.info fallback",
            pub.mdUrls.any { it.startsWith("https://download.dnscrypt.info/resolvers-list/v3/") })
        // Every mirror's signature URL is its `.md` URL + `.minisig`.
        assertEquals(pub.mdUrls.map { it + ".minisig" }, pub.sigUrls)
    }

    // ---- Atomic write (no torn list ever reaches the rotation pool) ----

    @Test
    fun `atomicWrite writes bytes the target reads back identical`() {
        val dir = Files.createTempDirectory("sourcelist").toFile()
        try {
            val target = File(dir, "public-resolvers.md")
            val payload = "## public-resolvers\nsdns://AAA\n".toByteArray()
            assertTrue(SourceListUpdateManager.atomicWrite(target, payload))
            assertTrue(target.isFile)
            assertArrayEquals(payload, target.readBytes())
            // No staging temp left behind.
            assertFalse(File(dir, "public-resolvers.md.new").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `atomicWrite replaces an existing file`() {
        val dir = Files.createTempDirectory("sourcelist").toFile()
        try {
            val target = File(dir, "relays.md")
            target.writeBytes("OLD".toByteArray())
            val fresh = "NEW-AND-LONGER".toByteArray()
            assertTrue(SourceListUpdateManager.atomicWrite(target, fresh))
            assertArrayEquals(fresh, target.readBytes())
        } finally {
            dir.deleteRecursively()
        }
    }

    // ---- Minimal in-memory SharedPreferences (only the surface the gate touches) ----

    private class FakePrefs : SharedPreferences {
        private val bools = HashMap<String, Boolean>()
        fun setBoolean(key: String, value: Boolean) {
            bools[key] = value
        }

        override fun getBoolean(key: String?, defValue: Boolean): Boolean =
            bools[key] ?: defValue

        override fun contains(key: String?): Boolean = bools.containsKey(key)
        override fun getAll(): MutableMap<String, *> = bools.toMutableMap()
        override fun getString(key: String?, defValue: String?): String? = defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
        override fun getInt(key: String?, defValue: Int): Int = defValue
        override fun getLong(key: String?, defValue: Long): Long = defValue
        override fun getFloat(key: String?, defValue: Float): Float = defValue
        override fun edit(): SharedPreferences.Editor = throw UnsupportedOperationException()
        override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }
}
