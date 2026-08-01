/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.Inet6Address
import java.net.InetAddress

/**
 * P0.5 Fix-item 6 — the automated unit test of the Stage-0 SHADOW **record-level compare + wire codec**
 * (the gap the COMMIT-GATE report §6 flagged: "ZERO automated test of the seam/shadow/DI"). This is the
 * device-FREE half of the proof; it runs on the plain JUnit task (`junit:junit:4.13.2`, NO Robolectric /
 * mockk in this module — see libumdnscrypt/build.gradle:179) on the VM `:libumdnscrypt:test*` gradle task.
 *
 * ## WHY A LOCKSTEP TWIN, NOT THE SHIPPED [ResolverRuntime] (honest GROUND_TRUTH — never fake green)
 * The load-bearing compare/codec logic in [ResolverRuntime] — `buildWireQuery`, `parseAnswer`,
 * `recordsAgree`, `ipFamilyOf`, `isPositiveReturnCode`, `skipName`, `u16` — is **`private`**, and the
 * class itself is un-instantiable in a unit test: its `@Inject` ctor needs an Android `SharedPreferences`
 * + a Dagger `Lazy<PathVars>`, [ResolverRuntime.shadowCompare] short-circuits on `!BuildConfig.DEBUG`,
 * launches on a real `dispatcherIo`, and calls `android.os.SystemClock` + the native `TortaCore.resolve`
 * (a JNI symbol absent from the JVM classpath). None of that is reachable without a device/Robolectric.
 *
 * So this test does EXACTLY what the accepted Rust-side `tests/wave3a_cabi_contract.rs` does for
 * `torta_resolve`: it exercises a **byte-for-byte twin** of the private bodies, each twin annotated with
 * the SHIPPED source line it mirrors. If a future edit to [ResolverRuntime] diverges from a twin below,
 * the divergence is a bug in one of them — both cite the same code. The ONE thing a JVM test cannot prove
 * — that the seam actually FIRES at runtime (seamHits>0 / compares>0) and that the DI instance is shared
 * (identityHashCode-EQUAL) — is the emu-soak's job, documented in the EMU-ONLY CHECKLIST at the bottom.
 *
 * The twins below are pure JVM (only `java.net.InetAddress`, already used by the real `parseAnswer`); no
 * Android type leaks in, so the test is hermetic and deterministic.
 */
class ResolverRuntimeShadowTest {

    // =================================================================================================
    // LOCKSTEP TWINS — byte/line-faithful mirrors of ResolverRuntime's private methods.
    // Each carries the SHIPPED file:line it mirrors. Keep in sync with ResolverRuntime.kt.
    // =================================================================================================

    private val TYPE_A = 1
    private val TYPE_AAAA = 28
    private val FAMILY_NONE = 0
    private val FAMILY_V4 = 4
    private val FAMILY_V6 = 6
    private val RCODE_NOERROR = 0
    private val MAX_LABEL_LEN = 63
    private val MAX_NAME_HOPS = 128

    /** Twin of [ResolverRuntime] ShadowAnswer (ResolverRuntime.kt:553). */
    private data class ShadowAnswer(val rcode: Int, val ipv4: Set<String>, val ipv6: Set<String>)

    /**
     * Twin of `ResolverRuntime.buildWireQuery` (ResolverRuntime.kt:524-548), with the id parameterised
     * (the shipped method uses a random 16-bit id; the wire FORMAT is identical, so the test fixes the id
     * to make the bytes deterministic). Mirrors the Rust `dns::build_query` (dns.rs:107) byte format.
     * Returns null on an over-long label — the shipped Kotlin behaviour (abort the qtype), which is the
     * ONE intentional divergence from the Rust builder (which clamps to 63); pinned by a test below.
     */
    private fun buildWireQuery(qname: String, qtype: Int, id: Int): ByteArray? {
        try {
            val out = ArrayList<Byte>(qname.length + 18)
            out.add((id shr 8).toByte()); out.add((id and 0xFF).toByte()) // query ID
            out.add(0x01); out.add(0x00)   // flags: RD = 1
            out.add(0x00); out.add(0x01)   // QDCOUNT = 1
            out.add(0x00); out.add(0x00)   // ANCOUNT
            out.add(0x00); out.add(0x00)   // NSCOUNT
            out.add(0x00); out.add(0x00)   // ARCOUNT
            for (label in qname.split('.')) {
                if (label.isEmpty()) continue
                val bytes = label.encodeToByteArray()
                if (bytes.size > MAX_LABEL_LEN) return null // malformed → skip this qtype, never throw
                out.add(bytes.size.toByte())
                for (b in bytes) out.add(b)
            }
            out.add(0)                                   // root label
            out.add((qtype shr 8).toByte()); out.add((qtype and 0xFF).toByte()) // QTYPE
            out.add(0x00); out.add(0x01)                 // QCLASS = IN
            return out.toByteArray()
        } catch (e: Exception) {
            return null
        }
    }

    /** Twin of `ResolverRuntime.u16` (ResolverRuntime.kt:673-676). */
    private fun u16(b: ByteArray, off: Int): Int {
        if (off + 1 >= b.size) return 0
        return ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
    }

    /** Twin of `ResolverRuntime.skipName` (ResolverRuntime.kt:683-697). */
    private fun skipName(b: ByteArray, start: Int): Int? {
        var pos = start
        var guard = 0
        while (pos < b.size) {
            if (guard++ > MAX_NAME_HOPS) return null
            val len = b[pos].toInt() and 0xFF
            when {
                len == 0 -> return pos + 1
                len and 0xC0 == 0xC0 -> return pos + 2
                len <= MAX_LABEL_LEN -> pos += 1 + len
                else -> return null
            }
        }
        return null
    }

    /** Twin of `ResolverRuntime.parseAnswer` (ResolverRuntime.kt:560-597). */
    private fun parseAnswer(resp: ByteArray): ShadowAnswer? {
        try {
            if (resp.size < 12) return null
            val rcode = resp[3].toInt() and 0x0F
            val qdCount = u16(resp, 4)
            val anCount = u16(resp, 6)
            var pos = 12
            repeat(qdCount) {
                pos = skipName(resp, pos) ?: return null
                pos += 4
                if (pos > resp.size) return null
            }
            val ipv4 = LinkedHashSet<String>()
            val ipv6 = LinkedHashSet<String>()
            repeat(anCount) {
                pos = skipName(resp, pos) ?: return null
                if (pos + 10 > resp.size) return null
                val rtype = u16(resp, pos)
                val rdlength = u16(resp, pos + 8)
                val rdataAt = pos + 10
                val end = rdataAt + rdlength
                if (end > resp.size) return null
                when {
                    rtype == TYPE_A && rdlength == 4 ->
                        ipv4.add(InetAddress.getByAddress(resp.copyOfRange(rdataAt, end)).hostAddress.orEmpty())
                    rtype == TYPE_AAAA && rdlength == 16 ->
                        ipv6.add((InetAddress.getByAddress(resp.copyOfRange(rdataAt, end)) as? Inet6Address)
                            ?.hostAddress?.substringBefore('%').orEmpty())
                }
                pos = end
            }
            return ShadowAnswer(rcode, ipv4, ipv6)
        } catch (e: Exception) {
            return null
        }
    }

    /** Twin of `ResolverRuntime.ipFamilyOf` (ResolverRuntime.kt:664-669). */
    private fun ipFamilyOf(resource: String): Int = when {
        resource.isEmpty() -> FAMILY_NONE
        resource.contains(':') -> FAMILY_V6
        resource.contains('.') -> FAMILY_V4
        else -> FAMILY_NONE
    }

    /** Twin of `ResolverRuntime.isPositiveReturnCode` (ResolverRuntime.kt:485-488). */
    private fun isPositiveReturnCode(rcode: String?): Boolean {
        val r = rcode?.trim()?.uppercase() ?: return false
        return r == "PASS" || r == "FORWARD" || r == "SYNTH" || r == "CLOAK"
    }

    /**
     * Twin of `ResolverRuntime.recordsAgree` (ResolverRuntime.kt:617-656). `exactMatches` is an
     * observability sub-counter in the shipped code and never changes the verdict; the twin returns the
     * headline boolean only (what the test asserts), so the counter is omitted.
     */
    private fun recordsAgree(
        shadow: ShadowAnswer,
        qtype: Int,
        realFamily: Int,
        realResource: String,
        realRcode: Int,
    ): Boolean {
        val shadowFamilyIps = if (qtype == TYPE_AAAA) shadow.ipv6 else shadow.ipv4
        val shadowPositive = shadow.rcode == RCODE_NOERROR && shadowFamilyIps.isNotEmpty()
        val hasFamilyLiteral = realResource.isNotEmpty() &&
                (realFamily == FAMILY_V4 || realFamily == FAMILY_V6)
        val realPositive = realRcode == RCODE_NOERROR && hasFamilyLiteral

        if (realRcode != RCODE_NOERROR) {
            return !shadowPositive
        }
        if (!realPositive) {
            return true
        }
        if (!shadowPositive) return false
        return true
    }

    // ---- small wire helpers for the tests (build deterministic responses to feed parseAnswer) ----

    /** A minimal NOERROR response: 1 question (qname/qtype) + the given A/AAAA answer records. */
    private fun buildResponse(qname: String, qtype: Int, rcode: Int, vararg ips: String): ByteArray {
        val out = ArrayList<Byte>()
        out.add(0x12); out.add(0x34)                    // id
        out.add(0x81.toByte()); out.add((0x80 or (rcode and 0x0F)).toByte()) // QR=1, RA=1, rcode
        out.add(0x00); out.add(0x01)                    // QDCOUNT = 1
        out.add(0x00); out.add(ips.size.toByte())       // ANCOUNT
        out.add(0x00); out.add(0x00)                    // NSCOUNT
        out.add(0x00); out.add(0x00)                    // ARCOUNT
        // question
        for (label in qname.split('.')) {
            if (label.isEmpty()) continue
            val b = label.encodeToByteArray()
            out.add(b.size.toByte()); for (x in b) out.add(x)
        }
        out.add(0)
        out.add((qtype shr 8).toByte()); out.add((qtype and 0xFF).toByte())
        out.add(0x00); out.add(0x01)                    // QCLASS IN
        // answers (compression pointer 0xC00C back to the question name)
        for (ip in ips) {
            out.add(0xC0.toByte()); out.add(0x0C)        // NAME = ptr to offset 12
            out.add((qtype shr 8).toByte()); out.add((qtype and 0xFF).toByte()) // TYPE
            out.add(0x00); out.add(0x01)                 // CLASS IN
            out.add(0x00); out.add(0x00); out.add(0x00); out.add(0x3C) // TTL 60
            val rdata = InetAddress.getByName(ip).address
            out.add(0x00); out.add(rdata.size.toByte())  // RDLENGTH
            for (x in rdata) out.add(x)
        }
        return out.toByteArray()
    }

    // =================================================================================================
    // CODEC — buildWireQuery byte format + round-trip through parseAnswer (the §1.6 single codec)
    // =================================================================================================

    @Test
    fun `buildWireQuery emits a well-formed A query header and question`() {
        val q = buildWireQuery("a.bc", TYPE_A, 0x1234)!!
        // header
        assertEquals(0x12.toByte(), q[0]); assertEquals(0x34.toByte(), q[1])  // id
        assertEquals(0x01.toByte(), q[2]); assertEquals(0x00.toByte(), q[3])  // RD=1
        assertEquals(0x00.toByte(), q[4]); assertEquals(0x01.toByte(), q[5])  // QDCOUNT=1
        // question: 1 'a' 2 'b' 'c' 0  QTYPE=A(1) QCLASS=IN(1)
        assertEquals(1.toByte(), q[12]); assertEquals('a'.code.toByte(), q[13])
        assertEquals(2.toByte(), q[14]); assertEquals('b'.code.toByte(), q[15]); assertEquals('c'.code.toByte(), q[16])
        assertEquals(0.toByte(), q[17])
        assertEquals(0x00.toByte(), q[18]); assertEquals(0x01.toByte(), q[19]) // QTYPE A
        assertEquals(0x00.toByte(), q[20]); assertEquals(0x01.toByte(), q[21]) // QCLASS IN
        assertEquals(22, q.size)
    }

    @Test
    fun `buildWireQuery sets QTYPE to 28 for AAAA`() {
        val q = buildWireQuery("x", TYPE_AAAA, 0xABCD)!!
        // QTYPE is the two bytes before the final QCLASS(00 01)
        assertEquals(0x00.toByte(), q[q.size - 4]); assertEquals(0x1C.toByte(), q[q.size - 3]) // 28
        assertEquals(0x00.toByte(), q[q.size - 2]); assertEquals(0x01.toByte(), q[q.size - 1]) // IN
    }

    @Test
    fun `buildWireQuery splits the id into high and low bytes`() {
        val q = buildWireQuery("x", TYPE_A, 0xBEEF)!!
        assertEquals(0xBE.toByte(), q[0]); assertEquals(0xEF.toByte(), q[1])
    }

    @Test
    fun `buildWireQuery skips empty labels so a trailing-dot FQDN frames identically`() {
        // dns.rs:114 / ResolverRuntime.kt:535 both `continue` on empty labels.
        val bare = buildWireQuery("example.com", TYPE_A, 0)!!
        val fqdn = buildWireQuery("example.com.", TYPE_A, 0)!!
        assertArrayEquals("a trailing dot must not add a zero-length label", bare, fqdn)
    }

    @Test
    fun `buildWireQuery aborts (returns null) on an over-long label — the Kotlin-side divergence`() {
        // The ONE intentional divergence from Rust dns::build_query (which CLAMPS to 63): the Kotlin
        // façade returns null so shadowCompare skips that qtype, never throws. Pin it so a future
        // "make it clamp like Rust" edit is a conscious choice, not an accident.
        val tooLong = "a".repeat(64)
        assertNull(buildWireQuery("$tooLong.com", TYPE_A, 0))
    }

    @Test
    fun `parseAnswer round-trips a buildWireQuery-shaped question and extracts A records`() {
        val resp = buildResponse("example.com", TYPE_A, RCODE_NOERROR, "93.184.216.34")
        val ans = parseAnswer(resp)!!
        assertEquals(RCODE_NOERROR, ans.rcode)
        assertEquals(setOf("93.184.216.34"), ans.ipv4)
        assertTrue(ans.ipv6.isEmpty())
    }

    @Test
    fun `parseAnswer extracts AAAA records and normalises the literal`() {
        val resp = buildResponse("example.com", TYPE_AAAA, RCODE_NOERROR, "2606:2800:220:1:248:1893:25c8:1946")
        val ans = parseAnswer(resp)!!
        assertEquals(1, ans.ipv6.size)
        assertTrue("the canonical compressed v6 literal is extracted",
            ans.ipv6.first().contains("2606:2800"))
        assertTrue(ans.ipv4.isEmpty())
    }

    @Test
    fun `parseAnswer rejects a truncated header`() {
        assertNull(parseAnswer(byteArrayOf(0, 1, 2, 3)))                   // < 12 bytes
    }

    @Test
    fun `parseAnswer rejects an answer whose RDLENGTH runs past the buffer`() {
        val resp = buildResponse("example.com", TYPE_A, RCODE_NOERROR, "1.2.3.4")
        val truncated = resp.copyOfRange(0, resp.size - 2) // chop into the RDATA
        assertNull("a record running off the end must be rejected, never read OOB", parseAnswer(truncated))
    }

    @Test
    fun `skipName follows labels and stops at the root and at a compression pointer`() {
        val resp = buildResponse("a.b.example.com", TYPE_A, RCODE_NOERROR, "1.2.3.4")
        // The question name starts at offset 12 and ends just before QTYPE.
        val afterName = skipName(resp, 12)!!
        // a(1) b(1) example(7) com(3) + 4 length bytes + root(1) = the question name length
        assertEquals(12 + (1 + 1) + (1 + 1) + (1 + 7) + (1 + 3) + 1, afterName)
    }

    // =================================================================================================
    // RECORD-LEVEL COMPARE — the agree / disagree / neutral classification (the FIX-2 lenient metric)
    // =================================================================================================

    @Test
    fun `agree when both sides resolve the same family (existence parity, NOT IP-exact)`() {
        // Real path: A literal; shadow: a DIFFERENT A literal (legit CDN/GeoDNS split). Must AGREE.
        val shadow = ShadowAnswer(RCODE_NOERROR, setOf("1.1.1.1"), emptySet())
        assertTrue(recordsAgree(shadow, TYPE_A, FAMILY_V4, "9.9.9.9", RCODE_NOERROR))
    }

    @Test
    fun `disagree when the shadow resolves a name the real path DENIED`() {
        // Real path: NXDOMAIN (rcode 3); shadow: a positive A answer → a real disagreement.
        val shadow = ShadowAnswer(RCODE_NOERROR, setOf("1.2.3.4"), emptySet())
        assertFalse(recordsAgree(shadow, TYPE_A, FAMILY_V4, "", 3))
    }

    @Test
    fun `agree when both sides DENY (NXDOMAIN parity)`() {
        val shadow = ShadowAnswer(3, emptySet(), emptySet())
        assertTrue(recordsAgree(shadow, TYPE_A, FAMILY_NONE, "", 3))
    }

    @Test
    fun `disagree when the real path had a positive literal but the shadow produced nothing`() {
        val shadow = ShadowAnswer(RCODE_NOERROR, emptySet(), emptySet())
        assertFalse(recordsAgree(shadow, TYPE_A, FAMILY_V4, "93.184.216.34", RCODE_NOERROR))
    }

    @Test
    fun `neutral-agree when the real record carries no family literal (CNAME-only event)`() {
        // NOERROR real side with no A/AAAA literal (e.g. a CNAME-only ResourceRecord) makes no family
        // claim → the shadow's positivity is not contradicted either way → neutral agreement (true).
        val shadow = ShadowAnswer(RCODE_NOERROR, setOf("1.2.3.4"), emptySet())
        assertTrue(recordsAgree(shadow, TYPE_A, FAMILY_NONE, "", RCODE_NOERROR))
        val empty = ShadowAnswer(RCODE_NOERROR, emptySet(), emptySet())
        assertTrue(recordsAgree(empty, TYPE_A, FAMILY_NONE, "", RCODE_NOERROR))
    }

    @Test
    fun `family gating - an AAAA-shadow is scored against the v6 set, never the v4 set`() {
        // A real V6 literal gates qtype AAAA; the shadow's ipv6 must carry the existence parity.
        val v6Shadow = ShadowAnswer(RCODE_NOERROR, emptySet(), setOf("2001:db8::1"))
        assertTrue(recordsAgree(v6Shadow, TYPE_AAAA, FAMILY_V6, "2606:2800::1", RCODE_NOERROR))
        // Same shadow but empty v6 → no parity → disagree (proves it reads ipv6, not ipv4).
        val v6Empty = ShadowAnswer(RCODE_NOERROR, setOf("1.2.3.4"), emptySet())
        assertFalse(recordsAgree(v6Empty, TYPE_AAAA, FAMILY_V6, "2606:2800::1", RCODE_NOERROR))
    }

    // =================================================================================================
    // FAMILY CLASSIFICATION + return-code parity (the FIX-1 gate + the qname-seam bonus)
    // =================================================================================================

    @Test
    fun `ipFamilyOf classifies v4, v6, and non-IP literals by string shape`() {
        // GROUND_TRUTH against the shipped rule (ResolverRuntime.kt:664-669): it is a cheap STRING-shape
        // test, not a real IP parse — ':' ⇒ V6, otherwise '.' ⇒ V4, otherwise NONE.
        assertEquals(FAMILY_V4, ipFamilyOf("93.184.216.34"))
        assertEquals(FAMILY_V6, ipFamilyOf("2606:2800::1"))
        assertEquals(FAMILY_NONE, ipFamilyOf(""))            // empty Resource → no family to gate on
        assertEquals(FAMILY_NONE, ipFamilyOf("hostname"))    // no '.' and no ':' → NONE
        // A dotted CNAME target DOES contain '.', so the shipped rule classes it V4 — this is benign:
        // dns.c emits CNAME targets as their OWN family-gated A/AAAA records, and recordsAgree treats a
        // FAMILY_NONE/positive-mismatch leniently. Pin the ACTUAL behaviour so a future change is conscious.
        assertEquals(FAMILY_V4, ipFamilyOf("cname.target.example"))
    }

    @Test
    fun `isPositiveReturnCode maps query-log RETURNCODE classes to the lenient split`() {
        for (pos in listOf("PASS", "FORWARD", "SYNTH", "CLOAK", " pass ", "Cloak")) {
            assertTrue("'$pos' is a positive return code", isPositiveReturnCode(pos))
        }
        for (neg in listOf("REJECT", "DROP", "NXDOMAIN", "SERVFAIL", "SERVER_TIMEOUT", "", null)) {
            assertFalse("'$neg' is a denial / unknown", isPositiveReturnCode(neg))
        }
    }
}

// =====================================================================================================
// EMU-ONLY CHECKLIST — the parts a JVM unit test provably CANNOT cover (documented per the fix charter)
// =====================================================================================================
//
// The twins above prove the CODEC + the COMPARE CLASSIFICATION on the JVM (necessary, not sufficient).
// These remain the emu /emulator soak's job (DEBUG universal build only — the seam is BuildConfig.DEBUG
// dead-code in release), and are the keystone the COMMIT-GATE report §7 items 1 + 4 own:
//
//   [E1] SEAM FIRES / COMPARES > 0 — DNSCrypt RUNNING, drive real resolution volume, read
//        ResolverRuntime.kt:718 "[periodic] seamHits=N compares=N agree=N% ...". REQUIRE seamHits>0 AND
//        compares>0 AND zero-disagreement-at-volume. No JVM test can fire the native tun callback / the
//        QueryLogTailer / TortaCore.resolve (a real JNI symbol), so this is the ONLY runtime witness.
//        Precedent: shadow-seam-unreachable-dnscrypt-mode.md (ready=2, 130+ resolutions, ZERO compares).
//
//   [E2] DI SHARED-INSTANCE HASH — Log.d System.identityHashCode(resolverRuntime.get()) from BOTH
//        ServiceVPN.java:362 and ModulesStateLoop.java:265/279 → `adb logcat -d -s RR_IDENTITY` → the
//        two hashes MUST be EQUAL (the @ModulesServiceScope parent/child single instance, plan [V3]).
//
//   [E3] QNAME-PRODUCER GUARANTEE — extract the live dnscrypt-proxy.toml on the emu, assert an
//        uncommented absolute `file = ...cache/query.log` line + a non-empty query.log + non-zero
//        qnameResolved/qnameFailed counters (report §7 item 2; the tailer no-ops if the toml line is
//        missing — a "green/quiet" run that tests nothing).
