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
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys

/**
 * P10 — the RotationManager DECISION + FAIL-SAFE COMMIT guard. Plain JUnit4 against a tiny in-memory
 * [SharedPreferences] fake (the [CentauriArtifactManagerGovernanceTest] pattern: exercise the REAL
 * production gate, not a copy — no Robolectric, no Mockito). It pins the two load-bearing pure decisions
 * the manager makes; the candidate-flow (RotationPing/RotationSelector) is the sibling parts' unit territory
 * and the VM gradle/emulator path.
 *
 * Properties under test (both exercise the REAL [RotationManager] companion gates):
 *  - **noob default ON** ([RotationManager.shouldRotate]) — an untouched install ROTATES (#133 always-on:
 *    rotation is a privacy feature, default ON so every install gets relay diversity with zero config). The
 *    noob switch is an opt-OUT, not an opt-in.
 *  - **master-gate** — the engine master switch OFF keeps rotation inert even when rotation is opted in.
 *  - **fail-safe COMMIT condition** ([RotationManager.isUsableSummary]) — a rotation commits ONLY on a real
 *    `ready=N>0` summary; `null` / `ready=0` / garbage is the fail-safe "no swap" (keep the current set).
 *    This is the guarantee that a fully-bad candidate set can NEVER tear down a live resolution.
 */
class RotationManagerGateTest {

    // ---- The static decision gate: noob default ON (#133 always-on) + master-gate (no Android runtime). ----

    @Test
    fun `untouched install rotates (noob switch default ON - the always-on privacy default)`() {
        assertTrue(
            "An untouched install MUST rotate (#133 always-on: rotation is a privacy feature, default ON)",
            RotationManager.shouldRotate(FakePrefs())
        )
    }

    @Test
    fun `explicit opt-in is redundant with the default - rotation stays enabled`() {
        val prefs = FakePrefs().apply { setBoolean(TortaeKeys.RESOLVER_ROTATION_ENABLED, true) }
        assertTrue(
            "With the rotate-for-privacy switch ON, rotation is enabled (same as the default)",
            RotationManager.shouldRotate(prefs)
        )
    }

    @Test
    fun `master engine switch off keeps rotation inert even when opted in`() {
        val prefs = FakePrefs().apply {
            setBoolean(TortaeKeys.RESOLVER_ROTATION_ENABLED, true)
            setBoolean(TortaeKeys.DNS_ENGINE_ENABLED, false)
        }
        assertFalse(
            "Engine master switch OFF must keep rotation inert regardless of the opt-in",
            RotationManager.shouldRotate(prefs)
        )
    }

    @Test
    fun `explicit opt-out disables rotation (the noob opt-OUT path)`() {
        val prefs = FakePrefs().apply { setBoolean(TortaeKeys.RESOLVER_ROTATION_ENABLED, false) }
        assertFalse(
            "An explicit opt-out disables rotation (the noob switch is opt-OUT, not opt-in)",
            RotationManager.shouldRotate(prefs)
        )
    }

    // ---- The fail-safe COMMIT condition: only ready=N>0 swaps; everything else keeps the current set. ----

    @Test
    fun `a real ready greater than zero summary commits a rotation`() {
        assertTrue(RotationManager.isUsableSummary("ready=2 transports=do53,dnscrypt"))
        assertTrue(RotationManager.isUsableSummary("ready=1 transports=dnscrypt"))
    }

    @Test
    fun `null summary is no-swap (native unavailable or no usable upstream)`() {
        assertFalse(
            "null = configure unavailable / None -> keep current set",
            RotationManager.isUsableSummary(null)
        )
    }

    @Test
    fun `ready zero is no-swap (a fully-bad candidate set must not commit)`() {
        assertFalse(
            "ready=0 -> no usable upstream -> keep current set",
            RotationManager.isUsableSummary("ready=0 transports=")
        )
    }

    @Test
    fun `garbage or shapeless summary is no-swap`() {
        assertFalse(RotationManager.isUsableSummary(""))
        assertFalse(RotationManager.isUsableSummary("   "))
        assertFalse(RotationManager.isUsableSummary("transports=do53")) // no ready= token
        assertFalse(RotationManager.isUsableSummary("ready=notanumber transports=x"))
        assertFalse(RotationManager.isUsableSummary("ready=-1 transports=x"))
    }

    // ---- FAIL-SAFE layer 2 (availability): never swap onto an all-unreachable pool (cadence-long SERVFAIL). ----

    @Test
    fun `an all-unreachable pick keeps the current set (0 reachable of N targets)`() {
        assertTrue(
            "0 reachable of 10 targets -> the datapath would SERVFAIL every query until the next cadence -> keep current",
            RotationManager.keepCurrentForUnreachablePool(reachableCount = 0, pingTargetCount = 10)
        )
    }

    @Test
    fun `a partially-reachable pick commits (even one live resolver resolves)`() {
        assertFalse(
            "1+ reachable -> the pool resolves -> swap is allowed (the datapath tries the live upstreams)",
            RotationManager.keepCurrentForUnreachablePool(reachableCount = 1, pingTargetCount = 10)
        )
        assertFalse(RotationManager.keepCurrentForUnreachablePool(reachableCount = 7, pingTargetCount = 10))
    }

    @Test
    fun `an empty target set is NOT a keep (nothing to probe - the ready gate still guards)`() {
        assertFalse(
            "no ping targets -> not a reachability keep (a probe-less pick; ready=N>0 commit gate decides)",
            RotationManager.keepCurrentForUnreachablePool(reachableCount = 0, pingTargetCount = 0)
        )
    }

    // ---- FAIL-SAFE layer 3 (ANSWERING): reachable is not answering. ----
    //
    // Layer 2 above proves a server ACCEPTS A TCP CONNECTION. It does not prove the server ANSWERS,
    // and a DNSCrypt resolver whose certificate has rotated does the first while failing the second
    // forever. MEASURED on-device 2026-08-01: rotation index=18 installed 8 servers that every one of
    // them probed reachable at 366-420 ms, and then answered ZERO of 311 queries -- `transport_miss`
    // 63 -> 558 with `answered` frozen at 247. Layer 2 was green throughout. These are the two
    // criteria layer 3 decides on.

    @Test
    fun `a null response is not proof of a live transport`() {
        assertFalse(
            "null is the facade's 'nothing came back' -- mute pool, native fault, or a rejected answer",
            RotationManager.responseProvesLiveTransport(null)
        )
    }

    @Test
    fun `a response shorter than a DNS header is not proof`() {
        assertFalse(
            "a DNS message is >= 12 bytes (RFC 1035 4.1.1); 11 cannot be one",
            RotationManager.responseProvesLiveTransport(ByteArray(11))
        )
        assertFalse("empty is not a DNS message", RotationManager.responseProvesLiveTransport(ByteArray(0)))
    }

    @Test
    fun `a header-sized response IS proof - NXDOMAIN counts as a live transport`() {
        assertTrue(
            "the question is whether the transport carries a validated answer, not what it says: a " +
                "signed 'no such name' proves the server is alive just as well as an address does",
            RotationManager.responseProvesLiveTransport(ByteArray(12))
        )
        assertTrue(RotationManager.responseProvesLiveTransport(ByteArray(512)))
    }

    @Test
    fun `every verification qname is unique - the cache can never answer for the pool`() {
        // THE load-bearing property of the whole gate. resolver_resolve is block-check -> cache ->
        // transport, so a repeatable qname could be served from cache and the gate would go GREEN
        // against a pool that answered nothing -- reinstating the exact outage it exists to catch.
        val names = (1..64).map { RotationManager.verificationQname() }.toSet()
        assertEquals(
            "64 verification qnames must be 64 DISTINCT qnames; a collision means a cached answer can " +
                "satisfy the gate and a mute pool passes verification",
            64,
            names.size
        )
    }

    @Test
    fun `a verification qname is a labelled name under the reserved zone`() {
        val qname = RotationManager.verificationQname()
        assertTrue(
            "must sit under the RFC 2606 reserved zone -- never a vendor domain, so this can never " +
                "become a heartbeat to someone's infrastructure: $qname",
            qname.endsWith(".${RotationManager.VERIFY_ZONE}")
        )
        assertTrue(
            "must be self-identifying in a capture as Tortae's own liveness probe: $qname",
            qname.startsWith(RotationManager.VERIFY_LABEL_PREFIX)
        )
        assertTrue(
            "must carry real entropy in the label, not a fixed string: $qname",
            qname.length > RotationManager.VERIFY_LABEL_PREFIX.length +
                RotationManager.VERIFY_ZONE.length + 1
        )
    }

    // ---- The TOML server_names writer: block-aware, single-line AND multi-line (AVD-caught corruption). ----

    @Test
    fun `single-line server_names is replaced in place, surroundings untouched`() {
        val toml = listOf(
            "server_names = ['old-a', 'old-b']",
            "listen_addresses = [\"127.0.0.1:5354\"]",
        )
        val out = RotationManager.replaceServerNamesBlock(toml, listOf("new-a", "new-b", "new-c"))!!
        assertEquals(2, out.size) // one-line-for-one-line: no growth, no orphan
        assertEquals("server_names = ['new-a', 'new-b', 'new-c']", out[0])
        assertEquals("listen_addresses = [\"127.0.0.1:5354\"]", out[1]) // neighbor intact
    }

    @Test
    fun `multi-line server_names array collapses to one line with NO orphaned body`() {
        // The exact shape the Rust dnscrypt_config_to_toml serializer writes after a torta_ui toggle — the
        // one a single-line-only replace corrupted (orphaned quoted strings + a stray ] → invalid TOML).
        val toml = listOf(
            "server_names = [",
            "    \"old-ipv6\",",
            "    \"old-ipv4\",",
            "    \"old-cisco\",",
            "]",
            "listen_addresses = [\"127.0.0.1:5354\"]",
        )
        val out = RotationManager.replaceServerNamesBlock(toml, listOf("fresh-1", "fresh-2"))!!
        assertEquals("server_names = ['fresh-1', 'fresh-2']", out[0])
        assertEquals("listen_addresses = [\"127.0.0.1:5354\"]", out[1]) // the very next line is the neighbor
        assertEquals(2, out.size) // whole 5-line block ⇒ 1 line: body + closing ] gone
        // Prove the corruption class is gone: no orphaned array-body line, no stray bracket survives.
        assertFalse("no orphaned quoted server entry may survive", out.any { it.trim().startsWith("\"old-") })
        assertFalse("no stray closing bracket may survive", out.any { it.trim() == "]" })
    }

    @Test
    fun `absent server_names returns null so the caller aborts (never a pool-less TOML)`() {
        val toml = listOf("listen_addresses = [\"127.0.0.1:5354\"]", "require_nolog = true")
        assertNull(RotationManager.replaceServerNamesBlock(toml, listOf("x")))
    }

    @Test
    fun `a commented server_names is ignored - only the live uncommented value is rewritten`() {
        val toml = listOf(
            "# server_names = ['a-disabled-example']",
            "server_names = ['live-old']",
        )
        val out = RotationManager.replaceServerNamesBlock(toml, listOf("live-new"))!!
        assertEquals("# server_names = ['a-disabled-example']", out[0]) // comment preserved verbatim
        assertEquals("server_names = ['live-new']", out[1])
    }

    // ---- The LIVE next-flip clock (the `RotationSnapshot.next_flip_secs` producer) — pure, on an
    //      injected monotonic `now` so the plain JVM never touches android.os.SystemClock. The companion
    //      holds ONE global schedule, so every test starts + ends CLEARED (no cross-test bleed). ----

    @Test
    fun `next-flip clock - unarmed reads null (the durable-0 fallback signal)`() {
        RotationManager.clearNextFlip()
        assertNull(
            "No schedule armed MUST read null — the bridge then falls back to the durable 0 (idle dial)",
            RotationManager.liveNextFlipSecs(nowElapsedMs = 1_000L)
        )
    }

    @Test
    fun `next-flip clock - counts down the armed window in whole seconds`() {
        RotationManager.clearNextFlip()
        try {
            RotationManager.publishNextFlip(inMs = 30_000L, nowElapsedMs = 1_000L) // deadline @31s
            assertEquals(30L, RotationManager.liveNextFlipSecs(nowElapsedMs = 1_000L))
            assertEquals(15L, RotationManager.liveNextFlipSecs(nowElapsedMs = 16_000L))
            assertEquals(0L, RotationManager.liveNextFlipSecs(nowElapsedMs = 31_000L))
        } finally {
            RotationManager.clearNextFlip()
        }
    }

    @Test
    fun `next-flip clock - overdue reads NEGATIVE - the slint STALLED contract, never clamped`() {
        RotationManager.clearNextFlip()
        try {
            RotationManager.publishNextFlip(inMs = 30_000L, nowElapsedMs = 1_000L) // deadline @31s
            val overdue = RotationManager.liveNextFlipSecs(nowElapsedMs = 61_000L)!!
            assertTrue(
                "An overdue flip MUST read negative (rotation.slint:174 stalled = next-flip-secs < 0), got $overdue",
                overdue < 0
            )
        } finally {
            RotationManager.clearNextFlip()
        }
    }

    @Test
    fun `next-flip clock - a re-stamp moves the deadline forward (the pre-pass false-overdue guard)`() {
        RotationManager.clearNextFlip()
        try {
            RotationManager.publishNextFlip(inMs = 10_000L, nowElapsedMs = 0L) // the boot settle @10s
            // The settle elapsed; the pass is about to run — the loop re-stamps a full cadence window.
            RotationManager.publishNextFlip(inMs = 1_800_000L, nowElapsedMs = 10_000L)
            assertEquals(
                "The re-stamp owns the schedule — the dial reads the fresh window, never a stale overdue",
                1_800L,
                RotationManager.liveNextFlipSecs(nowElapsedMs = 10_000L)
            )
        } finally {
            RotationManager.clearNextFlip()
        }
    }

    @Test
    fun `next-flip clock - clear returns the dial to the unarmed null`() {
        RotationManager.publishNextFlip(inMs = 30_000L, nowElapsedMs = 1_000L)
        RotationManager.clearNextFlip()
        assertNull(
            "stop() clears the schedule — the dashboard must fall back to the honest idle dial",
            RotationManager.liveNextFlipSecs(nowElapsedMs = 2_000L)
        )
    }

    // ---- #22 capstone slice 4: the direct warm-seed hint mapping (probe sample → typed RttHint). ----

    @Test
    fun `seed hints - probe samples map to typed hints with the same spec-id label`() {
        val samples = listOf(
            RotationPing.RttSample(RotationPing.Candidate(id = "quad9", address = "9.9.9.9:8443"), rttMs = 23),
            RotationPing.RttSample(RotationPing.Candidate(id = "mullvad", address = "194.242.2.2:443"), rttMs = 47),
        )
        val hints = RotationManager.toSeedHints(samples)
        assertEquals(2, hints.size)
        assertEquals("The hint id MUST be the spec-id label (the Rust Transport::id() key)", "quad9", hints[0].id)
        assertEquals(23L, hints[0].rttMs)
        assertEquals("mullvad", hints[1].id)
        assertEquals(47L, hints[1].rttMs)
    }

    @Test
    fun `seed hints - a negative (unreachable) sample is dropped, never a poisoned seed`() {
        val samples = listOf(
            RotationPing.RttSample(RotationPing.Candidate(id = "dead", address = "203.0.113.1:443"), rttMs = -1),
            RotationPing.RttSample(RotationPing.Candidate(id = "alive", address = "9.9.9.9:8443"), rttMs = 12),
        )
        val hints = RotationManager.toSeedHints(samples)
        assertEquals("Only the reachable sample survives the map", 1, hints.size)
        assertEquals("alive", hints[0].id)
        assertEquals(12L, hints[0].rttMs)
    }

    @Test
    fun `seed hints - an empty probe maps to an empty seed (the silent non-event)`() {
        assertTrue(RotationManager.toSeedHints(emptyList()).isEmpty())
    }

    // ---- #22 s5A — the stepper clamps: floor-only, NO upper limit (Socio 2026-07-19:
    //      "remove any Limit to the Number of Resolver / Relays Selectable by the User"). ----

    @Test
    fun `clamp - servers floors at 1 and is free upward (no ceiling, per the Socio no-limits law)`() {
        assertEquals(1, RotationManager.geekClampMaxServers(0))
        assertEquals(1, RotationManager.geekClampMaxServers(-7))
        assertEquals(10, RotationManager.geekClampMaxServers(10))
        assertEquals(999, RotationManager.geekClampMaxServers(999))
    }

    @Test
    fun `clamp - relays allows the legal direct 0 and is free upward (no ceiling)`() {
        assertEquals(0, RotationManager.geekClampMaxRelays(0))
        assertEquals(0, RotationManager.geekClampMaxRelays(-3))
        assertEquals(4, RotationManager.geekClampMaxRelays(4))
        // Socio: "they must even be capable of choosing 20 Relays per 1 Resolver only" — and beyond.
        assertEquals(20, RotationManager.geekClampMaxRelays(20))
        assertEquals(999, RotationManager.geekClampMaxRelays(999))
    }

    // ---- Fake. ----

    /**
     * A minimal in-memory [SharedPreferences] — only the boolean surface [RotationManager.shouldRotate]
     * touches is implemented; everything else throws so an accidental dependency on un-faked behavior fails
     * loudly rather than silently passing. Keeps the test honest (it runs the production gate, not a copy).
     */
    private class FakePrefs : SharedPreferences {
        private val booleans = HashMap<String, Boolean>()

        fun setBoolean(key: String, value: Boolean) { booleans[key] = value }

        override fun getBoolean(key: String?, defValue: Boolean): Boolean = booleans[key] ?: defValue

        // --- Unused surface: fail loudly if the gate ever grows a dependency on these. ---
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
            UnsupportedOperationException("FakePrefs: only getBoolean is supported by the rotation gate")
    }
}
