/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

/*
    This file is part of Yeah! Tortä. GPL-3.0-or-later. Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM proofs for the provider-agnostic elevation backbone (P11 builder "provider-core"):
 *   - the [ElevationTransitions] state machine (Idle→Discovering→Pairing→Connecting→Elevated / Failed),
 *   - [ElevationManager] routing: Shizuku-first → self-ADB fallback → none,
 *   - the ephemeral-session + status flow contracts.
 *
 * No Android, no real binder, no device — fake [ElevationProvider]s drive everything. The live
 * SPAKE2/mDNS pairing E2E is a tracked device-only witness (the emulator is a LeakCanary tar pit).
 */
class ElevationRoutingTest {

    // ---- a scriptable fake provider -----------------------------------------

    private class FakeProvider(
        override val id: ProviderId,
        private val availability: Availability,
        private val script: List<ElevationState> = emptyList(),
        private val probeThrows: Boolean = false,
    ) : ElevationProvider {
        var acquireCalls = 0
        private val _session = MutableStateFlow<ElevationSession?>(null)
        override val session: StateFlow<ElevationSession?> = _session

        override suspend fun probe(): Availability {
            if (probeThrows) throw IllegalStateException("boom")
            return availability
        }

        override fun acquire(request: ElevationRequest): Flow<ElevationProgress> = flow {
            acquireCalls++
            for (state in script) {
                if (state is ElevationState.Elevated) _session.value = FakeSession()
                emit(ElevationProgress(id, state))
            }
        }
    }

    private class FakeSession : ElevationSession {
        override val uid = ElevationSession.SHELL_UID
        private val _alive = MutableStateFlow(true)
        override val alive: StateFlow<Boolean> = _alive
        var closed = false
        override suspend fun exec(command: String, timeoutMs: Long) =
            ShellResult(0, "ok", "")
        override fun close() {
            closed = true
            _alive.value = false
        }
    }

    private fun providersOf(vararg p: ElevationProvider): ElevationProviders =
        ElevationProviders { p.toList() }

    private fun manager(vararg p: ElevationProvider) =
        ElevationManager(Dispatchers.Unconfined, providersOf(*p))

    private val happyScript = listOf(
        ElevationState.Discovering,
        ElevationState.Pairing,
        ElevationState.Connecting,
        ElevationState.Elevated,
    )

    // ---- state machine: legal transitions -----------------------------------

    @Test
    fun `idle advances only to discovering or failed`() {
        assertTrue(ElevationTransitions.isValid(ElevationState.Idle, ElevationState.Discovering))
        assertTrue(ElevationTransitions.isValid(ElevationState.Idle, ElevationState.Failed(FailureReason.NO_PROVIDER)))
        assertFalse(ElevationTransitions.isValid(ElevationState.Idle, ElevationState.Connecting))
        assertFalse(ElevationTransitions.isValid(ElevationState.Idle, ElevationState.Elevated))
    }

    @Test
    fun `discovering can skip pairing straight to connecting (shizuku one-tap)`() {
        assertTrue(ElevationTransitions.isValid(ElevationState.Discovering, ElevationState.Pairing))
        assertTrue(ElevationTransitions.isValid(ElevationState.Discovering, ElevationState.Connecting))
    }

    @Test
    fun `the full self-adb happy path is a legal chain`() {
        val chain = listOf(
            ElevationState.Idle,
            ElevationState.Discovering,
            ElevationState.Pairing,
            ElevationState.Connecting,
            ElevationState.Elevated,
        )
        chain.zipWithNext().forEach { (from, to) ->
            assertTrue("$from -> $to must be legal", ElevationTransitions.isValid(from, to))
        }
    }

    @Test
    fun `connecting cannot leap back to discovering`() {
        assertFalse(ElevationTransitions.isValid(ElevationState.Connecting, ElevationState.Discovering))
    }

    @Test
    fun `elevated is ephemeral - drops back to idle, may fail on session loss`() {
        assertTrue(ElevationTransitions.isValid(ElevationState.Elevated, ElevationState.Idle))
        assertTrue(ElevationTransitions.isValid(ElevationState.Elevated, ElevationState.Failed(FailureReason.CONNECT_FAILED)))
        assertFalse(ElevationTransitions.isValid(ElevationState.Elevated, ElevationState.Pairing))
    }

    @Test
    fun `failed is absorbing except a retry reset to idle`() {
        assertTrue(ElevationTransitions.isValid(ElevationState.Failed(FailureReason.PAIRING_REJECTED), ElevationState.Idle))
        // Failed -> Failed is an idempotent re-emit (same class), allowed.
        assertTrue(
            ElevationTransitions.isValid(
                ElevationState.Failed(FailureReason.PAIRING_REJECTED),
                ElevationState.Failed(FailureReason.UNKNOWN),
            )
        )
        assertFalse(ElevationTransitions.isValid(ElevationState.Failed(FailureReason.UNKNOWN), ElevationState.Connecting))
    }

    @Test
    fun `terminal recognises only elevated and failed`() {
        assertTrue(ElevationTransitions.isTerminal(ElevationState.Elevated))
        assertTrue(ElevationTransitions.isTerminal(ElevationState.Failed(FailureReason.UNKNOWN)))
        assertFalse(ElevationTransitions.isTerminal(ElevationState.Idle))
        assertFalse(ElevationTransitions.isTerminal(ElevationState.Connecting))
    }

    // ---- routing: Shizuku-first -> self-ADB fallback -> none -----------------

    @Test
    fun `detect picks shizuku when both are ready`() = runBlocking {
        val shizuku = FakeProvider(ProviderId.SHIZUKU, Availability.Ready)
        val selfAdb = FakeProvider(ProviderId.SELF_ADB, Availability.Ready)
        val mgr = manager(shizuku, selfAdb)
        assertEquals(ProviderId.SHIZUKU, mgr.detectBestProvider())
        assertTrue(mgr.status.value is ElevationStatus.Available)
    }

    @Test
    fun `detect falls back to self-adb when shizuku is unavailable`() = runBlocking {
        val shizuku = FakeProvider(ProviderId.SHIZUKU, Availability.Unavailable(UnavailableReason.SHIZUKU_NOT_INSTALLED))
        val selfAdb = FakeProvider(ProviderId.SELF_ADB, Availability.Ready)
        assertEquals(ProviderId.SELF_ADB, manager(shizuku, selfAdb).detectBestProvider())
    }

    @Test
    fun `detect returns null and NoneAvailable when neither works`() = runBlocking {
        val shizuku = FakeProvider(ProviderId.SHIZUKU, Availability.Unavailable(UnavailableReason.SHIZUKU_NOT_INSTALLED))
        val selfAdb = FakeProvider(ProviderId.SELF_ADB, Availability.Unavailable(UnavailableReason.API_TOO_OLD))
        val mgr = manager(shizuku, selfAdb)
        assertEquals(null, mgr.detectBestProvider())
        assertEquals(ElevationStatus.NoneAvailable, mgr.status.value)
    }

    @Test
    fun `a NeedsSetup channel is still selectable (the wizard will guide it)`() = runBlocking {
        val shizuku = FakeProvider(ProviderId.SHIZUKU, Availability.NeedsSetup(SetupReason.SHIZUKU_NOT_AUTHORIZED))
        assertEquals(ProviderId.SHIZUKU, manager(shizuku).detectBestProvider())
    }

    @Test
    fun `a probe that throws degrades that channel and falls through`() = runBlocking {
        val shizuku = FakeProvider(ProviderId.SHIZUKU, Availability.Ready, probeThrows = true)
        val selfAdb = FakeProvider(ProviderId.SELF_ADB, Availability.Ready)
        // Throwing probe must not crash routing; self-adb is chosen.
        assertEquals(ProviderId.SELF_ADB, manager(shizuku, selfAdb).detectBestProvider())
    }

    // ---- acquire routing + flow contracts -----------------------------------

    @Test
    fun `acquire drives shizuku to elevated and never touches self-adb`() = runBlocking {
        val shizuku = FakeProvider(ProviderId.SHIZUKU, Availability.Ready, happyScript)
        val selfAdb = FakeProvider(ProviderId.SELF_ADB, Availability.Ready, happyScript)
        val mgr = manager(shizuku, selfAdb)

        val emitted = mgr.acquire().toList()

        assertEquals(1, shizuku.acquireCalls)
        assertEquals(0, selfAdb.acquireCalls)
        assertTrue(emitted.last().isElevated)
        assertEquals(ProviderId.SHIZUKU, emitted.last().provider)
        assertTrue(mgr.status.value is ElevationStatus.Elevated)
    }

    @Test
    fun `acquire falls through an unavailable shizuku into self-adb`() = runBlocking {
        val shizuku = FakeProvider(ProviderId.SHIZUKU, Availability.Unavailable(UnavailableReason.SHIZUKU_NOT_INSTALLED), happyScript)
        val selfAdb = FakeProvider(ProviderId.SELF_ADB, Availability.Ready, happyScript)
        val mgr = manager(shizuku, selfAdb)

        val emitted = mgr.acquire().toList()

        assertEquals(0, shizuku.acquireCalls)
        assertEquals(1, selfAdb.acquireCalls)
        assertEquals(ProviderId.SELF_ADB, emitted.last().provider)
        assertTrue(emitted.last().isElevated)
    }

    @Test
    fun `acquire does NOT fall through a provider-specific failure (wrong code stays put)`() = runBlocking {
        // Shizuku is AVAILABLE but the attempt fails (e.g. user declined the tap). Routing must NOT
        // silently re-drive self-ADB mid-flow — a real-but-failed attempt is the user's to retry.
        val failingScript = listOf(
            ElevationState.Discovering,
            ElevationState.Failed(FailureReason.CONNECT_FAILED),
        )
        val shizuku = FakeProvider(ProviderId.SHIZUKU, Availability.Ready, failingScript)
        val selfAdb = FakeProvider(ProviderId.SELF_ADB, Availability.Ready, happyScript)
        val mgr = manager(shizuku, selfAdb)

        val emitted = mgr.acquire().toList()

        assertEquals(1, shizuku.acquireCalls)
        assertEquals(0, selfAdb.acquireCalls)
        assertTrue(emitted.last().isFailed)
    }

    @Test
    fun `acquire with no providers emits a single NO_PROVIDER failure, never throws`() = runBlocking {
        val mgr = manager() // empty
        val emitted = mgr.acquire().toList()
        assertEquals(1, emitted.size)
        val failure = emitted.single().state
        assertTrue(failure is ElevationState.Failed)
        assertEquals(FailureReason.NO_PROVIDER, (failure as ElevationState.Failed).reason)
        assertEquals(ElevationStatus.NoneAvailable, mgr.status.value)
    }

    @Test
    fun `forceProvider pins self-adb even when shizuku is ready (Expert override)`() = runBlocking {
        val shizuku = FakeProvider(ProviderId.SHIZUKU, Availability.Ready, happyScript)
        val selfAdb = FakeProvider(ProviderId.SELF_ADB, Availability.Ready, happyScript)
        val mgr = manager(shizuku, selfAdb)

        val emitted = mgr.acquire(forceProvider = ProviderId.SELF_ADB).toList()

        assertEquals(0, shizuku.acquireCalls)
        assertEquals(1, selfAdb.acquireCalls)
        assertEquals(ProviderId.SELF_ADB, emitted.last().provider)
    }

    @Test
    fun `release closes the held session and resets status (ephemeral steady state)`() = runBlocking {
        val shizuku = FakeProvider(ProviderId.SHIZUKU, Availability.Ready, happyScript)
        val mgr = manager(shizuku)
        mgr.acquire().toList()
        val held = mgr.session.value as FakeSession
        assertTrue(held.alive.value)

        mgr.release()

        assertTrue(held.closed)
        assertFalse(held.alive.value)
        assertEquals(ElevationStatus.Unknown, mgr.status.value)
    }

    // ---- contract sanity on the value types ---------------------------------

    @Test
    fun `ShellResult ok is exit-zero and value trims stdout`() {
        assertTrue(ShellResult(0, " app.torta.yeah \n", "").ok)
        assertFalse(ShellResult(1, "", "denied").ok)
        assertEquals("app.torta.yeah", ShellResult(0, "  app.torta.yeah\n", "").value)
        assertEquals(-1, ShellResult.failure("nope").exit)
    }

    @Test
    fun `ProviderId round-trips through its display id`() {
        assertEquals(ProviderId.SHIZUKU, ProviderId.fromDisplayId("shizuku"))
        assertEquals(ProviderId.SELF_ADB, ProviderId.fromDisplayId("self-adb"))
        assertEquals(null, ProviderId.fromDisplayId("root"))
    }
}
