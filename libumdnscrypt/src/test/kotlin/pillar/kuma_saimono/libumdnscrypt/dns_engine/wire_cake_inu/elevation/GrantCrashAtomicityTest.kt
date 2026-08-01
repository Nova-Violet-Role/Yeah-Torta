/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * THE ELEVATION KILLS ITS OWN PROCESS — so [GrantEngine.applyAll] must persist EACH power as it
 * lands, never in one batch at the end.
 *
 * MEASURED ON THE AVD (checkpoint 95), driving the real flow — Developer settings → Wireless
 * debugging → Pair device with pairing code → the 6-digit code typed into the Inu notification:
 *
 *     PairingConnectionCtx: Handshake succeeded.
 *     PairingConnectionCtx: PeerInfo{type=1, data=[adb-EMULATOR36X6X11X0-rlaotK]}
 *     ActivityManager: Scheduling restart of crashed service ... WireCakeInuService
 *     Zygote: Process 6072 exited due to signal 9 (Killed)
 *
 * The pairing SUCCEEDED and the pane still read "DEMO POSTURE — no elevation record exists on this
 * device yet", because `PowerCatalogue` grants `android.permission.READ_LOGS` and Android kills the
 * target process when that permission changes. The old `applyAll` looped every op and called
 * `persist()` ONCE at the end, so signal 9 landed before the only write and every granted power —
 * plus the pairing that earned them — was forgotten.
 *
 * Signal 9 cannot be caught: no exception, no `finally`, no coroutine cancellation handler. The ONLY
 * defence is to have already written. That makes the ordering of writes the property under test, and
 * it is invisible to a test that merely checks the final state — which is why the old code passed
 * every existing test while losing everything on a real device.
 *
 * The companion proof over EVERY kill point (not just the three sampled here) is
 * `D:\Lean\proofs\Proofs\GrantCrashAtomicity.lean`.
 */
class GrantCrashAtomicityTest {

    private val pkg = "app.torta.yeah"

    /** A session that records the order commands ran in — the timeline we compare writes against. */
    private class FakeSession(
        private val responder: (String) -> Pair<String, Int>,
        private val onCommand: (String) -> Unit = {},
    ) : ElevationSession {
        override val uid = ElevationSession.SHELL_UID
        private val _alive = MutableStateFlow(true)
        override val alive: StateFlow<Boolean> = _alive

        override suspend fun exec(command: String, timeoutMs: Long): ShellResult {
            val core = command.substringBefore("; echo \"${AdbSentinel.MARK}")
            onCommand(core)
            val (out, exit) = responder(core)
            val merged = if (out.isEmpty()) "${AdbSentinel.MARK}$exit" else "$out\n${AdbSentinel.MARK}$exit"
            return ShellResult(0, merged, "")
        }

        override fun close() {
            _alive.value = false
        }
    }

    /**
     * A store that remembers EVERY save, not just the last one. The bug is in the write TIMELINE, so
     * a store that only keeps the final value cannot see it.
     */
    private class RecordingStore : PowerStateStore {
        var states: List<PowerState> = emptyList()
        val saves = mutableListOf<List<PowerState>>()
        override fun load() = states
        override fun save(states: List<PowerState>) {
            this.states = states
            saves.add(states.toList())
        }
    }

    /** Everything the engine asks for succeeds and reads back as desired. */
    private fun happyResponder(): (String) -> Pair<String, Int> = { cmd ->
        when {
            cmd.startsWith("settings get secure always_on_vpn_app") -> pkg to 0
            cmd.startsWith("settings get secure always_on_vpn_lockdown_whitelist") -> "null" to 0
            cmd.startsWith("settings get secure always_on_vpn_lockdown") -> "1" to 0
            cmd.startsWith("settings get global private_dns_mode") -> "off" to 0
            cmd.startsWith("settings get global private_dns_specifier") -> "null" to 0
            cmd.startsWith("settings get") -> "1" to 0
            else -> "" to 0
        }
    }

    /**
     * THE REGRESSION GUARD. Every op must be durable BEFORE the next op runs, because the next op
     * may be the one that kills us. Batch persistence produces exactly ONE save; per-op persistence
     * produces one per op.
     */
    @Test
    fun everyPowerIsPersistedBeforeTheNextOneRuns() = runBlocking {
        val store = RecordingStore()
        val ops = PowerCatalogue.tier1(pkg)
        assertTrue("need >1 op for this to mean anything", ops.size > 1)

        GrantEngine(store).applyAll(FakeSession(happyResponder()), ops)

        assertEquals(
            "one durable write per power — a single save means the old BATCH behaviour is back, " +
                "and a kill mid-loop would lose every power already granted",
            ops.size,
            store.saves.size,
        )
    }

    /**
     * The kill is simulated where it really happens: the process dies during op k, so nothing after
     * it runs. We assert that the store — as it stood at that moment — already holds every power
     * applied before k. This is the property the AVD run violated.
     */
    @Test
    fun aKillPartWayThroughKeepsEveryPowerAlreadyGranted() = runBlocking {
        val store = RecordingStore()
        val ops = PowerCatalogue.tier1(pkg)
        val killAt = ops.size / 2

        GrantEngine(store).applyAll(FakeSession(happyResponder()), ops)

        // The store's state immediately after op `killAt` — i.e. what a SIGKILL there would leave.
        val survived = store.saves[killAt - 1]
        val expected = ops.take(killAt).map { it.id }.toSet()
        assertTrue(
            "a kill after op $killAt must leave those powers on disk; found ${survived.map { it.id }}",
            survived.map { it.id }.toSet().containsAll(expected),
        )
    }

    /**
     * The fix must not change the OUTCOME of a complete run — only what survives an interrupted one.
     * If this fails, the crash-safety change smuggled in a behaviour change.
     */
    @Test
    fun aCompleteRunEndsInTheSameStateAsBefore() = runBlocking {
        val store = RecordingStore()
        val ops = PowerCatalogue.tier1(pkg)

        val outcomes = GrantEngine(store).applyAll(FakeSession(happyResponder()), ops)

        assertEquals("every op reported", ops.size, outcomes.size)
        assertEquals(
            "final persisted set == every op applied",
            ops.map { it.id }.toSet(),
            store.states.map { it.id }.toSet(),
        )
        assertTrue("every persisted power is marked desired", store.states.all { it.desired })
    }
}
