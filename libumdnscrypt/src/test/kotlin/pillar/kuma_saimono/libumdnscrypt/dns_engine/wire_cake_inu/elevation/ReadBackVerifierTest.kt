/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

/*
    This file is part of Yeah! Tortä. GPL-3.0-or-later. Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins [ReadBackVerifier]: the `verify → (if mismatch) set → verify` convergence that makes "protected"
 * HONEST (plan §3 / §5.6). The fix for P6's unconditional `GRANTED=true`. Driven against a faked
 * UID-2000 shell — no Android, no device.
 */
class ReadBackVerifierTest {

    private val alwaysOnVpn = ReadBackVerifier.Power(
        id = "always_on_vpn_app",
        setCommand = "settings put secure always_on_vpn_app app.torta.yeah",
        readBackCommand = "settings get secure always_on_vpn_app",
        expected = "app.torta.yeah",
    )
    private val lockdown = ReadBackVerifier.Power(
        id = "always_on_vpn_lockdown",
        setCommand = "settings put secure always_on_vpn_lockdown 1",
        readBackCommand = "settings get secure always_on_vpn_lockdown",
        expected = "1",
    )

    /** A scripted shell: each command maps to a queue of results popped in order; records every call. */
    private class FakeShell(private val script: Map<String, MutableList<ShellResult>>) {
        val calls = mutableListOf<String>()
        suspend fun exec(cmd: String): ShellResult {
            calls.add(cmd)
            val queue = script[cmd] ?: return ShellResult(0, "", "")
            return if (queue.size > 1) queue.removeAt(0) else queue.first()
        }
    }

    private fun ok(value: String) = ShellResult(0, value, "")
    private fun fail(msg: String) = ShellResult(255, "", msg)

    @Test
    fun `matches requires both ok AND the trimmed value to equal expected`() {
        assertTrue(ReadBackVerifier.matches(alwaysOnVpn, ok("app.torta.yeah")))
        assertTrue(ReadBackVerifier.matches(alwaysOnVpn, ok("  app.torta.yeah \n")))
        assertFalse(ReadBackVerifier.matches(alwaysOnVpn, ok("other.pkg")))
        // Right value but a non-zero exit is NEVER a match (the read itself failed).
        assertFalse(ReadBackVerifier.matches(alwaysOnVpn, ShellResult(1, "app.torta.yeah", "")))
    }

    @Test
    fun `converge is idempotent - an already-applied power costs one read and NO write`() = runBlocking {
        val shell = FakeShell(mapOf(alwaysOnVpn.readBackCommand to mutableListOf(ok("app.torta.yeah"))))
        val outcome = ReadBackVerifier.converge(alwaysOnVpn, shell::exec)

        assertTrue(outcome.verified)
        assertFalse(outcome.wrote)
        assertEquals("app.torta.yeah", outcome.finalValue)
        // Exactly one call (the read-back); the set command was NEVER issued.
        assertEquals(listOf(alwaysOnVpn.readBackCommand), shell.calls)
    }

    @Test
    fun `converge sets then re-verifies a missing power`() = runBlocking {
        // First read: empty (null/missing). Set. Second read: applied.
        val shell = FakeShell(
            mapOf(
                alwaysOnVpn.readBackCommand to mutableListOf(ok("null"), ok("app.torta.yeah")),
                alwaysOnVpn.setCommand to mutableListOf(ok("")),
            ),
        )
        val outcome = ReadBackVerifier.converge(alwaysOnVpn, shell::exec)

        assertTrue(outcome.verified)
        assertTrue(outcome.wrote)
        assertEquals("app.torta.yeah", outcome.finalValue)
        assertEquals(
            listOf(alwaysOnVpn.readBackCommand, alwaysOnVpn.setCommand, alwaysOnVpn.readBackCommand),
            shell.calls,
        )
    }

    @Test
    fun `converge is HONEST - a silent-reject ROM that never applies the value is NOT verified`() =
        runBlocking {
            // Both reads return the unapplied value: the OS put it in the DB but never applied it.
            val shell = FakeShell(
                mapOf(
                    alwaysOnVpn.readBackCommand to mutableListOf(ok("null")),
                    alwaysOnVpn.setCommand to mutableListOf(ok("")),
                ),
            )
            val outcome = ReadBackVerifier.converge(alwaysOnVpn, shell::exec)

            assertFalse("must NOT claim protected when the value never took", outcome.verified)
            assertTrue(outcome.wrote)
        }

    @Test
    fun `converge treats a failing set+read as unverified`() = runBlocking {
        val shell = FakeShell(
            mapOf(
                alwaysOnVpn.readBackCommand to mutableListOf(fail("denied")),
                alwaysOnVpn.setCommand to mutableListOf(fail("denied")),
            ),
        )
        val outcome = ReadBackVerifier.converge(alwaysOnVpn, shell::exec)
        assertFalse(outcome.verified)
        assertEquals("", outcome.finalValue)
    }

    @Test
    fun `convergeAll verifies every power when all take`() = runBlocking {
        val shell = FakeShell(
            mapOf(
                alwaysOnVpn.readBackCommand to mutableListOf(ok("app.torta.yeah")),
                lockdown.readBackCommand to mutableListOf(ok("1")),
            ),
        )
        val outcomes = ReadBackVerifier.convergeAll(listOf(alwaysOnVpn, lockdown), shell::exec)

        assertEquals(2, outcomes.size)
        assertTrue(outcomes.all { it.verified })
        assertTrue(ReadBackVerifier.allVerified(outcomes, expectedCount = 2))
    }

    @Test
    fun `convergeAll stops at the first unverifiable power - partial, never lying`() = runBlocking {
        val shell = FakeShell(
            mapOf(
                // First power can never be verified (silent reject), so the loop stops before lockdown.
                alwaysOnVpn.readBackCommand to mutableListOf(ok("null")),
                alwaysOnVpn.setCommand to mutableListOf(ok("")),
                lockdown.readBackCommand to mutableListOf(ok("1")),
            ),
        )
        val outcomes = ReadBackVerifier.convergeAll(listOf(alwaysOnVpn, lockdown), shell::exec)

        assertEquals(1, outcomes.size) // stopped after the failing first power
        assertFalse(outcomes.first().verified)
        assertFalse(ReadBackVerifier.allVerified(outcomes, expectedCount = 2))
        // lockdown's read-back was never reached.
        assertFalse(shell.calls.contains(lockdown.readBackCommand))
    }

    @Test
    fun `allVerified is false when fewer outcomes than expected even if all present passed`() {
        val outcomes = listOf(
            ReadBackVerifier.Outcome("a", verified = true, wrote = false, finalValue = "x"),
        )
        assertFalse(ReadBackVerifier.allVerified(outcomes, expectedCount = 2))
        assertTrue(ReadBackVerifier.allVerified(outcomes, expectedCount = 1))
    }
}
