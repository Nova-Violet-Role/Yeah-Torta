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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

/**
 * The honest "did it actually take?" core (plan §3 / §5.6). P6 ran each grant once and then wrote
 * `WIRELESS_DEBUG_GRANTED = true` UNCONDITIONALLY — so a write that the OS silently rejected (some
 * ROMs put a `secure` value in the DB but never apply it) still reported "protected". P11 NEVER
 * claims protected without a live read-back of the value.
 *
 * Each power is `apply = verify → (if mismatch) set → verify`, which is idempotent and convergent:
 * an already-applied power costs ONE read-back and no write; a missing one is set then re-read. All
 * commands run in the UID-2000 shell — never in-process `WRITE_SECURE_SETTINGS` (throws on Android
 * 14+). This object is pure: it drives an abstract `exec`, so the whole convergence is unit-testable
 * on metal against a faked shell.
 */
object ReadBackVerifier {

    /**
     * A single self-targeted power: the command that SETS it, the command that READS it back, and the
     * exact value the read-back must equal. Hard-coded allow-list members only — no user input is ever
     * concatenated into a shell command (plan §5.3). [id] is the stable key for the persistence map
     * (never a display string, which P6 wrongly keyed on).
     */
    data class Power(
        val id: String,
        val setCommand: String,
        val readBackCommand: String,
        val expected: String,
    )

    /** Whether a read-back result matches the desired value. A non-ok read is never a match. */
    fun matches(power: Power, readBack: ShellResult): Boolean =
        readBack.ok && readBack.value == power.expected

    /** The outcome of converging a single power. */
    data class Outcome(
        val id: String,
        val verified: Boolean,
        /** True when a set was issued (the power was missing/mismatched on first read). */
        val wrote: Boolean,
        /** The final read-back value observed (for the Expert log / status card). */
        val finalValue: String,
    )

    /**
     * Converge ONE power: read it back; if it already matches, done (no write). Otherwise set it and
     * read back again; report whether the second read matches. [exec] is the UID-2000 shell command
     * runner — abstract so a faked session drives this in a unit test.
     *
     * Failure is honest: if the post-write read-back still does not match, [Outcome.verified] is false
     * — the caller must NOT mark the power (or the whole flow) protected.
     */
    suspend fun converge(power: Power, exec: suspend (String) -> ShellResult): Outcome {
        val first = exec(power.readBackCommand)
        if (matches(power, first)) {
            return Outcome(power.id, verified = true, wrote = false, finalValue = first.value)
        }

        exec(power.setCommand)

        val second = exec(power.readBackCommand)
        return Outcome(
            id = power.id,
            verified = matches(power, second),
            wrote = true,
            finalValue = if (second.ok) second.value else "",
        )
    }

    /**
     * Converge a whole plan in order. Stops on the FIRST power that cannot be verified (a partial,
     * honest result is better than barreling on and then lying "protected"). Returns the outcomes for
     * every power attempted; the caller marks protected only when EVERY outcome is verified.
     */
    suspend fun convergeAll(
        powers: List<Power>,
        exec: suspend (String) -> ShellResult,
    ): List<Outcome> {
        val results = ArrayList<Outcome>(powers.size)
        for (power in powers) {
            val outcome = converge(power, exec)
            results.add(outcome)
            if (!outcome.verified) break
        }
        return results
    }

    /** The whole plan is protected only when every power was verified — never on a partial run. */
    fun allVerified(outcomes: List<Outcome>, expectedCount: Int): Boolean =
        outcomes.size == expectedCount && outcomes.all { it.verified }
}
