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
 * P11 — applies the [PowerCatalogue] through a privileged [ElevationSession], honestly.
 *
 * The P6 grant loop ran each command once and DISCARDED its output (WireCakeInuManager.kt:205), then
 * wrote `GRANTED=true` unconditionally (:214-217): "Done" could lie. The GrantEngine replaces that with
 * the convergent, idempotent contract from plan §3:
 *
 *     apply(op) = verify → (if mismatch) set → verify
 *
 * Re-running it on an already-protected device is a no-op (every power verifies on the first read-back,
 * no `set` runs). A power only counts as held when a LIVE read-back equals its expected value — never
 * inferred from a non-zero apply exit, never faked (plan §5.6).
 *
 * All commands run IN the UID-2000 shell via [ElevationSession.exec]; nothing here runs in-process
 * `WRITE_SECURE_SETTINGS` (broken on Android 14+). The catalogue is constant + self-targeted, so no
 * user input is ever concatenated into a command (plan §5.3).
 *
 * Pure orchestration over the seam — the persistence layer is behind [PowerStateStore] so the whole
 * convergence path is unit-testable on metal against a fake session + an in-memory store.
 */
class GrantEngine(
    private val store: PowerStateStore,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    /**
     * Apply [ops] in order through [session], converging each to its desired value. Returns the
     * per-power outcomes; also persists them to [store] so status survives launches + drives boot
     * re-apply. Never throws on a single power failure — it records the failure and moves on so one
     * stubborn ROM quirk does not abort the whole protection.
     */
    suspend fun applyAll(session: ElevationSession, ops: List<PowerOp>): List<PowerOutcome> {
        val outcomes = ArrayList<PowerOutcome>(ops.size)
        for (op in ops) {
            val outcome = apply(session, op)
            outcomes.add(outcome)
            // CRASH ATOMICITY -- persist EACH outcome the moment it is achieved, never in one batch
            // at the end. THE ELEVATION KILLS ITS OWN PROCESS: `pm grant <pkg>
            // android.permission.READ_LOGS` (PowerCatalogue) makes Android SIGKILL us mid-loop, so a
            // trailing persist() never runs and every power already granted -- and the pairing that
            // earned them -- is forgotten. MEASURED on the AVD: the pairing handshake SUCCEEDED
            // ("PairingConnectionCtx: Handshake succeeded", peer adb-EMULATOR36X6X11X0), then
            // "Process 6072 exited due to signal 9 (Killed)", and the pane still read DEMO POSTURE
            // because nothing reached the store. The pillar looked broken while its hardest step had
            // actually worked.
            //
            // `persist` merges by id (load -> overwrite -> save), so per-op writes converge to
            // exactly the same map a single batch write produced. The only thing that changes is
            // WHAT SURVIVES A KILL AT OP k: everything up to k, instead of nothing.
            persist(listOf(outcome))
        }
        return outcomes
    }

    /**
     * Revert [ops] — run each [PowerOp.reverseCmd] and clear their persisted desired-state — so
     * "disable protection" / uninstall leaves nothing enforced (#8 reversibility). Best-effort and
     * never-throws per power: a failed undo on one ROM quirk must not block the rest. Returns the
     * per-power revert outcomes (all `held = false` — the desired post-revert state).
     */
    suspend fun revertAll(session: ElevationSession, ops: List<PowerOp>): List<PowerOutcome> {
        val outcomes = ArrayList<PowerOutcome>(ops.size)
        for (op in ops) {
            outcomes.add(revert(session, op))
        }
        clearDesired(ops)
        return outcomes
    }

    /** Run one power's reverse command. Never throws; a power with no [PowerOp.reverseCmd] is a no-op. */
    suspend fun revert(session: ElevationSession, op: PowerOp): PowerOutcome {
        val cmd = op.reverseCmd
            ?: return outcome(op, held = false, applied = false, detail = "no reverse")
        val result = runCatching { session.exec(AdbSentinel.wrap(cmd)) }
            .map { AdbSentinel.parse(it.combined()) }
            .getOrElse { return outcome(op, held = false, applied = true, detail = it.message ?: "revert threw") }
        return outcome(op, held = false, applied = true, detail = if (result.ok) "reverted" else "revert exit ${result.exit}")
    }

    /** Drop the reverted powers from the persisted map — after this they read as "not protected". */
    private fun clearDesired(ops: List<PowerOp>) {
        val ids = ops.map { it.id }.toSet()
        store.save(store.load().filterNot { it.id in ids })
    }

    /**
     * Convergent apply of a single power: verify first (no-op if already held), set only on mismatch,
     * then verify again. The final [PowerOutcome.held] is ALWAYS from a live read-back (or, for
     * non-read-backable powers, from the apply command's clean exit).
     */
    suspend fun apply(session: ElevationSession, op: PowerOp): PowerOutcome {
        // 1) verify — already held?
        if (op.readBackable && verify(session, op)) {
            return outcome(op, held = true, applied = false, detail = "already held")
        }

        // 2) set
        val setResult = runCatching { session.exec(AdbSentinel.wrap(op.setCmd)) }
            .map { AdbSentinel.parse(it.combined()) }
            .getOrElse { return outcome(op, held = false, applied = true, detail = it.message ?: "set threw") }

        // For non-read-backable powers (e.g. pm grant of a normal runtime perm) the apply exit IS the
        // signal — there is no value to read back. Trust ONLY a clean exit, never non-empty output.
        if (!op.readBackable) {
            return outcome(op, held = setResult.ok, applied = true, detail = if (setResult.ok) "granted" else "set exit ${setResult.exit}")
        }

        // 3) verify again — the only thing that lets us claim "held"
        val held = verify(session, op)
        return outcome(op, held = held, applied = true, detail = if (held) "set+verified" else "set but read-back mismatch")
    }

    /** Read the live value back and check it against the op's expected value. */
    private suspend fun verify(session: ElevationSession, op: PowerOp): Boolean {
        val cmd = op.readBackCmd ?: return false
        val result = runCatching { session.exec(AdbSentinel.wrap(cmd)) }
            .map { AdbSentinel.parse(it.combined()) }
            .getOrElse { return false }
        return PowerCatalogue.isHeld(op, result)
    }

    private fun outcome(op: PowerOp, held: Boolean, applied: Boolean, detail: String): PowerOutcome =
        PowerOutcome(op.id, held = held, applied = applied, verifiedAt = clock(), detail = detail)

    private fun persist(outcomes: List<PowerOutcome>) {
        val existing = store.load().associateBy { it.id }.toMutableMap()
        for (o in outcomes) {
            existing[o.id] = PowerState(
                id = o.id,
                desired = true,
                lastVerified = o.verifiedAt,
                lastResult = o.held,
            )
        }
        store.save(existing.values.toList())
    }

    /** True when EVERY persisted desired power last verified as held — the honest "protected" status. */
    fun isFullyProtected(catalogue: List<PowerOp>): Boolean {
        val byId = store.load().associateBy { it.id }
        return catalogue.all { byId[it.id]?.let { s -> s.desired && s.lastResult } == true }
    }
}

/** The live outcome of applying one power in this pass. */
data class PowerOutcome(
    val id: PowerId,
    val held: Boolean,
    val applied: Boolean,
    val verifiedAt: Long,
    val detail: String,
)

/** Persisted per-power state — the `{id→{desired,lastVerified,lastResult}}` map of plan §3. */
data class PowerState(
    val id: PowerId,
    val desired: Boolean,
    val lastVerified: Long,
    val lastResult: Boolean,
)

/**
 * The persistence seam. The Android binding stores [PowerStateCodec.encode]'s string under
 * `TortaeKeys.WIRELESS_DEBUG_POWER_MAP`; tests use an in-memory implementation.
 */
interface PowerStateStore {
    fun load(): List<PowerState>
    fun save(states: List<PowerState>)
}

/**
 * Pure-Kotlin codec for the per-power map (no `org.json` — that throws "not mocked" in plain JUnit
 * unit tests). Format is one record per line: `key|desired|lastVerified|lastResult`. Unknown/garbled
 * keys are skipped (fail-closed: an unparseable map reads as "nothing held", never a fake "protected").
 */
object PowerStateCodec {

    fun encode(states: List<PowerState>): String =
        states.joinToString("\n") { s ->
            "${s.id.key}|${if (s.desired) 1 else 0}|${s.lastVerified}|${if (s.lastResult) 1 else 0}"
        }

    fun decode(raw: String?): List<PowerState> {
        if (raw.isNullOrBlank()) return emptyList()
        return raw.split("\n").mapNotNull { line ->
            val parts = line.split("|")
            if (parts.size != 4) return@mapNotNull null
            val id = PowerId.fromKey(parts[0]) ?: return@mapNotNull null
            val desired = parts[1] == "1"
            val lastVerified = parts[2].toLongOrNull() ?: return@mapNotNull null
            val lastResult = parts[3] == "1"
            PowerState(id, desired, lastVerified, lastResult)
        }
    }
}

/**
 * Merge a session's merged stream the way [AdbSentinel.parse] expects: libadb gives us one combined
 * text on [ShellResult.stdout] (LibAdbElevation.kt:50-61). When a provider DID split the streams
 * (Shizuku UserService), fold stderr in too so the sentinel still finds its marker.
 */
private fun ShellResult.combined(): String =
    if (stderr.isBlank()) stdout else "$stdout\n$stderr"
