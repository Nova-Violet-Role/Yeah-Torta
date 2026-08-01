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

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The Shizuku leg of the no-root elevation backbone (P11 §2, the **preferred** provider — one
 * approval tap, no pairing UI). It gives the *same* privileged primitive as the P6 self-ADB path:
 * run a shell command as UID 2000.
 *
 * REUSE, not fork (task law): this mirrors the existing P6
 * [pillar.kuma_saimono.libumdnscrypt .dns_engine.wire_cake_inu.AdbElevation]/[AdbShell] seam shape
 * (AdbElevation.kt:19-36) so the backbone's `ElevationProvider`/`ElevationSession` can wrap a
 * [ShizukuElevation] exactly as it wraps the SelfAdb leg. It hardens the one gap that seam has —
 * `exec` returning a bare stdout `String` with no exit/stderr/timeout (AdbElevation.kt:34) — by
 * returning a [ShizukuExecResult] carrying the real exit code via the sentinel `cmd; echo "$?"`
 * (same fix the plan applies to the libadb leg, P11 §2/§5.6: "Verify never fake").
 *
 * BUILD-GREEN-WITHOUT-THE-DEP (the honest stub the task requires): Shizuku is **not** a dependency
 * at HEAD (build.gradle:196-199 — only libadb/sun-security/conscrypt). So this adapter binds the
 * Shizuku binder through [ShizukuBridge] **by reflection**; with the dep absent every probe answers
 * [ShizukuAvailability.NOT_INSTALLED] and elevation degrades honestly to the self-ADB path. When
 * the dep is added later, the bridge swaps to direct calls behind the same one-method seam — no
 * change here. No root, ever.
 */
class ShizukuElevation(
    private val bridge: ShizukuBridge = ReflectiveShizukuBridge(),
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) {

    /** Why the user can/can't use the one-tap Shizuku path right now. */
    fun availability(): ShizukuAvailability =
        when {
            !bridge.apiPresent -> ShizukuAvailability.NOT_INSTALLED
            !bridge.pingBinder() -> ShizukuAvailability.NOT_RUNNING
            !bridge.hasPermission() -> ShizukuAvailability.PERMISSION_NEEDED
            else -> ShizukuAvailability.READY
        }

    /** True once a live, permission-held Shizuku service can execute privileged commands. */
    val isReady: Boolean
        get() = availability() == ShizukuAvailability.READY

    /**
     * Open the privileged channel. Mirrors [AdbElevation.connect] — a [Result] so a failure only
     * fails this flow, never the app. There is no pairing/handshake for Shizuku (its strength):
     * readiness IS the connection.
     */
    suspend fun connect(): Result<ShizukuShell> =
        withContext(dispatcher) {
            runCatching {
                when (val state = availability()) {
                    ShizukuAvailability.READY -> ShizukuShell(bridge, dispatcher)
                    else -> error(state.honestReason)
                }
            }
        }

    /**
     * Drive the permission REQUEST — the half [availability] can only *observe* (P11 §2 permission
     * handshake, deepened from the corpus). Delegates to [ShizukuBridge.requestPermission]; the
     * manager surfaces the confirmation UI and returns allowed/onetime asynchronously (corpus:
     * `ShizukuService.showPermissionConfirmation` :255-281 → `dispatchPermissionConfirmationResult`
     * :294-316). The `onetime` result there maps 1:1 onto our "protect once" vs "keep protected"
     * `PowerState.desired` UX. Returns true if the ask was dispatched.
     */
    fun requestPermission(requestCode: Int = REQUEST_CODE_ONE_TAP): Boolean =
        bridge.requestPermission(requestCode)

    /** Whether to show the "why we need this" rationale before re-asking (the user denied once). */
    fun shouldShowRationale(): Boolean = bridge.shouldShowRationale()

    /**
     * The privilege the live channel runs at, read from the middle-man's `bindApplication` identity
     * (server uid — ShizukuService.java:233; README.md:52). Our posture PREFERS
     * [ShizukuPrivilege.ADB] (uid 2000, the smaller attack surface); [ShizukuPrivilege.ROOT] works
     * too but is surfaced honestly, never silently preferred.
     */
    fun serverPrivilege(): ShizukuPrivilege = ShizukuPrivilege.fromUid(bridge.serverUid())

    companion object {
        /**
         * The one-tap permission request code (playful: CAke-DEn). App-owned, any stable int works.
         */
        const val REQUEST_CODE_ONE_TAP: Int = 0xCADE
    }
}

/**
 * A live privileged shell over the Shizuku binder. Each [exec] spawns one short-lived `sh -c`
 * process.
 */
class ShizukuShell
internal constructor(
    private val bridge: ShizukuBridge,
    private val dispatcher: CoroutineDispatcher,
) {

    /**
     * Honest liveness of the held privileged channel (the `linkToDeath` deepening). The corpus only
     * accepts a binder that answers `pingBinder()` (ServiceStarter.java:136) and tears the server
     * down on binder death (`linkToDeath { System.exit(0) }` :138-141) — so a stopped Shizuku
     * service must report `false` here, never a stale "connected". Cheap (a binder ping), safe to
     * poll.
     */
    val isAlive: Boolean
        get() = bridge.pingBinder()

    /**
     * Run [command] as UID 2000 and return its real exit code + output.
     *
     * The command MUST be a constant, hard-coded allow-listed op (P11 §5.3); the caller never
     * concatenates user input into it. The exit sentinel `cmd; echo "$?"` recovers the true exit
     * code even though the Shizuku process merges stdout+stderr — the same read-back-honest fix the
     * plan applies to the libadb leg.
     *
     * Binder-death honesty: a held channel can die mid-session (the corpus `linkToDeath` teardown).
     * If the binder no longer answers, [exec] reports a distinct "not alive" result instead of a
     * generic spawn failure — an honest `alive=false` rather than a lie.
     */
    suspend fun exec(command: String): ShizukuExecResult =
        withContext(dispatcher) {
            if (!bridge.pingBinder()) {
                return@withContext ShizukuExecResult(
                    exit = -1,
                    stdout = "",
                    stderr = "Shizuku binder is not alive (service stopped)",
                )
            }
            val raw =
                bridge.newProcess(ShizukuSentinel.wrap(command))
                    ?: return@withContext ShizukuExecResult(
                        exit = -1,
                        stdout = "",
                        stderr = "Shizuku process could not be spawned",
                    )
            ShizukuSentinel.parse(raw)
        }
}

/**
 * The exit-sentinel codec — pure logic, unit-testable on metal (no Android, no Shizuku).
 *
 * Shizuku's `newProcess` gives a real exit code via `waitFor`, but to stay byte-identical with the
 * libadb merged-stream leg (and robust to ROMs that swallow the process exit) we ALSO append the
 * shell sentinel. We trust the parsed sentinel when present, else fall back to the process exit
 * code.
 */
object ShizukuSentinel {

    /** Marks the sentinel line so parsing never confuses it with command output. */
    const val MARKER: String = "__TORTA_RC__"

    /**
     * Wrap a command so its last output line is `MARKER <exit-code>`. (`\$?` = the literal shell
     * var.)
     */
    fun wrap(command: String): String = "$command; echo \"$MARKER \$?\""

    /**
     * Split the raw merged stream into clean output + the real exit code. If the sentinel line is
     * present it wins (it survives stdout/stderr merging); otherwise the process exit code is used
     * and the full output is returned verbatim.
     */
    fun parse(raw: RawProcessResult): ShizukuExecResult {
        val lines = raw.output.split('\n')
        val sentinelIdx = lines.indexOfLast { it.trimStart().startsWith(MARKER) }
        if (sentinelIdx < 0) {
            return ShizukuExecResult(
                exit = raw.exit,
                stdout = raw.output.trimEnd('\n'),
                stderr = "",
            )
        }
        val parsedExit =
            lines[sentinelIdx].trim().removePrefix(MARKER).trim().toIntOrNull() ?: raw.exit
        val clean = lines.subList(0, sentinelIdx).joinToString("\n").trimEnd('\n')
        return ShizukuExecResult(exit = parsedExit, stdout = clean, stderr = "")
    }
}

/**
 * Result of a privileged exec. Carries the real exit code + streams — the upgrade over the existing
 * seam's bare `String` (AdbElevation.kt:34). Shaped to map 1:1 onto the backbone's
 * `ShellResult(exit,stdout,stderr)` (P11 §2:24) when the elevation interfaces land.
 */
data class ShizukuExecResult(
    val exit: Int,
    val stdout: String,
    val stderr: String,
) {
    /** Convenience matching the plan's `ShellResult.ok`. */
    val ok: Boolean
        get() = exit == 0
}

/**
 * Why the one-tap Shizuku path is or isn't usable right now (drives honest UX, never a fake green).
 */
enum class ShizukuAvailability(val honestReason: String) {
    /**
     * The Shizuku app/API is not present — show an install link; self-ADB stays the working path.
     */
    NOT_INSTALLED("Shizuku is not installed — using the on-device pairing path instead"),

    /** Installed but the service isn't started (user must start Shizuku/Sui once). */
    NOT_RUNNING("Shizuku is installed but not running — start it once, then return"),

    /** Running but this app hasn't been granted the one-tap permission yet. */
    PERMISSION_NEEDED("Tap Allow in the Shizuku prompt to grant one-tap protection"),

    /** Ready — privileged commands can run with no pairing screen. */
    READY("Ready");

    val usable: Boolean
        get() = this == READY
}

/**
 * The privilege level of the Shizuku middle-man, decoded from its server uid (README.md:52 —
 * `ShizukuService#getUid`; the `bindApplication` reply `BIND_APPLICATION_SERVER_UID`,
 * ShizukuService.java:233). Drives honest UX/logging ("elevated via ADB shell" vs "via root") — our
 * posture prefers [ADB] (the smaller attack surface) but surfaces [ROOT] rather than hiding it.
 */
enum class ShizukuPrivilege {
    /** Unknown — the API is absent, or the server hasn't reported its uid yet. */
    UNKNOWN,

    /** The ADB shell (uid 2000) — our preferred, smaller-attack-surface privileged channel. */
    ADB,

    /** Root (uid 0) — more powerful; works, but surfaced honestly, never silently preferred. */
    ROOT;

    companion object {
        private const val UID_ROOT = 0
        private const val UID_ADB_SHELL = 2000

        /** Map a server uid to its privilege class. */
        fun fromUid(uid: Int): ShizukuPrivilege =
            when (uid) {
                UID_ROOT -> ROOT
                UID_ADB_SHELL -> ADB
                else -> UNKNOWN
            }
    }
}
