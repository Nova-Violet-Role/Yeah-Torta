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

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

/**
 * P11 — the no-root **privileged executor** abstraction.
 *
 * Both Shizuku and on-device self-ADB hand us the same primitive: *run a shell command as UID 2000*
 * (`shell` user) with **no root, ever**. The rest of the app must never care which channel delivered
 * it — so it is modelled here as a privileged executor, not as "ADB". This is the clean seam the rest
 * of the app calls (see [ElevationManager]).
 *
 * This file is pure logic / pure contracts — **no Android imports, no device APIs** — so the whole
 * routing + state machine is unit-testable on the JVM with fake providers (the live SPAKE2/mDNS
 * pairing E2E stays a tracked device-only witness; the emulator is a LeakCanary tar pit).
 *
 * The self-ADB implementation REUSES the P6 scaffold, never forks it: a [SelfAdbProvider] wraps the
 * existing [pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.AdbElevation] seam
 * (AdbElevation.kt:19-36) and its [pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.AdbConnectionManager]
 * key/cert persistence (AdbConnectionManager.java:75-95), upgrading its stdout-only
 * `exec(String): String` (AdbElevation.kt:34) to a richer [ShellResult] via an exit sentinel.
 */
interface ElevationProvider {

    /** Stable provider identity, used for ordering, logging and `last_provider` persistence. */
    val id: ProviderId

    /**
     * Cheap, side-effect-free readiness check. Never throws — a probe failure degrades to
     * [Availability.Unavailable], never a crash (fail-open, the wire_cake_inu never-throw contract).
     */
    suspend fun probe(): Availability

    /**
     * Drive this provider toward a live privileged [ElevationSession], emitting [ElevationProgress]
     * as it advances through the [ElevationState] machine. Cold flow: collecting it starts the work;
     * cancelling the collector tears the attempt down. On success the terminal element is
     * [ElevationProgress] at [ElevationState.Elevated]; on failure, [ElevationState.Failed].
     */
    fun acquire(request: ElevationRequest): Flow<ElevationProgress>

    /**
     * The currently held privileged session, or `null` when none is open. Steady state for the
     * security model is `null` (ephemeral: open → grant → verify → close); a session is held only
     * for the duration of an active grant/reconnect cycle.
     */
    val session: StateFlow<ElevationSession?>
}

/** The two no-root channels, in routing-preference order (Shizuku first — one tap, no pairing UI). */
enum class ProviderId(val displayId: String) {
    SHIZUKU("shizuku"),
    SELF_ADB("self-adb");

    companion object {
        fun fromDisplayId(value: String?): ProviderId? =
            entries.firstOrNull { it.displayId == value }
    }
}

/** Result of [ElevationProvider.probe] — whether this channel can be used right now, and why not. */
sealed interface Availability {
    /** Ready to acquire with no further user setup beyond what [acquire] guides. */
    data object Ready : Availability

    /**
     * The channel exists on this device/OS but needs a one-time user action first
     * (e.g. Shizuku installed but not authorized; Wireless Debugging not yet enabled).
     * [reason] is a stable machine token for the UI to map to guidance — never raw shell text.
     */
    data class NeedsSetup(val reason: SetupReason) : Availability

    /** This channel cannot work on this device at all (e.g. API < 30, Shizuku app absent). */
    data class Unavailable(val reason: UnavailableReason) : Availability
}

/** Stable, machine-readable setup hints (the UI maps these to friendly, no-root/no-PC copy). */
enum class SetupReason {
    SHIZUKU_NOT_AUTHORIZED,
    WIRELESS_DEBUG_OFF,
    NOT_PAIRED,
}

/** Stable, machine-readable unavailability reasons. */
enum class UnavailableReason {
    API_TOO_OLD,
    SHIZUKU_NOT_INSTALLED,
    NSD_UNAVAILABLE,
    UNKNOWN,
}

/**
 * What a caller wants from [ElevationProvider.acquire]. Self-ADB needs the 6-digit pairing code
 * (which feeds SPAKE2 pairing crypto ONLY — never concatenated into any shell command) and an
 * optional Expert manual `host:port` fallback. Shizuku ignores both (one approval tap).
 */
data class ElevationRequest(
    /** The 6-digit Wireless Debugging pairing code. `null`/blank when already paired (codeless reconnect) or for Shizuku. */
    val pairingCode: String? = null,
    /** Expert-only manual override of the pairing endpoint, used when mDNS discovery is blocked. */
    val manualHost: String? = null,
    val manualPort: Int? = null,
)

/**
 * A live privileged `shell:` stream running as UID 2000. The exec contract is richer than the P6
 * seam: it returns a full [ShellResult] (exit + stdout + stderr) so a grant can be honestly
 * read-back-verified — "Done" can never lie.
 */
interface ElevationSession {
    /** The effective uid the shell runs as (2000 = the `shell` user for both channels). */
    val uid: Int

    /**
     * Run [command] as UID 2000, bounded by [timeoutMs]. Implementations must surface a non-zero
     * [ShellResult.exit] (or throw) rather than silently swallowing failure. The default path only
     * ever runs constant, allow-listed commands — never user input concatenated into the shell.
     */
    suspend fun exec(command: String, timeoutMs: Long = DEFAULT_EXEC_TIMEOUT_MS): ShellResult

    /** `true` while the underlying stream/binder is usable; flips to `false` on drop or [close]. */
    val alive: StateFlow<Boolean>

    /** Tear the privileged channel down. Idempotent; never throws. */
    fun close()

    companion object {
        const val DEFAULT_EXEC_TIMEOUT_MS = 10_000L
        /** The `shell` user both channels run as — never root (uid 0). */
        const val SHELL_UID = 2000
    }
}

/**
 * The outcome of one privileged command. [ok] is the read-back primitive the GrantEngine builds on.
 */
data class ShellResult(
    val exit: Int,
    val stdout: String,
    val stderr: String,
) {
    val ok: Boolean get() = exit == 0

    /** Trimmed stdout — the canonical form for read-back comparisons (`settings get …`). */
    val value: String get() = stdout.trim()

    companion object {
        /** A synthetic failure result for channels that never opened (no exec ran). */
        fun failure(message: String): ShellResult = ShellResult(exit = -1, stdout = "", stderr = message)
    }
}
