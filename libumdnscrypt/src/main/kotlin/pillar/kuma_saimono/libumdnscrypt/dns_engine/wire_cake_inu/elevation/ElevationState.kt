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
 * P11 — the provider-agnostic elevation lifecycle, as an explicit, **pure-logic** state machine.
 *
 * This is the canonical phase set the task pins: Idle → Discovering → Pairing → Connecting →
 * Elevated, with Failed as the absorbing error state. It is deliberately *device-independent* — no
 * Android types — so the routing and transitions are unit-testable on the JVM with fake providers.
 *
 * It sits one level above the existing P6
 * [pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.WireCakeInuUiState] (WireCakeInuUiState.kt:15-45,
 * a 10-state UI machine for the self-ADB wizard). That UI machine stays as the SelfAdb provider's
 * own fine-grained rendering; this coarser machine is what the **rest of the app** observes through
 * [ElevationManager], identical no matter which channel (Shizuku one-tap or self-ADB guided) drove it.
 */
sealed interface ElevationState {

    /** Nothing in flight. No provider chosen, no session held. The resting state. */
    data object Idle : ElevationState

    /**
     * Locating the privileged channel: Shizuku binder ping, or self-ADB mDNS discovery of the
     * `_adb-tls-pairing._tcp` / `_adb-tls-connect._tcp` endpoints. Bounded by a timeout — never an
     * infinite spinner (the P6 gap, WireCakeInuManager.kt:89-107).
     */
    data object Discovering : ElevationState

    /**
     * Establishing trust: self-ADB runs the SPAKE2 + TLS pairing seeded by the 6-digit code; Shizuku
     * has no pairing step and passes straight through (it surfaces as a no-op transition).
     */
    data object Pairing : ElevationState

    /** Opening the privileged shell (self-ADB TLS connect; Shizuku binder process). */
    data object Connecting : ElevationState

    /**
     * A live privileged session is held — commands run as UID 2000. Terminal-success of [acquire];
     * the [ElevationManager] then runs the GrantEngine and drops back toward [Idle] (ephemeral).
     */
    data object Elevated : ElevationState

    /**
     * Absorbing failure state. [reason] is a stable machine token; [detail] is the verbatim message
     * for the Expert log only (never shown in default copy).
     */
    data class Failed(val reason: FailureReason, val detail: String? = null) : ElevationState
}

/** Stable, machine-readable failure reasons (the UI maps these to friendly no-root/no-PC copy). */
enum class FailureReason {
    /** No usable channel on this device (API < 30 and no Shizuku). */
    NO_PROVIDER,
    /** mDNS discovery / binder ping timed out. */
    DISCOVERY_TIMEOUT,
    /** SPAKE2 pairing rejected (wrong/expired 6-digit code). */
    PAIRING_REJECTED,
    /** Could not open the privileged shell (Wireless Debugging turned off mid-flow, binder died). */
    CONNECT_FAILED,
    /** The resolved host was NOT a loopback/self address — a rogue-LAN endpoint was rejected. */
    HOST_NOT_SELF,
    /** A privileged command failed or read-back did not converge. */
    GRANT_FAILED,
    /** The user cancelled. */
    CANCELLED,
    /** Anything else; [ElevationState.Failed.detail] carries the verbatim message. */
    UNKNOWN,
}

/**
 * One step of an [ElevationProvider.acquire] flow: the coarse [state], which provider is driving it,
 * and an optional [substep] string for richer UI (e.g. the self-ADB wizard's per-step labels). Kept
 * a plain data class so it is trivial to assert on in unit tests.
 */
data class ElevationProgress(
    val provider: ProviderId,
    val state: ElevationState,
    val substep: String? = null,
) {
    /** Convenience: this is the terminal-success element of an acquire flow. */
    val isElevated: Boolean get() = state is ElevationState.Elevated

    /** Convenience: this is a terminal-failure element of an acquire flow. */
    val isFailed: Boolean get() = state is ElevationState.Failed
}

/**
 * Validates an [ElevationState] transition for the provider-agnostic machine. Pure function — the
 * single source of truth the unit tests exercise, independent of any device, coroutine, or provider.
 *
 * The legal graph:
 * ```
 *   Idle        → Discovering | Failed
 *   Discovering → Pairing | Connecting | Failed   (Shizuku skips Pairing → Connecting)
 *   Pairing     → Connecting | Failed
 *   Connecting  → Elevated   | Failed
 *   Elevated    → Idle | Failed                    (ephemeral: drop back after grant, or session lost)
 *   Failed      → Idle                             (retry resets to Idle; Failed is otherwise absorbing)
 * ```
 * A self-transition (same state → same state) is always allowed (idempotent re-emit).
 */
object ElevationTransitions {

    fun isValid(from: ElevationState, to: ElevationState): Boolean {
        if (from::class == to::class) return true // idempotent re-emit (Failed→Failed allowed too)
        return when (from) {
            is ElevationState.Idle ->
                to is ElevationState.Discovering || to is ElevationState.Failed
            is ElevationState.Discovering ->
                to is ElevationState.Pairing || to is ElevationState.Connecting || to is ElevationState.Failed
            is ElevationState.Pairing ->
                to is ElevationState.Connecting || to is ElevationState.Failed
            is ElevationState.Connecting ->
                to is ElevationState.Elevated || to is ElevationState.Failed
            is ElevationState.Elevated ->
                to is ElevationState.Idle || to is ElevationState.Failed
            is ElevationState.Failed ->
                to is ElevationState.Idle
        }
    }

    /** `true` if [state] is a terminal element of an acquire flow (no further emits expected). */
    fun isTerminal(state: ElevationState): Boolean =
        state is ElevationState.Elevated || state is ElevationState.Failed
}
