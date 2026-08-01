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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn

/**
 * P11 — the single no-root elevation seam the **rest of the app** calls.
 *
 * Routing law: **Shizuku first** (one approval tap, no pairing UI), **self-ADB fallback** (the P6
 * guided path), **none** otherwise (degrade with guidance, never crash). The manager owns the chosen
 * provider, exposes one [StateFlow] of [ElevationStatus] for the UI, and re-exposes the held
 * [ElevationSession] so a caller can run a verified grant and then drop back to the ephemeral
 * resting state.
 *
 * ## Kotlin-Inject wiring (the Dagger→KI migration)
 * Constructed by the pillar's Kotlin-Inject [pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu
 * .WireCakeInuComponent] (`@Provides provideElevationManager`), which supplies the IO dispatcher
 * (`Dispatchers.IO`, exactly what the retired `CoroutinesModule.provideDispatcherIo()` gave) and the
 * [ElevationProviders] set. `@InuScope` there = one shared instance (the old Dagger `@Singleton`): the
 * Inu Activity and the cross-pillar keep-alive card both read it from `App.wireCakeInuComponent`, so
 * the single [status] StateFlow is one source of truth. The provider set is EMPTY until the
 * Shizuku/SelfAdb wrappers land (P11 Stage 2), so the manager is AVAILABLE but inert, degrading
 * honestly to `NO_PROVIDER` rather than fabricating an elevation channel.
 *
 * This class is pure routing logic over the [ElevationProvider] abstraction — no device APIs — so it
 * is fully unit-testable on the JVM with fake providers (the live SPAKE2/mDNS E2E is a tracked
 * device-only witness; the emulator is a LeakCanary tar pit).
 */
class ElevationManager(
    private val dispatcherIo: CoroutineDispatcher,
    private val providers: ElevationProviders,
) {

    private val _status = MutableStateFlow<ElevationStatus>(ElevationStatus.Unknown)

    /** The single source of truth the UI observes — provider chosen + coarse [ElevationState]. */
    val status: StateFlow<ElevationStatus> = _status.asStateFlow()

    /**
     * The live privileged session, or `null`. Mirrors the chosen provider's session so a caller can
     * `exec` a verified grant. Steady state is `null` (ephemeral security model).
     */
    val session: StateFlow<ElevationSession?>
        get() = chosen?.session ?: NoSession

    @Volatile
    private var chosen: ElevationProvider? = null

    /**
     * Probe both channels in preference order and report which (if any) is usable, without opening a
     * session. Never throws — a probe exception degrades that channel to unavailable.
     */
    suspend fun detectBestProvider(): ProviderId? {
        for (provider in providers.inPreferenceOrder()) {
            val availability = runCatchingProbe(provider)
            if (availability is Availability.Ready || availability is Availability.NeedsSetup) {
                _status.value = ElevationStatus.Available(provider.id, availability)
                return provider.id
            }
        }
        _status.value = ElevationStatus.NoneAvailable
        return null
    }

    /**
     * Acquire a privileged session, routing Shizuku → self-ADB → none. Emits the chosen provider's
     * [ElevationProgress] stream, mirrored into [status]. If the preferred provider is unavailable it
     * falls through to the next; if none is available it emits a single [ElevationState.Failed]
     * ([FailureReason.NO_PROVIDER]) rather than throwing.
     *
     * Provider preference may be pinned via [forceProvider] (Expert "use self-ADB"); otherwise the
     * routing order is honoured.
     */
    fun acquire(
        request: ElevationRequest = ElevationRequest(),
        forceProvider: ProviderId? = null,
    ): Flow<ElevationProgress> = flow {
        val ordered = providers.inPreferenceOrder()
            .let { all -> if (forceProvider != null) all.filter { it.id == forceProvider } else all }

        var lastFailure: ElevationProgress? = null
        for (provider in ordered) {
            val availability = runCatchingProbe(provider)
            if (availability is Availability.Unavailable) {
                lastFailure = ElevationProgress(
                    provider = provider.id,
                    state = ElevationState.Failed(FailureReason.NO_PROVIDER, availability.reason.name),
                )
                continue
            }
            chosen = provider
            provider.acquire(request).collect { progress ->
                _status.value = ElevationStatus.Acquiring(progress.provider, progress.state)
                emit(progress)
                if (progress.isElevated) {
                    _status.value = ElevationStatus.Elevated(progress.provider)
                }
            }
            // A *probed-usable* channel was driven to its own terminal (success, or a
            // provider-specific failure like a wrong 6-digit code / debug toggled off). Routing ends
            // here — it must NOT silently fall through to a different channel mid-attempt. Only an
            // *unavailable* channel falls through (handled above); a pairing rejection is the user's
            // to retry.
            return@flow
        }
        // Nothing usable at all.
        val terminal = lastFailure
            ?: ElevationProgress(ProviderId.SELF_ADB, ElevationState.Failed(FailureReason.NO_PROVIDER))
        _status.value = ElevationStatus.NoneAvailable
        emit(terminal)
    }.flowOn(dispatcherIo)

    /** Drop the held session and return to the ephemeral resting state. Idempotent, never throws. */
    fun release() {
        try {
            chosen?.session?.value?.close()
        } catch (_: Exception) {
            // already closed
        }
        chosen = null
        _status.value = ElevationStatus.Unknown
    }

    private suspend fun runCatchingProbe(provider: ElevationProvider): Availability =
        try {
            provider.probe()
        } catch (_: Exception) {
            Availability.Unavailable(UnavailableReason.UNKNOWN)
        }

    private companion object {
        /** A constant empty-session flow for when no provider is chosen. */
        val NoSession: StateFlow<ElevationSession?> = MutableStateFlow<ElevationSession?>(null)
    }
}

/**
 * The set of [ElevationProvider]s, returned in routing-preference order (Shizuku before self-ADB).
 * A tiny seam so the manager's routing is testable with fakes and so providers stay Dagger-`Lazy`
 * (no Shizuku/ADB stack is built until acquire/probe actually needs it).
 */
fun interface ElevationProviders {
    /** Providers in descending preference: Shizuku first, then self-ADB, then any future channel. */
    fun inPreferenceOrder(): List<ElevationProvider>
}

/** The single app-facing status the UI binds to. */
sealed interface ElevationStatus {
    /** Not yet probed. */
    data object Unknown : ElevationStatus

    /** A channel is usable but no session is open yet. */
    data class Available(val provider: ProviderId, val availability: Availability) : ElevationStatus

    /** No no-root channel is usable on this device. */
    data object NoneAvailable : ElevationStatus

    /** A session acquisition is in flight. */
    data class Acquiring(val provider: ProviderId, val state: ElevationState) : ElevationStatus

    /** A privileged session is held (UID 2000). */
    data class Elevated(val provider: ProviderId) : ElevationStatus
}
