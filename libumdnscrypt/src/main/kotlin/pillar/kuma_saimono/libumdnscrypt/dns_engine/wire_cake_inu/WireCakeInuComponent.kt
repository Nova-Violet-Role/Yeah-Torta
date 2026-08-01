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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu

import android.content.Context
import kotlinx.coroutines.Dispatchers
import me.tatarka.inject.annotations.Component
import me.tatarka.inject.annotations.Provides
import me.tatarka.inject.annotations.Scope
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.ElevationManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.ElevationProvider
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.ElevationProviders
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.LegacyInuMigration
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.PowerStateStore
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.RustPowerStateStore
import uniffi.torta_core.InuStore

/**
 * The Kotlin-Inject scope for the Wire Cake Inu pillar — the compile-time, zero-reflection
 * equivalent of Dagger's `@Singleton` within THIS component's lifetime. Applied to the component +
 * the bindings that must be a single shared instance (the elevation seam, the durable [InuStore],
 * its store wrapper).
 */
@Scope annotation class InuScope

/**
 * The Wire Cake Inu pillar's DI graph — the Kotlin-Inject (KSP, compile-time, ZERO reflection)
 * replacement for the retired Dagger `di/ElevationModule` + the `AppComponent` elevation bindings.
 * This is the de-Dagger showcase for a self-contained pillar (the rest of the app stays Dagger THIS
 * wave; the full app-wide migration is the later substrate wave).
 *
 * Held once per process by [pillar.kuma_saimono.libumdnscrypt.App.wireCakeInuComponent]. Every consumer
 * pulls from that one instance: • [WireCakeInuActivity] / [WireCakeInuService] read
 * [wireCakeInuManager] (fresh per screen/service — each owns its NSD discovery scope, disposed in
 * onDestroy; matches the old non-`@Singleton` Dagger behaviour). • [WireCakeInuActivity] + the
 * cross-pillar keep-alive card read [elevationManager] (ONE shared `@InuScope` instance — the
 * single `StateFlow` source of truth, the old `@Singleton`). • the keep-alive card reads
 * [powerStateStore] (the shared Rust-backed store — F17 single source of truth across both
 * pillars).
 *
 * The elevation LOGIC stays Kotlin (ADB pairing, the grant/read-back); only the DURABLE STATE is
 * Rust (the [InuStore] RAM⊗NAND replacing SharedPreferences).
 */
@InuScope
@Component
abstract class WireCakeInuComponent(@get:Provides val appContext: Context) {

    /**
     * Fresh per access — each Activity/Service owns + disposes its own discovery scope
     * (non-singleton).
     */
    abstract val wireCakeInuManager: WireCakeInuManager

    /** The ONE elevation routing seam (shared `@InuScope` — the old `@Singleton`). */
    abstract val elevationManager: ElevationManager

    /** The shared Rust-backed power-state store (F17 single source of truth across pillars). */
    abstract val powerStateStore: PowerStateStore

    /** The shared durable [InuStore] handle (RAM⊗NAND), for direct typed-state reads/writes. */
    abstract val inuStore: InuStore

    /**
     * `AdbElevation ← LibAdbElevation` — the P6 self-ADB Wave-B engine (was
     * ElevationModule @Provides).
     */
    @Provides fun provideAdbElevation(): AdbElevation = LibAdbElevation(appContext)

    /**
     * The routing set (was ElevationModule @Provides). EMPTY by design (P11 orphan close): with no
     * provider wrappers bound, `ElevationManager.acquire()` degrades to a single honest
     * `NO_PROVIDER` failure and never fabricates a channel (proven by ElevationRoutingTest).
     */
    @Provides
    fun provideElevationProviders(): ElevationProviders = ElevationProviders {
        emptyList<ElevationProvider>()
    }

    /**
     * The durable [InuStore] — opened once (IO-free ctor) and seeded from the legacy
     * SharedPreferences keys on first cold start (F9/F10). `@InuScope`, so the migration + the
     * single shared handle both happen exactly once per process.
     */
    @InuScope
    @Provides
    fun provideInuStore(): InuStore = LegacyInuMigration.openAndMigrate(appContext)

    /** The Rust-backed [PowerStateStore] over the one shared [InuStore]. */
    @InuScope
    @Provides
    fun providePowerStateStore(store: InuStore): PowerStateStore = RustPowerStateStore(store)

    /**
     * The elevation seam (was Dagger `@Singleton @Inject`). Constructed with the app IO dispatcher
     * — `Dispatchers.IO`, exactly what the retired `CoroutinesModule.provideDispatcherIo()`
     * supplied — so the `.flowOn(dispatcherIo)` behaviour is unchanged.
     */
    @InuScope
    @Provides
    fun provideElevationManager(providers: ElevationProviders): ElevationManager =
        ElevationManager(Dispatchers.IO, providers)

    /**
     * The wizard/notification orchestrator (was Dagger `@Inject`). Fresh per access; owns the
     * durable store.
     */
    @Provides
    fun provideWireCakeInuManager(adb: AdbElevation, store: InuStore): WireCakeInuManager =
        WireCakeInuManager(appContext, adb, store)

    // Present so kotlin-inject can also expose a companion-scoped accessor; the primary factory is
    // the
    // generated `KClass<WireCakeInuComponent>.create(...)` extension (App.wireCakeInuComponent).
    companion object
}
