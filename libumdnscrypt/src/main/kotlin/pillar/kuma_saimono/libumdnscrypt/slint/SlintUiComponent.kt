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

package pillar.kuma_saimono.libumdnscrypt.slint

import android.content.Context
import android.content.Intent
import me.tatarka.inject.annotations.Component
import me.tatarka.inject.annotations.Inject
import me.tatarka.inject.annotations.Provides
import me.tatarka.inject.annotations.Scope

/**
 * The SLINT graph's scope (SLINT substitution · 1C) — the compile-time equivalent of Dagger's
 * `@Singleton` within THIS component's lifetime (the `InuScope` precedent,
 * wire_cake_inu/WireCakeInuComponent.kt:28). Applied to the component + the bindings that must be
 * ONE instance per process: [SlintSurfaceLifecycle] (its once-per-process feed-prep guard is
 * instance state — an unscoped accessor would mint a fresh instance per activity generation and
 * silently reset the guard, measured on the 1C witness run).
 */
@Scope annotation class SlintUiScope

/**
 * The #69 SLINT-on-Android spike DI graph (OMEGA Stage-D · D1) — the Kotlin-Inject bridge the
 * charter specifies for every SLINT surface ("Kotlin bridge via Kotlin-Inject").
 *
 * Kotlin-Inject (KSP, compile-time, ZERO reflection) on the `WireCakeInuComponent` precedent
 * (dns_engine/wire_cake_inu) — but in the NATIVE idiom the B3 judgment recommends as the migration
 * template (GAP-5): own-code classes carry `@Inject` constructors; `@Provides` exists ONLY for the
 * true external ([Context]).
 *
 * Held once per process by [pillar.kuma_saimono.libumdnscrypt.App.slintUiComponent]; consumers pull the
 * typed accessor (the Android-legal service-locator hop for framework-constructed classes).
 */
@SlintUiScope
@Component
abstract class SlintUiComponent(@get:Provides val appContext: Context) {

    /**
     * The SLINT surface launcher: opens [TortaSlintActivity] (fresh per access — stateless). Since
     * D2 the activity's `android_main` renders the ||| ADVANCED HAMBURGER (the SLINT navigation
     * surface: the K5 DNSCrypt section + the pillar private tabs), with the D1 Centauri dashboard
     * riding behind its centauri tab.
     */
    abstract val slintSpikeLauncher: SlintSpikeLauncher

    /**
     * The app/activity-level SLINT surface lifecycle bracket (SLINT substitution · 1C): feed-root
     * prep at surface start + the teardown witness at surface end. Constructor-injected off this
     * graph; holds ONLY app-scoped state (never an Activity) — leak-free by construction. Driven by
     * the launcher [TortaSlintActivity], which owns the SLINT lifecycle.
     */
    abstract val slintSurfaceLifecycle: SlintSurfaceLifecycle

    /**
     * The log-tail reader behind the Kotlin-ported
     * [pillar.kuma_saimono.libumdnscrypt.settings .ShowLogFragment] (OMEGA D2 — the general-settings
     * `.java` retirement rides this graph: constructor-injected, compile-time, zero reflection).
     */
    abstract val logFileReader: pillar.kuma_saimono.libumdnscrypt.settings.LogFileReader

    /**
     * CP-U · #15 UNDERGROUND H — the Underground pillar's typed view-model (snapshot + the live
     * verdict [kotlinx.coroutines.flow.Flow] + scoring.toml law + verdict pins + the reputation
     * amnesty). Constructor-injected off this graph (the kotlin-inject native `@Inject` idiom).
     */
    abstract val undergroundViewModel: UndergroundViewModel

    /**
     * The app-private data root the SLINT rail feeds from — byte-for-byte the SAME root
     * `torta_ui`'s `android_main` derives natively via `internal_data_path` (torta_ui
     * src/lib.rs:741-744). One truth, two readers: Kotlin preps it, the rail tails it.
     */
    @Provides
    fun slintAppDataDir(): SlintAppDataDir = SlintAppDataDir(appContext.applicationInfo.dataDir)

    // Present so kotlin-inject can also expose a companion-scoped accessor; the primary factory
    // is the generated `KClass<SlintUiComponent>.create(...)` extension (App.slintUiComponent).
    companion object
}

/**
 * Launches the on-device SLINT render witness. Constructor-injected (the kotlin-inject native
 * `@Inject` idiom — no hand-rolled factory), stateless, safe from any context (adds
 * `FLAG_ACTIVITY_NEW_TASK` so an application-context launch is legal).
 */
@Inject
class SlintSpikeLauncher(private val appContext: Context) {

    fun launch() {
        val intent =
            Intent(appContext, TortaSlintActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        appContext.startActivity(intent)
    }
}
