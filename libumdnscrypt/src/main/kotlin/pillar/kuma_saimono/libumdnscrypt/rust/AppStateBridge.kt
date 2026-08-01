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

package pillar.kuma_saimono.libumdnscrypt.rust

import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RuntimeTierManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.settings.PresetFirstRun
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.SAVED_DNSCRYPT_STATE_PREF

/**
 * #21 G7-RESIDUAL — the Kotlin face of the Rust `app-state` DurableTier record
 * ([uniffi.torta_core.AppStateStore], app_state.rs): the LAST load-bearing app-level flags leaving
 * SharedPreferences. The [LegacyInuMigration]-style seam for state that has no pillar component of
 * its own — held by [TortaCore] (the process-global holder), absorbed once, then typed forever.
 *
 * ## What moved (this slice)
 * - `savedDNSCryptState` ([SAVED_DNSCRYPT_STATE_PREF], the ModulesStateLoop dedupe token) — the 4
 *   call sites (loop read/write + the two reset-UNDEFINED) all route here.
 * - the one-shot "default preset seeded" latch ([PresetFirstRun.PREF_DEFAULT_PRESET_SEEDED]).
 *
 * `OPERATION_MODE` / `VPN_SERVICE_ENABLED` have live SCHEMA SEATS in the record but their 20/35
 * call sites stay on prefs this slice (NO dual-write shadow state — a seam migrates atomically or
 * not at all).
 *
 * ## The fallback law (crash-proof, no-regression)
 * Every accessor falls back to the EXACT legacy prefs path when the `.so`/store is unreachable
 * (the [TortaCore] facade contract) — behaviour then is byte-identical to pre-#21. The two lanes
 * never run together in one process: the store either opens (and owns the truth) or it never does.
 *
 * ## The one-shot absorb
 * On the first successful open per process, each legacy value folds into the record ONCE, guarded
 * by the record's own cold state (absorb only into an empty seat — never clobber a truth the
 * record already owns). The preset-seeded legacy KEY is removed after a successful fold (the
 * one-shot latch); the repo string is left in place but never consulted again.
 */
object AppStateBridge {

    /** One absorb attempt per process (the fold itself is idempotent — this just skips rework). */
    @Volatile private var absorbed = false

    /** The shared durable root (G9 law: `<appData>/app_data/runtime_tier`, never a third root). */
    private fun durableDir(): String =
        App.instance.daggerComponent.getPathVars().get().appDataDir +
            RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR

    /**
     * The opened store (opening + absorbing on first touch), or null → callers use the legacy
     * lane. Never throws.
     */
    private fun store(): uniffi.torta_core.AppStateStore? =
        try {
            TortaCore.appStateOrNull()
                ?: TortaCore.appStateOpen(durableDir())?.also { absorbLegacyOnce(it) }
        } catch (t: Throwable) {
            loge("AppStateBridge store", t)
            null
        }

    /** Fold the legacy pref values into the record's cold seats, once per process. */
    private fun absorbLegacyOnce(store: uniffi.torta_core.AppStateStore) {
        if (absorbed) return
        absorbed = true
        try {
            // savedDNSCryptState: repo string → the record, only into an EMPTY seat.
            val repo = App.instance.daggerComponent.getPreferenceRepository().get()
            val legacyState = repo.getStringPreference(SAVED_DNSCRYPT_STATE_PREF)
            if (legacyState.isNotEmpty() && store.savedDnscryptState().isEmpty()) {
                store.setSavedDnscryptState(legacyState)
            }
            // preset-seeded latch: default-prefs bool → the record; REMOVE the key on a
            // successful fold (the one-shot latch — pre-#21 installs stop carrying it).
            val prefs =
                PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
            if (prefs.contains(PresetFirstRun.PREF_DEFAULT_PRESET_SEEDED)) {
                val seeded = prefs.getBoolean(PresetFirstRun.PREF_DEFAULT_PRESET_SEEDED, false)
                val folded = if (seeded && !store.defaultPresetSeeded()) {
                    store.setDefaultPresetSeeded(true)
                } else {
                    true // false/absent value or already-folded record — nothing to carry.
                }
                if (folded) {
                    prefs.edit().remove(PresetFirstRun.PREF_DEFAULT_PRESET_SEEDED).apply()
                }
            }
        } catch (t: Throwable) {
            loge("AppStateBridge absorbLegacyOnce", t)
        }
    }

    /**
     * The persisted DNSCrypt module-state token (`""` = never written — the legacy absent-key
     * read). RAM-tier read on the store lane. Never throws.
     */
    @JvmStatic
    fun savedDnsCryptState(): String =
        try {
            store()?.savedDnscryptState()
                ?: App.instance.daggerComponent.getPreferenceRepository().get()
                    .getStringPreference(SAVED_DNSCRYPT_STATE_PREF)
        } catch (t: Throwable) {
            loge("AppStateBridge savedDnsCryptState", t)
            ""
        }

    /** Persist the DNSCrypt module-state token (control-plane write-through). Never throws. */
    @JvmStatic
    fun setSavedDnsCryptState(token: String) {
        try {
            val s = store()
            if (s != null) {
                s.setSavedDnscryptState(token)
            } else {
                App.instance.daggerComponent.getPreferenceRepository().get()
                    .setStringPreference(SAVED_DNSCRYPT_STATE_PREF, token)
            }
        } catch (t: Throwable) {
            loge("AppStateBridge setSavedDnsCryptState", t)
        }
    }

    /** The one-shot "default preset seeded" latch. Never throws (false on any fault). */
    @JvmStatic
    fun defaultPresetSeeded(): Boolean =
        try {
            store()?.defaultPresetSeeded()
                ?: PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                    .getBoolean(PresetFirstRun.PREF_DEFAULT_PRESET_SEEDED, false)
        } catch (t: Throwable) {
            loge("AppStateBridge defaultPresetSeeded", t)
            false
        }

    /** Latch the seeded flag (fires once per install). Never throws. */
    @JvmStatic
    fun setDefaultPresetSeeded(on: Boolean) {
        try {
            val s = store()
            if (s != null) {
                s.setDefaultPresetSeeded(on)
            } else {
                PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                    .edit().putBoolean(PresetFirstRun.PREF_DEFAULT_PRESET_SEEDED, on).apply()
            }
        } catch (t: Throwable) {
            loge("AppStateBridge setDefaultPresetSeeded", t)
        }
    }
}
