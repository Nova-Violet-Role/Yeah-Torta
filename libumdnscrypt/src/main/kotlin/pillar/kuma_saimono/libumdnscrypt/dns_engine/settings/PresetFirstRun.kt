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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.settings

import android.content.Context
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.rust.AppStateBridge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys

/**
 * 🔒 The DEFAULT-PRESET wiring (Pillar 13 §B — Socio privacy-first law, checklist §B:86).
 *
 * Settles the open default-preset decision: the out-of-box profile is **Privacy** (always-rotate,
 * full DNSCrypt privacy), with **Gaming** as a one-tap chip. This file owns the *default* side of
 * the preset system — the single source of truth for "what an untouched install lands on" and the
 * one-time first-run seed that makes that real in SharedPreferences.
 *
 * WHY A FIRST-RUN SEED IS NEEDED (and is the right, minimal mechanism): The out-of-box
 * everything-ON posture is a BUNDLE of keys, not a single XML `defaultValue`. Even with the
 * XML/code defaults flipped ON, the multi-key Privacy bundle written together is the
 * belt-and-braces that makes first-run + restore + migration ALL land everything-ON coherently.
 * [PresetApplier] is the canonical value-only bundle writer; this object simply applies the
 * **default** bundle ONCE, the first time the app initialises, then steps aside forever.
 *
 * DATAPATH-SAFE by construction: it only delegates to [PresetApplier.applyPreset], which writes
 * pref **values** only (engine preset + the constant all-ON pillars: native resolver #85 +
 * rotation + governors #91 + solver). It performs NO live arm, touches NO datapath, changes NO leak
 * surface — the engine / resolver / rotation / governor / solver subsystems read these values only
 * when THEIR subsystem arms, and native-resolver is fail-safe behind the #85 ModulesStateLoop
 * release-arm guard. Seeding the default is exactly as inert as the user tapping the Privacy card
 * on first launch.
 *
 * USER-FREEDOM honoured: the seed runs ONCE, guarded by [PREF_DEFAULT_PRESET_SEEDED]. After that
 * the profile is a **starting point, not a lock** — every key the bundle set (rotation, solver, the
 * base preset) stays individually toggleable, and the seed never re-asserts itself over a returning
 * user's choices. It also yields gracefully if the user somehow set any of these keys before first
 * init.
 */
object PresetFirstRun {

    /**
     * One-time guard: set to true once the out-of-box default profile has been seeded. #21
     * G7-RESIDUAL: the LIVE latch moved into the Rust `app-state` DurableTier record (read/written
     * through [pillar.kuma_saimono.libumdnscrypt.rust.AppStateBridge]); this key survives only as the
     * LEGACY name the one-shot absorb reads (then removes) on a pre-#21 install. `internal` so the
     * bridge can name it; the shared [TortaeKeys] schema stays untouched (disjoint ownership).
     */
    internal const val PREF_DEFAULT_PRESET_SEEDED = "pref_torta_default_preset_seeded"

    /**
     * The out-of-box default profile for an untouched install — Privacy-first (always-rotate).
     *
     * Re-exposes the canonical [TortaPreset.DEFAULT_TORTA_PRESET] so callers wiring "the default"
     * have a single, named entry point on the default-wiring surface, without reaching into the
     * bundle enum directly. (Both resolve to [TortaPreset.PRIVACY].)
     */
    @JvmField val DEFAULT_PROFILE: TortaPreset = TortaPreset.DEFAULT_TORTA_PRESET

    /**
     * Whether the out-of-box default profile has already been seeded into this install.
     *
     * @param context any context; the default SharedPreferences are inspected.
     */
    @JvmStatic
    fun isSeeded(context: Context): Boolean =
        // #21: the latch lives in the Rust app-state record (legacy-prefs fallback inside).
        AppStateBridge.defaultPresetSeeded()

    /**
     * Seed the out-of-box **Privacy** default profile EXACTLY ONCE, on first init.
     *
     * Idempotent and self-guarding: on every call after the first it is a cheap no-op (returns
     * false), so it never clobbers a returning user's individual choices. Safe to call from any
     * app-start / first-install path — calling it more than once, or on an already-configured
     * install, does nothing.
     *
     * Returns true only on the first run, when the Privacy bundle was actually written.
     *
     * @param context any context; the default SharedPreferences are used (the same store the
     *   engine, rotation and solver subsystems read when they arm).
     */
    @JvmStatic
    fun seedDefaultProfileIfFirstRun(context: Context): Boolean {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)

        // Already seeded (or a returning user) → never overwrite their posture. (#21: the latch
        // reads from the Rust app-state record, absorb-migrated from the legacy pref.)
        if (AppStateBridge.defaultPresetSeeded()) {
            return false
        }

        // Extra safety: if the user has already expressed an explicit choice over ANY of the
        // constant
        // core pillars the everything-ON bundle arms (the engine base preset OR any of the four
        // pillars
        // PresetApplier writes — native resolver #85, rotation, governors #91, self-heal Solver),
        // respect
        // it — only mark seeded so we never reconsider, but do not overwrite. Checking the FULL
        // pillar set
        // (not just preset+rotation) keeps this "already-configured" test coherent with the
        // everything-ON
        // contract the bundle now arms, so first-run + restore + migration agree on what counts as
        // a
        // user-touched install. (Belt-and-braces for USER-FREEDOM; normally this is a clean first
        // install
        // where none of these keys exist → the seed proceeds and everything-ON lands.)
        val alreadyChosen =
            prefs.contains(TortaeKeys.DNS_ENGINE_PRESET) ||
                prefs.contains(TortaeKeys.RESOLVER_ROTATION_ENABLED) ||
                prefs.contains(TortaeKeys.RESOLVER_NATIVE_ENABLED) ||
                prefs.contains(TortaeKeys.DNS_ENGINE_GOVERN) ||
                prefs.contains(TortaeKeys.DNS_ENGINE_SOLVER)

        val wrote: Boolean =
            if (alreadyChosen) {
                false
            } else {
                // Write the canonical Privacy default bundle (value-only, datapath-safe) via the
                // shared
                // applier — the single source of the "what Privacy sets" truth lives in
                // PresetApplier.
                PresetApplier.applyPreset(context, DEFAULT_PROFILE)
            }

        // Flip the one-time guard regardless, so the seed never runs again for this install.
        // (#21: latched in the Rust app-state record — durable across prefs backup/clear skew.)
        AppStateBridge.setDefaultPresetSeeded(true)

        return wrote
    }

    /**
     * Rotation is ON by default — every install (Socio 2026-06-26). The "rotate for privacy" switch
     * STAYS (user-toggleable), but its DEFAULT is ON; the user never has to flip it for the privacy
     * pillar to run.
     *
     * Why a dedicated ensure (and not just the XML `defaultValue="true"` + the first-run bundle):
     * an UPDATE from a pre-rotation build already has other core keys set (e.g.
     * [TortaeKeys.DNS_ENGINE_PRESET]), so [seedDefaultProfileIfFirstRun]'s `alreadyChosen`
     * guard skips the bundle → [RESOLVER_ROTATION_ENABLED] stays UNSET. An unset key reads
     * default-true via [RotationManager.shouldRotate]'s `getBoolean(…, true)`, but default-FALSE
     * via the dashboard card's generic `getBoolPreference` — so the engine rotates while the card
     * says "off". This materializes the ON default into the store so EVERY reader agrees.
     *
     * Idempotent + USER-FREEDOM-safe: sets the default ONLY when the key is ABSENT, so a user who
     * explicitly turned rotation off is NEVER overridden. Cheap no-op on every run after the key
     * exists. Call on app start (App.onCreate), after [seedDefaultProfileIfFirstRun].
     */
    @JvmStatic
    fun ensureRotationDefaultOn(context: Context) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        if (!prefs.contains(TortaeKeys.RESOLVER_ROTATION_ENABLED)) {
            prefs.edit().putBoolean(TortaeKeys.RESOLVER_ROTATION_ENABLED, true).apply()
        }
    }

    /**
     * The constant all-ON pillar flags materialized into the store — every install (Socio all-ON
     * contract, 2026-06-26). This GENERALIZES [ensureRotationDefaultOn] to the rest of the
     * always-ON pillars, fixing the SAME defect: each pillar's MANAGER + its settings fragment
     * already read `getBoolean(key, TRUE)` (default- ON), but the at-a-glance dashboard CARDS read
     * the generic [PreferenceRepository.getBoolPreference], which is
     * `appPreferences.getBoolean(key, FALSE)` (AppPreferenceHelperImpl:65) — so on an UPDATE
     * install (where [seedDefaultProfileIfFirstRun]'s `alreadyChosen` guard skips the first-run
     * bundle) these keys stay UNSET and the CARD renders "off" while the engine runs ON. Writing
     * the ON default into the store makes EVERY reader agree (the rotation defect, one card at a
     * time, generalized).
     *
     * NO arm / NO datapath change: the managers ALREADY read these default-TRUE, so this only makes
     * the store explicit (exactly as inert as the user opening each pillar's settings, which also
     * default-checks them). Idempotent + USER-FREEDOM-safe: seeds a key ONLY when ABSENT, so a
     * user's explicit OFF is NEVER overridden, and it is a cheap no-op once the keys exist. Call on
     * app start after [ensureRotationDefaultOn].
     */
    @JvmStatic
    fun ensureAlwaysOnPillarDefaults(context: Context) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        // Each key's owning manager/fragment reads it `getBoolean(key, true)`; only the cards'
        // getBoolPreference
        // defaults it false. Seed the ON default so the card agrees with the already-running
        // engine.
        val alwaysOn =
            listOf(
                TortaeKeys
                    .CENTAURI_MIRROR_ENABLED, // local loopback serve-mirror
                                              // (CentauriMirrorManager:203 default-true)
                TortaeKeys
                    .DNSMASQ_NEVER_FORWARD, // dnsmasq never-forward hygiene
                                            // (DnsmasqDashboardFragment:70 default-true)
                TortaeKeys
                    .DNSMASQ_BOGUS_PRIV, // dnsmasq bogus-priv reject (DnsmasqDashboardFragment:76
                                         // default-true)
                TortaeKeys
                    .WARDEN_NATIVE_ENABLED, // the Warden watch (WardenDashboardFragment:50
                                            // default-true, all-ON)
            )
        val editor = prefs.edit()
        var changed = false
        for (key in alwaysOn) {
            if (!prefs.contains(key)) {
                if (key == TortaeKeys.WARDEN_NATIVE_ENABLED) editor.putBoolean(key, false) else editor.putBoolean(key, true)
                changed = true
            }
        }
        if (changed) editor.apply()
    }
}
