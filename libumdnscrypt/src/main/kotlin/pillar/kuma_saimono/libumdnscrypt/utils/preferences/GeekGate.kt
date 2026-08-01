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

package pillar.kuma_saimono.libumdnscrypt.utils.preferences

import android.content.Context
import androidx.preference.Preference
import androidx.preference.PreferenceGroup
import androidx.preference.PreferenceManager

/**
 * 🤓 The GLOBAL geek-master gate — depth-tiering on one switch.
 *
 * Tortä ships simple-by-default: a noob sees only the friendly switches. The Expert / Nerd surfaces
 * (raw dials, cadence/policy, GOVERN/SOLVER knobs, standalone, Fortress, Centauri, wireless-debug
 * expert) stay hidden until the user flips ONE master — [TortaeKeys.DNS_ENGINE_EXPERT]
 * (`pref_engine_expert`). This is the single, faithful global gate: the key already exists and the
 * PreferenceKeys comments at :173/:185/:201-202/:232 already declare it the shared Expert gate that
 * the engine/solver/rotation/wireless-debug consumers ride. We reuse it rather than coin a new
 * `pref_geek_mode`, so there is exactly one source of truth.
 *
 * Reveal mechanic = androidx [Preference.setVisible] (NOT `removePreference`): visibility is
 * reversible, so toggling the master back ON re-shows every gated row instantly without re-inflating
 * the screen. The friendly/enhancer rows are NEVER passed here — they stay always-visible. This is
 * purely a UI depth-gate: it changes no key value, no default, and nothing in the DNS datapath
 * (privacy-first). USER-FREEDOM holds — gating only hides advanced *rows from a noob*; every function
 * stays individually toggleable once the geek reveals it.
 *
 * Single-source so the new one-root settings fragment (and any future PreferenceFragment) gate depth
 * identically. EngineSettingsFragment keeps its own hand-coded section swap — that screen pre-dates
 * this helper and is left untouched (FAITHFUL+MINIMAL).
 */
object GeekGate {

    /** The global Expert/Geek master key. Reusing the existing, already-shared Expert gate. */
    const val MASTER_KEY: String = TortaeKeys.DNS_ENGINE_EXPERT

    /** Default OFF — simple-by-default; the noob never has to touch a thing. */
    const val DEFAULT_EXPERT: Boolean = false

    /** True when the global Geek / Expert mode is on (advanced surfaces should be revealed). */
    @JvmStatic
    fun isExpert(context: Context): Boolean =
        PreferenceManager.getDefaultSharedPreferences(context)
            .getBoolean(MASTER_KEY, DEFAULT_EXPERT)

    /** The deeper NERD master key (the raw-dials tier). NERD implies GEEK. */
    const val NERD_KEY: String = TortaeKeys.DNS_ENGINE_NERD

    /** Default OFF — the raw dials stay hidden until the user opts into the deeper tier. */
    const val DEFAULT_NERD: Boolean = false

    /**
     * True when the deeper NERD tier (raw dials) should be revealed: the NERD master is on AND the GEEK
     * master is on. NERD structurally implies GEEK — the dials can never reveal without the geek gate.
     */
    @JvmStatic
    fun isNerd(context: Context): Boolean =
        isExpert(context) &&
            PreferenceManager.getDefaultSharedPreferences(context)
                .getBoolean(NERD_KEY, DEFAULT_NERD)

    /**
     * Reveal or hide a set of advanced [Preference]s / [PreferenceGroup]s according to the live
     * master state. Pass any preference (a whole [androidx.preference.PreferenceCategory] or a single
     * row) that should live behind the geek gate; null entries are skipped (so callers can splat
     * `findPreference(...)` results without null-guarding each one).
     *
     * Hiding a [PreferenceGroup] hides its whole subtree, so callers normally pass the advanced
     * categories. Friendly/enhancer rows must NOT be passed in — only the geek-only surfaces.
     */
    @JvmStatic
    fun applyVisibility(context: Context, vararg advanced: Preference?) {
        val expert = isExpert(context)
        for (pref in advanced) {
            pref?.isVisible = expert
        }
    }

    /**
     * Bind the master [SwitchPreference] (the "Expert / Geek mode" row) so flipping it immediately
     * re-runs [refresh] — which the caller wires to re-apply visibility on its advanced groups. The
     * change listener returns true so the new value is persisted normally; an optional caller-supplied
     * listener is chained after the refresh for any extra side effects.
     *
     * @param master the master switch row (typically `findPreference(MASTER_KEY)`); no-op if null.
     * @param refresh re-apply your [applyVisibility] call against the just-flipped master value.
     */
    @JvmStatic
    @JvmOverloads
    fun bindMaster(
        master: Preference?,
        refresh: (Boolean) -> Unit,
        also: Preference.OnPreferenceChangeListener? = null,
    ) {
        master ?: return
        master.onPreferenceChangeListener =
            Preference.OnPreferenceChangeListener { pref, newValue ->
                val on = newValue as? Boolean ?: false
                refresh(on)
                also?.onPreferenceChange(pref, newValue) ?: true
            }
    }
}
