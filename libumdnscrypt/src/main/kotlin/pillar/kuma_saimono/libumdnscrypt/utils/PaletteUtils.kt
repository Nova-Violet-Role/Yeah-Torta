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

package pillar.kuma_saimono.libumdnscrypt.utils

import android.app.Activity
import android.os.Build
import androidx.preference.PreferenceManager
import com.google.android.material.color.DynamicColors
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge

/**
 * Tortä THEME PICKER — the palette-identity applier.
 *
 * GROUND_TRUTH (measured this session):
 *  - The day/night MODE axis is [ThemeUtils.setDayNightTheme] reading `pref_fast_theme`
 *    (1/2/3/4 -> AppCompatDelegate.setDefaultNightMode, ThemeUtils.kt:45-50). That axis is
 *    KEPT untouched — DayNight keeps working.
 *  - This is a SEPARATE palette-identity axis, pref [PALETTE_PREF] = `pref_fast_palette`,
 *    applied as a ThemeOverlay onto the M2 base theme (values/styles.xml:6) at Activity
 *    onCreate, BEFORE super.onCreate / setContentView, so the chrome (app-bar / accents /
 *    dialogs / ?attr-driven M2 widgets) re-skins per identity.
 *  - Beast-gold ([PALETTE_DEFAULT] = "0") is the DEFAULT identity: a no-op overlay shell that
 *    keeps the base BeastGold/void attrs (DESIGN_FINALE.md:60 "Beast-gold stays DEFAULT").
 *  - Material You ([PALETTE_MATERIAL_YOU] = "5") is the API-31+ opt-in (DESIGN_FINALE.md:58-61):
 *    DynamicColors.applyToActivitiesIfAvailable is global, so here we apply per-Activity via
 *    [DynamicColors.applyToActivityIfAvailable] only when selected AND available — never the
 *    default, the brand is never surrendered to the wallpaper.
 *
 * FAITHFUL+MINIMAL: an overlay can only override THEME ATTRIBUTES, so this re-skins the
 * attribute-driven chrome; layouts that reference `@color/torta_*` / `@color/cake*` directly
 * resolve at resource level and are not retinted here (full per-dashboard propagation is the
 * deeper own-build). Never crashes — every path is guarded and degrades to the base theme.
 */
object PaletteUtils {

    const val PALETTE_PREF = "pref_fast_palette"

    // Values mirror res/values/array.xml `pref_fast_palette_values`.
    const val PALETTE_DEFAULT = "0"        // Beast-gold (default, no-op overlay)
    private const val PALETTE_BEAST_DARK = "1"
    private const val PALETTE_WARM_LIGHT = "2"
    private const val PALETTE_CENTAURI = "3"
    private const val PALETTE_CAKE = "4"
    private const val PALETTE_MATERIAL_YOU = "5"

    /**
     * Apply the selected palette identity to [activity]. Call as the FIRST line of onCreate,
     * after [ThemeUtils.setDayNightTheme] and BEFORE super.onCreate().
     */
    @JvmStatic
    fun applyPalette(activity: Activity) {
        try {
            val palette = PreferenceManager.getDefaultSharedPreferences(activity)
                .getString(PALETTE_PREF, PALETTE_DEFAULT) ?: PALETTE_DEFAULT

            when (palette) {
                PALETTE_MATERIAL_YOU -> {
                    // Dynamic color is API-31+; below that, fall back to the brand default
                    // (no overlay) so it never washes out to a generic look.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        DynamicColors.applyToActivityIfAvailable(activity)
                    } else {
                        applyOverlay(activity, R.style.ThemeOverlay_Torta_BeastGold)
                    }
                }
                PALETTE_BEAST_DARK -> applyOverlay(activity, R.style.ThemeOverlay_Torta_BeastDark)
                PALETTE_WARM_LIGHT -> applyOverlay(activity, R.style.ThemeOverlay_Torta_WarmLight)
                PALETTE_CENTAURI -> applyOverlay(activity, R.style.ThemeOverlay_Torta_Centauri)
                PALETTE_CAKE -> applyOverlay(activity, R.style.ThemeOverlay_Torta_Cake)
                else -> applyOverlay(activity, R.style.ThemeOverlay_Torta_BeastGold)
            }
        } catch (e: Exception) {
            loge("PaletteUtils applyPalette", e)
        }
    }

    private fun applyOverlay(activity: Activity, styleRes: Int) {
        // force=true so the overlay wins over the base theme attrs it redefines.
        activity.theme.applyStyle(styleRes, true)
    }

    /**
     * Service-safe palette accent resolver — maps the stored [PALETTE_PREF] id to its
     * DayNight-aware accent COLOR resource, mirroring the id->overlay map in [applyPalette]
     * (single source of truth for the palette id table).
     *
     * Unlike [applyPalette] (which needs an Activity theme to host the overlay), this returns
     * a plain color resource id, so a Service (FGS notification, ARP/kill-switch alerts) can
     * track the active palette WITHOUT an Activity-scoped overlay. DayNight resolves
     * automatically through values/ vs values-night/ peers.
     *
     * Beast-gold ("0", the no-op default) and Material You ("5", whose dynamic wallpaper accent
     * is not reachable outside an Activity) both resolve to the base brand gold
     * [R.color.torta_primary] — the faithful base identity.
     *
     * @param prefValue the raw [PALETTE_PREF] string ("0".."5"); null -> default.
     * @return a `@ColorRes` id (never throws; callers wrap [androidx.core.content.ContextCompat.getColor]).
     */
    @JvmStatic
    fun paletteAccentColorRes(prefValue: String?): Int = when (prefValue) {
        PALETTE_BEAST_DARK -> R.color.palette_torta_beastdark_accent
        PALETTE_WARM_LIGHT -> R.color.palette_torta_warmlight_accent
        PALETTE_CENTAURI -> R.color.palette_torta_centauri_accent
        PALETTE_CAKE -> R.color.palette_torta_cake_accent
        // "0" (Beast-gold no-op default), "5" (Material You — dynamic accent unreachable in a
        // Service), or null -> the DayNight base brand gold.
        else -> R.color.torta_primary
    }
}
