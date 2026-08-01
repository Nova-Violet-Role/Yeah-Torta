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

import android.content.Context
import android.content.res.Configuration
import android.os.Build
import androidx.appcompat.app.AppCompatDelegate
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.assistance.AccelerateDevelop
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.lang.Exception

object ThemeUtils {

    /**
     * `AppCompatDelegate.MODE_NIGHT_AUTO_TIME`, routed through ONE named alias.
     *
     * MEASURED from `appcompat-1.7.1.aar` -> `classes.jar` -> `AppCompatDelegate.class` with
     * `javap -v`, not recalled:
     *
     * ```text
     *   MODE_NIGHT_AUTO_TIME     = 0   Deprecated: true
     *   MODE_NIGHT_AUTO          = 0   Deprecated: true    <- only same-value alias, also gone
     *   MODE_NIGHT_AUTO_BATTERY  = 3   (not deprecated)
     *   MODE_NIGHT_FOLLOW_SYSTEM = -1  (not deprecated)
     * ```
     *
     * So there is NO equivalent replacement: every non-deprecated mode carries a DIFFERENT value
     * and therefore different behaviour. Swapping in `MODE_NIGHT_AUTO_BATTERY` would silently
     * convert a user's time-of-day choice into a battery-saver choice -- a behaviour change
     * dressed as a deprecation fix. It stays, and it stays declared rather than hidden.
     *
     * What DID change: the suppression used to sit on the whole of [setDayNightTheme], so every
     * other line of that function was unmeasurable. Routing the constant through a single alias --
     * the `LEGACY_*` convention this codebase already uses in ModulesReceiver -- narrows the
     * suppression to the one declaration that needs it and leaves the function itself measured.
     */
    @Suppress("DEPRECATION")
    private val LEGACY_MODE_NIGHT_AUTO_TIME: Int = AppCompatDelegate.MODE_NIGHT_AUTO_TIME

    @JvmStatic
    fun setDayNightTheme(context: Context, pathVars: PathVars) {
        try {
            val theme = if (pathVars.appVersion.startsWith("g") && !AccelerateDevelop.accelerated) {
                "1"
            } else {
                val defaultSharedPreferences =
                    PreferenceManager.getDefaultSharedPreferences(context)
                defaultSharedPreferences.getString("pref_fast_theme", "4") ?: "4"
            }
            when (theme) {
                "1" -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO)
                "2" -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
                "3" -> AppCompatDelegate.setDefaultNightMode(LEGACY_MODE_NIGHT_AUTO_TIME)
                "4" -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
            }
        } catch (e: Exception) {
            loge("ThemeUtils setDayNightTheme", e)
        }
    }

    fun isNightMode(context: Context) =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.resources.configuration.isNightModeActive
        } else {
            context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        }
}
