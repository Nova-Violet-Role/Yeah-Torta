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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.keepalive

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge

/**
 * Pillar 13 A-bis — the keep-alive battery layer (Socio 2026-06-20).
 *
 * Pure, stateless helper for the NON-BLOCKING "Run reliably in background" flow:
 *   1. [isIgnoringBatteryOptimizations] — detect the current OS allowlist state.
 *   2. [requestIgnoreBatteryOptimizations] — fire the direct OS allowlist prompt
 *      (ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, gated by the manifest permission of the
 *      same name) and, if that fails, fall back to the permission-free deep-link
 *      ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS list screen.
 *
 * This helper is GUIDE-not-gate: it only detects + launches an OS surface. The dismiss /
 * remind-me-later persistence lives in [BatteryKeepAliveCardView] (the card surface). It NEVER
 * touches the service, datapath, or any privacy/leak surface — it merely asks Android to stop
 * killing the running shield.
 */
object BatteryOptimizationHelper {

    /**
     * True if the system is already exempting this package from Doze/battery-optimization
     * (or if we are below API 23 where the concept does not exist → treat as "already fine",
     * so the card never shows). Fail-safe: any unexpected error → true (suppress the card
     * rather than nag).
     */
    @JvmStatic
    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return true
        }
        return try {
            val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            pm?.isIgnoringBatteryOptimizations(context.packageName) ?: true
        } catch (e: Exception) {
            loge("BatteryOptimizationHelper isIgnoringBatteryOptimizations", e)
            true
        }
    }

    /**
     * Launch the OS battery-optimization surface. Prefers the direct allowlist prompt
     * (one tap to exempt), degrading to the settings-list deep-link, degrading to the app's
     * own details page. Returns true if any surface was launched.
     *
     * NON-BLOCKING by construction: this only starts an external Activity; the caller's screen
     * stays fully usable. Never throws.
     */
    @SuppressLint("BatteryLife")
    @JvmStatic
    fun requestIgnoreBatteryOptimizations(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return false
        }

        // 1) Direct allowlist prompt (needs REQUEST_IGNORE_BATTERY_OPTIMIZATIONS in the manifest;
        //    declared for the GitHub Universal APK — not a Play build).
        try {
            val direct = Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:${context.packageName}")
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(direct)
            return true
        } catch (e: Exception) {
            loge("BatteryOptimizationHelper direct request failed, falling back to settings list", e)
        }

        // 2) Permission-free deep-link to the full battery-optimization list.
        try {
            val list = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(list)
            return true
        } catch (e: Exception) {
            loge("BatteryOptimizationHelper settings-list fallback failed, falling back to app details", e)
        }

        // 3) Last resort: this app's own details page (every OEM has a battery section there).
        try {
            val details = Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:${context.packageName}")
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(details)
            return true
        } catch (e: Exception) {
            loge("BatteryOptimizationHelper app-details fallback failed", e)
        }

        return false
    }
}
