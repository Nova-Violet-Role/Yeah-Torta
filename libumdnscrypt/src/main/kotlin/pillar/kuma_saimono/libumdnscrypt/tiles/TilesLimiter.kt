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

package pillar.kuma_saimono.libumdnscrypt.tiles

import android.app.Dialog
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.view.ContextThemeWrapper
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.assistance.AccelerateDevelop
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.di.tiles.TilesScope
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.ThemeUtils
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ALWAYS_SHOW_HELP_MESSAGES
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.TILES_LIMIT_DIALOG_NOT_SHOW
import java.lang.Exception
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Named

private const val TILES_SAFE_COUNT = 3

@RequiresApi(Build.VERSION_CODES.N)
@TilesScope
class TilesLimiter @Inject constructor(
    private val appPreferences: dagger.Lazy<PreferenceRepository>,
    @Named(DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: dagger.Lazy<SharedPreferences>,
    private val pathVars: dagger.Lazy<PathVars>
) {

    private val currentTilesSet by lazy {
        Collections.newSetFromMap(ConcurrentHashMap<Class<TileService>, Boolean>())
    }

    private val isModulesNotInstalled by lazy {
        !PathVars.isModulesInstalled(appPreferences.get())
    }

    fun <T : TileService> listenTile(service: T) {
        currentTilesSet.add(service.javaClass)
        activeTilesSet.add(service.javaClass)
    }

    fun <T : TileService> unlistenTile(service: T) {
        currentTilesSet.remove(service.javaClass)

        if (currentTilesSet.isEmpty()) {
            BaseTileService.releaseTilesSubcomponent()
        }
    }

    fun checkActiveTilesCount(service: TileService) {

        applyAppTheme(service)

        if (checkModulesNotInstalled(service)) {
            return
        }

        if (activeTilesSet.size > TILES_SAFE_COUNT) {
            val doNotShow = appPreferences.get()
                .getBoolPreference(TILES_LIMIT_DIALOG_NOT_SHOW)

            val showHelperMessages = defaultPreferences.get()
                .getBoolean(ALWAYS_SHOW_HELP_MESSAGES, false)

            if (!service.isSecure && (!doNotShow || showHelperMessages)) {
                showDialog(service, getWarningDialog(service))
            }
        } else {
            if (pathVars.get().appVersion.endsWith("p") && !AccelerateDevelop.accelerated) {
                showDialog(service, getDonateDialogForGp(service))
            }
        }
    }

    private fun applyAppTheme(service: TileService) {
        if (!themeApplied) {
            try {
                ThemeUtils.setDayNightTheme(service, pathVars.get())
                themeApplied = true
            } catch (e: Exception) {
                loge("TilesLimiter applyAppTheme", e)
            }
        }
    }

    private fun checkModulesNotInstalled(service: TileService): Boolean {
        if (isModulesNotInstalled) {
            tryStartMainActivity(service)
        }
        return isModulesNotInstalled
    }

    fun reset() {
        activeTilesSet.clear()
    }

    private fun getWarningDialog(context: Context): Dialog =
        AlertDialog.Builder(ContextThemeWrapper(context, R.style.Theme_AppTheme_Dialog_Alert_Contrast))
            .apply {
                setTitle(R.string.main_activity_label)
                setMessage(uniffi.torta_core.tortaText("tile_dialog_over_three_tiles_message"))
                setPositiveButton(uniffi.torta_core.tortaText("ok")) { _, _ -> }
                setNegativeButton(uniffi.torta_core.tortaText("dont_show")) { _, _ ->
                    appPreferences.get().setBoolPreference(TILES_LIMIT_DIALOG_NOT_SHOW, true)
                }
            }.create()

    private fun showDialog(service: TileService, dialog: Dialog) {
        try {
            service.showDialog(dialog)
        } catch (e: Exception) {
            loge("TilesLimiter show dialog", e)
        }
    }

    private fun getDonateDialogForLite(context: Context): Dialog =
        AlertDialog.Builder(ContextThemeWrapper(context, R.style.Theme_AppTheme_Dialog_Alert_Contrast))
            .apply {
                setTitle(uniffi.torta_core.tortaText("donate"))
                setMessage(uniffi.torta_core.tortaText("donate_project"))
                setPositiveButton(uniffi.torta_core.tortaText("ok")) { _, _ ->
                    tryStartMainActivity(context)
                }
                setNegativeButton(uniffi.torta_core.tortaText("cancel")) { _, _ -> }
            }.create()

    private fun getDonateDialogForGp(context: Context): Dialog =
        AlertDialog.Builder(ContextThemeWrapper(context, R.style.Theme_AppTheme_Dialog_Alert_Contrast))
            .apply {
                setTitle(uniffi.torta_core.tortaText("premium"))
                setMessage(uniffi.torta_core.tortaText("buy_premium_gp"))
                setPositiveButton(uniffi.torta_core.tortaText("ok")) { _, _ ->
                    tryStartMainActivity(context)
                }
                setNegativeButton(uniffi.torta_core.tortaText("cancel")) { _, _ -> }
            }.create()

    private fun tryStartMainActivity(context: Context) {
        try {
            Intent(context, TortaSlintActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
                context.startActivity(this)
            }
        } catch (e: Exception) {
            loge("TilesLimiter show activity", e)
        }
    }

    companion object {

        private var themeApplied = false

        private val activeTilesSet by lazy {
            Collections.newSetFromMap(ConcurrentHashMap<Class<TileService>, Boolean>())
        }

        fun resetActiveTiles() {
            activeTilesSet.clear()
        }
    }

}
