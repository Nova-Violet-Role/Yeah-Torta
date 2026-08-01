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

package pillar.kuma_saimono.libumdnscrypt.dialogs

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import androidx.annotation.Nullable
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import javax.inject.Inject

class RequestIgnoreBatteryOptimizationDialog : ExtendedDialogFragment() {

    @Inject
    lateinit var preferenceRepository: dagger.Lazy<PreferenceRepository>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        App.instance.daggerComponent.inject(this)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun assignBuilder(): AlertDialog.Builder? {

        val activity = activity
        if (activity == null || activity.isFinishing) {
            return null
        }

        val builder = AlertDialog.Builder(activity)

        builder.setTitle(uniffi.torta_core.tortaText("notification_exclude_bat_optimisation_title"))
        builder.setMessage(uniffi.torta_core.tortaText("pref_common_notification_helper"))

        builder.setPositiveButton(uniffi.torta_core.tortaText("ok")) { _, _ ->
            context?.let {
                Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
                    try {
                        it.startActivity(this)
                    } catch (e: Exception) {
                        loge("Requesting ignore battery optimization failed", e)
                    }
                }
            }
        }

        builder.setNeutralButton(uniffi.torta_core.tortaText("dont_show")) { _, _ ->
            preferenceRepository.get().setBoolPreference(
                TortaeKeys.DO_NOT_SHOW_IGNORE_BATTERY_OPTIMIZATION_DIALOG, true
            )
        }

        builder.setNegativeButton(uniffi.torta_core.tortaText("ask_later")) { dialog, _ ->
            dialog.cancel()
        }

        return builder
    }

    companion object {
        @JvmStatic
        @JvmOverloads
        @Nullable
        fun getInstance(
            context: Context,
            preferenceRepository: PreferenceRepository,
            forceShow: Boolean = false
        ): DialogFragment? {
            val pref = PreferenceManager.getDefaultSharedPreferences(context)
            val packageName = context.packageName
            val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M
                || pm?.isIgnoringBatteryOptimizations(packageName) == true
                || (preferenceRepository.getBoolPreference(TortaeKeys.DO_NOT_SHOW_IGNORE_BATTERY_OPTIMIZATION_DIALOG)
                        && !pref.getBoolean(TortaeKeys.ALWAYS_SHOW_HELP_MESSAGES, false)
                        && !forceShow)
            ) {
                return null
            }
            return RequestIgnoreBatteryOptimizationDialog()
        }

        const val TAG = "RequestIgnoreBatteryOptimizationDialog"
    }
}
