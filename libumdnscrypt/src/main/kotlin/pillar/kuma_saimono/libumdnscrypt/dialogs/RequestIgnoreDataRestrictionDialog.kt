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
import android.net.ConnectivityManager
import android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_DISABLED
import android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED
import android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
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

class RequestIgnoreDataRestrictionDialog : ExtendedDialogFragment() {

    @Inject
    lateinit var preferenceRepository: dagger.Lazy<PreferenceRepository>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        App.instance.daggerComponent.inject(this)
    }

    @RequiresApi(Build.VERSION_CODES.N)
    override fun assignBuilder(): AlertDialog.Builder? {

        val activity = activity
        if (activity == null || activity.isFinishing) {
            return null
        }

        val builder = AlertDialog.Builder(activity)

        builder.setTitle(uniffi.torta_core.tortaText("notification_exclude_data_restriction_title"))
        builder.setMessage(uniffi.torta_core.tortaText("notification_exclude_data_restriction_message"))

        builder.setPositiveButton(uniffi.torta_core.tortaText("ok")) { _, _ ->
            context?.let {
                Intent(
                    Settings.ACTION_IGNORE_BACKGROUND_DATA_RESTRICTIONS_SETTINGS,
                    Uri.parse("package:${it.packageName}")
                ).apply {
                    try {
                        it.startActivity(this)
                    } catch (e: Exception) {
                        loge("RequestIgnoreDataRestrictionDialog", e)
                    }
                }
            }
        }

        builder.setNeutralButton(uniffi.torta_core.tortaText("dont_show")) { _, _ ->
            preferenceRepository.get().setBoolPreference(
                TortaeKeys.DO_NOT_SHOW_REQUEST_DATA_RESTRICTION_DIALOG, true
            )
        }

        builder.setNegativeButton(uniffi.torta_core.tortaText("ask_later")) { dialog, _ ->
            dialog.cancel()
        }

        return builder
    }

    companion object {
        @JvmStatic
        fun getInstance(
            context: Context,
            preferenceRepository: PreferenceRepository
        ): DialogFragment? {
            val preferences = PreferenceManager.getDefaultSharedPreferences(context)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
                && (!preferenceRepository.getBoolPreference(TortaeKeys.DO_NOT_SHOW_REQUEST_DATA_RESTRICTION_DIALOG)
                        || preferences.getBoolean(TortaeKeys.ALWAYS_SHOW_HELP_MESSAGES, false))
            ) {
                (context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).apply {
                    when (restrictBackgroundStatus) {
                        RESTRICT_BACKGROUND_STATUS_ENABLED -> {
                            return RequestIgnoreDataRestrictionDialog()
                        }

                        RESTRICT_BACKGROUND_STATUS_WHITELISTED -> {
                            return null
                        }

                        RESTRICT_BACKGROUND_STATUS_DISABLED -> {
                            return null
                        }
                    }
                }
            }

            return null
        }

        const val TAG = "RequestIgnoreDataRestrictionDialog"
    }
}
