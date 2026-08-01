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

import android.os.Bundle
import androidx.appcompat.app.AlertDialog
import androidx.core.os.bundleOf
import kotlinx.coroutines.ExperimentalCoroutinesApi
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.utils.mode.AppModeManager
import pillar.kuma_saimono.libumdnscrypt.utils.mode.AppModeManagerCallback
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import javax.inject.Inject
import pillar.kuma_saimono.libumdnscrypt.utils.serializableCompat

private const val OPERATION_MODE_ARG = "pillar.kuma_saimono.libumdnscrypt.dialogs.ChangeModeDialog"

@ExperimentalCoroutinesApi
class ChangeModeDialog: ExtendedDialogFragment() {

    @Inject
    lateinit var appModeManager: AppModeManager

    override fun onCreate(savedInstanceState: Bundle?) {
        App.instance.subcomponentsManager.modulesServiceSubcomponent().inject(this)
        super.onCreate(savedInstanceState)
    }

    override fun assignBuilder(): AlertDialog.Builder? {

        val activity = activity
        if (activity == null || activity.isFinishing) {
            return null
        }

        val builder = AlertDialog.Builder(activity)

        // Typed, version-gated read (see utils/IntentExtras.kt). The old `get(...) as OperationMode`
        // was an untyped fetch plus an unchecked cast: a wrong-typed argument threw
        // ClassCastException here rather than naming the argument that was actually wrong.
        // `?: return null` keeps the dialog absent instead of crashing when the argument is
        // missing -- the same outcome the two guards above this line already choose.
        val mode = arguments?.serializableCompat<OperationMode>(OPERATION_MODE_ARG) ?: return null

        builder.setTitle(mode.name)
        builder.setMessage(uniffi.torta_core.tortaText("ask_save_changes"))

        builder.setPositiveButton(uniffi.torta_core.tortaText("ok")) { _, _ ->

            val appModeManagerCallback = activity as? AppModeManagerCallback
            appModeManagerCallback ?: return@setPositiveButton

            when (mode) {
                OperationMode.ROOT_MODE -> appModeManager.switchToRootMode(appModeManagerCallback)
                OperationMode.PROXY_MODE -> appModeManager.switchToProxyMode(appModeManagerCallback)
                OperationMode.VPN_MODE -> appModeManager.switchToVPNMode(appModeManagerCallback)
                else -> loge("ChangeModeDialog unknown mode!")
            }

        }

        builder.setNegativeButton(uniffi.torta_core.tortaText("cancel")) { dialog, _ ->
            dialog.cancel()
        }

        return builder
    }

    companion object INSTANCE {
        @JvmStatic
        fun getInstance(mode: OperationMode) = ChangeModeDialog().apply {
            arguments = bundleOf(OPERATION_MODE_ARG to mode)
        }
    }
}
