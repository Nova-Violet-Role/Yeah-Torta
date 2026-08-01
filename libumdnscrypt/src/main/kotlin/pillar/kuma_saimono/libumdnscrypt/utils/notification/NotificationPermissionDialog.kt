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

package pillar.kuma_saimono.libumdnscrypt.utils.notification

import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.FragmentManager
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.dialogs.ExtendedDialogFragment

class NotificationPermissionDialog: ExtendedDialogFragment() {

    override fun assignBuilder(): AlertDialog.Builder? {
        if (activity?.isFinishing != false) {
            return null
        }

        val builder = AlertDialog.Builder(requireActivity())
        builder.setMessage(uniffi.torta_core.tortaText("notifications_permission_rationale_message"))
            .setTitle(uniffi.torta_core.tortaText("reset_settings_title"))
            .setPositiveButton(uniffi.torta_core.tortaText("ok")) { _, _ ->
                activity?.supportFragmentManager?.let {
                    getListener(it)?.notificationPermissionDialogOkPressed()
                }
            }
            .setNegativeButton(uniffi.torta_core.tortaText("ask_later")) { _, _ ->
                dismiss()
            }
            .setNeutralButton(uniffi.torta_core.tortaText("dont_show")) { _, _ ->
                activity?.supportFragmentManager?.let {
                    getListener(it)?.notificationPermissionDialogDoNotShowPressed()
                }
            }
        return builder
    }

    private fun getListener(manager: FragmentManager): NotificationPermissionDialogListener ? {
        for (fragment in manager.fragments) {
            if (fragment is NotificationPermissionDialogListener) {
                return fragment
            }
            getListener(fragment.childFragmentManager)
        }
        return null
    }

    interface NotificationPermissionDialogListener {
        fun notificationPermissionDialogOkPressed()
        fun notificationPermissionDialogDoNotShowPressed()
    }
}
