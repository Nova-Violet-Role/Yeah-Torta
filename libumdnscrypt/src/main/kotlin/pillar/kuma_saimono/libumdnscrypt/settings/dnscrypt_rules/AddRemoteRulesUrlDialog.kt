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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules

import android.content.Context
import android.text.Editable
import android.text.TextWatcher
import android.widget.EditText
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.core.view.setPadding
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.URL_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Utils.dp2pixels
import pillar.kuma_saimono.libumdnscrypt.utils.Utils.getDomainNameFromUrl
import java.util.regex.Pattern

class AddRemoteRulesUrlDialog {

    var callback: OnAddRemoteRulesUrl? = null

    fun createDialog(context: Context) =
        AlertDialog.Builder(context)
            .apply {
                val urlPattern = Pattern.compile(URL_REGEX)
                val editText = EditText(context).apply {
                    setPadding(dp2pixels(8).toInt())
                    addTextChangedListener(object : TextWatcher {
                        override fun beforeTextChanged(
                            s: CharSequence?,
                            start: Int,
                            count: Int,
                            after: Int
                        ) {
                        }

                        override fun onTextChanged(
                            s: CharSequence?,
                            start: Int,
                            before: Int,
                            count: Int
                        ) {
                        }

                        override fun afterTextChanged(s: Editable?) {
                            if (urlPattern.matcher(s?.toString() ?: "").matches()) {
                                setTextColor(ContextCompat.getColor(context, R.color.colorText))
                            } else {
                                setTextColor(ContextCompat.getColor(context, R.color.colorAlert))
                            }
                        }

                    })
                }
                setView(editText)
                setTitle(uniffi.torta_core.tortaText("dns_rule_add_url"))
                setPositiveButton(uniffi.torta_core.tortaText("ok")) { _, _ ->
                    val url = editText.text?.toString() ?: ""
                    if (urlPattern.matcher(url).matches()) {
                        val name = getDomainNameFromUrl(url)
                        callback?.onRemoteRulesUrlAdded(url, name)
                    }
                }
                setNegativeButton(uniffi.torta_core.tortaText("cancel")) { _, _ -> }
            }.create()

    interface OnAddRemoteRulesUrl {
        fun onRemoteRulesUrlAdded(url: String, name: String)
    }
}
