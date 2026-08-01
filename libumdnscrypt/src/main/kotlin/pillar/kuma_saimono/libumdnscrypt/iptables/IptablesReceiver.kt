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

package pillar.kuma_saimono.libumdnscrypt.iptables

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.widget.Toast
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ALWAYS_SHOW_HELP_MESSAGES
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.REFRESH_RULES
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.WAIT_IPTABLES
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark.Companion.IPTABLES_MARK
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootExecService.Companion.COMMAND_RESULT
import java.util.*
import javax.inject.Inject
import pillar.kuma_saimono.libumdnscrypt.utils.serializableExtraCompat

class IptablesReceiver : BroadcastReceiver() {

    @Inject
    lateinit var handler: dagger.Lazy<Handler>

    var lastIptablesCommandsReturnError = false
    private var savedError = ""

    override fun onReceive(context: Context?, intent: Intent?) {
        App.instance.daggerComponent.inject(this)

        if (context == null || intent == null) {
            return
        }

        val action = intent.action

        if (action == null || action.isBlank() || action != COMMAND_RESULT
                || intent.getIntExtra("Mark", 0) != IPTABLES_MARK) {
            return
        }

        logi("IptablesReceiver onReceive")

        val comResult = intent.serializableExtraCompat<RootCommands>("CommandsResult")

        val result = StringBuilder()
        if (comResult != null) {
            for (com in comResult.commands) {
                logi(com)
                result.append(com).append("\n")
            }
        }

        if (result.isBlank()) {
            lastIptablesCommandsReturnError = false
            return
        }

        val resultStr = result.toString().lowercase(Locale.ROOT)

        lastIptablesCommandsReturnError = true

        //Prevent cyclic iptables update
        val removedDigits = resultStr.replace(Regex("\\d+"), "*")
        if (removedDigits == savedError) {
            return
        }

        savedError = removedDigits

        handler.get().let {

            val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
            val showToastWithCommandsResultError = sharedPreferences.getBoolean(ALWAYS_SHOW_HELP_MESSAGES, false)
            val refreshRules = sharedPreferences.getBoolean(REFRESH_RULES, false)

            if (resultStr.contains("unknown option \"-w\"")) {
                sharedPreferences.edit().putBoolean(WAIT_IPTABLES, false).apply()
                it.postDelayed({ ModulesStatus.getInstance().setIptablesRulesUpdateRequested(context, true) }, 1000)
            } else if (refreshRules
                && (resultStr.contains(" -w ")
                || resultStr.contains("Exit code=4")
                || resultStr.contains("try again")) ||
                resultStr.matches(Regex(".*tun\\d+.*"))) {
                it.postDelayed({ ModulesStatus.getInstance().setIptablesRulesUpdateRequested(context, true) }, 5000)
            }
            if (showToastWithCommandsResultError) {
                it.post { Toast.makeText(context, result.toString().trim(), Toast.LENGTH_LONG).show() }
            }
        }
    }
}
