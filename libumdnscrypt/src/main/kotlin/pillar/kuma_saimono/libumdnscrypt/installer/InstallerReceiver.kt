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

package pillar.kuma_saimono.libumdnscrypt.installer

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootExecService
import pillar.kuma_saimono.libumdnscrypt.utils.serializableExtraCompat

class InstallerReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent != null) {

            if (isBroadcastMatch(intent)) {
                logi("InstallerReceiver onReceive")
            } else {
                return
            }

            @Suppress("DEPRECATION")
            val comResult = intent.serializableExtraCompat<RootCommands>("CommandsResult")

            if (comResult == null || isRootCommandResultEmpty(comResult)) {
                return
            }

            val rootCommandsResult = getResultString(comResult)

            doAppropriateAction(rootCommandsResult)
        }
    }

    private fun doAppropriateAction(rootCommandsResult: String) {
        if (rootCommandsResult.replace("\\W+".toRegex(), "") == "checkModulesRunning") {
            Installer.continueInstallation(false)

            logi("InstallerReceiver receive $rootCommandsResult continueInstallation")
        } else {
            Installer.continueInstallation(true)

            logi("InstallerReceiver receive \"$rootCommandsResult\" interruptInstallation")
        }
    }

    private fun getResultString(comResult: RootCommands): String {
        val sb = StringBuilder()
        for (com in comResult.commands) {
            sb.append(com)
        }
        return sb.toString()
    }

    private fun isRootCommandResultEmpty(comResult: RootCommands): Boolean {
        return comResult.commands.size == 0
    }

    private fun isBroadcastMatch(intent: Intent?): Boolean {
        if (intent == null) {
            return false
        }

        val action = intent.action

        if (action == null || action == "") {
            return false
        }

        if (action != RootExecService.COMMAND_RESULT) {
            return false
        }

        return intent.getIntExtra("Mark", 0) == RootCommandsMark.INSTALLER_MARK
    }
}
