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

import android.content.Context
import android.content.IntentFilter
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark.Companion.IPTABLES_MARK
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootExecService.Companion.COMMAND_RESULT

abstract class IptablesRulesSender(
    protected var context: Context,
    protected var pathVars: PathVars
) : IptablesRules {

    protected var appDataDir: String = pathVars.appDataDir
    protected var rejectAddress: String = pathVars.getRejectAddress()

    protected var runModulesWithRoot = false
    protected var tethering: Tethering = Tethering(context)
    protected var receiver: IptablesReceiver? = null
    protected var routeAllThroughTor = false
    protected var blockHttp = false
    protected var preventDnsLeaks = false
    protected var apIsOn = false
    protected var modemIsOn = false
    protected var lan = false

    init {
        registerReceiver()
    }

    private fun registerReceiver() {

        if (receiverIsRegistered) {
            return
        }

        receiverIsRegistered = true

        receiver = IptablesReceiver()

        val intentFilterBckgIntSer = IntentFilter(COMMAND_RESULT)
        LocalBroadcastManager.getInstance(context).registerReceiver(receiver!!, intentFilterBckgIntSer)
    }

    override fun unregisterReceiver() {
        if (receiver != null && receiverIsRegistered) {
            receiverIsRegistered = false
            try {
                LocalBroadcastManager.getInstance(context).unregisterReceiver(receiver!!)
            } catch (ignored: Exception) {
            }
        }
    }


    override fun isLastIptablesCommandsReturnError(): Boolean {
        return if (receiver == null) {
            false
        } else {
            receiver!!.lastIptablesCommandsReturnError
        }
    }

    override fun sendToRootExecService(commands: List<String>) {
        RootCommands.execute(context, commands, IPTABLES_MARK)
    }

    companion object {
        private var receiverIsRegistered = false
    }
}
