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

package pillar.kuma_saimono.libumdnscrypt.modules

import android.content.Context
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark
import javax.inject.Inject

class ContextUIDUpdater(private val context: Context) {

    @Inject
    lateinit var pathVars: PathVars

    private val appDataDir: String
    private val busyboxPath: String

    init {
        App.instance.daggerComponent.inject(this)
        appDataDir = pathVars.appDataDir
        busyboxPath = pathVars.busyboxPath
    }

    fun updateModulesContextAndUID() {

        val appUID = pathVars.appUidStr
        val commands: List<String> = if (ModulesStatus.getInstance().isUseModulesWithRoot) {
            arrayListOf(
                busyboxPath + "chown -R 0.0 " + appDataDir + "/app_data/dnscrypt-proxy 2> /dev/null",
                busyboxPath + "chown -R 0.0 " + appDataDir + "/dnscrypt-proxy.pid 2> /dev/null",
                busyboxPath + "chown -R 0.0 " + appDataDir + "/tor_data 2> /dev/null",
                busyboxPath + "chown -R 0.0 " + appDataDir + "/tor.pid 2> /dev/null",
                busyboxPath + "chown -R 0.0 " + appDataDir + "/i2pd_data 2> /dev/null",
                busyboxPath + "chown -R 0.0 " + appDataDir + "/i2pd.pid 2> /dev/null"
            )
        } else {
            arrayListOf(
                busyboxPath + "chown -R " + appUID + "." + appUID + " " + appDataDir + "/app_data/dnscrypt-proxy 2> /dev/null",
                busyboxPath + "chown -R " + appUID + "." + appUID + " " + appDataDir + "/dnscrypt-proxy.pid 2> /dev/null",
                "restorecon -R " + appDataDir + "/app_data/dnscrypt-proxy 2> /dev/null",
                "restorecon -R " + appDataDir + "/dnscrypt-proxy.pid 2> /dev/null",

                busyboxPath + "chown -R " + appUID + "." + appUID + " " + appDataDir + "/tor_data 2> /dev/null",
                busyboxPath + "chown -R " + appUID + "." + appUID + " " + appDataDir + "/tor.pid 2> /dev/null",
                "restorecon -R " + appDataDir + "/tor_data 2> /dev/null",
                "restorecon -R " + appDataDir + "/tor.pid 2> /dev/null",

                busyboxPath + "chown -R " + appUID + "." + appUID + " " + appDataDir + "/i2pd_data 2> /dev/null",
                busyboxPath + "chown -R " + appUID + "." + appUID + " " + appDataDir + "/i2pd.pid 2> /dev/null",
                "restorecon -R " + appDataDir + "/i2pd_data 2> /dev/null",
                "restorecon -R " + appDataDir + "/i2pd.pid 2> /dev/null",

                busyboxPath + "chown -R " + appUID + "." + appUID + " " + appDataDir + "/logs 2> /dev/null",
                "restorecon -R " + appDataDir + "/logs 2> /dev/null"
            )
        }

        RootCommands.execute(context, commands, RootCommandsMark.NULL_MARK)
    }
}
