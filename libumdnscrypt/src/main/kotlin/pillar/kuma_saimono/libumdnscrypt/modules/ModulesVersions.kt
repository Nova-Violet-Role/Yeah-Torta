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
import android.content.Intent
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.jrummyapps.android.shell.Shell
import com.jrummyapps.android.shell.ShellNotFoundException
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.executors.CoroutineExecutor
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootExecService
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ModulesVersions @Inject constructor(
    private val executor: CoroutineExecutor
) {

    private var dnsCryptVersion = ""

    private var console: Shell.Console? = null

    fun refreshVersions(context: Context) {

        executor.submit("ModulesVersions refreshVersions") {
            //openCommandShell()

            val pathVars = App.instance.daggerComponent.getPathVars().get()

            //checkModulesVersions(pathVars)
            checkModulesVersionsModern(context, pathVars)

            if (isBinaryFileAccessible(pathVars.dnsCryptPath) && dnsCryptVersion.isNotEmpty()) {
                sendResult(context, dnsCryptVersion, RootCommandsMark.DNSCRYPT_RUN_FRAGMENT_MARK)
            }

            //closeCommandShell()
        }
    }

    private fun isBinaryFileAccessible(path: String): Boolean {
        val file = File(path)
        return file.isFile && file.canExecute()
    }

    private fun sendResult(context: Context, version: String?, mark: Int) {

        if (version == null) {
            return
        }

        val comResult = RootCommands(arrayListOf(version))
        val intent = Intent(RootExecService.COMMAND_RESULT)
        intent.putExtra("CommandsResult", comResult)
        intent.putExtra("Mark", mark)
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent)
    }

    private fun checkModulesVersions(pathVars: PathVars) {
        val console = this.console
        if (console == null || console.isClosed) {
            return
        }

        dnsCryptVersion = console.run(
            "echo 'DNSCrypt_version'",
            pathVars.dnsCryptPath + " --version"
        ).getStdout()
    }

    private fun checkModulesVersionsModern(context: Context, pathVars: PathVars) {

        val dnsCryptOutput = ProcessStarter(context.applicationInfo.nativeLibraryDir)
            .startProcess(pathVars.dnsCryptPath + " --version").stdout
        if (dnsCryptOutput.isNotEmpty()) {
            dnsCryptVersion = "DNSCrypt_version " + dnsCryptOutput[0]
        }
    }

    private fun openCommandShell() {
        closeCommandShell()

        try {
            console = Shell.SH.getConsole()
        } catch (e: ShellNotFoundException) {
            loge("ModulesStatus: SH shell not found!", e)
        }
    }

    private fun closeCommandShell() {

        val console = this.console
        if (console != null && !console.isClosed) {
            console.run("exit")
            console.close()
        }
        this.console = null
    }
}
