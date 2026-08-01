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

package pillar.kuma_saimono.libumdnscrypt.arp

import com.jrummyapps.android.shell.Shell
import com.jrummyapps.android.shell.ShellNotFoundException
import pillar.kuma_saimono.libumdnscrypt.di.arp.ArpScope
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import java.lang.Exception
import javax.inject.Inject

@ArpScope
class CommandExecutor @Inject constructor() {

    private var console: Shell.Console? = null

    fun execNormal(command: String): MutableList<String> {
        val result = mutableListOf<String>()
        var process: Process? = null
        try {
            process = Runtime.getRuntime().exec(command)

            process.inputStream.bufferedReader().use {
                result.addAll(it.readLines())
            }
            process.errorStream.bufferedReader().use {
                it.forEachLine { line ->
                    loge("ArpScanner execCommand $command error $line")
                }
            }
            val exitCode = process.waitFor()

            if (exitCode != 0) {
                logw("ArpScanner result exitCode:$exitCode command:$command")
            }

        } catch (e: Exception) {
            loge("ArpScanner execCommand $command", e)
        } finally {
            process?.destroy()
        }
        return result
    }


    fun execRoot(command: String): MutableList<String> {
        val result = mutableListOf<String>()

        console ?: openCommandShell()

        val console = console ?: return result


        if (console.isClosed) {
            return result
        }

        try {
            result.addAll(console.run(command).getStdout().split("\n"))
        } catch (e: Exception) {
            loge("Arp command executor: SU exec failed", e)
        }

        return result
    }

    private fun openCommandShell() {
        closeRootCommandShell()
        try {
            console = Shell.SU.getConsole()
        } catch (e: ShellNotFoundException) {
            loge("Arp command executor: SU not found!", e)
        }
    }

    fun closeRootCommandShell() {
        console?.let { console ->
            if (!console.isClosed) {
                console.run("exit")
                console.close()
            }
        }
        console = null
    }
}
