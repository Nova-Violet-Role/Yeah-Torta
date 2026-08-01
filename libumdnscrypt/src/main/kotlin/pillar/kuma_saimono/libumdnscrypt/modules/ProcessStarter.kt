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

import com.jrummyapps.android.shell.CommandResult
import com.jrummyapps.android.shell.ShellExitCode
import java.io.*

class ProcessStarter(private val libraryDir: String) {

    fun startProcess(startCommand: String): CommandResult {

        val stdout = mutableListOf<String>()
        val stderr = mutableListOf<String>()
        var exitCode: Int

        try {

            val env = Array(1) { "LD_LIBRARY_PATH=$libraryDir" }
            val process = Runtime.getRuntime().exec(startCommand, env)

            BufferedReader(InputStreamReader(process.inputStream)).use { bufferedReader ->
                var line = bufferedReader.readLine()
                while (line != null) {
                    stdout.add(line)
                    line = bufferedReader.readLine()
                }
            }

            BufferedReader(InputStreamReader(process.errorStream)).use { bufferedReader ->
                var line = bufferedReader.readLine()
                while (line != null) {
                    stderr.add(line)
                    line = bufferedReader.readLine()
                }
            }

            try {
                OutputStreamWriter(process.outputStream, "UTF-8").use { writer ->
                    writer.write("exit\n")
                    writer.flush()
                }
            } catch (e: IOException) {
                //noinspection StatementWithEmptyBody
                if (e.message?.contains("EPIPE") == true || e.message?.contains("Stream closed") == true) {
                    // Method most horrid to catch broken pipe, in which case we do nothing. The command is not a shell, the
                    // shell closed stdin, the script already contained the exit command, etc. these cases we want the output
                    // instead of returning null
                } else {
                    // other issues we don't know how to handle, leads to returning null
                    throw e
                }
            }

            exitCode = process.waitFor()
            process.destroy()
        } catch (e: InterruptedException) {
            exitCode = ShellExitCode.WATCHDOG_EXIT
        } catch (e: IOException) {
            exitCode = ShellExitCode.SHELL_WRONG_UID
        }

        return CommandResult(stdout, stderr, exitCode)
    }
}
