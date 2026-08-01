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

import android.annotation.SuppressLint
import java.io.File

object ChmodCommand {

    @SuppressLint("SetWorldReadable")
    @JvmStatic
    fun dirChmod(path: String, executableDir: Boolean) {
        val dir = File(path)

        if (!dir.isDirectory) {
            throw IllegalStateException("dirChmod dir not exist or not dir $path")
        }

        if (!dir.setReadable(true, false)
            || !dir.setWritable(true)
            || !dir.setExecutable(true, false)
        ) {
            throw IllegalStateException("DirChmod chmod dir fault $path")
        }

        val files = dir.listFiles() ?: return

        for (file in files) {

            if (file.isDirectory) {

                dirChmod(file.absolutePath, executableDir)

            } else if (file.isFile) {

                if (executableDir) {
                    executableFileChmod(file.absolutePath)
                } else {
                    regularFileChmod(file.absolutePath)
                }
            }

        }


    }

    @SuppressLint("SetWorldReadable")
    private fun executableFileChmod(path: String) {
        val executable = File(path)

        if (!executable.isFile) {
            throw IllegalStateException("executableFileChmod file not exist or not file $path")
        }

        if (!executable.setReadable(true, false)
            || !executable.setWritable(true)
            || !executable.setExecutable(true, false)
        ) {
            throw IllegalStateException("executableFileChmod chmod file fault $path")
        }
    }

    @SuppressLint("SetWorldReadable")
    private fun regularFileChmod(path: String) {
        val file = File(path)

        if (!file.isFile) {
            throw IllegalStateException("regularFileChmod file not exist or not file $path")
        }

        if (!file.setReadable(true, false)
            || !file.setWritable(true)
        ) {
            throw IllegalStateException("regularFileChmod chmod file fault $path")
        }
    }
}
