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

package pillar.kuma_saimono.libumdnscrypt.utils.filemanager

import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile

object FileShortener {
    private const val TOO_TOO_LONG_FILE_LENGTH = 1024 * 500L
    private const val TOO_TOO_LONG_FILE_LENGTH_HYSTERESIS = 1024 * 100L

    @JvmStatic
    fun shortenTooTooLongFile(filePath: String) {
        val file = File(filePath)
        if (!file.exists())
            return

        val fileLength = file.length()

        if (fileLength > TOO_TOO_LONG_FILE_LENGTH) {

            try {
                RandomAccessFile(file, "rw").use { randomAccessFile ->
                    ByteArrayOutputStream().use { baos ->

                        randomAccessFile.seek(fileLength - (TOO_TOO_LONG_FILE_LENGTH - TOO_TOO_LONG_FILE_LENGTH_HYSTERESIS))

                        val buffer = ByteArray(1024)
                        var len: Int
                        while (randomAccessFile.read(buffer).also { len = it } != -1) {
                            baos.write(buffer, 0, len)
                        }
                        baos.flush()

                        randomAccessFile.seek(0)
                        randomAccessFile.write(baos.toByteArray())
                        randomAccessFile.setLength(baos.size().toLong())

                    }
                }
            } catch (e: IOException) {
                loge("Unable to rewrite too too long file$filePath", e)
            }
        }
    }
}
