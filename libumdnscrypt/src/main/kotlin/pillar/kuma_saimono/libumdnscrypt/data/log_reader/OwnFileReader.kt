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

package pillar.kuma_saimono.libumdnscrypt.data.log_reader

import android.content.Context
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileManager
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileShortener
import pillar.kuma_saimono.libumdnscrypt.utils.mmap.MmapTail
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStreamReader
import java.io.PrintWriter
import java.util.LinkedList
import java.util.concurrent.locks.ReentrantLock

class OwnFileReader(
    private val context: Context?,
    private val filePath: String
) {

    fun readLastLines(): List<String> {

        var lines: MutableList<String> = LinkedList()

        var fileIsTooLong = false

        try {
            reentrantLock.lockInterruptibly()

            val file = File(filePath)

            if (!file.exists()) {
                return emptyList()
            }

            if (context != null && !file.canRead()) {
                if (!file.setReadable(true)) {
                    logw("Impossible to read file $filePath Try restore access")

                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, filePath)
                }

                if (file.canRead()) {
                    logi("Access to $filePath restored")
                } else {
                    loge("Impossible to read file $filePath")
                }
            }

            FileShortener.shortenTooTooLongFile(filePath)

            // #20 — mmap fast path: map ONLY the tail window (O(window), the head pages are never
            // faulted in; hot in the page-cache across polls) instead of BufferedReader-scanning the
            // whole file (up to FileShortener's 500 KiB bound) every UI poll. Authoritative-or-null:
            // MmapTail returns null on any fault OR when a mid-file window can't rule the head lines
            // out — then the original stream path below answers with identical semantics (fail-open).
            val mapped = MmapTail.tailLines(
                file, TAIL_WINDOW_BYTES, MAX_LINES_QUANTITY + MAX_LINES_HYSTERESIS
            )
            if (mapped != null) {
                if (mapped.size > MAX_LINES_QUANTITY + MAX_LINES_HYSTERESIS) {
                    val kept = mapped.subList(mapped.size - MAX_LINES_QUANTITY, mapped.size)
                    shortenTooLongFile(kept)
                    return kept
                }
                return mapped
            }

            FileInputStream(filePath).use { fstream ->
                InputStreamReader(fstream).use { reader ->
                    BufferedReader(reader).use { br ->

                        while (true) {
                            val line = br.readLine() ?: break
                            lines.add(line)
                            if (lines.size > MAX_LINES_QUANTITY + MAX_LINES_HYSTERESIS) {
                                lines.removeAt(0)
                                fileIsTooLong = true
                            }

                            if (Thread.currentThread().isInterrupted) {
                                return lines
                            }
                        }
                    }
                }
            }

            if (fileIsTooLong) {
                lines = lines.subList(lines.size - MAX_LINES_QUANTITY, lines.size)
                shortenTooLongFile(lines)
            }

        } catch (e: Exception) {
            loge("Impossible to read file $filePath", e)
        } finally {
            reentrantLock.unlock()
        }

        return lines
    }

    private fun shortenTooLongFile(lines: List<String>?) {
        val file = File(filePath)
        if (!file.isFile) {
            return
        }

        try {
            PrintWriter(file, "UTF-8").use { writer ->
                if (lines != null && lines.size != 0) {
                    val buffer = StringBuilder()
                    for (line in lines) {
                        buffer.append(line).append("\n")
                    }
                    writer.println(buffer)
                }
            }
        } catch (e: IOException) {
            loge("Unable to rewrite too long file$filePath", e)
        }
    }

    internal fun updateLines(lines: List<String>?) {
        val file = File(filePath)
        if (!file.isFile) {
            return
        }

        try {
            PrintWriter(file, "UTF-8").use { writer ->
                if (lines != null && !lines.isEmpty()) {
                    val buffer = StringBuilder()
                    for (line in lines) {
                        buffer.append(line).append("\n")
                    }
                    writer.println(buffer)
                }
            }
        } catch (e: IOException) {
            loge("Unable to update lines$filePath", e)
        }
    }

    internal val fileLength: Long
        get() {
            try {
                reentrantLock.lockInterruptibly()

                val file = File(filePath)
                if (!file.isFile || !file.canRead()) {
                    return -1L
                }

                return file.length()
            } catch (e: Exception) {
                loge("OwnFileReader getFileSize", e)
            } finally {
                if (reentrantLock.isLocked && reentrantLock.isHeldByCurrentThread) {
                    reentrantLock.unlock()
                }
            }
            return -1L
        }

    companion object {
        //private final static long TOO_LONG_FILE_LENGTH = 1024 * 100;
        private const val MAX_LINES_QUANTITY = 80
        private const val MAX_LINES_HYSTERESIS = 50

        // #20 — the mmap tail window: 64 KiB comfortably holds 130 log lines (~16 KiB typical) while
        // staying a fraction of FileShortener's 500 KiB whole-file bound the stream path re-scans.
        private const val TAIL_WINDOW_BYTES = 64 * 1024

        private val reentrantLock = ReentrantLock()
    }
}
