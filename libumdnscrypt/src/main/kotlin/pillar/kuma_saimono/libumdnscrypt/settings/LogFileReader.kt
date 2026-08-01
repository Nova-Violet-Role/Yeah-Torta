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

package pillar.kuma_saimono.libumdnscrypt.settings

import java.io.File
import java.io.IOException
import me.tatarka.inject.annotations.Inject
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge

/**
 * Yeah! Tortä — the log-tail reader behind [ShowLogFragment] (OMEGA Stage-D · D2, the
 * general-settings `.java` retirement: the Garmatin `ShowLogFragment.java` is rewritten in Kotlin
 * and its file IO moves into THIS Kotlin-Inject-constructed class — compile-time constructor DI on
 * the [pillar.kuma_saimono.libumdnscrypt.slint.SlintUiComponent] graph, zero reflection, the B3 GAP-5
 * native idiom).
 *
 * Pure app-private-file IO (the query/nx logs live under the app cache — no root, no FileManager
 * indirection needed), crash-proof: an unreadable/absent log reads as the honest empty tail, never
 * a throw.
 */
@Inject
class LogFileReader {

    /**
     * Read the last [maxLines] lines of [path] (the legacy 1000-line window). Preserves the legacy
     * shorten side-effect: once the file exceeds `2 × maxLines` lines it is rewritten in place with
     * just the kept tail, so an ever-growing log never balloons the read.
     */
    fun readTail(path: String, maxLines: Int): String {
        return try {
            val lines = File(path).readLines()
            val text =
                (if (lines.size > maxLines) lines.takeLast(maxLines) else lines)
                    .joinToString(System.lineSeparator())
                    .trim()
            if (lines.size > maxLines * 2) {
                shortenInPlace(path, text)
            }
            text
        } catch (e: IOException) {
            loge("LogFileReader readTail $path", e)
            ""
        }
    }

    /** Truncate the log (the clear-FAB action). */
    fun clear(path: String) {
        try {
            File(path).writeText("")
        } catch (e: IOException) {
            loge("LogFileReader clear $path", e)
        }
    }

    private fun shortenInPlace(path: String, keptTail: String) {
        try {
            File(path).writeText(keptTail)
        } catch (e: IOException) {
            loge("LogFileReader shorten $path", e)
        }
    }
}
