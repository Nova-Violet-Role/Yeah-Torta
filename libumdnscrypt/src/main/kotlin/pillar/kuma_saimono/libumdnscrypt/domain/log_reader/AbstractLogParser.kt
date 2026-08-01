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

package pillar.kuma_saimono.libumdnscrypt.domain.log_reader

import android.text.TextUtils
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.lang.StringBuilder
import java.util.*

abstract class AbstractLogParser {

    abstract fun parseLog(): LogDataModel

    fun formatLines(lines: List<String>): String {
        val stringBuilder = StringBuilder()

        try {
            for (line in lines) {

                if (line.isBlank()) {
                    continue
                }

                //s = Html.escapeHtml(s);
                var encodedLine = TextUtils.htmlEncode(line)
                val encodedLineLowerCase = encodedLine.lowercase(Locale.ROOT)

                if (encodedLineLowerCase.contains("[notice]") || encodedLineLowerCase.contains("/info")) {
                    encodedLine = "<font color=#808080>" + encodedLine.replace("[notice]", "")
                        .replace("[NOTICE]", "") + "</font>"
                } else if (encodedLineLowerCase.contains("[warn]") || encodedLineLowerCase.contains("/warn")) {
                    encodedLine = "<font color=#ffa500>$encodedLine</font>"
                } else if (encodedLineLowerCase.contains("[warning]")) {
                    encodedLine = "<font color=#ffa500>$encodedLine</font>"
                } else if (encodedLineLowerCase.contains("[error]") || encodedLineLowerCase.contains("[err]") || encodedLineLowerCase.contains("/error")) {
                    encodedLine = "<font color=#f08080>$encodedLine</font>"
                } else if (encodedLineLowerCase.contains("[critical]")) {
                    encodedLine = "<font color=#990000>$encodedLine</font>"
                } else if (encodedLineLowerCase.contains("[fatal]")) {
                    encodedLine = "<font color=#990000>$encodedLine</font>"
                } else if (encodedLineLowerCase.isNotEmpty()) {
                    encodedLine = "<font color=#6897bb>$encodedLine</font>"
                }
                if (encodedLine.isNotBlank()) {
                    stringBuilder.append(encodedLine)
                    stringBuilder.append("<br />")
                }
            }
        } catch (e: Exception) {
            loge("LogParser formatLines", e)
        }

        val lastBrIndex: Int = stringBuilder.lastIndexOf("<br />")

        return if (lastBrIndex > 0) {
            stringBuilder.substring(0, lastBrIndex)
        } else {
            stringBuilder.toString()
        }
    }
}
