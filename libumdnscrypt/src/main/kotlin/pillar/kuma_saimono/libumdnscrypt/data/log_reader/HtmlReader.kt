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

import pillar.kuma_saimono.libumdnscrypt.utils.Constants.CHROME_BROWSER_USER_AGENT
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.lang.Exception
import java.net.HttpURLConnection
import java.net.URL

private const val CONNECT_TIMEOUT = 1

class HtmlReader(val port: Int) {

    private var con: HttpURLConnection? = null

    fun readLines(): List<String> {

        var lines = emptyList<String>()

        try {
            lines = tryReadLines()
        } catch (e: Exception) {
            loge("HtmlReader", e)
        } finally {
            con?.disconnect()
        }

        return lines
    }

    private fun tryReadLines(): List<String> {
        val lines = mutableListOf<String>()

        val url = URL("http://127.0.0.1:$port/")
        con = url.openConnection() as HttpURLConnection

        val connection = con ?: return emptyList()

        connection.apply {
            requestMethod = "GET"
            setRequestProperty("User-Agent", CHROME_BROWSER_USER_AGENT)
            connectTimeout = CONNECT_TIMEOUT * 1000
            connect()
        }

        val code = connection.responseCode
        if (code != HttpURLConnection.HTTP_OK) {
            return lines
        }

        connection.inputStream.bufferedReader().use { reader ->
            var line = reader.readLine()
            while (line != null) {
                lines.add(line)
                line = reader.readLine()
            }
        }

        return lines
    }
}
