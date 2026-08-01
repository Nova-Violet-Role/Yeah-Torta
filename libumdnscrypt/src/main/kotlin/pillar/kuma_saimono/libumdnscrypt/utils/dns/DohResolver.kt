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

package pillar.kuma_saimono.libumdnscrypt.utils.dns

import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.io.DataOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection

class DohResolver @AssistedInject constructor(
    @Assisted server: String,
    @Assisted("type") type: Int,
    @Assisted("timeout") timeout: Int
) : DnsResolver(server, type, timeout) {

    @Throws(IOException::class)
    internal override fun request(server: String, host: String, recordType: Int): DnsResponse? {
        val d = Math.random()
        val messageId = (d * 0xFFFF).toInt().toShort()
        val request = DnsRequest(messageId, recordType, host)
        val requestData = request.toDnsQuestionData()

        val httpConn = URL(server).openConnection() as HttpsURLConnection
        httpConn.connectTimeout = timeout * 1000
        httpConn.readTimeout = timeout * 1000
        httpConn.doOutput = true
        httpConn.requestMethod = "POST"
        httpConn.setRequestProperty("Content-Type", "application/dns-message")
        httpConn.setRequestProperty("Accept", "application/dns-message")
        httpConn.setRequestProperty("Accept-Encoding", "")

        val bodyStream = DataOutputStream(httpConn.outputStream)
        bodyStream.write(requestData)
        bodyStream.close()

        val responseCode = httpConn.responseCode
        if (responseCode != HttpURLConnection.HTTP_OK) {
            return null
        }

        val length = httpConn.contentLength
        if (length <= 0 || length > 1024 * 1024) {
            return null
        }
        val inputStream = httpConn.inputStream
        val responseData = ByteArray(length)
        val read = inputStream.read(responseData)
        inputStream.close()
        if (read <= 0) {
            return null
        }

        return DnsResponse(server, Record.Source.Doh, request, responseData)
    }
}
