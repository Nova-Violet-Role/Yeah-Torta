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

package pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker

import pillar.kuma_saimono.libumdnscrypt.utils.Constants.CHROME_BROWSER_USER_AGENT
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.ProxyAuthManager.setDefaultAuth
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import javax.inject.Inject
import javax.net.ssl.HttpsURLConnection

private const val READ_TIMEOUT_SEC = 30
private const val CONNECT_TIMEOUT_SEC = 30
private const val USER_AGENT_PROPERTY = "User-Agent"
private const val REQUEST_METHOD_GET = "GET"

class HttpInternetChecker @Inject constructor() {

    private var connection: HttpURLConnection? = null

    fun checkConnectionAvailability(
        site: String,
        proxyAddress: String,
        proxyPort: Int,
        proxyUser: String,
        proxyPass: String
    ): Boolean {
        var result = false

        try {
            result = checkConnection(site, proxyAddress, proxyPort, proxyUser, proxyPass)
            return result
        } finally {
            if (result) {
                connection?.disconnect()
            }
        }
    }

    private fun checkConnection(
        site: String,
        proxyAddress: String,
        proxyPort: Int,
        proxyUser: String,
        proxyPass: String
    ): Boolean {
        val url = URL(site)

        connection = if (proxyAddress.isNotBlank() && proxyPort != 0) {
            val proxy = Proxy(
                Proxy.Type.SOCKS,
                InetSocketAddress(
                    proxyAddress,
                    proxyPort
                )
            )

            setDefaultAuth(proxyUser, proxyPass)

            url.openConnection(proxy) as HttpsURLConnection
        } else {
            url.openConnection() as HttpsURLConnection
        }

        val connection = connection ?: return false

        connection.apply {
            requestMethod = REQUEST_METHOD_GET
            connectTimeout = CONNECT_TIMEOUT_SEC * 1000
            readTimeout = READ_TIMEOUT_SEC * 1000
            setRequestProperty(USER_AGENT_PROPERTY, CHROME_BROWSER_USER_AGENT)
            connect()
        }

        return true
    }
}
