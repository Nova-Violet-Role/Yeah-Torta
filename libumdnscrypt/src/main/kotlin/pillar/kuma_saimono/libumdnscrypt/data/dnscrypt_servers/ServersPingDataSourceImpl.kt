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

package pillar.kuma_saimono.libumdnscrypt.data.dnscrypt_servers

import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.SocketInternetChecker
import javax.inject.Inject
import javax.inject.Provider

class ServersPingDataSourceImpl @Inject constructor(
    private val socketInternetChecker: Provider<SocketInternetChecker>
) : ServersPingDataSource {
    override fun checkTimeoutDirectly(ip: String, port: Int) =
        socketInternetChecker.get().checkConnectionPing(
            ip = ip,
            port = port,
            "",
            0,
            "",
            ""
        )

    override fun checkTimeoutViaProxy(
        ip: String,
        port: Int,
        proxyAddress: String,
        proxyPort: Int
    ) =
        socketInternetChecker.get().checkConnectionPing(
            ip = ip,
            port = port,
            proxyAddress = proxyAddress,
            proxyPort = proxyPort,
            "",
            ""
        )
}
