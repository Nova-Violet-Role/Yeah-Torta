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

package pillar.kuma_saimono.libumdnscrypt.data.connection_checker

import pillar.kuma_saimono.libumdnscrypt.domain.connection_checker.ConnectionCheckerRepository
import javax.inject.Inject

class ConnectionCheckerRepositoryImpl @Inject constructor(
    private val connectionCheckerDataSource: ConnectionCheckerDataSource,
) : ConnectionCheckerRepository {

    override fun checkInternetAvailableOverHttp(
        site: String,
        proxyAddress: String,
        proxyPort: Int,
        proxyUser: String,
        proxyPass: String
    ): Boolean {
        return connectionCheckerDataSource.checkInternetAvailableOverHttp(
            site,
            proxyAddress,
            proxyPort,
            proxyUser,
            proxyPass
        )
    }

    override fun checkInternetAvailableOverSocks(
        ip: String,
        port: Int,
        proxyAddress: String,
        proxyPort: Int,
        proxyUser: String,
        proxyPass: String,
    ): Boolean {
        return connectionCheckerDataSource.checkInternetAvailableOverSocks(
            ip,
            port,
            proxyAddress,
            proxyPort,
            proxyUser,
            proxyPass
        )
    }

    override fun checkNetworkAvailable(): Boolean {
        return connectionCheckerDataSource.checkNetworkAvailable()
    }

    override fun isCaptivePortalOnWiFiDetected(): Boolean {
        return connectionCheckerDataSource.isWiFiActive() && connectionCheckerDataSource.isCaptivePortalDetected()
    }
}
