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

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.HttpInternetChecker
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.NetworkChecker
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.SocketInternetChecker
import javax.inject.Inject
import javax.inject.Provider

class ConnectionCheckerDataSourceImpl @Inject constructor(
    private val httpInternetChecker: Provider<HttpInternetChecker>,
    private val socketInternetChecker: Provider<SocketInternetChecker>,
    private val context: Context
) : ConnectionCheckerDataSource {
    override fun checkInternetAvailableOverHttp(
        site: String,
        proxyAddress: String,
        proxyPort: Int,
        proxyUser: String,
        proxyPass: String
    ): Boolean =
        httpInternetChecker.get().checkConnectionAvailability(site, proxyAddress, proxyPort, proxyUser, proxyPass)

    override fun checkInternetAvailableOverSocks(
        ip: String,
        port: Int,
        proxyAddress: String,
        proxyPort: Int,
        proxyUser: String,
        proxyPass: String,
    ): Boolean = socketInternetChecker.get().checkConnectionAvailability(
        ip,
        port,
        proxyAddress,
        proxyPort,
        proxyUser,
        proxyPass
    )

    override fun checkNetworkAvailable(): Boolean =
        NetworkChecker.isNetworkAvailable(context)

    override fun isWiFiActive(): Boolean = NetworkChecker.isWifiActive(context)

    override fun isCaptivePortalDetected() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        NetworkChecker.isCaptivePortalDetected(context)
    } else {
        false
    }

}
