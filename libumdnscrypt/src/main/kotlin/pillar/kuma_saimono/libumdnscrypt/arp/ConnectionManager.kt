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

package pillar.kuma_saimono.libumdnscrypt.arp

import android.content.Context
import pillar.kuma_saimono.libumdnscrypt.di.arp.ArpScope
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.NetworkChecker
import javax.inject.Inject

@ArpScope
class ConnectionManager @Inject constructor(
    private val context: Context
) {
    @Volatile
    var connectionAvailable = false
    @Volatile
    var cellularActive = false
    @Volatile
    var wifiActive = false
    @Volatile
    var ethernetActive = false

    fun updateActiveNetworks() {
        cellularActive = NetworkChecker.isCellularActive(context)
        wifiActive = NetworkChecker.isWifiActive(context)
        ethernetActive = NetworkChecker.isEthernetActive(context)
    }

    fun clearActiveNetworks() {
        cellularActive = false
        wifiActive = false
        ethernetActive = false
    }

    fun isConnected(): Boolean = NetworkChecker.isNetworkAvailable(context)
}
