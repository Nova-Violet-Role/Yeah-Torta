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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_servers

import android.content.Context
import android.content.SharedPreferences
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.assistance.AccelerateDevelop

data class DnsServerFeatures(
    val requireDnssec: Boolean,
    val requireNofilter: Boolean,
    var requireNolog: Boolean,
    val useDnsServers: Boolean,
    val useDohServers: Boolean,
    val useOdohServers: Boolean,
    val useIPv4Servers: Boolean,
    val useIPv6Servers: Boolean
) {
    constructor(context: Context, defaultPreferences: SharedPreferences) : this(
        requireDnssec = defaultPreferences.getBoolean("require_dnssec", false),
        requireNofilter = defaultPreferences.getBoolean("require_nofilter", false)
                || context.getText(R.string.package_name).contains(".gp") && !AccelerateDevelop.accelerated,
        requireNolog = defaultPreferences.getBoolean("require_nolog", false),
        useDnsServers = defaultPreferences.getBoolean("dnscrypt_servers", true),
        useDohServers = defaultPreferences.getBoolean("doh_servers", true),
        useOdohServers = defaultPreferences.getBoolean("odoh_servers", true),
        useIPv4Servers = defaultPreferences.getBoolean("ipv4_servers", true),
        useIPv6Servers = defaultPreferences.getBoolean("ipv6_servers", true)
    )
}
