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

package pillar.kuma_saimono.libumdnscrypt.vpn.service

import android.content.SharedPreferences
import android.os.Build
import javax.inject.Inject
import javax.inject.Named
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.proxy.CLEARNET_APPS_FOR_PROXY
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.DEFAULT_PROXY_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.LOOPBACK_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.MAX_PORT_NUMBER
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.NUMBER_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.APPS_DIRECT_UDP
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FIREWALL_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.CONNECTION_LOGS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.BLOCK_HTTP
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.BYPASS_LAN
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PREVENT_DNS_LEAKS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.BLOCK_LAN_ON_FREE_WIFI
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ARP_SPOOFING_DETECTION
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ARP_SPOOFING_BLOCK_INTERNET
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.COMPATIBILITY_MODE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNS_REBIND_PROTECTION
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.USE_PROXY
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PROXY_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PROXY_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PROXY_USER
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PROXY_PASS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_BLOCK_IPv6

class VpnPreferenceHolder
@Inject
constructor(
    @Named(DEFAULT_PREFERENCES_NAME) defaultPreferences: SharedPreferences,
    preferenceRepository: PreferenceRepository,
    pathVars: PathVars,
) {
    val dnsBlockedResponseCode = 3
    val ownUID = pathVars.appUid
    val blockHttp = defaultPreferences.getBoolean(BLOCK_HTTP, false)
    val blockIPv6DnsCrypt = defaultPreferences.getBoolean(DNSCRYPT_BLOCK_IPv6, false)

    val setBypassProxy = preferenceRepository.getStringSetPreference(CLEARNET_APPS_FOR_PROXY)
    val setDirectUdpApps = preferenceRepository.getStringSetPreference(APPS_DIRECT_UDP)

    val compatibilityMode =
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.LOLLIPOP) {
            true
        } else {
            defaultPreferences.getBoolean(COMPATIBILITY_MODE, false)
        }

    val arpSpoofingDetection = defaultPreferences.getBoolean(ARP_SPOOFING_DETECTION, false)
    val blockInternetWhenArpAttackDetected =
        defaultPreferences.getBoolean(ARP_SPOOFING_BLOCK_INTERNET, false)
    val dnsRebindProtection = defaultPreferences.getBoolean(DNS_REBIND_PROTECTION, true)
    val lan = defaultPreferences.getBoolean(BYPASS_LAN, true)
    val firewallEnabled = preferenceRepository.getBoolPreference(FIREWALL_ENABLED)
    val preventDnsLeaks = defaultPreferences.getBoolean(PREVENT_DNS_LEAKS, false)
    val blockLanOnFreeWiFi = defaultPreferences.getBoolean(BLOCK_LAN_ON_FREE_WIFI, true)

    val proxyAddress =
        defaultPreferences.getString(PROXY_ADDRESS, LOOPBACK_ADDRESS)?.take(46) ?: LOOPBACK_ADDRESS
    val proxyPort =
        defaultPreferences.getString(PROXY_PORT, DEFAULT_PROXY_PORT).let {
            if (it?.matches(Regex(NUMBER_REGEX)) == true && it.toLong() <= MAX_PORT_NUMBER) {
                it.toInt()
            } else {
                DEFAULT_PROXY_PORT.toInt()
            }
        }
    val proxyUser = defaultPreferences.getString(PROXY_USER, "")?.take(127) ?: ""
    val proxyPass = defaultPreferences.getString(PROXY_PASS, "")?.take(127) ?: ""

    val useProxy =
        defaultPreferences.getBoolean(USE_PROXY, false) &&
            proxyAddress.isNotBlank() &&
            proxyPort != 0

    private val modulesStatus = ModulesStatus.getInstance()
    val fixTTL =
        (modulesStatus.isFixTTL &&
            modulesStatus.mode == OperationMode.ROOT_MODE &&
            !modulesStatus.isUseModulesWithRoot)
    val connectionLogsEnabled = defaultPreferences.getBoolean(CONNECTION_LOGS, true)
}
