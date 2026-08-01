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

package pillar.kuma_saimono.libumdnscrypt.data.modules_configuration

import android.content.SharedPreferences
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv4_REGEX_WITH_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.LOOPBACK_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_OUTBOUND_PROXY_PORT
import java.io.File
import javax.inject.Inject
import javax.inject.Named

/**
 * K5 D33 — ONE config brain. The outbound-proxy address is read from the TYPED Rust authority
 * ([TortaCore.dnscryptConfigImportOrDefault] over the on-disk compatibility TOML), retiring the
 * second Java TOML parser (`DnsCryptConfigurationParser`) this data source used to hand-scan
 * `proxy = 'socks5://…'` lines with. The legacy scan also recovered a COMMENTED `#proxy` line; the
 * typed read models the active `proxy` key only — behavior-equivalent, because this address is
 * consumed exclusively when the outbound proxy is ENABLED (the key is active then, written by
 * [pillar.kuma_saimono.libumdnscrypt.proxy.ProxyHelper] through the same typed owner), and the disabled
 * path already fell back to the prefs port. Crash-safe: any read fault degrades to the fallback.
 */
class DnsCryptConfigurationDataSource @Inject constructor(
    private val pathVars: dagger.Lazy<PathVars>,
    @Named(DEFAULT_PREFERENCES_NAME) private val defaultPreferences: SharedPreferences
) {
    fun getDnsCryptOutboundProxyAddress(): String =
        readTypedProxyAddress() ?: "$LOOPBACK_ADDRESS:${getDnsCryptOutboundProxyPort()}"

    private fun readTypedProxyAddress(): String? = try {
        val toml = File(pathVars.get().dnscryptConfPath)
            .takeIf { it.isFile }
            ?.readText() ?: ""
        TortaCore.dnscryptConfigImportOrDefault(toml)
            ?.proxy
            ?.removePrefix(SOCKS5_PREFIX)
            ?.takeIf { it.matches(Regex(IPv4_REGEX_WITH_PORT)) }
    } catch (e: Exception) {
        loge("DnsCryptConfigurationDataSource readTypedProxyAddress", e)
        null
    }

    private fun getDnsCryptOutboundProxyPort() =
        defaultPreferences.getString(DNSCRYPT_OUTBOUND_PROXY_PORT, "") ?: ""

    companion object {
        private const val SOCKS5_PREFIX = "socks5://"
    }
}
