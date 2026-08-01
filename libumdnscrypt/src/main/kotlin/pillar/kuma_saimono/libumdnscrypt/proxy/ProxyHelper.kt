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

package pillar.kuma_saimono.libumdnscrypt.proxy

import android.content.Context
import android.content.SharedPreferences
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesRestarter
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RuntimeTierManager
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.DEFAULT_PROXY_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv4_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.LOOPBACK_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.QUAD_DNS_41
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.ProxyAuthManager.setDefaultAuth
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.executors.CoroutineExecutor
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_OUTBOUND_PROXY
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.USE_PROXY
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.SocketAddress
import javax.inject.Inject
import javax.inject.Named

class ProxyHelper @Inject constructor(
    private val context: Context,
    private val pathVars: PathVars,
    private val executor: CoroutineExecutor,
    @Named(DEFAULT_PREFERENCES_NAME) private val defaultPreferences: SharedPreferences
) {

    fun manageProxy(
        server: String,
        port: String,
        serverOrPortChanged: Boolean,
        enableNonTorProxy: Boolean,
        enableDNSCryptProxy: Boolean
    ) {

        val modulesStatus = ModulesStatus.getInstance()

        val nonTorProxified = defaultPreferences.getBoolean(USE_PROXY, false)
        val dnsCryptProxified = defaultPreferences.getBoolean(DNSCRYPT_OUTBOUND_PROXY, false)

        val proxyAddr = if (server.isNotEmpty() && port.isNotEmpty()) {
            "$server:$port"
        } else {
            "$LOOPBACK_ADDRESS:$DEFAULT_PROXY_PORT"
        }

        executor.submit("ProxyHelper manageProxy") {
            val dnsCryptSettingChanged = enableDNSCryptProxy xor dnsCryptProxified
            if (dnsCryptSettingChanged || serverOrPortChanged) {
                manageDNSCryptProxy(pathVars.dnscryptConfPath, proxyAddr, enableDNSCryptProxy)
                defaultPreferences.edit().putBoolean(DNSCRYPT_OUTBOUND_PROXY, enableDNSCryptProxy)
                    .apply()

                if (modulesStatus.dnsCryptState == ModuleState.RUNNING && (enableDNSCryptProxy || dnsCryptSettingChanged)) {
                    ModulesRestarter.restartDNSCrypt(context)
                }
            }

            val nonTorProxySettingsChanged = enableNonTorProxy xor nonTorProxified
            if (dnsCryptSettingChanged
                || nonTorProxySettingsChanged || serverOrPortChanged
            ) {
                defaultPreferences.edit().putBoolean(USE_PROXY, enableNonTorProxy).apply()
                modulesStatus.setIptablesRulesUpdateRequested(context, true)
            }

        }
    }

    fun checkProxyConnectivity(
        proxyHost: String,
        proxyPort: Int,
        proxyUser: String,
        proxyPass: String
    ): String {
        val start = System.currentTimeMillis()

        try {
            val dnsCryptFallbackRes = pathVars.dnsCryptFallbackRes
                .split(Regex(", ?"))
                .filter { it.matches(Regex(IPv4_REGEX)) }
                .shuffled()
                .getOrElse(0) { QUAD_DNS_41 }
            val sockaddr: SocketAddress =
                InetSocketAddress(InetAddress.getByName(dnsCryptFallbackRes), 53)
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(proxyHost, proxyPort))

            Socket(proxy).use {
                setDefaultAuth(proxyUser, proxyPass)
                it.connect(sockaddr, CHECK_CONNECTION_TIMEOUT_MSEC)
                it.soTimeout = CHECK_CONNECTION_TIMEOUT_MSEC

                if (!it.isConnected) {
                    throw IllegalStateException("unable to connect to $dnsCryptFallbackRes")
                }
            }
        } catch (e: Exception) {
            return e.message ?: ""
        }

        return (System.currentTimeMillis() - start).toString()
    }

    /**
     * K5 D33 — ONE TOML write owner: the DNSCrypt outbound-proxy flip goes through the TYPED Rust
     * config authority (import → mutate the typed Record → set the authority + export the
     * compatibility view), retiring this helper's raw line-surgery (`proxy = …` / `force_tcp = …`
     * in-place rewrites) — the same read-typed→mutate→serialize funnel the K5 settings screen
     * owns. Enabling sets the proxy AND `force_tcp = true` (an outbound SOCKS proxy needs TCP
     * transport — the legacy proxy↔force_tcp link, and the settings screen's `applyProxyEnabled`
     * twin); disabling clears the proxy key and leaves `force_tcp` as last set (the legacy disable
     * never reset it either). BONUS over the legacy surgery: a TOML that never carried a
     * `proxy = ` line (where the old line-replace silently did NOTHING) now genuinely gains the
     * proxy. Crash-safe: any fault leaves the on-disk TOML untouched.
     */
    private fun manageDNSCryptProxy(dnsCryptConfPath: String?, address: String, enable: Boolean) {

        if (dnsCryptConfPath == null) {
            return
        }

        try {
            val toml = FileManager.readTextFileSynchronous(context, dnsCryptConfPath)
                .joinToString("\n")
            val cfg = TortaCore.dnscryptConfigImportOrDefault(toml)
            if (cfg != null) {
                if (enable) {
                    cfg.proxy = "socks5://$address"
                    cfg.forceTcp = true
                } else {
                    cfg.proxy = null
                }
                TortaCore.dnscryptConfigSet(cfg)
                // W5 #12 (RAMxNAND Opt-2) — the config edit now rides the DurableTier: persist the
                // just-set authority to the app-private W5 record, then MATERIALIZE the compatibility
                // toml Rust-side (atomic tmp+rename), RETIRING this helper's Kotlin FileManager write.
                val durableDir =
                    pathVars.appDataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR
                TortaCore.persistDnscryptConfig(durableDir)
                TortaCore.materializeDnscryptToml(dnsCryptConfPath)
            }
        } catch (e: Exception) {
            loge("ProxyHelper manageDNSCryptProxy", e)
        }
    }

    companion object {
        const val CHECK_CONNECTION_TIMEOUT_MSEC = 5000
    }
}
