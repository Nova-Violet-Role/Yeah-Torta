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

package pillar.kuma_saimono.libumdnscrypt.settings

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.Environment
import android.os.Process
import androidx.preference.PreferenceManager
import javax.inject.Inject
import javax.inject.Singleton
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv4_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv6_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.QUAD_DNS_41
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_BOOTSTRAP_RESOLVERS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_LISTEN_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.USE_IPTABLES
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.WAIT_IPTABLES

@Singleton
class PathVars @SuppressLint("SdCardPath") @Inject constructor(context: Context) {

    private val preferences: SharedPreferences =
        PreferenceManager.getDefaultSharedPreferences(context)

    val appDataDir: String =
        context.applicationInfo.dataDir ?: ("/data/data/" + context.packageName)

    @Volatile
    var appVersion: String = context.getString(R.string.appVersion)

    val appProcVersion: String = context.getString(R.string.appProcVersion)

    private val dnscryptPath: String
    val dnsttPath: String
    val nflogPath: String

    private val bbOK: Boolean =
        App.instance.daggerComponent.getPreferenceRepository().get().getBoolPreference("bbOK")

    @Volatile
    private var cachedAppUid: Int = -1

    @Volatile
    private var cachedAppUidStr: String = ""

    init {
        val nativeLibPath = context.applicationInfo.nativeLibraryDir

        dnscryptPath = nativeLibPath + "/libdnscrypt-proxy.so"
        dnsttPath = nativeLibPath + "/libdnstt.so"
        nflogPath = nativeLibPath + "/libnflog.so"
    }

    fun getDefaultBackupPath(): String {
        return Environment.getExternalStorageDirectory().path + "/LibUmDNSCrypt"
    }

    fun getIptablesPath(): String {
        var iptablesSelector = preferences.getString(USE_IPTABLES, "2")
        if (iptablesSelector == null) {
            iptablesSelector = "2"
        }

        val waitIptables = preferences.getBoolean(WAIT_IPTABLES, true)

        var path = when (iptablesSelector) {
            "1" -> appDataDir + "/app_bin/iptables "
            else -> "iptables "
        }

        if (waitIptables) {
            path += "-w "
        }

        return path
    }

    fun getIp6tablesPath(): String {
        var iptablesSelector = preferences.getString(USE_IPTABLES, "2")
        if (iptablesSelector == null) {
            iptablesSelector = "2"
        }

        val waitIptables = preferences.getBoolean(WAIT_IPTABLES, true)

        var path = when (iptablesSelector) {
            "1" -> appDataDir + "/app_bin/ip6tables "
            else -> "ip6tables "
        }

        if (waitIptables) {
            path += "-w "
        }

        return path
    }

    val busyboxPath: String
        get() {
            var busyBoxSelector = preferences.getString("pref_common_use_busybox", "1")
            if (busyBoxSelector == null) {
                busyBoxSelector = "1"
            }

            val path = when (busyBoxSelector) {
                "2" -> "busybox "
                "3" -> appDataDir + "/app_bin/busybox "
                "4" -> ""
                else -> {
                    if (bbOK) {
                        "busybox "
                    } else if (ModulesStatus.getInstance().isRootAvailable) {
                        appDataDir + "/app_bin/busybox "
                    } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        "toybox "
                    } else {
                        "toolbox "
                    }
                }
            }
            return path
        }

    fun getRejectAddress(): String {
        return "10.191.0.2"
    }

    @get:JvmName("getDNSCryptPath")
    val dnsCryptPath: String
        get() = dnscryptPath

    @get:JvmName("getDNSCryptPort")
    val dnsCryptPort: String
        get() = preferences.getString(DNSCRYPT_LISTEN_PORT, "5354")!!

    @get:JvmName("getDNSCryptFallbackRes")
    val dnsCryptFallbackRes: String
        get() {
            val dnsCryptFallbackResolvers =
                preferences.getString(DNSCRYPT_BOOTSTRAP_RESOLVERS, QUAD_DNS_41)!!
            val fallbackResolvers = StringBuilder()

            for (rawResolver in dnsCryptFallbackResolvers.split(", ?".toRegex())) {
                var resolver = rawResolver
                    .replace("[", "").replace("]", "")
                    .replace("'", "").replace("\"", "")
                if (resolver.endsWith(":53")) {
                    resolver = resolver.substring(0, resolver.lastIndexOf(":53"))
                }
                if (resolver.matches(IPv4_REGEX.toRegex()) || resolver.matches(IPv6_REGEX.toRegex())) {
                    if (fallbackResolvers.length != 0) {
                        fallbackResolvers.append(", ")
                    }
                    fallbackResolvers.append(resolver)
                }
            }

            if (fallbackResolvers.length == 0) {
                fallbackResolvers.append(QUAD_DNS_41)
            }

            return fallbackResolvers.toString()
        }

    @get:JvmName("getDNSCryptBlackListPath")
    val dnsCryptBlackListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/blacklist.txt"

    @get:JvmName("getDNSCryptSingleBlackListPath")
    val dnsCryptSingleBlackListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/blacklist-single.txt"

    @get:JvmName("getDNSCryptLocalBlackListPath")
    val dnsCryptLocalBlackListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/blacklist-local.txt"

    @get:JvmName("getDNSCryptRemoteBlackListPath")
    val dnsCryptRemoteBlackListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/blacklist-remote.txt"

    @get:JvmName("getDNSCryptIPBlackListPath")
    val dnsCryptIPBlackListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/ip-blacklist.txt"

    @get:JvmName("getDNSCryptSingleIPBlackListPath")
    val dnsCryptSingleIPBlackListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/ip-blacklist-single.txt"

    @get:JvmName("getDNSCryptLocalIPBlackListPath")
    val dnsCryptLocalIPBlackListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/ip-blacklist-local.txt"

    @get:JvmName("getDNSCryptRemoteIPBlackListPath")
    val dnsCryptRemoteIPBlackListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/ip-blacklist-remote.txt"

    @get:JvmName("getDNSCryptWhiteListPath")
    val dnsCryptWhiteListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/whitelist.txt"

    @get:JvmName("getDNSCryptSingleWhiteListPath")
    val dnsCryptSingleWhiteListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/whitelist-single.txt"

    @get:JvmName("getDNSCryptLocalWhiteListPath")
    val dnsCryptLocalWhiteListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/whitelist-local.txt"

    @get:JvmName("getDNSCryptRemoteWhiteListPath")
    val dnsCryptRemoteWhiteListPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/whitelist-remote.txt"

    @get:JvmName("getDNSCryptCloakingRulesPath")
    val dnsCryptCloakingRulesPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/cloaking-rules.txt"

    @get:JvmName("getDNSCryptSingleCloakingRulesPath")
    val dnsCryptSingleCloakingRulesPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/cloaking-rules-single.txt"

    @get:JvmName("getDNSCryptLocalCloakingRulesPath")
    val dnsCryptLocalCloakingRulesPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/cloaking-rules-local.txt"

    @get:JvmName("getDNSCryptRemoteCloakingRulesPath")
    val dnsCryptRemoteCloakingRulesPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/cloaking-rules-remote.txt"

    @get:JvmName("getDNSCryptForwardingRulesPath")
    val dnsCryptForwardingRulesPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/forwarding-rules.txt"

    //Tor/I2P stripped: no pre-shipped onion/i2p default rules.
    @get:JvmName("getDNSCryptDefaultForwardingRule")
    val dnsCryptDefaultForwardingRule: String
        get() = ""

    @get:JvmName("getDNSCryptDefaultCloakingRule")
    val dnsCryptDefaultCloakingRule: String
        get() = ""

    @get:JvmName("getDNSCryptSingleForwardingRulesPath")
    val dnsCryptSingleForwardingRulesPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/forwarding-rules-single.txt"

    @get:JvmName("getDNSCryptLocalForwardingRulesPath")
    val dnsCryptLocalForwardingRulesPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/forwarding-rules-local.txt"

    @get:JvmName("getDNSCryptRemoteForwardingRulesPath")
    val dnsCryptRemoteForwardingRulesPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/forwarding-rules-remote.txt"

    @get:JvmName("getDNSCryptCaptivePortalsPath")
    val dnsCryptCaptivePortalsPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/captive-portals.txt"

    fun getDNSCryptPublicResolversPath(): String {
        return appDataDir + "/app_data/dnscrypt-proxy/public-resolvers.md"
    }

    fun getDNSCryptRelaysPath(): String {
        return appDataDir + "/app_data/dnscrypt-proxy/relays.md"
    }

    fun getDNSCryptOwnResolversPath(): String {
        return appDataDir + "/app_data/dnscrypt-proxy/own-resolvers.md"
    }

    fun getOdohServersPath(): String {
        return appDataDir + "/app_data/dnscrypt-proxy/odoh-servers.md"
    }

    fun getOdohRelaysPath(): String {
        return appDataDir + "/app_data/dnscrypt-proxy/odoh-relays.md"
    }

    fun getCacheDirPath(context: Context): String {
        var cacheDirPath = "/storage/emulated/0/Android/data/" + context.packageName + "/cache"

        try {
            var cacheDir = context.externalCacheDir
            if (cacheDir == null) {
                cacheDir = context.cacheDir
            }

            if (!cacheDir.isDirectory) {
                if (cacheDir.mkdirs()) {
                    logi("PathVars getCacheDirPath create cache dir success")
                    if (cacheDir.setReadable(true) && cacheDir.setWritable(true)) {
                        logi("PathVars getCacheDirPath chmod cache dir success")
                    } else {
                        loge("PathVars getCacheDirPath chmod cache dir failed")
                    }
                } else {
                    loge("PathVars getCacheDirPath create cache dir failed")
                }
            }

            cacheDirPath = cacheDir.canonicalPath

        } catch (e: Exception) {
            loge("PathVars getCacheDirPath exception", e)
        }

        return cacheDirPath
    }

    val dnscryptConfPath: String
        get() = appDataDir + "/app_data/dnscrypt-proxy/dnscrypt-proxy.toml"

    val appUid: Int
        @Synchronized get() {
            if (cachedAppUid < 0) {
                cachedAppUid = Process.myUid()
            }
            return cachedAppUid
        }

    val appUidStr: String
        @Synchronized get() {
            if (cachedAppUidStr.isEmpty()) {
                cachedAppUidStr = appUid.toString()
            }
            return cachedAppUidStr
        }

    companion object {

        @JvmStatic
        fun isModulesInstalled(preferences: PreferenceRepository): Boolean {
            return preferences.getBoolPreference("DNSCrypt Installed")
        }
    }
}
