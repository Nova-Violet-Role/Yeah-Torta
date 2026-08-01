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

package pillar.kuma_saimono.libumdnscrypt.patches

import android.content.Context
import android.content.SharedPreferences
import androidx.annotation.WorkerThread
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.BuildConfig
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.QUAD_DNS_41
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_BOOTSTRAP_RESOLVERS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.IGNORE_SYSTEM_DNS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PREVENT_DNS_LEAKS
import java.util.concurrent.atomic.AtomicBoolean

private const val SAVED_VERSION_CODE = "SAVED_VERSION_CODE"

class Patch(private val context: Context, private val pathVars: PathVars) {

    private companion object {
        val patchingIsInProgress = AtomicBoolean(false)
    }

    private val dnsCryptConfigPatches = mutableListOf<AlterConfig>()

    private val preferenceRepository = App.instance.daggerComponent.getPreferenceRepository()

    @WorkerThread
    fun checkPatches(forceCheck: Boolean) {

        if (patchingIsInProgress.compareAndSet(false, true)) {
            try {
                tryCheckPatches(forceCheck)
            } finally {
                patchingIsInProgress.getAndSet(false)
            }
        }
    }

    private fun tryCheckPatches(forceCheck: Boolean) {
        val currentVersion = BuildConfig.VERSION_CODE
        val currentVersionSaved = preferenceRepository.get().getIntPreference(SAVED_VERSION_CODE)

        if (currentVersionSaved != 0 && currentVersion > currentVersionSaved || forceCheck) {
            try {
                val configUtil = ConfigUtil(context)

                removeQuad9FromBrokenImplementation()
                changeV2DNSCryptUpdateSourcesToV3()
                replaceBlackNames()
                fallbackResolverToBootstrapResolvers()
                removeDNSCryptDaemonize()
                addDNSCryptOdohServers()
                setPreventDnsLeaks(currentVersionSaved)

                if (dnsCryptConfigPatches.isNotEmpty()) {
                    configUtil.patchDNSCryptConfig(dnsCryptConfigPatches)
                }

                preferenceRepository.get().setIntPreference(SAVED_VERSION_CODE, currentVersion)
            } catch (e: Exception) {
                loge("Patch checkPatches", e, true)
            }

        } else if (currentVersionSaved == 0) {
            preferenceRepository.get()
                .setIntPreference(SAVED_VERSION_CODE, currentVersion)
        }
    }

    private fun removeQuad9FromBrokenImplementation() {
        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "[broken_implementations]",
                Regex("fragments_blocked =.*quad9-dnscrypt.*"),
                "fragments_blocked = ['cisco', 'cisco-ipv6', 'cisco-familyshield'," +
                        " 'cisco-familyshield-ipv6', 'cleanbrowsing-adult', 'cleanbrowsing-family-ipv6'," +
                        " 'cleanbrowsing-family', 'cleanbrowsing-security']"
            )
        )
    }

    private fun changeV2DNSCryptUpdateSourcesToV3() {
        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "",
                Regex(".*v2/public-resolvers.md.*"),
                "urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md'," +
                        " 'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md']"
            )
        )
        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "",
                Regex(".*v2/relays.md.*"),
                "urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md'," +
                        " 'https://download.dnscrypt.info/resolvers-list/v3/relays.md']"
            )
        )
    }

    private fun replaceBlackNames() {
        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "[blacklist]",
                Regex("blacklist_file = 'blacklist.txt'"), "blocked_names_file = 'blacklist.txt'"
            )
        )
        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "[ip_blacklist]",
                Regex("blacklist_file = 'ip-blacklist.txt'"),
                "blocked_ips_file = 'ip-blacklist.txt'"
            )
        )
        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "[whitelist]",
                Regex("whitelist_file = 'whitelist.txt'"), "allowed_names_file = 'whitelist.txt'"
            )
        )

        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "",
                Regex("\\[blacklist]"), "[blocked_names]"
            )
        )
        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "",
                Regex("\\[ip_blacklist]"), "[blocked_ips]"
            )
        )
        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "",
                Regex("\\[whitelist]"), "[allowed_names]"
            )
        )
    }

    private fun fallbackResolverToBootstrapResolvers() {
        val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        var fallbackResolver = QUAD_DNS_41

        when {
            sharedPreferences.contains(DNSCRYPT_BOOTSTRAP_RESOLVERS) -> {
                fallbackResolver =
                    extractResolverIp(sharedPreferences, DNSCRYPT_BOOTSTRAP_RESOLVERS)
            }

            sharedPreferences.contains("fallback_resolvers") -> {
                fallbackResolver = extractResolverIp(sharedPreferences, "fallback_resolvers")
                sharedPreferences.edit()
                    .putString(DNSCRYPT_BOOTSTRAP_RESOLVERS, fallbackResolver)
                    .remove("fallback_resolvers")
                    .apply()
            }

            sharedPreferences.contains("fallback_resolver") -> {
                fallbackResolver = extractResolverIp(sharedPreferences, "fallback_resolver")
                sharedPreferences.edit()
                    .putString(DNSCRYPT_BOOTSTRAP_RESOLVERS, fallbackResolver)
                    .remove("fallback_resolver")
                    .apply()
            }
        }

        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "",
                Regex("fallback_resolver =.+"), "bootstrap_resolvers = ['$fallbackResolver:53']"
            )
        )
        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "",
                Regex("fallback_resolvers =.+"), "bootstrap_resolvers = ['$fallbackResolver:53']"
            )
        )
    }

    private fun extractResolverIp(
        sharedPreferences: SharedPreferences,
        preferenceKey: String,
    ): String {
        val defaultValue = QUAD_DNS_41
        val ipRegex =
            Regex("((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
        val fallbackResolversPreference = sharedPreferences
            .getString(preferenceKey, defaultValue)?.trim() ?: defaultValue
        val matcher = ipRegex.toPattern().matcher(fallbackResolversPreference)
        if (matcher.find()) {
            return matcher.group()
        }
        return defaultValue
    }

    private fun removeDNSCryptDaemonize() {
        dnsCryptConfigPatches.add(
            AlterConfig.ReplaceLine(
                "",
                Regex("daemonize.+"), ""
            )
        )
    }

    private fun enableDNSCryptRequireNoFilterByDefault(savedVersion: Int) {
        if (pathVars.appVersion.endsWith("p") && (savedVersion <= 2143 || savedVersion <= 3143)) {

            PreferenceManager.getDefaultSharedPreferences(context)
                .edit()
                .putBoolean("require_nofilter", true)
                .apply()

            dnsCryptConfigPatches.add(
                AlterConfig.ReplaceLine(
                    "",
                    Regex("require_nofilter ?=.+"),
                    "require_nofilter = true"
                )
            )
        }
    }

    private fun addDNSCryptOdohServers() {
        dnsCryptConfigPatches.add(
            AlterConfig.AddLine(
                "",
                Regex("doh_servers = .+"),
                "odoh_servers = true"
            )
        )
    }

    private fun setPreventDnsLeaks(savedVersion: Int) {
        if (pathVars.appVersion.startsWith("f") && savedVersion.toString().take(3)
                .toInt() <= 244
            || !pathVars.appVersion.startsWith("f") && savedVersion.toString()
                .takeLast(3).toInt() <= 244
        ) {
            val defaultPreferences = PreferenceManager.getDefaultSharedPreferences(context)
            if (defaultPreferences.getBoolean(IGNORE_SYSTEM_DNS, false)
                && !defaultPreferences.getBoolean(PREVENT_DNS_LEAKS, false)
            ) {
                defaultPreferences.edit().putBoolean(PREVENT_DNS_LEAKS, true).apply()
            }
        }
    }

}
