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

package pillar.kuma_saimono.libumdnscrypt.utils.connectivitycheck

import android.content.SharedPreferences
import kotlinx.coroutines.*
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule.Companion.DISPATCHER_IO
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.domain.dns_resolver.DnsInteractor
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv4_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv6_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import javax.inject.Inject
import javax.inject.Named

private const val GSTATIC_CONNECTIVITY_CHECK_URL = "connectivitycheck.gstatic.com"
private const val GSTATIC_CONNECTIVITY_CHECK_DEFAULT_IPS =
    "142.251.39.3, 64.233.164.94, 74.125.132.94, 74.125.20.94, 142.250.180.227, 64.233.185.94, 142.251.39.67, 74.125.21.94, 64.233.162.94"
private const val ANDROID_CONNECTIVITY_CHECK_URL = "connectivitycheck.android.com"
private const val ANDROID_CONNECTIVITY_CHECK_DEFAULT_IPS =
    "64.233.162.102, 64.233.162.113, 64.233.162.101, 142.250.180.238, 64.233.162.100, 142.250.180.206, 142.251.39.46, 64.233.162.139, 64.233.162.138, 172.217.20.14"
private const val GET_CONNECTIVITY_CHECK_IPS_TIME_INTERVAL_HRS = 1
private const val ATTEMPTS_RESOLVE_DOMAIN = 5
private const val RESOLVE_TIMEOUT_SEC = 10

@ModulesServiceScope
class ConnectivityCheckManager @Inject constructor(
    private val pathVars: PathVars,
    private val dnsInteractor: DnsInteractor,
    @Named(DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: dagger.Lazy<SharedPreferences>,
    @Named(DISPATCHER_IO)
    dispatcherIo: CoroutineDispatcher

) {

    private val coroutineScope = CoroutineScope(
        SupervisorJob() +
                dispatcherIo +
                CoroutineName("ConnectivityCheckManager") +
                CoroutineExceptionHandler { _, throwable ->
                    loge("ConnectivityCheckManager uncaught exception", throwable, true)
                }
    )

    private val ip4Regex by lazy { Regex(IPv4_REGEX) }
    private val ip6Regex by lazy { Regex(IPv6_REGEX) }

    @Volatile
    private var connectivityCheckTimeToIps = Pair<Long, Set<String>>(0, emptySet())

    private val updatingInProgress = AtomicBoolean(false)

    fun getConnectivityCheckIps(): Set<String> {

        if (System.currentTimeMillis() - connectivityCheckTimeToIps.first < GET_CONNECTIVITY_CHECK_IPS_TIME_INTERVAL_HRS * 3600 * 1000) {
            return connectivityCheckTimeToIps.second
        }

        val connectivityCheckIps = hashSetOf<String>()

        try {
            var lines = readDnsCryptCaptivePortalsFile()

            if (lines.isEmpty()) {
                createDnsCryptCaptivePortalsFile()
            }

            lines = readDnsCryptCaptivePortalsFile()

            if (lines.isEmpty()) {
                return connectivityCheckIps
            }

            for (line in lines) {
                if (!line.startsWith("#") && line.contains(GSTATIC_CONNECTIVITY_CHECK_URL)) {
                    connectivityCheckIps.addAll(
                        getIpsFromLine(
                            line,
                            GSTATIC_CONNECTIVITY_CHECK_URL
                        )
                    )
                } else if (!line.startsWith("#") && line.contains(ANDROID_CONNECTIVITY_CHECK_URL)) {
                    connectivityCheckIps.addAll(
                        getIpsFromLine(
                            line,
                            ANDROID_CONNECTIVITY_CHECK_URL
                        )
                    )
                }
            }

            connectivityCheckTimeToIps = Pair(System.currentTimeMillis(), connectivityCheckIps)
        } catch (e: Exception) {
            loge("ConnectivityCheckManager getConnectivityCheckIps", e)
        }

        if (updatingInProgress.compareAndSet(false, true)) {
            coroutineScope.launch { updateCaptivePortalsFile() }
        }

        return connectivityCheckIps
    }

    fun refreshConnectivityCheckIPs() {
        if (updatingInProgress.compareAndSet(false, true)) {
            coroutineScope.launch { updateCaptivePortalsFile() }
        }
    }

    private suspend fun updateCaptivePortalsFile() {
        try {

            val lines = readDnsCryptCaptivePortalsFile()

            if (lines.isEmpty()) {
                return
            }

            val prefs = defaultPreferences.get()
            val blockIPv6DnsCrypt: Boolean =
                prefs.getBoolean(TortaeKeys.DNSCRYPT_BLOCK_IPv6, false)
            val includeIPv6 = (ModulesStatus.getInstance().mode != OperationMode.ROOT_MODE
                    && !blockIPv6DnsCrypt)

            val fileNewLines = mutableListOf<String>()
            for (line in lines) {
                if (!line.startsWith("#") && line.contains(GSTATIC_CONNECTIVITY_CHECK_URL)) {
                    getGstaticConnectivityCheckIpsLine(line, includeIPv6).also {
                        fileNewLines.add(it)
                    }
                } else if (!line.startsWith("#") && line.contains(ANDROID_CONNECTIVITY_CHECK_URL)) {
                    getLineAndUpdateAndroidConnectivityCheckIps(line, includeIPv6).also {
                        fileNewLines.add(it)
                    }
                } else {
                    fileNewLines.add(line)
                }
            }

            if (lines.size != fileNewLines.size || !lines.containsAll(fileNewLines)) {
                writeDnsCryptCaptivePortalsFile(fileNewLines)
            }

        } catch (e: Exception) {
            loge("ConnectivityCheckManager getIpsAndUpdateCaptivePortalsFile", e)
        } finally {
            updatingInProgress.getAndSet(false)
        }
    }

    private suspend fun getGstaticConnectivityCheckIpsLine(
        line: String,
        includeIPv6: Boolean
    ): String {

        val ips = resolveIps("https://$GSTATIC_CONNECTIVITY_CHECK_URL", includeIPv6)

        return when {
            ips.size == 1 -> {
                val appendedIps = getIpsFromLine(line, GSTATIC_CONNECTIVITY_CHECK_URL)
                    .also {
                        it.add(ips.first())
                    }
                "$GSTATIC_CONNECTIVITY_CHECK_URL   ${appendedIps.joinToString(", ")}"
            }
            ips.size > 1 -> {
                "$GSTATIC_CONNECTIVITY_CHECK_URL   ${ips.joinToString(", ")}"
            }
            else -> {
                line
            }
        }
    }

    private suspend fun getLineAndUpdateAndroidConnectivityCheckIps(
        line: String,
        includeIPv6: Boolean
    ): String {

        val ips = resolveIps("https://$ANDROID_CONNECTIVITY_CHECK_URL", includeIPv6)

        return when {
            ips.size == 1 -> {
                val appendedIps =
                    getIpsFromLine(line, ANDROID_CONNECTIVITY_CHECK_URL)
                        .also {
                            it.add(ips.first())
                        }

                "$ANDROID_CONNECTIVITY_CHECK_URL   ${appendedIps.joinToString(", ")}"

            }
            ips.size > 1 -> {
                "$ANDROID_CONNECTIVITY_CHECK_URL   ${ips.joinToString(", ")}"
            }
            else -> {
                line
            }
        }
    }

    private fun readDnsCryptCaptivePortalsFile() =
        File(pathVars.dnsCryptCaptivePortalsPath).let { file ->
            if (file.isFile) {
                file.bufferedReader().use { it.readLines() }
            } else {
                emptyList()
            }
        }

    private fun createDnsCryptCaptivePortalsFile() =
        File(pathVars.dnsCryptCaptivePortalsPath).also {
            if (it.createNewFile()) {
                writeDnsCryptCaptivePortalsFile(
                    listOf(
                        "$GSTATIC_CONNECTIVITY_CHECK_URL $GSTATIC_CONNECTIVITY_CHECK_DEFAULT_IPS",
                        "$ANDROID_CONNECTIVITY_CHECK_URL $ANDROID_CONNECTIVITY_CHECK_DEFAULT_IPS"
                    )
                )
            }
        }

    private fun writeDnsCryptCaptivePortalsFile(lines: List<String>) =
        File(pathVars.dnsCryptCaptivePortalsPath).printWriter().use {
            lines.forEach { line ->
                if (line != "\n") {
                    it.println(line)
                }
            }
        }

    private fun getIpsFromLine(line: String, url: String) =
        line.replace(Regex("$url\\s+"), "")
            .split(", ")
            .filter { it.matches(ip4Regex) || it.matches(ip6Regex) }
            .toHashSet()

    private suspend fun resolveIps(
        url: String,
        includeIPv6: Boolean,
        attempt: Int = 0
    ): Set<String> = try {
        if (attempt < ATTEMPTS_RESOLVE_DOMAIN) {
            if (attempt > 0) {
                delay(attempt * 3000L)
            }
            dnsInteractor.resolveDomain(url, false, RESOLVE_TIMEOUT_SEC)
        } else {
            emptySet()
        }
    } catch (e: Exception) {
        loge("ConnectivityCheckManager resolveIps $url attempt:${attempt + 1}", e)
        resolveIps(url, includeIPv6, attempt + 1)
    }

}
