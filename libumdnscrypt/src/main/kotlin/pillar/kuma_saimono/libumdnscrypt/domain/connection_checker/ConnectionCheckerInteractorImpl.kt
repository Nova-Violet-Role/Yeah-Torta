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

package pillar.kuma_saimono.libumdnscrypt.domain.connection_checker

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import kotlinx.coroutines.*
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule.Companion.SUPERVISOR_JOB_IO_DISPATCHER_SCOPE
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.dns_resolver.DnsRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.DEFAULT_PROXY_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.DNS_GOOGLE
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.DNS_MOZILLA
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.DNS_QUAD9
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.LOOPBACK_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.MAX_PORT_NUMBER
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.NUMBER_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.PLAINTEXT_DNS_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.USE_PROXY
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PROXY_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PROXY_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PROXY_USER
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.PROXY_PASS
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils
import java.io.IOException
import java.lang.ref.WeakReference
import java.net.Inet4Address
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import javax.inject.Inject
import javax.inject.Named
import javax.inject.Singleton

private const val CHECK_INTERVAL_SEC = 10
private const val ADDITIONAL_DELAY_SEC = 30
private const val CHECK_SOCKET_TIMEOUT_SEC = 20
private const val CHECKING_LOOP_TIMEOUT_MINT = 20
private const val CHECKING_TIMEOUT_SEC = 120

@Singleton
class ConnectionCheckerInteractorImpl @Inject constructor(
    private val checkerRepository: ConnectionCheckerRepository,
    private val pathVars: PathVars,
    @Named(SUPERVISOR_JOB_IO_DISPATCHER_SCOPE)
    private val baseCoroutineScope: CoroutineScope,
    private val dnsRepository: DnsRepository,
    @Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: SharedPreferences,
    private val context: Context
) : ConnectionCheckerInteractor {

    private val coroutineScope = baseCoroutineScope + CoroutineName("ConnectionCheckerInteractor")

    private val listenersMap =
        ConcurrentHashMap<String, WeakReference<OnInternetConnectionCheckedListener>>()
    private val modulesStatus = ModulesStatus.getInstance()

    private val checking by lazy { AtomicBoolean(false) }

    @Volatile
    private var internetAvailable = false

    @Volatile
    private var networkAvailable = false

    @Volatile
    private var networkAvailableViaNetworkCallback = false

    @Volatile
    private var task: Job? = null

    @Synchronized
    override fun <T : OnInternetConnectionCheckedListener> addListener(listener: T) {
        listenersMap[listener.javaClass.name] = WeakReference(listener)
    }

    @Synchronized
    override fun <T : OnInternetConnectionCheckedListener> removeListener(listener: T) {

        listenersMap.remove(listener.javaClass.name)
        if (listenersMap.isEmpty()) {
            task?.let {
                if (!it.isCompleted) {
                    it.cancel()
                }
            }
            task = null
        }
    }

    override fun getInternetConnectionResult(): Boolean = internetAvailable

    override fun setInternetConnectionResult(internetIsAvailable: Boolean) {
        this.internetAvailable = internetIsAvailable
    }

    override fun checkNetworkConnection() {
        networkAvailable =
            networkAvailableViaNetworkCallback || checkerRepository.checkNetworkAvailable()
    }

    override fun getNetworkConnectionResult(): Boolean =
        networkAvailableViaNetworkCallback || networkAvailable

    override fun setNetworkConnectionResult(networkIsAvailable: Boolean) {
        networkAvailableViaNetworkCallback = networkIsAvailable
    }

    override fun isFreeWiFiAccessPointDetected(): Boolean {
        return checkerRepository.isCaptivePortalOnWiFiDetected()
    }

    override fun checkInternetConnection() {
        if (checking.compareAndSet(false, true)) {
            checkConnection()
        }
    }

    private fun checkConnection() {

        if (task?.isCompleted == false) {
            task?.cancel()
        }

        task = coroutineScope.launch {
            tryCheckConnection()
        }
    }

    private suspend fun tryCheckConnection() {
        try {
            withTimeout(CHECKING_LOOP_TIMEOUT_MINT * 60_000L) {
                while (isActive && !internetAvailable) {

                    checkNetworkConnection()
                    if (!getNetworkConnectionResult()) {
                        makeDelay(CHECK_INTERVAL_SEC)
                        continue
                    }

                    val via = Via.DIRECT

                    val available = try {
                        withTimeout(CHECKING_TIMEOUT_SEC * 1000L) {
                            check(via)
                        }
                    } catch (e: SocketTimeoutException) {
                        logException(via, e)
                        false
                    } catch (e: IOException) {
                        logException(via, e)
                        makeDelay(ADDITIONAL_DELAY_SEC)
                        false
                    } catch (e: Exception) {
                        logException(via, e)
                        false
                    }

                    ensureActive()

                    logi("Internet is ${if (available) "available" else "not available"}")

                    internetAvailable = available

                    informListeners(available)

                    if (!available) {
                        makeDelay(CHECK_INTERVAL_SEC)
                    }
                }

                checking.getAndSet(false)
            }
        } catch (e: Exception) {
            if (e !is CancellationException) {
                loge("ConnectionCheckerInteractor tryCheckConnection", e)
            }
        } finally {
            checking.compareAndSet(true, false)
        }
    }

    private fun informListeners(available: Boolean) {
        val iterator = listenersMap.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value.get()?.isActive() == true) {
                entry.value.get()?.onConnectionChecked(available)
            } else {
                iterator.remove()
            }
        }
    }

    private suspend fun makeDelay(delaySec: Int) {
        try {
            delay(delaySec * 1000L)
        } catch (_: Exception) {
        }
    }

    private fun logException(via: Via, e: Exception) {
        loge("CheckConnectionInteractor checkConnection via $via", e)
    }

    private suspend fun check(via: Via): Boolean = coroutineScope {
        when (via) {
            Via.DIRECT -> {
                val proxyAddress =
                    defaultPreferences.getString(PROXY_ADDRESS, LOOPBACK_ADDRESS)
                        ?: LOOPBACK_ADDRESS
                val proxyPort = defaultPreferences.getString(PROXY_PORT, DEFAULT_PROXY_PORT).let {
                    if (it?.matches(Regex(NUMBER_REGEX)) == true && it.toLong() <= MAX_PORT_NUMBER) {
                        it.toInt()
                    } else {
                        DEFAULT_PROXY_PORT.toInt()
                    }
                }
                val proxyUser = defaultPreferences.getString(PROXY_USER, "") ?: ""
                val proxyPass = defaultPreferences.getString(PROXY_PASS, "") ?: ""
                val useProxy = defaultPreferences.getBoolean(USE_PROXY, false)
                        && proxyAddress.isNotBlank()
                        && proxyPort != 0

                if (useProxy && modulesStatus.mode == OperationMode.VPN_MODE) {
                    val site = sequenceOf(DNS_GOOGLE, DNS_QUAD9, DNS_MOZILLA).shuffled().first()

                    logi("Checking connection via Socks Proxy $proxyAddress:$proxyPort $site")

                    checkerRepository.checkInternetAvailableOverHttp(
                        site,
                        proxyAddress,
                        proxyPort,
                        proxyUser,
                        proxyPass
                    )
                } else {
                    val dnsForConnectivityCheck = getNetworkDns()
                        .plus(pathVars.dnsCryptFallbackRes.split(Regex(", ?")))
                        .filter {
                            if (modulesStatus.mode == OperationMode.ROOT_MODE) {
                                !it.isIPv6()
                            } else {
                                true
                            }
                        }
                        .shuffled()
                        .first()

                    logi("Checking connection directly using $dnsForConnectivityCheck")

                    checkerRepository.checkInternetAvailableOverSocks(
                        dnsForConnectivityCheck,
                        PLAINTEXT_DNS_PORT,
                        "",
                        0,
                        "",
                        ""
                    )
                }

            }
        }

    }

    private fun getNetworkDns(): List<String> = try {
        //Don't get network DNS if SDK_INT < O because jni_getprop("net.dns1") doesn't work well on all phones
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            VpnUtils.getDefaultDNS(context)
                .filter {
                    val dns = InetAddress.getByName(it)
                    !dns.isLoopbackAddress && !dns.isAnyLocalAddress && dns is Inet4Address
                }
        } else {
            emptyList()
        }
    } catch (_: Exception) {
        pathVars.dnsCryptFallbackRes.split(Regex(", ?"))
    }

    private fun String.isIPv6() = contains(":")

    private enum class Via {
        DIRECT
    }
}
