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

package pillar.kuma_saimono.libumdnscrypt.data.dnscrypt_servers

import android.content.SharedPreferences
import pillar.kuma_saimono.libumdnscrypt.data.modules_configuration.DnsCryptConfigurationDataSource
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.domain.dnscrypt_servers.ServersPingRepository
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.SocketInternetChecker.Companion.NO_CONNECTION
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_OUTBOUND_PROXY
import java.net.ConnectException
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.regex.Pattern
import javax.inject.Inject
import javax.inject.Named

class ServersPingRepositoryImpl @Inject constructor(
    private val serversPingDataSource: ServersPingDataSource,
    private val dnsCryptConfigurationDataSource: DnsCryptConfigurationDataSource,
    @Named(DEFAULT_PREFERENCES_NAME) private val defaultPreferences: SharedPreferences
) : ServersPingRepository {

    private val outboundProxyAddress = getDnsCryptOutboundProxyAddress()

    private val ipv4WithPortPattern =
        Pattern.compile("([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}):(\\d+)\\b")

    override fun getTimeout(address: String): Int = try {
        tryGetTimeout(address)
    } catch (_: SocketTimeoutException) {
        NO_CONNECTION
    } catch (_: ConnectException) {
        NO_CONNECTION
    } catch (e: Exception) {
        loge("ServersPingRepositoryImpl getTimeout", e)
        NO_CONNECTION
    }

    private fun tryGetTimeout(address: String): Int {
        val (ip, port) = getIpToPort(address)
        if (ip.isEmpty() || port == 0) {
            return NO_CONNECTION
        }

        return if (isDnsCryptOutboundProxyEnabled()) {
            val outboundProxyIp = outboundProxyAddress.substring(0, outboundProxyAddress.indexOf(":"))
            val outboundProxyPort = outboundProxyAddress.substring(outboundProxyAddress.indexOf(":") + 1)
            serversPingDataSource.checkTimeoutViaProxy(
                ip,
                port,
                outboundProxyIp,
                outboundProxyPort.toInt()
            )
        } else {
            serversPingDataSource.checkTimeoutDirectly(ip, port)
        }

        return NO_CONNECTION
    }

    //Address example: 1.2.3.4:123 or [1:2:3:4]:123 or www.host.com:123
    private fun getIpToPort(address: String): Pair<String, Int> {
        var ip = ""
        var port = 0
        val ipv6Address = address.isIPv6Address()
        if (ipv6Address) {
            ip = address.substring(address.indexOf("[") + 1, address.indexOf("]"))
            port = address.substring(address.indexOf("]") + 2).toInt()
        } else {
            val matcher = ipv4WithPortPattern.matcher(address)
            if (matcher.find()) {
                ip = matcher.group(1) ?: ""
                port = matcher.group(2)?.toInt() ?: 0
            } else if (address.contains(":")) {
                val host = address.substring(0, address.indexOf(":"))
                port = address.substring(address.indexOf(":") + 1).toInt()
                ip = try {
                    InetAddress.getAllByName(host).filter {
                        !it.isLoopbackAddress && !it.isAnyLocalAddress
                    }.minByOrNull {
                        it?.hostAddress?.isIPv6Address() == false
                    }?.hostAddress ?: ""
                } catch (e: Exception) {
                    loge("ServersPingRepositoryImpl tryGetTimeout", e)
                    ""
                }
            }
        }
        return Pair(ip, port)
    }

    private fun String.isIPv6Address() = contains("[") && contains("]")

    private fun isDnsCryptOutboundProxyEnabled() =
        defaultPreferences.getBoolean(DNSCRYPT_OUTBOUND_PROXY, false)

    private fun getDnsCryptOutboundProxyAddress() =
        dnsCryptConfigurationDataSource.getDnsCryptOutboundProxyAddress()
}
