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

package pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker

import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.ProxyAuthManager.setDefaultAuth
import java.lang.Exception
import java.net.*
import javax.inject.Inject

private const val CONNECT_TIMEOUT_SEC = 50
private const val PING_TIMEOUT_SEC = 1
private const val CHECK_ADDRESS_REACHABLE_TIMEOUT_SEC = 3

class SocketInternetChecker @Inject constructor() {

    fun checkConnectionAvailability(
        ip: String,
        port: Int,
        proxyAddress: String,
        proxyPort: Int,
        proxyUser: String,
        proxyPass: String,
        connectTimeout: Int = CONNECT_TIMEOUT_SEC,
        reachableTimeout: Int = CHECK_ADDRESS_REACHABLE_TIMEOUT_SEC
    ): Boolean {

        var socket: Socket? = null

        try {
            socket = if (isProxyUsed(proxyAddress, proxyPort)) {
                setDefaultAuth(proxyUser, proxyPass)
                val proxySockAdr: SocketAddress = InetSocketAddress(
                    proxyAddress,
                    proxyPort
                )
                val proxy = Proxy(Proxy.Type.SOCKS, proxySockAdr)
                Socket(proxy)
            } else {
                Socket()
            }

            val sockAddress: SocketAddress =
                InetSocketAddress(InetAddress.getByName(ip), port)

            socket.connect(sockAddress, connectTimeout * 1000)
            socket.soTimeout = 100

            return if (isProxyUsed(proxyAddress, proxyPort)) {
                socket.inetAddress.isReachable(reachableTimeout * 1000)
            } else {
                socket.isConnected
            }

        } finally {
            try {
                socket?.close()
            } catch (ignored: Exception) {
            }
        }
    }

    fun checkConnectionPing(
        ip: String,
        port: Int,
        proxyAddress: String,
        proxyPort: Int,
        proxyUser: String,
        proxyPass: String
    ): Int {

        var socket: Socket? = null
        val timeStart = System.currentTimeMillis()

        try {
            socket = if (isProxyUsed(proxyAddress, proxyPort)) {
                setDefaultAuth(proxyUser, proxyPass)
                val proxySockAdr: SocketAddress = InetSocketAddress(
                    proxyAddress,
                    proxyPort
                )
                val proxy = Proxy(Proxy.Type.SOCKS, proxySockAdr)
                Socket(proxy)
            } else {
                Socket()
            }

            val sockAddress: SocketAddress =
                InetSocketAddress(InetAddress.getByName(ip), port)

            socket.connect(sockAddress, PING_TIMEOUT_SEC * 1000)
            socket.soTimeout = PING_TIMEOUT_SEC * 1000

            if (isProxyUsed(proxyAddress, proxyPort)) {
                socket.shutdownOutput()
                socket.getInputStream().read(byteArrayOf(0))
                return ((System.currentTimeMillis() - timeStart) / 2).toInt()
            } else {
                if (socket.isConnected) {
                    val time = System.currentTimeMillis()
                    socket.shutdownOutput()
                    return (time - timeStart).toInt()
                }
            }

            return NO_CONNECTION

        } finally {
            try {
                socket?.close()
            } catch (ignored: Exception) {
            }
        }
    }

    private fun isProxyUsed(
        proxyAddress: String,
        proxyPort: Int
    ) = proxyAddress.isNotBlank() && proxyPort != 0

    companion object {
        const val NO_CONNECTION = -1
    }

}
