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

package pillar.kuma_saimono.libumdnscrypt.utils.portchecker

import pillar.kuma_saimono.libumdnscrypt.utils.Constants.LOOPBACK_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.MAX_PORT_NUMBER
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.NUMBER_REGEX
import java.net.ConnectException
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import javax.inject.Inject

class PortChecker @Inject constructor() {

    fun isPortBusy(port: String): Boolean {
        val portInt: Int
        if (port.matches(NUMBER_REGEX.toRegex()) && port.length <= 5 && port.toLong() <= MAX_PORT_NUMBER) {
            portInt = port.toInt()
        } else {
            return true
        }
        return !isPortAvailable(portInt)
    }

    fun isPortAvailable(port: Int): Boolean {
        if (isTCPPortAvailable(port)) {
            return isUDPPortAvailable(port)
        }
        return false
    }

    fun getFreePort(port: String): String {

        if (!port.matches(NUMBER_REGEX.toRegex()) || port.length > 5 || port.toLong() > MAX_PORT_NUMBER) {
            return port
        }

        val portInt = port.toInt()

        for (i in 0 until 3) {
            val freePort = portInt + i + 1
            if (isPortAvailable(freePort)) {
                return freePort.toString()
            }
        }
        return port
    }

    private fun isTCPPortAvailable(port: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(LOOPBACK_ADDRESS, port), 200)
                socket.soTimeout = 1
                false
            }
        } catch (e: ConnectException) {
            true
        } catch (e: SocketTimeoutException) {
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun isUDPPortAvailable(port: Int): Boolean {
        try {
            DatagramSocket(port).use { socket ->
                socket.soTimeout = 1
                return true
            }
        } catch (ignored: Exception) {
        }
        return false
    }
}
