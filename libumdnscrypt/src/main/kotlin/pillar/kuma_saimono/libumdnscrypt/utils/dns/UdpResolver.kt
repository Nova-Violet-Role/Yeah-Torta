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

package pillar.kuma_saimono.libumdnscrypt.utils.dns

import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

class UdpResolver @AssistedInject constructor(
    @Assisted serverIP: String,
    @Assisted("port") dnsUdpPort: Int,
    @Assisted("type") type: Int,
    @Assisted("timeout") timeout: Int
) : DnsResolver(serverIP, type, timeout) {

    private val dnsUdpPort: Int = dnsUdpPort

    @Throws(IOException::class)
    internal override fun request(server: String, host: String, recordType: Int): DnsResponse? {
        val d = Math.random()
        val messageId = (d * 0xFFFF).toInt().toShort()
        val request = DnsRequest(messageId, recordType, host)
        val requestData = request.toDnsQuestionData()

        val address = InetAddress.getByName(server)
        return DatagramSocket().use { socket ->
            var packet = DatagramPacket(
                requestData, requestData.size,
                address, dnsUdpPort
            )
            socket.soTimeout = timeout * 1000
            socket.send(packet)
            packet = DatagramPacket(ByteArray(1500), 1500)
            socket.receive(packet)
            DnsResponse(server, Record.Source.Udp, request, packet.data)
        }
    }
}
