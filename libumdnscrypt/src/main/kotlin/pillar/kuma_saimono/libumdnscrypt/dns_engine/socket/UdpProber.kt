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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.socket

import pillar.kuma_saimono.libumdnscrypt.dns_engine.core.DnsQueryBuilder
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Stateless single-shot UDP DNS prober: one ephemeral [DatagramSocket] per probe.
 * Measures wall-clock RTT to an upstream resolver and validates the reply by query-id.
 * Pure java.net (no root). The DSCP hint is best-effort and silently dropped if the OS
 * or network won't honour it — we never depend on it.
 */
object UdpProber {
    private const val RECV_BUF = 512
    private const val DSCP_EF = 0xB8

    /**
     * Fire one UDP A-query for [domain] at [host]:[port], waiting up to [timeoutMs].
     * Returns the measured RTT in ms on a matching reply, or -1.0 on timeout/error.
     */
    fun probe(host: String, port: Int, domain: String, queryId: Int, timeoutMs: Int): Double {
        var sock: DatagramSocket? = null
        return try {
            val query = DnsQueryBuilder.buildQuery(domain, queryId)
            val addr = InetAddress.getByName(host)
            sock = DatagramSocket()
            sock.soTimeout = timeoutMs
            try { sock.trafficClass = DSCP_EF } catch (_: Exception) { /* best-effort */ }
            val start = System.currentTimeMillis()
            sock.send(DatagramPacket(query, query.size, addr, port))
            val reply = DatagramPacket(ByteArray(RECV_BUF), RECV_BUF)
            sock.receive(reply)
            val rtt = (System.currentTimeMillis() - start).toDouble()
            // reject stray datagrams: the reply's 16-bit id must echo our query id
            if (reply.length >= 2 && reply.data[0] == query[0] && reply.data[1] == query[1]) rtt else -1.0
        } catch (_: Exception) {
            -1.0
        } finally {
            try { sock?.close() } catch (_: Exception) { /* ignore */ }
        }
    }
}
