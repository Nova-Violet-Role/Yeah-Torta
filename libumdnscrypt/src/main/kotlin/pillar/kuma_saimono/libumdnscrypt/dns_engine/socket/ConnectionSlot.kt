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

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * One pooled TCP connection to an upstream DNS resolver (port 53), with health tracking.
 * Port of the C# connection-slot in MonokumaTcpDnsEngine: EWMA rtt, fail counter, age check.
 * Pure java.net — no root, no special privilege. Reads/writes are driven by [ConnectionPool].
 */
class ConnectionSlot(
    val host: String,
    val port: Int,
) {
    companion object {
        const val MAX_FAILS = 3
        const val MAX_AGE_MS = 30 * 60 * 1000L // recycle after 30 min
        const val CONNECT_TIMEOUT_MS = 3000
        private const val RTT_ALPHA = 0.2
        private const val DSCP_EF = 0xB8 // Expedited-Forwarding hint; best-effort, ignored without root
    }

    /** Serializes pipelined writes from concurrent probes onto this one socket. */
    val writeLock = Any()

    @Volatile
    var socket: Socket? = null
        private set

    @Volatile
    var input: InputStream? = null
        private set

    @Volatile
    var output: OutputStream? = null
        private set

    @Volatile
    var rttEwma: Double = 0.0
        private set

    @Volatile
    private var failCount: Int = 0
    private var createdAtMs: Long = 0L

    val isDead: Boolean
        get() {
            val s = socket
            return failCount >= MAX_FAILS || s == null || s.isClosed || !s.isConnected
        }

    fun isAged(nowMs: Long): Boolean = createdAtMs > 0L && (nowMs - createdAtMs) > MAX_AGE_MS

    @Throws(IOException::class)
    fun connect(nowMs: Long) {
        val s = Socket()
        s.tcpNoDelay = true
        try { s.trafficClass = DSCP_EF } catch (_: Exception) { /* unsupported on some networks */ }
        s.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        socket = s
        input = s.getInputStream()
        output = s.getOutputStream()
        createdAtMs = nowMs
        failCount = 0
    }

    fun recordSuccess(rttMs: Double) {
        rttEwma = if (rttEwma <= 0.0) rttMs else (1 - RTT_ALPHA) * rttEwma + RTT_ALPHA * rttMs
        if (failCount > 0) failCount--
    }

    fun recordFailure() {
        failCount++
    }

    fun close() {
        try { socket?.close() } catch (_: Exception) { /* ignore */ }
        socket = null
        input = null
        output = null
    }
}
