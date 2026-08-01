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

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import pillar.kuma_saimono.libumdnscrypt.dns_engine.core.DnsQueryBuilder
import java.io.InputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * A small pool of pipelined TCP/53 connections to one upstream resolver, driven by the YeAH
 * window. Each slot has a background reader coroutine that demuxes length-prefixed DNS replies
 * back to their awaiting probe by query-id (RFC 7766 pipelining). Port of the C# connection-pool
 * half of MonokumaTcpDnsEngine. No root: plain java.net sockets, app-level pacing only.
 */
class ConnectionPool(
    private val host: String,
    private val port: Int,
    private val scope: CoroutineScope,
) {
    companion object {
        const val MIN_SLOTS = 2
        const val MAX_SLOTS = 8
        private const val MAX_DNS_MSG = 4096
    }

    private val poolLock = Any()
    private val pool = ArrayList<ConnectionSlot>(MAX_SLOTS)

    /** qid -> awaiting probe; completed by the owning slot's reader when the reply lands. */
    private val pendingQueries = ConcurrentHashMap<Int, CompletableDeferred<ByteArray>>()
    private val queryIdCounter = AtomicInteger(0)

    val aliveCount: Int get() = synchronized(poolLock) { pool.count { !it.isDead } }
    val size: Int get() = synchronized(poolLock) { pool.size }
    val pendingCount: Int get() = pendingQueries.size

    fun bestRttMs(): Double = synchronized(poolLock) {
        pool.filter { !it.isDead && it.rttEwma > 0.0 }.minOfOrNull { it.rttEwma } ?: 0.0
    }

    private fun nextQueryId(): Int = queryIdCounter.incrementAndGet() and 0xFFFF

    suspend fun warm() = resize(MIN_SLOTS)

    /** Grow/shrink the pool toward [target] (clamped to [MIN_SLOTS]..[MAX_SLOTS]); prune dead/aged. */
    suspend fun resize(target: Int) {
        val t = target.coerceIn(MIN_SLOTS, MAX_SLOTS)
        val now = System.currentTimeMillis()
        synchronized(poolLock) {
            val it = pool.iterator()
            while (it.hasNext()) {
                val s = it.next()
                if (s.isDead || s.isAged(now)) { s.close(); it.remove() }
            }
            while (pool.size > t) {
                val worst = pool.maxByOrNull { it.rttEwma } ?: break
                worst.close(); pool.remove(worst)
            }
        }
        // connect outside the lock — a blocking connect must not stall other pool ops
        withContext(Dispatchers.IO) {
            while (size < t) {
                val slot = createSlot() ?: break
                synchronized(poolLock) { if (pool.size < t) pool.add(slot) else slot.close() }
            }
        }
    }

    private fun createSlot(): ConnectionSlot? {
        val slot = ConnectionSlot(host, port)
        return try {
            slot.connect(System.currentTimeMillis())
            startReader(slot)
            slot
        } catch (_: Exception) {
            slot.close(); null
        }
    }

    private fun startReader(slot: ConnectionSlot) {
        scope.launch(Dispatchers.IO) {
            val input = slot.input ?: return@launch
            val lenBuf = ByteArray(2)
            try {
                while (isActive && !slot.isDead) {
                    if (!readFully(input, lenBuf, 2)) break
                    val len = ((lenBuf[0].toInt() and 0xFF) shl 8) or (lenBuf[1].toInt() and 0xFF)
                    if (len <= 0 || len > MAX_DNS_MSG) break
                    val msg = ByteArray(len)
                    if (!readFully(input, msg, len)) break
                    val qid = ((msg[0].toInt() and 0xFF) shl 8) or (msg[1].toInt() and 0xFF)
                    pendingQueries.remove(qid)?.complete(msg)
                }
            } catch (_: Exception) {
                // drop through to failure marking
            } finally {
                slot.recordFailure()
            }
        }
    }

    private fun readFully(input: InputStream, buf: ByteArray, n: Int): Boolean {
        var off = 0
        while (off < n) {
            val r = input.read(buf, off, n - off)
            if (r < 0) return false
            off += r
        }
        return true
    }

    /**
     * Pipeline one A-query for [domain] over the lowest-RTT live slot, awaiting its reply up to
     * [timeoutMs]. Returns the measured RTT in ms, or -1.0 if no live slot / timeout / write error.
     * Records success (with rtt) or failure on the chosen slot to drive pool health + selection.
     */
    suspend fun sendProbe(domain: String, timeoutMs: Int): Double {
        val slot = bestAliveSlot() ?: return -1.0
        val out = slot.output ?: return -1.0
        val qid = nextQueryId()
        val query = DnsQueryBuilder.buildQuery(domain, qid)
        val framed = ByteArray(query.size + 2).also {
            it[0] = (query.size ushr 8).toByte()
            it[1] = (query.size and 0xFF).toByte()
            query.copyInto(it, 2)
        }
        val deferred = CompletableDeferred<ByteArray>()
        pendingQueries[qid] = deferred
        val start = System.currentTimeMillis()
        return try {
            synchronized(slot.writeLock) { out.write(framed); out.flush() }
            val reply = withTimeoutOrNull(timeoutMs.toLong()) { deferred.await() }
            if (reply != null) {
                val rtt = (System.currentTimeMillis() - start).toDouble()
                slot.recordSuccess(rtt); rtt
            } else {
                slot.recordFailure(); -1.0
            }
        } catch (_: Exception) {
            slot.recordFailure(); -1.0
        } finally {
            pendingQueries.remove(qid)
        }
    }

    private fun bestAliveSlot(): ConnectionSlot? = synchronized(poolLock) {
        // prefer the lowest measured RTT; unmeasured slots sort last but stay usable
        pool.filter { !it.isDead }
            .minByOrNull { if (it.rttEwma <= 0.0) Double.MAX_VALUE else it.rttEwma }
    }

    fun shutdown() {
        synchronized(poolLock) { pool.forEach { it.close() }; pool.clear() }
        pendingQueries.values.forEach { it.cancel() }
        pendingQueries.clear()
    }
}
