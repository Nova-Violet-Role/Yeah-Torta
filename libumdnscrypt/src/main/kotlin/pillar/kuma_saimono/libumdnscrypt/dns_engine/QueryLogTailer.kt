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

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import pillar.kuma_saimono.libumdnscrypt.BuildConfig
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import java.io.File
import java.io.RandomAccessFile

/**
 * P7 Wave-3 / 2e — the **LIVE qname trigger** for the shadow resolver in DNSCrypt-VPN mode.
 *
 * **Why this exists.** This is a REDUNDANT second live trigger that runs ALONGSIDE the rr-seam
 * (`ServiceVPN.dnsResolved → shadowCompare(rr)`) in DNSCrypt-VPN mode — NOT a replacement for a "dark"
 * rr-seam. The rr-seam DOES fire here: the app dials a PUBLIC bootstrap DNS IP (`VpnBuilder` rejects
 * loopback), so the tun packet is born dest==53, and `s->udp.dest` STAYS 53 — `udp.c:326` records it
 * from the ORIGINAL packet BEFORE the socket-level loopback→`127.0.0.1:5354` redirect (`udp.c:449-457`,
 * which rewrites only the `sendto` target), so the reply gate `udp.c:143` (dest==53) is TRUE and the
 * rr-seam fires. (The earlier "fires zero times / empirically proven zero" claim is REFUTED, file:line-
 * grounded, per [[shadow-seam-unreachable-dnscrypt-mode]] 2026-06-19: the 2026-06-12 zero-compares was a
 * shadow-SIDE gate — configure-null / do53 reject — NOT structural unreachability.) The value this tailer
 * adds: a SECOND live qname signal sourced from the file `dnscrypt-proxy` writes **after** it has already
 * answered the app — its `[query_log]` — which also carries the RETURNCODE class. This tailer reads that
 * file append-only and feeds each resolved qname to [ResolverRuntime.shadowCompare], which re-resolves it
 * through the SAME loopback proxy (the do53 shadow upstream) and records resolver-health. Both seams fire
 * and share one egress pool; do NOT delete the rr-seam as dead code.
 *
 * **PRIME (read-only).** The file is opened strictly `"r"` ([RandomAccessFile]); this class NEVER
 * writes, truncates, shortens, or deletes it — unlike [pillar.kuma_saimono.libumdnscrypt.data.log_reader.OwnFileReader],
 * whose `readLastLines()` rewrites the file (FileShortener / PrintWriter) and would both violate PRIME
 * and race `dnscrypt-proxy`'s live appender. `dnscrypt-proxy` writes each query.log line only AFTER it
 * has returned the answer to the app, so this tail can never sit on, delay, or drop the real answer.
 *
 * **T20 (no qname re-logging).** A parsed qname is used ONLY to call [ResolverRuntime.shadowCompare];
 * it is NEVER logged, never re-emitted, never routed to any records pipeline. Every diagnostic line
 * here is qname-free (counts / the file path / error class). The one-time start log prints the file
 * PATH (appDataDir-derived, qname-free) so a soak can confirm the seam targets the right file.
 *
 * **Bounded egress.** None is added here: the in-flight cap + conflation live inside
 * [ResolverRuntime.shadowCompare]. This class only transports qnames; the budget is shared with the
 * rr-seam in exactly one place.
 *
 * **DEBUG-gate.** A privacy DNS app must NEVER ship query logging on. This whole class is inert in
 * release three ways: (1) it is only constructed + [start]ed / [stop]ped from [ResolverRuntime]'s
 * already-DEBUG-gated `onDnsCryptStarted` / `onDnsCryptStopped`; (2) the const-true `!BuildConfig.DEBUG`
 * guard in [start] lets the optimizer drop the body in release; (3) the `[query_log] file=` toml enable
 * (the producer) is itself DEBUG-gated, so in release `dnscrypt-proxy` writes no query.log at all and
 * even a stray [tailOnce] finds nothing.
 *
 * Bullet-proof: every tick is wrapped so a tailer throw (missing file, partial line, rotation, IO error)
 * is a counted, swallowed non-event — it can never surface into the datapath or kill the poll loop.
 */
class QueryLogTailer(
    private val pathVars: dagger.Lazy<PathVars>,
    private val dispatcherIo: CoroutineDispatcher,
    /** Called with each resolved (qname, returnCode) parsed from a new query.log line. T20: the callee
     *  uses the qname ONLY to drive the shadow — it is never logged here or there. */
    private val onQname: (qname: String, returnCode: String?) -> Unit,
) {

    /** Own private scope (not [ResolverRuntime]'s) so this file stays self-contained; lives for the
     *  tailer's start..stop window, which sits inside the ModulesService-scoped shadow's lifetime. */
    private val scope by lazy {
        CoroutineScope(
            SupervisorJob() +
                    dispatcherIo +
                    CoroutineName("QueryLogTailer") +
                    CoroutineExceptionHandler { _, t -> loge("QueryLogTailer uncaught exception", t) }
        )
    }

    @Volatile
    private var pollJob: Job? = null

    /** Byte offset of the next unread byte = position just past the last COMPLETE line consumed. A
     *  partial (newline-less) trailing line is intentionally NOT committed — it is re-read next tick. */
    @Volatile
    private var lastOffset: Long = 0L

    // qname-free diagnostics only (T20): never a qname, only counts + the resolved file path.
    private var linesParsed: Long = 0L
    private var tailErrors: Long = 0L

    /** Internal data dir + cache/query.log — the SAME string the toml producer writes the file= line to. */
    private fun queryLogPath(): String = pathVars.get().appDataDir + "/cache/query.log"

    /**
     * Begin tailing. DEBUG-only (the const-true guard also enables dead-code elimination in release).
     * Idempotent: a second [start] without [stop] is a no-op. Resets [lastOffset] to 0 so a fresh soak
     * re-reads from the current file (release never runs, and the soak is post-CLEAR, so starting at 0
     * is correct — at worst the first tick replays a few already-logged lines, which the shadow's own
     * conflation window dedupes).
     */
    @Synchronized
    fun start() {
        if (!BuildConfig.DEBUG) return
        if (pollJob != null) return
        lastOffset = 0L
        linesParsed = 0L
        tailErrors = 0L
        val path = queryLogPath()
        // T20-clean: this logs the FILE PATH (appDataDir-derived), never a qname. One line per soak so
        // the operator can confirm the seam targets the file the toml producer enabled.
        logi("QueryLogTailer start — tailing (read-only) $path")
        pollJob = scope.launch {
            while (isActive) {
                tailOnce(path)
                delay(POLL_MS)
            }
        }
    }

    /** Stop tailing and release the poll job. Idempotent; safe to call when never started. */
    @Synchronized
    fun stop() {
        val job = pollJob
        pollJob = null
        try {
            job?.cancel()
        } catch (e: Exception) {
            loge("QueryLogTailer stop", e)
        }
        if (BuildConfig.DEBUG) {
            logi("QueryLogTailer stop — linesParsed=$linesParsed tailErrors=$tailErrors")
        }
    }

    /**
     * One read pass: open the file READ-ONLY, seek to [lastOffset], read every COMPLETE line up to the
     * last newline, hand each to [parseLine], and advance [lastOffset] to the byte just past that last
     * newline. A partial trailing line (the appender mid-write) is left for the next tick. Any failure
     * is swallowed (counted) — never propagated, so the poll loop can never die on a transient IO error.
     */
    private fun tailOnce(path: String) {
        try {
            val f = File(path)
            // Graceful no-op until dnscrypt-proxy lazily creates the file on its first logged query
            // (mirrors OwnFileReader's !file.exists() early-out). No file ⇒ nothing to do this tick.
            if (!f.exists()) return

            val len = f.length()
            // Rotation/truncation guard: dnscrypt rotates query.log at log_files_max_size, so a shorter
            // file than our offset means it was replaced — restart from the head of the new file.
            if (len < lastOffset) lastOffset = 0L
            if (len == lastOffset) return // no new bytes appended since last tick

            // PRIME: strictly read-only. seek to where we left off, read forward to EOF, never write.
            RandomAccessFile(f, "r").use { raf ->
                raf.seek(lastOffset)
                var committedOffset = lastOffset
                while (true) {
                    val before = raf.filePointer
                    if (before >= len) break
                    // readLine() returns the next line WITHOUT its terminator, or null at EOF. A line
                    // that ends exactly at EOF with no '\n' is still returned — so we must distinguish
                    // "line was newline-terminated" (commit it) from "partial tail" (do NOT commit).
                    val line = raf.readLine() ?: break
                    val after = raf.filePointer
                    // If the read consumed up to EOF without crossing a newline boundary strictly before
                    // EOF, this is the in-progress last line: roll back and leave it for the next tick.
                    val newlineTerminated = after < len || endsWithNewline(raf, after)
                    if (!newlineTerminated) {
                        // Partial last line — do not consume it; re-read whole next tick (conflation in
                        // shadowCompare dedupes the eventual re-read of the completed line).
                        break
                    }
                    committedOffset = after
                    parseLine(line)
                }
                lastOffset = committedOffset
            }
        } catch (e: Exception) {
            // A tailer throw is invisible to the real answer (already delivered). Count + carry on.
            tailErrors++
            loge("QueryLogTailer tailOnce", e)
        }
    }

    /**
     * Was the byte at `pos-1` a newline? `RandomAccessFile.readLine()` swallows the terminator, so after
     * a terminated line `filePointer` sits just past the '\n' (or past a "\r\n" pair). We confirm a real
     * terminator by peeking the byte before `pos`; if it is '\n' the line was complete and committable.
     * Read-only peek (PRIME): we seek back, read one byte, and restore the pointer.
     */
    private fun endsWithNewline(raf: RandomAccessFile, pos: Long): Boolean {
        if (pos <= 0L) return false
        val save = raf.filePointer
        return try {
            raf.seek(pos - 1)
            val b = raf.read()
            b == '\n'.code
        } catch (e: Exception) {
            false
        } finally {
            try {
                raf.seek(save)
            } catch (e: Exception) {
                // best effort — the outer use{} closes the handle regardless
            }
        }
    }

    /**
     * Parse one dnscrypt-proxy tsv query.log line into (qname, returnCode) and drive the shadow.
     *
     * Authoritative tsv layout (plugin_query_log.go): 8 TAB columns —
     *   [timestamp] \t clientIP \t "qname" \t qtype \t RETURNCODE \t durMs \t "server" \t "relay"
     * We need field[2] (qname, double-quoted) and field[4] (RETURNCODE class). There are NO answer IPs
     * in any column, so the shadow does resolver-health only (no byte-compare) — the returnCode is passed
     * for the OPTIONAL lenient class-parity bonus in shadowCompare.
     *
     * T20: the qname is extracted ONLY to call [onQname]; it is never logged or re-emitted here.
     */
    private fun parseLine(line: String) {
        try {
            if (line.isEmpty()) return
            val cols = line.split('\t')
            if (cols.size < 5) return // not a well-formed query.log row — ignore quietly
            var qname = cols[2].trim().removeSurrounding("\"")
            qname = qname.removeSuffix(".").lowercase()
            if (qname.isEmpty()) return
            val rcode = cols[4].trim().ifEmpty { null }
            linesParsed++
            // Hand off to the shadow. The callee owns the DEBUG kill-switch, conflation, in-flight cap,
            // and all telemetry — this class adds no egress and keeps no qname.
            onQname(qname, rcode)
        } catch (e: Exception) {
            tailErrors++
            // No qname in the message (T20) — only the error class.
            loge("QueryLogTailer parseLine", e)
        }
    }

    companion object {
        /** Poll cadence. query.log is a low-rate file (one line per resolved query); 1s keeps the shadow
         *  responsive during a soak without busy-spinning. */
        private const val POLL_MS = 1000L
    }
}
