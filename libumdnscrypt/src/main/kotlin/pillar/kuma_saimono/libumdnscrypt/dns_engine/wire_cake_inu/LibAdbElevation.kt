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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu

import android.content.Context
import io.github.muntashirakon.adb.AbsAdbConnectionManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.AdbSentinel
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.ShellResult

/**
 * Wave B engine, backed by libadb-android (Apache-2.0). Pairs over Android 11+ Wireless Debugging,
 * then auto-connects (mDNS-discovered) and opens privileged `shell:` streams as UID 2000. All
 * blocking work runs on IO; isolated behind [AdbElevation] so a failure only fails the flow, never
 * the app. The geeky parts (SPAKE2/TLS/ADB) stay entirely out of the user's sight.
 */
class LibAdbElevation(
    private val appContext: Context,
) : AdbElevation {

    override val isImplemented: Boolean = true

    override suspend fun pair(host: String, port: Int, code: String): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                val ok = AdbConnectionManager.getInstance(appContext).pair(host, port, code)
                if (!ok) error("Pairing was rejected — check the 6-digit code")
            }
        }

    override suspend fun connect(host: String, port: Int): Result<AdbShell> =
        withContext(Dispatchers.IO) {
            runCatching {
                val manager = AdbConnectionManager.getInstance(appContext)
                val ok = manager.autoConnect(appContext, CONNECT_TIMEOUT_MS)
                if (!ok) error("Could not connect — is Wireless debugging still on?")
                LibAdbShell(manager)
            }
        }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 15_000L
    }
}

/**
 * A live `shell:` stream as UID 2000. Each [exec] opens a one-shot stream and reads it to EOF.
 *
 * libadb-android's `shell:` transport returns one merged stdout+stderr text with NO exit code, so the
 * command is decorated with [AdbSentinel.wrap] (`; echo "<MARK>$?"`) before it runs and the exit code
 * is recovered from the stream with [AdbSentinel.parse]. The result is the canonical [ShellResult] the
 * GrantEngine read-back verifies against — "Done" can no longer lie. A truncated stream parses to
 * [AdbSentinel.EXIT_UNKNOWN] (a FAILURE), never a fake success.
 */
private class LibAdbShell(private val manager: AbsAdbConnectionManager) : AdbShell {

    override suspend fun exec(command: String): ShellResult = withContext(Dispatchers.IO) {
        val stream = manager.openStream("shell:" + AdbSentinel.wrap(command))
        try {
            // Read until the AdbSentinel MARK (the command's done-marker) or a deadline — NOT until EOF.
            // The libadb `shell:` stream does not cleanly EOF after a large batched command on some
            // transports (measured live on the AVD: readText() blocked forever after the full hardening
            // batch even though every command had run), which hung the whole grant. The MARK arrives as
            // soon as the shell finishes, so stop there; the deadline is a safety net against a dead stream.
            val input = stream.openInputStream()
            val sb = StringBuilder()
            val deadline = System.currentTimeMillis() + READ_TIMEOUT_MS
            while (System.currentTimeMillis() < deadline) {
                // available()-based, truly non-blocking: a blocking read() can hang past the deadline on a
                // poisoned stream (measured live: read() never returned after the big batch). available()
                // + reading only the ready bytes guarantees the deadline is honoured.
                val avail = try { input.available() } catch (_: Exception) { 0 }
                if (avail > 0) {
                    val bytes = ByteArray(avail)
                    val n = input.read(bytes, 0, avail)
                    if (n < 0) break // EOF
                    sb.append(String(bytes, 0, n, Charsets.UTF_8))
                    if (sb.indexOf(AdbSentinel.MARK) >= 0) break // command finished
                } else {
                    if (sb.indexOf(AdbSentinel.MARK) >= 0) break
                    Thread.sleep(25)
                }
            }
            AdbSentinel.parse(sb.toString())
        } finally {
            try {
                stream.close()
            } catch (_: Exception) {
                // already closed
            }
        }
    }

    override fun close() {
        // Fire-and-forget: AbsAdbConnectionManager.close() can BLOCK on a poisoned connection after a big
        // batch (measured live: the grant hung in the finally{} close, never reaching Done/the cake). Run it
        // on a daemon thread so a hung close never blocks the grant flow; the OS reaps the socket anyway.
        Thread {
            try {
                manager.close()
            } catch (_: Exception) {
                // already closed
            }
        }.apply { isDaemon = true }.start()
    }

    private companion object {
        // Safety deadline for one command's read. The MARK normally arrives in well under a second; this
        // only fires if the stream is dead/never EOFs. Generous enough for a large batched command.
        const val READ_TIMEOUT_MS = 20_000L
    }
}
