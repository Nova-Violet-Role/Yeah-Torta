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

package pillar.kuma_saimono.libumdnscrypt.utils.mmap

import java.io.File
import java.io.FileInputStream
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel

/**
 * #20 ANDROID-MODERN I/O — the reusable **tail-window mmap** read helper (RAM ⊗ NAND: the kernel
 * page-cache IS the RAM tier fronting the NAND file). `FileChannel.map(READ_ONLY, pos, size)` maps ONLY
 * the tail window of a growing file into the address space — the head pages are never read, never
 * copied, never faulted in. That turns the repeated tail reads this app actually does (the DNSCrypt log
 * view poll re-reading `DnsCrypt.log` every cycle; the pillar-log anti-bloat trim re-reading a 256 KiB
 * file to keep its 128 KiB tail) from **O(file) into O(window)** — and across polls the tail pages stay
 * hot in the page-cache, so the map+copy is served from RAM without touching NAND at all.
 *
 * ## Where the win is REAL (measured on the live tree, #20 ground law)
 *  - `OwnFileReader.readLastLines` — whole-file `BufferedReader` scan up to the 500 KiB
 *    `FileShortener` bound, per UI poll, to keep ~80 lines ⇒ tail-window map.
 *  - `PillarLog` anti-bloat trim — whole-file `readBytes()` of a >256 KiB log to keep the last
 *    128 KiB ⇒ map exactly the kept window.
 *  Measured NOT-A-WIN (deliberately NOT converted): the verify-sig / FFI-bound whole-file reads
 *  (Centauri `.tblk`/`.tcat`, TrustManager raw lists) — those bytes must materialize as a full
 *  `ByteArray` to cross the UniFFI seam regardless of read mechanism, so the copy count is identical
 *  either way; and the Rust `log_tier` Tailer already seeks incrementally (offset + bounded read).
 *  Converting either would be cargo-cult mmap, not engineering.
 *
 * ## Android-system discipline (minSdk21..36)
 *  - `FileChannel.map` is public API since 1 — NO api-floor guard needed anywhere in this object.
 *  - **Atomicity**: callers map plain append/rewrite-in-place log files (never a `.tmp` side of an
 *    atomic tmp+rename — the durable-tier records keep their own Rust read path). The map is taken,
 *    copied out, and released inside ONE call; nothing is parsed lazily off the mapping.
 *  - **Unmap determinism**: Android's public SDK exposes no unmap; [release] runs a best-effort
 *    cleaner ladder (Java-9+ `Unsafe.invokeCleaner` → legacy `cleaner().clean()` → libcore
 *    `NioUtils.freeDirectBuffer`), each reflective and individually swallowed. When every rung is
 *    blocked (hidden-API policy), the ≤128 KiB read-only mapping simply dies with GC — benign here
 *    BECAUSE these files are rewritten in place, never renamed-over, so a GC-deferred unmap cannot
 *    block an atomic rename (the f2fs concern) nor pin stale content.
 *  - **Fail-open**: ANY fault returns null and the caller falls back to its original stream read —
 *    the mmap path is an accelerator, never a dependency.
 */
object MmapTail {

    /**
     * The tail window of [file]: its last `min(window, length)` bytes.
     * [tailStartsAtByte] > 0 ⇔ the window did NOT cover the whole file (the first decoded line is
     * then a partial torn head the caller must drop). [fileLength] is the length that was mapped.
     */
    class Tail(
        @JvmField val bytes: ByteArray,
        @JvmField val tailStartsAtByte: Long,
        @JvmField val fileLength: Long,
    )

    /**
     * Map the last [window] bytes of [file] READ_ONLY, copy them out, release the mapping, return the
     * copy. An empty file returns an empty [Tail]; any fault (missing file, mmap refusal, OOM-sized
     * window) returns null — the caller keeps its stream fallback.
     */
    fun tailWindow(file: File, window: Int): Tail? {
        if (window <= 0) return null
        return try {
            FileInputStream(file).use { fis ->
                val ch = fis.channel
                val len = ch.size()
                if (len <= 0L) return Tail(ByteArray(0), 0L, 0L)
                val size = if (len < window.toLong()) len else window.toLong()
                val pos = len - size
                val buf = ch.map(FileChannel.MapMode.READ_ONLY, pos, size)
                try {
                    val out = ByteArray(size.toInt())
                    buf.get(out)
                    Tail(out, pos, len)
                } finally {
                    release(buf)
                }
            }
        } catch (t: Throwable) {
            null
        }
    }

    /**
     * The last complete lines of [file] read through a tail-window map. Drops the torn head line when
     * the window starts mid-file. Returns null when the fast path cannot answer AUTHORITATIVELY —
     * i.e. on any mmap fault, or when the window is mid-file yet holds ≤ [sufficientLines] lines
     * (pathologically long lines: the caller's whole-file semantics could differ, so it falls back).
     */
    fun tailLines(file: File, window: Int, sufficientLines: Int): List<String>? {
        val tail = tailWindow(file, window) ?: return null
        val text = String(tail.bytes, Charsets.UTF_8)
        var lines = text.split('\n')
        // A trailing newline yields one empty phantom entry — drop it (BufferedReader parity).
        if (lines.isNotEmpty() && lines.last().isEmpty()) lines = lines.dropLast(1)
        if (tail.tailStartsAtByte > 0L) {
            // The window began mid-file: the first entry is a torn head fragment, not a line.
            lines = if (lines.isEmpty()) lines else lines.drop(1)
            if (lines.size <= sufficientLines) return null // can't rule out head lines mattering
        }
        return lines
    }

    /**
     * Best-effort deterministic unmap — the reflective cleaner ladder. Every rung individually
     * swallowed; a fully-blocked ladder leaves the mapping to GC (see the class doc for why that is
     * benign for these callers).
     */
    private fun release(buffer: MappedByteBuffer) {
        // Rung 1 — Java 9+ / host JVM: sun.misc.Unsafe.invokeCleaner(ByteBuffer).
        try {
            val unsafeClass = Class.forName("sun.misc.Unsafe")
            val theUnsafe = unsafeClass.getDeclaredField("theUnsafe").apply { isAccessible = true }
            val unsafe = theUnsafe.get(null)
            unsafeClass.getMethod("invokeCleaner", java.nio.ByteBuffer::class.java)
                .invoke(unsafe, buffer)
            return
        } catch (_: Throwable) {
        }
        // Rung 2 — legacy JVM/ART: DirectByteBuffer.cleaner().clean().
        try {
            val cleaner = buffer.javaClass.getMethod("cleaner").apply { isAccessible = true }
                .invoke(buffer)
            cleaner?.javaClass?.getMethod("clean")?.invoke(cleaner)
            return
        } catch (_: Throwable) {
        }
        // Rung 3 — Android libcore: java.nio.NioUtils.freeDirectBuffer(ByteBuffer).
        try {
            Class.forName("java.nio.NioUtils")
                .getMethod("freeDirectBuffer", java.nio.ByteBuffer::class.java)
                .invoke(null, buffer)
        } catch (_: Throwable) {
        }
    }
}
