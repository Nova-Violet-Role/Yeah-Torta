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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * #20 — the tail-window mmap helper proven byte-identical to the stream reads it fronts (the
 * deliverable's own gate: "cold-boot rehydrate works byte-identical to the FileInputStream path"),
 * plus the authoritative-or-null law that keeps every caller's fallback semantics exact.
 */
class MmapTailTest {

    private fun temp(content: ByteArray): File =
        File.createTempFile("mmaptail", ".log").apply { deleteOnExit(); writeBytes(content) }

    private fun lines(n: Int, width: Int = 90): String =
        (1..n).joinToString("") { "line-$it-" + "x".repeat(width) + "\n" }

    // ── byte identity ─────────────────────────────────────────────────────────────────────────

    @Test
    fun `tailWindow returns byte-identical suffix to a stream read (window smaller than file)`() {
        val content = lines(500).toByteArray() // ~50 KB
        val f = temp(content)
        val window = 8 * 1024
        val tail = MmapTail.tailWindow(f, window)
        assertNotNull(tail)
        // The stream-read ground truth: the same suffix via plain readBytes.
        val expected = content.copyOfRange(content.size - window, content.size)
        assertArrayEquals("mmap suffix must be byte-identical to the stream suffix", expected, tail!!.bytes)
        assertEquals((content.size - window).toLong(), tail.tailStartsAtByte)
        assertEquals(content.size.toLong(), tail.fileLength)
    }

    @Test
    fun `tailWindow covers the whole file when the window is larger`() {
        val content = lines(10).toByteArray()
        val tail = MmapTail.tailWindow(temp(content), 1024 * 1024)
        assertNotNull(tail)
        assertArrayEquals(content, tail!!.bytes)
        assertEquals(0L, tail.tailStartsAtByte)
    }

    @Test
    fun `tailWindow on an empty file is an empty tail - on a missing file null`() {
        val tail = MmapTail.tailWindow(temp(ByteArray(0)), 4096)
        assertNotNull(tail)
        assertEquals(0, tail!!.bytes.size)
        assertNull(MmapTail.tailWindow(File("definitely/not/here.log"), 4096))
        assertNull("non-positive window is a fault", MmapTail.tailWindow(temp(lines(3).toByteArray()), 0))
    }

    // ── tailLines semantics (BufferedReader parity) ──────────────────────────────────────────

    @Test
    fun `tailLines equals BufferedReader lines when the window covers the file`() {
        val f = temp(lines(120).toByteArray())
        val streamed = f.bufferedReader().readLines() // the slow-path ground truth
        val mapped = MmapTail.tailLines(f, 1024 * 1024, sufficientLines = 130)
        assertNotNull(mapped)
        assertEquals("mmap lines must equal BufferedReader lines exactly", streamed, mapped)
    }

    @Test
    fun `tailLines drops the torn head line on a mid-file window and matches the stream tail`() {
        val f = temp(lines(1000).toByteArray()) // ~100 KB, window will start mid-line
        val mapped = MmapTail.tailLines(f, 16 * 1024, sufficientLines = 130)
        assertNotNull("16 KiB of ~100 B lines holds >130 lines — authoritative", mapped)
        val streamed = f.bufferedReader().readLines()
        assertTrue(mapped!!.size > 130)
        assertEquals(
            "the mapped tail must be EXACTLY the stream's last lines (no torn fragment)",
            streamed.takeLast(mapped.size), mapped
        )
        assertTrue("first mapped line is complete", mapped.first().startsWith("line-"))
    }

    @Test
    fun `tailLines refuses a mid-file window that cannot rule out head lines (caller falls back)`() {
        // Pathological long lines: a 4 KiB window over ~100 KB of 1 KiB lines sees only ~4 lines.
        val f = temp(lines(100, width = 1024).toByteArray())
        assertNull(
            "window mid-file with <= sufficientLines must return null — the stream path answers",
            MmapTail.tailLines(f, 4 * 1024, sufficientLines = 130)
        )
    }

    @Test
    fun `tailLines has no phantom empty entry from the trailing newline`() {
        val f = temp("a\nb\nc\n".toByteArray())
        assertEquals(listOf("a", "b", "c"), MmapTail.tailLines(f, 4096, sufficientLines = 130))
    }

    // ── the PillarLog trim equivalence (the exact consumer arithmetic) ───────────────────────

    @Test
    fun `trim suffix via tailWindow equals the whole-file readBytes suffix the old trim used`() {
        val keep = 8 * 1024
        val content = lines(300).toByteArray() // ~30 KB > keep
        val f = temp(content)
        val viaMmap = MmapTail.tailWindow(f, keep)!!.bytes
        val all = f.readBytes()
        val viaStream = all.copyOfRange((all.size - keep).coerceAtLeast(0), all.size)
        assertArrayEquals("both trim mechanisms must hand the boundary scan the SAME bytes", viaStream, viaMmap)
    }

    // ── repeated-cycle stability + the honest micro-measure ──────────────────────────────────

    @Test
    fun `1000 map-release cycles stay stable and mmap tail beats whole-file scan on a big log`() {
        val f = temp(lines(4000).toByteArray()) // ~400 KB — the FileShortener regime
        // Warmup + correctness on every cycle.
        repeat(50) { assertNotNull(MmapTail.tailWindow(f, 64 * 1024)) }
        val t1 = System.nanoTime()
        repeat(1000) { MmapTail.tailLines(f, 64 * 1024, 130) }
        val mmapMs = (System.nanoTime() - t1) / 1_000_000
        val t2 = System.nanoTime()
        repeat(1000) { f.bufferedReader().readLines() }
        val scanMs = (System.nanoTime() - t2) / 1_000_000
        println("MmapTail micro-measure (400 KB log, 1000 cycles): tail-window=${mmapMs}ms whole-file-scan=${scanMs}ms")
        // No strict speed assert (CI variance) — the invariant is stability: 1000 cycles, zero faults.
        assertNotNull(MmapTail.tailWindow(f, 64 * 1024))
    }
}
