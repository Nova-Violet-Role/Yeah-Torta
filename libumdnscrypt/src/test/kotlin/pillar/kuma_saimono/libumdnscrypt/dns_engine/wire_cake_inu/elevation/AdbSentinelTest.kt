/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

/*
    This file is part of Yeah! Tortä. GPL-3.0-or-later. Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins [AdbSentinel]: the exit-code sentinel that makes read-back HONEST over libadb 3.1.1's single
 * merged `shell:` stream. "Done" must never lie — a failing command has to surface its non-zero exit;
 * a truncated/garbled stream must read as a FAILURE, never a silent success. All metal — no Android.
 */
class AdbSentinelTest {

    @Test
    fun `wrap appends an echo of the exit sentinel with semicolon not ampersand`() {
        // `; echo` (not `&&`) so a FAILING command still emits its non-zero exit.
        assertEquals(
            "settings get secure always_on_vpn_app; echo \"${AdbSentinel.MARK}\$?\"",
            AdbSentinel.wrap("settings get secure always_on_vpn_app"),
        )
    }

    @Test
    fun `parse recovers exit 0 and strips the marker from the output`() {
        val raw = "app.torta.yeah\n${AdbSentinel.MARK}0\n"
        val r = AdbSentinel.parse(raw)
        assertEquals(0, r.exit)
        assertTrue(r.ok)
        assertEquals("app.torta.yeah", r.value)
        assertEquals("", r.stderr)
    }

    @Test
    fun `parse recovers a non-zero exit from a failing command`() {
        val raw = "Permission denied\n${AdbSentinel.MARK}255\n"
        val r = AdbSentinel.parse(raw)
        assertEquals(255, r.exit)
        assertFalse(r.ok)
        assertEquals("Permission denied", r.value)
    }

    @Test
    fun `parse handles empty command output - just the marker line`() {
        val raw = "${AdbSentinel.MARK}0\n"
        val r = AdbSentinel.parse(raw)
        assertEquals(0, r.exit)
        assertEquals("", r.value)
    }

    @Test
    fun `parse handles multi-line output preserving the body, stripping only the marker`() {
        val raw = "line1\nline2\nline3\n${AdbSentinel.MARK}0\n"
        val r = AdbSentinel.parse(raw)
        assertEquals(0, r.exit)
        assertEquals("line1\nline2\nline3", r.value)
    }

    @Test
    fun `parse normalizes CRLF from toybox echo on some ROMs`() {
        val raw = "value\r\n${AdbSentinel.MARK}0\r\n"
        val r = AdbSentinel.parse(raw)
        assertEquals(0, r.exit)
        assertEquals("value", r.value)
    }

    @Test
    fun `parse takes the LAST marker when the command output itself echoes the token`() {
        // A rogue command echoes a fake marker; the sentinel's own echo is always last and wins.
        val raw = "${AdbSentinel.MARK}99 some payload\n${AdbSentinel.MARK}0\n"
        val r = AdbSentinel.parse(raw)
        assertEquals(0, r.exit)
        assertEquals("${AdbSentinel.MARK}99 some payload", r.value)
    }

    @Test
    fun `parse with no marker reads as UNKNOWN failure - a truncated stream is never success`() {
        val raw = "partial output, stream cut off"
        val r = AdbSentinel.parse(raw)
        assertEquals(AdbSentinel.EXIT_UNKNOWN, r.exit)
        assertFalse(r.ok)
        assertEquals("partial output, stream cut off", r.value)
    }

    @Test
    fun `parse with a non-numeric tail after the marker reads as UNKNOWN failure`() {
        val raw = "output\n${AdbSentinel.MARK}garbage\n"
        val r = AdbSentinel.parse(raw)
        assertEquals(AdbSentinel.EXIT_UNKNOWN, r.exit)
        assertFalse(r.ok)
    }

    @Test
    fun `wrap then parse round-trips a typical settings-get read-back`() {
        // Simulate the merged stream a successful `settings get` produces under the wrapper.
        val wrapped = AdbSentinel.wrap("settings get secure always_on_vpn_lockdown")
        assertTrue(wrapped.endsWith("; echo \"${AdbSentinel.MARK}\$?\""))
        val merged = "1\n${AdbSentinel.MARK}0\n"
        val r = AdbSentinel.parse(merged)
        assertTrue(r.ok)
        assertEquals("1", r.value)
    }
}
