/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

package pillar.kuma_saimono.libumdnscrypt.utils.parsers

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The `sdns://` scheme strip — the fix for `SDNS type 177 handling is not implemented`, which cost
 * the relay probe plane EVERY candidate (`0/365 relays probed reachable`) and starved the Beast of
 * RTT samples.
 *
 * Only the PURE half is testable here: `android.util.Base64` is not available to a plain JVM unit
 * test (no Robolectric in this project), so the decode itself is covered by the on-device
 * measurement instead — `0/365` before, a non-zero count after. That split is stated rather than
 * papered over: this test pins the string surgery, the device pins the parse.
 *
 * The `typeByteOfUnstrippedStampIs177` case is the interesting one. It does not test our code at
 * all — it reproduces the base64 arithmetic that PRODUCED the bogus type, so the diagnosis itself is
 * pinned. If someone ever "fixes" this by adding a `177 ->` branch to the parser, this test states
 * in one place why that would be treating the symptom.
 */
class DnsCryptSDNSParserSchemeTest {

    // Real relay stamps, pulled from the device's own app_data/dnscrypt-proxy/relays.md.
    private val v4Stamp = "sdns://gRE5NC4xOTguNDEuMjM1OjQ0Mw"
    private val v6Stamp = "sdns://gRhbMjAwMTphYzg6Mjk6YTE6OjUzXTo0NDM"

    @Test
    fun theSchemeIsRemoved() {
        assertEquals("gRE5NC4xOTguNDEuMjM1OjQ0Mw", DnsCryptSDNSParser.stripScheme(v4Stamp))
        assertEquals("gRhbMjAwMTphYzg6Mjk6YTE6OjUzXTo0NDM", DnsCryptSDNSParser.stripScheme(v6Stamp))
    }

    /** A payload that never had a scheme must survive untouched — callers may pass either form. */
    @Test
    fun anAlreadyStrippedStampIsUnchanged() {
        val bare = "gRE5NC4xOTguNDEuMjM1OjQ0Mw"
        assertEquals(bare, DnsCryptSDNSParser.stripScheme(bare))
    }

    @Test
    fun theSchemeMatchIsCaseInsensitiveAndWhitespaceTolerant() {
        assertEquals("gRE5", DnsCryptSDNSParser.stripScheme("SDNS://gRE5"))
        assertEquals("gRE5", DnsCryptSDNSParser.stripScheme("  sdns://gRE5  "))
    }

    /**
     * A stamp is not a scheme: stripping must not eat the payload of something that merely starts
     * with similar characters, and must never throw on a short or empty input.
     */
    @Test
    fun shortAndOddInputsAreSafe() {
        assertEquals("", DnsCryptSDNSParser.stripScheme(""))
        assertEquals("sdns:/", DnsCryptSDNSParser.stripScheme("sdns:/"))
        assertEquals("sdnsX//gRE5", DnsCryptSDNSParser.stripScheme("sdnsX//gRE5"))
    }

    /**
     * THE DIAGNOSIS, PINNED. Decoding the literal text "sdns" as URL-safe base64 yields first byte
     * 0xB1 = 177 — exactly the type the device reported 264 times. This reproduces the arithmetic
     * with the alphabet spelled out, so the claim is checkable rather than asserted.
     */
    @Test
    fun typeByteOfUnstrippedStampIs177() {
        val alphabet = ('A'..'Z') + ('a'..'z') + ('0'..'9') + '-' + '_'
        val s = alphabet.indexOf('s')
        val d = alphabet.indexOf('d')
        assertEquals(44, s)
        assertEquals(29, d)
        // first output byte = 6 bits of 's' then the top 2 bits of 'd'
        val firstByte = (s shl 2) or (d shr 4)
        assertEquals("the bogus type the device reported", 177, firstByte)
        assertTrue("177 is not a real DNS-stamp type", 177 != 0x81 && 177 != 0x85)
    }
}
