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

import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.ShellResult

/**
 * The Wave B seam. A real implementation performs the Android 11+ wireless-ADB handshake:
 *   NSD-discovered pairing port → TLS 1.3 + SPAKE2 pairing with the 6-digit code → our ADB key
 *   becomes trusted → TLS connect to the connect endpoint → a `shell:` stream running as UID 2000.
 *
 * That stack (SPAKE2 + the TLS-wrapped ADB protocol) is large, security-sensitive, and only
 * testable on a real device — so it is kept behind this interface. The proven, GPL-compatible path
 * is libadb-android (Apache-2.0, Muntashir/App Manager); [StubAdbElevation] stands in until it is
 * wired and iterated on-device.
 */
interface AdbElevation {

    /** True once a real engine is plugged in (the UI uses this to be honest about Wave B). */
    val isImplemented: Boolean

    /** Run the pairing handshake against the discovered pairing endpoint with the 6-digit code. */
    suspend fun pair(host: String, port: Int, code: String): Result<Unit>

    /** Open a privileged shell on the connect endpoint (after a successful pair). */
    suspend fun connect(host: String, port: Int): Result<AdbShell>
}

/** A live ADB `shell:` stream running as UID 2000. */
interface AdbShell {
    /**
     * Run a command and return its honest outcome as a [ShellResult] (exit + stdout + stderr).
     *
     * The transport (libadb-android's merged `shell:` stream) hands back only one combined text with
     * no exit code, so implementations recover the exit via
     * [pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.AdbSentinel] — turning the old
     * `exec(String): String` (which let "Done" lie) into a read-back a grant can be honestly verified
     * against. A truncated/garbled stream reads as a FAILURE (exit `EXIT_UNKNOWN`), never a silent success.
     */
    suspend fun exec(command: String): ShellResult
    fun close()
}
