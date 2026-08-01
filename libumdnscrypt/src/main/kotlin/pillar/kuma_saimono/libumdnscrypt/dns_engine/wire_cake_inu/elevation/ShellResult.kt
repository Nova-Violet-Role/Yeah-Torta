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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

/**
 * The exit-code sentinel — the crux of honest read-back on a transport that hands us only one merged
 * text stream.
 *
 * The canonical [ShellResult] (exit + stdout + stderr, with [ShellResult.ok]) lives on the
 * [ElevationSession] seam in ElevationProvider.kt — every caller composes with THAT type. This file
 * carries only the sentinel that recovers an exit code from libadb-android 3.1.1's merged `shell:`
 * stream (LibAdbElevation.kt:50-61 reads the combined stdout+stderr to EOF with no exit code), turning
 * the P6 `exec(String): String` (AdbElevation.kt:34) into something a grant can be honestly verified
 * against — "Done" can never lie (P11 plan §2, §5.6).
 *
 * We append `; echo "<MARK><exit>"` so the exit code rides out in the output, then strip the marker
 * line back off so callers see only the real command output. All pure string work — no I/O, no
 * Android — so the whole read-back path is unit-testable on metal.
 *
 * A Shizuku [UserService] leg that splits the streams can later bypass the sentinel and populate a
 * real `stderr`; the canonical [ShellResult] does not change, so no caller is affected ([INCERTO] on
 * the `shell,v2` split until smoke-tested on a device).
 */
object AdbSentinel {

    /** The exit code used when the sentinel marker was never found (the stream was truncated/garbled). */
    const val EXIT_UNKNOWN = -1

    /** The sentinel marker. Distinctive enough that real command output will not forge it. */
    const val MARK = "__YT_ELEV_EXIT__"

    /**
     * Decorate [command] so its exit status is emitted on the merged stream after its output.
     * Uses `; echo` (not `&&`) so the exit code is captured even when the command FAILS — a failing
     * `settings put` must still report its non-zero status, never be swallowed.
     */
    fun wrap(command: String): String = "$command; echo \"$MARK\$?\""

    /**
     * Parse the raw merged-stream text produced by running [wrap]'s output into the canonical
     * [ShellResult].
     *
     * - Finds the LAST line that starts with [MARK], reads the integer that follows as the exit code.
     * - Everything before that marker line is the real command output ([ShellResult.stdout]).
     * - No marker / non-numeric tail → [EXIT_UNKNOWN] with the whole text as stdout (a truncated or
     *   garbled stream must read as a FAILURE, never as a silent success).
     *
     * On the merged-stream self-ADB leg, `stderr` is left empty (the combined text lands in stdout).
     */
    fun parse(raw: String): ShellResult {
        // Normalize CRLF (some ROMs' toybox echo emits \r\n) so the marker match is stable.
        val normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
        val lines = normalized.split("\n")

        var markerIndex = -1
        for (i in lines.indices.reversed()) {
            if (lines[i].startsWith(MARK)) {
                markerIndex = i
                break
            }
        }
        if (markerIndex < 0) {
            return ShellResult(EXIT_UNKNOWN, normalized.trimEnd('\n'), "")
        }

        val tail = lines[markerIndex].substring(MARK.length).trim()
        val exit = tail.toIntOrNull() ?: EXIT_UNKNOWN

        val outputLines = lines.subList(0, markerIndex).toMutableList()
        // Drop a single trailing blank line left by the command's own newline before the echo.
        if (outputLines.isNotEmpty() && outputLines.last().isEmpty()) {
            outputLines.removeAt(outputLines.size - 1)
        }
        return ShellResult(exit, outputLines.joinToString("\n"), "")
    }
}
