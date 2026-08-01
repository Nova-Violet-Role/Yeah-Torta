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

package pillar.kuma_saimono.libumdnscrypt.rust

import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

/**
 * Live wiring of the Rust blocklist matcher into the DNS path.
 *
 * Loaded from the on-disk blacklist when DNSCrypt goes RUNNING; every observed query is checked,
 * lighting up a real "would-block" count — the substrate Centauri's (P8) live wall reads. This is the
 * live INTELLIGENCE; actual enforcement (returning NXDOMAIN) is Wave 2. dnscrypt-proxy still does the
 * real blocking today, so with the same list the counts overlap — the value appears when P8 feeds the
 * matcher richer GitHub/custom lists dnscrypt-proxy doesn't have. All calls route through the
 * crash-proof [TortaCore] wrapper, so a missing .so simply means "0 armed, nothing blocked".
 */
object BlocklistRuntime {

    private val observed = AtomicInteger(0)
    private val blocked = AtomicInteger(0)

    @Volatile
    private var armed = 0

    /** Compile the on-disk blacklist files into the Rust matcher (merged). Returns the armed count. */
    @Synchronized
    fun compileFromFiles(paths: List<String>): Int {
        var fresh = true
        for (path in paths) {
            if (!File(path).exists()) continue
            TortaCore.compileBlocklist(path, merge = !fresh)
            fresh = false
        }
        armed = TortaCore.blocklistCount()
        logi("BlocklistRuntime: $armed domains armed in the Rust matcher")
        return armed
    }

    /**
     * Compile a PRE-COMPILED blocklist ARTIFACT (P8 additive binary surface) into the SAME Rust
     * matcher [compileFromFiles] feeds. This is an opt-in, ADDITIVE path — the manual/DNSCrypt file
     * pipeline above stays the default and is untouched. [merge] stacks the artifact onto the current
     * list instead of replacing it. Lands in the same process-global matcher, so the resolver and the
     * observe path see the swap atomically. Returns the armed count (unchanged on a rejected artifact:
     * bad header / fingerprint mismatch come back as a no-op from the crash-proof [TortaCore] wrapper).
     */
    @Synchronized
    fun compileFromArtifact(bytes: ByteArray, merge: Boolean = false): Int {
        TortaCore.compileBlocklistArtifact(bytes, merge = merge)
        armed = TortaCore.blocklistCount()
        logi("BlocklistRuntime: $armed domains armed in the Rust matcher (from artifact)")
        return armed
    }

    /** Observe one resolved DNS query; counts it and whether the Beast would block it. Crash-proof. */
    fun observe(domain: String?) {
        if (domain.isNullOrBlank()) return
        observed.incrementAndGet()
        if (TortaCore.isBlocked(domain)) {
            blocked.incrementAndGet()
        }
    }

    /** Domains compiled into the matcher. */
    fun armedCount(): Int = armed

    /** Total queries observed since start. */
    fun observedCount(): Int = observed.get()

    /** Observed queries the Beast would block (the Centauri feed seed). */
    fun blockedCount(): Int = blocked.get()
}
