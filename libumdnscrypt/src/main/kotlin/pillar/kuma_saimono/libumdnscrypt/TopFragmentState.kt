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

package pillar.kuma_saimono.libumdnscrypt

/**
 * Compatibility holder for the few process-global fields the retired InviZible
 * TopFragment UI shell used to own. The SLINT surface is the live UI now; these
 * values are still read by kept, non-UI code (Utils crash-report metadata, the
 * integrity Verifier, the DNSCrypt module status broadcast), so they migrate here
 * unchanged instead of dying with the shell.
 */
object TopFragmentState {

    /** The running dnscrypt-proxy internal version string (crash-report metadata). */
    @Volatile
    @JvmField
    var DNSCryptVersion: String = ""

    /** Verbose-debug flag (default off, matching the retired shell). */
    @JvmField
    var debug: Boolean = false

    /** Module status broadcast action, preserved verbatim from the old shell. */
    const val TOP_BROADCAST = "pillar.kuma_saimono.libumdnscrypt.action.TOP_BROADCAST"
}
