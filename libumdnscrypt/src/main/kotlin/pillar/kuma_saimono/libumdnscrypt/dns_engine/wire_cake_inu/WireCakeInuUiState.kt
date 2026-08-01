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

/**
 * The on-device wireless-ADB self-elevation flow as an explicit state machine. The setup screen
 * renders each state; the manager advances through them. No transport mode is involved — this is a
 * one-shot elevation action (Android 11+ Wireless Debugging → ADB shell as UID 2000), not a 4th
 * operation mode.
 */
sealed interface WireCakeInuUiState {
    /** Android < 11: wireless ADB pairing does not exist. */
    data object Unsupported : WireCakeInuUiState

    /** Ready; the user works through the guided steps. */
    data object Idle : WireCakeInuUiState

    /** NSD is searching for the `_adb-tls-pairing._tcp` service the system advertises while open. */
    data object Discovering : WireCakeInuUiState

    /** The pairing endpoint was discovered (port is random per session — this is why we use NSD). */
    data class Found(val host: String, val port: Int) : WireCakeInuUiState

    /** Running the TLS + SPAKE2 pairing handshake seeded by the 6-digit code. */
    data object Pairing : WireCakeInuUiState

    /** Pairing trusted our key; opening the TLS ADB connection to the connect endpoint. */
    data object Connecting : WireCakeInuUiState

    /** Shell stream open — commands now run as UID 2000. */
    data object Connected : WireCakeInuUiState

    /** Applying one elevation step (e.g. always-on VPN). */
    data class Granting(val step: String) : WireCakeInuUiState

    /** All requested powers granted. */
    data class Done(val granted: List<String>) : WireCakeInuUiState

    /** Any failure, surfaced verbatim to the user. */
    data class Error(val message: String) : WireCakeInuUiState
}
