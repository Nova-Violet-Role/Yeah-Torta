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
 * Honest placeholder for the wireless-ADB engine. The surrounding flow — menu entry, guided screen,
 * NSD port discovery, state machine — is fully live; only the SPAKE2/TLS handshake is pending. This
 * stub fails clearly so the UI never pretends to have elevated when it has not (Wave B replaces it
 * with libadb-android, iterated on a real device).
 */
class StubAdbElevation : AdbElevation {

    override val isImplemented: Boolean = false

    override suspend fun pair(host: String, port: Int, code: String): Result<Unit> =
        Result.failure(NotWiredYet)

    override suspend fun connect(host: String, port: Int): Result<AdbShell> =
        Result.failure(NotWiredYet)

    private companion object {
        val NotWiredYet = UnsupportedOperationException(
            "Pairing engine not wired yet (Wave B). Port discovery and the flow are live."
        )
    }
}
