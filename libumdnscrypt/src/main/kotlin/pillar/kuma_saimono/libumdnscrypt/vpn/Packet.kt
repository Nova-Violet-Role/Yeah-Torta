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

package pillar.kuma_saimono.libumdnscrypt.vpn

import androidx.annotation.Keep

@Keep
class Packet {
    @JvmField
    var time: Long = 0

    @JvmField
    var version = 0

    @JvmField
    var protocol = 0

    @JvmField
    var flags: String? = null

    @JvmField
    var saddr: String? = null

    @JvmField
    var sport = 0

    @JvmField
    var daddr: String? = null

    @JvmField
    var dport = 0

    @JvmField
    var data: String? = null

    @JvmField
    var uid = 0

    @JvmField
    var allowed = false

    override fun toString(): String =
        "uid=$uid v$version p$protocol $saddr/$sport $daddr/$dport"
}
