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
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.Date

@Keep
class Usage {
    @JvmField
    var Time: Long = 0

    @JvmField
    var Version: Int = 0

    @JvmField
    var Protocol: Int = 0

    @JvmField
    var DAddr: String? = null

    @JvmField
    var DPort: Int = 0

    @JvmField
    var Uid: Int = 0

    @JvmField
    var Sent: Long = 0

    @JvmField
    var Received: Long = 0

    override fun toString(): String =
        formatter.format(Date(Time).time) +
                " v" + Version + " p" + Protocol +
                " " + DAddr + "/" + DPort +
                " uid " + Uid +
                " out " + Sent + " in " + Received

    private companion object {
        private val formatter: DateFormat = SimpleDateFormat.getDateTimeInstance()
    }
}
