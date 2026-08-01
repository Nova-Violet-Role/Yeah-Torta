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

package pillar.kuma_saimono.libumdnscrypt.utils.root

import androidx.annotation.IntDef

@IntDef(
    RootCommandsMark.DNSCRYPT_RUN_FRAGMENT_MARK,
    RootCommandsMark.TOR_RUN_FRAGMENT_MARK,
    RootCommandsMark.I2PD_RUN_FRAGMENT_MARK,
    RootCommandsMark.HELP_ACTIVITY_MARK,
    RootCommandsMark.BOOT_BROADCAST_MARK,
    RootCommandsMark.NULL_MARK,
    RootCommandsMark.FILE_OPERATIONS_MARK,
    RootCommandsMark.INSTALLER_MARK,
    RootCommandsMark.TOP_FRAGMENT_MARK,
    RootCommandsMark.IPTABLES_MARK
)
@Retention(AnnotationRetention.SOURCE)
annotation class RootCommandsMark {
    companion object {
        const val DNSCRYPT_RUN_FRAGMENT_MARK = 100
        const val TOR_RUN_FRAGMENT_MARK = 200
        const val I2PD_RUN_FRAGMENT_MARK = 300
        const val HELP_ACTIVITY_MARK = 400
        const val BOOT_BROADCAST_MARK = 500
        const val NULL_MARK = 600
        const val FILE_OPERATIONS_MARK = 700
        const val INSTALLER_MARK = 800
        const val TOP_FRAGMENT_MARK = 900
        const val IPTABLES_MARK = 1000
    }
}
