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

package pillar.kuma_saimono.libumdnscrypt.modules

object ModulesServiceActions {
    const val ACTION_DISMISS_NOTIFICATION = "pillar.kuma_saimono.libumdnscrypt.action.DISMISS_NOTIFICATION"
    const val ACTION_STOP_SERVICE = "pillar.kuma_saimono.libumdnscrypt.action.STOP_SERVICE"
    const val ACTION_STOP_SERVICE_FOREGROUND = "pillar.kuma_saimono.libumdnscrypt.action.STOP_SERVICE_FOREGROUND"

    const val ACTION_START_DNSCRYPT = "pillar.kuma_saimono.libumdnscrypt.action.START_DNSCRYPT"
    const val ACTION_STOP_DNSCRYPT = "pillar.kuma_saimono.libumdnscrypt.action.STOP_DNSCRYPT"

    // CAKE/YeAH engine as a standalone module (public so MainFragment can fire them via ModulesActionSender)
    const val ACTION_START_ENGINE = "pillar.kuma_saimono.libumdnscrypt.action.START_ENGINE"
    const val ACTION_STOP_ENGINE = "pillar.kuma_saimono.libumdnscrypt.action.STOP_ENGINE"
    const val ACTION_RESTART_DNSCRYPT = "pillar.kuma_saimono.libumdnscrypt.action.RESTART_DNSCRYPT"

    // #2 nerd "Rotate Now" — public so RotationDashboardFragment can fire an immediate resolver rotation.
    const val ACTION_ROTATE_RESOLVERS_NOW = "pillar.kuma_saimono.libumdnscrypt.action.ROTATE_RESOLVERS_NOW"
    const val ACTION_UPDATE_MODULES_STATUS = "pillar.kuma_saimono.libumdnscrypt.action.UPDATE_MODULES_STATUS"
    const val ACTION_RECOVER_SERVICE = "pillar.kuma_saimono.libumdnscrypt.action.RECOVER_SERVICE"
    const val SPEEDUP_LOOP = "pillar.kuma_saimono.libumdnscrypt.action.SPEEDUP_LOOP"
    const val SLOWDOWN_LOOP = "pillar.kuma_saimono.libumdnscrypt.action.SLOWDOWN_LOOP"
    const val EXTRA_LOOP = "pillar.kuma_saimono.libumdnscrypt.action.MAKE_EXTRA_LOOP"
    const val START_ARP_SCANNER = "pillar.kuma_saimono.libumdnscrypt.action.START_ARP_SCANNER"
    const val STOP_ARP_SCANNER = "pillar.kuma_saimono.libumdnscrypt.action.STOP_ARP_SCANNER"
    const val CLEAR_IPTABLES_COMMANDS_HASH = "pillar.kuma_saimono.libumdnscrypt.action.CLEAR_IPTABLES_COMMANDS_HASH"
}
