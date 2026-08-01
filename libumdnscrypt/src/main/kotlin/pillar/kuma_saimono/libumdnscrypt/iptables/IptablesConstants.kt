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

package pillar.kuma_saimono.libumdnscrypt.iptables

object IptablesConstants {
    const val FILTER_OUTPUT_CORE = "libumdnscrypt"
    const val FILTER_OUTPUT_FIREWALL = "ipro_fwl_output"
    const val FILTER_FIREWALL_LAN = "ipro_fwl_lan"
    const val NAT_OUTPUT_CORE = "libumdnscrypt_nat_output"
    const val MANGLE_FIREWALL_ALLOW = "ipro_mangle_fwl"
    const val FILTER_FORWARD_CORE = "libumdnscrypt_forward"
    const val FILTER_FORWARD_FIREWALL = "ipro_fwl_forward"
    const val NAT_PREROUTING_CORE = "libumdnscrypt_prerouting"
    const val FILTER_OUTPUT_BLOCKING = "ipro_blocking"
}
