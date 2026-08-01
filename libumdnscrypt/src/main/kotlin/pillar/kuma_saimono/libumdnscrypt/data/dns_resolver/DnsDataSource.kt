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

package pillar.kuma_saimono.libumdnscrypt.data.dns_resolver

import pillar.kuma_saimono.libumdnscrypt.utils.dns.Record

interface DnsDataSource {
    fun resolveDomainUDP(
        domain: String,
        includeIPv6: Boolean,
        port: Int,
        timeout: Int
    ): Array<Record>?

    fun resolveDomainDOH(
        domain: String,
        includeIPv6: Boolean,
        timeout: Int
    ): Array<Record>?

    fun reverseResolveUDP(
        ip: String,
        port: Int,
        timeout: Int
    ): Array<Record>?

    fun reverseResolveDOH(
        ip: String,
        timeout: Int
    ): Array<Record>?
}
