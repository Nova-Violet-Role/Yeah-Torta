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

package pillar.kuma_saimono.libumdnscrypt.domain.dns_resolver

interface DnsRepository {
    fun resolveDomainUDP(domain: String, includeIPv6: Boolean, port: Int, timeout: Int): Set<String>
    fun resolveDomainDOH(domain: String, includeIPv6: Boolean, timeout: Int): Set<String>
    fun reverseResolveDomainUDP(ip: String, port: Int, timeout: Int): String
    fun reverseResolveDomainDOH(ip: String, timeout: Int): String
}
