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
import pillar.kuma_saimono.libumdnscrypt.domain.dns_resolver.DnsRepository
import javax.inject.Inject

class DnsRepositoryImpl @Inject constructor(
    private val dnsDataSource: DnsDataSource
) : DnsRepository {

    override fun resolveDomainUDP(
        domain: String,
        includeIPv6: Boolean,
        port: Int,
        timeout: Int
    ): Set<String> {
        return dnsDataSource.resolveDomainUDP(domain, includeIPv6, port, timeout)
            ?.filter { isRecordValid(it) }
            ?.flatMap {
                when {
                    it.isA || it.isAAAA -> listOf(it.value!!.trim())
                    it.isCname -> resolveDomainUDP(
                        "https://${it.value}",
                        includeIPv6,
                        port,
                        timeout
                    )
                    else -> emptyList()
                }
            }
            ?.toHashSet() ?: emptySet()
    }

    override fun resolveDomainDOH(
        domain: String,
        includeIPv6: Boolean,
        timeout: Int
    ): Set<String> {
        return dnsDataSource.resolveDomainDOH(domain, includeIPv6, timeout)
            ?.filter { isRecordValid(it) }
            ?.flatMap {
                when {
                    it.isA || it.isAAAA -> listOf(it.value!!.trim())
                    it.isCname -> resolveDomainDOH(
                        "https://${it.value}",
                        includeIPv6,
                        timeout
                    )
                    else -> emptyList()
                }
            }
            ?.toHashSet() ?: emptySet()
    }

    override fun reverseResolveDomainUDP(ip: String, port: Int, timeout: Int): String {
        return dnsDataSource.reverseResolveUDP(ip, port, timeout)
            ?.getOrNull(0)?.value ?: ""
    }

    override fun reverseResolveDomainDOH(ip: String, timeout: Int): String {
        return dnsDataSource.reverseResolveDOH(ip, timeout)
            ?.getOrNull(0)?.value ?: ""
    }

    private fun isRecordValid(record: Record?): Boolean {
        return record?.value != null && record.value.isNotEmpty() && !record.isExpired()
    }
}
