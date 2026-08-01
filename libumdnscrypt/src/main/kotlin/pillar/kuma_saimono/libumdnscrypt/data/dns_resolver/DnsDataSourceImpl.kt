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

import dagger.assisted.Assisted
import dagger.assisted.AssistedFactory
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.LOOPBACK_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.QUAD_DOH_SERVER
import pillar.kuma_saimono.libumdnscrypt.utils.dns.*
import java.net.URL
import javax.inject.Inject

class DnsDataSourceImpl @Inject constructor(
    private val udpResolverFactory: UdpResolverFactory,
    private val dohResolverFactory: DohResolverFactory
) : DnsDataSource {

    override fun resolveDomainUDP(
        domain: String,
        includeIPv6: Boolean,
        port: Int,
        timeout: Int
    ): Array<Record>? {
        val domainVerified = Domain(URL(domain).host ?: "")
        return if (includeIPv6) {
            (resolveDomainUDPIPv4(domainVerified, port, timeout) ?: emptyArray()) +
                    (resolveDomainUDPIPv6(domainVerified, port, timeout) ?: emptyArray())
        } else {
            resolveDomainUDPIPv4(domainVerified, port, timeout)
        }
    }


    private fun resolveDomainUDPIPv4(
        domain: Domain,
        port: Int,
        timeout: Int
    ): Array<Record>? {
        return udpResolverFactory.createUdpResolver(
            LOOPBACK_ADDRESS,
            port,
            Record.TYPE_A,
            timeout
        ).resolve(domain)
    }

    private fun resolveDomainUDPIPv6(
        domain: Domain,
        port: Int,
        timeout: Int
    ): Array<Record>? {
        return udpResolverFactory.createUdpResolver(
            LOOPBACK_ADDRESS,
            port,
            Record.TYPE_AAAA,
            timeout
        ).resolve(domain)
    }

    override fun resolveDomainDOH(
        domain: String,
        includeIPv6: Boolean,
        timeout: Int
    ): Array<Record>? {
        val domainVerified = Domain(URL(domain).host ?: "")
        return if (includeIPv6) {
            (resolveDomainDOHIPv4(domainVerified, timeout) ?: emptyArray()) +
                    (resolveDomainDOHIPv6(domainVerified, timeout) ?: emptyArray())
        } else {
            resolveDomainDOHIPv4(domainVerified, timeout)
        }
    }

    private fun resolveDomainDOHIPv4(
        domain: Domain,
        timeout: Int
    ): Array<Record>? {
        return dohResolverFactory.createDohResolver(
            QUAD_DOH_SERVER,
            Record.TYPE_A,
            timeout
        ).resolve(domain)
    }

    private fun resolveDomainDOHIPv6(
        domain: Domain,
        timeout: Int
    ): Array<Record>? {
        return dohResolverFactory.createDohResolver(
            QUAD_DOH_SERVER,
            Record.TYPE_AAAA,
            timeout
        ).resolve(domain)
    }

    override fun reverseResolveUDP(
        ip: String,
        port: Int,
        timeout: Int
    ): Array<Record>? {
        return udpResolverFactory.createUdpResolver(
            LOOPBACK_ADDRESS,
            port,
            Record.TYPE_PTR,
            timeout
        ).reverseResolve(ip)
    }

    override fun reverseResolveDOH(
        ip: String,
        timeout: Int
    ): Array<Record>? {
        return dohResolverFactory.createDohResolver(
            QUAD_DOH_SERVER,
            Record.TYPE_PTR,
            timeout
        ).reverseResolve(ip)
    }

    @AssistedFactory
    interface UdpResolverFactory {
        fun createUdpResolver(
            domain: String,
            @Assisted("port") port: Int,
            @Assisted("type") type: Int,
            @Assisted("timeout") timeout: Int = Resolver.DNS_DEFAULT_TIMEOUT_SEC
        ): UdpResolver
    }

    @AssistedFactory
    interface DohResolverFactory {
        fun createDohResolver(
            domain: String,
            @Assisted("type") type: Int,
            @Assisted("timeout") timeout: Int = Resolver.DNS_DEFAULT_TIMEOUT_SEC
        ): DohResolver
    }
}
