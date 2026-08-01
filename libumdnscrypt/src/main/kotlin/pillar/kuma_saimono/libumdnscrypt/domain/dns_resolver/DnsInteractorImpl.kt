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

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.actor
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.settings.tor_ips.DomainEntity
import pillar.kuma_saimono.libumdnscrypt.settings.tor_ips.DomainIpEntity
import pillar.kuma_saimono.libumdnscrypt.settings.tor_ips.IpEntity
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv4_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv6_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.dns.Resolver
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.io.IOException
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject

private const val ERROR_RETRY_COUNT = 1

class DnsInteractorImpl @Inject constructor(
    private val pathVars: PathVars,
    private val dnsRepository: DnsRepository,
) : DnsInteractor {
    private val modulesStatus = ModulesStatus.getInstance()

    private val ipv4Regex by lazy { Regex(IPv4_REGEX) }
    private val ipv6Regex by lazy { Regex(IPv6_REGEX) }

    override fun resolveDomain(domain: String, includeIPv6: Boolean): Set<String> =
        resolveDomain(domain, includeIPv6, Resolver.DNS_DEFAULT_TIMEOUT_SEC)

    override fun resolveDomain(domain: String, includeIPv6: Boolean, timeout: Int): Set<String> =
        when {
            modulesStatus.dnsCryptState == ModuleState.RUNNING && modulesStatus.isDnsCryptReady -> {
                dnsRepository.resolveDomainUDP(
                    domain,
                    includeIPv6,
                    pathVars.dnsCryptPort.toInt(),
                    timeout
                )
            }
            else -> {
                dnsRepository.resolveDomainDOH(domain, includeIPv6, timeout)
            }
        }.filter {
            it.matches(ipv4Regex) || it.matches(ipv6Regex)
        }.toHashSet()

    override fun reverseResolve(ip: String): String =
        when {
            modulesStatus.dnsCryptState == ModuleState.RUNNING && modulesStatus.isDnsCryptReady -> {
                dnsRepository.reverseResolveDomainUDP(
                    ip,
                    pathVars.dnsCryptPort.toInt(),
                    Resolver.DNS_DEFAULT_TIMEOUT_SEC
                )
            }
            else -> {
                dnsRepository.reverseResolveDomainDOH(
                    ip,
                    Resolver.DNS_DEFAULT_TIMEOUT_SEC
                )
            }
        }

    @ObsoleteCoroutinesApi
    override suspend fun resolveDomainOrIp(
        domainIps: Set<DomainIpEntity>,
        includeIPv6: Boolean,
        timeout: Int
    ): Set<DomainIpEntity> {
        val result = Collections.newSetFromMap(ConcurrentHashMap<DomainIpEntity, Boolean>())

        coroutineScope {
            val channel = actor<Triple<DomainIpEntity, Deferred<DomainIpEntity>, Int>> {
                for (triple in channel) {
                    launch {
                        supervisorScope {
                            try {
                                val hostIp = triple.second.await()
                                result.add(hostIp)
                                if (result.size == domainIps.size) {
                                    channel.close(CancellationException())
                                }
                            } catch (e: IOException) {
                                if (triple.third < ERROR_RETRY_COUNT) {
                                    channel.send(
                                        Triple(
                                            triple.first,
                                            async {
                                                resolveDomainOrIp(
                                                    triple.first,
                                                    includeIPv6,
                                                    timeout
                                                )
                                            },
                                            triple.third + 1
                                        )
                                    )

                                } else {
                                    loge("DnsInteractor resolveDomainOrIp", e)
                                    result.add(triple.first)
                                    if (result.size == domainIps.size) {
                                        channel.close(CancellationException())
                                    }
                                }
                            } catch (e: CancellationException) {
                                channel.close(CancellationException())
                            } catch (e: Exception) {
                                loge("DnsInteractor resolveDomainOrIp", e)
                                channel.close(CancellationException())
                            }
                        }
                    }
                }
            }

            supervisorScope {
                domainIps.map {
                    Triple(it, async { resolveDomainOrIp(it, includeIPv6, timeout) }, 0)
                }.map {
                    ensureActive()
                    channel.send(it)
                }
            }

        }

        return result
    }

    private fun resolveDomainOrIp(
        domainIp: DomainIpEntity,
        includeIPv6: Boolean,
        timeout: Int
    ): DomainIpEntity =
        when (domainIp) {
            is DomainEntity -> {
                DomainEntity(
                    domainIp.domain,
                    resolveDomain(domainIp.domain, includeIPv6, timeout),
                    domainIp.isActive
                )
            }
            is IpEntity -> {
                IpEntity(domainIp.ip, reverseResolve(domainIp.ip), domainIp.isActive)
            }
        }
}
