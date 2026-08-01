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

package pillar.kuma_saimono.libumdnscrypt.domain.dns_rules

import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.recycler.DnsRuleRecycleItem

interface DnsRulesRepository {

    suspend fun getMixedBlacklistRulesMetadata(): DnsRulesMetadata.MixedDnsRulesMetadata
    suspend fun getSingleBlacklistRules(): List<DnsRuleRecycleItem.DnsSingleRule>
    fun saveSingleBlacklistRules(rules: List<DnsRuleRecycleItem.DnsSingleRule>)
    suspend fun getRemoteBlacklistRulesMetadata(): DnsRulesMetadata.RemoteDnsRulesMetadata
    fun clearRemoteBlacklistRules()
    suspend fun getLocalBlacklistRulesMetadata(): DnsRulesMetadata.LocalDnsRulesMetadata
    fun clearLocalBlacklistRules()

    suspend fun getMixedWhitelistRulesMetadata(): DnsRulesMetadata.MixedDnsRulesMetadata
    suspend fun getSingleWhitelistRules(): List<DnsRuleRecycleItem.DnsSingleRule>
    fun saveSingleWhitelistRules(rules: List<DnsRuleRecycleItem.DnsSingleRule>)
    suspend fun getRemoteWhitelistRulesMetadata(): DnsRulesMetadata.RemoteDnsRulesMetadata
    fun clearRemoteWhitelistRules()
    suspend fun getLocalWhitelistRulesMetadata(): DnsRulesMetadata.LocalDnsRulesMetadata
    fun clearLocalWhitelistRules()

    suspend fun getMixedIpBlacklistRulesMetadata(): DnsRulesMetadata.MixedDnsRulesMetadata
    suspend fun getSingleIpBlacklistRules(): List<DnsRuleRecycleItem.DnsSingleRule>
    fun saveSingleIpBlacklistRules(rules: List<DnsRuleRecycleItem.DnsSingleRule>)
    suspend fun getRemoteIpBlacklistRulesMetadata(): DnsRulesMetadata.RemoteDnsRulesMetadata
    fun clearRemoteIpBlacklistRules()
    suspend fun getLocalIpBlacklistRulesMetadata(): DnsRulesMetadata.LocalDnsRulesMetadata
    fun clearLocalIpBlacklistRules()

    suspend fun getMixedForwardingRulesMetadata(): DnsRulesMetadata.MixedDnsRulesMetadata
    suspend fun getSingleForwardingRules(): List<DnsRuleRecycleItem.DnsSingleRule>
    fun saveSingleForwardingRules(rules: List<DnsRuleRecycleItem.DnsSingleRule>)
    suspend fun getRemoteForwardingRulesMetadata(): DnsRulesMetadata.RemoteDnsRulesMetadata
    fun clearRemoteForwardingRules()
    suspend fun getLocalForwardingRulesMetadata(): DnsRulesMetadata.LocalDnsRulesMetadata
    fun clearLocalForwardingRules()

    suspend fun getMixedCloakingRulesMetadata(): DnsRulesMetadata.MixedDnsRulesMetadata
    suspend fun getSingleCloakingRules(): List<DnsRuleRecycleItem.DnsSingleRule>
    fun saveSingleCloakingRules(rules: List<DnsRuleRecycleItem.DnsSingleRule>)
    suspend fun getRemoteCloakingRulesMetadata(): DnsRulesMetadata.RemoteDnsRulesMetadata
    fun clearRemoteCloakingRules()
    suspend fun getLocalCloakingRulesMetadata(): DnsRulesMetadata.LocalDnsRulesMetadata
    fun clearLocalCloakingRules()

    companion object {
        const val LOCAL_RULES_DEFAULT_HEADER = "local-rules.txt"
        const val REMOTE_RULES_DEFAULT_HEADER = "remote-rules.txt"
    }
}
