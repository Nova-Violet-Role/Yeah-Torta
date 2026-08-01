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

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.recycler.DnsRuleRecycleItem
import pillar.kuma_saimono.libumdnscrypt.utils.Utils.isLogsDirAccessible
import javax.inject.Inject
import javax.inject.Named

class DnsRulesInteractorImpl @Inject constructor(
    private val repository: DnsRulesRepository,
    @Named(CoroutinesModule.DISPATCHER_IO)
    private val dispatcherIo: CoroutineDispatcher
) : DnsRulesInteractor {

    override suspend fun getMixedRulesMetadata(type: DnsRuleType): DnsRulesMetadata.MixedDnsRulesMetadata =
        withContext(dispatcherIo) {
            when (type) {
                DnsRuleType.BLACKLIST -> repository.getMixedBlacklistRulesMetadata()
                DnsRuleType.WHITELIST -> repository.getMixedWhitelistRulesMetadata()
                DnsRuleType.IP_BLACKLIST -> repository.getMixedIpBlacklistRulesMetadata()
                DnsRuleType.FORWARDING -> repository.getMixedForwardingRulesMetadata()
                DnsRuleType.CLOAKING -> repository.getMixedCloakingRulesMetadata()
            }
        }

    override suspend fun getSingleRules(type: DnsRuleType): List<DnsRuleRecycleItem.DnsSingleRule> =
        withContext(dispatcherIo) {
            when (type) {
                DnsRuleType.BLACKLIST -> repository.getSingleBlacklistRules()
                DnsRuleType.WHITELIST -> repository.getSingleWhitelistRules()
                DnsRuleType.IP_BLACKLIST -> repository.getSingleIpBlacklistRules()
                DnsRuleType.FORWARDING -> repository.getSingleForwardingRules()
                DnsRuleType.CLOAKING -> repository.getSingleCloakingRules()
            }
        }

    override suspend fun saveSingleRules(
        type: DnsRuleType,
        rules: List<DnsRuleRecycleItem.DnsSingleRule>
    ) = withContext(dispatcherIo) {
        when (type) {
            DnsRuleType.BLACKLIST -> repository.saveSingleBlacklistRules(rules)
            DnsRuleType.WHITELIST -> repository.saveSingleWhitelistRules(rules)
            DnsRuleType.IP_BLACKLIST -> repository.saveSingleIpBlacklistRules(rules)
            DnsRuleType.FORWARDING -> repository.saveSingleForwardingRules(rules)
            DnsRuleType.CLOAKING -> repository.saveSingleCloakingRules(rules)
        }
    }

    override suspend fun getRemoteRulesMetadata(
        type: DnsRuleType
    ): DnsRulesMetadata.RemoteDnsRulesMetadata = withContext(dispatcherIo) {
        when (type) {
            DnsRuleType.BLACKLIST -> repository.getRemoteBlacklistRulesMetadata()
            DnsRuleType.WHITELIST -> repository.getRemoteWhitelistRulesMetadata()
            DnsRuleType.IP_BLACKLIST -> repository.getRemoteIpBlacklistRulesMetadata()
            DnsRuleType.FORWARDING -> repository.getRemoteForwardingRulesMetadata()
            DnsRuleType.CLOAKING -> repository.getRemoteCloakingRulesMetadata()
        }
    }

    override suspend fun getLocalRulesMetadata(
        type: DnsRuleType
    ): DnsRulesMetadata.LocalDnsRulesMetadata = withContext(dispatcherIo) {
        when (type) {
            DnsRuleType.BLACKLIST -> repository.getLocalBlacklistRulesMetadata()
            DnsRuleType.WHITELIST -> repository.getLocalWhitelistRulesMetadata()
            DnsRuleType.IP_BLACKLIST -> repository.getLocalIpBlacklistRulesMetadata()
            DnsRuleType.FORWARDING -> repository.getLocalForwardingRulesMetadata()
            DnsRuleType.CLOAKING -> repository.getLocalCloakingRulesMetadata()
        }
    }

    override suspend fun clearRemoteRules(type: DnsRuleType) = withContext(dispatcherIo) {
        when (type) {
            DnsRuleType.BLACKLIST -> repository.clearRemoteBlacklistRules()
            DnsRuleType.WHITELIST -> repository.clearRemoteWhitelistRules()
            DnsRuleType.IP_BLACKLIST -> repository.clearRemoteIpBlacklistRules()
            DnsRuleType.FORWARDING -> repository.clearRemoteForwardingRules()
            DnsRuleType.CLOAKING -> repository.clearRemoteCloakingRules()
        }
    }

    override suspend fun clearLocalRules(type: DnsRuleType) = withContext(dispatcherIo) {
        when (type) {
            DnsRuleType.BLACKLIST -> repository.clearLocalBlacklistRules()
            DnsRuleType.WHITELIST -> repository.clearLocalWhitelistRules()
            DnsRuleType.IP_BLACKLIST -> repository.clearLocalIpBlacklistRules()
            DnsRuleType.FORWARDING -> repository.clearLocalForwardingRules()
            DnsRuleType.CLOAKING -> repository.clearLocalCloakingRules()
        }
    }

    override suspend fun isExternalStorageAllowsDirectAccess(): Boolean =
        runInterruptible(dispatcherIo) {
            isLogsDirAccessible()
        }
}
