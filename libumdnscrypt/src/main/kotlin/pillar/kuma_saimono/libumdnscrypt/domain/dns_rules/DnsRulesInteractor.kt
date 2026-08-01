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

interface DnsRulesInteractor {

    suspend fun getMixedRulesMetadata(type: DnsRuleType): DnsRulesMetadata.MixedDnsRulesMetadata
    suspend fun getSingleRules(type: DnsRuleType): List<DnsRuleRecycleItem.DnsSingleRule>
    suspend fun saveSingleRules(type: DnsRuleType, rules: List<DnsRuleRecycleItem.DnsSingleRule>)
    suspend fun getRemoteRulesMetadata(type: DnsRuleType): DnsRulesMetadata.RemoteDnsRulesMetadata
    suspend fun getLocalRulesMetadata(type: DnsRuleType): DnsRulesMetadata.LocalDnsRulesMetadata
    suspend fun clearRemoteRules(type: DnsRuleType)
    suspend fun clearLocalRules(type: DnsRuleType)

    suspend fun isExternalStorageAllowsDirectAccess(): Boolean
}
