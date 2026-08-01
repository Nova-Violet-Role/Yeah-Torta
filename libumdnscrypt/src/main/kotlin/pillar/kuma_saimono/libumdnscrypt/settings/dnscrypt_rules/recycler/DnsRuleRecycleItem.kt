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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.recycler

import java.util.Date

sealed class DnsRuleRecycleItem {
    data class DnsRemoteRule(
        val name: String,
        val url: String,
        val date: Date,
        val count: Int,
        val size: Long,
        val inProgress: Boolean,
        val fault: Boolean = false
    ) : DnsRuleRecycleItem()

    data object AddRemoteRulesButton : DnsRuleRecycleItem()

    data class DnsLocalRule(
        val name: String,
        val date: Date,
        val count: Int,
        val size: Long,
        val inProgress: Boolean,
        val fault: Boolean = false
    ) : DnsRuleRecycleItem()

    data object AddLocalRulesButton : DnsRuleRecycleItem()

    data class DnsSingleRule(
        var rule: String,
        val protected: Boolean,
        val active: Boolean
    ) : DnsRuleRecycleItem()

    data object AddSingleRuleButton : DnsRuleRecycleItem()

    data class DnsRuleComment(
        val comment: String
    ) : DnsRuleRecycleItem()
}
