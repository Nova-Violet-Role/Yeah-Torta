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

package pillar.kuma_saimono.libumdnscrypt.data.dns_rules

import java.io.InputStreamReader

interface DnsRulesDataSource {
    fun getBlacklistRulesStream(): InputStreamReader
    fun getSingleBlacklistRulesStream(): InputStreamReader?
    fun saveSingleBlacklistRules(rules: List<String>)
    fun getRemoteBlacklistRulesStream(): InputStreamReader
    fun getRemoteBlacklistRulesFileSize(): Long
    fun getRemoteBlacklistRulesFileDate(): Long
    fun clearRemoteBlacklistRules()
    fun getLocalBlacklistRulesStream(): InputStreamReader
    fun clearLocalBlacklistRules()
    fun getLocalBlacklistRulesFileSize(): Long
    fun getLocalBlacklistRulesFileDate(): Long

    fun getWhitelistRulesStream(): InputStreamReader
    fun getSingleWhitelistRulesStream(): InputStreamReader?
    fun saveSingleWhitelistRules(rules: List<String>)
    fun getRemoteWhitelistRulesStream(): InputStreamReader
    fun getRemoteWhitelistRulesFileSize(): Long
    fun getRemoteWhitelistRulesFileDate(): Long
    fun clearRemoteWhitelistRules()
    fun getLocalWhitelistRulesStream(): InputStreamReader
    fun getLocaleWhitelistRulesFileSize(): Long
    fun getLocalWhitelistRulesFileDate(): Long
    fun clearLocalWhitelistRules()

    fun getIpBlacklistRulesStream(): InputStreamReader
    fun getSingleIpBlacklistRulesStream(): InputStreamReader?
    fun saveSingleIpBlacklistRules(rules: List<String>)
    fun getRemoteIpBlacklistRulesStream(): InputStreamReader
    fun getRemoteIpBlacklistRulesFileSize(): Long
    fun getRemoteIpBlacklistRulesFileDate(): Long
    fun clearRemoteIpBlacklistRules()
    fun getLocalIpBlacklistRulesStream(): InputStreamReader
    fun getLocalIpBlacklistRulesFileSize(): Long
    fun getLocalIpBlacklistRulesFileDate(): Long
    fun clearLocalIpBlacklistRules()

    fun getForwardingRulesStream(): InputStreamReader
    fun getSingleForwardingRulesStream(): InputStreamReader?
    fun saveSingleForwardingRules(rules: List<String>)
    fun getRemoteForwardingRulesStream(): InputStreamReader
    fun getRemoteForwardingRulesFileSize(): Long
    fun getRemoteForwardingRulesFileDate(): Long
    fun clearRemoteForwardingRules()
    fun getLocalForwardingRulesStream(): InputStreamReader
    fun getLocalForwardingRulesFileSize(): Long
    fun getLocalForwardingRulesFileDate(): Long
    fun clearLocalForwardingRules()

    fun getCloakingRulesStream(): InputStreamReader
    fun getSingleCloakingRulesStream(): InputStreamReader?
    fun saveSingleCloakingRules(rules: List<String>)
    fun getRemoteCloakingRulesStream(): InputStreamReader
    fun getRemoteCloakingRulesFileSize(): Long
    fun getRemoteCloakingRulesFileDate(): Long
    fun clearRemoteCloakingRules()
    fun getLocalCloakingRulesStream(): InputStreamReader
    fun getLocalCloakingRulesFileSize(): Long
    fun getLocalCloakingRulesFileDate(): Long
    fun clearLocalCloakingRules()
}
