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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_settings

import androidx.annotation.WorkerThread
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.domain.dns_rules.DnsRuleType
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingRulesWorkManager
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.UpdateLocalRulesWorkManager
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.UpdateRemoteRulesWorkManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.REMOTE_BLACKLIST_URL
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.REMOTE_CLOAKING_URL
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.REMOTE_FORWARDING_URL
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.REMOTE_IP_BLACKLIST_URL
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.REMOTE_WHITELIST_URL
import java.io.File
import javax.inject.Inject
import kotlin.Exception

class RulesEraser @Inject constructor(
    private val preferences: PreferenceRepository,
    private val pathVars: PathVars,
    private val remixExistingRulesWorkManager: RemixExistingRulesWorkManager,
    private val updateRemoteDnsRulesManager: UpdateRemoteRulesWorkManager,
    private val updateLocalRulesWorkManager: UpdateLocalRulesWorkManager
) {

    var callback: OnRulesErased? = null

    @WorkerThread
    fun eraseRules(ruleType: DnsRuleType) {
        stopRelatedWorks(ruleType)
        Thread.sleep(500)
        getFiles(ruleType).forEach {
            eraseFile(it)
        }
        erasePreference(ruleType)
        callback?.onRulesEraseFinished()
    }

    private fun getFiles(ruleType: DnsRuleType) =
        when (ruleType) {
            DnsRuleType.BLACKLIST -> listOf(
                pathVars.dnsCryptBlackListPath,
                pathVars.dnsCryptSingleBlackListPath,
                pathVars.dnsCryptLocalBlackListPath,
                pathVars.dnsCryptRemoteBlackListPath
            )

            DnsRuleType.IP_BLACKLIST -> listOf(
                pathVars.dnsCryptIPBlackListPath,
                pathVars.dnsCryptSingleIPBlackListPath,
                pathVars.dnsCryptLocalIPBlackListPath,
                pathVars.dnsCryptRemoteIPBlackListPath
            )

            DnsRuleType.WHITELIST -> listOf(
                pathVars.dnsCryptWhiteListPath,
                pathVars.dnsCryptSingleWhiteListPath,
                pathVars.dnsCryptLocalWhiteListPath,
                pathVars.dnsCryptRemoteWhiteListPath
            )

            DnsRuleType.CLOAKING -> listOf(
                pathVars.dnsCryptCloakingRulesPath,
                pathVars.dnsCryptSingleCloakingRulesPath,
                pathVars.dnsCryptLocalCloakingRulesPath,
                pathVars.dnsCryptRemoteCloakingRulesPath
            )

            DnsRuleType.FORWARDING -> listOf(
                pathVars.dnsCryptForwardingRulesPath,
                pathVars.dnsCryptSingleForwardingRulesPath,
                pathVars.dnsCryptLocalForwardingRulesPath,
                pathVars.dnsCryptRemoteForwardingRulesPath
            )
        }

    private fun eraseFile(filePath: String) {

        var eraseText = ""
        if (filePath == pathVars.dnsCryptCloakingRulesPath
            || filePath == pathVars.dnsCryptSingleCloakingRulesPath
        ) {
            eraseText = pathVars.dnsCryptDefaultCloakingRule
        } else if (filePath == pathVars.dnsCryptForwardingRulesPath
            || filePath == pathVars.dnsCryptSingleForwardingRulesPath
        ) {
            eraseText = pathVars.dnsCryptDefaultForwardingRule
        }

        try {
            val file = File(filePath)
            if (file.isFile) {
                file.printWriter().use { it.println(eraseText) }
            }
        } catch (e: Exception) {
            loge("EraseRules", e)
        }

    }

    private fun erasePreference(ruleType: DnsRuleType) {
        preferences.setStringPreference(getRemoteRulesUrlPreferenceKey(ruleType), "")
    }

    private fun getRemoteRulesUrlPreferenceKey(ruleType: DnsRuleType) =
        when (ruleType) {
            DnsRuleType.BLACKLIST -> REMOTE_BLACKLIST_URL
            DnsRuleType.IP_BLACKLIST -> REMOTE_IP_BLACKLIST_URL
            DnsRuleType.WHITELIST -> REMOTE_WHITELIST_URL
            DnsRuleType.CLOAKING -> REMOTE_CLOAKING_URL
            DnsRuleType.FORWARDING -> REMOTE_FORWARDING_URL
        }

    private fun stopRelatedWorks(ruleType: DnsRuleType) {
        remixExistingRulesWorkManager.stopMix(ruleType)
        updateRemoteDnsRulesManager.stopRefreshDnsRules(ruleType)
        updateLocalRulesWorkManager.stopImportDnsRules(ruleType)
    }

    interface OnRulesErased {
        fun onRulesEraseFinished()
    }
}
