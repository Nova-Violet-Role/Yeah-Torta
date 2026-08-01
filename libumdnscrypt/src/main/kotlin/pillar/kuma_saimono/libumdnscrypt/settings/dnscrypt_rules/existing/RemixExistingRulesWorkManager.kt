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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkRequest
import androidx.work.workDataOf
import pillar.kuma_saimono.libumdnscrypt.domain.dns_rules.DnsRuleType
import java.util.concurrent.TimeUnit
import javax.inject.Inject

class RemixExistingRulesWorkManager @Inject constructor(
    private val context: Context,
) {

    fun startMix(ruleType: DnsRuleType) {

        val constraints = Constraints.Builder()
            .setRequiresStorageNotLow(true)
            .build()

        val mixRequest = OneTimeWorkRequestBuilder<RemixExistingDnsRulesWorker>()
            .setConstraints(constraints)
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS,
                TimeUnit.MILLISECONDS
            )
            .setInputData(
                workDataOf(
                    MIX_RULES_TYPE_ARG to ruleType.name,
                )
            )
            .build()

        WorkManager.getInstance(context)
            .enqueueUniqueWork(
                getWorkName(ruleType),
                ExistingWorkPolicy.REPLACE,
                mixRequest
            )
    }

    fun stopMix(type: DnsRuleType) {
        WorkManager.getInstance(context)
            .cancelUniqueWork(getWorkName(type))
    }

    private fun getWorkName(type: DnsRuleType) =
        when (type) {
            DnsRuleType.BLACKLIST -> MIX_DNS_BLACKLIST_WORK
            DnsRuleType.WHITELIST -> MIX_DNS_WHITELIST_WORK
            DnsRuleType.IP_BLACKLIST -> MIX_DNS_IP_BLACKLIST_WORK
            DnsRuleType.FORWARDING -> MIX_DNS_FORWARDING_WORK
            DnsRuleType.CLOAKING -> MIX_DNS_CLOAKING_WORK
        }

    companion object {
        const val MIX_RULES_TYPE_ARG = "pillar.kuma_saimono.libumdnscrypt.SINGLE_RULES_TYPE_ARG"

        const val MIX_DNS_BLACKLIST_WORK =
            "pillar.kuma_saimono.libumdnscrypt.MIX_DNS_BLACKLIST_WORK"
        const val MIX_DNS_WHITELIST_WORK =
            "pillar.kuma_saimono.libumdnscrypt.MIX_DNS_WHITELIST_WORK"
        const val MIX_DNS_IP_BLACKLIST_WORK =
            "pillar.kuma_saimono.libumdnscrypt.MIX_DNS_IP_BLACKLIST_WORK"
        const val MIX_DNS_FORWARDING_WORK =
            "pillar.kuma_saimono.libumdnscrypt.MIX_DNS_FORWARDING_WORK"
        const val MIX_DNS_CLOAKING_WORK =
            "pillar.kuma_saimono.libumdnscrypt.REFRESH_SINGLE_DNS_CLOAKING_WORK"
    }
}
