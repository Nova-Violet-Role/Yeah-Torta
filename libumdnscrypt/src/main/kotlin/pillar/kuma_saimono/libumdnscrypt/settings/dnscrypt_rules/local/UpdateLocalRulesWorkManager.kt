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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local

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

class UpdateLocalRulesWorkManager @Inject constructor(
    private val context: Context,
) {

    fun startImportDnsRules(ruleType: DnsRuleType, filesToImport: Array<*>) {

        filesToImport.firstOrNull() ?: return

        val constraints = Constraints.Builder()
            .setRequiresStorageNotLow(true)
            .build()

        val files = if (filesToImport.first() is String) {
            LOCAL_RULES_PATH_ARG to filesToImport.map { it.toString() }.toTypedArray()
        } else {
            LOCAL_RULES_URI_ARG to filesToImport.map { it.toString() }.toTypedArray()
        }

        val importRequest = OneTimeWorkRequestBuilder<UpdateLocalDnsRulesWorker>()
            .setConstraints(constraints)
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS,
                TimeUnit.MILLISECONDS
            )
            .setInputData(
                workDataOf(
                    LOCAL_RULES_TYPE_ARG to ruleType.name,
                    files
                )
            )
            .build()

        WorkManager.getInstance(context)
            .enqueueUniqueWork(
                getWorkName(ruleType),
                ExistingWorkPolicy.REPLACE,
                importRequest
            )
    }

    fun stopImportDnsRules(type: DnsRuleType) {
        WorkManager.getInstance(context)
            .cancelUniqueWork(getWorkName(type))
    }

    private fun getWorkName(type: DnsRuleType) =
        when (type) {
            DnsRuleType.BLACKLIST -> REFRESH_LOCAL_DNS_BLACKLIST_WORK
            DnsRuleType.WHITELIST -> REFRESH_LOCAL_DNS_WHITELIST_WORK
            DnsRuleType.IP_BLACKLIST -> REFRESH_LOCAL_DNS_IP_BLACKLIST_WORK
            DnsRuleType.FORWARDING -> REFRESH_LOCAL_DNS_FORWARDING_WORK
            DnsRuleType.CLOAKING -> REFRESH_LOCAL_DNS_CLOAKING_WORK
        }

    companion object {
        const val LOCAL_RULES_TYPE_ARG = "pillar.kuma_saimono.libumdnscrypt.LOCAL_RULES_TYPE_ARG"
        const val LOCAL_RULES_PATH_ARG = "pillar.kuma_saimono.libumdnscrypt.LOCAL_RULES_PATH_ARG"
        const val LOCAL_RULES_URI_ARG = "pillar.kuma_saimono.libumdnscrypt.LOCAL_RULES_URI_ARG"

        const val REFRESH_LOCAL_DNS_BLACKLIST_WORK =
            "pillar.kuma_saimono.libumdnscrypt.REFRESH_LOCAL_DNS_BLACKLIST_WORK"
        const val REFRESH_LOCAL_DNS_WHITELIST_WORK =
            "pillar.kuma_saimono.libumdnscrypt.REFRESH_LOCAL_DNS_WHITELIST_WORK"
        const val REFRESH_LOCAL_DNS_IP_BLACKLIST_WORK =
            "pillar.kuma_saimono.libumdnscrypt.REFRESH_LOCAL_DNS_IP_BLACKLIST_WORK"
        const val REFRESH_LOCAL_DNS_FORWARDING_WORK =
            "pillar.kuma_saimono.libumdnscrypt.REFRESH_LOCAL_DNS_FORWARDING_WORK"
        const val REFRESH_LOCAL_DNS_CLOAKING_WORK =
            "pillar.kuma_saimono.libumdnscrypt.REFRESH_LOCAL_DNS_CLOAKING_WORK"
    }
}
