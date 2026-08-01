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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.runInterruptible
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.domain.dns_rules.DnsRuleType
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.ImportRulesManager
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.UpdateLocalRulesWorkManager.Companion.REFRESH_LOCAL_DNS_BLACKLIST_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.UpdateLocalRulesWorkManager.Companion.REFRESH_LOCAL_DNS_CLOAKING_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.UpdateLocalRulesWorkManager.Companion.REFRESH_LOCAL_DNS_FORWARDING_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.UpdateLocalRulesWorkManager.Companion.REFRESH_LOCAL_DNS_IP_BLACKLIST_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.UpdateLocalRulesWorkManager.Companion.REFRESH_LOCAL_DNS_WHITELIST_WORK
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.UpdateRemoteRulesWorkManager.Companion.REMOTE_RULES_NAME_ARG
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.UpdateRemoteRulesWorkManager.Companion.REMOTE_RULES_TYPE_ARG
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.UpdateRemoteRulesWorkManager.Companion.REMOTE_RULES_URL_ARG
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingRulesWorkManager.Companion.MIX_DNS_BLACKLIST_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingRulesWorkManager.Companion.MIX_DNS_CLOAKING_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingRulesWorkManager.Companion.MIX_DNS_FORWARDING_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingRulesWorkManager.Companion.MIX_DNS_IP_BLACKLIST_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingRulesWorkManager.Companion.MIX_DNS_WHITELIST_WORK
import java.io.File
import javax.inject.Inject
import javax.inject.Named

class UpdateRemoteDnsRulesWorker(private val appContext: Context, workerParams: WorkerParameters) :
    CoroutineWorker(appContext, workerParams) {

    init {
        App.instance.daggerComponent.inject(this)
    }

    @Inject
    @Named(CoroutinesModule.DISPATCHER_IO)
    lateinit var dispatcherIo: CoroutineDispatcher

    @Inject
    lateinit var downloadRulesManager: DownloadRemoteRulesManager

    override suspend fun doWork(): Result {
        try {
            val url = inputData.getString(REMOTE_RULES_URL_ARG) ?: return Result.failure()
            val ruleType = inputData.getString(REMOTE_RULES_TYPE_ARG)?.let {
                DnsRuleType.valueOf(it)
            } ?: return Result.failure()
            val ruleName = inputData.getString(REMOTE_RULES_NAME_ARG) ?: return Result.failure()
            val fileName = when (ruleType) {
                DnsRuleType.BLACKLIST -> "blacklist-remote.txt"
                DnsRuleType.WHITELIST -> "whitelist-remote.txt"
                DnsRuleType.IP_BLACKLIST -> "ip-blacklist-remote.txt"
                DnsRuleType.FORWARDING -> "forwarding-rules-remote.txt"
                DnsRuleType.CLOAKING -> "cloaking-rules-remote.txt"
            }
            val file = downloadRulesManager.downloadRules(ruleName, url, fileName)

            while (isLocalDnsRulesImportingInProgress(ruleType)
                || isMixDnsRulesInProgress(ruleType)
            ) {
                delay(500)
            }

            file?.let {
                if (it.length() > 0) {
                    importRulesFromFile(it, ruleType, url, ruleName)
                } else {
                    return Result.failure()
                }
            } ?: return Result.retry()
            return Result.success()
        } catch (e: Exception) {
            loge("UpdateRemoteDnsRulesWorker doWork", e)
        }
        return Result.failure()
    }

    private suspend fun importRulesFromFile(
        file: File,
        ruleType: DnsRuleType,
        url: String,
        ruleName: String
    ) = runInterruptible(dispatcherIo) {
        ImportRulesManager(
            context = appContext,
            rulesVariant = ruleType,
            remoteRulesUrl = url,
            remoteRulesName = ruleName,
            importType = ImportRulesManager.ImportType.REMOTE_RULES,
            filePathToImport = arrayOf(file.path)
        ).run()
    }

    private fun isLocalDnsRulesImportingInProgress(type: DnsRuleType): Boolean =
        WorkManager.getInstance(appContext)
            .getWorkInfosForUniqueWork(getLocalWorkName(type)).get()
            .firstOrNull()?.state == WorkInfo.State.RUNNING


    private fun getLocalWorkName(type: DnsRuleType) =
        when (type) {
            DnsRuleType.BLACKLIST -> REFRESH_LOCAL_DNS_BLACKLIST_WORK
            DnsRuleType.WHITELIST -> REFRESH_LOCAL_DNS_WHITELIST_WORK
            DnsRuleType.IP_BLACKLIST -> REFRESH_LOCAL_DNS_IP_BLACKLIST_WORK
            DnsRuleType.FORWARDING -> REFRESH_LOCAL_DNS_FORWARDING_WORK
            DnsRuleType.CLOAKING -> REFRESH_LOCAL_DNS_CLOAKING_WORK
        }

    private fun isMixDnsRulesInProgress(type: DnsRuleType): Boolean =
        WorkManager.getInstance(appContext)
            .getWorkInfosForUniqueWork(getMixWorkName(type)).get()
            .firstOrNull()?.state == WorkInfo.State.RUNNING

    private fun getMixWorkName(type: DnsRuleType) =
        when (type) {
            DnsRuleType.BLACKLIST -> MIX_DNS_BLACKLIST_WORK
            DnsRuleType.WHITELIST -> MIX_DNS_WHITELIST_WORK
            DnsRuleType.IP_BLACKLIST -> MIX_DNS_IP_BLACKLIST_WORK
            DnsRuleType.FORWARDING -> MIX_DNS_FORWARDING_WORK
            DnsRuleType.CLOAKING -> MIX_DNS_CLOAKING_WORK
        }

}
