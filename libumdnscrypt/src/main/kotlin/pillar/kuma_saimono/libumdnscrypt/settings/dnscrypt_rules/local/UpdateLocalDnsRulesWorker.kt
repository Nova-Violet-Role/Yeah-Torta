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
import android.net.Uri
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
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.UpdateLocalRulesWorkManager.Companion.LOCAL_RULES_PATH_ARG
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.UpdateLocalRulesWorkManager.Companion.LOCAL_RULES_TYPE_ARG
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.UpdateLocalRulesWorkManager.Companion.LOCAL_RULES_URI_ARG
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.UpdateRemoteRulesWorkManager.Companion.REFRESH_REMOTE_DNS_BLACKLIST_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.UpdateRemoteRulesWorkManager.Companion.REFRESH_REMOTE_DNS_CLOAKING_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.UpdateRemoteRulesWorkManager.Companion.REFRESH_REMOTE_DNS_FORWARDING_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.UpdateRemoteRulesWorkManager.Companion.REFRESH_REMOTE_DNS_IP_BLACKLIST_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.UpdateRemoteRulesWorkManager.Companion.REFRESH_REMOTE_DNS_WHITELIST_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingRulesWorkManager.Companion.MIX_DNS_BLACKLIST_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingRulesWorkManager.Companion.MIX_DNS_CLOAKING_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingRulesWorkManager.Companion.MIX_DNS_FORWARDING_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingRulesWorkManager.Companion.MIX_DNS_IP_BLACKLIST_WORK
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingRulesWorkManager.Companion.MIX_DNS_WHITELIST_WORK
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import javax.inject.Inject
import javax.inject.Named

class UpdateLocalDnsRulesWorker(private val appContext: Context, workerParams: WorkerParameters) :
    CoroutineWorker(appContext, workerParams) {

    init {
        App.instance.daggerComponent.inject(this)
    }

    @Inject
    @Named(CoroutinesModule.DISPATCHER_IO)
    lateinit var dispatcherIo: CoroutineDispatcher

    override suspend fun doWork(): Result {
        try {
            val ruleType = inputData.getString(LOCAL_RULES_TYPE_ARG)?.let {
                DnsRuleType.valueOf(it)
            } ?: return Result.failure()
            val filesWithPath = inputData.getStringArray(LOCAL_RULES_PATH_ARG)
            val filesWithUri = inputData.getStringArray(LOCAL_RULES_URI_ARG)
            val files = filesWithPath ?: (filesWithUri?.map { Uri.parse(it) }?.toTypedArray()
                ?: return Result.failure())

            while (isRemoteDnsRulesImportingInProgress(ruleType)
                || isMixDnsRulesInProgress(ruleType)
            ) {
                delay(500)
            }

            importRulesFromFiles(files, ruleType)

            return Result.success()
        } catch (e: Exception) {
            loge("UpdateLocalDnsRulesWorker doWork", e)
        }
        return Result.failure()
    }

    private suspend fun importRulesFromFiles(
        files: Array<*>,
        ruleType: DnsRuleType,
    ) = runInterruptible(dispatcherIo) {
        ImportRulesManager(
            context = appContext,
            rulesVariant = ruleType,
            importType = ImportRulesManager.ImportType.LOCAL_RULES,
            filePathToImport = files
        ).run()
    }

    private fun isRemoteDnsRulesImportingInProgress(type: DnsRuleType): Boolean =
        WorkManager.getInstance(appContext)
            .getWorkInfosForUniqueWork(getRemoteWorkName(type)).get()
            .firstOrNull()?.state == WorkInfo.State.RUNNING


    private fun getRemoteWorkName(type: DnsRuleType) =
        when (type) {
            DnsRuleType.BLACKLIST -> REFRESH_REMOTE_DNS_BLACKLIST_WORK
            DnsRuleType.WHITELIST -> REFRESH_REMOTE_DNS_WHITELIST_WORK
            DnsRuleType.IP_BLACKLIST -> REFRESH_REMOTE_DNS_IP_BLACKLIST_WORK
            DnsRuleType.FORWARDING -> REFRESH_REMOTE_DNS_FORWARDING_WORK
            DnsRuleType.CLOAKING -> REFRESH_REMOTE_DNS_CLOAKING_WORK
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
