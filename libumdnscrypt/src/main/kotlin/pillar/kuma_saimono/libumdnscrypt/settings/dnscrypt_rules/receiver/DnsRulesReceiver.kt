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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.IntentCompat
import android.os.Build
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.DownloadRemoteRulesManager.Companion.DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_ACTION
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.DownloadRemoteRulesManager.Companion.DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_DATA
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.ImportRulesManager.Companion.UPDATE_DNS_RULES_PROGRESS_DATA
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.ImportRulesManager.Companion.UPDATE_LOCAL_DNS_RULES_PROGRESS_ACTION
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.ImportRulesManager.Companion.UPDATE_REMOTE_DNS_RULES_PROGRESS_ACTION
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.ImportRulesManager.Companion.UPDATE_TOTAL_DNS_RULES_PROGRESS_ACTION
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.ImportRulesManager.Companion.UPDATE_TOTAL_DNS_RULES_PROGRESS_DATA
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.DnsRulesDownloadProgress
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.DnsRulesUpdateProgress
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.recycler.DnsRuleRecycleItem
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.util.Date
import javax.inject.Inject

class DnsRulesReceiver @Inject constructor(
    context: Context
) : BroadcastReceiver() {

    var callback: Callback? = null

    private var receiverRegistered = false

    private val localBroadcastManager by lazy {
        LocalBroadcastManager.getInstance(context)
    }

    fun registerReceiver() {
        try {
            receiverRegistered = true
            localBroadcastManager.registerReceiver(
                this,
                IntentFilter(DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_ACTION)
            )
            localBroadcastManager.registerReceiver(
                this,
                IntentFilter(UPDATE_REMOTE_DNS_RULES_PROGRESS_ACTION)
            )
            localBroadcastManager.registerReceiver(
                this,
                IntentFilter(UPDATE_LOCAL_DNS_RULES_PROGRESS_ACTION)
            )
            localBroadcastManager.registerReceiver(
                this,
                IntentFilter(UPDATE_TOTAL_DNS_RULES_PROGRESS_ACTION)
            )
        } catch (e: Exception) {
            loge("DnsRulesReceiver registerReceiver", e)
        }
    }

    fun unregisterReceiver() {
        try {
            if (receiverRegistered) {
                receiverRegistered = false
                localBroadcastManager.unregisterReceiver(this)
            }
        } catch (e: Exception) {
            loge("DnsRulesReceiver unregisterReceiver", e)
        }
    }

    override fun onReceive(context: Context?, intent: Intent?) {
        when (intent?.action) {
            DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_ACTION -> downloadRemoteRulesProgress(intent)
            UPDATE_REMOTE_DNS_RULES_PROGRESS_ACTION -> updateRemoteRulesProgress(intent)
            UPDATE_LOCAL_DNS_RULES_PROGRESS_ACTION -> updateLocalRulesProgress(intent)
            UPDATE_TOTAL_DNS_RULES_PROGRESS_ACTION -> updateTotalRulesProgress(intent)
        }
    }

    private fun downloadRemoteRulesProgress(intent: Intent) {
        // IntentCompat performs the API-33 split internally, so the deprecated single-argument
        // overload no longer appears in this source at all.
        val data = IntentCompat.getParcelableExtra(
            intent, DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_DATA, DnsRulesDownloadProgress::class.java
        )
        data ?: return
        when (data) {
            is DnsRulesDownloadProgress.DownloadProgress -> {
                callback?.onUpdateRemoteRules(
                    DnsRuleRecycleItem.DnsRemoteRule(
                        name = data.name,
                        url = data.url,
                        date = Date(),
                        count = 0,
                        size = data.size,
                        inProgress = true
                    )
                )
            }

            is DnsRulesDownloadProgress.DownloadFinished -> {
                callback?.onUpdateRemoteRules(
                    DnsRuleRecycleItem.DnsRemoteRule(
                        name = data.name,
                        url = data.url,
                        date = Date(),
                        count = 0,
                        size = data.size,
                        inProgress = false
                    )
                )
            }

            is DnsRulesDownloadProgress.DownloadFailure -> {
                callback?.onUpdateRemoteRules(
                    DnsRuleRecycleItem.DnsRemoteRule(
                        name = data.name,
                        url = data.error,
                        date = Date(),
                        count = 0,
                        size = 0,
                        inProgress = false,
                        fault = true
                    )
                )
            }
        }
    }

    private fun updateRemoteRulesProgress(intent: Intent) {
        // IntentCompat performs the API-33 split internally, so the deprecated single-argument
        // overload no longer appears in this source at all.
        val data = IntentCompat.getParcelableExtra(
            intent, UPDATE_DNS_RULES_PROGRESS_DATA, DnsRulesUpdateProgress::class.java
        )
        data ?: return
        when (data) {
            is DnsRulesUpdateProgress.UpdateProgress -> {
                callback?.onUpdateRemoteRules(
                    DnsRuleRecycleItem.DnsRemoteRule(
                        name = data.name,
                        url = data.url ?: "",
                        date = Date(),
                        count = data.count,
                        size = data.size,
                        inProgress = true
                    )
                )
            }

            is DnsRulesUpdateProgress.UpdateFinished -> {
                callback?.onUpdateRemoteRules(
                    DnsRuleRecycleItem.DnsRemoteRule(
                        name = data.name,
                        url = data.url ?: "",
                        date = Date(),
                        count = data.count,
                        size = data.size,
                        inProgress = false
                    )
                )
                callback?.onUpdateFinished()
            }

            is DnsRulesUpdateProgress.UpdateFailure -> {
                callback?.onUpdateRemoteRules(
                    DnsRuleRecycleItem.DnsRemoteRule(
                        name = data.name,
                        url = data.url ?: "",
                        date = Date(),
                        count = 0,
                        size = 0,
                        inProgress = false,
                        fault = true
                    )
                )
                callback?.onUpdateFinished()
            }
        }
    }

    private fun updateLocalRulesProgress(intent: Intent) {
        // IntentCompat performs the API-33 split internally, so the deprecated single-argument
        // overload no longer appears in this source at all.
        val data = IntentCompat.getParcelableExtra(
            intent, UPDATE_DNS_RULES_PROGRESS_DATA, DnsRulesUpdateProgress::class.java
        )
        data ?: return
        when (data) {
            is DnsRulesUpdateProgress.UpdateProgress -> {
                callback?.onUpdateLocalRules(
                    DnsRuleRecycleItem.DnsLocalRule(
                        name = data.name,
                        date = Date(),
                        count = data.count,
                        size = data.size,
                        inProgress = true
                    )
                )
            }

            is DnsRulesUpdateProgress.UpdateFinished -> {
                callback?.onUpdateLocalRules(
                    DnsRuleRecycleItem.DnsLocalRule(
                        name = data.name,
                        date = Date(),
                        count = data.count,
                        size = data.size,
                        inProgress = false
                    )
                )
                callback?.onUpdateFinished()
            }

            is DnsRulesUpdateProgress.UpdateFailure -> {
                callback?.onUpdateLocalRules(
                    DnsRuleRecycleItem.DnsLocalRule(
                        name = data.name,
                        date = Date(),
                        count = 0,
                        size = 0,
                        inProgress = false,
                        fault = true
                    )
                )
                callback?.onUpdateFinished()
            }
        }
    }

    private fun updateTotalRulesProgress(intent: Intent) {
        val count = intent.getIntExtra(UPDATE_TOTAL_DNS_RULES_PROGRESS_DATA, 0)
        callback?.onUpdateTotalRules(count)
    }

    interface Callback {
        fun onUpdateRemoteRules(rules: DnsRuleRecycleItem.DnsRemoteRule)
        fun onUpdateLocalRules(rules: DnsRuleRecycleItem.DnsLocalRule)
        fun onUpdateTotalRules(count: Int)
        fun onUpdateFinished()
    }
}
