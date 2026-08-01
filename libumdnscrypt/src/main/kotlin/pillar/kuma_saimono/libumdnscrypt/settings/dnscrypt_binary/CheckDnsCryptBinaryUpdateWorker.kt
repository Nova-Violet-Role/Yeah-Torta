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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_binary

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import org.json.JSONObject
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.AUX_CHANNEL_ID
import pillar.kuma_saimono.libumdnscrypt.BuildConfig
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RuntimeTierManager
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.DNSCRYPT_PROXY_RELEASES_API
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_UPDATE_AVAILABLE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_UPSTREAM_VERSION
import pillar.kuma_saimono.libumdnscrypt.utils.web.HttpsConnectionManager
import javax.inject.Inject
import javax.inject.Named

/**
 * Notify-only awareness of newer dnscrypt-proxy upstream releases. Polls the GitHub releases feed
 * over TLS, compares the upstream semver to the bundled [BuildConfig.DNSCRYPT_BUNDLED_VERSION], and
 * if newer persists a flag + posts a notification telling the user to update the app (via F-Droid).
 *
 * CONTRACT: this NEVER downloads or writes a binary. The dnscrypt-proxy binary runs from
 * nativeLibraryDir (W^X, read-only on API 29+); a binary bump ships only as a new APK. This honours
 * the W^X constraint and F-Droid's no-in-app-update policy. (Resolver/relay/odoh + rule data refresh
 * is handled separately by dnscrypt-proxy's own minisign-verified [sources] refresh + the rule workers.)
 */
class CheckDnsCryptBinaryUpdateWorker(
    private val appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    init {
        App.instance.daggerComponent.inject(this)
    }

    @Inject
    @Named(CoroutinesModule.DISPATCHER_IO)
    lateinit var dispatcherIo: CoroutineDispatcher

    @Inject
    lateinit var httpsConnectionManager: HttpsConnectionManager

    @Inject
    lateinit var preferences: PreferenceRepository

    override suspend fun doWork(): Result = try {
        val latest = withContext(dispatcherIo) { fetchLatestVersion() }
        when {
            latest == null -> Result.retry()
            isNewer(latest, BuildConfig.DNSCRYPT_BUNDLED_VERSION) -> {
                logi("dnscrypt-proxy upstream $latest > bundled ${BuildConfig.DNSCRYPT_BUNDLED_VERSION}")
                preferences.setStringPreference(DNSCRYPT_UPSTREAM_VERSION, latest)
                preferences.setBoolPreference(DNSCRYPT_UPDATE_AVAILABLE, true)
                withContext(dispatcherIo) { syncDnscryptLayer(latest) }
                notifyUpdateAvailable(latest)
                Result.success()
            }
            else -> {
                preferences.setBoolPreference(DNSCRYPT_UPDATE_AVAILABLE, false)
                withContext(dispatcherIo) { syncDnscryptLayer(latest) }
                Result.success()
            }
        }
    } catch (e: Exception) {
        loge("CheckDnsCryptBinaryUpdateWorker", e)
        Result.retry()
    }

    /**
     * D14 — the DNSCrypt LAYER version-sync (the Rust `dnscrypt_update` pillar; distinct from the
     * notify-only binary check above, which stays untouched). Distills the fetched release into the
     * line-oriented envelope the Rust side parses (`version=<tag>` plus the AUDITED capability
     * coordinates from [distillUpstreamEnvelope] — the releases feed itself carries no capability
     * lines, so the registry is hand-audited per release), then drives the typed chain
     * [TortaCore.currentDnscryptEnvelope] → [TortaCore.buildDnscryptSyncPlan] →
     * [TortaCore.applyDnscryptSyncPlan]: the "the layer is at version X with capabilities Y"
     * coordinate persists through the shared durable tier ([RuntimeTierManager] rehydrates it as
     * pillar 5 at boot). CONTRACT preserved: control-plane only — no binary download/swap, no
     * pool/hot-path touch (the Rust module enforces the core isolation statically). Best-effort +
     * crash-safe: a fault changes nothing and never disturbs the notify path.
     */
    private fun syncDnscryptLayer(latest: String) {
        try {
            val layer = TortaCore.currentDnscryptEnvelope()
            val upstreamEnvelope = distillUpstreamEnvelope(latest)
            val plan = TortaCore.buildDnscryptSyncPlan(upstreamEnvelope) ?: return
            if (!plan.isNewer) {
                logi(
                    "dnscrypt layer sync — upstream $latest is not newer than the " +
                        "${layer?.protocolVersion ?: "implemented"} layer; no-op plan"
                )
                return
            }
            val durableDir = App.instance.daggerComponent.getPathVars().get().appDataDir +
                RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR
            val applied = TortaCore.applyDnscryptSyncPlan(
                durableDir,
                upstreamEnvelope,
                System.currentTimeMillis() / MILLIS_PER_SECOND,
            )
            if (applied) {
                logi(
                    "dnscrypt layer sync — plan applied durably: layer " +
                        "${layer?.protocolVersion ?: "?"} → $latest " +
                        "(missing=${plan.missingCapabilities.size} sources=${plan.newSources.size})"
                )
            }
        } catch (e: Exception) {
            loge("CheckDnsCryptBinaryUpdateWorker syncDnscryptLayer", e)
        }
    }

    private fun fetchLatestVersion(): String? {
        val body = StringBuilder()
        httpsConnectionManager.get(DNSCRYPT_PROXY_RELEASES_API) { input ->
            input.bufferedReader().use { body.append(it.readText()) }
        }
        val tag = JSONObject(body.toString()).optString("tag_name").trim().removePrefix("v")
        return tag.takeIf { it.matches(Regex("""\d+\.\d+\.\d+.*""")) }
    }

    /**
     * ★ 2.1.18-absorb — distill the fetched release tag into the line-oriented envelope WITH the
     * hand-audited capability coordinates. The releases feed carries no capability lines, so this
     * registry is the audit's product: each entry names an upstream release's fetch-worthy deltas
     * in the SAME coordinates as the Rust `current_envelope` (dnscrypt_update.rs) — an
     * absorbed/surpassed delta therefore diffs to ZERO missing (the honest "we own it" record on
     * the durable `dnscrypt-sync` row), while a future release we have NOT audited yet still
     * lands its version bump (forward-tolerant: version-only remains a valid envelope by the
     * module contract). Extend ONLY alongside a real audit — a cap line here is a CLAIM that the
     * delta was measured against the Tortä tree (v2.1.17 audited at the PQ flagship absorb;
     * v2.1.18's fragmentation-hardening + latency-honesty absorbed with this distillation).
     */
    private fun distillUpstreamEnvelope(latest: String): String = buildString {
        append("version=").append(latest).append('\n')
        if (isAtLeast(latest, "2.1.17")) {
            append("cap=pqdnscrypt_xwing_0x0003\n")
            append("cap=key_rotate_on_network_change\n")
        }
        if (isAtLeast(latest, "2.1.18")) {
            append("cap=pq_cert_fetch_fragmentation_hardening\n")
            append("cap=latency_excludes_setup\n")
        }
    }

    /** `latest >= floor` on the same strict 3-part compare as [isNewer] (its negated converse). */
    private fun isAtLeast(latest: String, floor: String): Boolean = !isNewer(floor, latest)

    /** Strict 3-part numeric semver compare; true iff [latest] > [bundled] (e.g. 2.1.16 > 2.1.9). */
    private fun isNewer(latest: String, bundled: String): Boolean {
        val a = parse(latest)
        val b = parse(bundled)
        for (i in 0 until 3) {
            if (a[i] != b[i]) return a[i] > b[i]
        }
        return false
    }

    private fun parse(version: String): IntArray {
        val parts = version.split('.', '-', '+')
        return IntArray(3) { i ->
            parts.getOrNull(i)?.takeWhile { it.isDigit() }?.toIntOrNull() ?: 0
        }
    }

    // Guarded upstream: areNotificationsEnabled() short-circuits when POST_NOTIFICATIONS is denied,
    // and the whole body is wrapped in a try/catch that swallows any SecurityException. Lint cannot
    // follow the runtime guard, so the check is suppressed here.
    @SuppressLint("MissingPermission")
    private fun notifyUpdateAvailable(version: String) {
        try {
            val manager = NotificationManagerCompat.from(appContext)
            if (!manager.areNotificationsEnabled()) return
            val intent = Intent(appContext, TortaSlintActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            val pending = PendingIntent.getActivity(
                appContext, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val text = uniffi.torta_core.tortaText("dnscrypt_update_text").format(version)
            val notification = NotificationCompat.Builder(appContext, AUX_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(uniffi.torta_core.tortaText("dnscrypt_update_title"))
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setAutoCancel(true)
                .setContentIntent(pending)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .build()
            manager.notify(NOTIFICATION_ID, notification)
        } catch (e: Exception) {
            loge("CheckDnsCryptBinaryUpdateWorker notify", e)
        }
    }

    companion object {
        private const val NOTIFICATION_ID = 1916
        private const val MILLIS_PER_SECOND = 1000L
        const val CHECK_DNSCRYPT_BINARY_UPDATE_WORK =
            "pillar.kuma_saimono.libumdnscrypt.CHECK_DNSCRYPT_BINARY_UPDATE_WORK"
    }
}
