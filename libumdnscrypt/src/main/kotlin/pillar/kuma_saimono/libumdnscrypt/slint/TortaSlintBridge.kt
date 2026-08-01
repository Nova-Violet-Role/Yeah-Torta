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

package pillar.kuma_saimono.libumdnscrypt.slint

import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.util.Log
import androidx.annotation.Keep
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesAux
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesKiller
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesRunner
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper
import pillar.kuma_saimono.libumdnscrypt.vpn.tunnel.TunnelController

/**
 * THE SLINT ↔ ENGINE DRIVE BRIDGE (SLINT substitution · 2-DRIVE-CORE) — the Rust→Kotlin→service
 * seam behind the SLINT HOME master switch. `torta_ui`'s `android_main` `engine-toggled` callback
 * JNI-calls [setDnsCryptEnabled]; the 1 s state-poll Timer JNI-calls [dnsCryptStateCode]. This is
 * the ONE place the pure-Rust SLINT rail reaches the Kotlin ModulesService authority (the D09 law:
 * the module runner is Kotlin's — the .so never fakes a start; it ASKS the service to start/stop
 * DNSCrypt and READS the real state back onto the switch).
 *
 * WHY a static bridge (not a callback into the rail): the SLINT surface renders on the
 * NativeActivity native thread (`android_main`); a rail-thread `FindClass` sees only the SYSTEM
 * classloader, so the Rust side resolves THIS class through the Activity's classloader and
 * JNI-calls these statics. Every entry point is `@JvmStatic` (a real static the JNI `CallStatic*`
 * path resolves) + `@Keep` (R8 must never rename/strip them — the Rust side hard-codes the class +
 * method names) and FAIL-OPEN (never throw across the JNI boundary — the never-throw law the
 * Sanctum/SLINT hooks share).
 *
 * The start/stop recipe mirrors the canonical UI path (`ModulesControlTileManager.manageDnsCrypt`),
 * minus the QS-tile chrome: ensure the operation mode (first-start init the stripped legacy shell
 * no longer runs), allow system DNS (no-root), `ModulesRunner.runDNSCrypt` → ACTION_START_DNSCRYPT
 * → ModulesService, persist the intent, speed the state loop, and lift the VPN when consent is
 * already granted. STOP mirrors it via `ModulesKiller.stopDNSCrypt`.
 */
@Keep
object TortaSlintBridge {

    private const val TAG = "TORTA_SLINT"

    // OUR stable state contract the Rust poll maps (deliberately NOT the ModuleState ordinal — this
    // decouples the Rust side from any future enum reordering).
    private const val CODE_STOPPED = 0
    private const val CODE_STARTING = 1
    private const val CODE_RUNNING = 2
    private const val CODE_STOPPING = 3
    private const val CODE_FAULT = 5

    /**
     * Drive DNSCrypt on/off from the SLINT master switch. `enable` is the switch's toggled value
     * (`engine-toggled(true)` = START, `false` = STOP — the widgets.slint `toggled(!on)` contract).
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun setDnsCryptEnabled(enable: Boolean) {
        try {
            val context: Context = App.instance.applicationContext
            val modulesStatus = ModulesStatus.getInstance()
            if (enable) {
                ensureOperationMode(context, modulesStatus)
                allowSystemDNS(context, modulesStatus)
                ModulesRunner.runDNSCrypt(context)
                ModulesAux.saveDNSCryptStateRunning(true)
                ModulesAux.speedupModulesStateLoopTimer(context)
                startVpnServiceIfConsented(context, modulesStatus)
                Log.i(TAG, "engine-drive: START DNSCrypt requested (mode=${modulesStatus.mode})")
            } else {
                ModulesKiller.stopDNSCrypt(context)
                ModulesAux.saveDNSCryptStateRunning(false)
                ModulesAux.speedupModulesStateLoopTimer(context)
                Log.i(TAG, "engine-drive: STOP DNSCrypt requested")
            }
        } catch (t: Throwable) {
            Log.e(TAG, "engine-drive setDnsCryptEnabled($enable) failed", t)
        }
    }

    /**
     * The live DNSCrypt state as OUR stable int code (the Rust poll maps it to `engine-running` +
     * the crown state line). Fail-open to STOPPED — a read failure never fakes RUNNING.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: a read failure never fakes RUNNING
    fun dnsCryptStateCode(): Int =
        try {
            when (ModulesStatus.getInstance().dnsCryptState) {
                ModuleState.RUNNING -> CODE_RUNNING
                ModuleState.STARTING,
                ModuleState.RESTARTING -> CODE_STARTING
                ModuleState.STOPPING -> CODE_STOPPING
                ModuleState.FAULT -> CODE_FAULT
                else -> CODE_STOPPED
            }
        } catch (t: Throwable) {
            Log.e(TAG, "engine-drive dnsCryptStateCode failed", t)
            CODE_STOPPED
        }

    /**
     * Whether the DNSCrypt VPN tunnel is actually up — the truthful "the shield is engaged" signal
     * for the SLINT crown (SLINT substitution · 4-FIX round 4). Tortä's Rust resolver rides IN the
     * DNSCrypt [ServiceVPN]; there is NO separate dnscrypt-proxy process, so [dnsCryptStateCode]
     * (the legacy [ModulesStatus.dnsCryptState], which watches for that process) stays STOPPED even
     * while the tunnel shields DNS — witnessed on-device: VPN CONNECTED on tun0 + the resolver
     * ledger filling (queries=151) while the crown still read STOPPED.
     *
     * ★ SPLIT-BRAIN CURE (#129 field bug 1): this used to read [TortaeKeys.VPN_SERVICE_ENABLED] —
     * a persisted pref a backup restore / `pm install -r` resurrects as `true` into a process with
     * no tunnel, so the crown showed SHIELDED over a DNS blackhole (and stayed SHIELDED after STOP
     * when a teardown leg failed to clear the pref). [TunnelController.isDatapathLive] is the Rust
     * datapath's own live-holder — set at spawn, cleared FIRST in stop, dead with the process — so
     * the crown flips off the REAL transport, never a remembered one. Fail-open to `false` — a
     * read failure never fakes ON.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: a read failure never fakes ON
    fun engineTunnelUp(): Boolean =
        try {
            TunnelController.isDatapathLive()
        } catch (t: Throwable) {
            Log.e(TAG, "engine-drive engineTunnelUp failed", t)
            false
        }

    /**
     * #59 D2 · THE DONATE TRUTH — direct-link route. Fires a REAL `ACTION_VIEW` intent so the
     * Ko-Fi link opens in the user's DEFAULT browser. The URL is handed in from the Rust side and
     * is ALWAYS `torta_core::donate::donate_url()` (the four-sealed-clone majority vote — engine
     * truth, never a surface string; the .slint layer cannot divert it). `FLAG_ACTIVITY_NEW_TASK`
     * because the caller is the Slint render thread on the application context, not an Activity.
     * Fail-open: an ActivityNotFoundException (no browser on the device) logs and skips — the
     * shell keeps rendering, nothing crashes.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: no browser must never crash the shell
    fun openDonate(url: String) {
        try {
            val context: Context = App.instance.applicationContext
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        } catch (t: Throwable) {
            Log.e(TAG, "engine-drive openDonate failed", t)
        }
    }

    // ── #60C TEXT-MODE LANE — the carbon fetch bay (rust-pull, the house pattern:
    //    NO JNI downcalls exist and none are added). carbonFetch() rides a daemon
    //    thread through the platform HTTPS stack — every socket inside the YeAH
    //    Tortä tunnel like the rest of the device; the result parks in a @Volatile
    //    bay and the Rust carbon seam timer polls carbonPageSeq(), pulling the body
    //    only when the seq advances. FELT-TRUTH: a fetch failure lands AS a failure
    //    body + status -1 — never a canned page. ──
    @Volatile private var carbonSeq: Long = 0L
    @Volatile private var carbonStatus: Int = 0
    @Volatile private var carbonUrl: String = ""
    @Volatile private var carbonBody: String = ""

    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: a fetch failure renders AS a failure
    fun carbonFetch(url: String) {
        Thread({
            var status = -1
            var body: String
            try {
                val target =
                    if (url.startsWith("http://") || url.startsWith("https://")) url
                    else "https://$url"
                val conn =
                    java.net.URL(target).openConnection() as java.net.HttpURLConnection
                conn.instanceFollowRedirects = true
                conn.connectTimeout = 15000
                conn.readTimeout = 20000
                conn.setRequestProperty(
                    "User-Agent",
                    "Mozilla/5.0 (Android) TortaCarbon/0.1 text-mode"
                )
                conn.setRequestProperty("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
                status = conn.responseCode
                val stream = if (status < 400) conn.inputStream else conn.errorStream
                val cap = 524288
                val sb = StringBuilder()
                stream?.bufferedReader(Charsets.UTF_8)?.use { r ->
                    val buf = CharArray(8192)
                    while (sb.length < cap) {
                        val n = r.read(buf)
                        if (n <= 0) break
                        sb.append(buf, 0, minOf(n, cap - sb.length))
                    }
                }
                body = sb.toString()
                conn.disconnect()
            } catch (t: Throwable) {
                Log.e(TAG, "carbonFetch failed", t)
                body = "fetch failed — ${t.javaClass.simpleName}: ${t.message}"
                status = -1
            }
            carbonUrl = url
            carbonStatus = status
            carbonBody = body
            carbonSeq += 1
        }, "carbon-fetch").apply { isDaemon = true }.start()
    }

    @JvmStatic @Keep fun carbonPageSeq(): Long = carbonSeq

    @JvmStatic @Keep fun carbonPageStatus(): Int = carbonStatus

    @JvmStatic @Keep fun carbonPageUrl(): String = carbonUrl

    @JvmStatic @Keep fun carbonPageBody(): String = carbonBody

    /**
     * #60G THE ROLE LANE — read whether Tortä ACTUALLY holds the system default-browser role.
     * A REAL `RoleManager.isRoleHeld(ROLE_BROWSER)` read on every call — never a cached claim.
     * Pre-Q devices have no RoleManager: honest `false`. Fail-open to `false` — a read failure
     * never fakes the role.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: a read failure never fakes the role
    fun browserRoleHeld(): Boolean =
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                false
            } else {
                val rm = App.instance.applicationContext.getSystemService(RoleManager::class.java)
                rm != null && rm.isRoleHeld(RoleManager.ROLE_BROWSER)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "engine-drive browserRoleHeld failed", t)
            false
        }

    /**
     * #60G THE ROLE LANE — fire the system default-browser request. Returns OUR stable status
     * code: 1 SENT (dialog posted onto the live SLINT Activity) · 2 already-held · 3 role
     * unavailable (pre-Q / no RoleManager / role disabled) · 4 surface-gone (no live Activity
     * to host the dialog) · 5 error. The request NEVER claims success — the Rust side re-reads
     * [browserRoleHeld] for truth (the flag flips only when the system says so).
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never throw across the JNI boundary
    fun requestBrowserRole(): Int =
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                3
            } else {
                val rm = App.instance.applicationContext.getSystemService(RoleManager::class.java)
                when {
                    rm == null || !rm.isRoleAvailable(RoleManager.ROLE_BROWSER) -> 3
                    rm.isRoleHeld(RoleManager.ROLE_BROWSER) -> 2
                    TortaSlintActivity.launchBrowserRoleRequest() -> 1
                    else -> 4
                }
            }
        } catch (t: Throwable) {
            Log.e(TAG, "engine-drive requestBrowserRole failed", t)
            5
        }

    /**
     * First-start init the stripped legacy shell no longer performs: if the operation mode is
     * unset, derive it (no-root x86_64 → VPN_MODE) the same way `ModulesControlTileManager` does,
     * then read fix-TTL. Idempotent — a no-op once the mode is established.
     */
    private fun ensureOperationMode(context: Context, modulesStatus: ModulesStatus) {
        val mode = modulesStatus.mode
        if (mode != null && mode != OperationMode.UNDEFINED) return
        val prefRepo = App.instance.daggerComponent.getPreferenceRepository().get()
        val defaultPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        val rootIsAvailable = prefRepo.getBoolPreference(TortaeKeys.ROOT_IS_AVAILABLE)
        val runModulesWithRoot =
            defaultPreferences.getBoolean(TortaeKeys.RUN_MODULES_WITH_ROOT, false)
        val operationModeStr = prefRepo.getStringPreference(TortaeKeys.OPERATION_MODE)
        var derived = OperationMode.UNDEFINED
        if (operationModeStr.isNotEmpty()) {
            derived = OperationMode.valueOf(operationModeStr)
        }
        ModulesAux.switchModes(rootIsAvailable, runModulesWithRoot, derived)
        modulesStatus.isFixTTL = defaultPreferences.getBoolean(TortaeKeys.FIX_TTL, false)
    }

    /**
     * No-root: let system DNS route through the module (the `ModulesControlTileManager`
     * allowSystemDNS).
     */
    private fun allowSystemDNS(context: Context, modulesStatus: ModulesStatus) {
        val defaultPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        if (
            (!modulesStatus.isRootAvailable || !modulesStatus.isUseModulesWithRoot) &&
                !defaultPreferences.getBoolean(TortaeKeys.PREVENT_DNS_LEAKS, false)
        ) {
            modulesStatus.isSystemDNSAllowed = true
        }
    }

    /**
     * Lift the VPN tunnel so traffic routes through DNSCrypt (the query feed fills) — ONLY when the
     * one-time system VPN consent is already granted (`VpnService.prepare == null`). If consent is
     * NOT yet granted, `prepare` returns an Intent we cannot host from here (no Activity result):
     * the DNSCrypt PROCESS still starts and the state flips RUNNING; the tunnel simply waits for
     * consent.
     */
    private fun startVpnServiceIfConsented(context: Context, modulesStatus: ModulesStatus) {
        val defaultPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        if (modulesStatus.mode != OperationMode.VPN_MODE && !modulesStatus.isFixTTL) {
            return
        }
        // ★ SPLIT-BRAIN CURE (#129 field bug 1): "already up, don't double-start" must be measured
        // against the live datapath, not the VPN_SERVICE_ENABLED pref — a stale pref (backup
        // restore, `pm install -r`) made this guard swallow the master-switch tap: the user tapped
        // ON and NOTHING started. A stale `true` over a dead tunnel now logs and falls through to a
        // real start (which rewrites the pref honestly below).
        if (TunnelController.isDatapathLive()) {
            return
        }
        if (defaultPreferences.getBoolean(TortaeKeys.VPN_SERVICE_ENABLED, false)) {
            Log.w(
                TAG,
                "engine-drive: VPN_SERVICE_ENABLED=true but the datapath is dead (stale pref " +
                    "from a dead process) — starting the tunnel anyway"
            )
        }
        if (VpnService.prepare(context) == null) {
            defaultPreferences.edit().putBoolean(TortaeKeys.VPN_SERVICE_ENABLED, true).apply()
            ServiceVPNHelper.start("SLINT master switch", context)
        } else {
            // Consent not yet granted: the static bridge cannot host the system consent dialog, so
            // hand it up to the live SLINT Activity (posts onto the UI thread). On RESULT_OK the
            // Activity lifts the tunnel — traffic then routes through DNSCrypt and the live ledger
            // fills (SLINT substitution · 4-FIX round 3; was the "tunnel deferred" dead end).
            Log.i(TAG, "engine-drive: VPN consent needed — requesting via SLINT Activity")
            TortaSlintActivity.requestVpnConsent()
        }
    }

    // ------------------------------------------------------------------------------------------
    // BUGS2 #64 · NOTIFY-BAR TRUTH FEED — the Slint Notify-Bar and the REAL Android foreground
    // notification drink from the SAME TrafficStats well. The Rust 500 ms state timer JNI-calls
    // [trafficSnapshot]; we compute honest byte-counter deltas (never a fabricated number — the
    // FELT-TRUTH LAW) and, throttled, mirror the same speeds onto the live ModulesService
    // notification via [ModulesServiceNotificationManager.updateNotification] — so the shade
    // shows the identical truth the in-app pillar shows, even with the UI backgrounded.
    // ------------------------------------------------------------------------------------------

    private const val NOTIFY_PUSH_INTERVAL_MS = 2_000L

    @Volatile private var trafficLastNanos = 0L
    @Volatile private var trafficLastRx = -1L
    @Volatile private var trafficLastTx = -1L
    @Volatile private var notifyLastPushMs = 0L

    /**
     * Returns `[dlBps, ulBps]` — honest bytes-per-second deltas of the device's total interface
     * counters — or `[-1, -1]` when no honest number exists yet (first call baseline, counter
     * reset, or [android.net.TrafficStats.UNSUPPORTED]). FAIL-OPEN: never throws across JNI.
     */
    @JvmStatic
    @Keep
    fun trafficSnapshot(): LongArray {
        try {
            val rx = android.net.TrafficStats.getTotalRxBytes()
            val tx = android.net.TrafficStats.getTotalTxBytes()
            if (rx < 0L || tx < 0L) return longArrayOf(-1L, -1L)

            val now = System.nanoTime()
            val lastNanos = trafficLastNanos
            val lastRx = trafficLastRx
            val lastTx = trafficLastTx
            trafficLastNanos = now
            trafficLastRx = rx
            trafficLastTx = tx

            // No baseline yet / counter went backwards (radio reset) → no honest number.
            if (lastNanos == 0L || lastRx < 0L || rx < lastRx || tx < lastTx) {
                return longArrayOf(-1L, -1L)
            }
            val dtSec = (now - lastNanos) / 1_000_000_000.0
            if (dtSec <= 0.0) return longArrayOf(-1L, -1L)

            val dl = ((rx - lastRx) / dtSec).toLong().coerceAtLeast(0L)
            val ul = ((tx - lastTx) / dtSec).toLong().coerceAtLeast(0L)
            pushIntoLiveNotification(App.instance.applicationContext, dl, ul)
            return longArrayOf(dl, ul)
        } catch (e: Exception) {
            Log.e(TAG, "trafficSnapshot failed", e)
            return longArrayOf(-1L, -1L)
        }
    }

    /** Throttled (2 s) mirror of the honest speeds onto the live foreground notification. */
    private fun pushIntoLiveNotification(context: Context, dlBps: Long, ulBps: Long) {
        val nowMs = System.currentTimeMillis()
        if (nowMs - notifyLastPushMs < NOTIFY_PUSH_INTERVAL_MS) return
        notifyLastPushMs = nowMs
        try {
            if (ModulesStatus.getInstance().dnsCryptState != ModuleState.RUNNING) return
            val manager = pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceNotificationManager
                .getManager(context) ?: return
            manager.updateNotification(
                context,
                uniffi.torta_core.tortaText("app_name"),
                "↓ ${formatBps(dlBps)}  ·  ↑ ${formatBps(ulBps)}",
                0L
            )
        } catch (e: Exception) {
            Log.e(TAG, "notify-bar live push failed", e)
        }
    }

    private fun formatBps(bps: Long): String = when {
        bps < 0L -> "—"
        bps < 1024L -> "$bps B/s"
        bps < 1024L * 1024L -> String.format(java.util.Locale.US, "%.1f KB/s", bps / 1024.0)
        else -> String.format(java.util.Locale.US, "%.1f MB/s", bps / (1024.0 * 1024.0))
    }
}
