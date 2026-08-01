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

import android.Manifest
import android.app.NativeActivity
import android.app.role.RoleManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RuntimeTierManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.WireCakeInuService
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper
import pillar.kuma_saimono.libumdnscrypt.vpn.service.WardenDatapathGate

/**
 * THE APP ENTRY (SLINT substitution · 1A/1C) — the on-device SLINT render host, and since 1A the
 * MAIN/LAUNCHER: the icon opens THIS.
 *
 * A [NativeActivity]: the manifest `meta-data android.app.lib_name = "torta_ui"` makes the
 * framework `System.loadLibrary("torta_ui")`; the android-activity glue inside `libtorta_ui.so`
 * (slint's OFFICIAL `backend-android-activity-06` bridge) then resolves the crate's `android_main`
 * (torta_ui `src/lib.rs`), which installs the slint android platform on the activity's native
 * surface and renders the DESIGN-FINALE `TortaShell` (the 4-tab Home + the in-shell ||| Advanced
 * overlay), fed from the typed torta_core Records (honest cold baselines — never fabricated state).
 *
 * THE LIFECYCLE LAW (1C — measured, cited): each activity instance gets its OWN native rail — the
 * glue spawns a fresh `android_main` thread per instance (android-activity-0.6.1
 * native_activity/glue.rs:908), slint's platform slot is THREAD-local (i-slint-core
 * context.rs:51-54), `MainEvent::Destroy` breaks the event loop (androidwindowadapter.rs:267-268)
 * and `super.onDestroy()` BLOCKS until the rail thread returns (glue.rs:400-409) — so create and
 * teardown are inherently per-instance-clean, and relaunch renders on a fresh rail (witnessed:
 * 1c-baseline-1-relaunch.png). The launcher OWNS the app-level bracket around that law:
 * [SlintSurfaceLifecycle] via the Kotlin-Inject graph (compile-time, zero reflection) — feed-root
 * prep before the rail's first tail + the teardown witness after the rail unwound. The manifest
 * pins `launchMode="singleTask"`: ONE SLINT surface instance ever — re-launches surface the live
 * rail instead of stacking a second event loop.
 *
 * Launched through the Kotlin-Inject graph: [SlintUiComponent] → [SlintSpikeLauncher] (the
 * compile-time, zero-reflection DI axis the charter demands for every SLINT bridge).
 */
class TortaSlintActivity : NativeActivity() {

    /**
     * The Android-legal service-locator hop for framework-constructed activities (the graph itself
     * is compile-time Kotlin-Inject — zero reflection; this is a plain property pull, the
     * documented [SlintUiComponent] consumption idiom).
     */
    private val surfaceLifecycle: SlintSurfaceLifecycle by
        lazy(LazyThreadSafetyMode.NONE) {
            App.instance.slintUiComponent.slintSurfaceLifecycle
        }

    /** Debounce so a second START tap does not stack a second system consent dialog. */
    private var vpnRequested = false

    override fun onCreate(savedInstanceState: Bundle?) {
        // BEFORE super: super.onCreate() loads libtorta_ui.so and spawns the native rail thread
        // (glue.rs:908), whose first feed-tail lands within milliseconds — prep gets the head
        // start (async off-main either way; an unensured root reads as the honest "not written
        // yet", never a fault).
        surfaceLifecycle.onSurfaceCreated()
        bindWardenPostureBeforeAnySurfaceReads()
        super.onCreate(savedInstanceState)
        current = this
    }

    /**
     * Rehydrate the WARDEN's persisted posture at APP start, not only at DNSCrypt start.
     *
     * MEASURED DEFECT this closes. `RuntimeTierManager.rehydrateTier` is the only caller of
     * [WardenDatapathGate.bindDurable], and it runs from `onDnsCryptStarted()`. Until the engine
     * starts, the canonical `WardenObject` is a COLD instance with an UNBOUND durable tier, which
     * has two consequences and neither of them announces itself:
     *
     *  1. The WARDEN ||| SETTINGS pane renders cold defaults - every universal block OFF - while
     *     the user's real persisted posture may have them ON. On the AVD: `Block UDP-NTP` was
     *     toggled on, `app_data/runtime_tier/warden-matrix` was written, the app was force-stopped,
     *     and on relaunch the pane read OFF. Arming the engine brought it back ON from that same
     *     record. A firewall page that shows "Lockdown OFF / Fail closed OFF" over a stored ON is
     *     the worst shape of wrong value in this app: it reads as a safe answer.
     *  2. Edits made in that window are silently dropped. `Warden::set_universal_toggles` calls
     *     `write_through_state()`, which is documented as "a no-op if unbound" (warden/mod.rs:993),
     *     so the control appears to work, changes nothing durable, and is reverted by the first
     *     real rehydrate.
     *
     * Binding here fixes the CAUSE rather than papering the pane: one call, before the native rail
     * spawns and therefore before the first Warden feed can read anything. `bindDurable` rehydrates
     * the matrix and toggles from the record and drops any RULE19 TempAllow that lapsed while the
     * device was off; it ARMS nothing (the datapath still consults the user's firewall switch), so
     * this is inert on a device whose firewall is disarmed - which is exactly the AVD's state.
     *
     * Idempotent by construction: the engine's own later `bindDurable` re-reads the same record,
     * and any edit made in between was already written through because the tier is bound by then.
     *
     * Deliberately SYNCHRONOUS. It is a single small record (69 bytes as measured on the AVD), and
     * doing it off-thread would race the rail's first feed - the pane could still paint cold
     * defaults for a frame, which is the very thing being fixed. Fail-open: any throwable leaves
     * the previous behaviour exactly as it was.
     */
    private fun bindWardenPostureBeforeAnySurfaceReads() {
        try {
            val dir = applicationInfo.dataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR
            val rows = WardenDatapathGate.bindDurable(dir, System.currentTimeMillis())
            Log.i(TAG, "warden posture rehydrated at app start ($rows matrix row(s)) from $dir")
        } catch (t: Throwable) {
            Log.e(TAG, "warden posture rehydrate at app start failed - engine start will retry", t)
        }
    }

    override fun onResume() {
        super.onResume()
        // The singleTask launcher surfaces the live rail on relaunch — keep the consent-host ref
        // pointed at the visible instance.
        current = this
    }

    override fun onDestroy() {
        // super.onDestroy() BLOCKS until the slint loop breaks and android_main returns
        // (glue.rs:400-409) — the thread-local SlintContext (platform + window adapter +
        // components) drops WITH the rail thread. By this line the native surface is fully
        // torn down; the bracket below is the app-side witness.
        super.onDestroy()
        surfaceLifecycle.onSurfaceDestroyed()
        if (current === this) current = null
    }

    /**
     * THE VPN-CONSENT HOST (SLINT substitution · 4-FIX round 3) — the missing seam that kept the
     * tunnel deferred (every live ledger read 0). [TortaSlintBridge.setDnsCryptEnabled] starts the
     * DNSCrypt PROCESS from the native rail, but a static bridge has no Activity to host the
     * one-time `VpnService.prepare` consent dialog, so on a fresh install the tunnel never lifted →
     * no traffic routed through the resolver → the running-engine counts stayed at the honest cold
     * zero. This mirrors [pillar.kuma_saimono.libumdnscrypt.MainActivity.prepareVPNService] exactly:
     * prepare → if already consented start now, else host the system consent Activity and start on
     * RESULT_OK. Fail-open — a consent hiccup never crashes the rail; the tunnel simply stays down.
     */
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never crash the native rail
    private fun prepareVpnConsent() {
        try {
            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent == null) {
                startVpnFromConsent(RESULT_OK)
            } else if (!vpnRequested && !isFinishing) {
                vpnRequested = true
                startActivityForResult(prepareIntent, CODE_IS_VPN_ALLOWED)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "prepareVpnConsent failed", t)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == CODE_IS_VPN_ALLOWED) {
            vpnRequested = false
            startVpnFromConsent(resultCode)
        }
    }

    /**
     * THE NOTIFICATION-CONSENT HOST (#63 S1) — the twin gap to the VPN one: a [NativeActivity] never
     * asked for POST_NOTIFICATIONS, so on any Android-13+ fresh install EVERY notification (the engine
     * foreground-service notice, the Wire Cake Inu in-shade pairing-code entry, the celebratory grant)
     * was silently suppressed until the user hunted through system settings. The Inu notify-pair — type
     * the wireless code straight in the shade — is dead without it. Mirrors [prepareVpnConsent]: a no-op
     * below API 33 or when already granted, else the classic Activity permission request. Fail-open — a
     * consent hiccup never crashes the rail; notifications simply stay suppressed.
     */
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never crash the native rail
    private fun ensureNotificationPermission() {
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
            ) {
                return
            }
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), CODE_POST_NOTIFICATIONS)
        } catch (t: Throwable) {
            Log.e(TAG, "ensureNotificationPermission failed", t)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == CODE_POST_NOTIFICATIONS) {
            val granted = grantResults.isNotEmpty() &&
                grantResults[0] == PackageManager.PERMISSION_GRANTED
            Log.i(TAG, "POST_NOTIFICATIONS consent result: granted=$granted")
            if (granted) repostInuNotificationIfWanted()
        }
    }

    /**
     * FIRST-RUN ORDERING HEAL (#63 S1) — the always-on / pair intent starts [WireCakeInuService] and
     * asks for POST_NOTIFICATIONS in the SAME breath, so on the very first toggle the service posts its
     * searching-notification while consent is still pending → Android suppresses it and will NOT
     * retroactively surface it once consent lands. Re-post here the instant consent arrives, but ONLY
     * when the always-on notification is the wanted state — never for the engine-arm request path (that
     * foreground notice self-heals on its next state tick). Fail-open — a hiccup never crashes the rail.
     */
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never crash the native rail
    private fun repostInuNotificationIfWanted() {
        try {
            val prefs = PreferenceManager.getDefaultSharedPreferences(this)
            if (prefs.getBoolean(TortaeKeys.INU_ALWAYS_ON, false)) {
                WireCakeInuService.start(applicationContext)
                Log.i(TAG, "post-consent: re-posted Wire Cake Inu pairing notification")
            }
        } catch (t: Throwable) {
            Log.e(TAG, "repostInuNotificationIfWanted failed", t)
        }
    }

    /**
     * Persist the granted flag + lift the tunnel (the MainActivity.startVPNService recipe, minus
     * the toasts). RESULT_OK → the ServiceVPN comes up and system DNS routes through DNSCrypt.
     */
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never crash the native rail
    private fun startVpnFromConsent(resultCode: Int) {
        try {
            val prefs = PreferenceManager.getDefaultSharedPreferences(this)
            prefs.edit().putBoolean(TortaeKeys.VPN_SERVICE_ENABLED, resultCode == RESULT_OK).apply()
            if (resultCode == RESULT_OK) {
                ServiceVPNHelper.start("SLINT master switch consent granted", this)
                // The engine's foreground-service notice shares the POST_NOTIFICATIONS gap — ask at the
                // first arm so the ongoing "protected" notification is visible, not suppressed (#63 S1).
                ensureNotificationPermission()
            }
        } catch (t: Throwable) {
            Log.e(TAG, "startVpnFromConsent failed", t)
        }
    }

    /**
     * #60G — host the system default-browser role dialog (a role request needs an Activity; the
     * static bridge cannot host it). Fired via [launchBrowserRoleRequest] from the native rail.
     * The dialog result is deliberately unread: [TortaSlintBridge.browserRoleHeld] is the ONLY
     * truth source — the dialog outcome never flips the SLINT flag by itself.
     */
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never crash the native rail
    private fun hostBrowserRoleRequest() {
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
            val rm = getSystemService(RoleManager::class.java) ?: return
            if (!rm.isRoleAvailable(RoleManager.ROLE_BROWSER)) return
            if (rm.isRoleHeld(RoleManager.ROLE_BROWSER)) return
            startActivityForResult(
                rm.createRequestRoleIntent(RoleManager.ROLE_BROWSER),
                CODE_BROWSER_ROLE
            )
        } catch (t: Throwable) {
            Log.e(TAG, "hostBrowserRoleRequest failed", t)
        }
    }

    companion object {
        private const val TAG = "TORTA_SLINT"

        /** OUR request code for the system VPN-consent Activity (mirrors MainActivity's 110). */
        private const val CODE_IS_VPN_ALLOWED = 110

        /** OUR request code for the POST_NOTIFICATIONS runtime consent (Android 13+) — #63 S1. */
        private const val CODE_POST_NOTIFICATIONS = 111

        /** OUR request code for the #60G ROLE_BROWSER default-browser dialog. */
        private const val CODE_BROWSER_ROLE = 112

        /**
         * The live SLINT surface instance (singleTask ⇒ at most one). [TortaSlintBridge] runs on
         * the native rail thread and holds only the Application context; it hands the consent
         * request up to the visible Activity through this ref, posted onto the UI thread.
         */
        @Volatile private var current: TortaSlintActivity? = null

        /**
         * Called by [TortaSlintBridge.startVpnServiceIfConsented] when the master switch needs the
         * one-time VPN consent it cannot host from the static bridge. Posts onto the UI thread and
         * hosts the system consent dialog. A no-op if the surface is gone (fail-open).
         */
        @JvmStatic
        fun requestVpnConsent() {
            val act = current ?: return
            act.runOnUiThread { act.prepareVpnConsent() }
        }

        /**
         * Called by [TortaPillarBridge.inuAlwaysOn] (and the pair actions) when the user opts into a
         * notification the static bridge cannot host consent for. Posts onto the UI thread and hosts the
         * system POST_NOTIFICATIONS dialog. A no-op if the surface is gone / already granted (fail-open).
         */
        @JvmStatic
        fun requestNotificationPermission() {
            val act = current ?: return
            act.runOnUiThread { act.ensureNotificationPermission() }
        }

        /**
         * Called by [TortaSlintBridge.requestBrowserRole] (#60G) — the static bridge cannot host
         * the system role dialog. Posts onto the UI thread of the live SLINT surface. Returns
         * whether a live surface accepted the hand-off (`false` → the bridge reports 4).
         */
        @JvmStatic
        fun launchBrowserRoleRequest(): Boolean {
            val act = current ?: return false
            act.runOnUiThread { act.hostBrowserRoleRequest() }
            return true
        }
    }
}
