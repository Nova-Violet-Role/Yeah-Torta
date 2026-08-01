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

package pillar.kuma_saimono.libumdnscrypt

import android.app.*
import android.content.res.Configuration
import android.graphics.Color
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat.getSystemService
import androidx.lifecycle.ProcessLifecycleOwner
import pillar.kuma_saimono.libumdnscrypt.crash_handling.TopExceptionHandler
import pillar.kuma_saimono.libumdnscrypt.di.*
import pillar.kuma_saimono.libumdnscrypt.dns_engine.settings.PresetFirstRun
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.WireCakeInuComponent
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.create
import pillar.kuma_saimono.libumdnscrypt.language.Language
import pillar.kuma_saimono.libumdnscrypt.slint.SlintUiComponent
import pillar.kuma_saimono.libumdnscrypt.slint.create
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_binary.CheckDnsCryptBinaryUpdateWorker
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkRequest.Companion.DEFAULT_BACKOFF_DELAY_MILLIS
import java.util.concurrent.TimeUnit

const val AUX_CHANNEL_ID = "Auxiliary"

class App : Application() {

    val daggerComponent: AppComponent by lazy {
        DaggerAppComponent
            .builder()
            .appContext(applicationContext)
            .build()
    }

    val subcomponentsManager by lazy {
        SubcomponentsManager(this, daggerComponent)
    }

    /**
     * The Wire Cake Inu pillar's Kotlin-Inject graph (the Dagger→Kotlin-Inject showcase for a
     * self-contained pillar). Held once per process; the Inu Activity/Service pull their manager +
     * elevation seam from here, and the keep-alive card pulls the shared elevation seam + power store.
     */
    val wireCakeInuComponent: WireCakeInuComponent by lazy {
        WireCakeInuComponent::class.create(applicationContext)
    }

    /**
     * The #69 SLINT-on-Android spike graph (OMEGA Stage-D · D1): provides the
     * [pillar.kuma_saimono.libumdnscrypt.slint.SlintSpikeLauncher] that opens
     * [pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity] — the NativeActivity hosting the
     * libtorta_ui.so SLINT render. Kotlin-Inject, compile-time, zero reflection (the
     * WireCakeInuComponent pattern, in the B3 GAP-5 native `@Inject`-ctor idiom).
     */
    val slintUiComponent: SlintUiComponent by lazy {
        SlintUiComponent::class.create(applicationContext)
    }

    @Volatile
    var isAppForeground: Boolean = false

    companion object {
        @JvmStatic
        lateinit var instance: App
            private set
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)

        Language.setFromPreference(this, "pref_fast_language")
    }

    override fun onCreate() {
        super.onCreate()

        instance = this

        // #9/#10 UniFFI PROOF — call the generated binding (Rust #[uniffi::export] torta_core_version) via
        // JNA across the .so; a correct value proves UniFFI's JNA/libffi marshalling end-to-end. Then the
        // #9 C7 PROOF — the FULL Haskell-muscle chain: Kotlin → UniFFI → Rust → C-ABI → dlopen(libtorta_hs.so)
        // → the GHC RTS (hs_init via the .so's ELF constructor) → the Haskell `foreign export ccall
        // torta_hs_probe`. A correct 242 (=100*2+42) proves OUR own headless Haskell (#131 mkHeadlessLib)
        // runs on-device with ZERO JNI — the rail every Phase-D muscle rides. Both crash-proof.
        //
        // ★ E-FIX r4 (startup jank) — OFF the main thread. The first UniFFI touch loads libtorta_core.so
        // (JNA init + the uniffi contract checks) and the Haskell probe dlopens libtorta_hs.so (GHC RTS
        // boot via its ELF constructor) — measured inside the cold-start main-thread block (round-4
        // logcat 00:06:40.86→41.06, part of the witnessed "Skipped 51 frames" / Davey splash-exit jank).
        // ONE named background thread keeps the probe ORDER + the exact TORTA_UNIFFI/TORTA_HASKELL log
        // lines (the AVD rounds grep them) AND pre-warms the native lib before the UI's first native
        // call: JVM class-init is thread-safe, so a concurrent first native call simply joins the
        // one-time load instead of re-paying it — never a double load, never a race.
        Thread({
            try {
                android.util.Log.i("TORTA_UNIFFI", "tortaCoreVersion() via UniFFI = " + uniffi.torta_core.tortaCoreVersion())
            } catch (t: Throwable) {
                android.util.Log.e("TORTA_UNIFFI", "UniFFI call FAILED under arm64 translation: " + t)
            }
            try {
                android.util.Log.i("TORTA_HASKELL", "haskellProbe(100) via UniFFI→Rust→C-ABI→Haskell = " + uniffi.torta_core.haskellProbe(100))
            } catch (t: Throwable) {
                android.util.Log.e("TORTA_HASKELL", "Haskell C7 call FAILED: " + t)
            }
        }, "torta-native-probe").start()

        // Tortä Pillar 13 §B — seed the out-of-box 🔒 Privacy default profile ONCE on ANY start path
        // (launcher, boot-complete, FGS restart, settings deep-link), not just the skippable
        // install-only TopFragment.actionModulesNotInstalled path. Value-only + datapath-safe +
        // idempotent (guarded by pref_torta_default_preset_seeded); a profile is a starting point,
        // not a lock — subsystems read these values only when they arm (#85). Cheap no-op after run 1.
        PresetFirstRun.seedDefaultProfileIfFirstRun(this)

        // Rotation is ON by default on EVERY install (Socio 2026-06-26) — incl. updates where the bundle
        // seed above was skipped by its already-configured guard. The switch stays (user-toggleable); only
        // its default flips ON. Idempotent + respects an explicit user-off (only sets when the key is absent).
        PresetFirstRun.ensureRotationDefaultOn(this)

        // The rest of the constant all-ON pillars (Centauri mirror, dnsmasq never-forward/bogus-priv, Warden
        // watch) materialized into the store on EVERY install — same defect/fix as rotation: the managers read
        // these `getBoolean(key, true)` but the dashboard CARDS read getBoolPreference (`getBoolean(key, false)`),
        // so on an update where the bundle seed was skipped the cards showed "off" while the engine ran ON. This
        // makes the store explicit so every reader agrees. Idempotent + respects an explicit user-off.
        PresetFirstRun.ensureAlwaysOnPillarDefaults(this)

        Language.setFromPreference(this, "pref_fast_language")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            createAuxChannel()
        }

        setExceptionHandler()

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            AppCompatDelegate.setCompatVectorFromResourcesEnabled(true)
        }

        initAppLifecycleListener()

        registerActivityLifecycleCallbacks(ActivitiesLifecycleListener())

        scheduleDnsCryptBinaryUpdateCheck()
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun createAuxChannel() {
        val notificationManager = getSystemService(this, NotificationManager::class.java)
        val channel = NotificationChannel(
            AUX_CHANNEL_ID,
            uniffi.torta_core.tortaText("notification_channel_auxiliary"),
            NotificationManager.IMPORTANCE_HIGH
        )
        channel.setSound(null, Notification.AUDIO_ATTRIBUTES_DEFAULT)
        channel.description = ""
        channel.enableLights(true)
        channel.lightColor = Color.YELLOW
        channel.enableVibration(true)
        channel.lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        channel.setShowBadge(true)
        notificationManager?.createNotificationChannel(channel)
    }

    private fun setExceptionHandler() {
        val exceptionHandler = Thread.getDefaultUncaughtExceptionHandler()
        if (exceptionHandler is TopExceptionHandler) {
            return
        }
        Thread.setDefaultUncaughtExceptionHandler(
            TopExceptionHandler(
                getSharedPreferences(
                    SharedPreferencesModule.APP_PREFERENCES_NAME,
                    MODE_PRIVATE
                ),
                exceptionHandler
            )
        )
    }

    private fun initAppLifecycleListener() {
        ProcessLifecycleOwner.get().lifecycle.addObserver(AppLifecycleListener(this))
    }

    /** Weekly, idempotent (KEEP) upstream dnscrypt-proxy version check. Notify-only — never downloads a binary. */
    private fun scheduleDnsCryptBinaryUpdateCheck() {
        try {
            val request = PeriodicWorkRequestBuilder<CheckDnsCryptBinaryUpdateWorker>(7, TimeUnit.DAYS)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .setRequiresBatteryNotLow(true)
                        .build()
                )
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    DEFAULT_BACKOFF_DELAY_MILLIS,
                    TimeUnit.MILLISECONDS
                )
                .build()
            WorkManager.getInstance(this).enqueueUniquePeriodicWork(
                CheckDnsCryptBinaryUpdateWorker.CHECK_DNSCRYPT_BINARY_UPDATE_WORK,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        } catch (e: Exception) {
            loge("scheduleDnsCryptBinaryUpdateCheck", e)
        }
    }

}
