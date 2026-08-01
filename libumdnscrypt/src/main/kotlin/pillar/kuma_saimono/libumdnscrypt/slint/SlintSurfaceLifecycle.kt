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

import android.util.Log
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import me.tatarka.inject.annotations.Inject

/**
 * The app-private data root the SLINT rail feeds from (SLINT substitution · 1C). A typed holder
 * (never a bare [String] — a bare-String `@Provides` would type-collide with any future String on
 * the graph); provided once by [SlintUiComponent.slintAppDataDir] from the app
 * [android.content.Context].
 *
 * ONE truth, TWO readers: this is byte-for-byte the same root `torta_ui`'s `android_main` derives
 * natively via `AndroidApp::internal_data_path` (torta_ui src/lib.rs:741-744) — the Kotlin side
 * preps it, the native side tails it.
 */
class SlintAppDataDir(val path: String)

/**
 * The app/activity-level SLINT surface lifecycle bracket (SLINT substitution · 1C) — Kotlin-Inject,
 * constructor DI, zero reflection, on the [SlintUiComponent] graph.
 *
 * WHAT THE BRACKET OWNS (and what it honestly does NOT): the SLINT surface itself is created and
 * torn down by the NATIVE rail — measured, cited: · CREATE — `NativeActivity.onCreate` loads
 * `libtorta_ui.so` (manifest `android.app.lib_name`) and the android-activity glue spawns a FRESH
 * `android_main` thread PER activity instance (android-activity-0.6.1 native_activity/glue.rs:908).
 * · FEED — `android_main` reads the typed torta_core state + tails the feed roots under
 * [SlintAppDataDir] (torta_ui src/lib.rs: `query_log_path` lib.rs:27-33, the K5 TOML lib.rs:784). ·
 * TEARDOWN — `MainEvent::Destroy` breaks the slint event loop (i-slint-backend-android-activity
 * androidwindowadapter.rs:267-268), the Java `onDestroy` BLOCKS until `android_main` returns
 * (glue.rs:400-409 `notify_destroyed` waits for the rail thread), and the thread-local
 * `GLOBAL_CONTEXT` (i-slint-core context.rs:51-54 `thread_local!`) drops the whole SlintContext —
 * platform, window adapter, components — WITH the rail thread. Relaunch = fresh thread = fresh
 * platform slot (WITNESSED: 1c-baseline-1-relaunch.png renders after back-then-reopen).
 *
 * So the Kotlin bracket's jobs are the APP-LEVEL ones the native rail cannot do: ·
 * [onSurfaceCreated] — FEED-PREP: ensure the feed roots exist under the app data dir before the
 * rail's first tail, OFF the main thread (never an ANR; a `mkdirs` race with the rail's first read
 * degrades honestly — the rail's absent-path read is the "not written yet" truth, torta_ui
 * lib.rs:213-214). · [onSurfaceDestroyed] — the teardown bracket: a structured logcat witness that
 * the rail unwound. Deliberately NOTHING to free here: this class holds ONLY app-scoped state
 * (never an Activity/Window reference) — leak-free by construction, and the native side already
 * tore itself down (the law above) by the time the launcher calls this.
 *
 * Held on the app-scoped [SlintUiComponent]; driven by the launcher ([TortaSlintActivity]), which
 * OWNS the SLINT lifecycle. `@SlintUiScope` (ONE instance per process): an unscoped accessor mints
 * a fresh instance per activity generation, silently resetting [feedRootsEnsured] — measured on the
 * 1C witness run (the relaunch re-ran the prep instead of hitting the guard).
 */
@SlintUiScope
@Inject
class SlintSurfaceLifecycle(private val appDataDir: SlintAppDataDir) {

    /** One prep per process — the roots are stable once ensured (cheap CAS, re-entrant safe). */
    private val feedRootsEnsured = AtomicBoolean(false)

    /**
     * The surface-start hook — called by the launcher BEFORE `super.onCreate()` spawns the native
     * rail thread, so the prep has the head start (async either way; ordering is best-effort and
     * the rail degrades honestly on an absent root).
     */
    fun onSurfaceCreated() {
        if (feedRootsEnsured.compareAndSet(false, true)) {
            Thread({ ensureFeedRoots() }, "torta-slint-feedprep").start()
        } else {
            Log.i(TAG, "surface created — feed roots already ensured this process")
        }
    }

    /**
     * The off-main feed-root prep body — its OWN method so the witnessed log line sits at shallow
     * indent (the nested-lambda form pushed it past the max-line width). Fail-open: prep must NEVER
     * take the surface down; the rail reads an absent root as the honest "not written yet"
     * (torta_ui lib.rs:213-214).
     */
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open (see the FEED-PREP note above)
    private fun ensureFeedRoots() {
        try {
            val ensured = FEED_ROOTS.count { rel ->
                File(appDataDir.path, rel).let { it.isDirectory || it.mkdirs() }
            }
            Log.i(
                TAG,
                "surface created — feed roots ensured $ensured/${FEED_ROOTS.size} under ${appDataDir.path}",
            )
        } catch (t: Throwable) {
            // Fail-open: the rail reads absent paths as the honest "not written yet"
            // (torta_ui lib.rs:213-214) — prep failure must never take the surface down.
            Log.e(TAG, "feed-root prep failed — the rail degrades honestly", t)
        }
    }

    /**
     * The surface-end hook — called by the launcher AFTER `super.onDestroy()` returns, i.e. after
     * the glue's blocking wait (glue.rs:400-409) proves the rail thread unwound and the
     * thread-local SlintContext dropped with it.
     */
    fun onSurfaceDestroyed() {
        Log.i(TAG, "surface destroyed — the native rail thread unwound; nothing retained app-side")
    }

    private companion object {
        private const val TAG = "TORTA_SLINT"

        /**
         * The measured feed roots the rail tails (torta_ui lib.rs `query_log_path`:27-33 + the K5
         * TOML home lib.rs:784; the Kotlin writers: PillarLog.kt:87-89 `<data>/logs/`, dnscrypt's
         * own `<data>/cache/` query/nx logs, the module config home
         * `<data>/app_data/dnscrypt-proxy`). Centauri's `app_data/centauri_cache` is deliberately
         * ABSENT: the pillar owns creating its content-addressed cache — pre-creating it would mask
         * its own first-run path.
         */
        private val FEED_ROOTS = listOf("logs", "cache", "app_data/dnscrypt-proxy")
    }
}
