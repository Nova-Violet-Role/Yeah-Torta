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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R

/**
 * Shizuku-style ALWAYS-ON wireless-debug pairing notification (#7).
 *
 * A foreground service that keeps a persistent (ongoing) notification while it discovers the system's
 * randomly-chosen `_adb-tls-pairing._tcp` port, then lets the user type the 6-digit pairing code
 * DIRECTLY in the notification shade ([android.app.RemoteInput]) — no need to keep the app open. The
 * pairing + no-root elevation run through the same [WireCakeInuManager] as the in-app wizard, so the
 * notification path and the screen path share one brain.
 *
 * Lifecycle: [ACTION_START] → discover (ongoing "searching") → on [WireCakeInuUiState.Found] post the
 * in-shade code entry → the typed code arrives via [ACTION_REPLY] → [WireCakeInuManager.pairWithDiscovered]
 * → "working" → [WireCakeInuUiState.Done] success (notification detached, service stops) or
 * [WireCakeInuUiState.Error] (retry/stop actions). [ACTION_STOP] tears everything down.
 *
 * Fail-open like the rest of the wireless-debug stack: every notification post is best-effort
 * (POST_NOTIFICATIONS may be denied; the foreground-service notification itself is still allowed).
 */
class WireCakeInuService : Service() {

    lateinit var manager: WireCakeInuManager

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var observing: Job? = null

    /** The pairing port found by discovery — baked into the reply PendingIntent so the typed code can
     *  still pair if the service is restarted mid-input (Shizuku's trick). */
    @Volatile
    private var foundPort: Int = -1

    /** True until the user submits a code; gates the (re-)showing of the in-shade entry so a fallback
     *  re-discovery after submit cannot clobber the "working" notification with the code entry again. */
    @Volatile
    private var awaitingCode: Boolean = true

    private var inForeground = false

    private val notificationManager: NotificationManager
        get() = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    override fun onCreate() {
        super.onCreate()
        manager = App.instance.wireCakeInuComponent.wireCakeInuManager
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> onStart()
            ACTION_REPLY -> onReply(intent)
            ACTION_BOOT_REAPPLY -> {
                onBootReapply()
                return START_NOT_STICKY
            }
            ACTION_STOP -> {
                stopEverything()
                return START_NOT_STICKY
            }
            else -> return START_NOT_STICKY
        }
        return START_REDELIVER_INTENT
    }

    private fun onStart() {
        awaitingCode = true
        foundPort = -1
        promoteForeground(searchingNotification())
        if (observing == null) {
            observing = scope.launch {
                manager.state.collect { render(it) }
            }
        }
        manager.startDiscovery()
    }

    private fun onReply(intent: Intent) {
        val code = android.app.RemoteInput.getResultsFromIntent(intent)
            ?.getCharSequence(REMOTE_INPUT_KEY)?.toString()?.trim().orEmpty()
        if (code.length == CODE_LENGTH && code.all { it.isDigit() }) {
            awaitingCode = false
            // Delivered via getService to the ALREADY-foreground service → just update the notification.
            // (Re-promoting with startForeground while the app is backgrounded trips the bg restriction and
            // demotes the service, which throttles/kills the long grant — measured live.)
            updateNotification(workingNotification())
            manager.pairWithDiscovered(code)
        } else {
            // Empty / malformed code (the user dismissed the input or typed garbage) — re-show the entry
            // on the last-found port, or fall back to searching if the port was never resolved.
            val n = if (foundPort > 0) inputNotification(foundPort) else searchingNotification()
            updateNotification(n)
        }
    }

    /**
     * The silent boot re-arm (P11 §3 consumer). Started by [BootCompleteReceiver] when the user armed
     * "keep after reboot": promote to a quiet foreground (a background boot start needs FGS to run the
     * reconnect), drive [WireCakeInuManager.reapplyOnBoot] — which itself no-ops unless there is real,
     * previously-verified protection to re-establish — then stop. NO code entry, NO celebratory banner:
     * the manager posts nothing on a re-arm. One-shot; never re-observed.
     */
    private fun onBootReapply() {
        promoteForeground(reapplyingNotification())
        scope.launch {
            try {
                manager.reapplyOnBoot()
            } catch (_: Throwable) {
                // Wireless Debugging off / endpoint gone at boot — degrade quietly, no nag.
            } finally {
                stopEverything()
            }
        }
    }

    private fun render(s: WireCakeInuUiState) {
        when (s) {
            WireCakeInuUiState.Discovering ->
                if (awaitingCode) updateNotification(searchingNotification())
            is WireCakeInuUiState.Found -> {
                foundPort = s.port
                if (awaitingCode) updateNotification(inputNotification(s.port))
            }
            WireCakeInuUiState.Pairing,
            WireCakeInuUiState.Connecting,
            WireCakeInuUiState.Connected ->
                updateNotification(workingNotification())
            is WireCakeInuUiState.Granting ->
                updateNotification(workingNotification(s.step))
            is WireCakeInuUiState.Done ->
                // The grant's manager posts the celebratory "Soft-Cäke is baked" notification
                // (WireCakeInuManager.notifyProtected) for BOTH the wizard and notification paths — the
                // service just clears its own pairing notification + stops, so there's no duplicate.
                stopEverything()
            is WireCakeInuUiState.Error -> {
                // Pairing/elevation failed — let the user retry. Allow the entry to reappear.
                awaitingCode = true
                finishWith(errorNotification(s.message))
            }
            WireCakeInuUiState.Idle,
            WireCakeInuUiState.Unsupported -> {
                // nothing to surface — leave whatever is showing
            }
        }
    }

    // ---- notification builders ---------------------------------------------------------------------

    private fun baseBuilder(): Notification.Builder =
        Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_torta_notification)   // Tortä-branded
            .setColor(safeColor())
            .setContentIntent(openActivityIntent())
            .setOnlyAlertOnce(true)

    private fun searchingNotification(): Notification =
        baseBuilder()
            .setContentTitle(uniffi.torta_core.tortaText("wd_notif_searching_title"))
            .setContentText(uniffi.torta_core.tortaText("wd_notif_searching_body"))
            .setOngoing(true)
            // Expose the "Enter pairing code" input field FROM THE START — expand the notification and
            // type the live code straight away (no waiting for discovery). onReply stores it and pairs as
            // soon as the port is discovered (manager.pairWithDiscovered → pairAndElevate fallback).
            .addAction(replyAction(foundPort))
            .addAction(stopAction())
            .build()

    private fun inputNotification(port: Int): Notification =
        baseBuilder()
            .setContentTitle(uniffi.torta_core.tortaText("wd_notif_found_title"))
            .setContentText(uniffi.torta_core.tortaText("wd_notif_found_body"))
            .setOngoing(true)
            .addAction(replyAction(port))
            .addAction(stopAction())
            .build()

    private fun workingNotification(step: String? = null): Notification {
        val body = if (step != null)
            uniffi.torta_core.tortaText("wd_notif_working_step").format(step)
        else
            uniffi.torta_core.tortaText("wd_notif_working_body")
        return baseBuilder()
            .setContentTitle(uniffi.torta_core.tortaText("wd_notif_working_title"))
            .setContentText(body)
            .setOngoing(true)
            .build()
    }

    /** Quiet, transient foreground notice while the boot re-arm reconnects + re-applies (P11 §3). The
     *  copy is sourced from the canonical Rust layer over UniFFI ([uniffi.torta_core.inuRearmNotice]) —
     *  NOT an Android string resource. The repo is .xml-free: user-facing text rides Rust×UniFFI×Kotlin. */
    private fun reapplyingNotification(): Notification {
        val notice = uniffi.torta_core.inuRearmNotice()
        return baseBuilder()
            .setContentTitle(notice.title)
            .setContentText(notice.body)
            .setOngoing(true)
            .build()
    }

    private fun errorNotification(message: String): Notification =
        baseBuilder()
            .setContentTitle(uniffi.torta_core.tortaText("wd_notif_failed_title"))
            .setContentText(message)
            .setOngoing(false)
            .setAutoCancel(true)
            .addAction(retryAction())
            .build()

    // ---- notification actions ----------------------------------------------------------------------

    /** The in-shade pairing-code entry (Shizuku's RemoteInput). The [port] is baked into the reply
     *  intent so the typed code can pair even if the service is killed/restarted before submit. */
    private fun replyAction(port: Int): Notification.Action {
        val remoteInput = android.app.RemoteInput.Builder(REMOTE_INPUT_KEY)
            .setLabel(uniffi.torta_core.tortaText("wd_notif_enter_code"))
            .build()
        val replyIntent = Intent(this, WireCakeInuService::class.java)
            .setAction(ACTION_REPLY)
            .putExtra(EXTRA_PORT, port)
        // getService (NOT getForegroundService): the service is ALREADY foreground (started by the
        // always-on button), so the reply just delivers the code to the running service. Using
        // getForegroundService here forces a fresh startForegroundService while the app is backgrounded →
        // "startForeground() not allowed due to bg restriction" → the service is demoted and the long grant
        // gets throttled/killed (measured live: 0 powers landed). Delivering to the live service avoids it.
        val pending = PendingIntent.getService(
            this,
            REQ_REPLY,
            replyIntent,
            mutableFlags()
        )
        return Notification.Action.Builder(
            null,
            uniffi.torta_core.tortaText("wd_notif_enter_code"),
            pending
        ).addRemoteInput(remoteInput).build()
    }

    private fun stopAction(): Notification.Action {
        val pending = PendingIntent.getService(
            this,
            REQ_STOP,
            Intent(this, WireCakeInuService::class.java).setAction(ACTION_STOP),
            immutableFlags()
        )
        return Notification.Action.Builder(
            null,
            uniffi.torta_core.tortaText("wd_notif_stop"),
            pending
        ).build()
    }

    private fun retryAction(): Notification.Action {
        val pending = PendingIntent.getForegroundService(
            this,
            REQ_RETRY,
            Intent(this, WireCakeInuService::class.java).setAction(ACTION_START),
            immutableFlags()
        )
        return Notification.Action.Builder(
            null,
            uniffi.torta_core.tortaText("wd_notif_retry"),
            pending
        ).build()
    }

    private fun openActivityIntent(): PendingIntent {
        val activity = Intent(this, TortaSlintActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return PendingIntent.getActivity(this, REQ_OPEN, activity, immutableFlags())
    }

    // ---- foreground plumbing -----------------------------------------------------------------------

    /**
     * Promote to foreground (call startForeground). MUST be called from every onStartCommand entry that
     * arrived via startForegroundService — onStart's ACTION_START AND onReply's getForegroundService reply.
     * Android REQUIRES a prompt startForeground after a startForegroundService or it throws
     * ForegroundServiceDidNotStartInTimeException and kills the service mid-grant (MEASURED live: the reply
     * crashed the service after only 2 of the powers had been granted). A user-tapped notification action
     * carries a temporary FGS-start allowance, so the re-promote on reply is permitted; a genuine
     * bg-restriction degrades to a plain post.
     */
    private fun promoteForeground(n: Notification) {
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIF_ID, n)
            }
            inForeground = true
        } catch (e: Throwable) {
            try {
                notificationManager.notify(NOTIF_ID, n)
            } catch (_: Throwable) {
            }
        }
    }

    /**
     * Update the SAME notification for a STATE-driven change (discovery/working/etc.) WITHOUT re-calling
     * startForeground. State updates do NOT arrive via startForegroundService, so re-promoting here would
     * trip Android 12+'s background-FGS-start restriction → demote the service → "stopped due to app idle"
     * (the measured-live bug). notify() updates the foreground notification in place, no restriction.
     */
    private fun updateNotification(n: Notification) {
        try {
            notificationManager.notify(NOTIF_ID, n)
        } catch (_: Throwable) {
        }
    }

    private fun finishWith(n: Notification) {
        try {
            if (inForeground) {
                stopForeground(STOP_FOREGROUND_DETACH)
                inForeground = false
            }
        } catch (_: Throwable) {
        }
        try {
            notificationManager.notify(NOTIF_ID, n)
        } catch (_: Throwable) {
        }
        manager.stopDiscovery()
        stopSelf()
    }

    private fun stopEverything() {
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Throwable) {
        }
        inForeground = false
        manager.stopDiscovery()
        stopSelf()
    }

    private fun createChannel() {
        try {
            notificationManager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    uniffi.torta_core.tortaText("wd_notif_channel"),
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    setSound(null, null)
                    setShowBadge(false)
                    enableVibration(false)
                }
            )
        } catch (_: Throwable) {
        }
    }

    private fun safeColor(): Int = try {
        getColor(R.color.colorAccent)
    } catch (_: Throwable) {
        0
    }

    private fun mutableFlags(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        else
            PendingIntent.FLAG_UPDATE_CURRENT

    private fun immutableFlags(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        else
            PendingIntent.FLAG_UPDATE_CURRENT

    override fun onDestroy() {
        super.onDestroy()
        observing?.cancel()
        observing = null
        try {
            manager.dispose()
        } catch (_: Throwable) {
        }
        scope.cancel()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        private const val CHANNEL_ID = "yeah_torta_wd_pairing"
        private const val NOTIF_ID = 7022
        private const val CODE_LENGTH = 6

        private const val ACTION_START = "pillar.kuma_saimono.libumdnscrypt.wd.START"
        private const val ACTION_REPLY = "pillar.kuma_saimono.libumdnscrypt.wd.REPLY"
        private const val ACTION_STOP = "pillar.kuma_saimono.libumdnscrypt.wd.STOP"
        private const val ACTION_BOOT_REAPPLY = "pillar.kuma_saimono.libumdnscrypt.wd.BOOT_REAPPLY"
        private const val EXTRA_PORT = "wd_port"
        private const val REMOTE_INPUT_KEY = "wd_pairing_code"

        private const val REQ_REPLY = 1
        private const val REQ_STOP = 2
        private const val REQ_RETRY = 3
        private const val REQ_OPEN = 4

        /** Start (or re-arm) the always-on pairing notification. */
        fun start(context: Context) {
            val intent = Intent(context, WireCakeInuService::class.java).setAction(ACTION_START)
            try {
                context.startForegroundService(intent)
            } catch (_: Throwable) {
                // background-start restriction etc. — best effort
            }
        }

        /**
         * Silent boot re-arm (P11 §3): reconnect codelessly (persisted key/cert) + re-apply the granted
         * powers, WITHOUT re-pairing. Dispatched by [BootCompleteReceiver] when the user armed "keep
         * after reboot" ([TortaeKeys.INU_BOOT_REAPPLY]). The service + [WireCakeInuManager.reapplyOnBoot]
         * self-gate (no-op unless actually protected), so this is safe to fire on every eligible boot.
         * Best-effort — a background-FGS-start bar at boot on some ROMs is swallowed.
         */
        fun bootReapply(context: Context) {
            val intent = Intent(context, WireCakeInuService::class.java).setAction(ACTION_BOOT_REAPPLY)
            try {
                context.startForegroundService(intent)
            } catch (_: Throwable) {
                // background-start restriction at boot on some ROMs — best effort
            }
        }

        /**
         * Tear the always-on pairing notification down. Delivers [ACTION_STOP] to the LIVE service
         * (→ stopEverything → stopForeground(REMOVE) + stopDiscovery + stopSelf, the clean removal). If the
         * service is already dead / startService is barred, fall back to a direct stopService — a no-op when
         * nothing is running. Best-effort, never throws to the caller (the settings toggle).
         */
        fun stop(context: Context) {
            val stopIntent = Intent(context, WireCakeInuService::class.java).setAction(ACTION_STOP)
            try {
                context.startService(stopIntent)
            } catch (_: Throwable) {
                try {
                    context.stopService(Intent(context, WireCakeInuService::class.java))
                } catch (_: Throwable) {
                    // nothing running / restriction — the notification is already gone
                }
            }
        }
    }
}
