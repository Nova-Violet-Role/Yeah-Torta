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

package pillar.kuma_saimono.libumdnscrypt.modules

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.app.NotificationCompat
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.utils.PaletteUtils
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge

class ModulesServiceNotificationManager : BroadcastReceiver() {

    private val modulesStatus = ModulesStatus.getInstance()

    @SuppressLint("UnspecifiedImmutableFlag")
    private fun getContentIntent(context: Context): PendingIntent {
        val notificationIntent = Intent(context, TortaSlintActivity::class.java)
        notificationIntent.action = Intent.ACTION_MAIN
        notificationIntent.addCategory(Intent.CATEGORY_LAUNCHER)

        val contentIntent: PendingIntent
        contentIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.getActivity(
                context.applicationContext,
                0,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            PendingIntent.getActivity(
                context.applicationContext,
                0,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }

        return contentIntent
    }

    private fun getStopIntent(context: Context): PendingIntent {

        val intent = Intent(context, ModulesServiceNotificationManager::class.java)
        intent.action = STOP_ALL_ACTION

        val stopIntent: PendingIntent
        stopIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.getBroadcast(
                context.applicationContext,
                STOP_ALL_ACTION_CODE,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            PendingIntent.getBroadcast(
                context.applicationContext,
                STOP_ALL_ACTION_CODE,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }

        return stopIntent
    }

    @SuppressLint("UnspecifiedImmutableFlag")
    private fun getStartIntent(context: Context): PendingIntent {
        // Faithful + minimal: a Start action surfaces only when no module is running; it opens
        // TortaSlintActivity (the existing START surface) rather than fabricating a new start broadcast.
        val intent = Intent(context, TortaSlintActivity::class.java)
        intent.action = Intent.ACTION_MAIN
        intent.addCategory(Intent.CATEGORY_LAUNCHER)

        val startIntent: PendingIntent
        startIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.getActivity(
                context.applicationContext,
                START_ALL_ACTION_CODE,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            PendingIntent.getActivity(
                context.applicationContext,
                START_ALL_ACTION_CODE,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }

        return startIntent
    }

    @TargetApi(Build.VERSION_CODES.O)
    fun createNotificationChannel(context: Context) {
        val channel = NotificationChannel(
            ANDROID_CHANNEL_ID,
            uniffi.torta_core.tortaText("notification_channel_services"),
            NotificationManager.IMPORTANCE_LOW
        )
        channel.setSound(null, Notification.AUDIO_ATTRIBUTES_DEFAULT)
        channel.description = ""
        channel.enableLights(false)
        channel.enableVibration(false)
        channel.lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        channel.setShowBadge(false)
        val notificationManager = getNotificationManager(context)
        notificationManager.createNotificationChannel(channel)
        try {
            // de-InviZible: drop the legacy "InviZible" channel a pre-fix install created (deleting
            // a nonexistent channel is a no-op; the FGS is (re)posted on the new channel).
            notificationManager.deleteNotificationChannel(LEGACY_CHANNEL_ID)
        } catch (e: Exception) {
            loge("ModulesServiceNotificationManager deleteNotificationChannel", e)
        }
    }

    private fun getNotificationManager(context: Context): NotificationManager {
        return context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    }

    private fun getSmallIcon(context: Context): Int {

        // Tortä status-bar glyph (white-on-transparent silhouette of the brand cake slice).
        // Replaces the old upstream "ic_service_notification" raster so no old branding leaks.
        var iconResource = R.drawable.ic_torta_notification

        try {
            val torta = context.resources.getIdentifier(
                "ic_torta_notification",
                "drawable",
                context.packageName
            )
            if (torta != 0) {
                iconResource = torta
            }
        } catch (e: Exception) {
            loge("ModulesServiceNotificationManager getSmallIcon", e)
        }

        return iconResource
    }

    /**
     * Resolves the active Tortä brand colour for the notification accent (small-icon tint +
     * app-name colour), PALETTE-LIVE inside a Service. Reads `pref_fast_palette` directly
     * and maps the id to its DayNight-aware `palette_torta_<id>_accent` colour via
     * [PaletteUtils.paletteAccentColorRes]. This is the Service-safe path: a
     * Service theme carries the base attrs but NOT the runtime Activity palette overlay, so the
     * direct pref-keyed colour-resource read (not the theme attribute) tracks the chosen palette.
     * DayNight resolves automatically through values/ vs values-night/. Falls back to the brand
     * gold `@color/torta_primary` on any error.
     */
    private fun getBrandColor(context: Context): Int {
        try {
            val palette = androidx.preference.PreferenceManager
                .getDefaultSharedPreferences(context)
                .getString(PaletteUtils.PALETTE_PREF, PaletteUtils.PALETTE_DEFAULT)
            val colorRes = PaletteUtils.paletteAccentColorRes(palette)
            return androidx.core.content.ContextCompat.getColor(context, colorRes)
        } catch (e: Exception) {
            loge("ModulesServiceNotificationManager getBrandColor", e)
        }
        return androidx.core.content.ContextCompat.getColor(context, R.color.torta_primary)
    }


    @Synchronized
    fun sendNotification(service: Service, title: String, text: String, startTime: Long) {

        getNotificationManager(service).cancel(ModulesService.DEFAULT_NOTIFICATION_ID)

        val builder = NotificationCompat.Builder(service, ANDROID_CHANNEL_ID)
        builder.setContentIntent(getContentIntent(service))
            .setOngoing(true)
            .setSmallIcon(getSmallIcon(service))
            .setColor(getBrandColor(service))
            .setColorized(true)
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setChannelId(ANDROID_CHANNEL_ID)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (isAnyModuleRunning()) {
                builder.addAction(
                    R.drawable.ic_stop,
                    uniffi.torta_core.tortaText("main_fragment_button_stop"),
                    getStopIntent(service)
                )
            } else {
                builder.addAction(
                    R.drawable.ic_torta_notification,
                    uniffi.torta_core.tortaText("main_fragment_button_start"),
                    getStartIntent(service)
                )
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_SERVICE)
        }

        if (startTime != 0L) {
            builder.setWhen(startTime)
                .setUsesChronometer(true)
        }

        val notification = builder.build()

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                service.startForeground(ModulesService.DEFAULT_NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST)
            } else {
                service.startForeground(ModulesService.DEFAULT_NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            loge("ModulesServiceNotificationManager sendNotification", e)
        }
    }

    @SuppressLint("UnspecifiedImmutableFlag")
    fun updateNotification(context: Context, title: String, text: String, startTime: Long) {
        val builder = NotificationCompat.Builder(context, ANDROID_CHANNEL_ID)
        builder.setContentIntent(getContentIntent(context))
            .setOngoing(true)
            .setSmallIcon(getSmallIcon(context))
            .setColor(getBrandColor(context))
            .setColorized(true)
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setChannelId(ANDROID_CHANNEL_ID)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (isAnyModuleRunning()) {
                builder.addAction(
                    R.drawable.ic_stop,
                    uniffi.torta_core.tortaText("main_fragment_button_stop"),
                    getStopIntent(context)
                )
            } else {
                builder.addAction(
                    R.drawable.ic_torta_notification,
                    uniffi.torta_core.tortaText("main_fragment_button_start"),
                    getStartIntent(context)
                )
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_SERVICE)
        }

        if (startTime != 0L) {
            builder.setWhen(startTime)
                .setUsesChronometer(true)
        }

        val notification = builder.build()

        getNotificationManager(context).notify(ModulesService.DEFAULT_NOTIFICATION_ID, notification)
    }

    private fun isAnyModuleRunning(): Boolean {
        // 2-DRIVE-ENGINE-VPN: the Tortä engine rides the DNSCrypt VpnService FGS — it no longer keeps the
        // foreground service alive on its own, so the ongoing notification tracks DNSCrypt / the firewall
        // only. The engine follows the VPN; when the VPN is down there is nothing for the engine to keep up.
        return modulesStatus.dnsCryptState == ModuleState.RUNNING ||
                modulesStatus.firewallState == ModuleState.RUNNING
    }

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context != null && intent != null && STOP_ALL_ACTION == intent.action) {
            stopServices(context)
        }
    }

    private fun stopServices(context: Context) {
        ModulesAux.stopModulesIfRunning(context)
    }

    companion object {

        // de-InviZible (e-fix round 2): the FGS channel ID used to be the legacy "InviZible" — a
        // user-visible branding leak in the system notification-channel settings. The channel is now
        // "Tortae" (an ID is immutable once created, so a rename REQUIRES a new ID); the legacy channel
        // is deleted on upgrade in createNotificationChannel so no orphan row lingers.
        private const val ANDROID_CHANNEL_ID = "Tortae"
        private const val LEGACY_CHANNEL_ID = "InviZible"
        private const val STOP_ALL_ACTION = "pillar.kuma_saimono.libumdnscrypt.NOTIFICATION_STOP_ALL_ACTION"
        private const val STOP_ALL_ACTION_CODE = 1120
        private const val START_ALL_ACTION_CODE = 1121

        @Volatile
        private var instance: ModulesServiceNotificationManager? = null

        @SuppressLint("UnspecifiedRegisterReceiverFlag")
        @JvmStatic
        fun getManager(context: Context): ModulesServiceNotificationManager? {
            if (instance == null) {
                synchronized(ModulesServiceNotificationManager::class.java) {
                    if (instance == null) {
                        instance = ModulesServiceNotificationManager()
                        val filter = IntentFilter(STOP_ALL_ACTION)
                        try {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                context.applicationContext.registerReceiver(
                                    instance,
                                    filter,
                                    Context.RECEIVER_NOT_EXPORTED
                                )
                            } else {
                                context.applicationContext.registerReceiver(
                                    instance,
                                    filter
                                )
                            }
                        } catch (e: Exception) {
                            loge("ModulesServiceNotificationManager getNotificationManager", e)
                        }
                        return instance
                    }
                }
            }
            return instance
        }

        @JvmStatic
        fun stopManager(context: Context) {
            if (instance != null) {
                synchronized(ModulesServiceNotificationManager::class.java) {
                    if (instance != null) {
                        try {
                            context.applicationContext.unregisterReceiver(instance)
                        } catch (e: Exception) {
                            loge("ModulesServiceNotificationManager stopNotificationManager", e)
                        }
                        instance = null
                    }
                }
            }
        }
    }
}
