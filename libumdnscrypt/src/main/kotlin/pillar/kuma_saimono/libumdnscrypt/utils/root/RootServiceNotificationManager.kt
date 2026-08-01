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

package pillar.kuma_saimono.libumdnscrypt.utils.root

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.utils.PaletteUtils
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge

class RootServiceNotificationManager(
    private val service: Service,
    private val notificationManager: NotificationManager
) {

    @Volatile
    private var savedProgress = 0

    @RequiresApi(Build.VERSION_CODES.O)
    fun createNotificationChannel() {
        if (!rootNotificationChannelIsCreated) {
            val notificationChannel = NotificationChannel(
                ROOT_CHANNEL_ID, uniffi.torta_core.tortaText("notification_channel_root"), NotificationManager.IMPORTANCE_LOW
            )
            notificationChannel.description = ""
            notificationChannel.setSound(null, Notification.AUDIO_ATTRIBUTES_DEFAULT)
            notificationChannel.enableLights(false)
            notificationChannel.enableVibration(false)
            notificationChannel.lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            notificationManager.createNotificationChannel(notificationChannel)
            rootNotificationChannelIsCreated = true
        }

        sendNotification(uniffi.torta_core.tortaText("notification_exec_root_commands"), "")
    }

    fun sendNotification(title: String, text: String) {

        val contentIntent = getContentIntent()

        val iconResource = getIconResource()

        val notification = getNotification(
            contentIntent,
            iconResource,
            title,
            text,
            savedProgress
        )

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                service.startForeground(DEFAULT_NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST)
            } else {
                service.startForeground(DEFAULT_NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            loge("RootServiceNotificationManager sendNotification", e, true)
        }
    }

    fun updateNotification(title: String, text: String, progress: Int) {

        savedProgress = progress

        val contentIntent = getContentIntent()

        val iconResource = getIconResource()

        val notification = getNotification(
            contentIntent,
            iconResource,
            title,
            text,
            progress
        )

        notificationManager.notify(DEFAULT_NOTIFICATION_ID, notification)
    }

    fun resetNotification() {
        savedProgress = 0
    }

    @SuppressLint("UnspecifiedImmutableFlag")
    private fun getContentIntent(): PendingIntent {
        val startMainActivityIntent = getStartMainActivityIntent()

        val contentIntent: PendingIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.getActivity(
                service.applicationContext,
                0,
                startMainActivityIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            PendingIntent.getActivity(
                service.applicationContext,
                0,
                startMainActivityIntent,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }

        return contentIntent
    }

    private fun getStartMainActivityIntent(): Intent {
        val intent = Intent(service, TortaSlintActivity::class.java)
        intent.action = Intent.ACTION_MAIN
        intent.addCategory(Intent.CATEGORY_LAUNCHER)
        return intent
    }

    private fun getIconResource(): Int {
        // Tortä brand glyph — replaces the old upstream "ic_service_notification" raster so no
        // old branding leaks (matches the FGS ModulesServiceNotificationManager fix).
        var iconResource = service.resources.getIdentifier(
            "ic_torta_notification",
            "drawable",
            service.packageName
        )
        if (iconResource == 0) {
            iconResource = android.R.drawable.ic_menu_view
        }
        return iconResource
    }

    /**
     * PALETTE-LIVE notification accent (Service-safe): reads {@code pref_fast_palette} and maps
     * the id to its DayNight-aware accent colour via
     * {@link PaletteUtils#paletteAccentColorRes(String)}, so the notification tracks the active
     * palette without an Activity overlay. Falls back to brand gold {@code @color/torta_primary}.
     */
    private fun getBrandColor(): Int {
        try {
            val palette = PreferenceManager
                .getDefaultSharedPreferences(service)
                .getString(PaletteUtils.PALETTE_PREF, PaletteUtils.PALETTE_DEFAULT)
            val colorRes = PaletteUtils.paletteAccentColorRes(palette)
            return ContextCompat.getColor(service, colorRes)
        } catch (e: Exception) {
            loge("RootServiceNotificationManager getBrandColor", e)
        }
        return ContextCompat.getColor(service, R.color.torta_primary)
    }

    private fun getNotification(
        contentIntent: PendingIntent,
        iconResource: Int,
        title: String,
        text: String,
        progress: Int
    ): Notification {
        val builder = NotificationCompat.Builder(service, ROOT_CHANNEL_ID)
        builder.setContentIntent(contentIntent)
            .setOngoing(false)
            .setSmallIcon(iconResource)
            .setColor(getBrandColor())
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(Notification.PRIORITY_MIN)
            .setOnlyAlertOnce(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setSilent(true)
            .setChannelId(ROOT_CHANNEL_ID)
            .setProgress(100, progress, false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_PROGRESS)
        }

        return builder.build()
    }

    companion object {
        const val ROOT_CHANNEL_ID = "ROOT_COMMANDS_INVIZIBLE"
        const val DEFAULT_NOTIFICATION_ID = 102
        private var rootNotificationChannelIsCreated = false
    }
}
