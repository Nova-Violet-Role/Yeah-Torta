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

package pillar.kuma_saimono.libumdnscrypt.iptables

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.AUX_CHANNEL_ID
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.utils.PaletteUtils
import pillar.kuma_saimono.libumdnscrypt.utils.Utils.areNotificationsNotAllowed
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.lang.Exception
import javax.inject.Inject

private const val PENDING_INTENT_REQUEST_CODE = 111
private const val NOTIFICATION_ID = 102115

class KillSwitchNotification @Inject constructor(
    private val context: Context
) {

    private val notificationManager =
        context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    fun send() {

        if (areNotificationsNotAllowed(notificationManager)) {
            return
        }

        val contentIntent = getContentIntent()

        val iconResource = getIconResource()

        val builder = NotificationCompat.Builder(context, AUX_CHANNEL_ID)
        @Suppress("DEPRECATION")
        builder.setContentIntent(contentIntent)
            .setOngoing(true)
            .setSmallIcon(iconResource)
            .setColor(getBrandColor())
            .setContentTitle(uniffi.torta_core.tortaText("pref_common_kill_switch"))
            .setContentText(uniffi.torta_core.tortaText("notification_internet_blocked_message"))
            .setStyle(NotificationCompat.BigTextStyle()
                .bigText(uniffi.torta_core.tortaText("notification_internet_blocked_message")))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setOnlyAlertOnce(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setChannelId(AUX_CHANNEL_ID)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_ALARM)
                .setLargeIcon(
                    BitmapFactory.decodeResource(
                        context.resources,
                        R.drawable.ic_arp_attack_notification
                    )
                )
        }

        val notification = builder.build()
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    fun cancel() {
        notificationManager.cancel(NOTIFICATION_ID)
    }

    private fun getContentIntent(): PendingIntent {
        val notificationIntent = Intent(context, TortaSlintActivity::class.java)
        notificationIntent.action = Intent.ACTION_MAIN
        notificationIntent.addCategory(Intent.CATEGORY_LAUNCHER)

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.getActivity(
                context.applicationContext,
                PENDING_INTENT_REQUEST_CODE,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            @Suppress("UnspecifiedImmutableFlag")
            PendingIntent.getActivity(
                context.applicationContext,
                PENDING_INTENT_REQUEST_CODE,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }
    }

    private fun getIconResource(): Int {
        var iconResource: Int = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                context.resources.getIdentifier(
                    "ic_arp_attack_notification",
                    "drawable",
                    context.packageName
                )
            } else {
                // Tortä brand glyph — replaces the old upstream "ic_service_notification"
                // raster so no old branding leaks on the pre-M small-icon path.
                context.resources.getIdentifier(
                    "ic_torta_notification",
                    "drawable",
                    context.packageName
                )
            }
        } catch (e: Exception) {
            loge("KillSwitchNotification getIconResource", e)
            android.R.drawable.ic_lock_power_off
        }

        if (iconResource == 0) {
            iconResource = android.R.drawable.ic_lock_power_off
        }

        return iconResource
    }

    /**
     * PALETTE-LIVE notification accent (Service-safe): reads `pref_fast_palette` and maps the id
     * to its DayNight-aware accent colour via [PaletteUtils.paletteAccentColorRes], so the alert
     * tracks the active palette without an Activity overlay. Falls back to brand gold on error.
     */
    private fun getBrandColor(): Int = try {
        val palette = PreferenceManager.getDefaultSharedPreferences(context)
            .getString(PaletteUtils.PALETTE_PREF, PaletteUtils.PALETTE_DEFAULT)
        ContextCompat.getColor(context, PaletteUtils.paletteAccentColorRes(palette))
    } catch (e: Exception) {
        loge("KillSwitchNotification getBrandColor", e)
        ContextCompat.getColor(context, R.color.torta_primary)
    }
}
