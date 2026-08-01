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

package pillar.kuma_saimono.libumdnscrypt.arp

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.os.Build
import androidx.core.app.NotificationCompat
import pillar.kuma_saimono.libumdnscrypt.AUX_CHANNEL_ID
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.utils.Utils.areNotificationsNotAllowed

const val dnsRebindingWarning = "pillar.kuma_saimono.libumdnscrypt.dns_rebinding_attack_warning"
private const val DNS_REBINDING_NOTIFICATION_ID = 112

object DNSRebindProtection {

    fun sendNotification(context: Context, site: String) {
        val notificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (areNotificationsNotAllowed(notificationManager)) {
            return
        }

        val title = uniffi.torta_core.tortaText("notification_dns_rebinding_title")
        val text = String.format(uniffi.torta_core.tortaText("notification_dns_rebinding_text"), site)

        val notificationIntent = Intent(context, TortaSlintActivity::class.java)
        notificationIntent.action = Intent.ACTION_MAIN
        notificationIntent.addCategory(Intent.CATEGORY_LAUNCHER)
        notificationIntent.putExtra(dnsRebindingWarning, site)
        val contentIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.getActivity(
                context.applicationContext,
                112,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            @Suppress("UnspecifiedImmutableFlag")
            PendingIntent.getActivity(
                context.applicationContext,
                112,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }
        var iconResource: Int = context.resources.getIdentifier(
            "ic_arp_attack_notification",
            "drawable",
            context.packageName
        )
        if (iconResource == 0) {
            iconResource = android.R.drawable.ic_lock_power_off
        }
        val builder = NotificationCompat.Builder(context, AUX_CHANNEL_ID)
        @Suppress("DEPRECATION")
        builder.setContentIntent(contentIntent)
            .setOngoing(false) //Can be swiped out
            .setSmallIcon(iconResource)
            .setLargeIcon(
                BitmapFactory.decodeResource(
                    context.resources,
                    R.drawable.ic_arp_attack_notification
                )
            )
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setPriority(Notification.PRIORITY_HIGH)
            .setOnlyAlertOnce(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setAutoCancel(true)
            .setVibrate(longArrayOf(1000))
            .setChannelId(AUX_CHANNEL_ID)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_ALARM)
        }

        val notification = builder.build()
        notificationManager.notify(DNS_REBINDING_NOTIFICATION_ID, notification)
    }
}
