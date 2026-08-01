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

package pillar.kuma_saimono.libumdnscrypt.utils.privatedns

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.graphics.Color
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.os.Build
import android.provider.Settings
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import pillar.kuma_saimono.libumdnscrypt.AUX_CHANNEL_ID
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.utils.Utils.areNotificationsNotAllowed
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.NetworkChecker
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils.PRIVATE_DNS_MODE_OPPORTUNISTIC
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils.PRIVATE_DNS_MODE_PROVIDER_HOSTNAME

const val DISABLE_PRIVATE_DNS_NOTIFICATION = 167
const val DISABLE_PROXY_NOTIFICATION = 168

object PrivateDnsProxyManager {
    @RequiresApi(Build.VERSION_CODES.P)
    fun checkPrivateDNSAndProxy(
        context: Context,
        linkProperties: LinkProperties?,
        ignoreSystemDns: Boolean
    ) {
        try {
            val modulesStatus = ModulesStatus.getInstance()
            if (modulesStatus.mode == OperationMode.PROXY_MODE) {
                return
            }

            var localLinkProperties = linkProperties

            if (localLinkProperties == null) {
                val connectivityManager =
                    context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                localLinkProperties =
                    connectivityManager.getLinkProperties(connectivityManager.activeNetwork)

                logi("LinkProperties $localLinkProperties")
            }


            // localLinkProperties.privateDnsServerName == null - Opportunistic mode ("Automatic")
            val privateDnsMode = VpnUtils.getPrivateDnsMode(context)
            if (modulesStatus.dnsCryptState == ModuleState.RUNNING
                && (privateDnsMode == PRIVATE_DNS_MODE_PROVIDER_HOSTNAME
                        || privateDnsMode == PRIVATE_DNS_MODE_OPPORTUNISTIC && !ignoreSystemDns
                        || localLinkProperties?.isPrivateDnsActive == true
                        && (localLinkProperties.privateDnsServerName != null || !ignoreSystemDns))
            ) {
                sendNotification(
                    context,
                    uniffi.torta_core.tortaText("app_name"),
                    uniffi.torta_core.tortaText("helper_dnscrypt_private_dns"),
                    DISABLE_PRIVATE_DNS_NOTIFICATION
                )
            }

            if (modulesStatus.dnsCryptState == ModuleState.RUNNING
                && localLinkProperties?.httpProxy != null
            ) {

                if (NetworkChecker.isWifiActive(context)) {
                    sendNotification(
                        context,
                        uniffi.torta_core.tortaText("app_name"),
                        uniffi.torta_core.tortaText("helper_dnscrypt_proxy_wifi"),
                        DISABLE_PROXY_NOTIFICATION
                    )
                } else if (NetworkChecker.isCellularActive(context)) {
                    sendNotification(
                        context,
                        uniffi.torta_core.tortaText("app_name"),
                        uniffi.torta_core.tortaText("helper_dnscrypt_proxy_gsm"),
                        DISABLE_PROXY_NOTIFICATION
                    )
                }

            }
        } catch (e: Exception) {
            loge("AuxNotificationSender checkPrivateDNSAndProxy", e)
        }
    }

    private fun sendNotification(
        context: Context,
        title: String,
        text: String,
        NOTIFICATION_ID: Int
    ) {
        val notificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (areNotificationsNotAllowed(notificationManager)) {
            return
        }

        var notificationIntent = Intent(Settings.ACTION_WIRELESS_SETTINGS)

        val packageManager: PackageManager = context.packageManager
        if (notificationIntent.resolveActivity(packageManager) == null) {
            notificationIntent = Intent(context, TortaSlintActivity::class.java)
        }

        val contentIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.getActivity(
                context.applicationContext,
                165,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            @Suppress("UnspecifiedImmutableFlag")
            PendingIntent.getActivity(
                context.applicationContext,
                165,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }

        var iconResource: Int =
            context.resources.getIdentifier("ic_aux_notification", "drawable", context.packageName)
        if (iconResource == 0) {
            iconResource = android.R.drawable.ic_dialog_alert
        }
        val builder = NotificationCompat.Builder(context, AUX_CHANNEL_ID)
        @Suppress("DEPRECATION")
        builder.setContentIntent(contentIntent)
            .setOngoing(false) //Can be swiped out
            .setSmallIcon(iconResource)
            .setLargeIcon(
                BitmapFactory.decodeResource(
                    context.resources,
                    R.drawable.ic_aux_notification
                )
            )
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setPriority(Notification.PRIORITY_HIGH)
            .setOnlyAlertOnce(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setAutoCancel(true)
            .setLights(Color.YELLOW, 1000, 1000)
            .setChannelId(AUX_CHANNEL_ID)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_ALARM)
        }

        val notification = builder.build()
        notificationManager.notify(NOTIFICATION_ID, notification)
    }
}
