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

package pillar.kuma_saimono.libumdnscrypt.update

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.util.SparseArray
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import androidx.core.content.FileProvider
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.wakelock.WakeLocksManager
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject
import androidx.core.app.ServiceCompat

@Suppress("DEPRECATION")
class UpdateService : Service() {

    @JvmField
    val currentNotificationId = AtomicInteger(UPDATE_CHANNEL_NOTIFICATION_ID)

    @JvmField
    var notificationManager: NotificationManager? = null

    @Volatile
    @JvmField
    var sparseArray = SparseArray<DownloadTask>()

    private var wakeLocksManager: WakeLocksManager? = WakeLocksManager.getInstance()

    @Inject
    lateinit var preferenceRepository: dagger.Lazy<PreferenceRepository>

    override fun onBind(intent: Intent): IBinder? {
        return null
    }

    override fun onCreate() {
        App.instance.daggerComponent.inject(this)

        super.onCreate()

        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager?
        sparseArray = SparseArray()

        val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this)
        if (!sharedPreferences.getBoolean("swWakelock", false)
            || !wakeLocksManager!!.isPowerWakeLockHeld && !wakeLocksManager!!.isWiFiWakeLockHeld) {
            wakeLocksManager!!.managePowerWakelock(this, true)
            wakeLocksManager!!.manageWiFiLock(this, true)
        } else {
            wakeLocksManager = null
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && notificationManager != null) {
            createNotificationChannel()
            sendNotification(0, currentNotificationId.get(), System.currentTimeMillis(), uniffi.torta_core.tortaText("app_name"), uniffi.torta_core.tortaText("app_name"), "")
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent!!.action
        if (action == null) {
            sendNotification(startId, currentNotificationId.get(), System.currentTimeMillis(), uniffi.torta_core.tortaText("app_name"), uniffi.torta_core.tortaText("app_name"), "")
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
        } else if (action == DOWNLOAD_ACTION) {
            startDownloadAction(intent, startId)
        } else if (action == STOP_DOWNLOAD_ACTION) {
            stopDownloadAction(intent)
        } else if (action == INSTALLATION_REQUEST_ACTION) {
            installationRequestAction()
        } else {
            sendNotification(startId, currentNotificationId.get(), System.currentTimeMillis(), uniffi.torta_core.tortaText("app_name"), uniffi.torta_core.tortaText("app_name"), "")
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        super.onTimeout(startId, fgsType)

        loge("UpdateService timeout")

        for (i in 0 until sparseArray.size()) {
            try {
                val task = sparseArray.valueAt(i)
                task.interrupt()
            } catch (e: Exception) {
                loge("UpdateService onTimeout", e)
            }
        }

        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()

        if (wakeLocksManager != null) {
            wakeLocksManager!!.stopPowerWakelock()
            wakeLocksManager!!.stopWiFiLock()
        }
    }

    private fun startDownloadAction(intent: Intent, startId: Int) {
        val startTime = System.currentTimeMillis()
        val notificationId = currentNotificationId.getAndIncrement()

        val downloadTask = DownloadTask(this, intent, startId, notificationId, startTime)
        sparseArray.put(startId, downloadTask)

        sendNotification(
            startId,
            notificationId,
            startTime,
            uniffi.torta_core.tortaText("update_notification"),
            "",
            uniffi.torta_core.tortaText("update_notification")
        )

        downloadTask.start()
    }

    private fun stopDownloadAction(intent: Intent) {
        val serviceId = intent.getIntExtra("ServiceStartId", 0)
        val downloadTask = sparseArray.get(serviceId)
        if (downloadTask != null) {
            sendNotification(
                downloadTask.serviceStartId,
                downloadTask.notificationId,
                downloadTask.startTime,
                uniffi.torta_core.tortaText("update_interrupt_notification"),
                "",
                uniffi.torta_core.tortaText("update_interrupt_notification")
            )
            downloadTask.interrupt()
            sparseArray.delete(serviceId)
        }
    }

    private fun installationRequestAction() {
        sendNotification(0, currentNotificationId.get(), System.currentTimeMillis(), uniffi.torta_core.tortaText("app_name"), uniffi.torta_core.tortaText("app_name"), "")

        val path = preferenceRepository.get().getStringPreference("RequiredAppUpdateForQ")

        if (path.isNotEmpty()) {

            preferenceRepository.get().setStringPreference("RequiredAppUpdateForQ", "")

            val file = File(path)

            if (file.isFile) {
                val apkUri = FileProvider.getUriForFile(this, this.packageName + ".fileprovider", file)
                val intent = Intent(Intent.ACTION_INSTALL_PACKAGE)
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                intent.setData(apkUri)
                intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                this.startActivity(intent)
            }
        }

        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private fun createNotificationChannel() {
        val notificationChannel = NotificationChannel(
            UPDATE_CHANNEL_ID, uniffi.torta_core.tortaText("notification_channel_update"), NotificationManager.IMPORTANCE_DEFAULT
        )
        notificationChannel.setSound(null, Notification.AUDIO_ATTRIBUTES_DEFAULT)
        notificationChannel.description = ""
        notificationChannel.enableLights(false)
        notificationChannel.enableVibration(false)
        notificationChannel.lockscreenVisibility = Notification.VISIBILITY_PRIVATE

        notificationManager!!.createNotificationChannel(notificationChannel)
    }

    @SuppressLint("UnspecifiedImmutableFlag")
    fun sendNotification(serviceStartId: Int, notificationId: Int, startTime: Long, Ticker: String, Title: String, Text: String) {

        val notificationIntent = Intent(this, TortaSlintActivity::class.java)
        notificationIntent.setAction(Intent.ACTION_MAIN)
        notificationIntent.addCategory(Intent.CATEGORY_LAUNCHER)

        val stopDownloadIntent = Intent(this, UpdateService::class.java)
        stopDownloadIntent.setAction(STOP_DOWNLOAD_ACTION)
        stopDownloadIntent.putExtra("ServiceStartId", serviceStartId)
        val stopDownloadPendingIntent: PendingIntent
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            stopDownloadPendingIntent = PendingIntent.getService(
                this,
                notificationId,
                stopDownloadIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            stopDownloadPendingIntent = PendingIntent.getService(
                this,
                notificationId,
                stopDownloadIntent,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }

        val contentIntent: PendingIntent
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            contentIntent = PendingIntent.getActivity(
                this,
                0,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            contentIntent = PendingIntent.getActivity(
                this,
                0,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }

        val builder = NotificationCompat.Builder(this, UPDATE_CHANNEL_ID)
        builder.setContentIntent(contentIntent)
            .setOngoing(true)   //Can't be swiped out
            .setSmallIcon(R.drawable.ic_update)
            .setTicker(Ticker)
            .setContentTitle(Title)
            .setContentText(Text)
            .setOnlyAlertOnce(true)
            .setWhen(startTime)
            .setUsesChronometer(true)
            .setChannelId(UPDATE_CHANNEL_ID)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setProgress(100, 100, true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_PROGRESS)
        }

        if (serviceStartId != 0) {
            builder.addAction(R.drawable.ic_stop, uniffi.torta_core.tortaText("cancel_download"), stopDownloadPendingIntent)
        }

        val notification = builder.build()

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(notificationId, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST)
            } else {
                startForeground(notificationId, notification)
            }
        } catch (e: Exception) {
            loge("UpdateService sendNotification", e, true)
        }
    }

    companion object {
        const val DOWNLOAD_ACTION = "pillar.kuma_saimono.libumdnscrypt.DOWNLOAD_ACTION"
        const val INSTALLATION_REQUEST_ACTION = "pillar.kuma_saimono.libumdnscrypt.INSTALLATION_REQUEST_ACTION"
        const val STOP_DOWNLOAD_ACTION = "pillar.kuma_saimono.libumdnscrypt.STOP_DOWNLOAD_ACTION"
        const val UPDATE_RESULT = "pillar.kuma_saimono.libumdnscrypt.action.UPDATE_RESULT"
        const val UPDATE_CHANNEL_ID = "UPDATE_CHANNEL_INVIZIBLE"
        const val UPDATE_CHANNEL_NOTIFICATION_ID = 103104
    }
}
