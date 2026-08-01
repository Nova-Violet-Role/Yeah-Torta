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
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.FileProvider
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.CHROME_BROWSER_USER_AGENT
import pillar.kuma_saimono.libumdnscrypt.utils.Utils.areNotificationsAllowed
import pillar.kuma_saimono.libumdnscrypt.utils.app
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark.Companion.TOP_FRAGMENT_MARK
import pillar.kuma_saimono.libumdnscrypt.utils.web.HttpsConnectionManager
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.Objects
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeUnit
import java.util.zip.CRC32
import javax.inject.Inject
import javax.net.ssl.HttpsURLConnection
import androidx.core.app.ServiceCompat

@Suppress("DEPRECATION")
class DownloadTask(
    private val updateService: UpdateService,
    private val intent: Intent,
    val serviceStartId: Int,
    val notificationId: Int,
    val startTime: Long
) : Thread() {

    @Inject
    lateinit var preferenceRepository: dagger.Lazy<PreferenceRepository>
    @Inject
    lateinit var pathVars: PathVars
    @Inject
    lateinit var httpsConnectionManager: dagger.Lazy<HttpsConnectionManager>

    private val context: Context = updateService
    private val cacheDir: String

    private var allowSendBroadcastAfterUpdate = true

    init {
        App.instance.daggerComponent.inject(this)
        cacheDir = pathVars.getCacheDirPath(updateService)
    }

    override fun run() {
        val urlToDownload = intent.getStringExtra("url")
        val fileToDownload = intent.getStringExtra("file")
        val hash = intent.getStringExtra("hash")
        val preferences = preferenceRepository.get()
        var attempts = 0
        val startTime = System.currentTimeMillis()

        try {

            if (urlToDownload == null || fileToDownload == null || hash == null) {
                throw IllegalStateException("urlToDownload = " + urlToDownload
                        + " fileToDownload  = " + fileToDownload
                        + " hash = " + hash)
            }

            var outputFile: File? = null
            var exception: Exception = CancellationException(
                "UpdateService downloading file cancelled"
            )
            do {
                try {
                    outputFile = downloadFile(fileToDownload, urlToDownload)
                } catch (e: IOException) {
                    exception = e
                    logw("UpdateService failed to download file " + urlToDownload + ", attempt " + attempts, e)
                }
                attempts++
            } while (outputFile == null
                && (attempts < ATTEMPTS_TO_DOWNLOAD
                        || System.currentTimeMillis() - startTime < TIME_TO_DOWNLOAD_MINUTES * 60000
                        && attempts < MAX_ATTEMPTS_TO_DOWNLOAD)
                && !currentThread().isInterrupted)

            if (outputFile == null) {
                throw exception
            }

            val checkSum = hash.equals(crc32(outputFile), ignoreCase = true)

            if (checkSum) {

                preferences.setStringPreference("LastUpdateResult",
                    uniffi.torta_core.tortaText("update_installed"))

                if (fileToDownload.contains("InviZible")) {
                    allowSendBroadcastAfterUpdate = false

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && !context.app.isAppForeground) {
                        //Required for androidQ because even if the service is in the foreground we cannot start an activity if no activity is visible
                        preferences.setStringPreference("RequiredAppUpdateForQ", outputFile.canonicalPath)
                    } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        installApkForNougatAndHigher(outputFile)
                    } else {
                        installApkLowerNougat(outputFile)
                    }

                    makeDelay(3)
                }

            } else {
                preferences.setStringPreference("LastUpdateResult", uniffi.torta_core.tortaText("update_fault"))
                preferences.setStringPreference("UpdateResultMessage", uniffi.torta_core.tortaText("update_fault"))
                FileManager.deleteFile(context, cacheDir, fileToDownload, "ignored")
                loge("UpdateService file hashes mismatch " + fileToDownload)
            }

        } catch (e: Exception) {
            preferences.setStringPreference("LastUpdateResult", uniffi.torta_core.tortaText("update_fault"))
            preferences.setStringPreference("UpdateResultMessage", uniffi.torta_core.tortaText("update_fault"))
            loge("UpdateService failed to download file " + urlToDownload, e)
        } finally {
            updateService.sparseArray.delete(serviceStartId)
            if (updateService.currentNotificationId.get() - 1 == UpdateService.UPDATE_CHANNEL_NOTIFICATION_ID) {
                ServiceCompat.stopForeground(updateService, ServiceCompat.STOP_FOREGROUND_REMOVE)
                updateService.notificationManager!!.cancel(notificationId)
                sendUpdateResultBroadcast()
                updateService.stopSelf()
            } else {
                updateService.notificationManager!!.cancel(notificationId)
                updateService.currentNotificationId.getAndDecrement()
            }

        }
    }

    @Throws(IOException::class)
    private fun downloadFile(fileToDownload: String, urlToDownload: String): File {
        val notificationsAllowed = areNotificationsAllowed(updateService.notificationManager!!)

        var range: Long = 0

        val path = cacheDir + "/" + fileToDownload
        val outputFile = File(path)

        if (outputFile.isFile) {
            range = outputFile.length()
        } else {
            removeOldApkFileFromPrevUpdate(cacheDir)
            //noinspection ResultOfMethodCallIgnored
            outputFile.createNewFile()
        }

        val con = httpsConnectionManager.get().getHttpsUrlConnection(urlToDownload)

        con.connectTimeout = 1000 * CONNECT_TIMEOUT
        con.readTimeout = 1000 * READ_TIMEOUT
        con.setRequestProperty("User-Agent", CHROME_BROWSER_USER_AGENT)

        if (range != 0L) {
            con.setRequestProperty("Range", "bytes=" + range + "-")
        }

        val fileLength: Long
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
            fileLength = con.contentLengthLong + range
        } else {
            fileLength = con.contentLength + range
        }

        try {
            val input: InputStream = BufferedInputStream(con.inputStream)
            input.use {
                val output: OutputStream = FileOutputStream(path, true)
                output.use {
                    val data = ByteArray(1024)
                    var count = 0
                    var percent = 0
                    while (input.read(data).also { count = it } != -1) {
                        range += count

                        if (currentThread().isInterrupted) {
                            logw("Download was interrupted by user " + fileToDownload)
                            break
                        }


                        val currentPercent = (range * 100 / fileLength).toInt()
                        if (notificationsAllowed && currentPercent - percent >= 5) {
                            percent = currentPercent
                            updateNotification(fileToDownload, percent)
                        }

                        output.write(data, 0, count)
                    }
                }
            }
        } finally {
            con.disconnect()
        }

        return outputFile
    }

    private fun installApkForNougatAndHigher(outputFile: File) {
        val apkUri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", outputFile)
        val intent = Intent(Intent.ACTION_INSTALL_PACKAGE)
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        intent.setData(apkUri)
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val packageManager = context.packageManager
        if (packageManager != null && intent.resolveActivity(packageManager) != null) {
            updateService.startActivity(intent)
        }
    }

    private fun installApkLowerNougat(outputFile: File) {
        val apkUri = Uri.fromFile(outputFile)
        val intent = Intent(Intent.ACTION_VIEW)
        intent.setDataAndType(apkUri, "application/vnd.android.package-archive")
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val packageManager = context.packageManager
        if (packageManager != null && intent.resolveActivity(packageManager) != null) {
            updateService.startActivity(intent)
        }
    }

    private fun removeOldApkFileFromPrevUpdate(dirPath: String) {

        try {
            val dir = File(dirPath)

            if (dir.listFiles() == null) {
                return
            }

            for (file in Objects.requireNonNull(dir.listFiles())) {
                if (file.name.contains("InviZible")) {
                    //noinspection ResultOfMethodCallIgnored
                    file.delete()
                }
            }
        } catch (e: Exception) {
            loge("Unable to remove old InviZible.apk file during update", e)
        }
    }

    private fun sendUpdateResultBroadcast() {
        if (allowSendBroadcastAfterUpdate) {
            makeDelay(5)

            val intent = Intent(UpdateService.UPDATE_RESULT)
            intent.putExtra("Mark", TOP_FRAGMENT_MARK)
            LocalBroadcastManager.getInstance(context).sendBroadcast(intent)
        }
    }

    private fun makeDelay(sec: Int) {
        try {
            TimeUnit.SECONDS.sleep(sec.toLong())
        } catch (ignored: InterruptedException) {
        }
    }

    private fun crc32(file: File): String? {
        val crc = CRC32()

        try {
            val inputStream: InputStream = FileInputStream(file)
            inputStream.use {
                val bout = ByteArrayOutputStream()
                bout.use {
                    val readBuffer = ByteArray(4 * 1024)
                    var read = 0
                    while (inputStream.read(readBuffer).also { read = it } != -1) {
                        bout.write(readBuffer, 0, read)
                    }

                    crc.update(bout.toByteArray())

                    return String.format("%08X", crc.value)
                }
            }
        } catch (e: IOException) {
            loge("crc32() Exception while getting FileInputStream", e)
        }

        return null
    }

    @SuppressLint("UnspecifiedImmutableFlag")
    private fun updateNotification(fileToDownload: String, percent: Int) {
        val ticker = uniffi.torta_core.tortaText("update_notification")
        val text = uniffi.torta_core.tortaText("update_notification") +
                " " + fileToDownload

        val notificationIntent = Intent(updateService, TortaSlintActivity::class.java)
        notificationIntent.setAction(Intent.ACTION_MAIN)
        notificationIntent.addCategory(Intent.CATEGORY_LAUNCHER)

        val stopDownloadIntent = Intent(updateService, UpdateService::class.java)
        stopDownloadIntent.setAction(UpdateService.STOP_DOWNLOAD_ACTION)
        stopDownloadIntent.putExtra("ServiceStartId", serviceStartId)

        val stopDownloadPendingIntent: PendingIntent
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            stopDownloadPendingIntent = PendingIntent.getService(
                updateService,
                notificationId,
                stopDownloadIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        } else {
            stopDownloadPendingIntent = PendingIntent.getService(
                updateService,
                notificationId,
                stopDownloadIntent,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }

        val contentIntent: PendingIntent
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            contentIntent = PendingIntent.getActivity(
                updateService,
                0,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            contentIntent = PendingIntent.getActivity(
                updateService,
                0,
                notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }

        val builder = NotificationCompat.Builder(updateService, UpdateService.UPDATE_CHANNEL_ID)
        builder.setContentIntent(contentIntent)
            .setOngoing(true)
            .setSmallIcon(R.drawable.ic_update)
            .setTicker(ticker)
            .setContentTitle("")
            .setContentText(text)
            .setOnlyAlertOnce(true)
            .setWhen(startTime)
            .setUsesChronometer(true)
            .setChannelId(UpdateService.UPDATE_CHANNEL_ID)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .addAction(R.drawable.ic_stop, uniffi.torta_core.tortaText("cancel_download"), stopDownloadPendingIntent)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_PROGRESS)
        }

        val PROGRESS_MAX = 100
        builder.setProgress(PROGRESS_MAX, percent, false)

        val notification = builder.build()

        synchronized(updateService) {
            updateService.notificationManager!!.notify(notificationId, notification)
        }
    }

    companion object {
        private const val READ_TIMEOUT = 60
        private const val CONNECT_TIMEOUT = 60
        private const val ATTEMPTS_TO_DOWNLOAD = 5
        private const val MAX_ATTEMPTS_TO_DOWNLOAD = 120
        private const val TIME_TO_DOWNLOAD_MINUTES = 25
    }
}
