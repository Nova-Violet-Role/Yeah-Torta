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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.CHROME_BROWSER_USER_AGENT
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.web.HttpsConnectionManager
import java.io.File
import java.io.IOException
import javax.inject.Inject
import javax.inject.Named

private const val READ_TIMEOUT_SEC = 30
private const val CONNECT_TIMEOUT_SEC = 30
private const val ATTEMPTS_TO_DOWNLOAD = 5
private const val TIME_TO_DOWNLOAD_MINUTES = 10
private const val ATTEMPTS_TO_DOWNLOAD_WITHIN_TIME = 20
private const val UPDATE_PROGRESS_INTERVAL_MSEC = 300

class DownloadRemoteRulesManager @Inject constructor(
    private val context: Context,
    private val pathVars: PathVars,
    @Named(CoroutinesModule.DISPATCHER_IO)
    private val dispatcherIo: CoroutineDispatcher,
    private val httpsConnectionManager: HttpsConnectionManager
) {

    private val localBroadcastManager by lazy {
        LocalBroadcastManager.getInstance(context)
    }

    suspend fun downloadRules(ruleName: String, url: String, fileName: String): File? =
        withContext(dispatcherIo) {
            var attempts = 0
            val startTime = System.currentTimeMillis()
            var outputFile: File? = null
            var error = ""
            try {
                val path = "${pathVars.getCacheDirPath(context)}/$fileName"
                val oldFile = File(path)
                if (oldFile.isFile) {
                    oldFile.delete()
                }
                do {
                    attempts++
                    try {
                        outputFile = tryDownload(ruleName, url, path)
                    } catch (e: IOException) {
                        outputFile = null
                        error = e.message ?: ""
                        logw(
                            "DownloadRulesManager failed to download file $url, attempt $attempts",
                            e
                        )
                    }
                } while (
                    outputFile == null && isActive &&
                    (attempts < ATTEMPTS_TO_DOWNLOAD
                            || System.currentTimeMillis() - startTime < TIME_TO_DOWNLOAD_MINUTES * 60000
                            && attempts < ATTEMPTS_TO_DOWNLOAD_WITHIN_TIME)
                )
            } catch (e: Exception) {
                error = e.message ?: ""
                loge("DownloadRulesManager failed to download file $url", e)
            }
            if (outputFile != null && outputFile.length() > 0) {
                sendDownloadFinishedBroadcast(ruleName, url, outputFile.length())
                logi("Downloading $url was successful")
            } else {
                sendDownloadFailedBroadcast(ruleName, url, error)
            }
            return@withContext outputFile
        }

    private suspend fun tryDownload(ruleName: String, url: String, filePath: String): File? =
        withContext(dispatcherIo) {
            logi("Downloading DNSCrypt rules $url")

            var range: Long = 0
            val file = File(filePath)
            if (file.isFile) {
                range = file.length()
            } else {
                file.createNewFile()
            }

            val connection = httpsConnectionManager.getHttpsUrlConnection(url).apply {
                connectTimeout = CONNECT_TIMEOUT_SEC * 1000
                readTimeout = READ_TIMEOUT_SEC * 1000
                setRequestProperty("User-Agent", CHROME_BROWSER_USER_AGENT)
                if (range != 0L) {
                    setRequestProperty("Range", "bytes=$range-")
                }
            }
            val fileLength = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                connection.contentLengthLong + range
            } else {
                connection.getContentLength() + range
            }
            connection.inputStream.buffered().use { input ->
                val data = ByteArray(1024)
                file.outputStream().use { output ->
                    var time = System.currentTimeMillis()
                    var count = input.read(data)
                    while (count != -1 && isActive) {
                        range += count
                        val percent = (range * 100 / fileLength).toInt()
                        val currentTime = System.currentTimeMillis()
                        if (currentTime - time > UPDATE_PROGRESS_INTERVAL_MSEC) {
                            time = currentTime
                            sendUpdateProgressBroadcast(ruleName, url, range, percent)
                        }
                        output.write(data, 0, count)
                        count = input.read(data)
                    }
                }
            }
            connection.disconnect()
            return@withContext if (isActive) {
                file
            } else {
                file.delete()
                null
            }
        }

    private fun sendUpdateProgressBroadcast(
        name: String,
        url: String,
        size: Long,
        progress: Int
    ) {
        val intent = Intent(DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_ACTION).apply {
            putExtra(
                DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_DATA,
                DnsRulesDownloadProgress.DownloadProgress(name, url, size, progress)
            )
        }
        localBroadcastManager.sendBroadcast(intent)
    }

    private fun sendDownloadFinishedBroadcast(
        name: String,
        url: String,
        size: Long
    ) {
        val intent = Intent(DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_ACTION).apply {
            putExtra(
                DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_DATA,
                DnsRulesDownloadProgress.DownloadFinished(name, url, size)
            )
        }
        localBroadcastManager.sendBroadcast(intent)
    }

    private fun sendDownloadFailedBroadcast(
        name: String,
        url: String,
        error: String
    ) {
        val intent = Intent(DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_ACTION).apply {
            putExtra(
                DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_DATA,
                DnsRulesDownloadProgress.DownloadFailure(name, url, error)
            )
        }
        localBroadcastManager.sendBroadcast(intent)
    }

    companion object {
        const val DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_ACTION =
            "pillar.kuma_saimono.libumdnscrypt.DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_ACTION"
        const val DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_DATA =
            "pillar.kuma_saimono.libumdnscrypt.DOWNLOAD_REMOTE_DNS_RULES_PROGRESS_DATA"
    }
}
