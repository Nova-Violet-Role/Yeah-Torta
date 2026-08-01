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

package pillar.kuma_saimono.libumdnscrypt.dialogs

import android.app.ActivityManager
import android.content.Context
import android.os.Bundle
import androidx.annotation.Keep
import androidx.appcompat.app.AlertDialog
import androidx.core.content.FileProvider
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.help.Utils
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.executors.CoroutineExecutor
import pillar.kuma_saimono.libumdnscrypt.utils.integrity.Verifier
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ALWAYS_SHOW_HELP_MESSAGES
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.CRASH_REPORT
import java.io.BufferedReader
import java.io.File
import java.io.FileWriter
import java.io.InputStreamReader
import javax.inject.Inject

@Keep
class SendCrashReport : ExtendedDialogFragment() {

    @Inject
    lateinit var preferenceRepository: dagger.Lazy<PreferenceRepository>
    @Inject
    lateinit var pathVars: dagger.Lazy<PathVars>
    @Inject
    lateinit var executor: CoroutineExecutor
    @Inject
    lateinit var verifier: dagger.Lazy<Verifier>

    private var activityManager: ActivityManager? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        App.instance.daggerComponent.inject(this)
        super.onCreate(savedInstanceState)

        activityManager = context?.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
    }

    override fun assignBuilder(): AlertDialog.Builder? {
        if (activity == null || requireActivity().isFinishing) {
            return null
        }

        val builder = AlertDialog.Builder(requireActivity())
        builder.setMessage(uniffi.torta_core.tortaText("dialog_send_crash_report"))
                .setTitle(uniffi.torta_core.tortaText("helper_dialog_title"))
                .setPositiveButton(uniffi.torta_core.tortaText("ok")) { _, _ ->
                    if (activity != null && activity?.isFinishing == false) {
                        executor.submit("SendCrashReport assignBuilder") {

                            val ctx = activity as Context

                            try {
                                if (activity != null && activity?.isFinishing == false) {

                                    val logsDirPath = createLogsDir(ctx)

                                    val memoryInfo = ActivityManager.MemoryInfo().also {
                                        activityManager?.getMemoryInfo(it)
                                    }

                                    val info = Utils.collectInfo(
                                        verifier.get().getAppSignature(),
                                        pathVars.get().appVersion,
                                        pathVars.get().appProcVersion,
                                        Utils.getAppVersion(ctx, pathVars.get(), preferenceRepository.get()),
                                        memoryInfo
                                    )

                                    if (saveLogCat(logsDirPath)) {
                                        sendCrashEmail(ctx, info, File("$logsDirPath/logcat.log"))
                                    }

                                }
                            } catch (exception: Exception) {
                                loge("SendCrashReport", exception)
                            }


                        }
                    }
                }
                .setNeutralButton(uniffi.torta_core.tortaText("cancel")) { _, _ ->
                    dismiss()
                }
                .setNegativeButton(uniffi.torta_core.tortaText("dont_show")) { _, _ ->
                    if (activity != null) {
                        preferenceRepository.get().setBoolPreference("never_send_crash_reports", true)
                    }

                    dismiss()
                }
        return builder
    }

    private fun createLogsDir(context: Context): String? {

        val cacheDir: String
        try {
            cacheDir = context.cacheDir?.canonicalPath
                ?: (pathVars.get().appDataDir + "/cache")
        } catch (e: Exception) {
            logw("SendCrashReport cannot get cache dir", e)
            return null
        }

        val logDirPath = "$cacheDir/logs"
        val dir = File(logDirPath)
        if (!dir.isDirectory && !dir.mkdirs()) {
            loge("SendCrashReport cannot create logs dir")
            return null
        }

        return logDirPath
    }

    private fun saveLogCat(logsDirPath: String?): Boolean {

        if (logsDirPath == null) {
            return false
        }

        val process = Runtime.getRuntime().exec("logcat -d")
        val log = StringBuilder()
        BufferedReader(InputStreamReader(process.inputStream)).use { bufferedReader ->
            var line = bufferedReader.readLine()
            while (line != null) {
                log.append(line)
                log.append("\n")
                line = bufferedReader.readLine()
            }
        }

        FileWriter("$logsDirPath/logcat.log").use { out -> out.write(log.toString()) }

        process.destroy()

        return File("$logsDirPath/logcat.log").isFile
    }

    private fun sendCrashEmail(context: Context, info: String, logCat: File) {

        val text = preferenceRepository.get().getStringPreference(CRASH_REPORT)
        if (text.isNotEmpty()) {
            val uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", logCat)
            if (uri != null) {
                Utils.sendMail(context, info + "\n\n" + text, uri)
            }
            preferenceRepository.get().setStringPreference(CRASH_REPORT, "")
        }
    }

    companion object {
        fun getCrashReportDialog(context: Context): SendCrashReport? {
            val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
            val preferenceRepository = App.instance.daggerComponent.getPreferenceRepository()
            if (!preferenceRepository.get().getBoolPreference("never_send_crash_reports")
                    || sharedPreferences.getBoolean(ALWAYS_SHOW_HELP_MESSAGES, false)) {
                return SendCrashReport()
            }
            return null
        }
    }
}
