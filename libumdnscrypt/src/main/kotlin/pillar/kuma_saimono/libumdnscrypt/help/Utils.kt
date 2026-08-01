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

package pillar.kuma_saimono.libumdnscrypt.help

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.ResolveInfo
import android.net.Uri
import android.os.Build
import pillar.kuma_saimono.libumdnscrypt.BuildConfig
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.TopFragmentState
import pillar.kuma_saimono.libumdnscrypt.assistance.AccelerateDevelop
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils
import java.util.*

object Utils {

    fun sendMail(context: Context, text: String, attachmentUri: Uri) {

        val sendEmailIntent = Intent(Intent.ACTION_SEND).apply {
            // The intent does not have a URI, so declare the "text/plain" MIME type
            type = "message/rfc822"
            // Yeah! Tortä: no default recipient — the user chooses where to send
            // their logs. Tortä never pre-addresses logs to anyone (privacy).
            putExtra(Intent.EXTRA_SUBJECT, "Yeah! Tortä ${BuildConfig.VERSION_NAME} logcat")
            putExtra(Intent.EXTRA_TEXT, text)
            putExtra(Intent.EXTRA_STREAM, attachmentUri)
        }

        // Verify it resolves
        val activities: List<ResolveInfo> = context.packageManager.queryIntentActivities(sendEmailIntent, 0)
        val isIntentSafe: Boolean = activities.isNotEmpty()

        if (isIntentSafe) {
            try {
                context.startActivity(sendEmailIntent)
            } catch (e: java.lang.Exception) {
                loge("sendMail", e)
            }

        }
    }

    fun ownFault(context: Context, exp: Throwable): Boolean {

        var ex = exp

        if (ex is OutOfMemoryError) {
            return false
        }

        if (ex.cause != null) {
            ex = ex.cause!!
        }

        for (ste in ex.stackTrace) {
            if (ste.className.startsWith(context.packageName)) {
                return true
            }
        }

        return false
    }

    fun collectInfo(
        appSign: String,
        appVersion: String,
        appProcVersion: String,
        version: String,
        memoryInfo: ActivityManager.MemoryInfo?
    ): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return "BRAND " + Build.BRAND + 10.toChar() +
                    "MODEL " + Build.MODEL + 10.toChar() +
                    "MANUFACTURER " + Build.MANUFACTURER + 10.toChar() +
                    "PRODUCT " + Build.PRODUCT + 10.toChar() +
                    "DEVICE " + Build.DEVICE + 10.toChar() +
                    "BOARD " + Build.BOARD + 10.toChar() +
                    "HARDWARE " + Build.HARDWARE + 10.toChar() +
                    "SUPPORTED_ABIS " + Arrays.toString(Build.SUPPORTED_ABIS) + 10.toChar() +
                    "SUPPORTED_32_BIT_ABIS " + Arrays.toString(Build.SUPPORTED_32_BIT_ABIS) + 10.toChar() +
                    "SUPPORTED_64_BIT_ABIS " + Arrays.toString(Build.SUPPORTED_64_BIT_ABIS) + 10.toChar() +
                    "SDK_INT " + Build.VERSION.SDK_INT + 10.toChar() +
                    "THREADS " + Thread.getAllStackTraces().size + 10.toChar() +
                    "TOTAL_MEMORY " + (memoryInfo?.totalMem ?: 0) / 1024 / 1024 + 10.toChar() +
                    "AVAILABLE_MEMORY " + (memoryInfo?.availMem ?: 0) / 1024 / 1024 + 10.toChar() +
                    "LOW_MEMORY " + (memoryInfo?.lowMemory ?: "false") + 10.toChar() +
                    "MAX_HEAP_SIZE " + Runtime.getRuntime().maxMemory() / 1024 / 1024 + 10.toChar() +
                    "USED_HEAP_SIZE " + (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024 + 10.toChar() +
                    "VERSION " + version + 10.toChar() +
                    "APP_VERSION_CODE " + BuildConfig.VERSION_CODE + 10.toChar() +
                    "APP_VERSION_NAME " + BuildConfig.VERSION_NAME + 10.toChar() +
                    "APP_PROC_VERSION " + appProcVersion + 10.toChar() +
                    "CAN_FILTER " + VpnUtils.canFilter() + 10.toChar() +
                    "APP_VERSION " + appVersion + 10.toChar() +
                    "DNSCRYPT_INTERNAL_VERSION " + TopFragmentState.DNSCryptVersion + 10.toChar() +
                    "SIGN_VERSION " + appSign
        } else {
            return "BRAND " + Build.BRAND + 10.toChar() +
                    "MODEL " + Build.MODEL + 10.toChar() +
                    "MANUFACTURER " + Build.MANUFACTURER + 10.toChar() +
                    "PRODUCT " + Build.PRODUCT + 10.toChar() +
                    "DEVICE " + Build.DEVICE + 10.toChar() +
                    "BOARD " + Build.BOARD + 10.toChar() +
                    "HARDWARE " + Build.HARDWARE + 10.toChar() +
                    "SDK_INT " + Build.VERSION.SDK_INT + 10.toChar() +
                    "THREADS " + Thread.getAllStackTraces().size + 10.toChar() +
                    "TOTAL_MEMORY " + (memoryInfo?.totalMem ?: 0) / 1024 / 1024 + 10.toChar() +
                    "AVAILABLE_MEMORY " + (memoryInfo?.availMem ?: 0) / 1024 / 1024 + 10.toChar() +
                    "LOW_MEMORY " + (memoryInfo?.lowMemory ?: "false") + 10.toChar() +
                    "MAX_HEAP_SIZE " + Runtime.getRuntime().maxMemory() / 1024 / 1024 + 10.toChar() +
                    "USED_HEAP_SIZE " + (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024 + 10.toChar() +
                    "VERSION " + version + 10.toChar() +
                    "APP_VERSION_CODE " + BuildConfig.VERSION_CODE + 10.toChar() +
                    "APP_VERSION_NAME " + BuildConfig.VERSION_NAME + 10.toChar() +
                    "APP_PROC_VERSION " + appProcVersion + 10.toChar() +
                    "CAN_FILTER " + VpnUtils.canFilter() + 10.toChar() +
                    "APP_VERSION " + appVersion + 10.toChar() +
                    "DNSCRYPT_INTERNAL_VERSION " + TopFragmentState.DNSCryptVersion + 10.toChar() +
                    "SIGN_VERSION " + appSign
        }
    }

    @JvmStatic
    fun getAppVersion(context: Context, pathVars: PathVars, preferences: PreferenceRepository) =
        if (pathVars.appVersion.endsWith("p")) {
            if (AccelerateDevelop.accelerated) {
                uniffi.torta_core.tortaText("premium_version")
            } else if (preferences.getStringPreference(TortaeKeys.GP_DATA).isNotEmpty()) {
                uniffi.torta_core.tortaText("refunded_version")
            } else {
                uniffi.torta_core.tortaText("free_version")
            }
        } else if (pathVars.appVersion.startsWith("p")) {
            uniffi.torta_core.tortaText("premium_version")
        } else {
            uniffi.torta_core.tortaText("free_version")
        }
}
