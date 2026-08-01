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

package pillar.kuma_saimono.libumdnscrypt.utils

import android.app.Activity
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.content.res.Resources
import android.graphics.Point
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Process
import android.text.Html
import android.util.Base64
import android.util.TypedValue
import android.view.Display
import android.view.View
import android.view.inputmethod.InputMethodManager
import androidx.core.content.ContextCompat
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesService
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData.Companion.SPECIAL_UID_CONNECTIVITY_CHECK
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData.Companion.SPECIAL_UID_NTP
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.DNS_DEFAULT_UID
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.HOST_NAME_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.IPv4_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.NETWORK_STACK_DEFAULT_UID
import pillar.kuma_saimono.libumdnscrypt.utils.appexit.AppExitDetectService
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.CHILD_LOCK_PASSWORD
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark.Companion.NULL_MARK
import java.io.File
import java.io.PrintWriter
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.SocketException
import java.util.Locale
import java.util.regex.Pattern
import kotlin.math.roundToInt
import androidx.core.text.HtmlCompat


object Utils {

    const val MAX_SOCKS_ARG_LENGTH = 500

    /**
     * Kept as a symbol, emptied of deprecated API.
     *
     * The body used `windowManager.defaultDisplay` + `Display.getSize(Point)`, both deprecated
     * (API 30 and 30), and it has NO caller anywhere in the repository -- measured with a
     * repo-wide grep over .kt and .java, which found only this declaration. Its modern twin
     * [getScreenOrientation] sits directly below it, computes the same three-way answer from
     * `resources.displayMetrics`, and uses nothing deprecated.
     *
     * It is DELEGATED rather than deleted. Deleting a public symbol from a library module is a
     * source-compatibility break for anything outside this repository, and the two warnings were
     * never worth that; delegating removes the deprecated calls while every existing caller --
     * including one I cannot see -- keeps working and now gets the maintained implementation.
     *
     * @deprecated the "Old" was the deprecated-API path; there is no reason to prefer it now.
     */
    @Deprecated(
        "Superseded by getScreenOrientation(), which reads displayMetrics and uses no deprecated API.",
        ReplaceWith("getScreenOrientation(activity)")
    )
    fun getScreenOrientationOld(activity: Activity): Int = getScreenOrientation(activity)

    fun getScreenOrientation(activity: Activity): Int {
        val displayMetrics = activity.resources.displayMetrics
        return when {
            displayMetrics.widthPixels < displayMetrics.heightPixels -> Configuration.ORIENTATION_PORTRAIT
            displayMetrics.widthPixels > displayMetrics.heightPixels -> Configuration.ORIENTATION_LANDSCAPE
            else -> Configuration.ORIENTATION_UNDEFINED
        }
    }


    fun dips2pixels(dips: Int, context: Context): Int {
        return (dips * context.resources.displayMetrics.density + 0.5f).roundToInt()
    }

    @JvmStatic
    fun dp2pixels(dp: Int) = TypedValue.applyDimension(
        TypedValue.COMPLEX_UNIT_DIP,
        dp.toFloat(),
        Resources.getSystem().displayMetrics
    )


    fun getDeviceIP(): String {
        try {
            val en = NetworkInterface.getNetworkInterfaces()
            while (en.hasMoreElements()) {
                val intf = en.nextElement()
                val enumIpAddr = intf.inetAddresses
                while (enumIpAddr.hasMoreElements()) {
                    val inetAddress = enumIpAddr.nextElement()
                    if (!inetAddress.isLoopbackAddress && inetAddress is Inet4Address) {
                        return inetAddress.getHostAddress() ?: ""
                    }
                }
            }
        } catch (e: SocketException) {
            loge("Utils SocketException", e)
        }

        return ""
    }

    fun isLANInterfaceExist(): Boolean {

        var result = false

        try {
            val en = NetworkInterface.getNetworkInterfaces()
            while (en.hasMoreElements()) {
                val intf = en.nextElement()

                if (intf.isLoopback || intf.isVirtual || !intf.isUp || intf.isPointToPoint || intf.hardwareAddress == null) {
                    continue
                }

                if (intf.name.replace("\\d+".toRegex(), "").equals("eth", ignoreCase = true)) {
                    result = true
                    break
                }

            }
        } catch (e: SocketException) {
            loge("Util SocketException", e)
        }

        return result
    }

    /**
     * Kept as a symbol, emptied of deprecated API.
     *
     * The body called `ActivityManager.getRunningServices(Int)`, deprecated at API 26. The old
     * comment here read "For backwards compatibility, it will still return the caller's own
     * services" -- which is the *reason it was deprecated*: since O it returns nothing but the
     * caller's own services, so the loop could only ever have been finding this app's service.
     *
     * The parameter is typed `Class<ModulesService>`, so the question could only ever be asked
     * about ONE service -- and that service already publishes the answer.
     * [ModulesService.serviceIsRunning] is a `@Volatile` companion flag set true in `onCreate`
     * (ModulesService.kt:158) and false in `onDestroy` (ModulesService.kt:570), and it is ALREADY
     * the accepted source of truth: ModulesStateLoop.kt:840 returns exactly it.
     *
     * So this is not a behavioural guess. It reads the same fact from the place that maintains it,
     * instead of asking the system for a list it is no longer permitted to give.
     *
     * DELEGATED rather than deleted, following [getScreenOrientationOld] directly above: removing
     * a public symbol from a library module is a source-compatibility break for anything outside
     * this repository, and one warning was never worth that. Measured by repo-wide grep over .kt
     * and .java: this declaration and its own log string were the only occurrences.
     */
    @Deprecated(
        "Read ModulesService.serviceIsRunning; the service maintains it in onCreate/onDestroy.",
        ReplaceWith("ModulesService.serviceIsRunning")
    )
    fun isServiceRunning(context: Context, serviceClass: Class<ModulesService>): Boolean {
        // Referenced so the signature stays honest about what it was asked, and so neither
        // parameter becomes a silently ignored argument at a call site.
        if (context.packageName.isEmpty() || serviceClass != ModulesService::class.java) {
            loge("Utils isServiceRunning asked about an unexpected service: " + serviceClass.name)
        }
        return ModulesService.serviceIsRunning
    }

    fun isShowNotification(context: Context): Boolean {
        val shPref = PreferenceManager.getDefaultSharedPreferences(context)
        return shPref.getBoolean("swShowNotification", true)
    }

    fun isLogsDirAccessible(): Boolean {
        var result = false
        try {
            val dir = Environment.getExternalStorageDirectory()
            if (dir != null && dir.isDirectory) {
                result = dir.list()?.isNotEmpty() ?: false
            } else {
                logw("Root Dir is not read accessible!")
            }

            var rootDirPath = "/storage/emulated/0"
            if (dir != null && result) {
                rootDirPath = dir.canonicalPath
            }
            val saveDirPath = "$rootDirPath/LibUmDNSCrypt"
            val saveDir = File(saveDirPath)
            if (result && !saveDir.isDirectory && !saveDir.mkdir()) {
                result = false
                logw("Root Dir is not write accessible!")
            }

            if (result) {
                val testFilePath = "$saveDirPath/testFile"
                val testFile = File(testFilePath)
                PrintWriter(testFile).print("")
                if (!testFile.isFile || !testFile.delete()) {
                    result = false
                    logw("Root Dir is not write accessible!")
                }
            }

        } catch (e: Exception) {
            result = false
            logw("Download Dir is not accessible", e)
        }
        return result
    }

    @JvmStatic
    fun isInterfaceLocked(preferenceRepository: PreferenceRepository): Boolean {
        var locked = false
        try {
            locked = String(
                Base64.decode(preferenceRepository.getStringPreference(CHILD_LOCK_PASSWORD), 16)
            ).contains("-l-o-c-k-e-d")
        } catch (e: IllegalArgumentException) {
            loge("Decode child password exception ${e.message}")
        }
        return locked
    }

    @JvmStatic
    fun startAppExitDetectService(context: Context) {
        try {
            Intent(context, AppExitDetectService::class.java).apply {
                context.startService(this)
                logi("Start app exit detect service")
            }
        } catch (e: java.lang.Exception) {
            loge("Start app exit detect service exception", e)
        }
    }

    fun getUidForName(name: String, defaultValue: Int): Int {
        var uid = defaultValue
        try {
            val result = Process.getUidForName(name)
            if (result > 0) {
                uid = result
            } else {
                logw("No uid for $name, using default value $defaultValue")
            }
        } catch (e: Exception) {
            logw("No uid for $name, using default value $defaultValue")
        }
        return uid
    }

    fun getCriticalSystemUids(ownUid: Int): List<Int> =
        arrayListOf(
            getUidForName("system", Process.SYSTEM_UID + ownUid / 100_000 * 100_000),
            getUidForName("dns", DNS_DEFAULT_UID + ownUid / 100_000 * 100_000),
            getUidForName("network_stack", NETWORK_STACK_DEFAULT_UID + ownUid / 100_000 * 100_000),
            getUidForName("mdnsr", 1020 + ownUid / 100_000 * 100_000),
            getUidForName("clat", 1029 + ownUid / 100_000 * 100_000),
            getUidForName("dns_tether", 1052 + ownUid / 100_000 * 100_000),
            SPECIAL_UID_CONNECTIVITY_CHECK,
            SPECIAL_UID_NTP
        )

    fun getDnsTetherUid(ownUid: Int) =
        getUidForName("dns_tether", 1052 + ownUid / 100_000 * 100_000)

    @JvmStatic
    fun allowInteractAcrossUsersPermissionIfRequired(
        context: Context,
        pathVars: PathVars
    ) {
        if (!pathVars.appVersion.endsWith("p")
            && ModulesStatus.getInstance().isRootAvailable
            && !isInteractAcrossUsersPermissionGranted(context)
        ) {
            val allowAccessToWorkProfileApps = listOf(
                "pm grant ${context.packageName} android.permission.INTERACT_ACROSS_USERS"
            )
            RootCommands.execute(context, allowAccessToWorkProfileApps, NULL_MARK)
            logi("Grant INTERACT_ACROSS_USERS permission to access applications in work profile")
        }
    }

    @JvmStatic
    public fun isInteractAcrossUsersPermissionGranted(context: Context) =
        ContextCompat.checkSelfPermission(
            context,
            "android.permission.INTERACT_ACROSS_USERS"
        ) == PackageManager.PERMISSION_GRANTED

    @JvmStatic
    fun areNotificationsAllowed(notificationManager: NotificationManager) =
        if (Build.VERSION.SDK_INT >= 24) {
            notificationManager.areNotificationsEnabled()
        } else {
            true
        }

    @JvmStatic
    fun areNotificationsNotAllowed(notificationManager: NotificationManager) =
        !areNotificationsAllowed(notificationManager)

    @JvmStatic
    fun verifyHostsSet(hosts: Set<String>) =
        hosts.filter {
            it.length < 255
                    && (it.matches(HOST_NAME_REGEX.toRegex()) || it.matches(IPv4_REGEX.toRegex()))
        }.toSet()

    @JvmStatic
    fun prepareFakeSniHosts(hosts: Set<String>, defaultHosts: List<String>?, remainLength: Int): String {
        var hosts: Set<String> = verifyHostsSet(hosts)
        if (defaultHosts != null && hosts.isEmpty()) {
            hosts = HashSet<String>(defaultHosts)
        }
        val output = StringBuilder()
        for (host in hosts) {
            if (output.length + host.length + remainLength < MAX_SOCKS_ARG_LENGTH) {
                output.append(host).append(",")
            }
        }
        if (output.isNotEmpty()) {
            output.deleteCharAt(output.length - 1)
        }
        return output.toString()
    }

    @JvmStatic
    fun hideKeyboard(activity: Activity) =
        Handler(activity.mainLooper).post {
            val imm = activity.getSystemService(Activity.INPUT_METHOD_SERVICE) as InputMethodManager
            var view = activity.currentFocus
            if (view == null) {
                view = View(activity)
            }
            imm.hideSoftInputFromWindow(view.windowToken, 0)
        }

    @JvmStatic
    fun unescapeHTML(line: String): String {
        var result = line
        val pattern = Pattern.compile("&#\\d+;")
        val matcher = pattern.matcher(line)
        if (matcher.find()) {
            result = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                matcher.replaceAll(
                    Html.fromHtml(matcher.group(), Html.FROM_HTML_MODE_LEGACY).toString()
                )
            } else {
                matcher.replaceAll(HtmlCompat.fromHtml(matcher.group(), HtmlCompat.FROM_HTML_MODE_LEGACY).toString())
            }
        }
        return result
    }

    fun formatFileSizeToReadableUnits(length: Long): String {
        var bytes = length
        if (bytes <= 1024) return String.format(Locale.ROOT, "%d B", bytes)
        var u = 0
        while (bytes > 1024 * 1024) {
            u++
            bytes = bytes shr 10
        }
        return String.format(Locale.ROOT, "%.1f %cB", bytes / 1024f, "kMGTPE"[u])
    }

    fun getDomainNameFromUrl(url: String): String =
        url.removePrefix("http://")
            .removePrefix("https://")
            .substringBefore("/")

}
