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

package pillar.kuma_saimono.libumdnscrypt.utils.notification

import android.Manifest.permission.POST_NOTIFICATIONS
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.core.app.ActivityCompat.shouldShowRequestPermissionRationale
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import javax.inject.Inject

/**
 * MEMORY-LEAK FENCE (e-fix round 2, MEASURED by LeakCanary on the AVD): this manager is an
 * app-graph SINGLETON (Dagger DoubleCheck) while [launcher] is an ACTIVITY-scoped object — an
 * `ActivityResultLauncher` registered on ONE activity's `ActivityResultRegistry`. Holding it past
 * that activity's destruction retained the whole destroyed `MainActivity` (~498 KB, leak signature
 * `25614c8a…`: `TopFragment.notificationPermissionManager → DoubleCheck → launcher →
 * ActivityResultRegistry$2.this$0 → destroyed MainActivity`). The registering activity's lifecycle
 * now auto-clears the launcher (and the listener, whose anonymous impl captures the fragment) on
 * ITS destroy — identity-guarded, so a newer registration from the RECREATED activity is never
 * clobbered by the old activity's teardown.
 */
class NotificationPermissionManager @Inject constructor() {

    var onPermissionResultListener: OnPermissionResultListener? = null
    var launcher:  ActivityResultLauncher<String>? = null

    fun isNotificationPermissionRequestRequired(activity: FragmentActivity) =
        when {
            ContextCompat.checkSelfPermission(
                activity,
                POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED -> false

            shouldShowRequestPermissionRationale(
                activity,
                POST_NOTIFICATIONS
            ) -> false

            else -> true
        }

    @RequiresApi(33)
    fun requestNotificationPermission(activity: FragmentActivity) {
        when {
            ContextCompat.checkSelfPermission(
                activity,
                POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED -> {
                onPermissionResultListener?.onAllowed()
            }

            shouldShowRequestPermissionRationale(
                activity,
                POST_NOTIFICATIONS
            ) -> {
                onPermissionResultListener?.onShowRationale()
            }

            else -> {
                onPermissionResultListener?.onShowRationale()
            }
        }
    }

    fun launchNotificationPermissionSystemDialog(launcher: ActivityResultLauncher<String>) {
        if (Build.VERSION.SDK_INT >= 33) {
            launcher.launch(POST_NOTIFICATIONS)
        }
    }

    fun getNotificationPermissionLauncher(activity: FragmentActivity) =
        activity.registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { isGranted: Boolean ->
            if (isGranted) {
                onPermissionResultListener?.onAllowed()
            }
        }.also {
            launcher = it
            // The leak fence: drop the activity-bound refs when the REGISTERING activity dies.
            // Identity-guarded — if the recreated activity already registered a fresh launcher,
            // the old activity's onDestroy must not clear the new registration.
            activity.lifecycle.addObserver(object : DefaultLifecycleObserver {
                override fun onDestroy(owner: LifecycleOwner) {
                    owner.lifecycle.removeObserver(this)
                    if (launcher === it) {
                        launcher = null
                        onPermissionResultListener = null
                    }
                }
            })
        }

    interface OnPermissionResultListener {
        fun onAllowed()
        fun onShowRationale()
        fun onDenied()
    }
}
