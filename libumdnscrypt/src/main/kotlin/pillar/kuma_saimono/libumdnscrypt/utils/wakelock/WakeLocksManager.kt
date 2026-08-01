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

package pillar.kuma_saimono.libumdnscrypt.utils.wakelock

import android.annotation.SuppressLint
import android.content.Context
import android.net.wifi.WifiManager
import android.os.PowerManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import android.os.Build

object WakeLocksManager {

    private var powerWakeLock: PowerManager.WakeLock? = null
    private var wifiWakeLock: WifiManager.WifiLock? = null

    @JvmStatic
    fun getInstance(): WakeLocksManager {
        return this
    }

    @SuppressLint("InvalidWakeLockTag", "WakelockTimeout")
    fun managePowerWakelock(context: Context, lock: Boolean) {
        if (lock) {
            val TAG = "AudioMix"
            val pm = context.applicationContext.getSystemService(Context.POWER_SERVICE) as PowerManager?
            if (powerWakeLock == null && pm != null) {
                powerWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, TAG)
                powerWakeLock?.acquire()
                logi("WakeLocksManager Power wake lock is acquired")
            }
        } else {
            stopPowerWakelock()
        }
    }

    @Suppress("DEPRECATION")
    fun manageWiFiLock(context: Context, lock: Boolean) {
        if (lock) {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager?
            if (wifiWakeLock == null && wm != null) {
                // WIFI_MODE_FULL_HIGH_PERF is deprecated at API 29 and the documented replacement is
                // WIFI_MODE_FULL_LOW_LATENCY. Version-branched rather than swapped outright: the
                // constant does not exist below 29, and the old mode is still the correct one there.
                val wifiLockMode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                } else {
                    @Suppress("DEPRECATION")
                    WifiManager.WIFI_MODE_FULL_HIGH_PERF
                }
                wifiWakeLock = wm.createWifiLock(wifiLockMode, "InviZible::WifiLock")
                wifiWakeLock?.acquire()
                logi("WakeLocksManager WiFi wake lock is acquired")
            }
        } else {
            stopWiFiLock()
        }
    }

    fun stopPowerWakelock() {
        val lock = powerWakeLock
        if (lock != null && lock.isHeld) {
            lock.release()
            powerWakeLock = null
            logi("WakeLocksManager Power wake lock is released")
        }
    }

    fun stopWiFiLock() {
        val lock = wifiWakeLock
        if (lock != null && lock.isHeld) {
            lock.release()
            wifiWakeLock = null
            logi("WakeLocksManager WiFi wake lock is released")
        }
    }

    val isPowerWakeLockHeld: Boolean
        get() {
            val lock = powerWakeLock
            if (lock != null) {
                return lock.isHeld
            }
            return false
        }

    val isWiFiWakeLockHeld: Boolean
        get() {
            val lock = wifiWakeLock
            if (lock != null) {
                return lock.isHeld
            }
            return false
        }
}
