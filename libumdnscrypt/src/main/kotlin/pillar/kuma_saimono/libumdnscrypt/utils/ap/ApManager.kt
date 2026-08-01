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

package pillar.kuma_saimono.libumdnscrypt.utils.ap

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.wifi.WifiConfiguration
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.ResultReceiver
import androidx.annotation.RequiresApi
import javax.inject.Inject
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.utils.enums.AccessPointState
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi

@SuppressLint("PrivateApi")
@Suppress("DEPRECATION")
class ApManager @Inject constructor(
    private val context: Context,
    private val checker: InternetSharingChecker
) {

    //check whether wifi hotspot on or off
    private fun isApOn(): Int {
        return checker.checkApOn()
    }

    fun confirmApState(): Int {
        checker.updateData()

        return if (checker.isApOn) {
            AccessPointState.STATE_ON
        } else {
            AccessPointState.STATE_OFF
        }
    }

    // toggle wifi hotspot on or off
    fun configApState(): Boolean {
        var result = false

        try {
            val wifiManager =
                context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager?
            // if WiFi is on, turn it off
            if (isApOn() == AccessPointState.STATE_ON) {
                if (wifiManager != null) {
                    wifiManager.setWifiEnabled(false)
                }
            }


            result = if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.M) {
                configureHotspotBeforeNougat(wifiManager)
            } else if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                configureHotspotNougat()
            } else {
                configureHotspotOreoAndHigher()
            }
        } catch (e: Exception) {
            loge("ApManager configApState", e)
        }

        return result
    }

    private fun configureHotspotBeforeNougat(wifiManager: WifiManager?): Boolean {
        var result = false

        try {
            if (wifiManager != null) {
                val wifiApConfigurationMethod = wifiManager.javaClass.getMethod("getWifiApConfiguration")
                val netConfig = wifiApConfigurationMethod.invoke(wifiManager) as WifiConfiguration?
                val method = wifiManager.javaClass.getMethod(
                    "setWifiApEnabled",
                    WifiConfiguration::class.java,
                    Boolean::class.javaPrimitiveType
                )
                val apState = isApOn()
                if (apState == AccessPointState.STATE_ON) {
                    method.invoke(wifiManager, netConfig, false)
                } else if (apState == AccessPointState.STATE_OFF) {
                    method.invoke(wifiManager, netConfig, true)
                }
                result = true
            }
        } catch (e: Exception) {
            loge("ApManager configApState M", e)
        }

        return result
    }

    private fun configureHotspotNougat(): Boolean {
        var result = false

        try {
            val connectivityClass = ConnectivityManager::class.java
            val connectivityManager =
                context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

            val apState = isApOn()
            if (apState == AccessPointState.STATE_OFF) {
                @SuppressLint("SoonBlockedPrivateApi")
                val internalConnectivityManagerField =
                    ConnectivityManager::class.java.getDeclaredField("mService")
                internalConnectivityManagerField.isAccessible = true

                callStartTethering(internalConnectivityManagerField.get(connectivityManager))

            } else if (apState == AccessPointState.STATE_ON) {
                val stopTetheringMethod =
                    connectivityClass.getDeclaredMethod("stopTethering", Int::class.javaPrimitiveType)
                stopTetheringMethod.invoke(connectivityManager, 0)
            }

            result = true

        } catch (e: Exception) {
            loge("ApManager configApState N", e)
        }

        return result
    }

    @SuppressLint("MissingPermission")
    @RequiresApi(api = Build.VERSION_CODES.O)
    private fun configureHotspotOreoAndHigher(): Boolean {
        var result = false

        try {
            val apState = isApOn()
            if (apState == AccessPointState.STATE_OFF) {
                val manager =
                    context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager?

                if (manager != null) {
                    manager.startLocalOnlyHotspot(object : WifiManager.LocalOnlyHotspotCallback() {

                        override fun onStarted(reservation: WifiManager.LocalOnlyHotspotReservation) {
                            super.onStarted(reservation)
                            logi("Wifi Hotspot is on now")
                            mReservation = reservation
                        }

                        override fun onStopped() {
                            super.onStopped()
                            logi("Wifi Hotspot onStopped: ")
                        }

                        override fun onFailed(reason: Int) {
                            super.onFailed(reason)
                            logi("Wifi Hotspot onFailed: ")
                        }
                    }, Handler())
                }
            } else if (apState == AccessPointState.STATE_ON) {
                if (mReservation is WifiManager.LocalOnlyHotspotReservation) {
                    (mReservation as WifiManager.LocalOnlyHotspotReservation).close()
                    mReservation = null
                } else {
                    throw Exception("ApManager mReservation = null")
                }
            }

            result = true

        } catch (e: Exception) {
            loge("ApManager configApState O", e)
        }

        return result
    }

    private fun callStartTethering(internalConnectivityManager: Any?) {
        val internalConnectivityManagerClass = Class.forName("android.net.IConnectivityManager")

        val dummyResultReceiver = ResultReceiver(null as Handler?)

        try {
            val startTetheringMethod = internalConnectivityManagerClass.getDeclaredMethod(
                "startTethering",
                Int::class.javaPrimitiveType,
                ResultReceiver::class.java,
                Boolean::class.javaPrimitiveType
            )

            startTetheringMethod.invoke(
                internalConnectivityManager,
                0,
                dummyResultReceiver,
                false
            )
        } catch (e: NoSuchMethodException) {
            // Newer devices have "callingPkg" String argument at the end of this method.
            @SuppressLint("SoonBlockedPrivateApi")
            val startTetheringMethod = internalConnectivityManagerClass.getDeclaredMethod(
                "startTethering",
                Int::class.javaPrimitiveType,
                ResultReceiver::class.java,
                Boolean::class.javaPrimitiveType,
                String::class.java
            )

            startTetheringMethod.invoke(
                internalConnectivityManager,
                0,
                dummyResultReceiver,
                false,
                context.getString(R.string.package_name)
            )
        }
    }

    companion object {
        private var mReservation: Any? = null
    }
}
