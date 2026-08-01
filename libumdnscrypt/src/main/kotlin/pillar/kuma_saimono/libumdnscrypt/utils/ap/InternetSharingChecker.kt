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

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Pair
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.EXTENDED_AP_INTERFACE_RANGE
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.STANDARD_3G_INTERFACE_NAMES
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.STANDARD_AP_INTERFACE_RANGE
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.STANDARD_ETHERNET_INTERFACE_NAME
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.STANDARD_ETHERNET_INTERFACE_NAMES
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.STANDARD_USB_INTERFACE_TETHER_NAMES
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.STANDARD_USB_MODEM_INTERFACE_NAME
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.STANDARD_USB_MODEM_INTERFACE_RANGE
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.STANDARD_VPN_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.STANDARD_VPN_INTERFACE_NAME
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.STANDARD_WIFI_INTERFACE_NAME
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.STANDARD_WIFI_INTERFACE_NAMES
import pillar.kuma_saimono.libumdnscrypt.utils.enums.AccessPointState
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import java.lang.reflect.Method
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.SocketException
import java.util.Enumeration
import javax.inject.Inject

class InternetSharingChecker @Inject constructor(
    private val context: Context
) {

    var wifiAPAddressesRange = "192.168.43.0/24"
        private set
    var usbModemAddressesRange = "192.168.42.0/24"
        private set

    var isApOn = false
        private set
    var isUsbTetherOn = false
        private set
    var isEthernetOn = false
        private set

    var vpnInterfaceName = STANDARD_VPN_INTERFACE_NAME
        private set
    var wifiAPInterfaceName = STANDARD_WIFI_INTERFACE_NAME
        private set
    var usbModemInterfaceName = STANDARD_USB_MODEM_INTERFACE_NAME
        private set
    var ethernetInterfaceName = STANDARD_ETHERNET_INTERFACE_NAME
        private set

    fun updateData() {

        var wifiInterfaceNameToAddressExtended: Pair<String, String>? = null
        var gsmInternetIsUp = false
        var wifiInterfaceNameToAddressFuzzy: Pair<String, String>? = null
        val isLessAndroidR = Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q

        try {
            val en = NetworkInterface.getNetworkInterfaces()
            while (en.hasMoreElements()) {

                if (Thread.currentThread().isInterrupted) {
                    return
                }

                val networkInterface = en.nextElement()

                if (networkInterface.isLoopback) {
                    continue
                }
                if (networkInterface.isVirtual) {
                    continue
                }
                if (!networkInterface.isUp) {
                    continue
                }

                setVpnInterfaceName(networkInterface)

                if (networkInterface.isPointToPoint) {
                    continue
                }
                if (networkInterface.hardwareAddress == null
                        //https://developer.android.com/training/articles/user-data-ids#mac-addresses
                        && isLessAndroidR) {
                    continue
                }

                if (!isEthernetOn) {
                    checkEthernetAvailable(networkInterface)
                }

                if (apInterfaceNameFromReceiver != null
                        && apInterfaceNameFromReceiver != NO_INTERFACE) {
                    checkApInterfaceFromReceiver(networkInterface)
                }

                if (usbModemInterfaceNameFromReceiver != null
                        && usbModemInterfaceNameFromReceiver != NO_INTERFACE) {
                    checkUsbInterfaceFromReceiver(networkInterface)
                }

                if (!isApOn && apInterfaceNameFromReceiver == null) {
                    checkWiFiAccessPointAvailableStandard(networkInterface)
                }
                if (wifiInterfaceNameToAddressExtended == null && apInterfaceNameFromReceiver == null) {
                    wifiInterfaceNameToAddressExtended = checkWiFiAccessPointAvailableExtended(networkInterface)
                }
                if (!gsmInternetIsUp) {
                    gsmInternetIsUp = check3GIsUp(networkInterface)
                }
                if (wifiInterfaceNameToAddressFuzzy == null && apInterfaceNameFromReceiver == null) {
                    wifiInterfaceNameToAddressFuzzy = checkWiFiIsUp(networkInterface)
                }

                if (!isUsbTetherOn && usbModemInterfaceNameFromReceiver == null) {
                    checkUsbModemAvailableStandard(networkInterface)
                }
                if (!isUsbTetherOn && usbModemInterfaceNameFromReceiver == null) {
                    checkUsbModemAvailableExtended(networkInterface)
                }

            }

            var performExtendedCheck = false
            if (!isApOn && apInterfaceNameFromReceiver == null) {
                performExtendedCheck = checkApOn() != AccessPointState.STATE_OFF
            }

            if (!isApOn && performExtendedCheck && wifiInterfaceNameToAddressExtended != null) {
                isApOn = true
                wifiAPInterfaceName = wifiInterfaceNameToAddressExtended.first
                wifiAPAddressesRange = wifiInterfaceNameToAddressExtended.second
            }

            if (!isApOn && performExtendedCheck && gsmInternetIsUp
                    && wifiInterfaceNameToAddressFuzzy != null) {
                isApOn = true
                wifiAPInterfaceName = wifiInterfaceNameToAddressFuzzy.first
                wifiAPAddressesRange = wifiInterfaceNameToAddressFuzzy.second
            }

            val logEntry = " \nWiFi Access point is " + (if (isApOn) "ON" else "OFF") + "\n" +
                    "Final WiFi AP interface name " + wifiAPInterfaceName + "\n" +
                    "WiFi AP addresses range " + wifiAPAddressesRange + "\n" +
                    "USB modem is " + (if (isUsbTetherOn) "ON" else "OFF") + "\n" +
                    "USB modem interface name " + usbModemInterfaceName + "\n" +
                    "USB modem addresses range " + usbModemAddressesRange
            logi(logEntry)

        } catch (e: SocketException) {
            loge("Tethering SocketException", e)
        }
    }

    private fun checkEthernetAvailable(networkInterface: NetworkInterface) {
        val interfaceName = networkInterface.name
        for (name in STANDARD_ETHERNET_INTERFACE_NAMES) {
            if (interfaceName.matches(name.replace("+", "\\d+").toRegex())) {
                isEthernetOn = true
                ethernetInterfaceName = networkInterface.name
                logi("LAN interface name " + ethernetInterfaceName)
                break
            }
        }
    }

    private fun checkApInterfaceFromReceiver(networkInterface: NetworkInterface) {
        val interfaceName = networkInterface.name
        if (interfaceName.matches(apInterfaceNameFromReceiver!!.toRegex())) {

            val enumIpAddr = networkInterface.inetAddresses
            while (enumIpAddr.hasMoreElements()) {
                val inetAddress = enumIpAddr.nextElement()
                val hostAddress = inetAddress.hostAddress

                if (hostAddress != null && isNotIPv6Address(hostAddress) && isInetAddress(hostAddress)) {
                    isApOn = true
                    wifiAPInterfaceName = apInterfaceNameFromReceiver!!
                    wifiAPAddressesRange = hostAddress.replace("\\.\\d+$".toRegex(), ".0/24")
                    logi("Receiver WiFi AP interface name " + wifiAPInterfaceName)
                    return
                }
            }
        }
    }

    private fun checkUsbInterfaceFromReceiver(networkInterface: NetworkInterface) {
        val interfaceName = networkInterface.name
        if (interfaceName.matches(usbModemInterfaceNameFromReceiver!!.toRegex())) {

            val enumIpAddr = networkInterface.inetAddresses
            while (enumIpAddr.hasMoreElements()) {
                val inetAddress = enumIpAddr.nextElement()
                val hostAddress = inetAddress.hostAddress

                if (hostAddress != null && isNotIPv6Address(hostAddress) && isInetAddress(hostAddress)) {
                    isUsbTetherOn = true
                    usbModemInterfaceName = usbModemInterfaceNameFromReceiver!!
                    usbModemAddressesRange = hostAddress.replace("\\.\\d+$".toRegex(), ".0/24")
                    logi("Receiver USB interface name " + usbModemInterfaceName)
                    return
                }
            }
        }
    }

    private fun checkWiFiAccessPointAvailableStandard(networkInterface: NetworkInterface) {
        val enumIpAddr = networkInterface.inetAddresses
        while (enumIpAddr.hasMoreElements()) {
            val inetAddress = enumIpAddr.nextElement()
            val hostAddress = inetAddress.hostAddress

            if (hostAddress != null && hostAddress.contains(STANDARD_AP_INTERFACE_RANGE)) {
                isApOn = true
                wifiAPInterfaceName = networkInterface.name
                logi("Standard WiFi AP interface name " + wifiAPInterfaceName)
                return
            }
        }
    }

    private fun checkWiFiAccessPointAvailableExtended(networkInterface: NetworkInterface): Pair<String, String>? {

        val interfaceName = networkInterface.name
        if (interfaceName == STANDARD_WIFI_INTERFACE_NAME
                || interfaceName == STANDARD_ETHERNET_INTERFACE_NAME) {
            return null
        }

        val enumIpAddr = networkInterface.inetAddresses
        while (enumIpAddr.hasMoreElements()) {
            val inetAddress = enumIpAddr.nextElement()
            val hostAddress = inetAddress.hostAddress

            if (hostAddress != null && hostAddress.contains(EXTENDED_AP_INTERFACE_RANGE)) {
                return Pair(networkInterface.name, WIFI_AP_ADDRESSES_RANGE_EXTENDED)
            }
        }
        return null
    }

    private fun check3GIsUp(networkInterface: NetworkInterface): Boolean {
        val interfaceName = networkInterface.name
        for (interfaceName3g in STANDARD_3G_INTERFACE_NAMES) {
            if (interfaceName.matches(interfaceName3g.replace("+", "\\d+").toRegex())) {
                return true
            }
        }
        return false
    }

    private fun checkWiFiIsUp(networkInterface: NetworkInterface): Pair<String, String>? {
        val interfaceName = networkInterface.name
        for (interfaceNameWiFi in STANDARD_WIFI_INTERFACE_NAMES) {
            if (interfaceName.matches(interfaceNameWiFi.replace("+", "\\d+").toRegex())) {
                val enumIpAddr = networkInterface.inetAddresses
                while (enumIpAddr.hasMoreElements()) {
                    val inetAddress = enumIpAddr.nextElement()
                    val hostAddress = inetAddress.hostAddress

                    if (hostAddress != null && isNotIPv6Address(hostAddress)) {
                        return Pair(interfaceName, hostAddress)
                    }
                }
                return null
            }
        }
        return null
    }

    private fun checkUsbModemAvailableStandard(networkInterface: NetworkInterface) {
        val enumIpAddr = networkInterface.inetAddresses
        while (enumIpAddr.hasMoreElements()) {
            val inetAddress = enumIpAddr.nextElement()
            val hostAddress = inetAddress.hostAddress

            if (hostAddress != null && hostAddress.contains(STANDARD_USB_MODEM_INTERFACE_RANGE)) {
                isUsbTetherOn = true
                usbModemInterfaceName = networkInterface.name
                logi("USB Modem interface name " + usbModemInterfaceName)
                return
            }
        }
    }

    private fun checkUsbModemAvailableExtended(networkInterface: NetworkInterface) {
        val interfaceName = networkInterface.name
        for (name in STANDARD_USB_INTERFACE_TETHER_NAMES) {
            if (interfaceName.matches(name.replace("+", "\\d+").toRegex())) {
                isUsbTetherOn = true
                usbModemInterfaceName = networkInterface.name
                logi("USB Modem interface name " + usbModemInterfaceName)

                val enumIpAddr = networkInterface.inetAddresses
                while (enumIpAddr.hasMoreElements()) {
                    val inetAddress = enumIpAddr.nextElement()
                    val hostAddress = inetAddress.hostAddress

                    if (hostAddress != null && isNotIPv6Address(hostAddress) && isInetAddress(hostAddress)) {
                        usbModemAddressesRange = hostAddress
                        logi("USB Modem addresses range " + usbModemAddressesRange)
                        return
                    }
                }
                return
            }
        }
    }

    private fun isNotIPv6Address(address: String): Boolean {
        return !address.contains(":")
    }

    private fun isInetAddress(address: String): Boolean {
        return !address.startsWith("255") && !address.endsWith("255")
    }

    private fun setVpnInterfaceName(intf: NetworkInterface) {

        if (!intf.isPointToPoint) {
            return
        }

        val enumIpAddr = intf.inetAddresses
        while (enumIpAddr.hasMoreElements()) {
            val inetAddress = enumIpAddr.nextElement()
            val hostAddress = inetAddress.hostAddress

            if (hostAddress != null && hostAddress.contains(STANDARD_VPN_ADDRESS)) {
                vpnInterfaceName = intf.name
                logi("VPN interface name " + vpnInterfaceName)
            }
        }
    }

    fun checkApOn(): Int {

        var result = AccessPointState.STATE_UNKNOWN

        if (apInterfaceNameFromReceiver != null) {
            if (apInterfaceNameFromReceiver!!.isEmpty()) {
                result = AccessPointState.STATE_OFF
            } else {
                result = AccessPointState.STATE_ON
            }
            return result
        }

        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager?
            var method: Method? = null
            if (wifiManager != null) {
                method = wifiManager.javaClass.getDeclaredMethod("isWifiApEnabled")
                method.isAccessible = true
            }

            if (method != null) {
                val on = method.invoke(wifiManager)
                if (on != null && on as Boolean) {
                    result = AccessPointState.STATE_ON
                } else {
                    result = AccessPointState.STATE_OFF
                }
            }
        } catch (e: Exception) {
            logw("InternetSharingChecker checkApOn exception", e)
        }

        return result
    }

    fun setTetherInterfaceName(interfaceNames: List<String>?) {

        if (interfaceNames == null) {
            apInterfaceNameFromReceiver = null
            usbModemInterfaceNameFromReceiver = null
            return
        }

        var found = false
        apLoop@ for (interfaceName in interfaceNames) {
            for (interfaceNameWiFi in STANDARD_WIFI_INTERFACE_NAMES) {
                if (interfaceName.matches(interfaceNameWiFi.replace("+", "\\d+").toRegex())) {
                    apInterfaceNameFromReceiver = interfaceName
                    found = true
                    break@apLoop
                }
            }
        }
        if (!found) {
            isApOn = false
            apInterfaceNameFromReceiver = NO_INTERFACE
        }

        found = false
        usbLoop@ for (interfaceName in interfaceNames) {
            for (interfaceNameUsb in STANDARD_USB_INTERFACE_TETHER_NAMES) {
                if (interfaceName.matches(interfaceNameUsb.replace("+", "\\d+").toRegex())) {
                    usbModemInterfaceNameFromReceiver = interfaceName
                    found = true
                    break@usbLoop
                }
            }
        }
        if (!found) {
            isUsbTetherOn = false
            usbModemInterfaceNameFromReceiver = NO_INTERFACE
        }
    }

    companion object {

        private const val WIFI_AP_ADDRESSES_RANGE_EXTENDED = "192.168.0.0/16"

        private const val NO_INTERFACE = ""

        @Volatile
        private var apInterfaceNameFromReceiver: String? = null
        @Volatile
        private var usbModemInterfaceNameFromReceiver: String? = null

        @JvmStatic
        fun resetTetherInterfaceNames() {
            apInterfaceNameFromReceiver = null
            usbModemInterfaceNameFromReceiver = null
        }
    }

}
