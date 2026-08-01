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

package pillar.kuma_saimono.libumdnscrypt.domain.connection_records

import android.content.Context
import android.content.SharedPreferences
import android.text.format.DateUtils
import androidx.annotation.ColorRes
import androidx.core.content.ContextCompat
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionLogEntry
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionProtocol
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.DnsLogEntry
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.PacketLogEntry
import pillar.kuma_saimono.libumdnscrypt.iptables.Tethering
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.utils.Constants
import pillar.kuma_saimono.libumdnscrypt.utils.apps.InstalledAppNamesStorage
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import java.text.SimpleDateFormat
import java.util.*
import javax.inject.Inject
import javax.inject.Named

private const val MAX_LINES_IN_LOG = 200

class ConnectionRecordsParser @Inject constructor(
    private val applicationContext: Context,
    private val installedAppNamesStorage: dagger.Lazy<InstalledAppNamesStorage>,
    @Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    defaultPreferences: SharedPreferences
) {

    private val modulesStatus = ModulesStatus.getInstance()
    private val localEthernetDeviceAddress =
        defaultPreferences.getString(
            "pref_common_local_eth_device_addr",
            Constants.STANDARD_ADDRESS_LOCAL_PC
        ) ?: Constants.STANDARD_ADDRESS_LOCAL_PC

    private val liveLogEntryBlocked by lazy {
        applicationContext.getHexFromColors(R.color.liveLogEntryBlocked)
    }
    private val liveLogEntryNoDns by lazy {
        applicationContext.getHexFromColors(R.color.liveLogEntryNoDns)
    }
    private val liveLogEntryDnsUnused by lazy {
        applicationContext.getHexFromColors(R.color.liveLogEntryDnsUnused)
    }
    private val liveLogEntryDnsUsed by lazy {
        applicationContext.getHexFromColors(R.color.liveLogEntryDnsUsed)
    }

    private val dateFormatToday by lazy {
        SimpleDateFormat("HH:mm:ss", Locale.ROOT)
    }
    private val dateFormat by lazy {
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT)
    }

    fun formatLines(connectionRecords: List<ConnectionLogEntry>): String {

        val fixTTL =
            modulesStatus.isFixTTL && modulesStatus.mode == OperationMode.ROOT_MODE && !modulesStatus.isUseModulesWithRoot

        val apAddresses = if (Tethering.wifiAPAddressesRange.lastIndexOf(".") > 0) {
            Tethering.wifiAPAddressesRange.substring(
                0, Tethering.wifiAPAddressesRange.lastIndexOf(".")
            )
        } else {
            Constants.STANDARD_AP_INTERFACE_RANGE
        }

        val usbAddresses = if (Tethering.usbModemAddressesRange.lastIndexOf(".") > 0) {
            Tethering.usbModemAddressesRange.substring(
                0, Tethering.usbModemAddressesRange.lastIndexOf(".")
            )
        } else {
            Constants.STANDARD_USB_MODEM_INTERFACE_RANGE
        }

        val lines = StringBuilder()

        lines.append("<br />")

        var start = 0
        val logSize: Int = connectionRecords.size
        if (logSize > MAX_LINES_IN_LOG) {
            start = logSize - MAX_LINES_IN_LOG
        }

        for (i in start until logSize) {

            val record = connectionRecords[i]

            if (record is DnsLogEntry && !record.visible) {
                continue
            }

            if (record.blocked) {
                lines.append("<font color=$liveLogEntryBlocked>")
            } else if (record is PacketLogEntry && record.dnsLogEntry == null) {
                lines.append("<font color=$liveLogEntryNoDns>")
            } else if (record is DnsLogEntry) {
                lines.append("<font color=$liveLogEntryDnsUnused>")
            } else if (record is PacketLogEntry) {
                lines.append("<font color=$liveLogEntryDnsUsed>")
            }

            lines.append("[")
            if (DateUtils.isToday(record.time)) {
                lines.append(dateFormatToday.format(record.time))
            } else {
                lines.append(dateFormat.format(record.time))
            }
            lines.append("] ")

            if (record is PacketLogEntry) {
                var appName = installedAppNamesStorage.get().getAppNameByUid(record.uid) ?: ""
                if (appName.isEmpty() || record.uid == 1000) {
                    appName =
                        applicationContext.packageManager.getNameForUid(record.uid)
                            ?: ("Undefined UID" + record.uid)
                }

                val protocol = ConnectionProtocol.toString(record.protocol).let {
                    " ($it)"
                }

                if (Tethering.apIsOn && fixTTL && record.saddr.contains(apAddresses)) {
                    lines.append("<b>").append("WiFi").append("</b>")
                        .append(protocol).append(" → ")
                } else if (Tethering.usbTetherOn && fixTTL && record.saddr.contains(usbAddresses)) {
                    lines.append("<b>").append("USB").append("</b>")
                        .append(protocol).append(" → ")
                } else if (Tethering.ethernetOn && fixTTL && record.saddr.contains(
                        localEthernetDeviceAddress
                    )
                ) {
                    lines.append("<b>").append("LAN").append("</b>")
                        .append(protocol).append(" → ")
                } else if (appName.isNotEmpty()) {
                    lines.append("<b>").append(appName).append("</b>")
                        .append(protocol).append(" → ")
                } else {
                    lines.append("<b>").append("Unknown UID").append(record.uid).append("</b>")
                        .append(protocol).append(" → ")
                }

                record.dnsLogEntry?.let {
                    lines.append(it.domainsChain.joinToString(" → "))
                        .append(" → ")
                        .append(record.daddr)
                    if (record.dport != 0) {
                        lines.append("<i>:</i>${record.dport}")
                    }
                } ?: record.reverseDns?.let {
                    lines.append(it).append(" → ").append(record.daddr)
                    if (record.dport != 0) {
                        lines.append("<i>:</i>${record.dport}")
                    }
                } ?: run {
                    lines.append(record.daddr)
                    if (record.dport != 0) {
                        lines.append("<i>:</i>${record.dport}")
                    }
                }
            } else if (record is DnsLogEntry) {
                if (record.domainsChain.isNotEmpty()) {
                    lines.append(record.domainsChain.joinToString(" → "))
                }
                if (record.blocked && record.blockedByIpv6) {
                    lines.append(" ipv6")
                }
            }

            lines.append("</font>")

            if (i < connectionRecords.size - 1) {
                lines.append("<br />")
            }
        }

        return lines.toString()
    }

    private fun Context.getHexFromColors(
        @ColorRes colorRes: Int
    ): String = String.format("#%06X", 0xFFFFFF and ContextCompat.getColor(this, colorRes))
}
