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

package pillar.kuma_saimono.libumdnscrypt.vpn

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.provider.Settings
import android.text.TextUtils
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.LOOPBACK_ADDRESS_IPv6
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.META_ADDRESS
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.META_ADDRESS_IPv6
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPN
import pillar.kuma_saimono.libumdnscrypt.vpn.service.WardenDatapathGate
import java.io.File
import java.net.InetAddress
import java.util.Locale

object VpnUtils {

    @JvmField
    val nonTorList = arrayListOf(
        /*LAN destinations that shouldn't be routed through Tor*/
        "127.0.0.0/8", //Loopback RFC1122
        "10.0.0.0/8", //Private-Use RFC1918
        "172.16.0.0/12", //Private-Use RFC1918
        "192.168.0.0/16", //Private-Use RFC1918
        /*Other IANA reserved blocks (These are not processed by tor)*/
        META_ADDRESS,
        "100.64.0.0/10", //Shared Address Space(CGNAT) RFC6598
        "169.254.0.0/16", //Link local RFC3927
        "192.0.0.0/24", //IETF Protocol Assignments RFC6890
        "192.0.2.0/24", //Documentation(TEST-NET-1) RFC5737
        "192.88.99.0/24", //6to4 Relay Anycast RFC3068
        "198.18.0.0/15", //Benchmarking RFC2544
        "198.51.100.0/24", //Documentation(TEST-NET-2) RFC5737
        "203.0.113.0/24", //Documentation(TEST-NET-3) RFC5737
        "224.0.0.0/4", //Multicast RFC 3171
        "240.0.0.0/4", //Class E address reserved RFC1112
        "255.255.255.255/32" //	Limited Broadcast RFC0919
    )

    @JvmField
    val nonTorIPv6 = arrayListOf(
        /*LAN destinations that shouldn't be routed through Tor*/
        //https://www.rfc-editor.org/rfc/rfc3513.html
        LOOPBACK_ADDRESS_IPv6, //Loopback Address RFC4291
        META_ADDRESS_IPv6, //Unspecified Address RFC4291
        "FEC0::/10", //Site-local unicast, equivalent to 10.0.0.0/8 RFC3513
        "FE80::/10", //Link-local unicast, equivalent to 169.254.0.0/16 RFC4291
        "FC00::/7" //Unique local address RFC4193
    )

    @JvmField
    val multicastIPv6 = arrayListOf(
        //https://www.rfc-editor.org/rfc/rfc3513.html
        //"FF00::/8" Multicast
        "FF01::1", //All Nodes Addresses interface-local
        "FF02::1", // All Nodes Addresses link-local
        "FF01::2", // All Routers Addresses interface-local
        "FF02::2", // All Routers Addresses link-local, SLAAC
        "FF05::2", // All Routers Addresses site-local
        "FF02::1:FF00:0/104", //Neighbor discovery
        //https://source.android.com/docs/core/ota/modular-system/dns-resolver
        "FF02::FB", //mDNS .local resolution A12
        //https://datatracker.ietf.org/doc/html/rfc8415
        "FF02::1:2", //All_DHCP_Relay_Agents_and_Servers
        "FF05::1:3", //All_DHCP_Servers
        "FF02::16" // MLD rfc2710
    )

    @JvmField
    val dnsRebindList = arrayListOf(
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10"
    )

    // STAGE 2 (2026-07-04): the native surface (jni_getprop / is_numeric_address /
    // jni_set_resolver_native / jni_set_warden_native) lived in libinvizible.so, which is DELETED.
    // The pure-Rust tunnel::TunnelController owns the datapath; these are replaced by pure-Java
    // (isNumericAddress) or made obsolete (the resolver/warden arms are no-ops — the Rust loop
    // always resolves + verdicts inline). No native, no System.loadLibrary("invizible").

    /**
     * Did the LAST resolver-seam push actually reach the C layer? `false` until the first push
     * lands (or after a failed push) — the honest ground truth the armed-state claim must read
     * (E-FIX round-1: never report `nativeArmed=true` off the pref alone while the C flag is 0).
     */
    @Volatile
    private var resolverPushLanded = false

    /** Did the LAST Warden-seam push actually reach the C layer? Mirror of [resolverPushLanded]. */
    @Volatile
    private var wardenPushLanded = false

    @JvmStatic
    fun isResolverNativePushLanded(): Boolean {
        return resolverPushLanded
    }

    @JvmStatic
    fun isWardenNativePushLanded(): Boolean {
        return wardenPushLanded
    }

    /**
     * Crash-safe arm/disarm of the native Rust resolver datapath seam. Mirrors the no-op-on-failure posture
     * of the rest of the native facade: a missing/unloaded `libinvizible.so`, an
     * `UnsatisfiedLinkError`, or any native fault is swallowed — the C flag simply stays 0 (disarmed)
     * and the datapath remains the byte-identical dnscrypt path. Never throws. DEFAULT false ⇒ the C flag
     * stays 0 ⇒ no behavior change.
     *
     * E-FIX round-1: ensure-loads `libinvizible.so` first (see `ensureInviZibleLoaded()`) so a
     * cold-start arm lands instead of silently dying on class-load order, and REPORTS whether the push
     * actually reached the C layer so callers can log/claim the armed state honestly.
     *
     * @return `true` iff the JNI write landed (the C flag now holds `enabled`).
     */
    @JvmStatic
    fun setResolverNativeEnabled(enabled: Boolean): Boolean {
        // STAGE 2 (2026-07-04): the legacy C flag g_resolver_native_enabled lived in libinvizible.so,
        // which is DELETED — the pure-Rust tunnel::TunnelController loop ALWAYS resolves every :53
        // packet via torta_resolve (there is no C gate to arm). This arm is therefore a no-op that
        // always "lands": the Rust datapath is inherently the resolver. Kept as a stable API surface
        // for ModulesStarterHelper; never touches native (no UnsatisfiedLinkError).
        resolverPushLanded = true
        return true
    }

    /**
     * Crash-safe arm/disarm of the Rust Warden datapath enforcement. A6: the arm is REAL again — it
     * lands in `libtorta_core.so` via [WardenDatapathGate.setEnforced], flipping
     * the canonical-instance enforce bit the tunnel loop consults on every non-DNS packet
     * (`tunnel/warden.rs ask_canonical` — the `warden_set_datapath_enforced` UniFFI export).
     * Called with the live `WARDEN_NATIVE_ENABLED` pref on every DNSCrypt start
     * (`ModulesStarterHelper.applyWardenNativeFromPref`), so the bit is re-asserted after every
     * process rebirth, and immediately by the SLINT ARM switch (`TortaPillarBridge.setWardenArmed`).
     * Never throws (the gate catches everything); an unreachable .so leaves the bit 0 — the tunnel
     * falls through to the flat C-ABI consult, byte-identical to the pre-A6 datapath.
     *
     * @return `true` iff the push landed (the live enforce bit now reads `enabled`).
     */
    @JvmStatic
    fun setWardenNativeEnabled(enabled: Boolean): Boolean {
        // STAGE 2 (2026-07-04) retired the legacy libinvizible.so C flag and left this a no-op;
        // A6 (2026-07-19) re-points it at the canonical WardenObject enforce bit.
        wardenPushLanded = WardenDatapathGate.setEnforced(enabled) == enabled
        return wardenPushLanded
    }

    @JvmStatic
    fun getSelfVersionName(context: Context): String? {
        return try {
            val pInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            pInfo.versionName
        } catch (ex: PackageManager.NameNotFoundException) {
            ex.toString()
        }
    }

    @Suppress("DEPRECATION")
    @JvmStatic
    fun getSelfVersionCode(context: Context): Int {
        return try {
            val pInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            pInfo.versionCode
        } catch (ex: PackageManager.NameNotFoundException) {
            -1
        }
    }

    @JvmStatic
    fun getDefaultDNS(context: Context): List<String> {
        val listDns = ArrayList<String>()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager?
            var an: Network? = null
            if (cm != null) {
                an = cm.activeNetwork
            }
            if (an != null) {
                val lp = cm!!.getLinkProperties(an)
                if (lp != null) {
                    val dns = lp.dnsServers
                    for (d in dns) {
                        val host = d.hostAddress
                        if (host != null) {
                            logi("DNS from LP: $host")
                            listDns.add(host.split("%")[0])
                        }
                    }
                }
            }
        }
        // STAGE 2 (2026-07-04): the pre-LOLLIPOP `jni_getprop("net.dns")` fallback lived in the
        // DELETED libinvizible.so. minSdk is well past LOLLIPOP, so the LinkProperties path above is
        // always taken; the native getprop branch is removed (it would UnsatisfiedLinkError).

        return listDns
    }

    internal fun isNumericAddress(ip: String?): Boolean {
        // STAGE 2: was `is_numeric_address` in the deleted libinvizible.so — replaced with the pure
        // Java/Android numeric-literal check (no DNS resolution, matches the native's intent).
        if (ip == null || ip.isEmpty()) {
            return false
        }
        // Patterns.IP_ADDRESS is deprecated (API 31): it is a REGEX, and the platform's own note
        // is that it matches strings no address parser accepts. InetAddresses.isNumericAddress
        // (API 29) asks the actual parser instead, which is both stricter and the right question
        // for a function named isNumericAddress.
        //
        // The OR structure is preserved on purpose. isNumericAddress covers IPv4 AND IPv6, so the
        // modern branch could stand alone -- but the legacy branch below 29 still needs the
        // hand-rolled IPv6 check, and keeping one shape for both makes the two paths visibly answer
        // the same question. Below 29 the behaviour is exactly what it was before this change.
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            android.net.InetAddresses.isNumericAddress(ip)
        } else {
            @Suppress("DEPRECATION")
            android.util.Patterns.IP_ADDRESS.matcher(ip).matches() ||
                    ip.indexOf(':') >= 0 && isNumericIpv6(ip)
        }
    }

    private fun isNumericIpv6(ip: String): Boolean {
        return try {
            // A literal IPv6 parses without a network lookup when it contains only hex/':'/'.'/'%'.
            for (i in 0 until ip.length) {
                val c = ip[i]
                val ok = (c in '0'..'9') || (c in 'a'..'f') || (c in 'A'..'F') ||
                        c == ':' || c == '.' || c == '%'
                if (!ok) {
                    return false
                }
            }
            InetAddress.getByName(ip.split("%")[0])  // parses a literal; a bare hostname would need DNS
            true
        } catch (t: Throwable) {
            false
        }
    }

    internal fun isSystem(packageName: String, context: Context): Boolean {
        return try {
            val pm = context.packageManager
            val info = pm.getPackageInfo(packageName, 0)
            (info.applicationInfo!!.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
        } catch (ignore: PackageManager.NameNotFoundException) {
            false
        }
    }

    internal fun hasInternet(packageName: String, context: Context): Boolean {
        val pm = context.packageManager
        return pm.checkPermission("android.permission.INTERNET", packageName) == PackageManager.PERMISSION_GRANTED
    }

    internal fun isEnabled(info: PackageInfo, context: Context): Boolean {
        val setting: Int
        try {
            val pm = context.packageManager
            setting = pm.getApplicationEnabledSetting(info.packageName)
        } catch (ex: IllegalArgumentException) {
            logw("VpnUtils isEnabled", ex)
            return info.applicationInfo!!.enabled
        }
        return if (setting == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT)
            info.applicationInfo!!.enabled
        else
            setting == PackageManager.COMPONENT_ENABLED_STATE_ENABLED
    }

    @JvmStatic
    fun canFilterAsynchronous(serviceVPN: ServiceVPN?) {

        App.instance.daggerComponent
            .getCoroutineExecutor().submit("VpnUtils canFilterAsynchronous") {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && serviceVPN != null) {
                    serviceVPN.canFilter = true
                    return@submit
                }

                // https://android-review.googlesource.com/#/c/206710/1/untrusted_app.te
                val tcp = File("/proc/net/tcp")
                val tcp6 = File("/proc/net/tcp6")

                try {
                    if (tcp.exists() && tcp.canRead() && serviceVPN != null)
                        serviceVPN.canFilter = true
                    return@submit
                } catch (ignored: SecurityException) {
                }

                try {
                    if (tcp6.exists() && tcp6.canRead() && serviceVPN != null) {
                        serviceVPN.canFilter = true
                    }
                } catch (ignored: SecurityException) {
                    if (serviceVPN != null) {
                        serviceVPN.canFilter = false
                    }
                }
            }
    }

    @JvmStatic
    fun canFilter(): Boolean {
        // https://android-review.googlesource.com/#/c/206710/1/untrusted_app.te
        val tcp = File("/proc/net/tcp")
        val tcp6 = File("/proc/net/tcp6")
        try {
            if (tcp.exists() && tcp.canRead())
                return true
        } catch (ignored: SecurityException) {
        }
        return try {
            tcp6.exists() && tcp6.canRead()
        } catch (ignored: SecurityException) {
            false
        }
    }

    const val PRIVATE_DNS_MODE_OFF = 1
    const val PRIVATE_DNS_MODE_OPPORTUNISTIC = 2
    const val PRIVATE_DNS_MODE_PROVIDER_HOSTNAME = 3
    const val PRIVATE_DNS_DEFAULT_MODE = "private_dns_default_mode"
    const val PRIVATE_DNS_MODE = "private_dns_mode"

    @JvmStatic
    fun getPrivateDnsMode(context: Context): Int {
        try {
            val cr = context.contentResolver
            var mode = Settings.Global.getString(cr, PRIVATE_DNS_MODE)
            if (TextUtils.isEmpty(mode)) mode = Settings.Global.getString(cr, PRIVATE_DNS_DEFAULT_MODE)
            return getPrivateDnsModeAsInt(mode)
        } catch (e: Exception) {
            loge("VpnUtils getPrivateDnsMode", e)
        }
        return PRIVATE_DNS_MODE_OFF
    }

    private fun getPrivateDnsModeAsInt(mode: String?): Int {
        if (TextUtils.isEmpty(mode))
            return PRIVATE_DNS_MODE_OFF
        return when (mode) {
            "hostname" -> PRIVATE_DNS_MODE_PROVIDER_HOSTNAME
            "opportunistic" -> PRIVATE_DNS_MODE_OPPORTUNISTIC
            else -> PRIVATE_DNS_MODE_OFF
        }
    }

    @JvmStatic
    fun isIpInSubnetOld(ip: String, network: String): Boolean {
        var result = false

        try {
            var net = network
            var prefix = 0
            if (network.contains("/")) {
                net = network.substring(0, network.indexOf("/"))
                prefix = network.substring(network.indexOf("/") + 1).toInt()
            }

            val ipBin = InetAddress.getByName(ip).address
            val netBin = InetAddress.getByName(net).address
            if (ipBin.size != netBin.size) return false
            var p = prefix
            var i = 0
            while (p >= 8) {
                if (ipBin[i] != netBin[i]) return false
                ++i
                p -= 8
            }
            val m = (65280 shr p) and 255
            result = (ipBin[i].toInt() and m) == (netBin[i].toInt() and m)
        } catch (e: Exception) {
            loge("VpnUtils isIpInSubnet", e)
        }

        return result
    }

    @JvmStatic
    fun isIpInSubnet(ip: String, network: String): Boolean {
        try {
            var net = network
            var prefix = -1
            if (network.contains("/")) {
                net = network.substring(0, network.indexOf("/"))
                prefix = network.substring(network.indexOf("/") + 1).toInt()
            }

            if (prefix < 0) {
                return InetAddress.getByName(ip) == InetAddress.getByName(net)
            }

            val ipBin = InetAddress.getByName(ip).address
            val netBin = InetAddress.getByName(net).address
            if (netBin.size * 8 < prefix) {
                loge(
                    String.format(
                        Locale.ROOT,
                        "IP address %s is too short for bitmask of length %d",
                        network,
                        prefix
                    )
                )
                return false
            }

            if (ipBin.size != netBin.size) return false

            val nMaskFullBytes = prefix / 8
            val finalByte = (0xFF00 shr (prefix and 0x07)).toByte()

            for (i in 0 until nMaskFullBytes) {
                if (ipBin[i] != netBin[i]) {
                    return false
                }
            }

            if (finalByte.toInt() != 0) {
                return (ipBin[nMaskFullBytes].toInt() and finalByte.toInt()) == (netBin[nMaskFullBytes].toInt() and finalByte.toInt())
            }

            return true

        } catch (e: Exception) {
            loge("VpnUtils isIpInSubnet", e)
        }

        return false
    }

    @JvmStatic
    fun isIpInLanRange(destAddress: String): Boolean {

        if (destAddress.isEmpty()) {
            return false
        }

        for (address in nonTorList) {
            if (isIpInSubnet(destAddress, address)) {
                return true
            }
        }
        for (address in nonTorIPv6) {
            if (isIpInSubnet(destAddress, address)) {
                return true
            }
        }

        for (address in multicastIPv6) {
            if (isIpInSubnet(destAddress, address)) {
                return true
            }
        }
        return false
    }
}
