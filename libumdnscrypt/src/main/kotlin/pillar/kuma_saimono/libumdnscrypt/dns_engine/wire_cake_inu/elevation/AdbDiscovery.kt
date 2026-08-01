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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

/**
 * The pure classification + self-host guard for the Android 11+ wireless-debug mDNS discovery.
 *
 * P6's [WireCakeInuManager] discovered ONLY `_adb-tls-pairing._tcp` and then (the confirmed bug)
 * fed that PAIRING port straight into `connect()` — but pairing and connecting are two DIFFERENT
 * mDNS services on two DIFFERENT, independently-rotating ports:
 *   - `_adb-tls-pairing._tcp`  — advertised only while the "Pair device with code" dialog is open.
 *   - `_adb-tls-connect._tcp`  — the long-lived connect endpoint; its port rotates on reboot/Wi-Fi.
 *
 * So we never persist a port (it rotates); we re-discover each endpoint on its own service and match
 * the connect port at use time. This object holds the pure decision logic (string classification +
 * the loopback/self-host security assertion) so it is unit-testable on metal — the Android
 * [android.net.nsd.NsdManager] wiring stays in the manager and merely calls these.
 */
object AdbDiscovery {

    /** The mDNS service advertised while the pairing dialog (6-digit code) is open. */
    const val SERVICE_PAIRING = "_adb-tls-pairing._tcp"

    /** The mDNS service for the long-lived connect endpoint (port rotates — never persist it). */
    const val SERVICE_CONNECT = "_adb-tls-connect._tcp"

    /** Which kind of wireless-ADB endpoint an mDNS service-type string denotes. */
    enum class Endpoint { PAIRING, CONNECT, UNKNOWN }

    /**
     * Classify a (possibly noisy, possibly trailing-dot, possibly mixed-case) mDNS service-type
     * string. NSD on different OEMs reports e.g. `_adb-tls-pairing._tcp.` or `_adb-tls-pairing._tcp.local.`
     * so we match on the stable substring, not on exact equality.
     */
    fun classify(serviceType: String?): Endpoint {
        if (serviceType.isNullOrBlank()) return Endpoint.UNKNOWN
        val s = serviceType.lowercase()
        return when {
            s.contains("adb-tls-pairing") -> Endpoint.PAIRING
            s.contains("adb-tls-connect") -> Endpoint.CONNECT
            else -> Endpoint.UNKNOWN
        }
    }

    /**
     * The crown-jewel security gate (plan §5.1): before we ever open a privileged shell we ASSERT the
     * resolved host is this device's loopback / a self address. P6 connected to whatever NSD resolved
     * — on a hostile LAN a rogue host could advertise a fake `_adb-tls-pairing` and harvest the code.
     * P11 refuses any non-self host. Pure string check over the resolved [hostAddress].
     *
     * Accepts: IPv4 loopback 127.0.0.0/8, IPv6 loopback ::1 (and its mapped/zone-suffixed forms),
     * and the literal `localhost`. Rejects everything else (LAN/public addresses).
     */
    fun isSelfHost(hostAddress: String?): Boolean {
        if (hostAddress.isNullOrBlank()) return false
        // Strip an IPv6 zone id (e.g. fe80::1%wlan0) and surrounding brackets before classifying.
        val raw = hostAddress.trim().removePrefix("[").removeSuffix("]")
        val host = raw.substringBefore('%').lowercase()

        if (host == "localhost") return true

        // IPv6 loopback, incl. the IPv4-mapped loopback ::ffff:127.0.0.1 and the all-zeros-then-1 form.
        if (host == "::1" || host == "0:0:0:0:0:0:0:1") return true
        if (host.startsWith("::ffff:")) {
            return isIpv4Loopback(host.substringAfterLast(':'))
        }

        return isIpv4Loopback(host)
    }

    /** 127.0.0.0/8 — the whole loopback block, validated octet-by-octet (no partial/garbage match). */
    private fun isIpv4Loopback(ip: String): Boolean {
        val parts = ip.split(".")
        if (parts.size != 4) return false
        val octets = parts.map { it.toIntOrNull() ?: return false }
        if (octets.any { it < 0 || it > 255 }) return false
        return octets[0] == 127
    }

    /**
     * A discovered endpoint: where it was found and on which (rotating, never-persisted) port.
     * [self] caches the loopback assertion so the caller cannot connect without having checked.
     */
    data class Resolved(
        val endpoint: Endpoint,
        val host: String,
        val port: Int,
    ) {
        val self: Boolean get() = isSelfHost(host)
        val valid: Boolean get() = endpoint != Endpoint.UNKNOWN && port in 1..65535 && self
    }
}
