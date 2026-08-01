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

package pillar.kuma_saimono.libumdnscrypt.vpn.service

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.IpPrefix
import android.os.Build
import android.text.TextUtils
import dagger.Lazy
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.dns_resolver.DnsInteractor
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.utils.Constants
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.NetworkChecker
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.vpn.IPUtil
import pillar.kuma_saimono.libumdnscrypt.vpn.Rule
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils
import pillar.kuma_saimono.libumdnscrypt.vpn.tunnel.TunnelController
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.Arrays
import java.util.Collections
import java.util.concurrent.ConcurrentSkipListSet
import javax.inject.Inject
import javax.inject.Named

class VpnBuilder @Inject constructor(
    private val context: Context,
    private val dnsInteractor: Lazy<DnsInteractor>,
    @Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: Lazy<SharedPreferences>,
    private val preferenceRepository: Lazy<PreferenceRepository>
) {

    private val modulesStatus = ModulesStatus.getInstance()

    @SuppressLint("UnspecifiedImmutableFlag")
    fun getBuilder(vpn: ServiceVPN, listAllowed: List<String>, listRule: List<Rule>): ServiceVPN.BuilderVPN {
        val prefs = defaultPreferences.get()
        val lan = prefs.getBoolean(TortaeKeys.BYPASS_LAN, true)
        val fixTTL = modulesStatus.isFixTTL && (modulesStatus.mode == OperationMode.ROOT_MODE)
                && !modulesStatus.isUseModulesWithRoot

        // Build VPN service
        val builder = vpn.BuilderVPN()
        builder.setSession(uniffi.torta_core.tortaText("app_name"))

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        // VPN address
        val vpn4 = prefs.getString("vpn4", "10.1.10.1")
        logi("VPN Using VPN4=" + vpn4)
        builder.addAddress(vpn4!!, 32)

        val vpn6 = prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1")
        logi("VPN Using VPN6=" + vpn6)
        builder.addAddress(vpn6!!, 128)

        // DNS address
        for (dns in getDns()) {
            logi("VPN Using DNS=" + dns)
            builder.addDnsServer(dns)
        }

        // ★ Field bug #5 — the DORMANT-forwarder blackhole. The Rust sync DNS-only loop answers
        // :53 and DROPS every other captured packet (tunnel/mod.rs handle_packet, Stage-2-min by
        // design). Claiming 0.0.0.0/0 in that state blackholes ALL non-DNS traffic (AVD-proven:
        // nc 1.1.1.1:80 times out while DNS resolves). Route posture therefore follows the
        // datapath that will actually carry the packets:
        //  - forwarder ARMED (same pref TunnelController samples), or fixTTL (root-mode TTL
        //    repair) — full capture: those consumers need every flow inside the tun;
        //  - otherwise — capture ONLY the virtual DNS /32: system DNS stays shielded, the rest
        //    rides the real network instead of dying in the tun. Apps with hardcoded DNS IPs
        //    bypass the shield in this mode (full-capture :53 interception needs the forwarder).
        // The Warden does NOT gate this: FIREWALL_ENABLED is the default-TRUE alias of
        // WARDEN_NATIVE_ENABLED (FORK-3), and in the dormant-forwarder sync loop the Warden
        // consult is telemetry-only — every non-DNS packet drops REGARDLESS of verdict, so
        // capturing "for the firewall" there enforces nothing and blackholes everything (the
        // very bug). Warden ENFORCEMENT rides the armed forwarder, which full-captures anyway.
        // The pref is sampled at establish time — same VPN re-establish flips routes AND loop.
        // Caveat: on a .so built WITHOUT the netstack feature an armed pref still full-captures
        // into the sync loop (legacy blackhole) — unchanged from today.
        // ON by default — must agree with TunnelController/TortaPillarBridge or the route plan and the
        // tunnel disagree about whether the forwarder is armed.
        val netstackArmed = prefs.getBoolean(TunnelController.NETSTACK_FORWARDER_PREF, true)
        if (netstackArmed || fixTTL) {
            logi("VPN routes: full capture (forwarder armed=" + netstackArmed
                    + " fixTTL=" + fixTTL + ")")
            addIPv4Routes(builder, lan, fixTTL)
            addIPv6Routes(builder, lan)
        } else {
            logi("VPN routes: DNS-only capture (forwarder DORMANT)")
            addDnsOnlyRoutes(builder)
        }

        // MTU — was `vpn.jni_get_mtu()` (legacy C export, deleted task 4C); now the Kotlin constant
        // shared with the Rust tun loop + ServiceVPN.startNative.
        val mtu = VPN_MTU
        logi("VPN MTU=" + mtu)
        builder.setMtu(mtu)

        // Add list of allowed applications
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            manageAppsTunneling(builder, listRule, fixTTL)
        }

        builder.setConfigureIntent(getConfigureIntent())

        return builder
    }

    /**
     * ★ Field bug #5 — the DORMANT-forwarder route posture: capture ONLY the virtual DNS
     * ({@link #VPN_VIRTUAL_DNS_IP}/32) so the sync DNS-only loop answers what it can carry and
     * everything else keeps flowing on the real network. Block-IPv6 keeps its meaning here —
     * that blackhole IS the feature, so {@code ::/0} is still claimed when it is on (and the
     * engine runs), exactly the {@code addIPv6Routes} else-branch semantics.
     */
    private fun addDnsOnlyRoutes(builder: ServiceVPN.BuilderVPN) {
        builder.addRoute(VPN_VIRTUAL_DNS_IP, 32)

        // ★ #65 CENTAURI — the cloak sentinel MUST ride the tun, even in this dormant posture.
        //
        // The DNS-plane cloak answers a watched CDN host with [CENTAURI_CLOAK_SENTINEL_IP] so the
        // request lands on the in-app mirror and is served from the offline catalog with ZERO egress.
        // That only works if the sentinel is actually ROUTED INTO THE TUN. Routing only the virtual
        // DNS /32 here left the sentinel — the very next address — unrouted, so a cloaked flow left
        // on the real network and died with ERR_CONNECTION_REFUSED: the cloak pointed somewhere the
        // packets could never arrive, and Centauri could never serve a single asset.
        //
        // Unconditional on purpose, no cloak-state read: this is the VPN's OWN /32 out of its own
        // subnet, so the route is inert unless the cloak is armed (nothing resolves to the sentinel
        // otherwise, so no packet is ever generated). Gating it on the cloak instead would introduce
        // an ordering hazard — the VPN establishes before Centauri arms, and re-arming does not
        // re-establish the tun, which is exactly how this stayed broken.
        builder.addRoute(CENTAURI_CLOAK_SENTINEL_IP, 32)

        // The v6 twin, unconditional for the SAME reason as the v4 line above. The cloak answers AAAA
        // with CENTAURI_CLOAK_SENTINEL_IP6, and without this route that packet leaves the tun for a
        // ULA nothing claims. Happy Eyeballs reaches for the AAAA first, so a missing route here does
        // not degrade the v6 leg — it kills the request outright with ERR_CONNECTION_CLOSED, on
        // exactly the cloaked CDN hosts the seam exists to serve, while every uncloaked host looks
        // healthy. Inert unless the cloak is armed: nothing resolves to the sentinel otherwise.
        builder.addRoute(CENTAURI_CLOAK_SENTINEL_IP6, 128)

        val blockIPv6DnsCrypt = defaultPreferences.get().getBoolean(TortaeKeys.DNSCRYPT_BLOCK_IPv6, false)
        if (blockIPv6DnsCrypt && modulesStatus.dnsCryptState != ModuleState.STOPPED) {
            builder.addRoute("::", 0)
        }
    }

    private fun addIPv4Routes(builder: ServiceVPN.BuilderVPN, lan: Boolean, fixTTL: Boolean) {
        val firewallEnabled = preferenceRepository.get().getBoolPreference(TortaeKeys.FIREWALL_ENABLED)
        val apIsOn = preferenceRepository.get().getBoolPreference(TortaeKeys.WIFI_ACCESS_POINT_IS_ON)
        val modemIsOn = preferenceRepository.get().getBoolPreference(TortaeKeys.USB_MODEM_IS_ON)
        val compatibilityMode: Boolean
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.LOLLIPOP) {
            compatibilityMode = true
        } else {
            compatibilityMode = defaultPreferences.get().getBoolean(TortaeKeys.COMPATIBILITY_MODE, false)
        }
        val listExclude = ArrayList<IPUtil.CIDR>()
        if (!firewallEnabled || compatibilityMode || fixTTL) {
            listExclude.add(IPUtil.CIDR("127.0.0.0", 8)) // localhost
        }

        if ((apIsOn || modemIsOn) && !fixTTL) {
            // USB tethering 192.168.42.x
            // Wi-Fi tethering 192.168.43.x
            listExclude.add(IPUtil.CIDR("192.168.42.0", 23))
            // Bluetooth tethering 192.168.44.x
            listExclude.add(IPUtil.CIDR("192.168.44.0", 24))
            // Wi-Fi direct 192.168.49.x
            listExclude.add(IPUtil.CIDR("192.168.49.0", 24))
        }

        if (lan) {
            listExclude.add(IPUtil.CIDR("224.0.0.0", 4)) // Multicast
        }

        Collections.sort(listExclude)

        if (!listExclude.isEmpty()) {
            try {
                var start = InetAddress.getByName(Constants.META_ADDRESS)
                for (exclude in listExclude) {
                    for (include in IPUtil.toCIDR(start, IPUtil.minus1(exclude.getStart())!!))
                        try {
                            builder.addRoute(include.address!!, include.prefix)
                        } catch (ex: Throwable) {
                            loge("VPNBuilder addIPv4Routes", ex, true)
                        }
                    start = IPUtil.plus1(exclude.getEnd())
                }
                val end = (if (lan) "255.255.255.254" else "255.255.255.255")
                for (include in IPUtil.toCIDR(if (lan) "240.0.0.0" else "224.0.0.0", end))
                    try {
                        builder.addRoute(include.address!!, include.prefix)
                    } catch (ex: Throwable) {
                        loge("VPNBuilder addIPv4Routes", ex, true)
                    }
            } catch (ex: UnknownHostException) {
                loge("VPNBuilder addIPv4Routes", ex, true)
            }
        } else {
            builder.addRoute(Constants.META_ADDRESS, 0)
        }
    }

    private fun addIPv6Routes(builder: ServiceVPN.BuilderVPN, lan: Boolean) {
        val prefs = defaultPreferences.get()
        val blockIPv6DnsCrypt = prefs.getBoolean(TortaeKeys.DNSCRYPT_BLOCK_IPv6, false)
        var captivePortal = false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            captivePortal = NetworkChecker.isCaptivePortalDetected(context)
        }

        if (lan && !(blockIPv6DnsCrypt && modulesStatus.dnsCryptState != ModuleState.STOPPED)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && captivePortal) {
                try {
                    builder.addRoute("::", 0)
                    for (line in VpnUtils.multicastIPv6) {
                        val address: String
                        val prefix: Int
                        if (line.contains("/")) {
                            address = line.substring(0, line.indexOf("/"))
                            prefix = Integer.parseInt(line.substring(line.indexOf("/") + 1))
                        } else {
                            address = line
                            prefix = 128
                        }
                        try {
                            builder.excludeRoute(IpPrefix(InetAddress.getByName(address), prefix))
                        } catch (e: Exception) {
                            loge("VPNBuilder addIPv6Routes", e)
                        }
                    }
                } catch (e: Exception) {
                    loge("VPNBuilder addIPv6Routes", e)
                }
            } else {
                //https://datatracker.ietf.org/doc/html/rfc4291
                //Exclude "ff00::/8" Multicast
                val multicastExcluded = ArrayList(Arrays.asList(
                    "::/1",
                    "8000::/2",
                    "c000::/3",
                    "e000::/4",
                    "f000::/5",
                    "f800::/6",
                    "fc00::/7",
                    "fe00::/8"
                ))
                for (route in multicastExcluded) {
                    val address = route.split("/")
                    try {
                        builder.addRoute(address[0], Integer.parseInt(address[1]))
                    } catch (e: Exception) {
                        loge("VPNBuilder addIPv6Routes", e)
                    }
                }
            }
        } else {
            builder.addRoute("::", 0)
        }
    }

    private fun manageAppsTunneling(builder: ServiceVPN.BuilderVPN, listRule: List<Rule>, fixTTL: Boolean) {
        val prefs = defaultPreferences.get()
        val setVpnBypassApps = preferenceRepository.get().getStringSetPreference(TortaeKeys.APPS_BYPASS_VPN)
        var useProxy = prefs.getBoolean(TortaeKeys.USE_PROXY, false)
        if (useProxy && (prefs.getString(TortaeKeys.PROXY_ADDRESS, Constants.LOOPBACK_ADDRESS)!!.isEmpty()
                || prefs.getString(TortaeKeys.PROXY_PORT, Constants.DEFAULT_PROXY_PORT)!!.isEmpty())) {
            useProxy = false
        }
        try {
            builder.addDisallowedApplication(context.packageName)
            for (pack in setVpnBypassApps) {
                builder.addDisallowedApplication(pack)
                logi("VPN Not routing " + pack)
            }
        } catch (ex: PackageManager.NameNotFoundException) {
            loge("VPNBuilder", ex, true)
        }

        if (fixTTL) {
            builder.setFixTTL(true)

            if (!useProxy) {
                for (rule in listRule) {
                    try {
                        //logi("VPN Not routing " + rule.packageName);
                        builder.addDisallowedApplication(rule.packageName)
                    } catch (ex: PackageManager.NameNotFoundException) {
                        loge("VPNBuilder", ex, true)
                    }
                }
            } else {
                try {
                    builder.addDisallowedApplication(context.packageName)
                } catch (ex: PackageManager.NameNotFoundException) {
                    loge("VPNBuilder", ex, true)
                }
            }

        }
    }

    /**
     * Sovereign DNS rewire (STAGE 2 pure-Rust tunnel, 2026-07-04).
     *
     * The tun forwards system DNS to {@link #VPN_VIRTUAL_DNS_IP} ({@code 10.1.10.2}) — a
     * tun-SUBNET virtual DNS address (adjacent to the tun interface {@code 10.1.10.1},
     * VpnBuilder.java:121), NOT loopback. Android's {@code VpnService.Builder.addDnsServer}
     * REJECTS {@code 127.0.0.1} ("Bad address") because loopback cannot be a VPN DNS server —
     * so the earlier loopback rewire threw before {@code establish()} and no tun fd was ever
     * produced. A tun-subnet IP is accepted: the OS sends DNS to {@code 10.1.10.2:53} INTO the
     * tun, and the pure-Rust {@code tunnel::TunnelController} loop (which intercepts every
     * {@code dport == 53} packet, tunnel/parse.rs) resolves it via {@code torta_resolve} →
     * DNSCrypt upstream → writes the reply back to the tun. The address is never actually
     * reached on the network — it is a capture sentinel the Rust loop answers inline.
     *
     * <p>No egress loop: the loop answers {@code :53} inline and never forwards the query to
     * {@code 10.1.10.2}; the DNSCrypt upstream sockets are {@code protect()}'d (R2) so they
     * bypass the tun. The VPN address/route build above is untouched — only the DNS set changes.
     */
    private fun getDns(): List<InetAddress> {
        if (vpnDnsSet == null) {
            vpnDnsSet = ConcurrentSkipListSet()
        }

        val listDns = ArrayList<InetAddress>()
        try {
            val virtualDns = InetAddress.getByName(VPN_VIRTUAL_DNS_IP)
            listDns.add(virtualDns)
            vpnDnsSet!!.add(VPN_VIRTUAL_DNS_IP)
            logi("VPN Sovereign DNS rewire: tun DNS -> " + VPN_VIRTUAL_DNS_IP
                    + " (tun-subnet sentinel; the Rust tunnel loop intercepts :53 inline)")
        } catch (ex: Throwable) {
            // VPN_VIRTUAL_DNS_IP is a literal dotted-quad — UnknownHostException is unreachable
            // in practice, but fail-open so a lookup glitch never tears down the tun.
            loge("VPNBuilder getDns sovereign rewire", ex, true)
        }

        logi("VPN Get DNS=" + TextUtils.join(",", listDns))
        return listDns
    }

    @SuppressLint("UnspecifiedImmutableFlag")
    private fun getConfigureIntent(): PendingIntent {
        val configure = Intent(context, TortaSlintActivity::class.java)
        configure.setAction(Intent.ACTION_MAIN)
        configure.addCategory(Intent.CATEGORY_LAUNCHER)
        val pi: PendingIntent
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            pi = PendingIntent.getActivity(
                context,
                0,
                configure,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            pi = PendingIntent.getActivity(
                context,
                0,
                configure,
                PendingIntent.FLAG_UPDATE_CURRENT
            )
        }
        return pi
    }

    companion object {

        @Volatile
        @JvmStatic
        var vpnDnsSet: ConcurrentSkipListSet<String>? = null

        // Task 4C: the legacy `jni_get_mtu()` C export is GONE; the MTU is now a Kotlin constant.
        //
        // ★ THE ERR_CONNECTION_CLOSED CAUSE (measured, checkpoint 58). This was 1500, and the comment
        // defending it contained the reasoning error: it cited the Rust loop's `.max(64)` as if that
        // clamped the value. `.max(64)` is a FLOOR, not a ceiling — it cannot stop 1500 being too large.
        // It also conflated two different quantities that only LOOK alike:
        //   · the tun loop's READ BUFFER, which must be >= the MTU (a short buffer truncates packets), and
        //   · the VPN INTERFACE MTU, which must be <= the real path MTU MINUS the tunnel's own overhead.
        // Aligning the three surfaces on one number therefore aligned them on the WRONG number.
        //
        // At 1500 the tun MTU equals the underlying link MTU, leaving ZERO headroom: a full-size packet
        // handed to the tunnel exceeds the path MTU once it is re-encapsulated and is silently dropped.
        // The failure is SIZE-dependent, which is exactly why it looked site-dependent and survived three
        // weeks of debugging: DNS queries (~60-100 B) always fit, so every resolver instrument read
        // perfect (measured: 1364 verdicts, 1162 PASS, 0 TIMEOUT, 0 DROP), while a TLS handshake — whose
        // certificate records run 1400 B and up — is the FIRST full-size packet on a connection and dies.
        // Measured on the AVD in one 111-URL run: 704 x `ssl_client_socket_impl.cc:964 handshake failed`
        // from Chromium itself, plus 24 `reset by peer`, all surfacing to the user as
        // ERR_CONNECTION_CLOSED.
        //
        // 1400 is not a guess: it is this repo's OWN safe value, already named as such at
        // `utils/connectionchecker/NetworkChecker.kt:34` (`DEFAULT_MTU = 1400`) and used there as the
        // fallback whenever the link MTU cannot be read. The VPN builder was the one surface that
        // disagreed with it. 1400 leaves 100 B of headroom below a 1500 B Ethernet path — enough for the
        // encapsulation this datapath adds — and stays at or under the 1400-1450 MTUs common on mobile
        // carriers and PPPoE links, where a 1500 B tun is guaranteed to black-hole large packets.
        //
        // The read buffer stays independent: `ServiceVPN.startNative` passes this to
        // `TunnelController.start`, and `tunnel::TunnelConfig` floors it at 64, so a smaller MTU shrinks
        // the buffer safely without truncation (buffer == MTU is the exact-fit case, not a short read).
        //
        // PROVE IN LEAN: `Proofs/TunMtuHeadroom.lean` — for ALL link MTUs, tunMtu + overhead <= linkMtu,
        // and the clamp cannot be configured above that bound.
        const val VPN_MTU = 1400

        /**
         * The tun-subnet virtual DNS sentinel the OS is told to use as its DNS server. Adjacent to the
         * tun interface {@code 10.1.10.1} (VpnBuilder.java:121), inside the tun subnet, so Android's
         * {@code addDnsServer} accepts it (unlike loopback {@code 127.0.0.1}, which it rejects). The
         * address is never reached on the network — the pure-Rust {@code tunnel::TunnelController} loop
         * intercepts every {@code :53} packet inline and answers via {@code torta_resolve} → DNSCrypt.
         */
        const val VPN_VIRTUAL_DNS_IP = "10.1.10.2"

        /**
         * ★ #65 CENTAURI — the DNS-plane cloak sentinel, the address a watched CDN host is answered
         * with so its traffic lands on the in-app offline mirror instead of the real CDN.
         *
         * MUST stay byte-identical to the Rust authority `CLOAK_SENTINEL_V4`
         * (`rust/torta_core/src/resolver/local.rs:197`) — the resolver mints this address and the
         * forwarder recognises it (`forwarder/mod.rs:56 is_cloak_sentinel`). A drift between the two
         * would silently un-cloak every CDN host: the answer would point at an address the tun does
         * not claim, and the request would leave the device.
         *
         * Adjacent to [VPN_VIRTUAL_DNS_IP] inside the same tun subnet, and never reachable on the real
         * network — it exists only so the mirror can be addressed from inside the tunnel.
         */
        const val CENTAURI_CLOAK_SENTINEL_IP = "10.1.10.3"

        /**
         * The v6 twin of [CENTAURI_CLOAK_SENTINEL_IP] — the Kotlin mirror of
         * `resolver::local::CLOAK_SENTINEL_V6` (`resolver/local.rs:202`).
         *
         * The DNS-plane cloak answers a watched CDN host on BOTH address families: A gets
         * `10.1.10.3`, AAAA gets this. Cloaking only A is not an option — a fall-through AAAA would
         * resolve the REAL CDN and the fetch would leak over v6, bypassing the whole seam.
         *
         * So this address MUST be routed into the tun for exactly the reason the v4 sentinel is, and
         * its absence was a live defect: Happy Eyeballs reaches for the AAAA first, so every cloaked
         * CDN host died with ERR_CONNECTION_CLOSED while uncloaked hosts were fine. The v4 leg worked,
         * the v6 leg had nowhere to land.
         */
        const val CENTAURI_CLOAK_SENTINEL_IP6 = "fd00:1:fd00:1:fd00:1:fd00:3"
    }
}
