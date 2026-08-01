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

@file:Suppress(
    "PackageNaming"
) // `pillar.kuma_saimono` is the Saimonokuma app convention (project-wide).

package pillar.kuma_saimono.libumdnscrypt.vpn.tunnel

import android.net.ConnectivityManager
import android.net.InetAddresses
import android.net.VpnService
import android.os.Build
import java.net.InetSocketAddress
import javax.inject.Inject
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import uniffi.torta_core.UidResolver

/**
 * **★ N-WARDEN (#144) — THE FLOW-OWNER UID RESOLVER.** The Kotlin side of the Rust
 * `tunnel::UidResolver` trait (`#[uniffi::export(with_foreign)]`, `rust/torta_core/src/tunnel/mod.rs`
 * — the [VpnProtectCallback] shape): the netstack forwarder calls [uidOf] ONCE per accepted non-DNS
 * flow, and the returned uid is the ONE fact that brings the Warden verdict to life — the C-ABI
 * (`torta_firewall_verdict`) ABSTAINs unconditionally on `uid < 0`, so without this resolver the
 * forwarder's per-app firewall gate is permanently dormant (fail-safe pass, by design).
 *
 * ## The lookup — `ConnectivityManager.getConnectionOwnerUid` (API 29+)
 *
 * The ONLY sanctioned flow→uid attribution on modern Android (the `/proc/net` table parse the
 * legacy engines used is blocked since Q). The API is restricted to the app operating the CURRENT active
 * VPN — exactly what we are when the forwarder is running (the same posture Rethink/NetGuard hold).
 * It answers from the kernel's connection table: `(protocol, local, remote)` → uid, or
 * `Process.INVALID_UID` (-1) when the flow cannot be attributed.
 *
 * ## Fail-safe contract (the Warden's additive-block law)
 *
 * EVERY failure path returns `-1` — below API 29, unbound service, unparsable address,
 * `SecurityException` (VPN no longer active), anything: the Rust gate then ABSTAINs and the flow
 * forwards. A wrong uid could DENY an innocent app's traffic; an absent uid can only pass. Never
 * fabricate, never default to a real-looking uid.
 *
 * Bound/unbound by the Kotlin [TunnelController] alongside [VpnProtectCallback] (bind at
 * VPN-establish, unbind at stop) — `@Volatile` because [uidOf] fires from the Rust forwarder's
 * flow tasks (arbitrary OS threads via `Arc<dyn UidResolver>`).
 */
@ModulesServiceScope
class ConnectivityManagerUidResolver @Inject constructor() : UidResolver {

    /**
     * The live [ConnectivityManager], captured from the bound [VpnService]'s context at
     * VPN-establish time. `null` before [bind] / after [unbind] — [uidOf] then returns `-1`
     * (ABSTAIN upstream, fail-safe pass).
     */
    @Volatile private var connectivity: ConnectivityManager? = null

    /**
     * Bind the live [VpnService] (called by `TunnelController.start(...)` right next to
     * [VpnProtectCallback.bind], BEFORE the Rust `start` — so the forwarder's first accepted flow
     * already resolves). Idempotent.
     */
    fun bind(service: VpnService) {
        connectivity = service.getSystemService(ConnectivityManager::class.java)
    }

    /**
     * Unbind (called by `TunnelController.stop()` and the start-failure paths). After this, [uidOf]
     * returns `-1` — any straggler flow task racing the teardown gets ABSTAIN, never a stale lookup.
     */
    fun unbind() {
        connectivity = null
    }

    /**
     * **The N-warden call.** `protocol` is the IANA number (6 TCP / 17 UDP), addresses are numeric
     * `inet` strings exactly as the Rust forwarder rendered them (`SocketAddr::ip().to_string()`),
     * ports host-order. Returns the owning uid, or `-1` on ANY failure (see the class doc's
     * fail-safe contract). Kept log-quiet on the happy path — this fires per accepted flow.
     */
    override fun uidOf(
        protocol: Int,
        srcIp: String,
        srcPort: UShort,
        dstIp: String,
        dstPort: UShort,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return -1 // getConnectionOwnerUid does not exist below 29 — permanent ABSTAIN there.
        }
        val cm = connectivity ?: return -1
        return try {
            // parseNumericAddress (API 29+, satisfied by the gate above) NEVER touches DNS — a
            // malformed literal throws (→ -1) instead of resolving a name.
            val local = InetSocketAddress(InetAddresses.parseNumericAddress(srcIp), srcPort.toInt())
            val remote = InetSocketAddress(InetAddresses.parseNumericAddress(dstIp), dstPort.toInt())
            // Process.INVALID_UID (-1) when the kernel cannot attribute the flow — passes through
            // as the honest ABSTAIN.
            cm.getConnectionOwnerUid(protocol, local, remote)
        } catch (t: Throwable) {
            // SecurityException (we are no longer the active VPN), IllegalArgumentException
            // (unparsable literal), or any framework fault: ABSTAIN, never fabricate.
            loge("ConnectivityManagerUidResolver.uidOf: lookup threw — returning -1 (ABSTAIN)", t)
            -1
        }
    }
}
