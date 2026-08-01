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

import android.net.VpnService
import javax.inject.Inject
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import uniffi.torta_core.ProtectCallback

/**
 * **THE RISK-2 PROTECT CALLBACK (R2 egress-loop guard).** The Kotlin side of the contract locked in
 * S2-RUST-TUNNEL-ENGINE-SPEC §"LOCKED DECISIONS" (Risk 2, contract A) and
 * S2-PHASE1-DESIGN-option-b: the Rust `tunnel::ProtectCallback` trait
 * (`#[uniffi::export(with_foreign)]`, Rust `rust/torta_core/src/tunnel/mod.rs:94`) is surfaced to
 * Kotlin as `uniffi.torta_core.ProtectCallback` — `fun protectFd(fd: Int): Boolean`. The Rust loop
 * / resolver transports (dnscrypt.rs udp+tcp, doq.rs, doh3.rs — task 1E) call `protect_fd(fd)`
 * BEFORE every upstream `connect()` / `sendto()`; a `false` return makes them fail-fast to the next
 * transport. NEVER proceed with an unprotected socket — that is the silent egress loop (traffic
 * escaping the tun) the contract exists to prevent.
 *
 * ## Ownership (spec §1 piece 3 + §"LOCKED DECISIONS" 4)
 *
 * The Tortä `TunnelController` (the Kotlin-Inject component) OWNS this callback: it is `@Inject`ed
 * into the controller, bound to the live `VpnService` at VPN-establish time via [bind], and passed
 * as the `protectCb` arg to the Rust `TunnelController.start(...)` call (the UniFFI Object's
 * `start` — generated in `uniffi/torta_core/torta_core.kt`):
 * ```kotlin
 * val started = rustTunnel.start(
 *     tunFd = pfd.detachFd(),       // R1 — exactly once, see TunnelController
 *     mtu = mtu,
 *     virtualDnsIp = virtDns,
 *     blockedRcode = rcode,
 *     bypassLan = lan,
 *     protectCb = vpnProtectCallback,  // ← R2 — this instance, owned by the TunnelController
 * )
 * ```
 *
 * ## Why a separate class (not TunnelController implementing the interface)
 *
 * Two reasons, both load-bearing:
 * 1. **Late binding.** The `VpnService` is not a DI-provided dependency — it is a runtime instance
 *    the Android framework hands `ServiceVPN` at establish time. The callback therefore needs a
 *    `@Volatile` settable reference ([vpnService]) that the TunnelController binds via [bind] when
 *    `ServiceVPN.establish` runs and unbinds via [unbind] on `onRevoke` / `onDestroy`. The
 *    `@Volatile` guarantees the resolver's transport threads (which call `protect_fd` from the Rust
 *    side, on arbitrary threads) see the latest write.
 * 2. **Lifecycle decoupling.** The Rust `TunnelController` (the UniFFI Object) is one-per-establish
 *    too, but its Kotlin twin is the natural DI owner; keeping the callback as a composable
 *    `@ModulesServiceScope` dependency lets the SAME instance survive a Rust controller rebuild
 *    (e.g. a `stop`/`start` cycle within one VPN session) without losing the bound `VpnService`.
 *
 * ## Fail-fast contract (R2)
 *
 * [protectFd] returns `false` when no `VpnService` is bound. The Rust transports treat `false` as
 * "could not protect → do not proceed" and skip to the next transport (or synthesize SERVFAIL per
 * R4 if none remain). This is the SPEC-LOAD-BEARING failure mode: a `true` return without a real
 * `protect()` would let the upstream socket escape the tun (the egress loop). Never default to
 * `true`. Never swallow the result.
 *
 * UniFFI callback-interface stability is the project's UniFFI version (Q-ground-5); this impl is a
 * plain `override fun` on a concrete class — the simplest, most stable callback shape (no lambda,
 * no anonymous object — both of which UniFFI `with_foreign` accepts but a named class is the
 * long-lived-instance form the loop's `Arc<dyn ProtectCallback>` expects to outlive one call).
 */
@ModulesServiceScope
class VpnProtectCallback @Inject constructor() : ProtectCallback {

    /**
     * The live `VpnService` (a `ServiceVPN` instance — `ServiceVPN extends VpnService`, see
     * `vpn/service/ServiceVPN.java:117`). Bound at VPN-establish time. `@Volatile` so the
     * resolver's transport threads (which call [protectFd] from the Rust side, on arbitrary OS
     * threads via `Arc<dyn ProtectCallback>`) observe the latest bind/unbind without locking.
     *
     * `null` before [bind] / after [unbind] — [protectFd] then returns `false` (fail-fast, R2).
     */
    @Volatile private var vpnService: VpnService? = null

    /**
     * Bind the live [VpnService] (called by `TunnelController.start(...)` at VPN-establish time,
     * right before the Rust `start` — so the FIRST upstream `connect()` finds a bound service).
     * Idempotent: re-binding the same instance is a no-op; binding a different one replaces it (the
     * scope is `@ModulesServiceScope`, one service per session — but defensive nonetheless).
     */
    fun bind(service: VpnService) {
        vpnService = service
    }

    /**
     * Unbind the `VpnService` (called by `TunnelController.stop()` / `onRevoke` / `onDestroy`).
     * After this, [protectFd] returns `false` — the resolver's transports fail-fast to SERVFAIL
     * (R4) rather than opening an unprotected upstream socket.
     */
    fun unbind() {
        vpnService = null
    }

    /**
     * **The R2 call.** Delegates to [`VpnService.protect(int)`][VpnService.protect] — the Android
     * API that routes the given socket file descriptor AROUND the tun (so the resolver's upstream
     * DNSCrypt/DoQ/DoH3 sockets reach the network directly instead of looping back through the tun
     * we just captured :53 on). `ServiceVPN` already exposes the same primitive as
     * `protectSocket(int)` (`vpn/service/ServiceVPN.java:527`); calling `protect(fd)` directly here
     * is identical and avoids a coupling hop.
     *
     * Returns `true` only when `protect()` actually succeeded (Android returns `false` on failure —
     * e.g. the fd is invalid or the service is revoked). `false` makes the Rust transport skip to
     * the next path or synthesize SERVFAIL (R4). NEVER default to `true`.
     */
    override fun protectFd(fd: Int): Boolean {
        val service =
            vpnService
                ?: run {
                    // No VpnService bound — either before establish, after revoke, or a misordered
                    // start.
                    // Fail-fast (R2): the Rust side skips to the next transport / SERVFAIL (R4).
                    loge(
                        "VpnProtectCallback.protectFd($fd): no VpnService bound — returning false (R2 fail-fast)"
                    )
                    return false
                }
        // runCatching — `VpnService.protect()` is a native method that returns false on soft
        // failure (invalid fd / revoked permit) but may still raise if the service was torn down
        // mid-call. Any throw ⇒ fail-fast (R2): do NOT let the upstream socket escape the tun
        // unprotected; the Rust side advances to the next transport or synthesizes SERVFAIL (R4).
        val ok = runCatching { service.protect(fd) }.getOrElse { false }
        if (ok) {
            // Success — keep the log line cheap; this fires on EVERY upstream socket (hot path).
            logi("VpnProtectCallback.protectFd($fd): ok")
        } else {
            loge("VpnProtectCallback.protectFd($fd): protect() failed/threw — returning false (R2)")
        }
        return ok
    }
}
