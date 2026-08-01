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

package pillar.kuma_saimono.libumdnscrypt.vpn.tunnel

import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.net.VpnService
import androidx.preference.PreferenceManager
import javax.inject.Inject
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import uniffi.torta_core.ForwarderFlowRow
import uniffi.torta_core.ForwarderSnapshot
import uniffi.torta_core.TunnelSnapshot
import uniffi.torta_core.TunnelController as RustTunnelController
import uniffi.torta_core.tunnelCreate

/**
 * **THE KOTLIN TUNNEL CONTROLLER (Task 3A · the de-InviZible endgame, Kotlin side).**
 *
 * The Kotlin-Inject component that owns the lifecycle of the pure-Rust tun-packet-loop, replacing
 * the legacy C tunnel engine (the `jni/invizible` .c sources + `libinvizible.so`) AND the Go binary
 * (`libs/libdnscrypt-proxy.so`) on the VPN datapath. This is piece 3 of the four-piece architecture
 * locked in `S2-RUST-TUNNEL-ENGINE-SPEC.md` §1, woven by the 🧭 Claude lens after a Genesis study
 * of `tun-rs-main/` (the Rust tun-fd/async surface — resolves Q-ground-3) × `jni/invizible/udp.c`
 * (the proven DNS decision tree) × `resolver/listener.rs:152-215` (the dedicated-OS-thread
 * precedent). The Rust twin lives at `rust/torta_core/src/tunnel/mod.rs` (`TunnelController`, a
 * `#[derive(uniffi::Object)]`); the free-function constructor `tunnelCreate()` is at
 * `rust/torta_core/src/lib.rs:1921`.
 *
 * ## What this class OWNS (spec §"LOCKED DECISIONS")
 *
 * - **R1 — the fd-handoff discipline.** [`start`] calls `pfd.detachFd()` **EXACTLY ONCE** and hands
 *   the raw int to the Rust `TunnelController.start(...)`; Rust dups it into an `OwnedFd` and closes
 *   the DUP on [`stop`]. **Neither side ever closes the original int.** The detached `ParcelFileDescriptor`
 *   is never touched again by Kotlin after [`start`] returns (the spec's one-fd-per-start safety).
 *   The Kotlin caller (`ServiceVPN.startNative`) therefore shrinks to ~3 lines — see the spec §5.
 *
 * - **R2 — the protect-callback wiring.** This controller `@Inject`s the sibling [VpnProtectCallback]
 *   (a `@ModulesServiceScope` `ProtectCallback` impl), binds it to the live [VpnService] in [`start`]
 *   (right before the Rust `start`, so the resolver's FIRST upstream `connect()` finds a bound
 *   service), and passes it as the `protectCb` arg to the Rust `TunnelController.start(...)`. The
 *   Rust loop / resolver transports (dnscrypt.rs udp+tcp, doq.rs, doh3.rs — task 1E) call
 *   `protect_fd(fd)` BEFORE every upstream `connect()`/`sendto()`; a `false` return makes them
 *   fail-fast to the next transport. Unbound ⇒ `false` (never default to `true` — that is the silent
 *   egress loop the contract exists to prevent).
 *
 * - **The lifecycle.** [start] / [stop] / [snapshot] / [isRunning] ride the UniFFI Object surface
 *   (the Beast/Centauri/MaskSolver precedent). Idempotent: a second [start] while running is a no-op
 *   (returns `false`); [stop] joins the loop thread within the Rust poll-timeout + join window.
 *
 * ## Why a separate Kotlin class (not ServiceVPN talking to Rust directly)
 *
 * ServiceVPN (`vpn/service/ServiceVPN.java`) is the Android-instantiated `VpnService`; it is not
 * DI-constructible. The de-InviZible cut shrinks its `startNative`/`stopNative` bodies to ~3-line
 * forms that delegate here — so the R1/R2 discipline, the UniFFI Object ownership, and the
 * protect-callback lifecycle live in ONE `@ModulesServiceScope` place, not scattered across the
 * legacy Java service. This mirrors [ResolverRuntime] (`dns_engine/ResolverRuntime.kt:79-87`): a
 * `@ModulesServiceScope class … @Inject constructor(…)` shared across the DI graph.
 *
 * Field-injection (`javax.inject.Inject`) honors BOTH Dagger (the live graph) and kotlin-inject (the
 * migration target). The no-arg-sibling [VpnProtectCallback] is auto-supplied by the ModulesService
 * subcomponent, exactly like [ResolverRuntime]'s deps.
 *
 * ## Crash discipline
 *
 * Every Rust crossing is crash-firewalled: a throw from the UniFFI façade (lib unload, panic
 * crossing FFI, JNI detach fault) degrades to a documented no-op — [start] returns `false`,
 * [stop]/[snapshot]/[isRunning] return safe defaults — and is logged at `loge`. Never propagates into
 * `ServiceVPN`'s establish path (a VPN-establish crash would tear the whole session down). This is
 * the SAME contract [ResolverRuntime] keeps on every [TortaCore] façade call.
 */
@ModulesServiceScope
class TunnelController
@Inject
constructor(
    /**
     * The R2 protect-callback instance this controller OWNS for the `@ModulesServiceScope` lifetime.
     * Bound to the live [VpnService] in [start] (`vpnProtectCallback.bind(service)`); unbound in
     * [stop]. Held here so the Rust loop's `Arc<dyn ProtectCallback>` reaches a stable, long-lived
     * Kotlin instance (the spec §"LOCKED DECISIONS" 4 + [VpnProtectCallback]'s class doc).
     */
    private val vpnProtectCallback: VpnProtectCallback,
    /**
     * ★ N-warden (#144) — the flow-owner UID resolver this controller owns for the scope lifetime
     * (the [vpnProtectCallback] twin). Bound to the live [VpnService] in [start], installed on the
     * Rust controller via `setUidResolver` BEFORE the Rust `start` (the forwarder clones it at
     * fork time), unbound in [stop]. Without it the Warden gate ABSTAINs on every flow (uid=-1).
     */
    private val uidResolver: ConnectivityManagerUidResolver,
) {
    companion object {
        /**
         * **N6c · THE LIVE-INSTANCE HOLDER** — the same cross-.so seam the other pillars keep
         * (`ResolverRuntime`'s live holder behind `TortaCore.liveResolverStats`): `libtorta_ui.so`
         * links its OWN COLD `torta_core` copy, so the SLINT forwarder card can only see the RUNNING
         * tunnel's counters through a Kotlin static (`TortaPillarBridge.liveForwarderStats` →
         * [liveForwarderSnapshot]). Set on a successful [start], cleared FIRST in [stop] — a reader
         * mid-teardown gets `null` (the honest DORMANT card), never a controller whose loop thread
         * is being joined.
         */
        @Volatile private var live: TunnelController? = null

        /**
         * The RUNNING tunnel's [ForwarderSnapshot] (counts only — T20), or `null` when no tunnel is
         * live (holder empty) or the crossing faults (crash-firewalled in [forwarderSnapshot]).
         * `armed=false` + all-zero from a live-but-netstack-off tunnel is itself an honest record —
         * the card renders DORMANT off the `armed` flag, not off `null`.
         */
        @JvmStatic
        fun liveForwarderSnapshot(): ForwarderSnapshot? = live?.forwarderSnapshot()

        /**
         * ★ #47 N8 — the RUNNING tunnel's PER-FLOW docket (counts + classes only, T20), or `null`
         * when no tunnel is live or the crossing faults. An EMPTY list from a live tunnel is an
         * honest "no flows right now" and is NOT the same as `null` ("no tunnel / read failed") —
         * the FORWARDER panel must distinguish them rather than rendering both as blank.
         */
        @JvmStatic
        fun liveForwarderFlowDocket(): List<ForwarderFlowRow>? = live?.forwarderFlowDocket()

        /**
         * ★ SPLIT-BRAIN CURE (#129 field bug 1) — GROUND-TRUTH datapath liveness for
         * `ModulesStateLoop`. The pure-Rust DNSCrypt module is alive iff THIS holder is set
         * ([start] spawn ↔ [stop]): unlike the `VPN_SERVICE_ENABLED` pref — which a backup
         * restore or `pm install -r` resurrects into a process whose resolver pool never
         * existed — a `static` cannot outlive the process that owns the pool. A fresh process
         * is honestly `false` here, so the state loop never declares RUNNING over a dead
         * datapath.
         */
        @JvmStatic
        fun isDatapathLive(): Boolean = live != null

        /**
         * ★ NETSTACK GENESIS (#144) — the default-shared-prefs key that arms the pure-Rust ipstack
         * forwarder at the NEXT tunnel [start].
         *
         * **Absent ⇒ `true`.** This doc previously claimed `false` ("the OFF-by-default discipline")
         * and was stale by three call sites: [start] below, `VpnBuilder.addRoutes` and
         * `TortaPillarBridge.netstackForwarderArmed` all read it with a `true` default, and a fresh
         * install was measured LIVE on device with no pref written. The default was deliberately
         * flipped ON because **Centauri's HTTPS serve leg lives inside the forwarder** — a dormant
         * forwarder silently disables offline-CDN serving for every new user. The three defaults MUST
         * agree, or the route plan and the tunnel disagree about whether the forwarder is armed.
         *
         * Read in [start] right before the Rust `start` (the loop samples the switch once, at spawn —
         * never hot-swapped mid-session).
         */
        const val NETSTACK_FORWARDER_PREF = "swNetstackForwarder"

        /**
         * ★ WARM-UP BEACON (#129 field bug 6) — the neutral question driven through the cold
         * resolver ladder: a root-NS query (".", qtype 2) carries ZERO user information (T20-clean)
         * and no blocklist can match it, so it always exercises the real upstream path.
         */
        private const val WARM_UP_QNAME = "."
        private const val WARM_UP_QTYPE = 2 // NS

        /** Beacon give-up window: the pool never configured ⇒ nothing to warm this session. */
        private const val WARM_UP_DEADLINE_MS = 60_000L

        /** Spin cadence while the pool is still empty (pre-configure resolves fail fast). */
        private const val WARM_UP_SPIN_MS = 750L
    }

    /**
     * The Rust `TunnelController` (the UniFFI Object — `rust/torta_core/src/tunnel/mod.rs:171`).
     * Constructed lazily via `tunnelCreate()` (`lib.rs:1921`) on the FIRST [start]: no loop runs
     * until then, so a fresh `@ModulesServiceScope` instance pays nothing at construction time. One
     * per scope; a [stop] does NOT drop it (the Rust side joins the thread but the Object lives until
     * the DI scope drops it), so a [start]/[stop]/[start] cycle within one VPN session reuses the
     * same Object — the Rust `start` is idempotent (returns `false` if already running).
     */
    private val rust: RustTunnelController by lazy { tunnelCreate() }

    /**
     * **THE R1 FD-HANDOFF + R2 PROTECT-BIND + LOOP LAUNCH (spec §"LOCKED DECISIONS" 3 + 4).**
     *
     * Call this from the shrunk `ServiceVPN.startNative` (spec §5 step 5) at VPN-ESTABLISH time:
     *
     * ```kotlin
     * val started = tunnelController.start(
     *     pfd = vpn,                              // the established ParcelFileDescriptor
     *     mtu = jni_get_mtu(),                    // the legacy MTU
     *     virtualDnsIp = VpnBuilder.VPN_VIRTUAL_DNS_IP,  // the tun-subnet DNS IP (NOT loopback)
     *     blockedRcode = vpnPreferences.getDnsBlockedResponseCode(),
     *     bypassLan = vpnPreferences.getLan(),
     *     vpnService = this,                      // ServiceVPN extends VpnService
     * )
     * ```
     *
     * Order (load-bearing):
     * 1. **R2 FIRST** — [VpnProtectCallback.bind] the [vpnService] so the Rust resolver's FIRST
     *    upstream `connect()` (fired from the loop thread the moment [rustStart] returns `true`) finds
     *    a bound service. If the bind races the first packet, `protectFd` returns `false` and the
     *    transport fail-fasts to the next (or synthesizes SERVFAIL per R4) — never an egress loop.
     * 2. **R1** — `pfd.detachFd()` **EXACTLY ONCE**. The int is handed to Rust; the original PFD is
     *    never touched again by Kotlin (the one-fd-per-start safety). Rust dups it into an `OwnedFd`,
     *    owns the dup for the loop lifetime, and closes the dup on [stop]. Neither side closes the
     *    original int.
     * 3. **Rust `start`** — install the [vpnProtectCallback] as the loop's `Arc<dyn ProtectCallback>`
     *    (Rust does this internally BEFORE spawning the loop thread), build the `TunnelConfig`, spawn
     *    the loop. Returns `true` iff the loop thread was spawned.
     *
     * @return `true` iff the loop thread was spawned. `false` on idempotency (already running), a
     *   `dup` failure, or any UniFFI/panic fault (crash-firewalled + logged).
     */
    @Synchronized
    fun start(
        pfd: ParcelFileDescriptor,
        mtu: Int,
        virtualDnsIp: String,
        blockedRcode: Int,
        bypassLan: Boolean,
        vpnService: VpnService,
    ): Boolean {
        // ★ DOUBLE-START GUARD (#129 hardening). With a loop already running, the Rust `start` can
        // only return `false` — but reaching it would first (a) `detachFd()` a fd Rust will never
        // dup (a kernel-level leak, the edge the old false-branch comment accepted) and (b) walk the
        // false branch's `unbind()`s, which would strip the protect callback + uid resolver from the
        // LIVE loop and break its upstream socket protection until the next start. Bail here
        // instead: the caller's PFD keeps fd ownership (its normal close path stays intact), and
        // the running datapath's bindings stay untouched. `isRunning()` is crash-firewalled to
        // `false`, so a faulted bridge never blocks a genuine start attempt.
        if (isRunning()) {
            logi("TunnelController.start: loop already running — double-start ignored (R1 fd untouched)")
            return false
        }

        // R2: bind the protect callback BEFORE the loop spawns so the first upstream connect is
        // guarded. Idempotent (re-binding replaces); see [VpnProtectCallback.bind].
        vpnProtectCallback.bind(vpnService)

        // ★ N-warden: bind + install the flow-owner uid resolver BEFORE the Rust start — the
        // netstack fork clones the resolver at spawn time, so a post-start install would miss this
        // session. A fault here is NON-fatal: the gate fail-safes to ABSTAIN (uid=-1), the tunnel
        // still starts (the Warden can only ADD a block, never break forwarding).
        uidResolver.bind(vpnService)
        runCatching { rust.setUidResolver(uidResolver) }
            .onFailure {
                loge(
                    "TunnelController.start: setUidResolver threw — Warden gate will ABSTAIN",
                    it
                )
            }

        // ★ NETSTACK GENESIS (#144): arm/disarm the pure-Rust forwarder from the ON-by-default
        // pref BEFORE the Rust start — the loop samples the switch once, at spawn. On a base
        // (non-netstack) .so the Rust side is a documented no-op. A fault here is NON-fatal: the
        // tunnel still starts on the sync DNS-only loop (the forwarder can only ADD a datapath).
        runCatching {
            val armForwarder = PreferenceManager.getDefaultSharedPreferences(vpnService)
                // ON by default: Centauri's HTTPS serve leg lives in the forwarder, so a dormant
                // forwarder silently disables offline CDN serving on every fresh install.
                .getBoolean(NETSTACK_FORWARDER_PREF, true)
            rust.setNetstack(armForwarder)
            if (armForwarder) {
                logi("TunnelController.start: netstack forwarder ARMED ($NETSTACK_FORWARDER_PREF)")
            }
        }.onFailure {
            loge("TunnelController.start: setNetstack threw — staying on the sync DNS-only loop", it)
        }

        // R1: detachFd EXACTLY ONCE. The original PFD is relinquished here — `pfd` must NEVER be
        // touched again by the caller after this returns (neither side closes the original int).
        val tunFd: Int =
            try {
                pfd.detachFd()
            } catch (t: Throwable) {
                // detachFd can throw on an already-detached/closed PFD. Fail-safe: do NOT spawn the
                // loop on a fd we don't unequivocally own (R1's one-fd-per-start invariant).
                vpnProtectCallback.unbind()
                uidResolver.unbind()
                loge("TunnelController.start: pfd.detachFd() threw — aborting (R1)", t)
                return false
            }

        // Rust start. Installs the protect callback, builds TunnelConfig, spawns the loop thread.
        val started =
            try {
                rust.start(
                    tunFd = tunFd,
                    mtu = mtu,
                    virtualDnsIp = virtualDnsIp,
                    blockedRcode = blockedRcode,
                    bypassLan = bypassLan,
                    protectCb = vpnProtectCallback,
                )
            } catch (t: Throwable) {
                // Crash firewall: a panic crossing FFI / an unloaded lib / a JNI detach fault —
                // degrade to "not started", keep the protect-callback unbound so a stray transport
                // connect fails fast. Never propagate into ServiceVPN's establish path.
                vpnProtectCallback.unbind()
                uidResolver.unbind()
                loge("TunnelController.start: rust.start threw — loop not spawned", t)
                false
            }

        if (started) {
            // N6c: publish the live instance for the SLINT bridge the moment the loop is running.
            live = this
            logi(
                "TunnelController.start: Rust tun loop spawned (fd=$tunFd mtu=$mtu " +
                    "virtDns=$virtualDnsIp rcode=$blockedRcode bypassLan=$bypassLan)"
            )
            // #129 field bug 6: pay the resolver's cold-start bill NOW, not on the user's first tap.
            launchWarmUpBeacon()
        } else {
            // With the double-start guard above, `false` here means a genuine fault (a dup failure —
            // kernel-fd exhaustion — or a race the guard's snapshot missed): the loop is NOT running
            // off THIS call, so unbinding is safe AND required (a later start re-binds cleanly). The
            // R1 fd we detached is owned by Rust only when start returned true; on false Rust never
            // dups it, so the int leaks at the kernel level — accepted for this rare fault edge.
            vpnProtectCallback.unbind()
            uidResolver.unbind()
            logi("TunnelController.start: rust.start returned false (already running or dup failed)")
        }

        // ★ FIXED 2026-07-31 — R1 SAID "NEITHER SIDE CLOSES THE ORIGINAL INT". THAT IS A LEAK.
        //
        // `detachFd()` TRANSFERS ownership of the raw int to the caller. A transferred fd that
        // nobody closes is a leak by definition, and Android holds a tun interface up for as long as
        // ANY descriptor on it is open — so the rule written to prevent a double-close is precisely
        // what made the VPN impossible to turn off. Measured on the x86_64 AVD:
        //     ARM    -> tun0 inet 10.1.10.1/32
        //     DISARM -> tun still 1 across 8 polls, with always_on_vpn_app cleared so the system's
        //               own always-on restart could not be mistaken for the app ignoring the request
        // and the teardown ran CLEANLY on the way through — `VPN Stop native (Rust tunnel)`,
        // `VPN Handler Stopping`, no exception logged. Nothing was broken; the fd was simply never
        // closed. `stopVPN(serviceVPN.vpn!!)` closes a ParcelFileDescriptor that, post-detach, owns
        // nothing at all.
        //
        // The contract was stated identically in THREE places (ServiceVPN.kt:181,
        // TunnelController.kt:216, tunnel/mod.rs:1017-1018), so it was deliberate, not forgotten —
        // which is why no amount of re-reading the teardown found it.
        //
        // Closing here is safe on BOTH branches, and both are required:
        //   started == true  — Rust already dup'd the int into its OwnedFd (tunnel/mod.rs:1021,
        //                      inside rust.start, BEFORE it returned true) and closes that dup in
        //                      stop(). The original is redundant, and the loop cannot be harmed by
        //                      its close: a dup is an independent descriptor.
        //   started == false — Rust never dup'd, so this int is the ONLY reference. The old comment
        //                      above says so outright: "the int leaks at the kernel level — accepted
        //                      for this rare fault edge". It is no longer accepted.
        // The double-start guard returns EARLY, before detachFd, so that path never reaches here and
        // cannot double-close a fd owned by a live loop.
        //
        // adoptFd() wraps the raw int in a PFD purely so close() can own it; it is the documented way
        // to hand a detached fd back to something that will close it exactly once.
        try {
            android.os.ParcelFileDescriptor.adoptFd(tunFd).close()
            logi("TunnelController.start: original tun fd $tunFd closed (R1 ownership; started=$started)")
        } catch (t: Throwable) {
            // Never fatal: a failure to close leaves the pre-fix behaviour (a leaked fd), which is
            // strictly no worse than before. Logged rather than swallowed so it cannot become a
            // silent regression of the very defect this block fixes.
            loge("TunnelController.start: closing the original tun fd $tunFd FAILED", t)
        }

        return started
    }

    /**
     * ★ FIRST-CONTACT WARM-UP BEACON (#129 field bug 6). The resolver pool bootstraps LAZILY:
     * `StrictOrder` walks the upstream ladder serially and each DNSCrypt transport fetches +
     * Ed25519-verifies its provider cert on its FIRST exchange (`resolver/dnscrypt.rs`
     * `ensure_cert`) — so the first user query after a cold start pays (dead-rung timeout × ladder
     * position) + cert RTT before the first byte comes back: ~5.6 s measured on the AVD, ~12 s in
     * the field. The beacon pays that bill BEFORE the user does: a daemon thread spins until
     * `ResolverRuntime` configures the pool (a pre-configure resolve fails FAST against the empty
     * transport slate — measured `None` in microseconds), then drives the neutral [WARM_UP_QNAME]
     * root-NS question through the SAME global resolver the tun loop serves from, iterating until
     * one answer lands. Each iteration re-drives the cert fetch, so a lost cert UDP reply (killed
     * by the per-query deadline) is simply re-sent next spin — the loop converges the moment any
     * rung completes cert + exchange, and every later query (the user's first contact included)
     * rides the warm cert cache.
     *
     * Fail-open everywhere: a null wire builder (missing/faulted `.so`), a spin past
     * [WARM_UP_DEADLINE_MS], an interrupt, or a [stop] mid-spin (live-holder cleared ⇒ the loop
     * condition dies) all end the beacon silently. It can only ever ADD warmth — never gate,
     * never block, never break the datapath.
     */
    private fun launchWarmUpBeacon() {
        Thread(
            {
                val query =
                    TortaCore.buildQuery(WARM_UP_QNAME, WARM_UP_QTYPE) ?: return@Thread
                val spinStart = SystemClock.elapsedRealtime()
                val deadline = spinStart + WARM_UP_DEADLINE_MS
                while (live === this@TunnelController &&
                    SystemClock.elapsedRealtime() < deadline
                ) {
                    if (TortaCore.resolve(query) != null) {
                        logi(
                            "TunnelController warm-up beacon: resolver cold path warmed in " +
                                "${SystemClock.elapsedRealtime() - spinStart} ms"
                        )
                        return@Thread
                    }
                    try {
                        Thread.sleep(WARM_UP_SPIN_MS)
                    } catch (e: InterruptedException) {
                        return@Thread
                    }
                }
            },
            "TortaWarmUpBeacon",
        ).apply {
            isDaemon = true
            start()
        }
    }

    /**
     * **Stop the loop.** Signals the Rust stop flag, joins the loop thread (within the Rust poll
     * timeout + join window — `tunnel/mod.rs` `POLL_TIMEOUT_MILLIS` + `handle.join()`), and drops
     * the `OwnedFd` (closes the DUP). The original detached int (Kotlin-side) is never touched by
     * Rust — R1's "neither side closes the original int" holds for the whole lifecycle.
     *
     * Also unbinds the [VpnProtectCallback] so any in-flight resolver transport `connect()` after
     * the join fails fast (R2) rather than opening an unprotected socket against a torn-down VPN.
     * Idempotent + crash-firewalled.
     */
    @Synchronized
    fun stop() {
        // N6c: retire the live-holder FIRST — bridge readers racing the teardown fall to the honest
        // DORMANT null instead of snapshotting a controller whose loop thread is being joined.
        //
        // IDENTITY GUARD (#64 headless-tunnel bug): `@Synchronized` locks per-INSTANCE, so a stale
        // stop() on the OLD controller (late teardown racing a service restart) used to run AFTER
        // the new controller published itself — `live = null` clobbered the NEW holder and the
        // unbinds stripped the NEW tunnel's shared protect callback. isDatapathLive() then read
        // false forever: ModulesStateLoop never promoted (no pool-configure fan-out, no rotation,
        // no stopCounter refresh) and ModulesService died ~96s later while the Rust tun loop kept
        // forwarding headless. Only the instance that OWNS the holder may retire it or unbind the
        // shared callbacks; a stale stop() still joins its own (already-dead) Rust loop and exits.
        val ownsHolder = live === this
        if (ownsHolder) {
            live = null
        }
        // A7 — print the loop's OWN counters BEFORE `rust.stop()` joins the thread, because after the
        // join the snapshot is gone and the session's traffic can no longer be attributed.
        //
        // The counters (`tunnel/mod.rs`: packets read, `:53` intercepted-and-parsed, UDP flows
        // accepted, queries answered in-loop) have always existed and have never been printed on
        // device, which is why a zero-resolution measurement could not distinguish "packets never
        // reached the tun" from "packets reached it and were never classified as DNS". That
        // distinction is the whole of the egress question; without it an ON-arm reading is
        // unattributable. Counts-only (T20): no qname, no address.
        //
        // Wrapped and never rethrown — a telemetry line that can throw during teardown would corrupt
        // the very run it exists to measure, and `snapshot()` is already documented as null-on-fault.
        try {
            logi("A7 STATS at stop: tunnel=${snapshot()} forwarder=${forwarderSnapshot()}")
        } catch (t: Throwable) {
            loge("A7 STATS at stop: probe threw — reported, teardown continues", t)
        }
        try {
            rust.stop()
        } catch (t: Throwable) {
            loge("TunnelController.stop: rust.stop threw — best-effort teardown continues", t)
        }
        if (!ownsHolder) {
            logi("TunnelController.stop: stale controller — own Rust loop joined, live holder + shared callbacks left to the current owner")
            return
        }
        // Unbind AFTER the loop thread has joined, so a late in-flight protectFd (racing the join)
        // still sees a bound service. The join is synchronous in rust.stop(); once it returns the
        // loop thread is gone and no more protectFd calls originate from it. Same window for the
        // uid resolver — a flow task's last uidOf must not race an unbound ConnectivityManager.
        vpnProtectCallback.unbind()
        uidResolver.unbind()
        logi("TunnelController.stop: Rust tun loop stopped + protect-callback unbound")
    }

    /**
     * A counts-only telemetry snapshot (T20 — no qname, no IP). Wraps the Rust `TunnelController.snapshot`
     * (`tunnel/mod.rs:285`); returns `null` on any UniFFI/panic fault (the caller — a diagnostic
     * surface — must never crash on telemetry). See [TunnelSnapshot] for the fields.
     */
    fun snapshot(): TunnelSnapshot? =
        try {
            rust.snapshot()
        } catch (t: Throwable) {
            loge("TunnelController.snapshot: threw — returning null", t)
            null
        }

    /**
     * N6c · The netstack forwarder's counts-only telemetry (T20 — no address, no qname). Wraps the
     * Rust `TunnelController.forwarderSnapshot` (`tunnel/mod.rs` — armed from `netstack_enabled()`,
     * counters from the always-compiled `ForwarderStats`). `null` on any UniFFI/panic fault (the
     * SLINT bridge reader must never crash the app on telemetry).
     */
    fun forwarderSnapshot(): ForwarderSnapshot? =
        try {
            rust.forwarderSnapshot()
        } catch (t: Throwable) {
            loge("TunnelController.forwarderSnapshot: threw — returning null", t)
            null
        }

    /**
     * ★ #47 N8 · The netstack forwarder's PER-FLOW docket — one row per flow live right now, where
     * [forwarderSnapshot] gives only the aggregate. Same T20 discipline: a row carries the folded
     * CAKE key, its tin and the engine's numbers (cwnd/bytes/rtt/stalls/age), and NEVER an address,
     * port or hostname.
     *
     * An EMPTY list is honest in three different situations the reader must not conflate — a base
     * (non-netstack) `.so`, an armed-but-never-started forwarder, and a live forwarder with no flows
     * this instant. Use `forwarderSnapshot()?.live` to tell them apart.
     *
     * The list is CAPPED (`FLOW_DOCKET_CAP` = 256 in Rust); compare `size` against
     * `forwarderSnapshot()?.activeFlows` to render "N of M" instead of implying completeness.
     *
     * `null` on any UniFFI/panic fault — same crash-firewall law as the aggregate above: a telemetry
     * surface must never take the app down.
     */
    fun forwarderFlowDocket(): List<ForwarderFlowRow>? =
        try {
            rust.forwarderFlowDocket()
        } catch (t: Throwable) {
            loge("TunnelController.forwarderFlowDocket: threw — returning null", t)
            null
        }

    /**
     * `true` while the Rust loop thread is running. Crash-firewalled to `false` (the safe default —
     * a diagnostic surface reading `false` is honest; a crash propagating is not).
     */
    fun isRunning(): Boolean =
        try {
            rust.isRunning()
        } catch (t: Throwable) {
            loge("TunnelController.isRunning: threw — returning false", t)
            false
        }
}
