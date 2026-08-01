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

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import android.content.Context
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.telephony.TelephonyManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.BindingCache
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.CacheResult
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.LockedBinding
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.NetworkFingerprint
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.TransportKind
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import uniffi.torta_core.SolverBindingRow
import uniffi.torta_core.SolverBindingStore
import uniffi.torta_core.SolverTransport
import javax.inject.Inject
import javax.inject.Named
import android.os.Build
import android.net.wifi.WifiInfo

/**
 * #19 G10 — the Stage-E Solver's **BindingCache armed + durably mirrored** (RAM ⊗ NAND): the FIRST live
 * consumer of [BindingCache] (the #17 re-audit measured it never constructed — a mirror without a consumer
 * would be dead weight, so both arm TOGETHER here), fronted by the Rust `solver-bindings` DurableTier
 * record (`solver_bindings.rs` [SolverBindingStore] — the Inu FP2 Object template) so a solved network
 * survives process death: rehydrate ONCE at the engine-start edge, gentle write-through on the two
 * control-plane mutation points (commit / invalidate — NEVER a per-query write, F16).
 *
 * ## What "solved" means TODAY (the honest Stage-B scope)
 * The full 1–2 s `transport × resolver × relay` race ([pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.Solver.solveBinding])
 * stays SHADOW — live racing is gated on the per-upstream governor map + the Stage-C arm (#85), and this
 * manager NEVER steers the datapath (the #19 deliverable: datapath behavior unchanged). What IS live is the
 * **observed binding**: each committed rotation swap already reachability-probes its pool over real TCP
 * ([RotationManager.rotateOnce] → `probeReachable`, fastest-first), so the fastest reachable resolver + its
 * measured RTT is ground truth "this binding works on this network, this well" — THAT is what commits into
 * the cache under the current [NetworkFingerprint]. When the live race arms (Stage C), it inherits this
 * manager, the cache, and the durable record unchanged — only the commit source upgrades.
 *
 * ## The three verbs (all control-plane, all fail-open)
 *  - [start] — engine-start edge ([RotationManager.start], after the master-switch gate): open the store
 *    over the SAME `runtime_tier` root every durable pillar shares (G9 one-root law), rehydrate, admit
 *    FRESH-only through [BindingCache.rehydrateFrom] (a binding that expired while the process was dead
 *    misses exactly as in RAM — never serve a dead binding from NAND).
 *  - [onPoolApplied] — a rotation swap COMMITTED: fingerprint the live network (the impure Android read
 *    [NetworkFingerprint]'s pure producer deliberately defers to this manager), log the prior
 *    [BindingCache.lookup] hit/miss (the warm-reuse observability), commit the observed binding,
 *    write-through the full row set.
 *  - [onPoolUnreachable] — a rotation pick found ZERO reachable servers: the cached binding for THIS
 *    network is suspect → [BindingCache.invalidate] + write-through, so the next entry re-races instead
 *    of instant-reusing a rotted path.
 *
 * ## Privacy (T20)
 * Only the opaque [NetworkFingerprint.key] (an FNV-1a digest — no raw SSID) and resolver ids ever reach
 * the log/record. The SSID/carrier reads stay inside [currentFingerprint] and die there. On API 29+
 * without location permission Android hands `<unknown ssid>` — [NetworkFingerprint.of] degrades the
 * identity to the gateway alone by design (still a stable per-LAN key).
 *
 * ## No root, no `@Provides` (ADR-001)
 * `@ModulesServiceScope` + `@Inject` ctor — auto-supplied by the ModulesService subcomponent, never
 * hand-`new`. [RotationManager] receives this instance constructor-injected (never a second instance).
 */
@ModulesServiceScope
class SolverCacheManager @Inject constructor(
    private val pathVars: dagger.Lazy<PathVars>,
    @Named(DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: SharedPreferences,
) {

    /** THE consumer (#17: previously never constructed) — the pure LRU+TTL policy judge. RAM tier. */
    private val cache = BindingCache()

    /** The Rust durable mirror, or null until [start] (or when the .so/store open failed — fail-open). */
    @Volatile
    private var store: SolverBindingStore? = null

    /** Serializes the three control-plane verbs (start edge vs rotation IO thread). Tiny critical sections. */
    private val lock = Any()

    /**
     * Engine-start edge: open the `solver-bindings` durable record, rehydrate, admit FRESH-only into the
     * cache. Idempotent (a second start edge re-uses the open store; the cache admits over itself with
     * last-writer-wins). Gated on the solver flag ([TortaeKeys.DNS_ENGINE_SOLVER], DEFAULT ON — the noob
     * "auto-heal" enhancer); off ⇒ silently idle (no store, no writes). NEVER throws (fail-open).
     */
    fun start() {
        synchronized(lock) {
            try {
                if (!defaultPreferences.getBoolean(TortaeKeys.DNS_ENGINE_SOLVER, true)) return
                val appDataDir = pathVars.get().appDataDir
                val durableDir = appDataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR
                val s = store ?: SolverBindingStore(durableDir).also { store = it }
                val nowMs = System.currentTimeMillis()
                val rows = s.rehydrate()
                val admitted = cache.rehydrateFrom(rows.map { it.fpKey to it.toLockedBinding() }, nowMs)
                // #133 — the rehydrate line on query-solver.log (counts only, T20): rows read from NAND vs
                // rows admitted (the difference = stale corpses dropped by the in-RAM TTL law).
                PillarLog.event(
                    appDataDir,
                    PillarLog.Pillar.SOLVER,
                    "rehydrate",
                    "rows" to rows.size,
                    "admitted" to admitted,
                )
                if (admitted > 0) {
                    logi("SolverCacheManager — $admitted solved network(s) rehydrated (warm re-entry armed)")
                }
            } catch (e: Throwable) {
                // Fail-open: a missing .so / IO fault leaves the cache RAM-only (the pre-#19 behavior).
                logi("SolverCacheManager start — durable mirror unavailable, RAM-only (${e.javaClass.simpleName})")
            }
        }
    }

    /**
     * A rotation swap COMMITTED ([RotationManager.rotateOnce] APPLY path) — commit the OBSERVED binding:
     * the fastest reachable resolver of the just-applied pool + its measured TCP RTT, under the current
     * network's fingerprint. Logs the prior lookup hit/miss FIRST (the warm-reuse observability the AVD
     * prove reads). `lockedAtMs` provenance is preserved when the same resolver re-commits (a re-observation
     * of the SAME binding is not a new lock); a different resolver is a fresh lock. Write-through follows
     * (control-plane, F16). NEVER throws.
     */
    fun onPoolApplied(resolverId: String, rttMs: Int, nowMs: Long) {
        synchronized(lock) {
            try {
                if (!defaultPreferences.getBoolean(TortaeKeys.DNS_ENGINE_SOLVER, true)) return
                val fp = currentFingerprint()
                val prior = cache.lookup(fp, nowMs)
                val priorBinding = (prior as? CacheResult.Hit)?.binding
                val binding = LockedBinding(
                    transport = TransportKind.DNSCRYPT, // the only buildable transport today (RotationSelector.kt:60-63)
                    resolverId = resolverId,
                    relayId = null,
                    tunedCwnd = 0, // observed-only commit: no live race, no brain tune yet (Stage-C upgrades)
                    tunedCodelTargetMs = 0L,
                    score = rttMs.toDouble(), // LOWER-better (§4 governor convention) — the measured probe RTT
                    lockedAtMs = if (priorBinding?.resolverId == resolverId) priorBinding.lockedAtMs else nowMs,
                    lastHealthyAtMs = nowMs,
                )
                cache.commit(fp, binding)
                persistThrough()
                PillarLog.event(
                    pathVars.get().appDataDir,
                    PillarLog.Pillar.SOLVER,
                    "commit",
                    "fp" to fp.key,
                    "resolver" to resolverId,
                    "rtt_ms" to rttMs,
                    "warm_hit" to (prior is CacheResult.Hit),
                    "cached" to cache.size(),
                )
            } catch (e: Throwable) {
                logi("SolverCacheManager commit skipped (${e.javaClass.simpleName})")
            }
        }
    }

    /**
     * A rotation pick found ZERO reachable servers on this network ([RotationManager.rotateOnce] fail-safe
     * layer 2 keep-current branch) — the cached binding for THIS fingerprint is suspect: drop it so the next
     * entry onto this network re-races instead of instant-reusing a rotted path, and write the removal
     * through. A no-op when nothing was cached. NEVER throws.
     */
    fun onPoolUnreachable(nowMs: Long) {
        synchronized(lock) {
            try {
                if (!defaultPreferences.getBoolean(TortaeKeys.DNS_ENGINE_SOLVER, true)) return
                val fp = currentFingerprint()
                val removed = cache.invalidate(fp) ?: return
                persistThrough()
                PillarLog.event(
                    pathVars.get().appDataDir,
                    PillarLog.Pillar.SOLVER,
                    "invalidate",
                    "fp" to fp.key,
                    "resolver" to removed.resolverId,
                    "cached" to cache.size(),
                )
            } catch (e: Throwable) {
                logi("SolverCacheManager invalidate skipped (${e.javaClass.simpleName})")
            }
        }
    }

    /**
     * GENTLE write-through of the FULL cache to the durable record — called ONLY from the two mutation
     * verbs above (commit / invalidate: the control plane; the no-hot-path-write law F16). A null store
     * (solver off / open failed) is a silent RAM-only no-op; a refused write is best-effort (the next
     * control-plane event retries the full set).
     */
    private fun persistThrough() {
        val s = store ?: return
        s.persist(cache.snapshotEntries().map { (key, binding) -> binding.toRow(key) })
    }

    /**
     * The IMPURE Android read the pure [NetworkFingerprint.of] producer defers to this manager: transport
     * class + SSID/carrier + default-route gateway → the opaque per-network key. Reads the UNDERLYING
     * network (skipping our own VPN tun — its synthetic routes would collapse every real network onto one
     * key). Any fault ⇒ [NetworkFingerprint.NONE] (the single shared no-identity sentinel — never thrashes
     * the cache). The raw SSID/carrier never leaves this method (T20).
     */
    @Suppress("DEPRECATION") // WifiManager.connectionInfo + ConnectivityManager.allNetworks: functional on minSdk..36
    private fun currentFingerprint(): NetworkFingerprint {
        try {
            val ctx = App.instance.applicationContext
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return NetworkFingerprint.NONE
            // Prefer the active network unless it is our own VPN; then fall back to the first
            // internet-capable non-VPN network (the underlying carrier of the tun).
            val active = cm.activeNetwork
            val activeCaps = active?.let { cm.getNetworkCapabilities(it) }
            val network = if (active != null && activeCaps != null &&
                !activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            ) {
                active
            } else {
                cm.allNetworks.firstOrNull { n ->
                    val caps = cm.getNetworkCapabilities(n)
                    caps != null &&
                        !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                }
            } ?: return NetworkFingerprint.NONE
            val caps = cm.getNetworkCapabilities(network) ?: return NetworkFingerprint.NONE
            val linkType = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ->
                    NetworkFingerprint.Companion.LinkType.WIFI
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ->
                    NetworkFingerprint.Companion.LinkType.CELLULAR
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ->
                    NetworkFingerprint.Companion.LinkType.ETHERNET
                else -> NetworkFingerprint.Companion.LinkType.UNKNOWN
            }
            val gateway = cm.getLinkProperties(network)?.routes
                ?.firstOrNull { it.isDefaultRoute && it.gateway != null }
                ?.gateway?.hostAddress
            val ssidOrCarrier = when (linkType) {
                // WifiManager.connectionInfo is deprecated at API 31. The supported replacement is
                // NetworkCapabilities.transportInfo, which is already in scope here as `caps` for
                // the very network this fingerprint describes -- and that is strictly MORE correct
                // than the old call, which asked the WifiManager about the CURRENT Wi-Fi connection
                // regardless of which network `caps` belongs to. On a device where those differ the
                // old code fingerprinted one network with another's SSID.
                NetworkFingerprint.Companion.LinkType.WIFI ->
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        (caps.transportInfo as? WifiInfo)?.ssid
                    } else {
                        @Suppress("DEPRECATION")
                        (ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager)
                            ?.connectionInfo?.ssid
                    }
                NetworkFingerprint.Companion.LinkType.CELLULAR ->
                    (ctx.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager)
                        ?.networkOperatorName
                else -> null
            }
            return NetworkFingerprint.of(linkType, ssidOrCarrier, gateway)
        } catch (e: Throwable) {
            return NetworkFingerprint.NONE
        }
    }

    // ---- the FFI row mapping (LockedBinding ⇄ SolverBindingRow, field-for-field, lossless) ----

    private fun LockedBinding.toRow(fpKey: String) = SolverBindingRow(
        fpKey = fpKey,
        transport = transport.toFfi(),
        resolverId = resolverId,
        relayId = relayId ?: "", // Option folded to "" (one codec shape, solver_bindings.rs)
        tunedCwnd = tunedCwnd,
        tunedCodelTargetMs = tunedCodelTargetMs,
        score = score,
        lockedAtMs = lockedAtMs,
        lastHealthyAtMs = lastHealthyAtMs,
    )

    private fun SolverBindingRow.toLockedBinding() = LockedBinding(
        transport = transport.fromFfi(),
        resolverId = resolverId,
        relayId = relayId.ifEmpty { null },
        tunedCwnd = tunedCwnd,
        tunedCodelTargetMs = tunedCodelTargetMs,
        score = score,
        lockedAtMs = lockedAtMs,
        lastHealthyAtMs = lastHealthyAtMs,
    )

    private fun TransportKind.toFfi(): SolverTransport = when (this) {
        TransportKind.DNSCRYPT -> SolverTransport.DNSCRYPT
        TransportKind.DOH -> SolverTransport.DOH
        TransportKind.DOH3 -> SolverTransport.DOH3
        TransportKind.DOQ -> SolverTransport.DOQ
    }

    private fun SolverTransport.fromFfi(): TransportKind = when (this) {
        SolverTransport.DNSCRYPT -> TransportKind.DNSCRYPT
        SolverTransport.DOH -> TransportKind.DOH
        SolverTransport.DOH3 -> TransportKind.DOH3
        SolverTransport.DOQ -> TransportKind.DOQ
    }
}
