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

import android.content.SharedPreferences
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.inject.Inject
import javax.inject.Named
import kotlin.random.Random
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import pillar.kuma_saimono.libumdnscrypt.BuildConfig
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.data.dns_rules.DnsSingleRuleRecords
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.vpn.ResourceRecord
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils

/**
 * ModulesService-scoped owner of the P7 Wave-3 **Stage-0 shadow resolver** (the "shadow brain").
 *
 * It mirrors [MonokumaDnsEngineManager]'s lifecycle exactly — configured when DNSCrypt goes
 * RUNNING, torn down (or retargeted to a public DNSCrypt upstream if the user runs it standalone)
 * when DNSCrypt stops — but it governs **nothing**. For every answer the real datapath produces
 * (delivered via `ServiceVPN.dnsResolved` → [shadowCompare]) it fires the SAME question into the
 * BUILT-but-unwired Rust resolver ([TortaCore.resolve]), parses the wire reply, and records whether
 * the two agree plus the shadow's own resolve latency. The real user answer is never read back,
 * never mutated, never delayed.
 *
 * **What "agreement" means (and what it deliberately does NOT mean).** Independent recursive
 * resolvers legitimately hand back DIFFERENT CDN/GeoDNS IPs for the same name, so byte-identical IP
 * equality is the WRONG metric — it would manufacture endless false disagreements. The shadow
 * therefore validates a weaker, honest claim: *"the native resolver resolves this name consistently
 * with the real path"* — i.e. the two agree on the **Rcode class** (NOERROR-with-answer vs a
 * name/data denial) AND on **existence parity** (both produced a non-empty answer of the real
 * record's address family). A cheap optional exact-IP sub-counter is kept for observability, but
 * the headline metric is the lenient one. The compare is also **family-gated**: each real
 * [ResourceRecord] carries exactly one single-family IP literal (`dns.c` emits one `dns_resolved`
 * per answer record), so we only run the shadow qtype that matches that family — never an A-shadow
 * against an AAAA-real (and vice-versa), which on a dual-stack host would deterministically score a
 * spurious disagreement.
 *
 * **Bullet-proof contract.** A throw, a null, a slow resolve, or an unconfigured runtime is a
 * *non-event*: counted and swallowed, never surfaced into the datapath. [shadowCompare] hands every
 * unit of work to [dispatcherIo] and returns instantly, so it can NEVER block the native tun
 * callback thread (`resolver::resolve` is a synchronous `block_on` up to the resolver's own
 * deadline).
 *
 * **Egress is bounded.** Each `dnsResolved` could otherwise `launch` an unbounded shadow resolve,
 * and a DNS flood (amplified by multi-record rrsets) would saturate the IO dispatcher and spew
 * external egress. Two guards cap it: a [shadowSlots] [Semaphore] (`tryAcquire`, max
 * [MAX_INFLIGHT]) that DROPS the shadow when full — never queues — and a short [recentQnames]
 * conflation window so the same qname is not re-shadowed back-to-back. A dropped shadow is a
 * counted, intentional non-event.
 *
 * No root, no `@Provides`: the `@ModulesServiceScope` + `@Inject` ctor is auto-supplied by the
 * ModulesService subcomponent (same as the engine), and — crucially — the SAME single instance is
 * shared between `ServiceVPN` (shadow seam, parent) and `ModulesStateLoop` (lifecycle, child via
 * LogReaderSubcomponent), so the configure edge and the compare seam can never split.
 */
@ModulesServiceScope
@ExperimentalCoroutinesApi
class ResolverRuntime
@Inject
constructor(
    @Named(CoroutinesModule.DISPATCHER_IO) private val dispatcherIo: CoroutineDispatcher,
    private val pathVars: dagger.Lazy<PathVars>,
    @Named(DEFAULT_PREFERENCES_NAME) private val defaultPreferences: SharedPreferences,
) {

    private val coroutineScope by lazy {
        CoroutineScope(
            SupervisorJob() +
                dispatcherIo +
                CoroutineName("ResolverRuntime") +
                CoroutineExceptionHandler { _, t ->
                    loge("ResolverRuntime uncaught exception", t)
                }
        )
    }

    /**
     * Gate for [shadowCompare]: true only once [TortaCore.configureResolver] installed a usable
     * pool. Until then `resolve` always returns null (fall-through) and the shadow would silently
     * test nothing, so the compare is skipped entirely (no wasted egress, no false
     * "agreement"). @Volatile so the tun-thread read in [shadowCompare] sees the IO-thread
     * configure/shutdown write.
     */
    @Volatile private var configured = false

    /**
     * ★ SOVEREIGN REWIRE — the runtime fallback flag. `true` when [maybeFallbackToGo] detected that
     * the Rust DNSCrypt transport was failing under load (transport_miss + panics rate over threshold)
     * and flipped the live pool to the Go loopback (MODE 1). @Volatile so the tun-thread production
     * `torta_resolve` path reads the latest decision. Reset to `false` on every DNSCrypt RUNNING edge
     * (a fresh configure gives Rust a clean chance) and on [onDnsCryptStopped]. The C-level per-query
     * fallback (udp.c:497, r≤0 → Go sendto) is the IMMEDIATE safety net that NEVER depends on this
     * flag; this flag swaps the WHOLE pool to Go when Rust is structurally failing, not just declining
     * one query.
     */
    @Volatile private var fallbackActive = false

    /**
     * ★ SOVEREIGN REWIRE — the periodic fallback-detector coroutine job. Launched by
     * [startFallbackCheckLoop] on the DNSCrypt RUNNING edge (native-arm-only) and cancelled on
     * STOPPED. Held so [onDnsCryptStopped] can cancel it deterministically (no leaked checker).
     */
    @Volatile private var fallbackCheckJob: kotlinx.coroutines.Job? = null

    // ---- Shadow tallies. Plain atomics; published as a compact periodic log (no qname, T20). ----
    // Counts EVERY call into shadowCompare BEFORE any gate — the disambiguator for the soak: a
    // non-zero
    // seamHits with zero compares proves "the seam fires, the resolve is dark" (vs the seam never
    // firing).
    private val shadowSeamHits = AtomicLong(0)
    private val comparisons =
        AtomicLong(0) // record-level compares actually run (one per gated qtype)
    private val agreements =
        AtomicLong(0) // LENIENT agreement: Rcode class + existence parity match
    private val disagreements =
        AtomicLong(0) // shadow disagrees with the real path (class/parity differ)
    private val exactMatches =
        AtomicLong(0) // optional sub-counter: the real IP literal was ALSO present
    private val resolverNulls = AtomicLong(0) // resolve() == null → fall-through, a NON-event
    private val shadowErrors = AtomicLong(0) // any throw inside the off-thread compare, swallowed
    private val shadowsDropped =
        AtomicLong(0) // shadow declined (in-flight cap or conflation), a non-event
    // Σ(ABSOLUTE shadow resolve latency). NOT a delta vs the real path — the real-path timing is
    // not
    // available at this seam — so it is named honestly: divide by `comparisons` for the mean shadow
    // ms.
    private val shadowLatencySumMs = AtomicLong(0)

    // ---- P7 2e qname-seam health (a SECOND, REDUNDANT live trigger). DISTINCT from the rr-seam's
    // agree/disagree, which are meaningless here: query.log carries NO answer IPs, so there is
    // nothing
    // to byte-compare — the only honest signal is resolver-health (did the SHADOW resolve this
    // qname?).
    // The qname overload is driven by [QueryLogTailer], which tails dnscrypt-proxy's query.log.
    // This is
    // NOT a replacement for a "dark" rr-seam — the rr-seam DOES fire in DNSCrypt mode too
    // (s->udp.dest
    // STAYS 53 after the socket-level loopback->5354 redirect: udp.c:326 records the dest from the
    // ORIGINAL packet BEFORE udp.c:449-457 rewrites only the sendto target). Both seams fire and
    // share
    // one egress pool; this one is redundant qname coverage, valuable because query.log carries the
    // RETURNCODE class for the lenient parity bonus. (Corrected per
    // [[shadow-seam-unreachable-dnscrypt-mode]],
    // REFUTED 2026-06-19 — the earlier "provably dark" claim was a shadow-side gate, not
    // unreachability.)
    private val qnameResolved = AtomicLong(0) // shadow got NOERROR + a non-empty A/AAAA answer
    private val qnameFailed = AtomicLong(0) // shadow got a denial / empty for this qname
    // OPTIONAL lenient return-code-class parity bonus (observability-only, never the headline
    // metric):
    // does the SHADOW's positive/denial verdict match the real RETURNCODE class from the query.log
    // line?
    private val qnameRcodeAgree = AtomicLong(0)
    private val qnameRcodeDisagree = AtomicLong(0)
    // ★ E-FIX round-1 (bucket coherence): the qname seam gets its OWN compare + latency tallies.
    // It used to bump the rr-seam's `comparisons`/`shadowLatencySumMs` while scoring its outcomes
    // into qnameResolved/qnameFailed — so in DNSCrypt-VPN mode (where the qname seam dominates) the
    // periodic line read `compares=170 agree=0 … disagree=0` with buckets that could never sum (the
    // round-1 20:34:35.364 evidence). Invariants now: agreements+disagreements == comparisons (rr
    // seam) and qnameResolved+qnameFailed == qnameCompares (qname seam) — each seam's outcome
    // buckets sum to its OWN compare count, and each mean latency divides its own sum.
    private val qnameCompares = AtomicLong(0)
    private val qnameLatencySumMs = AtomicLong(0)

    /**
     * In-flight cap (FIX 4): at most [MAX_INFLIGHT] concurrent shadow resolves. `tryAcquire` so a
     * full pool DROPS the shadow (counted in [shadowsDropped]) instead of queueing — a queue would
     * just defer the same egress flood. Released in a `finally` so a throw can never leak a permit.
     */
    private val shadowSlots = Semaphore(MAX_INFLIGHT)

    /**
     * Short conflation/dedupe window (FIX 4): qname → last-shadowed uptime millis. A name seen
     * again within [CONFLATE_WINDOW_MS] is NOT re-shadowed (a tight burst of the same lookup is one
     * shadow, not N). Bounded: pruned opportunistically and hard-capped at [CONFLATE_MAX] entries
     * so it cannot grow without bound under a flood of distinct names.
     */
    private val recentQnames = ConcurrentHashMap<String, Long>()

    /**
     * P7 2e — the DEBUG-only [QueryLogTailer] this runtime OWNS and drives. It tails
     * dnscrypt-proxy's `query.log` and feeds each resolved qname into [shadowCompare] (the qname
     * overload) via the callback below. Lazy because it is only ever started behind the DEBUG-gated
     * [onDnsCryptStarted]; its lifecycle is bound to this runtime's start/stop, which spans the
     * whole ModulesService, NOT the LogReaderLoop — so a log-loop idle teardown can never silently
     * kill the tail mid-soak. The callback `(qname, returnCode) -> shadowCompare(qname,
     * returnCode)` is the sole inter-file contract with layer 2: the tailer parses lines and the
     * qname is used ONLY to drive the shadow (T20).
     */
    private val queryLogTailer by lazy {
        QueryLogTailer(pathVars, dispatcherIo) { qname, returnCode ->
            shadowCompare(qname, returnCode)
        }
    }

    /**
     * DNSCrypt reached RUNNING: (re)configure the native resolver against the live upstream set.
     *
     * **P7 Wave 3 Stage-1 — this is THE pool-config seam for the live datapath arm (the
     * `[pool-arm-proof]` keystone).** The native pool that `torta_resolve` (lib.rs:699) resolves
     * through is built ONLY by [configureFromUpstreams] → [TortaCore.configureResolver]
     * (TortaCore.kt:289 → `nativeResolverConfigure` lib.rs:267 → `resolver::configure` lib.rs:281).
     * If this never runs, `torta_resolve` finds an EMPTY pool and returns `0` ⇒ the udp.c bridge
     * falls through to the unchanged `sendto` ⇒ the arm is a harmless NO-OP (DNS never breaks, but
     * the native resolver answers nothing). For the Socio's arm (`RESOLVER_NATIVE_ENABLED=true`,
     * TortaeKeys.java:165) to actually resolve, THIS configure must have run on the live
     * RUNNING edge — and it must run in a **release** build, not only the debug shadow.
     *
     * The two concerns are now separated:
     * - **the pool configure** (cheap, install-only — a config-replace that opens no extra egress
     *   beyond the transports it builds; the do53 arm is loopback-only) runs whenever EITHER the
     *   debug shadow harness is active OR the native datapath arm is on ([isNativeArmed]). This is
     *   what makes the armed `torta_resolve` resolve in release.
     * - **the debug-only shadow harness** (the [queryLogTailer] live qname seam + the duplicate
     *   egress it drives) stays strictly `BuildConfig.DEBUG`-gated — release never tails query.log
     *   nor double-resolves.
     *
     * Fail-safe is preserved either way: a `null` summary leaves the pool unconfigured ⇒
     * `torta_resolve` returns `0` ⇒ the udp.c bridge runs the unchanged dnscrypt `sendto`. Never
     * throws into the caller.
     *
     * ⚠️ REMAINING ARM-STEP (one line, owned by the `ModulesStateLoop` author — SAFE either way):
     * the call sites that invoke this method (ModulesStateLoop.java:388 RUNNING, :416 stop,
     * :282/:302 standalone) are today wrapped in `if (BuildConfig.DEBUG)`. To let the release arm
     * reach this configure, relax that one guard to `if (BuildConfig.DEBUG ||
     * defaultPreferences.getBoolean(RESOLVER_NATIVE_ENABLED, false))` (mirror at the stop edges).
     * Until then this method is arm-aware but only entered in debug; an un-entered configure leaves
     * the pool empty ⇒ `torta_resolve` returns 0 ⇒ fall-through (DNS never breaks). The arm
     * therefore composes with this seam the moment that single guard is relaxed.
     */
    @Synchronized
    fun onDnsCryptStarted() {
        try {
            // P7 Wave 3 Stage-1: configure the pool when EITHER the debug shadow OR the native
            // datapath arm
            // wants it. In a pure-release un-armed install both are false → stay idle (no pool, no
            // egress) →
            // byte-identical, exactly as today. The native arm flips this true so the armed
            // torta_resolve
            // has a live pool to resolve through. (Read crash-safe; a pref-read fault degrades to
            // "not armed".)
            val nativeArmed = isNativeArmed()
            if (!BuildConfig.DEBUG && !nativeArmed) {
                // Neither consumer wants the pool — leave it un-configured. shadowCompare is
                // release-inert
                // anyway, and an un-armed native datapath never calls torta_resolve. No pool, no
                // egress.
                configured = false
                fallbackActive = false
                logi("ResolverRuntime idle — neither the debug shadow nor the native arm is active")
                return
            }
            // ★ SOVEREIGN REWIRE — reset the runtime fallback on every RUNNING edge so a fresh
            // configure gives the Rust transport a clean chance (the previous fallback decision was
            // made against a prior pool/state that a stop/start has since replaced).
            fallbackActive = false
            // Reconfigure on every RUNNING edge — the port pref may have changed, and a
            // re-configure
            // installs a fresh pool/cache (the native side is idempotent; a re-configure replaces).
            val summary = configureFromUpstreams(dnsCryptRunning = true)
            if (summary != null) {
                configured = true
                logi(
                    "ResolverRuntime pool configured (DNSCrypt running; nativeArmed=$nativeArmed): $summary"
                )
                // P12 — push the user's dnsmasq Expert-toggle prefs into the resolver's
                // process-global flags
                // now that a fresh pool/cache is installed (same process + lifecycle as configure).
                // This is the
                // documented "resolver picks the prefs up on the next DNSCrypt start" contract.
                // Crash-safe.
                applyDnsmasqTogglesFromPref()
                // K5 D09 — drive the LIVE resolver from the typed DNSCrypt config authority on the
                // same edge (DNS64 always; static sdns:// pins only when the user pinned servers —
                // with no pins the pool configured above is left untouched). Crash-safe.
                applyDnscryptConfigAuthority()
                // P12 RAM⊗NAND — rehydrate the durable answer cache into the fresh pool
                // (still-valid entries
                // only; an expired/corrupt/cold snapshot restores nothing). One NAND read at
                // configure, off the
                // hot path — so a stop/start or app restart starts WARM instead of cold. Crash-safe
                // (≥0).
                val restored = TortaCore.rehydrateCache(durableDir())
                if (restored > 0)
                    logi("ResolverRuntime cache rehydrated: $restored entries from NAND")
                // D30 (Rotation × RAM⊗NAND) — warm-start the fresh pool's RTT EWMA from the
                // durable rotation record's hints, ONCE after the configure succeeded (a fresh
                // pool starts unlearned). Control-plane; the default StrictOrder resolve path
                // never consults it — only the Fastest ranking reads the seeded stat.
                warmStartRtt()
                // ★ E-FIX r5 (R5-Q1) — arm the Rust query.log FEED from the toml [query_log]
                // enable (the SAME producer gate the Go proxy obeys), so foreign queries the
                // sovereign MODE-2 pool answers directly still land in cache/query.log (the
                // QUERY surface fed). Disarmed on the STOPPED edge. Crash-safe inside.
                armQueryFeedFromConfig()
                // ★ STAGE 2 (2026-07-04): the Phase-1 resolverStartLoopback(53) call is REMOVED. The
                // pure-Rust tunnel::TunnelController (started from ServiceVPN.startNative) intercepts
                // every :53 packet INLINE and answers via torta_resolve — there is no separate
                // loopback listener to bind (binding :53 failed anyway: "bind returned 0", privileged
                // port). The tun forwards system DNS to the tun-subnet sentinel 10.1.10.2 and the Rust
                // loop resolves it. The pool the configure above installed is exactly what the loop
                // calls into. No loopback bind, no conflicting datapath.
                // P7 2e — start the LIVE qname seam: tail dnscrypt-proxy's query.log and feed each
                // resolved name into the qname overload of shadowCompare. DEBUG-only (so release
                // never
                // tails nor shadows); the configure above runs in release for the native arm, but
                // the
                // duplicate-egress shadow harness is strictly debug-gated here for explicit DCE.
                if (BuildConfig.DEBUG) queryLogTailer.start()
                // ★ SOVEREIGN REWIRE — start the periodic fallback detector. Runs in RELEASE too
                // (when the native arm is active), not just DEBUG: the Rust transport is the
                // production default, so its health must be monitored in production. The loop is
                // bounded (cancels with the resolver scope on STOPPED) and best-effort — a check
                // fault is swallowed inside maybeFallbackToGo. Native-arm-only because an un-armed
                // install never calls torta_resolve, so there is no Rust load to monitor.
                if (nativeArmed) startFallbackCheckLoop()
            } else {
                // No usable transport could be built (e.g. TLS verifier not yet initialised, or the
                // loopback listener is plain Do53 which the encrypted-only resolver cannot target).
                // Stay un-configured → torta_resolve returns 0 → udp.c falls through to sendto
                // (fail-safe).
                // Never throws into the caller.
                configured = false
                fallbackActive = false
                logi("ResolverRuntime stayed idle — no usable upstream to configure")
            }
        } catch (e: Exception) {
            configured = false
            loge("ResolverRuntime onDnsCryptStarted", e)
        }
    }

    /**
     * P12 — push the user's dnsmasq Expert-toggle prefs into the resolver's process-global flags.
     * Runs in the resolver's OWN process at configure time (called from [onDnsCryptStarted] right
     * after a fresh pool installs), so this is exactly the "the resolver picks the prefs up on the
     * next DNSCrypt start" contract the
     * [pillar.kuma_saimono.libumdnscrypt.dns_engine.dashboard.DnsmasqDashboardFragment] documents.
     *
     * Each [TortaCore] setter is crash-proof + idempotent; the Rust globals already ship at the
     * privacy-first default, so even a fully-swallowed call leaves correct behaviour (the base
     * `.so` byte-identical). Every pref read is crash-safe (a read fault leaves the prior/default
     * flag). AGGREGATE flags only — no qname, no per-query state ever crosses this seam.
     */
    private fun applyDnsmasqTogglesFromPref() {
        try {
            val p = defaultPreferences
            // --- noob privacy pillars (default ON) ---
            TortaCore.setNeverForward(p.getBoolean(TortaeKeys.DNSMASQ_NEVER_FORWARD, true))
            TortaCore.setBogusPriv(p.getBoolean(TortaeKeys.DNSMASQ_BOGUS_PRIV, true))
            // cloak/block action — 3-way string (default nxdomain). "custom" has no IP-store yet ⇒
            // pass "" and
            // the Rust side safe-falls to NXDOMAIN (a deny, never a sink-to-nowhere). 0=NXDOMAIN
            // 1=ZeroSink 2=Custom.
            val cloak =
                try {
                    p.getString(TortaeKeys.DNSMASQ_CLOAK_ACTION, CLOAK_NXDOMAIN)
                } catch (e: Exception) {
                    CLOAK_NXDOMAIN
                } ?: CLOAK_NXDOMAIN
            val cloakAction =
                when (cloak) {
                    CLOAK_ZEROSINK -> 1
                    CLOAK_CUSTOM -> 2
                    else -> 0
                }
            TortaCore.setCloakAction(cloakAction, "")
            // rebind enforce — driven by the existing common "DNS rebind protection" toggle,
            // DEFAULT ON
            // (enforce). Same semantics as Rust `--stop-dns-rebind`: a public name → private IP is
            // DROPPED
            // (falls through to dnscrypt, never a forged answer). On by default so the live AVD
            // exercises it.
            TortaCore.setRebindEnforce(p.getBoolean(TortaeKeys.DNS_REBIND_PROTECTION, true))
            // CLIENT-DoH BOOTSTRAP SINKHOLE — deny the handful of names a browser uses to bootstrap
            // its OWN encrypted resolver. Without this, a browser with Secure DNS on hands DNS
            // visibility to its provider after ONE lookup and every pillar goes blind: MEASURED
            // 2026-08-01, a fully-rendered page produced ZERO ledger rows, the only rows for it
            // being three lookups of `brave.cloudflare-dns.com`. DEFAULT ON here for the same
            // reason the Expert knobs below are — the live AVD must exercise it — and the user can
            // disable it; the Rust side defaults OFF so an unarmed engine is byte-identical.
            TortaCore.setDohSinkhole(p.getBoolean(TortaeKeys.DNS_DOH_SINKHOLE, true))
            // --- Expert knobs (all DEFAULT ON so the live AVD exercises every feature; user can
            // disable each) ---
            TortaCore.setCacheRr(p.getBoolean(TortaeKeys.DNSMASQ_CACHE_RR, true)) // default ON
            TortaCore.setProxyDnssec(
                p.getBoolean(TortaeKeys.DNSMASQ_PROXY_DNSSEC, true)
            ) // default ON
            TortaCore.setAllServers(
                p.getBoolean(TortaeKeys.DNSMASQ_ALL_SERVERS, true)
            ) // default ON (R6 race)
            // filter-rr — the dashboard bool maps to ANY-defang only (RFC 8482); it never strips
            // A/AAAA, so
            // apps never break. A future Expert type-picker can supply a real drop-CSV here.
            // Default ON.
            TortaCore.setFilterRr("", p.getBoolean(TortaeKeys.DNSMASQ_FILTER_RR, true))
            // --- #51 MaskSolver Expert-toggle DURABILITY — the 6 knobs the MaskSolver SETTINGS pane drives that
            // have NO dnsmasq-dashboard mirror. Each is a torta_core process-global that resets on the .so
            // restart; re-push the user's persisted pick here so an Expert choice survives VPN-off/app-kill/
            // reboot. Defaults MATCH the Rust compiled default, so an untouched install is byte-identical:
            // solve-ladder OFF; every int 0 = "leave the engine's configured/default value" (only a user-armed
            // >0 overrides — critically, this must NOT push cache-cap=0, which would stomp the cap that the
            // configureResolver call above just installed). ---
            TortaCore.setSolveLadder(p.getBoolean(TortaeKeys.RESOLVER_SOLVE_LADDER, false))
            p.getInt(TortaeKeys.RESOLVER_QUERY_TIMEOUT_MS, 0).let { if (it > 0) TortaCore.setQueryTimeout(it) }
            p.getInt(TortaeKeys.RESOLVER_CACHE_CAP, 0).let { if (it > 0) TortaCore.setCacheCap(it) }
            p.getInt(TortaeKeys.RESOLVER_SERVE_STALE_SECS, 0).let { if (it > 0) TortaCore.setServeStale(it) }
            p.getInt(TortaeKeys.RESOLVER_TTL_FLOOR_SECS, 0).let { if (it > 0) TortaCore.setTtlFloor(it) }
            p.getInt(TortaeKeys.RESOLVER_TTL_CEILING_SECS, 0).let { if (it > 0) TortaCore.setTtlCeiling(it) }
            // --- #49 THE BEAST DURABILITY — re-push the user's applied Yeah TCP/UDP brain + Soft-cake queue +
            // tunables onto the freshly-built process-global Beast (LIVE_BEAST resets to LineRate × SoftCake
            // on every .so restart). profiles carry a -1 "never staged" sentinel (leave the compiled default);
            // tunables carry 0 = unset (beastSetTunables won't clobber a live value). Order is load-bearing:
            // profiles FIRST (a re-seed resets the YeAH window), tunables LAST so the window override survives.
            // Same "the engine picks the prefs up on the next DNSCrypt start" contract as the knobs above. ---
            p.getInt(TortaeKeys.BEAST_YEAH_PROFILE, -1).let { if (it >= 0) TortaCore.beastSetYeahProfile(it) }
            p.getInt(TortaeKeys.BEAST_CAKE_PROFILE, -1).let { if (it >= 0) TortaCore.beastSetCakeProfile(it) }
            TortaCore.beastSetTunables(
                p.getInt(TortaeKeys.BEAST_MAX_WINDOW, 0),
                p.getInt(TortaeKeys.BEAST_FREE_THRESH, 0),
                p.getInt(TortaeKeys.BEAST_COMPETE_THRESH, 0),
            )
        } catch (e: Exception) {
            loge("ResolverRuntime applyDnsmasqTogglesFromPref", e)
        }
    }

    /**
     * K5 D09 — drive the LIVE resolver from the typed DNSCrypt config authority (the dossier's
     * `dnscryptConfigApply` ZERO-callers wire, closed). W5 #12 (RAMxNAND Opt-2): the config's
     * durable truth is the app-private DurableTier `"dnscrypt-config"` record, NOT the loose toml —
     * so this first RECOVERS the authority from that record when it exists (re-materializing the
     * toml from it), and only a TRUE cold boot (no record) falls back to importing the on-disk toml
     * and seeding the record from it. It then imports the (recovered or cold) TOML typed — fail-soft
     * to the upstream Default on an ABSENT file (a fresh install: DNS64 off, no pins) — and
     * applies: DNS64 prefixes are ALWAYS driven (the process-global a fresh pool never resets),
     * and the `[static]` `sdns://` pins — the explicit user server-pin intent — retarget the pool.
     * With NO pins the pool this lifecycle edge just configured is left UNTOUCHED (compose-safe
     * with the MODE-2 rotation derivation by construction: `configure_from` refuses to tear down a
     * source-configured pool on an empty pin set). Control-plane, once per lifecycle edge, off the
     * hot path. Crash-safe: an UNREADABLE (vs absent) TOML skips the apply entirely — the live
     * engine is never driven from a fabricated default while the user's real config exists.
     */
    private fun applyDnscryptConfigAuthority() {
        try {
            val confPath = pathVars.get().dnscryptConfPath
            // W5 #12 (RAMxNAND Opt-2) — the app-private DurableTier root the config's framed
            // `"dnscrypt-config"` record lives in, the SAME root RotationManager/RuntimeTierManager use.
            val durableDir =
                pathVars.get().appDataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR
            // W5 #12 slice 2 — mirror the user's five single-rule lists FIRST, decoupled from the config
            // authority below (which has early returns on an unparsable toml): a broken config must never
            // cost the user their durable single-list safety net. Self-contained try inside.
            syncDurableSingleLists(durableDir)
            // RAM⊗NAND recovery — the DurableTier "dnscrypt-config" record IS the config authority.
            // Whenever it exists, rehydrate the in-mem authority FROM it and re-materialize the loose
            // compatibility toml (Rust-side, atomic tmp+rename) so the file-reading import below sees
            // the restored config. This WINS over a toml the module-start pipeline just laid down from
            // a DEFAULT — ModulesStarterHelper auto-extracts assets/dnscrypt.zip's stock toml when the
            // signed lists are missing, and RotationManager rewrites server_names/routes — neither
            // touches the durable record. Gating on file-ABSENCE was wrong: the extract re-creates the
            // toml before this runs, so absence almost never held and the stock require_* silently won.
            // The record is never staler than the toml — every K5 UI commit persists BOTH (torta_ui +
            // ProxyHelper materialize+persist as a pair) — so record-wins never loses a live edit. Only
            // a TRUE cold boot (no record yet) falls through to importing the on-disk toml, and the
            // persist below then SEEDS the record from it.
            val recovered =
                try {
                    TortaCore.rehydrateDnscryptConfig(durableDir)
                } catch (e: Exception) {
                    false
                }
            if (recovered) {
                TortaCore.materializeDnscryptToml(confPath)
                logi("ResolverRuntime K5 config RECOVERED from the W5 DurableTier — re-materialized $confPath")
            }
            val toml =
                try {
                    java.io.File(confPath)
                        .takeIf { it.isFile }
                        ?.readText() ?: ""
                } catch (e: Exception) {
                    loge("ResolverRuntime applyDnscryptConfigAuthority read", e)
                    return
                }
            val cfg = TortaCore.dnscryptConfigImportOrDefault(toml) ?: return
            val summary = TortaCore.dnscryptConfigApply(cfg)
            if (summary != null) {
                logi("ResolverRuntime K5 config applied to the live resolver: $summary")
            }
            // W5 #12 — refresh the durable mirror from the just-applied authority (SEEDS the record on
            // a cold first boot, refreshes it on every lifecycle edge). Best-effort, off the hot path.
            TortaCore.persistDnscryptConfig(durableDir)
        } catch (e: Exception) {
            loge("ResolverRuntime applyDnscryptConfigAuthority", e)
        }
    }

    /**
     * W5 #12 slice 2 (RAMxNAND Opt-2) — keep the five user-authored DNSCrypt single-rule lists durable
     * across an app_data wipe. For each list, at every DNSCrypt configure edge (control-plane, off the
     * resolve hot path): if the loose *-single.txt is PRESENT it is the live authority — SEED/refresh its
     * DurableTier mirror from it (byte-faithful: FileManager writes each rule + '\n', so readLines() +
     * the Rust re-encode reproduce the exact frame). If the loose file is ABSENT — a wipe, never an
     * intentional empty (an emptied list is written as a present zero-byte file) — RECOVER it from the
     * mirror. Each list is guarded independently so no single one can throw the whole sweep.
     *
     * This is the RUNTIME home of single-list durability: the edit seam ([DnsRulesDataSourceImpl])
     * persists on save, but the recovery of a wiped loose file must run at engine start — before the
     * resolver composes its effective lists — hence here. Record basenames are shared through
     * [DnsSingleRuleRecords] so persist (save) and recover (start) can never desync.
     */
    private fun syncDurableSingleLists(durableDir: String) {
        val pv = pathVars.get()
        syncSingleList(durableDir, pv.dnsCryptSingleBlackListPath, DnsSingleRuleRecords.BLACKLIST)
        syncSingleList(durableDir, pv.dnsCryptSingleWhiteListPath, DnsSingleRuleRecords.WHITELIST)
        syncSingleList(durableDir, pv.dnsCryptSingleIPBlackListPath, DnsSingleRuleRecords.IP_BLACKLIST)
        syncSingleList(durableDir, pv.dnsCryptSingleForwardingRulesPath, DnsSingleRuleRecords.FORWARDING)
        syncSingleList(durableDir, pv.dnsCryptSingleCloakingRulesPath, DnsSingleRuleRecords.CLOAKING)
    }

    private fun syncSingleList(durableDir: String, path: String, record: String) {
        try {
            val file = java.io.File(path)
            if (file.isFile) {
                TortaCore.persistDnsRuleList(durableDir, record, file.readLines())
            } else if (TortaCore.materializeDnsRuleList(durableDir, record, path)) {
                logi("ResolverRuntime W5 single-list RECOVERED from the DurableTier — $path")
            }
        } catch (e: Exception) {
            loge("ResolverRuntime syncSingleList $record", e)
        }
    }

    /**
     * ★ E-FIX r5 (R5-Q1) — arm (or disarm) the Rust-side `cache/query.log` FEED from the effective
     * toml `[query_log] file` value, read through the SAME typed K5 config authority
     * [applyDnscryptConfigAuthority] rides. The round-5 regression: the sovereign MODE-2 pool
     * answers intercepted foreign queries DIRECTLY, so the Go proxy (the only query.log writer)
     * never sees them and the QUERY surface stopped reporting foreign traffic (round 4 still saw
     * rows only because its exercises ran while the Go loopback path was serving). With the feed
     * armed, `resolve_datapath` appends one Go-shape TSV row per Rust-ANSWERED query; MODE-1
     * loopback forwards stay the Go writer's own rows (no double-count — `query_feed::feed_status`).
     *
     * The arm value mirrors the PRODUCER's enable exactly: `[query_log] file` set (the DEBUG
     * enabler `ModulesStarterHelper.enableQueryLogForDebug`, or the user's query-log toggle) ⇒
     * armed at that path; absent/blank ⇒ DISARMED — a release build without the opt-in never
     * writes a qname anywhere (the same privacy posture as the Go proxy). Control-plane, once per
     * RUNNING edge; crash-safe (a read fault leaves the feed disarmed, never a throw).
     */
    private fun armQueryFeedFromConfig() {
        try {
            // ★ GENESIS A1 (2026-07-05) — the feed must ALWAYS arm when the pool configures (the Socio's
            // "enable it always, transparency" directive, 2026-06-25). A toml read/parse fault NO LONGER
            // bails — it falls through to the default cache path so the feed arms regardless. The
            // bundled toml ships query logging ON but with NO `[query_log] file` (the legacy enabler
            // lived in the removed Go body); the default path is the file QueryLogTailer reads.
            val toml =
                try {
                    java.io.File(pathVars.get().dnscryptConfPath)
                        .takeIf { it.isFile }
                        ?.readText().orEmpty()
                } catch (e: Exception) {
                    loge("ResolverRuntime armQueryFeedFromConfig read — using default path", e)
                    ""
                }
            val parsed =
                try {
                    TortaCore.dnscryptConfigImportOrDefault(toml)?.queryLog?.file?.trim().orEmpty()
                } catch (e: Exception) {
                    loge("ResolverRuntime armQueryFeedFromConfig parse — using default path", e)
                    ""
                }
            val defaultPath = pathVars.get().appDataDir + "/cache/query.log"
            val file = if (parsed.isNotEmpty()) parsed else defaultPath
            TortaCore.resolverArmQueryFeed(file)
            logi("ResolverRuntime query.log feed armed for Rust-answered queries: $file (parsed='${parsed.ifEmpty { "(default)" }}')")
        } catch (e: Exception) {
            loge("ResolverRuntime armQueryFeedFromConfig", e)
        }
    }

    /**
     * Is the native Rust resolver ARMED for the live C/UDP-53 datapath? True iff the user flipped
     * the Stage-1 keystone [TortaeKeys.RESOLVER_NATIVE_ENABLED] (`pref_resolver_native`,
     * TortaeKeys.java:165; DEFAULT true — the Default-ON #85 keystone) AND the arm push actually
     * REACHED the C layer ([VpnUtils.isResolverNativePushLanded] — the landed truth the crash-safe
     * setter records). This is the SAME pref [ModulesStarterHelper.applyResolverNativeFromPref]
     * pushes to the C-side `g_resolver_native_enabled` flag at DNSCrypt start.
     *
     * ★ E-FIX round-1 (the false armed-state claim, closed): the pref alone is INTENT, not state —
     * on the round-1 cold start the push died on an UnsatisfiedLinkError (libinvizible.so not yet
     * loaded) while this method still answered `true` off the pref, so the RUNNING-edge log claimed
     * `nativeArmed=true` with both C seam flags at 0. Composing the pref with the landed truth makes
     * the claim (and the fallback-detector gate that rides it) honest in every ordering: push landed
     * ⇒ armed; push swallowed / never fired ⇒ un-armed (matching the C flag, which is 0 in exactly
     * those cases). The setter itself now ensure-loads the .so, so in practice the push lands on the
     * FIRST start too. Crash-safe: any read fault degrades to false (un-armed ⇒ fall-through).
     */
    private fun isNativeArmed(): Boolean =
        try {
            defaultPreferences.getBoolean(TortaeKeys.RESOLVER_NATIVE_ENABLED, true) &&
                VpnUtils.isResolverNativePushLanded()
        } catch (e: Exception) {
            false
        }

    /**
     * The app-private durable NAND dir for the resolver's RAM⊗NAND cache snapshot — the SAME
     * runtime-tier dir the rotation/metrics W5 state uses
     * ([RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR] under the app data dir), so the cache
     * snapshot co-locates with the other durable pillars. The DurableTier writes its
     * `resolver-cache` record inside it.
     */
    private fun durableDir(): String =
        pathVars.get().appDataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR

    /**
     * DNSCrypt stopped. If the user runs the engine/resolver standalone, retarget the shadow onto
     * the public-DNSCrypt default set (so it keeps measuring a real path); otherwise tear the
     * native resolver down. Mirrors [MonokumaDnsEngineManager.onDnsCryptStopped].
     */
    @Synchronized
    fun onDnsCryptStopped() {
        try {
            // P7 2e — stop the LIVE qname seam FIRST, in BOTH branches: once DNSCrypt stops there
            // is no
            // loopback dnscrypt-proxy writing query.log to tail (standalone retargets to PUBLIC
            // upstreams,
            // which produce no local query.log). DEBUG-only and idempotent — safe even if never
            // started.
            if (BuildConfig.DEBUG) queryLogTailer.stop()
            // ★ E-FIX r5 — disarm the Rust query.log FEED in BOTH branches: the feed lives exactly
            // while the DNSCrypt datapath lives (the Go producer stops writing on this edge too;
            // standalone answers have their own query-masksolver.log surface). Crash-proof facade.
            TortaCore.resolverArmQueryFeed("")
            // ★ SOVEREIGN REWIRE — cancel the periodic fallback detector in BOTH branches (a STOPPED
            // edge retargets/tears-down the pool, so the prior Rust-health decision is moot).
            stopFallbackCheckLoop()
            if (defaultPreferences.getBoolean(TortaeKeys.DNS_ENGINE_STANDALONE, false)) {
                // D13 (RAM⊗NAND) — persist the warm cache BEFORE the standalone retarget installs a
                // fresh pool/cache (configureFromUpstreams → a new Cache), which would otherwise drop the
                // warm set on this edge without ever writing it through. Best-effort + off the hot path.
                checkpointCache()
                val summary = configureFromUpstreams(dnsCryptRunning = false)
                configured = summary != null
                if (summary != null) {
                    logi(
                        "ResolverRuntime shadow retargeted to public DNSCrypt (standalone): $summary"
                    )
                    // K5 D09 — the standalone engine still resolves through the Rust pool, so the
                    // typed config authority (DNS64 + static pins) applies on this edge too — a
                    // process restart into standalone must not lose the user's DNS64 posture.
                    applyDnscryptConfigAuthority()
                    // D30 — the standalone retarget installed a fresh (unlearned) pool: same
                    // warm-RTT seed law as the RUNNING edge.
                    warmStartRtt()
                } else {
                    logi("ResolverRuntime shadow idle — no usable standalone upstream")
                }
            } else {
                // P12 RAM⊗NAND — GENTLE persist of the live cache to NAND BEFORE teardown, so a
                // stop/start (or
                // app restart) starts WARM. Best-effort; the in-memory tier is unaffected by the
                // outcome.
                val persisted = TortaCore.persistCache(durableDir())
                if (persisted > 0) logi("ResolverRuntime cache persisted: $persisted bytes to NAND")
                configured = false
                fallbackActive = false
                TortaCore.shutdownResolver()
                logShadowSummary("DNSCrypt stopped")
                logi("ResolverRuntime shadow shut down")
            }
        } catch (e: Exception) {
            // Even a teardown failure must never escape — leave the gate closed and swallow.
            configured = false
            fallbackActive = false
            loge("ResolverRuntime onDnsCryptStopped", e)
        }
    }

    /**
     * Build the upstream spec set and hand it to the native resolver. Returns the resolver's
     * `"ready=N transports=…"` summary, or null when nothing usable could be configured.
     *
     * When DNSCrypt is **RUNNING** the shadow points at the **real loopback `dnscrypt-proxy`** via
     * the native `do53` (plain Do53, loopback-only) transport — see [buildSpecsJson]. That is the
     * genuine Stage-0 claim: it validates the in-app Rust resolver against the *exact* upstream the
     * user resolves through, not a public third-party resolver. When DNSCrypt is **stopped** but
     * the engine runs standalone, there is no loopback proxy, so the shadow retargets to the
     * public-DNSCrypt default set (the one encrypted arm that builds today with no
     * platform-verifier).
     */
    private fun configureFromUpstreams(dnsCryptRunning: Boolean): String? {
        // ★ RELAY-ON-START (2026-07-04) — when DNSCrypt runs in the sovereign RUST pool (MODE 2),
        // prefer the TYPED configure so the toml's 0x81 anonymized-relay routes bind on the FIRST
        // configure, not only the 30-min RotationManager tick. The relays ride in UpstreamSpec.relays
        // (the flat `configureResolver` path drops them — parse_upstream_obj has no relays field).
        // Falls through to the flat path below when no typed pool derives (fresh/unusable config), so
        // the never-dark floor + the Go/shadow modes are untouched.
        if (dnsCryptRunning && poolMode() == PoolMode.RUST) {
            deriveConfiguredUpstreamsTyped()?.let { specs ->
                val report =
                    TortaCore.configureResolverTyped(
                        specs,
                        TortaCore.resolverRoutesList(durableDir()),
                        SHADOW_TIMEOUT_MS,
                        CACHE_CAP,
                    )
                if (report != null && report.ready > 0) {
                    return "ready=${report.ready} transports=${report.transports} " +
                        "rejected=${report.rejected} (typed, relays-on-start)"
                }
                logi(
                    "ResolverRuntime — typed configure declined (ready=${report?.ready}), " +
                        "falling back to the flat pool"
                )
            }
        }
        // ★ SOVEREIGN DNSCRYPT REWIRE — the production pool is now the Rust DNSCrypt stamps (MODE 2)
        // when the user has the Rust transport enabled (DEFAULT ON); the Go loopback (MODE 1) is the
        // explicit fallback. The shadow harness (DEBUG-only) keeps its own honest Go-comparison pool
        // via PoolMode.SHADOW so the Stage-0 "Rust vs the real Go answer" parity test is preserved.
        val specsJson = buildSpecsJson(dnsCryptRunning, poolMode())
        // Tight-ish per-query budget so a slow upstream never piles up shadow work; the resolver
        // clamps to 50..60000 internally. 3000ms keeps the shadow honest without hammering battery.
        return TortaCore.configureResolver(
            specsJson,
            timeoutMs = SHADOW_TIMEOUT_MS,
            cacheCap = CACHE_CAP,
        )
    }

    /**
     * ★ SOVEREIGN REWIRE — which pool does the live Rust resolver resolve through?
     *
     * - **RUST (MODE 2, the DEFAULT):** the Rust DNSCrypt v2 transport answers encrypted queries
     *   DIRECTLY (`resolver/dnscrypt.rs` — stamp parse, Ed25519 cert verify, XChaCha20 exchange). The
     *   Go `libdnscrypt-proxy.so` STAYS spawned as the loopback listener and is the automatic
     *   per-query FALLBACK: the C bridge `udp.c:478-498` calls `torta_resolve` first; on `r<=0`
     *   (Rust decline / transport miss / panic-firewall) it falls through to the unchanged `sendto`
     *   to the Go loopback — zero C change. This is the production posture when
     *   [TortaeKeys.RESOLVER_USE_RUST_DNSCRYPT] is true (DEFAULT ON) and the runtime fallback
     *   detector has NOT flipped the pool to Go.
     * - **GO (MODE 1, the FALLBACK):** the Rust pool targets the Go loopback `dnscrypt-proxy` via
     *   `do53` (`127.0.0.1:<port>`), so the Go binary answers and Rust is inert. Selected when the
     *   user disabled the Rust transport (the explicit safety valve) OR when the runtime fallback
     *   detector ([maybeFallbackToGo]) tripped because Rust was failing under load.
     *
     * The shadow harness (DEBUG-only) shares this SAME pool — there is one resolver singleton. So
     * when production is RUST the shadow ALSO resolves through the Rust dnscrypt stamps: it validates
     * Rust's internal consistency (does Rust agree with the real answer the user received?) rather
     * than the old Stage-0 Rust-vs-Go comparison (a crutch for when Rust was non-production). This is
     * the honest sovereign-rewire posture. The C per-query fallback (r≤0 → Go sendto) is the safety
     * net that NEVER depends on the pool mode.
     *
     * When DNSCrypt is STOPPED (engine standalone) there is no loopback Go proxy, so the pool is the
     * public-DNSCrypt default set regardless of mode (the only encrypted arm that builds with no
     * platform-verifier).
     */
    private fun poolMode(): PoolMode {
        // The runtime fallback detector can force GO even when the user picked RUST (Rust failing
        // under load). @Volatile so the tun-thread production resolve sees the latest decision.
        if (fallbackActive) return PoolMode.GO
        val useRust =
            try {
                defaultPreferences.getBoolean(TortaeKeys.RESOLVER_USE_RUST_DNSCRYPT, true)
            } catch (e: Exception) {
                true // default-ON: a pref-read fault degrades to the Rust default, never to Go-only
            }
        return if (useRust) PoolMode.RUST else PoolMode.GO
    }

    /**
     * Compose the `{"upstreams":[{id,transport,url|stamp}]}` JSON the native resolver parses.
     *
     * **mode == RUST (DNSCrypt RUNNING, the sovereign DEFAULT):** emit the **DNSCrypt v2 stamps
     * DERIVED FROM THE LIVE CONFIG** (D06a — `server_names` ∩ the signed `public-resolvers.md`,
     * require_*-filtered via [deriveConfiguredUpstreams]; the hardcoded
     * [DEFAULT_DNSCRYPT_UPSTREAMS] pair is only the never-dark FLOOR for a fresh/unusable
     * config) — the Rust transport fetches + Ed25519-verifies the provider cert and speaks the
     * encrypted (XChaCha20-Poly1305) datapath directly. This is the production pool the C bridge
     * `torta_resolve` resolves through; the Go binary stays spawned as the loopback fallback listener.
     *
     * **mode == GO (DNSCrypt RUNNING, the FALLBACK):** emit ONE `do53` upstream pointing at the live
     * loopback `dnscrypt-proxy` listener (`127.0.0.1:<dnsCryptPort>`, read live from [PathVars],
     * never hardcoded). The native `do53` transport is a plain-Do53, **loopback-only** arm
     * (`Do53::new` hard-rejects any non-loopback address): a plaintext hop to our OWN proxy never
     * leaves the host and never enters the VpnService tun (loopback bypasses the VPN), so it needs no
     * `VpnService.protect()` and cannot loop. Go answers; Rust is inert.
     *
     * **DNSCrypt stopped, engine standalone:** there is no loopback proxy, so fall back to the
     * public-**DNSCrypt** default set regardless of mode (the `dnscrypt` BASE transport builds with
     * no platform-verifier). (The DoH default set — [DEFAULT_DOH_UPSTREAMS] — stays a doc note for
     * the Wave 3-A verifier shim.)
     */
    private fun buildSpecsJson(dnsCryptRunning: Boolean, mode: PoolMode): String {
        if (dnsCryptRunning) {
            // RUST = the sovereign production pool (DNSCrypt stamps, Rust answers directly).
            // GO = the loopback Do53 to the Go binary (the fallback: Go answers, Rust inert).
            if (mode == PoolMode.RUST) {
                deriveConfiguredUpstreams()?.let { derived ->
                    logi("ResolverRuntime upstream — Rust DNSCrypt stamps from live config (MODE 2, production)")
                    return wrapSpecs(derived)
                }
                val upstreams =
                    DEFAULT_DNSCRYPT_UPSTREAMS.joinToString(",") { (id, stamp) ->
                        """{"id":"$id","transport":"dnscrypt","stamp":"$stamp"}"""
                    }
                logi("ResolverRuntime upstream — Rust DNSCrypt stamps (MODE 2, default fallback pool)")
                return wrapSpecs(upstreams)
            }
            return try {
                val pv = pathVars.get()
                val port = pv.dnsCryptPort.toIntOrNull() ?: 5354
                // Context only — no qname, just the datapath coordinate.
                logi("ResolverRuntime upstream — do53 loopback 127.0.0.1:$port (Go fallback, MODE 1)")
                wrapSpecs("""{"id":"do53:proxy","transport":"do53","url":"127.0.0.1:$port"}""")
            } catch (e: Exception) {
                // If the live port can't be read, dial the default loopback port rather than going
                // dark.
                loge("ResolverRuntime buildSpecsJson loopback context", e)
                wrapSpecs("""{"id":"do53:proxy","transport":"do53","url":"127.0.0.1:5354"}""")
            }
        }
        // DNSCrypt stopped (standalone): no loopback Go proxy to target, but the on-disk TOML still
        // expresses the user's server choice — derive from it first (D06a; the derivation reads
        // files, never the live proxy), and only then fall back to the public DNSCrypt default set
        // (the one encrypted arm that always builds).
        deriveConfiguredUpstreams()?.let { derived ->
            logi("ResolverRuntime upstream — standalone pool derived from live config (D06)")
            return wrapSpecs(derived)
        }
        val upstreams =
            DEFAULT_DNSCRYPT_UPSTREAMS.joinToString(",") { (id, stamp) ->
                """{"id":"$id","transport":"dnscrypt","stamp":"$stamp"}"""
            }
        return wrapSpecs(upstreams)
    }

    /**
     * D06(a) — derive the MODE-2 production pool from the LIVE config instead of the hardcoded
     * two-stamp default: `server_names` (read through the typed K5 config authority over the
     * on-disk compatibility TOML — the SAME source the Go side obeys and the rotation rewrite
     * targets) ∩ the signed `public-resolvers.md` stamps, filtered by the user's require_*
     * criteria (the ONE shared [RotationPoolSource.policyFromPrefs] +
     * [RotationSelector.filterTrusted] gate rotation itself applies). The user's `server_names`
     * ORDER is preserved (StrictOrder tries the pool in order), bounded to
     * [RotationSelector.GEEK_SAFE_MAX_SERVERS] transports.
     *
     * This is also what makes a committed rotation SURVIVE every later reconfigure: rotation
     * rewrites `server_names` in the TOML, so a TRIP/RECOVER or lifecycle re-derive lands the
     * SAME rotated pool (config-as-authority convergence, no second source of truth).
     *
     * Returns the joined `{"id","transport","stamp"}` spec fragments, or null to fall back to
     * [DEFAULT_DNSCRYPT_UPSTREAMS] (fresh install, absent/unreadable TOML or md, empty
     * `server_names` = the dnscrypt "use all servers" posture — too broad to mirror into a
     * bounded Rust pool, no intersection, or every candidate policy-filtered). Never throws;
     * a null NEVER leaves the resolver dark — the default pair is the floor.
     */
    private fun deriveConfiguredUpstreams(): String? {
        return try {
            val pv = pathVars.get()
            val toml =
                try {
                    java.io.File(pv.dnscryptConfPath).takeIf { it.isFile }?.readText()
                } catch (e: Exception) {
                    loge("ResolverRuntime deriveConfiguredUpstreams toml read", e)
                    null
                } ?: return null
            val cfg = TortaCore.dnscryptConfigImportOrDefault(toml) ?: return null
            val serverNames = cfg.serverNames
            if (serverNames.isEmpty()) return null
            // --- The DNSCrypt lane (server_names ∩ public-resolvers.md, require_* filtered). May be
            // EMPTY without failing the derive: an ODoH-only config, or an unreadable public-resolvers.md,
            // must not sink the oblivious lane below (its source is a DIFFERENT file, odoh-servers.md).
            val dnscryptFrags: List<String> =
                run {
                    val stamped =
                        RotationPoolSource.readStampedCandidates(pv.getDNSCryptPublicResolversPath())
                    if (stamped.isEmpty()) return@run emptyList()
                    val byId = stamped.associateBy { it.candidate.id }
                    val inConfig = serverNames.mapNotNull { byId[it] }
                    if (inConfig.isEmpty()) return@run emptyList()
                    // ★ require→pool: the filter policy is driven by the TYPED config (the SLINT toggles →
                    // require_*), not the legacy prefs — so Require DNSSEC/no-log/no-filter reach the pool.
                    val policy =
                        RotationPoolSource.policyFromConfig(
                            cfg.requireNolog,
                            cfg.requireDnssec,
                            cfg.requireNofilter,
                            cfg.ipv4Servers,
                            cfg.ipv6Servers,
                        )
                    val allowed =
                        RotationSelector.filterTrusted(inConfig.map { it.candidate }, policy)
                            .map { it.id }
                            .toHashSet()
                    inConfig
                        .filter { it.candidate.id in allowed }
                        .take(RotationSelector.GEEK_SAFE_MAX_SERVERS)
                        .map {
                            """{"id":"${it.candidate.id}","transport":"dnscrypt","stamp":"${it.sdns}"}"""
                        }
                }
            // --- The ODoH oblivious lane (server_names ∩ odoh-servers.md [0x05], relays ∩ odoh-relays.md
            // [0x85]). Independent of the DNSCrypt lane above — the MaskSolver surpass axis nautilus never
            // routes. Empty when the `odoh_servers` pref is off or no ODoH server is selected.
            val odohFrags: List<String> =
                deriveOdohUpstreams(cfg, pv).map {
                    if (it.relays.isEmpty()) {
                        """{"id":"${it.id}","transport":"odoh","stamp":"${it.sdns}"}"""
                    } else {
                        val relaysJson = it.relays.joinToString(",") { r -> "\"$r\"" }
                        """{"id":"${it.id}","transport":"odoh","stamp":"${it.sdns}","relays":[$relaysJson]}"""
                    }
                }
            val all = dnscryptFrags + odohFrags
            if (all.isEmpty()) return null
            logi(
                "ResolverRuntime — derived ${dnscryptFrags.size} DNSCrypt + ${odohFrags.size} ODoH " +
                    "upstream(s) from live config (server_names ∩ md sources, require_* filtered)"
            )
            all.joinToString(",")
        } catch (e: Exception) {
            loge("ResolverRuntime deriveConfiguredUpstreams — default pool fallback", e)
            null
        }
    }

    /**
     * ★ RELAY-ON-START (2026-07-04) — the TYPED twin of [deriveConfiguredUpstreams] that binds the
     * toml's `[anonymized_dns] routes` (the 0x81 anonymized-DNSCrypt relays) onto each derived
     * server's [UpstreamSpec.relays], so the relays are LIVE on the FIRST configure — not only after
     * the 30-min RotationManager tick (RotationManager.rotateOnce was the ONLY path that populated
     * relays; the flat [deriveConfiguredUpstreams] → `configureResolver` path drops them because
     * `parse_upstream_obj` builds a 4-field spec with no relays).
     *
     * Same pool derivation as the flat twin (server_names ∩ public-resolvers.md, require_*-filtered),
     * then per server: look up its `via=[…]` relay NAMES from `anonymized_dns.routes` and resolve
     * each to a `sdns://` relay STAMP from relays.md (the SAME `readNamedStamps` source RotationManager
     * uses — the two brains never diverge). A server with no route yields a direct (relay-free) spec.
     * Returns null (⇒ caller falls back to the flat path) on any read miss / empty pool. Never throws.
     */
    private fun deriveConfiguredUpstreamsTyped(): List<uniffi.torta_core.UpstreamSpec>? {
        return try {
            val pv = pathVars.get()
            val toml =
                try {
                    java.io.File(pv.dnscryptConfPath).takeIf { it.isFile }?.readText()
                } catch (e: Exception) {
                    loge("ResolverRuntime deriveConfiguredUpstreamsTyped toml read", e)
                    null
                } ?: return null
            val cfg = TortaCore.dnscryptConfigImportOrDefault(toml) ?: return null
            val serverNames = cfg.serverNames
            if (serverNames.isEmpty()) return null
            // The toml's pre-configured relay routes: server_name → relay NAMES. Shared by BOTH lanes
            // (0x81 anonymized-DNSCrypt relays from relays.md, 0x85 ODoH relays from odoh-relays.md — the
            // route TABLE is one; only the stamp SOURCE differs by protocol).
            val routeVia: Map<String, List<String>> =
                cfg.anonymizedDns.routes.associate { it.serverName to it.via }
            // --- The TYPED DNSCrypt lane. May be EMPTY without failing the derive (ODoH-only config, or
            // unreadable public-resolvers.md) — the oblivious lane below reads a DIFFERENT source.
            var relayBound = 0
            val dnscryptSpecs: List<uniffi.torta_core.UpstreamSpec> =
                run {
                    val stamped =
                        RotationPoolSource.readStampedCandidates(pv.getDNSCryptPublicResolversPath())
                    if (stamped.isEmpty()) return@run emptyList()
                    val byId = stamped.associateBy { it.candidate.id }
                    val inConfig = serverNames.mapNotNull { byId[it] }
                    if (inConfig.isEmpty()) return@run emptyList()
                    // ★ require→pool: drive the filter from the TYPED config (SLINT toggles → require_*), so
                    // the armed Require DNSSEC/no-log/no-filter actually filter the live typed pool.
                    val policy =
                        RotationPoolSource.policyFromConfig(
                            cfg.requireNolog,
                            cfg.requireDnssec,
                            cfg.requireNofilter,
                            cfg.ipv4Servers,
                            cfg.ipv6Servers,
                        )
                    val allowed =
                        RotationSelector.filterTrusted(inConfig.map { it.candidate }, policy)
                            .map { it.id }
                            .toHashSet()
                    val pool =
                        inConfig
                            .filter { it.candidate.id in allowed }
                            .take(RotationSelector.GEEK_SAFE_MAX_SERVERS)
                    if (pool.isEmpty()) return@run emptyList()
                    // Resolve relay NAMES → sdns:// relay STAMPS from relays.md (only if any route exists).
                    val relayStampByName: Map<String, String> =
                        if (routeVia.isEmpty()) emptyMap()
                        else RotationPoolSource.readNamedStamps(pv.getDNSCryptRelaysPath()).toMap()
                    pool.map { c ->
                        // FOUNDATION (task #6 — resolution first): the DNSCrypt lane rides DIRECT. The
                        // toml's `via=[…]` is a list of relay CANDIDATES from which the Go proxy picks
                        // ONE per query (`prepareForRelay` wraps ONCE). Feeding the WHOLE list into
                        // UpstreamSpec.relays made Rust `wrap_for_relay_chain` NEST every entry into a
                        // multi-hop chain — a non-standard 2–10 hop envelope through mismatched (and, on
                        // this host, IPv6-site-local-unreachable) relays that every server silently drops
                        // (168/168 queries, 0 replies; tcpdump: all Out, 0 In). Correct anonymized
                        // SINGLE-relay routing + health rotation + direct fallback lands under the
                        // Underground pillar (task #4). Until then: relay-free so the pool actually answers.
                        val viaNames = routeVia[c.candidate.id].orEmpty()
                        if (viaNames.any { relayStampByName.containsKey(it) }) relayBound++
                        uniffi.torta_core.UpstreamSpec(
                            id = c.candidate.id,
                            transport = uniffi.torta_core.TransportKind.DNSCRYPT,
                            url = "",
                            stamp = c.sdns,
                            relays = emptyList(),
                        )
                    }
                }
            // --- The TYPED ODoH oblivious lane (0x05 targets from odoh-servers.md; 0x85 relays from
            // odoh-relays.md, KEEPING the relay path — the differentiator vs Kotlin handleODoHRelay which
            // drops it). TransportKind.ODOH is inert off the engine's `odoh` feature (arm skipped).
            val odohSpecs: List<uniffi.torta_core.UpstreamSpec> =
                deriveOdohUpstreams(cfg, pv).map {
                    uniffi.torta_core.UpstreamSpec(
                        id = it.id,
                        transport = uniffi.torta_core.TransportKind.ODOH,
                        url = "",
                        stamp = it.sdns,
                        relays = it.relays,
                    )
                }
            val specs = dnscryptSpecs + odohSpecs
            if (specs.isEmpty()) return null
            logi(
                "ResolverRuntime — derived ${dnscryptSpecs.size} TYPED DNSCrypt " +
                    "($relayBound with 0x81 relay routes) + ${odohSpecs.size} ODoH upstream(s) from live config"
            )
            specs
        } catch (e: Exception) {
            loge("ResolverRuntime deriveConfiguredUpstreamsTyped — falling back to flat path", e)
            null
        }
    }

    /** One derived ODoH upstream: the server id, its 0x05 target `sdns://` stamp, and any 0x85 ODoH-relay
     * stamps bound from `anonymized_dns.routes`. Empty [relays] ⇒ a direct (relay-less) ODoH connection. */
    private data class OdohUpstream(
        val id: String,
        val sdns: String,
        val relays: List<String>,
    )

    /**
     * Derive the ODoH oblivious lane — the MaskSolver axis nautilus-rs NEVER routes. Shape mirrors the
     * DNSCrypt derive (server_names ∩ md-source, require_* filtered, relays bound from routes), but on the
     * ODoH sources: 0x05 targets from `odoh-servers.md` and 0x85 relays from `odoh-relays.md`. Gated on the
     * `odoh_servers` pref (default on). Uses [RotationPoolSource.policyFromConfigOdoh] (requireDnsCrypt OFF)
     * so 0x05 targets survive the trust filter. Returns [] (never throws) on pref-off / no ODoH server
     * selected / empty pool — the caller simply emits no oblivious specs.
     */
    private fun deriveOdohUpstreams(
        cfg: uniffi.torta_core.DnscryptProxyConfig,
        pv: PathVars,
    ): List<OdohUpstream> {
        return try {
            if (!defaultPreferences.getBoolean("odoh_servers", true)) return emptyList()
            val serverNames = cfg.serverNames
            if (serverNames.isEmpty()) return emptyList()
            val stamped =
                RotationPoolSource.readStampedCandidates(pv.getOdohServersPath())
            if (stamped.isEmpty()) return emptyList()
            val byId = stamped.associateBy { it.candidate.id }
            val inConfig = serverNames.mapNotNull { byId[it] }
            if (inConfig.isEmpty()) return emptyList()
            // ODoH policy: same privacy require_* gates, but requireDnsCrypt OFF (0x05 ≠ 0x01).
            val policy =
                RotationPoolSource.policyFromConfigOdoh(
                    cfg.requireNolog,
                    cfg.requireDnssec,
                    cfg.requireNofilter,
                    cfg.ipv4Servers,
                    cfg.ipv6Servers,
                )
            val allowed =
                RotationSelector.filterTrusted(inConfig.map { it.candidate }, policy)
                    .map { it.id }
                    .toHashSet()
            val pool =
                inConfig
                    .filter { it.candidate.id in allowed }
                    .take(RotationSelector.GEEK_SAFE_MAX_SERVERS)
            if (pool.isEmpty()) return emptyList()
            // ODoH relay routes: same route TABLE (server_name → via NAMES) resolved against odoh-relays.md.
            val routeVia: Map<String, List<String>> =
                cfg.anonymizedDns.routes.associate { it.serverName to it.via }
            val relayStampByName: Map<String, String> =
                if (routeVia.isEmpty()) emptyMap()
                else RotationPoolSource.readNamedStamps(pv.getOdohRelaysPath()).toMap()
            pool.map { c ->
                val viaNames = routeVia[c.candidate.id].orEmpty()
                val relayStamps = viaNames.mapNotNull { relayStampByName[it] }
                OdohUpstream(c.candidate.id, c.sdns, relayStamps)
            }
        } catch (e: Exception) {
            loge("ResolverRuntime deriveOdohUpstreams — oblivious lane skipped", e)
            emptyList()
        }
    }

    /**
     * D06(b) — install a freshly-ROTATED upstream set into the LIVE Rust pool (the
     * [RotationManager.rotateOnce] hand-off that finally rotates the pool that answers).
     * TYPED end-to-end: a `List<UpstreamSpec>` through [TortaCore.configureResolverTyped] with
     * the user's persisted conditional routes riding along ([TortaCore.resolverRoutesList]) —
     * no hand-built JSON, no summary-string parse (D34's full-power law on a NEW seam).
     *
     * MODE-GUARDED (the c-plan's law): the swap runs ONLY when the live pool is the Rust
     * MODE-2 pool — an active Go fallback ([poolMode] == GO, whether user-chosen or
     * detector-tripped) is NEVER stomped (the rotation still lands Go-side via the TOML
     * rewrite + dnscrypt restart the caller owns). Fail-safe: a `null`/`ready=0` report is
     * "no swap" — the native side left the previous pool installed; the warm cache is
     * checkpointed BEFORE the swap (a configure installs a fresh cache) and rehydrated after,
     * so a rotation never costs the warm set. The K5 config authority re-applies after the
     * swap (explicit `[static]` user pins stay the last word — pinned users keep their pins,
     * pin-less users keep the rotated pool), and the fresh pool's RTT EWMA is warm-started
     * (D30). Returns true ONLY on a real committed Rust swap. Never throws.
     */
    @Synchronized
    fun applyRotatedPool(
        specs: List<uniffi.torta_core.UpstreamSpec>,
        timeoutMs: Long,
        cacheCap: Int,
    ): Boolean {
        return try {
            if (specs.isEmpty()) return false
            if (!configured) {
                logi("ResolverRuntime — rotated pool skipped (resolver not configured)")
                return false
            }
            if (poolMode() != PoolMode.RUST) {
                logi("ResolverRuntime — rotated pool skipped (Go pool active, MODE 1 — TOML apply governs)")
                return false
            }
            // Persist the warm answer cache BEFORE the swap installs a fresh pool/cache (the D13
            // posture on the standalone retarget, applied to the rotation edge).
            checkpointCache()
            val report =
                TortaCore.configureResolverTyped(
                    specs,
                    TortaCore.resolverRoutesList(durableDir()),
                    timeoutMs,
                    cacheCap,
                )
            if (report != null && report.ready > 0) {
                configured = true
                val restored = TortaCore.rehydrateCache(durableDir())
                if (restored > 0)
                    logi("ResolverRuntime cache rehydrated after rotation: $restored entries")
                // K5 D09 — the config authority stays the last word on every configure edge:
                // explicit [static] pins re-assert (pin-less users are untouched — configure_from
                // refuses a teardown on an empty pin set), DNS64 posture re-driven.
                applyDnscryptConfigAuthority()
                warmStartRtt()
                // ★ GENESIS A1 (2026-07-05) — re-arm the query.log feed on EVERY successful rotation
                // configure (the always-fire path: cadence + relay-on-start). The capture of WHICH
                // DNSCrypt server answered (GENESIS A2, ResolvedBy) is meaningless without the feed
                // armed — so we keep it armed on every pool swap, sovereign + always-on.
                armQueryFeedFromConfig()
                logi(
                    "ResolverRuntime rotated pool configured (typed): ready=${report.ready} " +
                        "transports=${report.transports} rejected=${report.rejected}"
                )
                true
            } else {
                logi("ResolverRuntime rotated pool declined — kept current set (fail-safe, ready=${report?.ready})")
                false
            }
        } catch (e: Exception) {
            loge("ResolverRuntime applyRotatedPool — kept current set (fail-safe)", e)
            false
        }
    }

    /**
     * D30 — seed the fresh pool's per-transport RTT EWMA from the durable rotation record's warm
     * hints ([TortaCore.warmStartResolverRtt]). Fired once after every successful configure (the
     * RUNNING edge, the standalone retarget, the rotated swap) — a fresh pool always starts
     * unlearned. Best-effort + crash-safe; 0 seeded (cold/no hints) is a silent non-event.
     */
    private fun warmStartRtt() {
        try {
            val seeded = TortaCore.warmStartResolverRtt(durableDir())
            if (seeded > 0) logi("ResolverRuntime warm-RTT seeded: $seeded transport(s) from NAND (D30)")
        } catch (e: Exception) {
            loge("ResolverRuntime warmStartRtt", e)
        }
    }

    /**
     * D33b (P12) — wrap the upstream objects into the final specs JSON, appending the user's
     * conditional-routing rules as the `"routes"` key (`routing::parse_routes` has been wired into
     * `resolver::configure` since R3 — this is the feed that was never emitted, so the production
     * Router sat empty). The array arrives READY from Rust ([TortaCore.resolverRoutesJson]:
     * Rust-parsed from the durable `resolver-routes` record + Rust-escaped — no Kotlin JSON
     * assembly of user input). No rules ⇒ the pre-P12 byte-identical object (the empty-Router
     * fast path). A rule naming an upstream id outside THIS pool is skipped by the engine's
     * `valid_ids` gate — fail-open, never fatal; `address=` literal rules work in every pool mode.
     * Crash-safe: a routes-read fault degrades to no routes.
     */
    private fun wrapSpecs(upstreams: String): String {
        val routes =
            try {
                TortaCore.resolverRoutesJson(durableDir())
            } catch (e: Exception) {
                loge("ResolverRuntime wrapSpecs routes read", e)
                ""
            }
        return if (routes.isEmpty()) {
            """{"upstreams":[$upstreams]}"""
        } else {
            """{"upstreams":[$upstreams],"routes":$routes}"""
        }
    }

    /**
     * The transport-selection mode for the live Rust resolver pool. See [poolMode].
     */
    private enum class PoolMode {
        /** MODE 2 — Rust DNSCrypt v2 stamps, Rust answers encrypted queries directly (production default). */
        RUST,

        /** MODE 1 — Go loopback via do53, Go answers + Rust inert (the explicit/automatic fallback). */
        GO,
    }

    /**
     * ★ SOVEREIGN REWIRE — start the periodic fallback-detector loop. Native-arm-only (an un-armed
     * install never calls torta_resolve, so there is no Rust load to monitor). The loop polls
     * [maybeFallbackToGo] every [FALLBACK_CHECK_PERIOD_MS]; each poll is a cheap stats-JSON read + a
     * threshold compare, off the tun thread (on [dispatcherIo]). Cancels its prior instance first so a
     * re-RUNNING edge never leaks two checkers. The loop self-terminates when [configured] flips false
     * (a STOPPED edge) even if the cancel races. Crash-safe: the body swallows everything.
     */
    private fun startFallbackCheckLoop() {
        try {
            fallbackCheckJob?.cancel()
            fallbackCheckJob = null
            fallbackCheckJob =
                coroutineScope.launch {
                    var tick = 0L
                    while (configured) {
                        kotlinx.coroutines.delay(FALLBACK_CHECK_PERIOD_MS)
                        if (!configured) break
                        maybeFallbackToGo()
                        // D13 (RAM⊗NAND) — GENTLE periodic answer-cache checkpoint. The warm cache used
                        // to survive ONLY the clean-stop edge (onDnsCryptStopped); a common Android
                        // process death (OOM-kill, force-stop, crash, battery swipe) lost the whole warm
                        // set. Piggyback a persist on this existing cadence every PERSIST_EVERY_N_TICKS
                        // (~10 min at the 15-s poll) so a hard kill starts WARM. Control-plane only (the
                        // Rust persist releases the cache lock before NAND IO); best-effort + crash-safe.
                        tick += 1L
                        if (tick % PERSIST_EVERY_N_TICKS == 0L) checkpointCache()
                    }
                }
        } catch (e: Exception) {
            loge("ResolverRuntime startFallbackCheckLoop", e)
        }
    }

    /**
     * D13 (RAM⊗NAND) — a GENTLE control-plane persist of the live answer cache to NAND, off the resolve
     * hot path. Fired periodically by [startFallbackCheckLoop] and once BEFORE the standalone retarget
     * (which installs a fresh pool/cache and would otherwise drop the warm set). Best-effort: a persist
     * fault leaves the in-memory tier untouched and is swallowed. Never throws.
     */
    private fun checkpointCache() {
        try {
            val persisted = TortaCore.persistCache(durableDir())
            if (persisted > 0)
                logi("ResolverRuntime cache checkpointed: $persisted bytes to NAND (D13 periodic)")
        } catch (e: Exception) {
            loge("ResolverRuntime checkpointCache", e)
        }
    }

    /** Cancel the periodic fallback-detector loop (called on STOPPED). Idempotent + crash-safe. */
    private fun stopFallbackCheckLoop() {
        try {
            fallbackCheckJob?.cancel()
        } catch (e: Exception) {
            loge("ResolverRuntime stopFallbackCheckLoop", e)
        }
        fallbackCheckJob = null
    }

    /**
     * ★ SOVEREIGN REWIRE — the runtime fallback detector. Examines the live Rust resolver stats JSON
     * (the SAME object [logShadowSummary] appends) and decides whether the Rust DNSCrypt transport is
     * failing under load. Two hysteresis bands, both over a minimum sample window so the detector
     * never trips on cold-start noise:
     *
     * - **TRIP (Rust → Go):** once at least [FALLBACK_MIN_SAMPLE] queries have been attempted AND the
     *   Rust failure rate (`(transport_miss + panics) / queries`) exceeds [FALLBACK_TRIP_RATE], flip
     *   [fallbackActive] to `true` and RECONFIGURE the pool to the Go loopback (MODE 1). The Go binary
     *   is already spawned (it is the loopback listener), so the reconfigure is a pure pool-swap — Go
     *   starts answering immediately. The C per-query fallback (udp.c:497) was already catching each
     *   failing query; this swaps the WHOLE pool so Rust stops being tried first.
     * - **RECOVER (Go → Rust):** once at least [FALLBACK_RECOVER_SAMPLE] MORE queries have been
     *   answered via the Go pool AND the user still has the Rust transport enabled, clear
     *   [fallbackActive] and RECONFIGURE back to the Rust stamps (MODE 2). This gives Rust a fresh
     *   chance after the transient load that tripped it has passed. Capped to once per
     *   [FALLBACK_RECOVER_COOLDOWN_MS] so a flapping network cannot ping-pong the pool.
     *
     * Never throws (a stats-parse / configure fault leaves the prior decision standing — fail-safe).
     * Called periodically from [fallbackCheckLoop] (release, when the native arm is active) and from
     * the DEBUG shadow path. NO-OP when the user explicitly disabled the Rust transport (MODE 1 is
     * already the chosen posture, so there is nothing to fall back FROM).
     */
    @Synchronized
    private fun maybeFallbackToGo() {
        try {
            if (!configured) return
            // The user's explicit choice: if they disabled the Rust transport, MODE 1 is already the
            // posture — no fallback decision to make.
            val userWantsRust =
                try {
                    defaultPreferences.getBoolean(TortaeKeys.RESOLVER_USE_RUST_DNSCRYPT, true)
                } catch (e: Exception) {
                    true
                }
            val stats = parseResolverStats(TortaCore.resolverStats()) ?: return
            val queries = stats.queries
            val fails = stats.transportMiss + stats.panics

            if (!fallbackActive) {
                // TRIP band — only meaningful when the user wants Rust (otherwise MODE 1 is intentional).
                if (userWantsRust &&
                    queries >= FALLBACK_MIN_SAMPLE &&
                    fails * 100 >= queries * FALLBACK_TRIP_RATE
                ) {
                    fallbackActive = true
                    fallbackRecoverAt = 0L
                    loge(
                        "ResolverRuntime FALLBACK TRIP — Rust failure ${fails}/$queries " +
                            "(${fails * 100 / queries}%) ≥ ${FALLBACK_TRIP_RATE}%, switching pool to Go loopback"
                    )
                    reconfigure()
                }
            } else {
                // RECOVER band — only when the user still wants Rust and the cooldown has elapsed.
                val now = android.os.SystemClock.elapsedRealtime()
                val cooldownOk = now >= fallbackRecoverAt
                if (userWantsRust && cooldownOk && queries - fallbackTripQueries >= FALLBACK_RECOVER_SAMPLE) {
                    logi(
                        "ResolverRuntime FALLBACK RECOVER — Rust stable for " +
                            "${queries - fallbackTripQueries} queries, switching pool back to Rust stamps"
                    )
                    fallbackActive = false
                    reconfigure()
                }
            }
        } catch (e: Exception) {
            // A detector fault must never escape — leave the prior decision standing (fail-safe).
            loge("ResolverRuntime maybeFallbackToGo", e)
        }
    }

    /**
     * Snapshot [fallbackTripQueries] at TRIP time so [maybeFallbackToGo]'s RECOVER band counts queries
     * answered UNDER the Go pool (not the lifetime total). Reset to 0 on TRIP + on every RUNNING edge.
     */
    @Volatile private var fallbackTripQueries: Long = 0L

    /**
     * The earliest epoch (elapsedRealtime) the RECOVER band may re-arm Rust, set to
     * `now + FALLBACK_RECOVER_COOLDOWN_MS` at TRIP time so a flapping network cannot ping-pong the pool.
     */
    @Volatile private var fallbackRecoverAt: Long = 0L

    /**
     * Reconfigure the pool with the CURRENT [poolMode] decision (Rust stamps or Go loopback). Called
     * by [maybeFallbackToGo] after a TRIP / RECOVER, and by [onDnsCryptStarted] on the RUNNING edge.
     * Snapshots [fallbackTripQueries] on a TRIP so the RECOVER band has a clean baseline. Crash-safe:
     * a configure fault leaves the prior pool standing (the C per-query fallback is the safety net).
     */
    private fun reconfigure() {
        val summary = configureFromUpstreams(dnsCryptRunning = true)
        if (summary != null) {
            configured = true
            if (fallbackActive) {
                // Baseline the query count at TRIP so RECOVER counts queries under the Go pool.
                val s = parseResolverStats(TortaCore.resolverStats())
                fallbackTripQueries = s?.queries ?: 0L
                fallbackRecoverAt =
                    android.os.SystemClock.elapsedRealtime() + FALLBACK_RECOVER_COOLDOWN_MS
            }
            logi("ResolverRuntime pool reconfigured (fallbackActive=$fallbackActive): $summary")
        } else {
            loge("ResolverRuntime reconfigure returned null — prior pool left standing")
        }
    }

    /**
     * The subset of the resolver stats JSON ([TortaCore.resolverStats]) the fallback detector reads.
     * `transport_miss` = Rust transport failures (timeout / refused / AEAD-reject); `panics` = Rust
     * panic-firewall trips. Both are signals the Rust transport could not answer.
     */
    private data class ResolverStatsSnap(val queries: Long, val transportMiss: Long, val panics: Long)

    /**
     * Parse the three integers the fallback detector needs out of the `resolverStats()` JSON. The JSON
     * is a flat `{"queries":N,"transport_miss":N,"panics":N,…}` object (resolver/mod.rs:955), so a
     * regex pull is robust to any field reordering / future additions. Returns null on any malformed
     * input (the detector then no-ops — fail-safe, never trips on a bad read).
     */
    private fun parseResolverStats(json: String): ResolverStatsSnap? {
        return try {
            ResolverStatsSnap(
                queries = jsonLong(json, "\"queries\":"),
                transportMiss = jsonLong(json, "\"transport_miss\":"),
                panics = jsonLong(json, "\"panics\":"),
            )
        } catch (e: Exception) {
            null
        }
    }

    /** Pull the integer following [key] in a flat JSON object; 0 if the key is absent. Never throws. */
    private fun jsonLong(json: String, key: String): Long {
        val i = json.indexOf(key)
        if (i < 0) return 0L
        var j = i + key.length
        val sb = StringBuilder()
        while (j < json.length) {
            val c = json[j]
            if (c.isDigit()) sb.append(c) else if (sb.isNotEmpty()) break
            j++
        }
        return sb.toString().toLongOrNull() ?: 0L
    }

    /**
     * The SHADOW seam, called from `ServiceVPN.dnsResolved(rr)` right after the Wave-1
     * `BlocklistRuntime.observe`. Synthesizes the wire query for the real record's address family
     * only (FIX 1), fires it into the native resolver OFF the caller thread, and records LENIENT
     * agreement (Rcode class + existence parity, FIX 2) plus the shadow's own resolve latency (FIX
     * 3).
     *
     * Egress is bounded (FIX 4): a [shadowSlots] semaphore caps concurrent shadows at
     * [MAX_INFLIGHT] (full ⇒ DROP, never queue) and a [recentQnames] conflation window suppresses
     * back-to-back re-shadows of the same name. Both the cap-drop and the conflation-skip are
     * counted non-events.
     *
     * Returns immediately and touches nothing on the datapath: the launch is on [dispatcherIo],
     * `rr` is read but never mutated, and every failure (null resolve, parse miss, throw) is a
     * swallowed, counted non-event. This is the whole point of Stage-0 — the shadow governs
     * nothing.
     */
    fun shadowCompare(rr: ResourceRecord) {
        // Belt-and-braces RELEASE kill-switch (constraint 4): even if a caller forgets the
        // BuildConfig
        // gate at the seam, the shadow harness (counters + duplicate egress) is INERT in release.
        // The
        // const-true `!BuildConfig.DEBUG` lets the optimizer drop the whole body in a release
        // build.
        if (!BuildConfig.DEBUG) return
        // Seam liveness, counted BEFORE every gate (T20: a count, never a qname). This is what the
        // soak
        // reads to split "seam not firing" from "resolve dark": seamHits>0 ⇒ the seam IS firing.
        shadowSeamHits.incrementAndGet()
        // Snapshot the immutable fields we need NOW, on the caller thread, then never touch `rr`
        // again
        // (it is reused/recycled by the native side). The launch must not capture mutable state.
        val qname = rr.QName?.trim()?.lowercase().orEmpty()
        if (qname.isEmpty()) return
        if (!configured) return
        val realResource = rr.Resource.orEmpty().trim()
        val realRcode = rr.Rcode
        // FIX 1 — the family of the real record's single IP literal decides which shadow qtype
        // runs.
        // dns.c emits one `dns_resolved` per answer record with ONE family literal, so an A-shadow
        // must
        // never be scored against an AAAA-real (and vice-versa). A non-IP Resource
        // (CNAME/HINFO/empty or
        // a denial) carries no family to gate on → fall back to BOTH qtypes, judged on Rcode class
        // only.
        val realFamily = ipFamilyOf(realResource)
        val qtypes =
            when (realFamily) {
                FAMILY_V4 -> QTYPES_A_ONLY
                FAMILY_V6 -> QTYPES_AAAA_ONLY
                else -> QTYPES_BOTH
            }

        // FIX 4 (conflation) — skip a name we shadowed within the window; a tight burst is one
        // shadow.
        if (!shouldShadowNow(qname)) {
            shadowsDropped.incrementAndGet()
            return
        }
        // FIX 4 (in-flight cap) — DROP, never queue, when MAX_INFLIGHT shadows are already running.
        if (!shadowSlots.tryAcquire()) {
            shadowsDropped.incrementAndGet()
            return
        }

        coroutineScope.launch {
            try {
                // Double-check inside the coroutine — the gate can flip on a STOPPED edge between
                // launch
                // and dispatch; an un-configured resolve is just a null (counted), so this is
                // belt+braces.
                if (!configured) return@launch
                for (qtype in qtypes) {
                    try {
                        val synth = synthQuery(qname, qtype) ?: continue
                        val startNs = System.nanoTime()
                        val answer = TortaCore.resolve(synth)
                        val elapsedMs = (System.nanoTime() - startNs) / 1_000_000L
                        if (answer == null) {
                            // null == "fall through to dnscrypt-proxy": a cache miss, a blocked
                            // name, a
                            // rejected/poisoned upstream answer, or simply not-configured. NEVER a
                            // disagreement — it is the resolver declining to assert. Counted, not
                            // judged.
                            resolverNulls.incrementAndGet()
                            continue
                        }
                        val shadow =
                            parseAnswer(answer)
                                ?: run {
                                    // A non-null reply we could not parse is an error on OUR side,
                                    // not a verdict.
                                    shadowErrors.incrementAndGet()
                                    continue
                                }
                        comparisons.incrementAndGet()
                        shadowLatencySumMs.addAndGet(elapsedMs)
                        if (recordsAgree(shadow, qtype, realFamily, realResource, realRcode)) {
                            agreements.incrementAndGet()
                        } else {
                            disagreements.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        // A shadow throw is invisible to the real answer (already delivered). Count
                        // + move on.
                        shadowErrors.incrementAndGet()
                    }
                }
                maybeLogShadowSummary()
            } finally {
                // ALWAYS release the permit — a throw above must never leak an in-flight slot (FIX
                // 4).
                shadowSlots.release()
            }
        }
    }

    /**
     * P7 2e — a **REDUNDANT LIVE qname seam** for DNSCrypt-VPN mode, called by [QueryLogTailer] for
     * each NEW resolved line tailed out of dnscrypt-proxy's `query.log`. It is a SECOND live
     * trigger that runs ALONGSIDE the rr-seam ([shadowCompare] above) — NOT a replacement for a
     * "dark" rr-seam. The rr-seam DOES fire in DNSCrypt mode: the app dials a PUBLIC bootstrap DNS
     * IP (`VpnBuilder` rejects loopback, :363), so the tun packet is born dest==53, and
     * `s->udp.dest` STAYS 53 — `udp.c:326` records it from the ORIGINAL packet BEFORE the
     * socket-level loopback->`127.0.0.1:5354` redirect (`udp.c:449-457`, which rewrites only the
     * `sendto` target, not `s->udp.dest`); the reply gate `udp.c:143` (dest==53) is then TRUE →
     * `dns_resolved` → `ServiceVPN.dnsResolved` → `shadowCompare(rr)`. So BOTH seams fire and SHARE
     * one egress pool. This qname seam adds value as redundant coverage that carries the RETURNCODE
     * class — and because query.log sidesteps the tun entirely (the proxy writes it AFTER returning
     * the answer to the app, so this tail can never sit on / touch / delay / drop the real answer,
     * PRIME). (Corrected per [[shadow-seam-unreachable-dnscrypt-mode]], REFUTED 2026-06-19 — the
     * earlier "provably dark" read was a shadow-side gate (configure-null / do53 reject), NOT
     * structural unreachability; do NOT delete the rr-seam as dead code.)
     *
     * Unlike the rr-seam there is **nothing to byte-compare**: query.log carries the qname +
     * RETURNCODE class but NO answer IPs, so the headline metric is honest **resolver-health** —
     * did our OWN Rust resolver (re-resolving the SAME qname through the SAME `127.0.0.1:<port>`
     * do53 loopback proxy) get a positive answer ([qnameResolved]) or a denial/empty
     * ([qnameFailed])? An OPTIONAL lenient RETURNCODE-class parity bonus compares the shadow's
     * positive/denial verdict to the real return code (positive {PASS,FORWARD,SYNTH,CLOAK} vs
     * denial otherwise) — observability only.
     *
     * Same bullet-proof contract as the rr-seam, and it SHARES the same egress budget: the same
     * [shadowSlots] [Semaphore] cap and the same [recentQnames] conflation window (one pool of
     * shadow egress for both seams). Off-thread, snapshot-and-swallow, T20 (the qname drives the
     * resolve and is NEVER re-logged — only the qname-free [qnameResolved]/[qnameFailed] counts are
     * surfaced).
     *
     * @param qname the resolved name tailed from query.log (already de-quoted by the tailer).
     * @param realReturnCode the query.log RETURNCODE class (field[4]) for the OPTIONAL parity
     *   bonus; the resolver-health verdict does NOT depend on it, so null is fine.
     */
    fun shadowCompare(qname: String, realReturnCode: String?) {
        // Belt-and-braces RELEASE kill-switch (privacy-critical): this whole qname harness — and
        // the
        // duplicate egress it drives — is INERT in release. The const-true `!BuildConfig.DEBUG`
        // lets the
        // optimizer drop the entire body (and so the only call site for query-log tailing) in
        // release.
        if (!BuildConfig.DEBUG) return
        // Seam liveness, counted BEFORE every gate (T20: a count, never the qname). The soak reads
        // this
        // to prove this REDUNDANT qname trigger also fires in DNSCrypt-VPN mode (the rr-seam fires
        // here
        // too — s->udp.dest stays 53, udp.c:326/449-457 — so both seams feed seamHits).
        shadowSeamHits.incrementAndGet()
        val q = qname.trim().lowercase()
        if (q.isEmpty()) return
        if (!configured) return
        // A bare qname carries no address family → resolve BOTH A and AAAA (the FAMILY_NONE
        // fall-through,
        // judged on the shadow's own Rcode/answer, exactly like the rr-seam's no-family case).
        val realPositive = isPositiveReturnCode(realReturnCode)

        // Conflation — skip a name we shadowed within the window; a tight burst is one shadow.
        // SHARED
        // with the rr-seam so the two seams never double-shadow the same name back-to-back.
        if (!shouldShadowNow(q)) {
            shadowsDropped.incrementAndGet()
            return
        }
        // In-flight cap — DROP, never queue, when MAX_INFLIGHT shadows are already running (SHARED
        // pool).
        if (!shadowSlots.tryAcquire()) {
            shadowsDropped.incrementAndGet()
            return
        }

        coroutineScope.launch {
            try {
                // Re-check inside the coroutine — the gate can flip on a STOPPED edge between
                // launch and
                // dispatch; an un-configured resolve is just a counted null, so this is
                // belt+braces.
                if (!configured) return@launch
                for (qtype in QTYPES_BOTH) {
                    try {
                        val synth = synthQuery(q, qtype) ?: continue
                        val startNs = System.nanoTime()
                        val answer = TortaCore.resolve(synth)
                        val elapsedMs = (System.nanoTime() - startNs) / 1_000_000L
                        if (answer == null) {
                            // null == "fall through to dnscrypt-proxy": a cache miss /
                            // not-configured /
                            // declined upstream answer. NEVER a failure verdict — the resolver
                            // declined
                            // to assert. Counted, not judged (shared with the rr-seam's null
                            // tally).
                            resolverNulls.incrementAndGet()
                            continue
                        }
                        val shadow =
                            parseAnswer(answer)
                                ?: run {
                                    // A non-null reply we could not parse is an error on OUR side,
                                    // not a verdict.
                                    shadowErrors.incrementAndGet()
                                    continue
                                }
                        // E-FIX round-1: this seam's OWN tallies (bucket-coherence note above).
                        qnameCompares.incrementAndGet()
                        qnameLatencySumMs.addAndGet(elapsedMs)
                        // Resolver-health (the HEADLINE metric): positive iff NOERROR + a non-empty
                        // A/AAAA answer of EITHER family (a bare qname makes no single-family
                        // claim).
                        val shadowPositive =
                            shadow.rcode == RCODE_NOERROR &&
                                (shadow.ipv4.isNotEmpty() || shadow.ipv6.isNotEmpty())
                        if (shadowPositive) {
                            qnameResolved.incrementAndGet()
                        } else {
                            qnameFailed.incrementAndGet()
                        }
                        // OPTIONAL lenient RETURNCODE-class parity bonus (observability only): does
                        // the
                        // shadow's positive/denial verdict agree with the real query.log return
                        // code? Only
                        // scored when the tailer actually supplied a return code (else it stays
                        // neutral).
                        if (realReturnCode != null) {
                            if (shadowPositive == realPositive) {
                                qnameRcodeAgree.incrementAndGet()
                            } else {
                                qnameRcodeDisagree.incrementAndGet()
                            }
                        }
                    } catch (e: Exception) {
                        // A shadow throw is invisible to the real answer (already delivered). Count
                        // + move on.
                        shadowErrors.incrementAndGet()
                    }
                }
                maybeLogShadowSummary()
            } finally {
                // ALWAYS release the permit — a throw above must never leak an in-flight slot.
                shadowSlots.release()
            }
        }
    }

    /**
     * Map a query.log RETURNCODE class to the lenient positive/denial split for the OPTIONAL parity
     * bonus in the qname overload. Positive = the proxy asserted an answer ({PASS, FORWARD, SYNTH,
     * CLOAK}); everything else (REJECT, DROP, NXDOMAIN, SERVFAIL, RESPONSE_ERROR, SERVER_TIMEOUT,
     * NETWORK_ERROR, PARSE_ERROR, NOT_READY, null/unknown) is treated as a denial. Pure, never
     * throws.
     */
    private fun isPositiveReturnCode(rcode: String?): Boolean {
        val r = rcode?.trim()?.uppercase() ?: return false
        return r == "PASS" || r == "FORWARD" || r == "SYNTH" || r == "CLOAK"
    }

    /**
     * FIX 4 conflation gate: return true (and record the timestamp) iff `qname` has NOT been
     * shadowed within [CONFLATE_WINDOW_MS]. Opportunistically prunes stale entries and hard-caps
     * the map size so a flood of distinct names cannot grow it without bound. Pure bookkeeping;
     * never throws into the caller (a failure here just degrades to "shadow it").
     */
    private fun shouldShadowNow(qname: String): Boolean {
        return try {
            val now = android.os.SystemClock.elapsedRealtime()
            val last = recentQnames[qname]
            if (last != null && now - last < CONFLATE_WINDOW_MS) {
                return false
            }
            recentQnames[qname] = now
            // Bound the map: prune stale entries, and if still oversized, clear it outright (a
            // coarse but
            // O(1)-amortised cap — the worst case is a brief loss of conflation, never a leak).
            if (recentQnames.size > CONFLATE_MAX) {
                recentQnames.entries.removeAll { now - it.value >= CONFLATE_WINDOW_MS }
                if (recentQnames.size > CONFLATE_MAX) recentQnames.clear()
            }
            true
        } catch (e: Exception) {
            true
        }
    }

    // ---- Wire synthesis (A=1, AAAA=28). SINGLE SOURCE OF TRUTH = the Rust dns::build_query codec.
    // ----

    /**
     * Synthesize the wire query through the SINGLE codec source of truth (FIX 5 — option A). Calls
     * the native [TortaCore.buildQuery], which wraps the already-tested Rust `dns::build_query`
     * (`dns.rs:107`) — the SAME builder the resolver itself uses — so the shadow never compiles a
     * second, hand-kept- byte-identical wire builder. [buildWireQuery] below is the DOCUMENTED
     * FALLBACK, used ONLY when the native codec is unreachable (a missing `.so` for the running
     * ABI, or a native fault → null façade), so the seam never goes dark; it is otherwise dead on
     * every shipping ABI. Never throws.
     */
    private fun synthQuery(qname: String, qtype: Int): ByteArray? =
        TortaCore.buildQuery(qname, qtype) ?: buildWireQuery(qname, qtype)

    /**
     * DOCUMENTED FALLBACK codec — used ONLY when the native [TortaCore.buildQuery] is unreachable
     * (the `.so` is absent for the running ABI), keeping the shadow seam live rather than dark. On
     * every shipping ABI the native path wins and this body is never reached. Build a recursive
     * A/AAAA query for `qname` with a random 16-bit ID; byte-format-identical to the Rust
     * `dns::build_query` (12-byte header, RD=1, QDCOUNT=1, QCLASS=IN). ASCII labels only; over-long
     * labels (>63) abort the synthesis (returns null → that qtype is skipped). NOTE: the
     * authoritative Rust codec TRUNCATES an over-long label to 63 bytes (`dns.rs:118`
     * `.min(MAX_LABEL_LEN)`) rather than skipping the qtype — the only behavioural seam between the
     * two, reached only on the (sub-63 in practice) fallback path; the native codec is the truth on
     * every shipping build.
     */
    private fun buildWireQuery(qname: String, qtype: Int): ByteArray? {
        try {
            val id = Random.nextInt(0, 0x10000)
            val out = ArrayList<Byte>(qname.length + 18)
            out.add((id shr 8).toByte())
            out.add((id and 0xFF).toByte()) // query ID
            out.add(0x01)
            out.add(0x00) // flags: RD = 1
            out.add(0x00)
            out.add(0x01) // QDCOUNT = 1
            out.add(0x00)
            out.add(0x00) // ANCOUNT
            out.add(0x00)
            out.add(0x00) // NSCOUNT
            out.add(0x00)
            out.add(0x00) // ARCOUNT
            for (label in qname.split('.')) {
                if (label.isEmpty()) continue
                val bytes = label.encodeToByteArray()
                if (bytes.size > MAX_LABEL_LEN)
                    return null // malformed → skip this qtype, never throw
                out.add(bytes.size.toByte())
                for (b in bytes) out.add(b)
            }
            out.add(0) // root label
            out.add((qtype shr 8).toByte())
            out.add((qtype and 0xFF).toByte()) // QTYPE
            out.add(0x00)
            out.add(0x01) // QCLASS = IN
            return out.toByteArray()
        } catch (e: Exception) {
            return null
        }
    }

    // ---- Response parsing. Bounds-checked, exception-proof; extracts Rcode + A/AAAA RDATA only.
    // ----

    /**
     * What the shadow extracted from one wire response: the answer-record Rcode and the IPs it
     * carried.
     */
    private data class ShadowAnswer(val rcode: Int, val ipv4: Set<String>, val ipv6: Set<String>)

    /**
     * Parse a validated wire DNS response into [ShadowAnswer]. Returns null on ANY malformed input
     * — the resolver already ran `validate_response`, but we never trust length, so every read is
     * bounds-guarded and a compression pointer in an answer owner-name is skipped, not followed.
     */
    private fun parseAnswer(resp: ByteArray): ShadowAnswer? {
        try {
            if (resp.size < 12) return null
            val rcode = resp[3].toInt() and 0x0F
            val qdCount = u16(resp, 4)
            val anCount = u16(resp, 6)
            // Walk past the question section (QDCOUNT questions: name + QTYPE(2) + QCLASS(2)).
            var pos = 12
            repeat(qdCount) {
                pos = skipName(resp, pos) ?: return null
                pos += 4 // QTYPE + QCLASS
                if (pos > resp.size) return null
            }
            val ipv4 = LinkedHashSet<String>()
            val ipv6 = LinkedHashSet<String>()
            repeat(anCount) {
                pos = skipName(resp, pos) ?: return null
                if (pos + 10 > resp.size) return null
                val rtype = u16(resp, pos)
                val rdlength = u16(resp, pos + 8)
                val rdataAt = pos + 10
                val end = rdataAt + rdlength
                if (end > resp.size) return null
                when {
                    rtype == TYPE_A && rdlength == 4 ->
                        ipv4.add(
                            InetAddress.getByAddress(resp.copyOfRange(rdataAt, end))
                                .hostAddress
                                .orEmpty()
                        )
                    rtype == TYPE_AAAA && rdlength == 16 ->
                        // Normalise IPv6 to its canonical compressed form for a robust string
                        // compare.
                        ipv6.add(
                            (InetAddress.getByAddress(resp.copyOfRange(rdataAt, end))
                                    as? Inet6Address)
                                ?.hostAddress
                                ?.substringBefore('%')
                                .orEmpty()
                        )
                }
                pos = end
            }
            return ShadowAnswer(rcode, ipv4, ipv6)
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Compare the shadow result to the real [ResourceRecord] LENIENTLY (FIX 2) — never
     * byte/IP-exact.
     *
     * Two independent recursive resolvers legitimately return DIFFERENT CDN/GeoDNS IPs for the same
     * name, so exact-IP equality is the wrong metric (it would manufacture endless false
     * disagreements). What we actually validate is *"the native resolver resolves this name
     * consistently with the real path"*, defined as:
     *
     * (a) **same Rcode class** — both NOERROR-with-answer, OR both a denial (NXDOMAIN / NODATA /
     * SERVFAIL); a successful answer on one side and a denial on the other is a real disagreement;
     * AND (b) **existence parity** — when the real path produced a positive same-family answer, the
     * shadow also produced a non-empty answer of THAT family. Whether the IPs match is NOT required
     * for agreement (but an exact membership hit is recorded in [exactMatches] as a cheap
     * sub-metric).
     *
     * The qtype is already family-gated by the caller (FIX 1), so `qtype`/`realFamily` agree with
     * the real record; we still pass both for the empty/denial fall-throughs.
     */
    private fun recordsAgree(
        shadow: ShadowAnswer,
        qtype: Int,
        realFamily: Int,
        realResource: String,
        realRcode: Int,
    ): Boolean {
        val shadowFamilyIps = if (qtype == TYPE_AAAA) shadow.ipv6 else shadow.ipv4
        val shadowPositive = shadow.rcode == RCODE_NOERROR && shadowFamilyIps.isNotEmpty()
        val hasFamilyLiteral =
            realResource.isNotEmpty() && (realFamily == FAMILY_V4 || realFamily == FAMILY_V6)
        val realPositive = realRcode == RCODE_NOERROR && hasFamilyLiteral

        // A genuine DENIAL on the real side (NXDOMAIN/NODATA/SERVFAIL — any non-NOERROR Rcode).
        // Same
        // Rcode-class + existence-parity agreement = the shadow ALSO did not produce a positive
        // answer
        // of this family. A shadow that resolves a name the real path denied is a real
        // disagreement.
        if (realRcode != RCODE_NOERROR) {
            return !shadowPositive
        }

        // NOERROR on the real side but no same-family literal to assert (a CNAME/HINFO-only record
        // — the
        // terminal A/AAAA literals arrive as their OWN family-gated ResourceRecords via separate
        // dns_resolved calls, see dns.c). This event makes no family claim, so the shadow's
        // positivity
        // is NOT contradicted either way → neutral agreement. (FAMILY_NONE here means "nothing to
        // gate
        // on", never "the name does not exist".)
        if (!realPositive) {
            return true
        }

        // The real path produced a positive same-family literal. Agreement (FIX 2) = the shadow
        // also
        // produced a NON-EMPTY same-family answer (existence parity) — NOT that the IPs are
        // identical.
        if (!shadowPositive) return false

        // Cheap optional exact-IP sub-counter (FIX 2): note when the real literal is ALSO in the
        // shadow
        // set. This never changes the headline verdict — it is observability only.
        if (realResource in shadowFamilyIps) {
            exactMatches.incrementAndGet()
        }
        return true
    }

    /**
     * FIX 1 — classify a real `Resource` literal's address family by string shape, mirroring the
     * rule the gate uses: a value containing `:` is IPv6; a dotted value with no `:` is IPv4;
     * anything else (empty, a CNAME target, HINFO text) is [FAMILY_NONE] and is not family-gated.
     * Pure string test — no allocation, no DNS parsing, never throws.
     */
    private fun ipFamilyOf(resource: String): Int =
        when {
            resource.isEmpty() -> FAMILY_NONE
            resource.contains(':') -> FAMILY_V6
            resource.contains('.') -> FAMILY_V4
            else -> FAMILY_NONE
        }

    // ---- Wire helpers (all bounds-checked; callers already guard via the surrounding try/catch).
    // ----

    private fun u16(b: ByteArray, off: Int): Int {
        if (off + 1 >= b.size) return 0
        return ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
    }

    /**
     * Advance past a DNS name starting at [start]. Handles label runs and a single compression
     * pointer (0xC0): a pointer ends the name in 2 bytes (we do NOT follow it — only its length
     * matters here). Returns the offset just past the name, or null if it runs off the end / loops.
     */
    private fun skipName(b: ByteArray, start: Int): Int? {
        var pos = start
        var guard = 0
        while (pos < b.size) {
            if (guard++ > MAX_NAME_HOPS) return null
            val len = b[pos].toInt() and 0xFF
            when {
                len == 0 -> return pos + 1 // root label terminates the name
                len and 0xC0 == 0xC0 -> return pos + 2 // compression pointer = 2 bytes, done
                len <= MAX_LABEL_LEN -> pos += 1 + len // ordinary label
                else -> return null // reserved length bits → malformed
            }
        }
        return null
    }

    // ---- Shadow telemetry (compact, periodic, qname-free at default verbosity, T20). ----

    private fun maybeLogShadowSummary() {
        // Count nulls+errors too, so a "seam fires but resolve is dark" run STILL prints a
        // [periodic]
        // line at low volume (the soak needs that line even when comparisons==0).
        // E-FIX round-1: qnameCompares rides the trigger too — in DNSCrypt-VPN mode the qname seam
        // carries most of the volume (it no longer bumps `comparisons`), and the periodic line must
        // keep printing there.
        val total =
            comparisons.get() + qnameCompares.get() + resolverNulls.get() + shadowErrors.get()
        if (total > 0 && total % LOG_EVERY == 0L) {
            logShadowSummary("periodic")
        }
        // ★ SOVEREIGN REWIRE — piggyback the fallback detector on the shadow's periodic tick too
        // (DEBUG observability: the soak sees a TRIP/RECOVER decision in the periodic log line).
        // In release the dedicated fallbackCheckLoop drives the detector; this DEBUG call is
        // belt-and-braces and harmless (maybeFallbackToGo is @Synchronized + idempotent).
        maybeFallbackToGo()
    }

    private fun logShadowSummary(reason: String) {
        val cmp = comparisons.get()
        val agree = agreements.get()
        // Honest name (FIX 3): this is the MEAN ABSOLUTE shadow resolve latency, not a delta vs the
        // real path (whose timing is not available at this seam) — divide Σ shadow ms by
        // `comparisons`.
        val meanShadowMs = if (cmp > 0) shadowLatencySumMs.get() / cmp else 0
        val rate = if (cmp > 0) agree * 100 / cmp else 0
        // E-FIX round-1 (bucket coherence): the rr-seam block sums (agree+disagree == compares) and
        // the qname-seam block sums (qnameResolved+qnameFailed == qnameCompares) — each with its OWN
        // compare count + mean latency. No more `compares=170 agree=0 disagree=0` incoherence.
        val qCmp = qnameCompares.get()
        val meanQnameMs = if (qCmp > 0) qnameLatencySumMs.get() / qCmp else 0
        logi(
            "ResolverRuntime shadow [$reason] — seamHits=${shadowSeamHits.get()} " +
                "compares=$cmp agree=$agree (${rate}%) " +
                "exact=${exactMatches.get()} disagree=${disagreements.get()} " +
                "nulls=${resolverNulls.get()} errors=${shadowErrors.get()} " +
                "dropped=${shadowsDropped.get()} meanShadowLatency=${meanShadowMs}ms · " +
                // P7 2e qname-seam health (qname-free counts, T20): the LIVE DNSCrypt-VPN trigger.
                "qnameCompares=$qCmp qnameResolved=${qnameResolved.get()} " +
                "qnameFailed=${qnameFailed.get()} " +
                "qnameRcodeAgree=${qnameRcodeAgree.get()} qnameRcodeDisagree=${qnameRcodeDisagree.get()} " +
                "meanQnameLatency=${meanQnameMs}ms · " +
                TortaCore.resolverStats()
        )
    }

    companion object {
        private const val TYPE_A = 1
        private const val TYPE_AAAA = 28

        // ★ PHASE-1 VPN-TUNNELING — the standard loopback DNS port the in-app Rust resolver binds
        // (127.0.0.1:53). The VpnService tun forwards system DNS to this port so the encrypted
        // DNSCrypt resolver answers, not a public server. Named (not inline) because the literal is
        // the keystone of the sovereign rewire — self-documenting at the call site.
        private const val LOOPBACK_DNS_PORT = 53

        // P12 cloak-action canonical pref values — mirror the dashboard's DnsmasqDashboardFragment
        // values
        // AND the Rust BlockAction { NXDOMAIN | ZeroSink | CustomIp } (R2). Kept here so the apply
        // seam has
        // its own source of truth (the fragment owns the WRITE side; this owns the READ-and-push
        // side).
        private const val CLOAK_NXDOMAIN = "nxdomain"
        private const val CLOAK_ZEROSINK = "zerosink"
        private const val CLOAK_CUSTOM = "custom"

        // FIX 1 — family of the real record's single IP literal, deciding which shadow qtype runs.
        private const val FAMILY_NONE = 0 // empty / CNAME / HINFO / denial → no family to gate on
        private const val FAMILY_V4 = 4 // dotted quad, no ':' → run the A shadow only
        private const val FAMILY_V6 = 6 // contains ':' → run the AAAA shadow only

        // Family-gated qtype subsets (FIX 1). A V4 real ⇒ A only; a V6 real ⇒ AAAA only; no-family
        // ⇒
        // both (judged on Rcode class). An A-shadow is NEVER compared against an AAAA-real.
        private val QTYPES_A_ONLY = intArrayOf(TYPE_A)
        private val QTYPES_AAAA_ONLY = intArrayOf(TYPE_AAAA)
        private val QTYPES_BOTH = intArrayOf(TYPE_A, TYPE_AAAA)

        private const val RCODE_NOERROR = 0
        private const val MAX_LABEL_LEN = 63
        private const val MAX_NAME_HOPS = 128
        private const val SHADOW_TIMEOUT_MS = 3000L
        private const val CACHE_CAP = 1024
        // Lowered from 50: at the shadow's modest volume a [periodic] line every 10 events surfaces
        // real data in a short soak instead of staying silent under the old 50-event threshold.
        private const val LOG_EVERY = 10L

        // FIX 4 — egress cap. At most MAX_INFLIGHT concurrent shadow resolves (full ⇒ drop, never
        // queue), and the same qname is not re-shadowed within CONFLATE_WINDOW_MS. CONFLATE_MAX
        // bounds
        // the dedupe map under a flood of distinct names.
        private const val MAX_INFLIGHT = 4
        private const val CONFLATE_WINDOW_MS = 1500L
        private const val CONFLATE_MAX = 2048

        // ★ SOVEREIGN REWIRE — runtime fallback-detector thresholds (the Rust transport → Go loopback
        // pool swap). Hysteresis bands over a minimum sample window so the detector never trips on
        // cold-start noise nor flaps on a transient blip.
        // Poll cadence of [maybeFallbackToGo] from [startFallbackCheckLoop]. Cheap stats-JSON read +
        // threshold compare; off the tun thread. 15s balances responsiveness against pointless churn.
        private const val FALLBACK_CHECK_PERIOD_MS = 15_000L
        // D13 — persist the answer cache every Nth fallback-check tick. 40 × 15 s = 10 min: gentle
        // enough to add no measurable battery cost, frequent enough that a hard kill loses < 10 min of
        // warm cache instead of the whole set. Off the resolve hot path (control-plane persist).
        private const val PERSIST_EVERY_N_TICKS = 40L
        // TRIP band: at least this many queries must have been attempted before a failure rate is
        // considered meaningful (cold-start / idle install never trips on noise).
        private const val FALLBACK_MIN_SAMPLE = 25L
        // TRIP band: Rust failure rate (transport_miss + panics, in %) at/above which the pool flips to
        // the Go loopback. 50% = the Rust transport is failing on half its queries — structurally broken,
        // not a transient blip.
        private const val FALLBACK_TRIP_RATE = 50L
        // RECOVER band: this many MORE queries answered via the Go pool (after TRIP) before Rust gets a
        // fresh chance. Ensures the transient load that tripped it has genuinely passed.
        private const val FALLBACK_RECOVER_SAMPLE = 50L
        // RECOVER band: the earliest (elapsedRealtime) a RECOVER may re-arm Rust after a TRIP, so a
        // flapping network cannot ping-pong the pool. 2 min floor regardless of query count.
        private const val FALLBACK_RECOVER_COOLDOWN_MS = 120_000L

        /**
         * Public **DNSCrypt** default set (FIX 5) — `sdns://` v2 resolver stamps. This is what the
         * shadow actually dials today: the `dnscrypt` transport is a BASE transport (always
         * compiled) that carries NO TLS, so it needs NO rustls-platform-verifier and builds NOW —
         * unlike the DoH set below, which stays dark until the Wave 3-A verifier-init shim lands.
         * Both stamps are real, public, no-filter DNSCrypt resolvers (Quad9 + Scaleway/FR); the
         * native side fetches + Ed25519- verifies the provider cert and only ever speaks the
         * encrypted (XChaCha20-Poly1305) datapath.
         */
        private val DEFAULT_DNSCRYPT_UPSTREAMS =
            listOf(
                // Quad9 DNSCrypt (9.9.9.9:8443, provider 2.dnscrypt-cert.quad9.net).
                "dc-quad9" to
                    "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUc-nQwAVVL7zhCgFh6sxzaThUS0iBkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0",
                // Scaleway / dnscrypt.org FR (212.47.228.136, provider
                // 2.dnscrypt-cert.fr.dnscrypt.org).
                "dc-fr" to
                    "sdns://AQcAAAAAAAAADjIxMi40Ny4yMjguMTM2ILyg0gB85GNZ1Yp77jDXLB6gz2HewdYNW8s9z_XbjfWFHzIuZG5zY3J5cHQtY2VydC5mci5kbnNjcnlwdC5vcmc",
            )

        /**
         * Public DoH default set — retained as a DOC NOTE only (FIX 5). The encrypted-only native
         * resolver CAN build these via the `doh` transport, but `Http2Doh::new` rides rustls and
         * needs `rustls-platform-verifier` initialised against the Android trust store; that shim
         * is Wave 3-A and is NOT wired yet, so configuring DoH today returns null (shadow idle).
         * Once 3-A lands, swap [DEFAULT_DNSCRYPT_UPSTREAMS] → these (or merge) to also exercise the
         * DoH path.
         */
        @Suppress("unused")
        private val DEFAULT_DOH_UPSTREAMS =
            listOf(
                "cf" to "https://cloudflare-dns.com/dns-query",
                "goog" to "https://dns.google/dns-query",
                "quad9" to "https://dns.quad9.net/dns-query",
            )
    }
}
