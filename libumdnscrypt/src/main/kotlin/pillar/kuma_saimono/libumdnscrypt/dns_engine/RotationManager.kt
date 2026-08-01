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
import android.os.SystemClock
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import javax.inject.Inject
import javax.inject.Named

/**
 * P10 — ModulesService-scoped owner of the **periodic resolver pool rotation** (privacy by upstream
 * diversity). Mirrors [TrustManager]/[MonokumaDnsEngineManager]/[ResolverRuntime]'s lifecycle exactly —
 * armed when DNSCrypt goes RUNNING (or the engine starts standalone), torn down when it stops — but it
 * governs **nothing destructive**: every rotation pass is an ATOMIC pool swap that fails SAFE to the
 * current live set, so a rotation can NEVER break a live resolution.
 *
 * **The division of labour (this is the cadence/swap OWNER; the pick is delegated).** P10's selection logic
 * lands as DISJOINT sibling parts and this manager is the orchestrator that drives them on a cadence and
 * commits the result via the EXISTING atomic swap:
 *  - the **pick** is the pure, deterministic [RotationSelector] (`object` — trust-filter on the resolver
 *    stamp props + a completely-random bounded set pick over `ResolverCandidate`), fed by the ONE shared
 *    [RotationPoolSource] scan of the signed `public-resolvers.md`/`relays.md` (the SAME source +
 *    require_* policy [ResolverRuntime]'s MODE-2 derivation reads — one filter law, two consumers).
 *  - the **committed-set RTT** is the [RotationPing] adapter (a THIN reuse of the existing DNSCrypt
 *    servers ping seam — `ServersPingInteractor` → `SocketInternetChecker`): after a committed swap the
 *    JUST-LANDED pool is measured and the `<id>:<ms>` hints ride [persistRotationCursor] into the durable
 *    record (D30 — the warm-RTT half finally carries data end-to-end).
 *  - the **swap** lands on BOTH datapath brains (D06b): the dnscrypt TOML rewrite + restart
 *    ([applyRotationToDnscrypt] — the Go loopback side) AND the LIVE Rust MODE-2 pool
 *    ([ResolverRuntime.applyRotatedPool] — typed `UpstreamSpec`s through
 *    [TortaCore.configureResolverTyped], mode-guarded so an active Go fallback is never stomped).
 *
 * **How a rotation lands (REUSE, no parallel resolver path).** On each cadence tick this manager composes
 * the next trust-filtered random set as TYPED [uniffi.torta_core.UpstreamSpec]s (never a hand-built JSON
 * string — D34), writes it into dnscrypt's `server_names`/`routes` + restarts (the Go side), then hands
 * the SAME set to [ResolverRuntime.applyRotatedPool] → [TortaCore.configureResolverTyped] →
 * `resolver::configure`. A re-configure replaces the WHOLE pool under one Mutex pointer-swap; an in-flight
 * query clones its own `Arc<Pool>` out and drops the lock before `block_on`, so the swap cancels no live
 * query and exposes no half-built pool. And because [ResolverRuntime]'s MODE-2 pool is DERIVED from the
 * TOML's `server_names` (D06a), every later reconfigure (lifecycle edge, TRIP/RECOVER) re-lands the SAME
 * rotated pool — config-as-authority convergence, no second source of truth.
 *
 * **The fail-safe (load-bearing — rotation must never break a live resolution).** Two layers, both REUSED
 * from the configure path:
 *  1. [composeRotatedUpstreams] returns `null`/empty when there is no trusted candidate this cycle →
 *     this manager DOES NOT apply at all (keeps the current live set, Go and Rust alike).
 *  2. the Rust swap commits ONLY on a typed `ready > 0` [uniffi.torta_core.ConfigureReport] — a
 *     `null`/`ready=0` report means the native side left the previous pool INSTALLED (no swap); the
 *     TOML apply aborts with NO change on any fault ([applyRotationToDnscrypt]'s airtight guard). A
 *     fully-bad candidate set is a NO-OP, never a teardown.
 *
 * **Simple-UX.** The noob "rotate for privacy" switch ([TortaeKeys.RESOLVER_ROTATION_ENABLED]) is
 * DEFAULT ON — rotation-by-upstream-diversity is a core privacy pillar, so a fresh install rotates out of the
 * box (the v1 "default-ON the main pillars" posture; the GEEK switch turns it off). The raw cadence/policy knobs
 * ([TortaeKeys.RESOLVER_ROTATION_CADENCE_MINUTES], minute-granular default 30 min /
 * [TortaeKeys.RESOLVER_ROTATION_POLICY]) live
 * behind the ONE Expert toggle ([TortaeKeys.DNS_ENGINE_EXPERT], `pref_engine_expert`), exactly like the
 * engine's expert knobs ([MonokumaDnsEngineManager.readEngineConfig]). The master engine gate
 * ([TortaeKeys.DNS_ENGINE_ENABLED], default ON) also short-circuits rotation, mirroring
 * [TrustManager.start]/[MonokumaDnsEngineManager.startEngine].
 *
 * **No root, no `@Provides`.** The `@ModulesServiceScope` + `@Inject` ctor is auto-supplied by the
 * ModulesService subcomponent (same as the engine/resolver/trust). [start]/[stop] are `@Synchronized` and
 * idempotent, so the state-loop can call them on any transition edge without races. The cadence is a plain
 * coroutine timer on [dispatcherIo] (NO `AlarmManager`/`WorkManager`) — that keeps it no-root and
 * battery-light, and it dies with the ModulesService scope the moment rotation stops.
 */
@ModulesServiceScope
@ExperimentalCoroutinesApi
class RotationManager @Inject constructor(
    @Named(CoroutinesModule.DISPATCHER_IO)
    private val dispatcherIo: CoroutineDispatcher,
    private val rotationPing: RotationPing,
    private val pathVars: dagger.Lazy<PathVars>,
    @Named(DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: SharedPreferences,
    /**
     * D06(b) — the SAME `@ModulesServiceScope` [ResolverRuntime] singleton the state-loop drives:
     * the rotated set is handed to its live Rust MODE-2 pool through [ResolverRuntime.applyRotatedPool]
     * (constructor-injected — never hand-`new`, never a second instance).
     */
    private val resolverRuntime: ResolverRuntime,
    /**
     * #19 G10 — the Solver BindingCache arm + durable mirror. Rotation is its OBSERVED-commit source:
     * each committed swap's fastest reachable probe (id + real TCP RTT) is ground truth "this binding
     * works on this network" ([SolverCacheManager.onPoolApplied]); a 0-reachable pick invalidates the
     * current network's cached binding ([SolverCacheManager.onPoolUnreachable]). Constructor-injected
     * (`@ModulesServiceScope` singleton — never hand-`new`, ADR-001).
     */
    private val solverCacheManager: SolverCacheManager,
) {

    private val coroutineScope by lazy {
        CoroutineScope(
            SupervisorJob() +
                    dispatcherIo +
                    CoroutineName("RotationManager") +
                    CoroutineExceptionHandler { _, t ->
                        loge("RotationManager uncaught exception", t)
                    }
        )
    }

    /**
     * The live cadence timer, or null while stopped. @Volatile because the rotate loop runs on
     * [dispatcherIo] while the state-loop drives [start]/[stop] from another thread. Replaced atomically
     * under the `@Synchronized` start/stop so two edges can never leave two timers running.
     */
    @Volatile
    private var rotationJob: Job? = null

    /**
     * The operator family of the CURRENTLY-installed set — fed to [RotationSelector] for the diversity
     * exclusion so a rotation never lands the same operator twice in a row. @Volatile; updated only on a
     * committed swap (on the IO thread). `null` until the first successful rotation.
     */
    @Volatile
    private var lastOperatorFamily: String? = null

    /**
     * The monotonically-advancing rotation index — the durable cursor that lets a reboot resume rotation WHERE
     * it left off (not at 0). Warmed from the durable record at [start] ([rehydrateRotationCursor]) and stepped
     * +1 on each committed swap (then persisted at the [rotateOnce] commit). @Volatile (same cross-thread
     * reasoning as [lastOperatorFamily]); 0 until the first warm/commit.
     */
    @Volatile
    private var rotationIndex: Long = 0L

    /**
     * The last slate that PROVED it answers real DNS — not merely that its servers accept a TCP
     * connection.
     *
     * [probeReachable] (fail-safe layer 2) is a CONNECT probe. A DNSCrypt resolver whose certificate
     * has rotated completes the TCP handshake and then fails every exchange, so a pool can be
     * "reachable" and still be mute. MEASURED on-device 2026-08-01: rotation `index=18` installed 8
     * servers that all probed 366–420 ms — and then answered ZERO of 311 queries. `transport_miss`
     * climbed 63 → 558 while `answered` stayed frozen at 247 and `cache/query.log` stopped growing
     * entirely. That is the `ERR_CONNECTION_CLOSED` cause: the datapath fails CLOSED (SERVFAIL, no
     * system-DNS fallback by design), so a mute pool is a cadence-long outage — ~30 minutes of a
     * browser that cannot open anything.
     *
     * This field holds the last set that answered a LIVE query, so [rotateOnce] has something known
     * good to roll back onto. @Volatile (same cross-thread reasoning as [lastOperatorFamily]); null
     * until one verifies — and a null is reported honestly rather than papered over.
     */
    @Volatile
    private var lastVerifiedSet: RotatedSet? = null

    /**
     * DNSCrypt reached RUNNING (or the engine started standalone): begin the periodic rotation cadence —
     * IF the user opted into rotation. Idempotent: a second start edge for an already-running timer is a
     * no-op (it does not stack a second timer).
     */
    @Synchronized
    fun start() {
        if (rotationJob?.isActive == true) return
        try {
            // Gate 1 — the master engine switch (same one the engine/trust respect). Off ⇒ never rotate.
            if (!defaultPreferences.getBoolean(TortaeKeys.DNS_ENGINE_ENABLED, true)) {
                logi("RotationManager — engine disabled, rotation off")
                return
            }
            // #19 G10 — arm the Solver binding cache on the SAME engine-start edge (AFTER the master
            // switch, BEFORE the rotation opt-in: the solved-network memory rehydrates whenever the
            // engine runs, even for a user who opted out of rotation swaps — its own DNS_ENGINE_SOLVER
            // gate lives inside). Fail-open + idempotent; never throws.
            solverCacheManager.start()
            // Gate 2 — the noob "rotate for privacy" opt-in (DEFAULT ON; simple-UX). Off ⇒ never rotate; a
            // user who flips the GEEK switch off gets the configured set with no swaps.
            if (!shouldRotate(defaultPreferences)) {
                logi("RotationManager — rotation opt-in OFF, staying idle")
                return
            }
            // W5 — warm the durable rotation cursor BEFORE arming the cadence so a reboot RESUMES the diversity
            // schedule (cadence + index + the last operator family the next pick must EXCLUDE) instead of
            // cold-starting at family 0. Read ONCE here (the boot/start edge), NEVER on the resolve hot path;
            // a cold/absent/corrupt record leaves the cold baseline (additive + inert). Never throws.
            rehydrateRotationCursor()
            val cadenceMs = readCadenceMs(defaultPreferences)
            // BOOT PICK then cadence: seed a diverse trust-filtered set IMMEDIATELY (after a short settle),
            // not a whole cadence from now — see [bootPickThenLoop]/[BOOT_PICK_SETTLE_MS]. The re-arm path
            // ([onCadencePrefChanged]) deliberately launches the plain [rotationLoop] instead, so changing the
            // cadence never triggers an extra rotation.
            rotationJob = coroutineScope.launch { bootPickThenLoop() }
            // ★ E-FIX round-1 (live re-arm): listen for cadence-pref changes while armed so a chip tap
            // takes effect IMMEDIATELY (re-arms the live timer) instead of only on the next stop/start
            // edge. Registering is idempotent (listener set); strongly held by this @ModulesServiceScope
            // singleton (SharedPreferencesImpl keeps listeners weakly).
            defaultPreferences.registerOnSharedPreferenceChangeListener(cadencePrefListener)
            logi("RotationManager — periodic resolver rotation armed (cadence=${cadenceMs}ms)")
        } catch (e: Exception) {
            loge("RotationManager start", e)
        }
    }

    /** DNSCrypt stopped (and the engine is not standalone): cancel the cadence. Idempotent. */
    @Synchronized
    fun stop() {
        try {
            defaultPreferences.unregisterOnSharedPreferenceChangeListener(cadencePrefListener)
            rotationJob?.cancel()
            rotationJob = null
            clearNextFlip() // no schedule — the dashboard dial falls back to the honest idle "—"
            logi("RotationManager — rotation stopped")
        } catch (e: Exception) {
            loge("RotationManager stop", e)
        }
    }

    /**
     * ★ E-FIX round-1 — the LIVE cadence re-arm. The cadence used to be read ONCE at the arm edge and
     * baked into the loop's `delay`, so changing it while running silently kept the OLD period until a
     * stop/start-class edge (compounding the chip silent-ignore). Now: (a) [rotationLoop] re-reads the
     * pref on EVERY iteration, and (b) this listener fires on a [TortaeKeys.RESOLVER_ROTATION_CADENCE_MINUTES]
     * write while the timer is armed and re-arms it IMMEDIATELY (cancel + relaunch), so the currently
     * sleeping delay is cut short too — a 5-min chip tap mid-30-min-sleep rotates 5 min later, not 30.
     * No-op when the timer is not armed (rotation off / engine stopped). @Synchronized with start/stop
     * so a re-arm can never race an edge into two live timers. Never throws.
     */
    private val cadencePrefListener =
        SharedPreferences.OnSharedPreferenceChangeListener { prefs, key ->
            if (key == TortaeKeys.RESOLVER_ROTATION_CADENCE_MINUTES) onCadencePrefChanged(prefs)
        }

    @Synchronized
    private fun onCadencePrefChanged(prefs: SharedPreferences) {
        try {
            if (rotationJob?.isActive != true) return
            rotationJob?.cancel()
            rotationJob = coroutineScope.launch { rotationLoop() }
            logi(
                "RotationManager — cadence changed while running; timer re-armed " +
                    "(cadence=${readCadenceMs(prefs)}ms)"
            )
        } catch (e: Exception) {
            loge("RotationManager onCadencePrefChanged", e)
        }
    }

    /** DNSCrypt reached RUNNING: (re)arm the rotation cadence. */
    fun onDnsCryptStarted() = start()

    /**
     * DNSCrypt stopped. If the user runs the engine/resolver standalone the resolver stays live against the
     * public set, so keep rotating; otherwise stop. Mirrors [TrustManager.onDnsCryptStopped] /
     * [MonokumaDnsEngineManager.onDnsCryptStopped] exactly.
     */
    fun onDnsCryptStopped() {
        if (defaultPreferences.getBoolean(TortaeKeys.DNS_ENGINE_STANDALONE, false)) {
            // Re-arm against the (now public-set) resolver: cancel any prior timer first so start's
            // idempotency guard re-reads the cadence and we never stack two loops.
            stop()
            start()
        } else {
            stop()
        }
    }

    /** Is the rotation cadence running? Symmetric with the sibling managers' `isRunning()`. */
    fun isRunning(): Boolean = rotationJob?.isActive == true

    /**
     * MANUAL one-shot rotation — the nerd Rotation dashboard's "Rotate Now" control fires this (via the
     * [ModulesService] action ROTATE_RESOLVERS_NOW → [pillar.kuma_saimono.libumdnscrypt.modules.ModulesStateLoop])
     * so a tester can WATCH a swap immediately instead of waiting a whole cadence period. It runs the SAME
     * [rotateOnce] apply-chain a timer tick runs (select → apply to dnscrypt + restart → log), off the
     * timer, on [coroutineScope]. Guarded on [isRunning] (the cadence is armed ⇒ DNSCrypt is up AND the
     * user opted in) so a manual tap can never rotate a stopped engine; [rotateOnce] additionally re-checks
     * [shouldRotate]. Never throws — a bad manual pass is swallowed exactly like a timer pass (the live set
     * stands). It does NOT disturb the periodic timer: the next scheduled tick still fires on its own clock.
     */
    fun rotateNow() {
        if (!isRunning()) {
            logi("RotationManager — Rotate Now ignored (cadence not armed: engine stopped or rotation off)")
            return
        }
        coroutineScope.launch {
            try {
                logi("RotationManager — Rotate Now: manual one-shot rotation requested")
                rotateOnce()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                loge("RotationManager — Rotate Now pass failed (kept current set)", e)
            }
        }
    }

    /**
     * BOOT PICK → cadence. The arm edge ([start]) launches THIS (not [rotationLoop] directly) so the diverse
     * trust-filtered set goes live AT boot instead of a whole cadence later: settle briefly (let dnscrypt
     * reach steady RUNNING and the source-list readiness probe finish — no mid-bring-up restart thrash), fire
     * ONE immediate [rotateOnce], then hand off to the periodic loop. The boot pass is self-guarded exactly
     * like a timer pass — a fault (e.g. the pool source not yet on disk) keeps the configured set and the
     * periodic loop picks on its own clock; cancellation from [stop] during the settle propagates cleanly.
     * The re-arm path ([onCadencePrefChanged]) launches [rotationLoop] directly, so a cadence change never
     * fires an extra boot-style pick.
     */
    private suspend fun bootPickThenLoop() {
        try {
            publishNextFlip(BOOT_PICK_SETTLE_MS) // the boot pick IS the next flip — dial counts the settle
            delay(BOOT_PICK_SETTLE_MS)
            coroutineScope.ensureActive()
            // Re-stamp BEFORE the multi-second boot pass (ping budget + restart) so the dial reads the
            // honest next window during the pass, never a false "overdue" STALLED flicker.
            publishNextFlip(readCadenceMs(defaultPreferences))
            logi("RotationManager — boot pick: seeding a diverse set now (not a full cadence from boot)")
            rotateOnce()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e // stop() asked us to die during the settle — honor it.
        } catch (e: Exception) {
            loge("RotationManager — boot pick failed (kept configured set; periodic loop will pick)", e)
        }
        rotationLoop()
    }

    /**
     * The cadence loop: wait one period, then rotate once, forever — until the scope is cancelled by
     * [stop]. Every iteration is wrapped so a single bad rotation pass can never kill the timer (the next
     * period still fires); cancellation propagates cleanly via [ensureActive].
     *
     * E-FIX round-1: the cadence is re-read from the pref on EVERY iteration (was a one-shot ctor-style
     * parameter baked in at the arm edge), so a cadence change always applies from the next tick even
     * without the [cadencePrefListener] immediate re-arm. Cheap: one SharedPreferences read per period.
     */
    private suspend fun rotationLoop() {
        while (coroutineScope.isActive) {
            try {
                val cadenceMs = readCadenceMs(defaultPreferences)
                publishNextFlip(cadenceMs) // the dial's schedule truth: this wait IS the countdown
                delay(cadenceMs)
                coroutineScope.ensureActive()
                // Re-stamp BEFORE the rotate pass (multi-second ping budget + restart) — same
                // false-overdue guard as the boot pick; the next iteration re-stamps precisely.
                publishNextFlip(readCadenceMs(defaultPreferences))
                rotateOnce()
                // D30(1) — the periodic warm-RTT checkpoint rides the SAME cadence tick: refresh
                // the durable rotation record's hints from the LIVE pool's RTT EWMA (cursor-
                // preserving Rust-side, so it can never regress the family/index a flip owns).
                // Self-guarded: a checkpoint fault never counts as a failed rotation pass.
                checkpointRotationRtt()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e // stop() asked us to die — honor it, do not swallow.
            } catch (e: Exception) {
                // A bad rotation pass is a counted non-event: keep the live set, keep the cadence alive.
                loge("RotationManager — rotation pass failed (kept current set)", e)
            }
        }
    }

    /**
     * D30(1) — GENTLY refresh the durable warm-RTT hints from the live pool's per-transport RTT
     * EWMA ([TortaCore.checkpointResolverRotation] — rehydrate-first Rust-side, cursor-preserving
     * by construction). Fired on every cadence tick, NEVER the resolve path. `false` (nothing
     * fresh / write refused) is a silent best-effort non-event. Never throws.
     */
    private fun checkpointRotationRtt() {
        try {
            if (TortaCore.checkpointResolverRotation(durableDir())) {
                logi("RotationManager — warm-RTT hints checkpointed to the durable record (D30)")
            }
        } catch (e: Exception) {
            loge("RotationManager checkpointRotationRtt — skipped (best-effort)", e)
        }
    }

    /**
     * One rotation pass. Compose the next trust-filtered random set as TYPED specs (delegating the pick
     * to [RotationSelector] over the shared [RotationPoolSource] scan); if there is no candidate
     * ([composeRotatedUpstreams] null/empty) keep the current set. Otherwise apply to BOTH datapath
     * brains (D06b): the dnscrypt TOML rewrite + restart (the Go side, [applyRotationToDnscrypt] — its
     * airtight fail-safe gates the whole commit), then the LIVE Rust MODE-2 pool
     * ([ResolverRuntime.applyRotatedPool] — mode-guarded, typed, `ready>0`-committed; a decline there
     * is fine, the Go apply already landed and the Rust derivation converges on the next edge). BEFORE the
     * commit the picked pool is reachability-probed ([probeReachable]); an all-unreachable pool is NEVER
     * swapped in (fail-safe layer 2, availability — the datapath fails closed with SERVFAIL, so a dead
     * pool would be a cadence-long outage). The same probe's RTT samples ride the durable cursor persist
     * (D30, [renderRttHints]). Visible for testing.
     */
    internal suspend fun rotateOnce() {
        // Re-check the opt-in each pass — the user can toggle the noob switch mid-run; off ⇒ silently skip
        // this pass (the next start/stop edge tears the timer down; this avoids one stale swap in between).
        if (!shouldRotate(defaultPreferences)) return

        val rotated = composeRotatedUpstreams()
        if (rotated == null || rotated.specs.isEmpty()) {
            // FAIL-SAFE layer 1: no diverse, trusted, reachable candidate this cycle ⇒ DO NOT swap.
            logi("RotationManager — no rotation candidate this cycle, keeping current set")
            return
        }

        // SELECTION LIVE — the random, criteria-filtered, ≤N-server pool is chosen from the auto-updating
        // SIGNED sources each cadence (provable via this log — ids only, no qname/PII, T20).
        logi(
            "RotationManager — rotation pool SELECTED (random, criteria-filtered): " +
                "${rotated.specs.size} server(s) [${rotated.serverNames.joinToString(",")}]"
        )
        // FAIL-SAFE layer 2 (AVAILABILITY) — [composeRotatedUpstreams] picks RANDOM by criteria, NOT by
        // reachability, so a cycle CAN land an all-unreachable set (stale stamp, restricted network). The
        // datapath fails CLOSED (R4 no-Go-fallback, tunnel/mod.rs: resolver None ⇒ SERVFAIL, NEVER a
        // system-DNS fallback), so committing an all-dead pool would SERVFAIL every query until the next
        // cadence (~30 min) — an outage, not a leak. Probe the picked resolvers over the SAME TCP-connect
        // seam the warm-RTT persist trusts; if NONE answer, keep the current (working) set and let the
        // next cadence re-pick. The samples are REUSED below as the warm-RTT hints (one probe, not two).
        // Bounded by [RTT_PING_BUDGET_MS]: a hung network yields "none reachable" ⇒ keep current — a false
        // keep is safe (the working set stays); a false swap-onto-dead is not.
        val reachable = probeReachable(rotated)
        if (keepCurrentForUnreachablePool(reachable.size, rotated.pingTargets.size)) {
            logi(
                "RotationManager — rotation pick has 0 reachable servers, keeping current set " +
                    "(fail-safe layer 2, availability)"
            )
            // #19 G10 — 0 reachable on this network ⇒ the cached solver binding for the CURRENT
            // fingerprint is suspect: invalidate it (+ durable write-through) so re-entering this
            // network re-races instead of instant-reusing a rotted path. Fail-open; never throws.
            solverCacheManager.onPoolUnreachable(System.currentTimeMillis())
            return
        }
        // APPLY 1/2 — the live dnscrypt config + restart (the fail-safe keeps the current TOML on any
        // fault; a failed Go apply aborts the WHOLE commit so the two brains never diverge).
        if (!applyRotationToDnscrypt(rotated)) {
            logi("RotationManager — apply declined/failed, kept current TOML (fail-safe)")
            return
        }
        // APPLY 2/2 (D06b) — hand the SAME typed set to the LIVE Rust MODE-2 pool. Mode-guarded inside
        // (an active Go fallback is never stomped); a decline is honest (Go carries the rotation until
        // the Rust pool re-derives from the just-rewritten TOML on its next configure edge).
        val rustSwap = resolverRuntime.applyRotatedPool(rotated.specs, ROTATION_TIMEOUT_MS, CACHE_CAP)
        // #22 capstone slice 4 — feed THIS committed set's just-measured probe RTTs (the SAME pre-commit
        // samples) straight into the freshly-configured Rust pool's per-transport EWMA
        // ([TortaCore.seedResolverRtt] — unlearned-only, live data wins). The swap's own warm-start reads
        // the DURABLE record, which still holds the PREVIOUS window's hints at this point (the persist
        // below lands after) — under a completely-random pick those rarely name the new servers, so
        // without this direct hand-off the freshest measurements were orphaned until the next boot.
        // Rust-swap edge only (a Go-mode decline leaves no live Rust pool to seed). Best-effort.
        if (rustSwap) seedCommittedRtt(reachable)
        // FAIL-SAFE layer 3 (ANSWERING) — layer 2 proved the servers ACCEPT A CONNECTION; it never
        // proved they ANSWER. Those are different failures and only the second one is fatal, because
        // the datapath fails closed. Ask the JUST-COMMITTED pool a real question and believe the
        // answer, not the handshake. A mute pool is rolled back onto the last set that answered;
        // leaving it installed costs a full cadence of total DNS outage (measured: 311 consecutive
        // misses, `answered` frozen, every page ERR_CONNECTION_CLOSED).
        if (!poolAnswersRealQueries()) {
            val fallback = lastVerifiedSet
            PillarLog.event(
                pathVars.get().appDataDir,
                PillarLog.Pillar.ROTATION,
                "rollback",
                "family" to rotated.operatorFamily,
                "servers" to rotated.serverNames.size,
                // The index of the set being RESTORED — the mute swap never earns an index.
                "index" to rotationIndex,
                "reason" to "mute_pool",
                "restored" to (fallback != null),
                "servers_list" to rotated.serverNames.joinToString(","),
            )
            if (fallback != null) {
                // Restore BOTH brains in the same order the commit applied them, so the Go TOML and
                // the live Rust pool can never diverge (the D06b two-brain contract).
                applyRotationToDnscrypt(fallback)
                resolverRuntime.applyRotatedPool(fallback.specs, ROTATION_TIMEOUT_MS, CACHE_CAP)
                logi(
                    "RotationManager — pick answers NOTHING; rolled back to the last ANSWERING set " +
                        "(${fallback.serverNames.size} servers) [${fallback.serverNames.joinToString(",")}]"
                )
            } else {
                // Nothing verified yet this process (first cadence, or every set so far was mute).
                // There is no known-good to restore, so the pick stays — but it is NOT recorded as
                // verified and NOT given an index. Saying so beats a silent pretend-success.
                logi(
                    "RotationManager — pick answers NOTHING and no verified set exists to restore; " +
                        "keeping it, NOT marking it verified"
                )
            }
            return
        }
        // Verified: this set answered a live query, so it is now the rollback target for the next one.
        lastVerifiedSet = rotated
        lastOperatorFamily = rotated.operatorFamily
        rotationIndex += 1L
        // #22 s5C — publish the LIVE relay chain (the DISTINCT relay names this committed set's routes
        // actually ride) for the bridge's `chain_relays` suffix + the dashboard's chain tile. Process-
        // scoped by design: "" until the first commit of THIS process (honest cold — the durable cursor
        // carries no relay names, and a fabricated chain is worse than an empty one).
        lastRelayChain = rotated.relayNames.joinToString(",")
        // D30(3) — persist the `<id>:<ms>` warm-RTT hints from the SAME pre-commit probe (resolver
        // reachability RTT is unchanged by the dnscrypt restart, so the pre-commit measurement is the
        // valid warm hint; was always "" before D30 — the warm-RTT half carried nothing).
        persistRotationCursor(renderRttHints(reachable))
        // #19 G10 — commit the OBSERVED solver binding: the fastest reachable resolver of the pool the
        // engine JUST applied + its real TCP probe RTT, under the current network's fingerprint (the
        // rotation swap IS the control-plane event; the probe list is fastest-first). The durable
        // write-through rides inside. Fail-open; never throws; never steers the datapath.
        reachable.firstOrNull()?.let {
            solverCacheManager.onPoolApplied(it.candidate.id, it.rttMs, System.currentTimeMillis())
        }
        // #133 — record the committed swap to this pillar's own query-rotation.log (the shared per-pillar
        // log substrate). Operational fields only — public resolver/relay LABELS + counts, no qname, no
        // client IP (T20). #22 s5C: `servers_list` + `relays` carry the actual NAMES so the dashboard's
        // ROTATION HISTORY can say WHICH servers and WHICH relays each flip installed (the plain-language
        // rescope — the bare `family` code confounded; names don't). PillarLog's per-value whitespace
        // scrub leaves comma-joined lists intact.
        PillarLog.event(
            pathVars.get().appDataDir,
            PillarLog.Pillar.ROTATION,
            "switch",
            "family" to rotated.operatorFamily,
            "servers" to rotated.serverNames.size,
            "index" to rotationIndex,
            "rust" to rustSwap,
            "servers_list" to rotated.serverNames.joinToString(","),
            "relays" to rotated.relayNames.joinToString(","),
        )
        logi(
            "RotationManager — rotation pool APPLIED (${rotated.serverNames.size} servers; " +
                "dnscrypt TOML+restart, rustPool=$rustSwap)"
        )
    }

    /**
     * FAIL-SAFE layer 3 (ANSWERING) — does the JUST-COMMITTED pool actually answer DNS?
     *
     * Asks the live Rust datapath ([TortaCore.resolve] → `resolver_resolve`, the same entry the tunnel
     * uses) for a name built by the SAME Rust codec the datapath encodes with ([TortaCore.buildQuery] →
     * `dns::build_query`), so this probe cannot pass on a wire format the datapath would reject.
     *
     * The qname carries a RANDOM label on every attempt, and that is the load-bearing detail. The
     * resolve path is block-check → cache → encrypted transport (`lib.rs:2104-2110`), so a name that
     * could be cached would return bytes WITHOUT any server being contacted — the probe would go green
     * against a pool that answers nothing, which is the exact failure this gate exists to catch. A
     * random label under a zone that is guaranteed to have working authoritative servers can never be
     * a cache hit, so any non-empty response proves an encrypted exchange completed end-to-end.
     *
     * NXDOMAIN counts as success ON PURPOSE: the question is whether the transport carries a validated
     * answer, not what the answer says. A signed "that name does not exist" is proof of a live server.
     *
     * Returns false only when [VERIFY_ATTEMPTS] independent questions all fail to come back — the
     * shape a mute pool produces every single time. Never throws (the façade swallows native faults
     * and returns null, which this reads as a failed attempt).
     */
    private suspend fun poolAnswersRealQueries(): Boolean {
        repeat(VERIFY_ATTEMPTS) { attempt ->
            // The commit just RESTARTED dnscrypt-proxy. Asking three questions back-to-back would put
            // all of them inside the restart window and could call a perfectly healthy pool mute —
            // a false rollback, which flaps rotation and is its own outage. Space the retries, and
            // pay the first wait up front so no question is asked into a socket that is still coming up.
            delay(VERIFY_RETRY_SPACING_MS)
            val wire = TortaCore.buildQuery(verificationQname(), VERIFY_QTYPE_A)
            if (wire != null) {
                val response = TortaCore.resolve(wire)
                if (responseProvesLiveTransport(response)) {
                    if (attempt > 0) {
                        logi("RotationManager — pool answered on verification attempt ${attempt + 1}")
                    }
                    return true
                }
            }
        }
        return false
    }

    /**
     * D30(3) / FAIL-SAFE layer 2 — measure the picked pool's reachability over the SAME TCP-connect seam
     * the app's ping cards trust ([RotationPing]; addresses decoded from the servers' own stamps by
     * [RotationPoolSource]) and return the reachable survivors fastest-first ([RotationPing.rankCandidates]
     * drops the unreachable). Serves BOTH consumers off ONE probe: the pre-commit availability gate
     * ([rotateOnce] — empty ⇒ keep-current) and the post-commit warm-RTT persist ([renderRttHints]).
     * Bounded by [RTT_PING_BUDGET_MS]: a hung network yields an EMPTY list — which both suppresses the
     * warm hint (pre-D30 posture) AND trips the gate toward keep-current (the safe direction).
     * Control-plane only (≤ once per cadence). Never throws.
     */
    private suspend fun probeReachable(rotated: RotatedSet): List<RotationPing.RttSample> = try {
        if (rotated.pingTargets.isEmpty()) {
            emptyList()
        } else {
            kotlinx.coroutines.withTimeoutOrNull(RTT_PING_BUDGET_MS) {
                rotationPing.rankCandidates(rotated.pingTargets)
            } ?: emptyList()
        }
    } catch (e: Exception) {
        loge("RotationManager probeReachable — no hints this pass (best-effort)", e)
        emptyList()
    }

    /**
     * #22 s5B — reachability-filter the relay pool before the seeded per-server pick, on the SAME
     * ping seam the committed-set probe trusts ([RotationPing.filterRoutableRelays]: sdns stamp →
     * RelaysPingInteractor TCP-connect). FAIL-OPEN at every layer: zero reachable, a hung network
     * (the [RTT_PING_BUDGET_MS] timeout), or ANY exception ⇒ the ORIGINAL pair list — the
     * anonymization layer is never thinned by a dead probe plane, and rotation composition is never
     * blocked on it. Control-plane only (≤ once per cadence). Never throws.
     */
    private suspend fun filterRoutableRelayPairs(
        relayPairs: List<Pair<String, String>>,
    ): List<Pair<String, String>> = try {
        if (relayPairs.isEmpty()) {
            relayPairs
        } else {
            kotlinx.coroutines.withTimeoutOrNull(RTT_PING_BUDGET_MS) {
                rotationPing
                    .filterRoutableRelays(
                        relayPairs.map { RotationPing.Candidate(id = it.first, sdns = it.second) }
                    )
                    .map { it.id to it.sdns.orEmpty() }
            } ?: relayPairs
        }
    } catch (e: Exception) {
        loge("RotationManager filterRoutableRelayPairs — FAIL-OPEN full relay list", e)
        relayPairs
    }

    /**
     * Render reachable RTT samples as the `<id>:<ms>` line blob the durable persist folds into the bounded
     * hint set (the tail of the old pingRotatedSet). Pure — no sockets, no coroutines; the part worth
     * unit-testing.
     */
    internal fun renderRttHints(samples: List<RotationPing.RttSample>): String =
        samples.joinToString("\n") { "${it.candidate.id}:${it.rttMs}" }

    /**
     * #22 capstone slice 4 — hand the committed set's probe RTTs to the live Rust pool
     * ([TortaCore.seedResolverRtt], unlearned-only). Control-plane, rotation-swap edge only; a fault or
     * a 0-seed is a silent best-effort non-event. Never throws.
     */
    private fun seedCommittedRtt(samples: List<RotationPing.RttSample>) {
        try {
            val seeded = TortaCore.seedResolverRtt(toSeedHints(samples))
            if (seeded > 0) {
                logi("RotationManager — direct warm-RTT seed: $seeded transport(s) from this swap's probe (#22 s4)")
            }
        } catch (e: Exception) {
            loge("RotationManager seedCommittedRtt — skipped (best-effort)", e)
        }
    }

    /**
     * Warm the durable rotation cursor at [start] — D34: read the TYPED
     * [uniffi.torta_core.RotationSnapshot] over the held MaskSolver Object
     * ([TortaCore.maskSolverRotationSnapshot], a single off-hot-path control-plane read): typed
     * family/index fields + the `rehydratedWarm` #98 crown flag — no summary-string parse. The flat
     * `"family=… cadence=… index=… hints=<n>"` summary ([TortaCore.rehydrateResolverRotation] +
     * [parseField]) stays the NO-BREAK fallback for a base `.so`/handle fault — old path
     * byte-identical. A cold snapshot / null / any unparsable field leaves the cold baseline. Never
     * throws (a failure degrades to cold — additive + inert). The durable dir is the SAME app-private
     * W5 root the boot driver warms ([RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR] under
     * [PathVars.getAppDataDir]).
     */
    private fun rehydrateRotationCursor() {
        try {
            val snap = TortaCore.maskSolverRotationSnapshot(durableDir())
            if (snap != null) {
                if (!snap.rehydratedWarm) return // honest cold start — keep the cold baseline
                if (snap.lastFamily.isNotEmpty()) lastOperatorFamily = snap.lastFamily
                rotationIndex = snap.rotationIndex
                logi(
                    "RotationManager — rotation cursor warmed (typed): family=${snap.lastFamily} " +
                        "index=${snap.rotationIndex} hints=${snap.rttHints.size}"
                )
                return
            }
            // NO-BREAK fallback (base `.so` / handle fault): the flat summary parse, byte-identical.
            val summary = TortaCore.rehydrateResolverRotation(durableDir()) ?: return
            parseField(summary, "family")?.let { if (it.isNotEmpty()) lastOperatorFamily = it }
            parseField(summary, "index")?.toLongOrNull()?.let { rotationIndex = it }
            logi("RotationManager — rotation cursor warmed from durable source ($summary)")
        } catch (e: Exception) {
            // A bad warm is a cold start, never a crash: keep the cold baseline + arm the cadence anyway.
            loge("RotationManager rehydrateRotationCursor — cold start (kept baseline)", e)
        }
    }

    /**
     * GENTLY persist the rotation cursor on a committed swap (the control plane) — best-effort, off the hot
     * path. The cadence is converted MINUTES→SECONDS for the durable record (the Rust `RotationState.cadence_secs`
     * is in seconds; the Kotlin pref is in minutes). [rttHints] is the committed set's `<id>:<ms>` line blob
     * (D30(3) — from [probeReachable]+[renderRttHints]; the Rust side folds each line into the bounded warm-hint set via
     * `observe_rtt`, and rehydrates FIRST so a flip preserves the periodic checkpoint's hints). A
     * refusal/failure is swallowed: the in-memory cursor stands, a live resolution is never affected.
     * Never throws.
     */
    private fun persistRotationCursor(rttHints: String) {
        try {
            val cadenceSecs = readCadenceMs(defaultPreferences) / 1000L
            val ok = TortaCore.persistResolverRotation(
                durableDir(),
                lastOperatorFamily.orEmpty(),
                cadenceSecs,
                rotationIndex,
                rttHints,
            )
            if (!ok) {
                logi("RotationManager — rotation cursor persist refused (best-effort, kept in memory)")
            }
        } catch (e: Exception) {
            loge("RotationManager persistRotationCursor — durable write skipped (kept in memory)", e)
        }
    }

    /**
     * The app-private durable W5 root for the NEW-durable `"resolver-rotation"` record — the SAME app-private
     * family the signed-source pillars + Centauri cache + dnscrypt config live in
     * ([PathVars.getAppDataDir] + [RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR]), so the boot driver's warm
     * read + this manager's read/write hit the identical record.
     */
    private fun durableDir(): String =
        pathVars.get().appDataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR

    /**
     * Pull the value of a `key=value` field out of the tiny rotation summary, whitespace-tolerant (the value
     * runs up to the next space or end-of-string). Returns null when the key is absent. Pure + side-effect-free.
     */
    private fun parseField(summary: String, key: String): String? {
        val marker = "$key="
        val at = summary.indexOf(marker)
        if (at < 0) return null
        val from = at + marker.length
        val end = summary.indexOf(' ', from).let { if (it < 0) summary.length else it }
        return summary.substring(from, end)
    }

    /**
     * Build the next rotated upstream set — TYPED end-to-end (D06b/D34): the pick flows from the ONE
     * shared [RotationPoolSource] scan (signed `public-resolvers.md`, decoded stamps) through the pure
     * [RotationSelector.selectRandomSet] into typed [uniffi.torta_core.UpstreamSpec]s (never a hand-built
     * JSON descriptor — the old `specsJson` existed only for a log line). ONE seeded relay pick feeds
     * BOTH datapath brains identically: the dnscrypt TOML `routes` lines carry the relay NAMES, the
     * typed specs carry the SAME relays' `sdns://` stamps (one privacy posture, two carriers — the Rust
     * engine stores relay stamps for its wired anonymized-relay hop; until `resolver::configure`
     * consumes the `relays` key the Go TOML routes remain the live relay authority — carried typed,
     * documented honestly, never claimed armed). Each picked server's stamp-decoded `ip:port` also
     * lands as a [RotationPing.Candidate] so the committed set can be RTT-measured (D30(3)).
     * Never throws (a failure degrades to "decline = keep current").
     *
     * @return the composed [RotatedSet], or `null` to keep the current set this cycle.
     */
    private suspend fun composeRotatedUpstreams(): RotatedSet? {
        return try {
            // 1. the AUTO-UPDATING signed source pool (public-resolvers.md) → decoded stamped candidates.
            val stamped =
                RotationPoolSource.readStampedCandidates(pathVars.get().getDNSCryptPublicResolversPath())
            if (stamped.isEmpty()) return null
            // 2. the user's DNSCrypt criteria (require_* + the IPv4/IPv6 family gate), Academic-Wall:
            //    never hard-coded. UNIFIED on the typed-config authority ([rotationPolicy] →
            //    policyFromConfig) so the cadence re-pick honours the SAME SLINT filter set as BOTH the
            //    manual pick and the MODE-2 derive (the LOCKED SPEC: one filter set, every path); a toml
            //    fault degrades to the legacy prefs policy (fail-safe, family gate open).
            val policy = rotationPolicy()
            val maxServers = readMaxServers()
            // 3. COMPLETELY-RANDOM bounded pick of ≤maxServers criteria-matching servers (RotationSelector).
            val picked = RotationSelector.selectRandomSet(
                stamped.map { it.candidate }, lastOperatorFamily, rotationIndex, maxServers, policy
            )
            if (picked.isEmpty()) return null
            // 4. bind ≤maxRelays random relays per server from the auto-updating relays.md — ONE seeded
            //    pick emitting the TOML route lines (names) AND the typed spec relays (stamps) together.
            //    #22 s5B: the pool is reachability-filtered FIRST ([RotationPing.filterRoutableRelays],
            //    fail-open — 0 reachable ⇒ blind full list, the anonymization layer is never stripped
            //    by a dead probe plane), so the seeded pick draws from relays that actually answer.
            val relayPairs = filterRoutableRelayPairs(
                RotationPoolSource.readNamedStamps(pathVars.get().getDNSCryptRelaysPath())
            )
            val stampedById = stamped.associateBy { it.candidate.id }
            buildRotatedSet(picked, stampedById, relayPairs, readMaxRelays())
        } catch (e: Exception) {
            loge("RotationManager composeRotatedUpstreams — declining (kept current set)", e)
            null
        }
    }

    /**
     * The rotation trust policy for the periodic pick — UNIFIED onto the SAME typed-config authority the
     * MODE-2 derive uses ([RotationPoolSource.policyFromConfig]), so the cadence re-pick honours the LIVE
     * SLINT toggles: the require_* privacy criteria AND the IPv4/IPv6 SERVER-TYPES family gate (the LOCKED
     * SPEC — one filter set gates the manual pick, the derive, AND the rotation auto-pick, never three
     * drifting policies). Reads the dnscrypt-proxy toml (the authority the SLINT section writes) and
     * imports the typed [uniffi.torta_core.DnscryptProxyConfig]. Any fault — unreadable toml, import miss
     * — degrades to the legacy [RotationPoolSource.policyFromPrefs] (permissive; the family gate stays
     * open), so a config hiccup never sinks a rotation. Never throws.
     */
    private fun rotationPolicy(): RotationSelector.RotationPolicy = try {
        val toml = java.io.File(pathVars.get().dnscryptConfPath).takeIf { it.isFile }?.readText()
        val cfg = toml?.let { TortaCore.dnscryptConfigImportOrDefault(it) }
        if (cfg != null) {
            RotationPoolSource.policyFromConfig(
                cfg.requireNolog,
                cfg.requireDnssec,
                cfg.requireNofilter,
                cfg.ipv4Servers,
                cfg.ipv6Servers,
                // #22 s5A-ext (Socio): the PROTOCOL gate — the rotation pick honours the SAME
                // dnscrypt/doh server-type bits the pillar's chips edit. ODoH is not a random-pick
                // protocol (its 0x05 targets ride ResolverRuntime.deriveOdohUpstreams' own lane,
                // gated by cfg.odohServers there).
                cfg.dnscryptServers,
                cfg.dohServers,
            )
        } else {
            RotationPoolSource.policyFromPrefs(defaultPreferences)
        }
    } catch (e: Exception) {
        loge("RotationManager rotationPolicy — falling back to the legacy prefs policy", e)
        RotationPoolSource.policyFromPrefs(defaultPreferences)
    }

    /**
     * Assemble the [RotatedSet] from a committed pick: typed specs + TOML route lines + ping targets in
     * ONE pass over ONE seeded shuffle (seeded by [rotationIndex], reproducible per window; the SAME
     * relay subset lands in the TOML `via=[…]` and the spec's `relays` — the two brains never diverge).
     * Route lines keep the PreferencesDNSCryptServers shape (`{ server_name = 'x', via=['r'] }`, last
     * route comma-free); no relays / maxRelays=0 ⇒ no route lines (the apply leaves the existing routes
     * untouched — fail-safe) and direct (relay-free) specs.
     */
    private fun buildRotatedSet(
        picked: List<RotationSelector.ResolverCandidate>,
        stampedById: Map<String, RotationPoolSource.StampedCandidate>,
        relayPairs: List<Pair<String, String>>,
        maxRelays: Int,
    ): RotatedSet {
        val rnd = java.util.Random(rotationIndex xor ROUTE_SHUFFLE_SEED)
        val emitRoutes = relayPairs.isNotEmpty() && maxRelays > 0
        val routeLines = ArrayList<String>(if (emitRoutes) picked.size + 2 else 0)
        val specs = ArrayList<uniffi.torta_core.UpstreamSpec>(picked.size)
        val pingTargets = ArrayList<RotationPing.Candidate>(picked.size)
        val usedRelays = LinkedHashSet<String>()
        if (emitRoutes) routeLines.add("routes = [")
        picked.forEachIndexed { i, s ->
            val via = if (emitRoutes) relayPairs.shuffled(rnd).take(maxRelays) else emptyList()
            via.forEach { usedRelays.add(it.first) }
            if (emitRoutes) {
                val viaNames = via.joinToString(", ") { "'${it.first}'" }
                val comma = if (i < picked.size - 1) "," else ""
                routeLines.add("{ server_name = '${s.id}', via=[$viaNames] }$comma")
            }
            val source = stampedById[s.id]
            // #22 s5A-ext: the TYPED Rust specs stay a DNSCRYPT-ONLY subset — the native transport
            // builds from 0x01 stamps only (doh.rs has no stamp-builder). A DoH pick (allowDoh chip)
            // still lands in `serverNames` above, so the Go TOML lane (DoH-native) carries it; the
            // Rust swap simply sees fewer typed specs. An ALL-DoH pick ⇒ specs empty ⇒ rotateOnce's
            // existing specs.isEmpty() keep-current guard holds the line (never an empty native pool).
            if (s.dnsCrypt) {
                specs.add(
                    uniffi.torta_core.UpstreamSpec(
                        id = s.id,
                        transport = uniffi.torta_core.TransportKind.DNSCRYPT,
                        url = "",
                        stamp = source?.sdns.orEmpty(),
                        // FOUNDATION (task #6): the TYPED Rust pool rides DIRECT — see ResolverRuntime
                        // deriveConfiguredUpstreamsTyped. Feeding the whole `via` subset here nested a
                        // multi-hop anonymized chain that dropped every reply. The toml `via=[…]` route
                        // lines above are still emitted (they only steer the Go fallback + document the
                        // routes); correct single-relay anonymized routing lands under Underground (#4).
                        relays = emptyList(),
                    )
                )
            }
            val address = source?.address.orEmpty()
            if (address.isNotEmpty()) {
                pingTargets.add(RotationPing.Candidate(id = s.id, address = address))
            }
        }
        if (emitRoutes) routeLines.add("]")
        return RotatedSet(
            specs = specs,
            operatorFamily = picked.firstOrNull()?.operatorFamily,
            serverNames = picked.map { it.id },
            routeLines = routeLines,
            pingTargets = pingTargets,
            relayNames = usedRelays.toList(),
        )
    }

    /**
     * The user's chosen server count — GEEK safe-slider OR NERD-free pref. Absent a pref (the count slider is
     * not yet wired), it lands on the LOCKED-SPEC default of [RotationSelector.GEEK_SAFE_DEFAULT_SERVERS] = 10
     * (NOT the geek-safe ceiling of 20) — a random pick of exactly 10 resolvers, per the Socio spec.
     */
    private fun readMaxServers(): Int =
        defaultPreferences.getInt(MAX_SERVERS_PREF, RotationSelector.GEEK_SAFE_DEFAULT_SERVERS).coerceAtLeast(1)

    /** The user's chosen relays-per-server count — GEEK safe-slider OR NERD-free pref. */
    private fun readMaxRelays(): Int =
        defaultPreferences.getInt(MAX_RELAYS_PREF, RotationSelector.GEEK_SAFE_DEFAULT_RELAYS).coerceAtLeast(0)

    /**
     * THE FINAL APPLY (touches the LIVE DNS path). Write the chosen pool to dnscrypt's server_names + routes
     * and restart dnscrypt so the new pool goes live (dnscrypt then does the per-query LB — "dnscrypt do the
     * rest"). AIRTIGHT FAIL-SAFE: never write an empty server_names; a missing file / absent server_names
     * line / any fault ABORTS with NO change (the current TOML stands). Returns true ONLY on a real committed
     * write + restart. NOTE: the live AVD soak (does dnscrypt still resolve after the rotated restart? does
     * the cadence keep firing?) is a deferred verification run — code is fail-safe + green here.
     */
    private fun applyRotationToDnscrypt(rotated: RotatedSet): Boolean {
        if (rotated.serverNames.isEmpty()) return false // fail-safe: NEVER empty the pool
        return try {
            val toml = java.io.File(pathVars.get().appDataDir + DNSCRYPT_TOML_RELATIVE)
            if (!toml.exists()) return false
            val lines = toml.readLines().toMutableList()
            // server_names — replace the live (uncommented) value, robust to BOTH a single-line array AND the
            // multi-line array block the Rust `dnscrypt_config_to_toml` serializer emits after any torta_ui
            // toggle. A single-line-only replace ORPHANS a multi-line body → invalid TOML → dnscrypt
            // parse-fail on the rotated restart (AVD-caught 2026-07-15). Abort (no write) if the key is absent.
            val afterServerNames = replaceServerNamesBlock(lines, rotated.serverNames) ?: return false
            lines.clear()
            lines.addAll(afterServerNames)
            // routes block — replace from `routes = [` to its closing `]` (only when both + our lines exist).
            if (rotated.routeLines.isNotEmpty()) {
                val rStart = lines.indexOfFirst { it.trim().startsWith("routes = [") }
                if (rStart >= 0) {
                    var rEnd = -1
                    var i = rStart
                    while (i < lines.size) {
                        if (lines[i].trim() == "]") { rEnd = i; break }
                        i++
                    }
                    if (rEnd >= rStart) {
                        for (k in rEnd downTo rStart) lines.removeAt(k)
                        lines.addAll(rStart, rotated.routeLines)
                    }
                }
            }
            toml.writeText(lines.joinToString("\n") + "\n")
            pillar.kuma_saimono.libumdnscrypt.modules.ModulesRestarter.restartDNSCrypt(
                pillar.kuma_saimono.libumdnscrypt.App.instance
            )
            true
        } catch (e: Exception) {
            loge("RotationManager applyRotationToDnscrypt — kept current TOML (fail-safe)", e)
            false
        }
    }

    /** A composed rotation result (D06b — TYPED, no descriptor string): the typed specs the Rust MODE-2
     *  swap installs + the chosen operator family + the concrete server_names list and dnscrypt routes
     *  block the TOML apply writes + the stamp-decoded ping targets the D30 warm-RTT feed measures. */
    internal data class RotatedSet(
        val specs: List<uniffi.torta_core.UpstreamSpec>,
        val operatorFamily: String?,
        val serverNames: List<String> = emptyList(),
        val routeLines: List<String> = emptyList(),
        val pingTargets: List<RotationPing.Candidate> = emptyList(),
        // #22 s5C — the DISTINCT relay names riding this set's routes (insertion-ordered), the honest
        // relay-chain witness the dashboard's chain tile + the bridge `chain_relays` suffix report.
        val relayNames: List<String> = emptyList(),
    )

    /**
     * The cadence in millis, clamped to a sane band. The pref is MINUTE-granular
     * ([TortaeKeys.RESOLVER_ROTATION_CADENCE_MINUTES] — the Rotation dashboard's cadence chips, the GEEK
     * preset dropdown and the NERD custom-minutes all write this ONE key); minutes × 60_000L → ms. The
     * Rust durable cursor ([RotationState.cadence_secs]) is unit-blind seconds, so 30 min = 1800 s
     * round-trips with no native change.
     *
     * ★ E-FIX round-1 (the silent-ignore class, closed): this read was gated behind
     * [TortaeKeys.DNS_ENGINE_EXPERT] — so the everyday Rotation-dashboard cadence chips wrote a value the
     * UI rendered ("every 5 min") but the armed timer silently ignored (stayed 1800000 ms) unless the
     * user had ALSO flipped the unrelated Expert toggle (AVD evidence: 09-cadence-5min.png vs the
     * 20:43:36 "armed (cadence=1800000ms)" logcat line). The gate is GONE: the pref is honored whenever
     * it is set (unset/0 still reads the noob [DEFAULT_CADENCE_MINUTES]); the
     * [MIN_CADENCE_MINUTES]..[MAX_CADENCE_MINUTES] clamp stays the battery/churn abuse guard. What the
     * UI accepts, the engine runs — no hidden second switch.
     */
    private fun readCadenceMs(prefs: SharedPreferences): Long = try {
        val raw = prefs.getInt(TortaeKeys.RESOLVER_ROTATION_CADENCE_MINUTES, DEFAULT_CADENCE_MINUTES)
        val minutes = (if (raw <= 0) DEFAULT_CADENCE_MINUTES else raw)
            .coerceIn(MIN_CADENCE_MINUTES, MAX_CADENCE_MINUTES)
        minutes.toLong() * 60_000L
    } catch (e: Exception) {
        loge("RotationManager readCadenceMs — falling back to default cadence", e)
        DEFAULT_CADENCE_MINUTES.toLong() * 60_000L
    }

    companion object {
        /**
         * The DECISION GATE, extracted Context-free so the noob opt-in + master gate is unit-testable on a
         * plain JVM against a tiny [SharedPreferences] fake (the [CentauriArtifactManager.shouldFetchRemote]
         * pattern — exercise the REAL production gate, not a copy). Rotation runs ONLY when BOTH the master
         * engine switch is on (default true) AND the noob rotate opt-in is on (DEFAULT ON). The engine-off
         * branch is defense-in-depth: a user who disabled the engine entirely gets no surprise rotations.
         */
        @JvmStatic
        fun shouldRotate(prefs: SharedPreferences): Boolean {
            if (!prefs.getBoolean(TortaeKeys.DNS_ENGINE_ENABLED, true)) return false
            return prefs.getBoolean(TortaeKeys.RESOLVER_ROTATION_ENABLED, true)
        }

        /**
         * True iff [summary] is a real `"ready=N transports=…"` with `N > 0` — the fail-safe commit gate
         * for the FLAT configure seam ([TortaCore.configureResolver]'s summary string). The rotation swap
         * itself now commits on the TYPED `ConfigureReport.ready > 0`
         * ([ResolverRuntime.applyRotatedPool], D34 — no string parse); this stays the NO-BREAK twin gate
         * for flat-path callers. `null`/`ready=0` is "no swap": the native side left the previous pool
         * installed. Extracted + visible for the adversarial JUnit (a fully-bad candidate must NEVER
         * commit a rotation).
         */
        @JvmStatic
        fun isUsableSummary(summary: String?): Boolean {
            val s = summary?.trim() ?: return false
            // Shape: "ready=N transports=…". Parse the ready count defensively; anything not ready>0 ⇒ no swap.
            val token = s.substringAfter("ready=", "").substringBefore(' ').trim()
            val ready = token.toIntOrNull() ?: return false
            return ready > 0
        }

        /**
         * FAIL-SAFE layer 2 (availability) decision — keep the CURRENT set (do NOT swap) exactly when the
         * picked pool HAS ping targets but NONE probed reachable. Rationale: [composeRotatedUpstreams] picks
         * RANDOM by criteria (never by reachability), and the datapath fails CLOSED (R4 no-Go-fallback:
         * resolver None ⇒ SERVFAIL, no system fallback), so committing an all-dead pool = a cadence-long
         * SERVFAIL outage. An EMPTY [pingTargetCount] is NOT a keep (nothing to probe — e.g. a probe-less
         * pick; the downstream `ready=N>0` commit gate still guards it); a hung-network empty probe over a
         * NON-empty target set DOES keep-current (the safe direction). Pure — the part worth pinning; the
         * socket probe is the instance-side [probeReachable].
         */
        fun keepCurrentForUnreachablePool(reachableCount: Int, pingTargetCount: Int): Boolean =
            pingTargetCount > 0 && reachableCount == 0

        /**
         * #22 capstone slice 4 — map the pre-commit probe samples to the typed warm-seed hints
         * ([uniffi.torta_core.RttHint]) the direct pool seed ([TortaCore.seedResolverRtt]) consumes. The
         * id is the SAME spec-id label the committed [uniffi.torta_core.UpstreamSpec]s carried (so the
         * Rust `Transport::id()` lookup matches by construction); an unreachable sample never reaches
         * here ([RotationPing.rankCandidates] drops them), and a defensive negative-RTT guard keeps the
         * seed non-poisoning anyway. Pure — the part worth pinning in JUnit.
         */
        fun toSeedHints(samples: List<RotationPing.RttSample>): List<uniffi.torta_core.RttHint> =
            samples.filter { it.rttMs >= 0 }
                .map { uniffi.torta_core.RttHint(id = it.candidate.id, rttMs = it.rttMs.toLong()) }

        // ── the LIVE NEXT-FLIP clock — the `RotationSnapshot.next_flip_secs` PRODUCER (the missing half
        //    of the designed contract: object.rs:221-226 declares "the Kotlin host computes the live
        //    countdown from its rotation timer (cadence − elapsedSinceLastFlip) and pushes it"; until
        //    this block NOBODY computed it, so the Rotation dashboard's cadence dial rendered a frozen
        //    "0s" forever). Companion-held (@Volatile) so the static JNI bridge
        //    ([pillar.kuma_saimono.libumdnscrypt.slint.TortaPillarBridge.liveRotationState]) — which has no
        //    DI handle to the @ModulesServiceScope instance — reads the live schedule in-process (the app
        //    declares NO android:process anywhere: activity + service + this manager share one process).
        //    [SystemClock.elapsedRealtime] is MONOTONIC — a wall-clock jump (NTP / user set) can never
        //    fake an overdue dial or stretch a window. ──

        /**
         * The next scheduled flip's [SystemClock.elapsedRealtime] deadline in ms; `0` = no schedule armed
         * (rotation off / engine stopped / fresh process). Stamped at every arm edge, cleared on [stop].
         */
        @Volatile
        private var nextFlipAtElapsedMs = 0L

        /**
         * Stamp the next-flip deadline [inMs] ahead of [nowElapsedMs]. Called at each arm edge: the boot
         * settle, each cadence-loop wait, and again right BEFORE a rotate pass (the pass runs a multi-second
         * ping budget + restart — re-stamping first keeps the dial from reading a false "overdue" STALLED
         * while the flip is actively in progress). [nowElapsedMs] is injectable for plain-JVM JUnit; the
         * default is the real monotonic clock.
         */
        @JvmStatic
        internal fun publishNextFlip(inMs: Long, nowElapsedMs: Long = SystemClock.elapsedRealtime()) {
            nextFlipAtElapsedMs = nowElapsedMs + inMs
        }

        /** Clear the schedule (rotation stopped) — readers then fall back to the durable 0 (idle "—"). */
        @JvmStatic
        internal fun clearNextFlip() {
            nextFlipAtElapsedMs = 0L
        }

        /**
         * The LIVE next-flip countdown in whole seconds, or `null` when no schedule is armed. NEGATIVE is
         * deliberate signal, never clamped: the flip is OVERDUE — the slint STALLED contract
         * (rotation.slint:174 `stalled: … next-flip-secs < 0`, the starved/frozen-wheel alarm).
         */
        @JvmStatic
        fun liveNextFlipSecs(nowElapsedMs: Long = SystemClock.elapsedRealtime()): Long? {
            val at = nextFlipAtElapsedMs
            if (at == 0L) return null
            return (at - nowElapsedMs) / 1000L
        }

        /**
         * #22 s5C — the DISTINCT relay names the LAST committed rotation's routes actually ride,
         * comma-joined ("" = no commit this process yet, or a relay-free set). Written only at the
         * [rotateOnce] commit edge; read by [TortaPillarBridge.liveRotationState]'s `chain_relays`
         * suffix so the Rotation dashboard's chain tile reports the REAL anonymization chain by name —
         * never a fabricated depth. Process-scoped on purpose: the durable cursor persists no relay
         * names, and honest-empty beats invented-warm.
         */
        @Volatile
        private var lastRelayChain: String = ""

        /** The live relay chain (see [lastRelayChain]) — "" when cold. Never throws. */
        fun liveRelayChain(): String = lastRelayChain

        /**
         * Rewrite the live (uncommented) `server_names` value to a fresh single-line array — robust to BOTH a
         * single-line value (`server_names = [...]`, what a prior rotation wrote) AND the multi-line array
         * block the Rust `dnscrypt_config_to_toml` serializer emits after any torta_ui toggle (server-type /
         * requirement / pin). A single-line-only replace left the multi-line body ORPHANED — bare quoted
         * strings + a stray `]` at top level → invalid TOML → dnscrypt parse-fail on the rotated restart
         * (AVD-caught 2026-07-15: a Rotate-Now after an IPv6-servers toggle corrupted the pool). Returns the
         * edited lines, or null when no uncommented `server_names` key exists (the caller then ABORTS — a
         * rotation must never write a pool-less TOML). Extracted PURE + [JvmStatic] so the multi-line case is
         * unit-provable on a plain JVM (the shape a single-line replace silently corrupts).
         */
        @JvmStatic
        internal fun replaceServerNamesBlock(lines: List<String>, serverNames: List<String>): List<String>? {
            val sIdx = lines.indexOfFirst {
                val t = it.trimStart(); t.startsWith("server_names") && !t.startsWith("#")
            }
            if (sIdx < 0) return null
            // Find the END of the existing value. Single-line (`= [..]` closed on the line, or a non-array
            // scalar) ⇒ sIdx itself. An OPEN multi-line array (`= [` with no `]` yet) ⇒ scan to its `]` line.
            val afterEq = lines[sIdx].substringAfter('=', "")
            val opensArray = afterEq.contains('[')
            val closedSameLine = afterEq.substringAfter('[', "").contains(']')
            var eIdx = sIdx
            if (opensArray && !closedSameLine) {
                var i = sIdx + 1
                while (i < lines.size) {
                    if (lines[i].trim() == "]") { eIdx = i; break }
                    i++
                }
            }
            val out = lines.toMutableList()
            for (k in eIdx downTo sIdx) out.removeAt(k)
            out.add(sIdx, "server_names = ['" + serverNames.joinToString("', '") + "']")
            return out
        }

        /** Noob default cadence: 30-min "rotate for privacy" diversity window (the real spec). */
        const val DEFAULT_CADENCE_MINUTES = 30

        /**
         * BOOT-PICK settle delay. The cadence loop used to `delay(cadence)` BEFORE its first pick, so the
         * diverse trust-filtered set only went live after a WHOLE cadence (default 30 min) — until then the
         * engine ran the bundled/configured server_names. That is the wrong posture for a no-fallback engine:
         * the diverse pool must be live AT boot. So [start] now fires ONE immediate boot pick after this short
         * settle (vs 30 min). The settle lets dnscrypt reach steady RUNNING before the rotation restart (no
         * mid-bring-up restart thrash) and lets the source-list readiness probe finish first; it is a boot
         * one-off, ~180× faster than the old first-swap wait. Kept OFF the cadence loop so a cadence-chip
         * re-arm ([onCadencePrefChanged]) never forces a spurious extra rotation.
         */
        const val BOOT_PICK_SETTLE_MS = 10_000L

        /** Expert clamp floor: never rotate faster than every 5 min (battery + churn guard). */
        const val MIN_CADENCE_MINUTES = 5

        /** Expert clamp ceiling: 7 days (10080 minutes = the old 168h max, preserved). */
        const val MAX_CADENCE_MINUTES = 10080

        /**
         * Per-query budget handed to the native resolver on a rotation swap
         * ([ResolverRuntime.applyRotatedPool]). The native side clamps to 50..60000 internally; this
         * keeps a freshly-rotated pool honest without hammering battery.
         */
        const val ROTATION_TIMEOUT_MS = 5000L

        /** Answer cache size for the freshly-rotated pool (a re-configure installs a fresh cache). */
        const val CACHE_CAP = 1024

        /**
         * How many independent questions [poolAnswersRealQueries] asks before calling a pool mute.
         * Three, because ONE unanswered query is ordinary packet loss and rolling back on it would
         * make rotation flap; three consecutive failures against a pool that just probed reachable is
         * the mute-pool signature (the measured outage produced 311 in a row, so three is generous).
         */
        const val VERIFY_ATTEMPTS = 3

        /**
         * The zone the verification query is asked under. RFC 2606 reserves `example.com` and IANA
         * runs real authoritative servers for it, so a random label beneath it is guaranteed to reach
         * a live nameserver and come back — NXDOMAIN, which is exactly the proof wanted. Deliberately
         * NOT a vendor domain: this must not become a heartbeat to anyone's infrastructure.
         */
        const val VERIFY_ZONE = "example.com"

        /**
         * Prefix on the random label, so anyone reading a capture can see the query is Tortä's own
         * liveness probe and not user traffic. The random suffix after it is what defeats the cache.
         */
        const val VERIFY_LABEL_PREFIX = "torta-rotverify-"

        /** QTYPE A (RFC 1035 §3.2.2) — the `dns::build_query` qtype for the verification question. */
        const val VERIFY_QTYPE_A = 1

        /**
         * Spacing between verification questions, also paid BEFORE the first one. The commit restarts
         * dnscrypt-proxy immediately beforehand, so an unspaced burst can land entirely inside the
         * restart window and mark a healthy pool mute — a false rollback, which flaps rotation between
         * two sets and is an outage of its own. 600 ms × 3 keeps the whole gate near two seconds on a
         * control-plane path that runs at most once per cadence.
         */
        const val VERIFY_RETRY_SPACING_MS = 600L

        /**
         * The qname for ONE verification question — a fresh random label under [VERIFY_ZONE] every
         * call. The randomness is the whole point and not cosmetic: `resolver_resolve` is
         * block-check → cache → transport (`lib.rs:2104-2110`), so a repeatable name could be served
         * from cache and the gate would pass against a pool that never answered anything. Two calls
         * returning the same string would silently restore exactly the bug this gate exists to catch,
         * which is why the test asserts they differ.
         */
        @JvmStatic
        internal fun verificationQname(): String {
            val label = java.util.UUID.randomUUID().toString().replace("-", "").take(VERIFY_LABEL_ENTROPY_CHARS)
            return "$VERIFY_LABEL_PREFIX$label.$VERIFY_ZONE"
        }

        /** Random hex characters in a verification label — 16 of 32 UUID hex chars = 64 bits. */
        const val VERIFY_LABEL_ENTROPY_CHARS = 16

        /**
         * Does this response prove an encrypted exchange completed? A null is the façade's "nothing
         * came back" (mute pool, native fault, or a rejected/poisoned answer — all failures here). A
         * buffer shorter than a DNS header cannot be a DNS message, so it is rejected rather than
         * counted. NXDOMAIN passes deliberately: the question is whether the TRANSPORT is alive, not
         * what the answer says.
         */
        @JvmStatic
        internal fun responseProvesLiveTransport(response: ByteArray?): Boolean =
            response != null && response.size >= DNS_HEADER_BYTES

        /**
         * A DNS message header is 12 bytes (RFC 1035 §4.1.1). A response shorter than that cannot be a
         * DNS message at all, so it is rejected rather than counted as a live answer.
         */
        const val DNS_HEADER_BYTES = 12

        /**
         * D30(3) — the whole-set RTT measurement budget per committed swap. The underlying
         * TCP-connect pings run concurrently with their own socket timeouts; this outer bound
         * guarantees a hung network can never stall a rotation commit (timeout ⇒ "" hints, the
         * pre-D30 posture).
         */
        const val RTT_PING_BUDGET_MS = 10_000L

        /**
         * The seed salt for the per-window relay shuffle (the java.util.Random LCG multiplier — an
         * arbitrary well-mixed constant, kept byte-identical to the pre-D06 route builder so a given
         * rotation index reproduces its window's relay binding).
         */
        private const val ROUTE_SHUFFLE_SEED = 0x5DEECE66DL

        /**
         * The user's chosen rotation pool sizes (the Academic-Wall, [[torta-rotation-engine-wiring]]): GEEK
         * tier writes a SAFE-bounded slider value (1..[RotationSelector.GEEK_SAFE_MAX_SERVERS] /
         * 1..[RotationSelector.GEEK_SAFE_MAX_RELAYS]); the NERD tier writes a FREE value (no cap). Absent ⇒
         * the geek-safe default. Read at rotation time so the count is never hard-coded.
         */
        const val MAX_SERVERS_PREF = "pref_resolver_rotation_max_servers"

        /** The user's chosen relays-per-server count pref (GEEK safe-slider or NERD-free). */
        const val MAX_RELAYS_PREF = "pref_resolver_rotation_max_relays"

        /**
         * #22 s5A — the floor-only clamp for the SLINT Rotation-dashboard SERVERS-PER-ROTATION
         * stepper: at least 1 (a rotation of zero resolvers is meaningless), NO upper limit — Socio
         * 2026-07-19: "remove any Limit to the Number of Resolver / Relays Selectable by the User …
         * because its not Genuine for the sake of the user". The GEEK_SAFE_* consts remain DEFAULTS
         * only, never ceilings. Pure + hermetic (unit-tested).
         */
        fun geekClampMaxServers(count: Int): Int =
            count.coerceAtLeast(1)

        /**
         * #22 s5A — the floor-only clamp for the SLINT RELAYS-PER-RESOLVER stepper: at least 0
         * (0 is a legal "direct, no relays" choice — [readMaxRelays] already honours it by emitting
         * no route lines), NO upper limit (the same Socio 2026-07-19 no-limits law as
         * [geekClampMaxServers]). Pure + hermetic.
         */
        fun geekClampMaxRelays(count: Int): Int =
            count.coerceAtLeast(0)

        /** Relative path of the runtime dnscrypt TOML under PathVars.appDataDir (the apply target). */
        const val DNSCRYPT_TOML_RELATIVE = "/app_data/dnscrypt-proxy/dnscrypt-proxy.toml"
    }
}
