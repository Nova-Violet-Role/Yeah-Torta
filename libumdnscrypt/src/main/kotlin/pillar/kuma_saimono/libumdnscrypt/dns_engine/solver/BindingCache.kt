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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.solver

/**
 * Monster Plan §7 (Stage E) — the **per-network binding cache**: fingerprint → the binding the solver locked
 * on that network, so re-entering a known-good network is an INSTANT REUSE (a 0-cost map lookup) instead of
 * re-running the 1–2 s `transport × resolver × relay` race (`MONSTER_ENHANCEMENT_PLAN.md:86` — "CACHE the
 * solution per network fingerprint (SSID/gateway → instant reuse)"). It is the **cost-amortizer** that makes
 * the solver cheap to keep on: solve a network once, then ride the cache.
 *
 * **Convergence seam (REUSE, not fork).** The sibling [Solver] produces a [SolverBinding] and converts it to
 * this file's [LockedBinding] via [Solver.toLockedBinding] (`Solver.kt:311-320`) so the race output drops
 * straight into [commit] — one cache record type, no parallel shape. The cache stores exactly that
 * [LockedBinding] (it already carries its own `lastHealthyAtMs`, the per-binding clock the value type needs
 * for expiry), and the sibling [Solver.detectObstruction] / `shouldTrigger` (the ENTER-side trigger) +
 * [Hysteresis] (the COMMIT-side dwell/cooldown/cost-of-switching) compose over it.
 *
 * **Pure data — the deferred-live boundary.** A side-effect-free LRU `Map` keyed on the opaque
 * [NetworkFingerprint] (no Android, no clock-of-its-own, no IO). The caller passes `nowMs` in (the
 * [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationSelector] precedent — "no clock, no RNG ⇒ JUnit-on-metal"),
 * so the live `SolverManager` owns the wall-clock and this stays 100% deterministically testable. The LIVE
 * solve/enforce (committing a [LockedBinding] to the resolver via `TortaCore.configureResolver`,
 * `RotationManager.kt:48-58`) is DEFERRED — this only remembers WHAT was solved; it never enforces it.
 *
 * **Anti-thrash role.** A fresh good lock short-circuits a fresh solve to an instant reuse ([lookup] →
 * [CacheResult.Hit]) so re-entering a known-good network never starts a race (invariant I6 — fingerprint
 * stickiness). [touchHealthy] keeps a good lock warm so it does not expire while in steady use; [invalidate]
 * drops a proven-dead binding so the NEXT entry is forced to re-race. The cache + the dwell/cost-of-switching
 * gate ([Hysteresis]) together are the no-flap spine.
 */
class BindingCache(
    /** Max distinct networks remembered; LRU-evicts the least-recently-used beyond this. ~16 covers a user's
     *  real network history (home/work/phone/a few cafés) with a trivial footprint. */
    val capacity: Int = DEFAULT_CAPACITY,
    /** A binding older than this since its last *healthy* touch is STALE → a [lookup] misses (force a re-race).
     *  Default 6 h: long enough to ride a commute/work-day reuse, short enough that a path that silently rotted
     *  off-network is re-validated rather than blindly reused. */
    val ttlMs: Long = DEFAULT_TTL_MS,
) {
    init {
        require(capacity > 0) { "BindingCache capacity must be > 0 (was $capacity)" }
        require(ttlMs > 0L) { "BindingCache ttlMs must be > 0 (was $ttlMs)" }
    }

    /**
     * accessOrder=true → a `get` (lookup) moves the entry to the most-recently-used end, so [removeEldestEntry]
     * evicts the genuine LRU. Insertion-ordered would evict by age-of-insert and drop a network you keep using.
     */
    private val map = object : LinkedHashMap<String, LockedBinding>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, LockedBinding>?): Boolean =
            size > capacity
    }

    /**
     * Look up the cached binding for [fp]. A [CacheResult.Hit] (instant reuse, no race) is returned ONLY when a
     * binding exists AND it is still fresh (`nowMs − lastHealthyAtMs < ttlMs`). A stale binding is a
     * [CacheResult.Miss] — it is left in place (LRU/[touchHealthy] may yet refresh it) but NOT reused, so an
     * obstruction re-race is armed. A missing binding is a [CacheResult.Miss] too.
     *
     * The lookup itself counts as a recency touch (LRU access-order), so a network you keep checking stays warm
     * against eviction even before it is re-marked healthy.
     */
    fun lookup(fp: NetworkFingerprint, nowMs: Long): CacheResult {
        val binding = map[fp.key] ?: return CacheResult.Miss
        return if (nowMs - binding.lastHealthyAtMs < ttlMs) CacheResult.Hit(binding) else CacheResult.Miss
    }

    /**
     * Commit (insert or replace) the binding the solver locked for [fp]. LRU-evicts the eldest if over
     * [capacity]. This is the "lock → cache" step: after a race picks a winner, remember it so the next entry
     * onto this network reuses it. The [LockedBinding] carries its own `lockedAtMs`/`lastHealthyAtMs`
     * (stamped by [Solver.toLockedBinding] at commit), so the cache adds no clock of its own.
     */
    fun commit(fp: NetworkFingerprint, binding: LockedBinding) {
        map[fp.key] = binding
    }

    /**
     * Refresh a binding's [LockedBinding.lastHealthyAtMs] on a healthy steady tick — keeps a good lock warm so
     * it never expires out from under continuous use. No-op if [fp] is not cached. Returns the refreshed
     * binding (or null if absent) for the caller's convenience.
     */
    fun touchHealthy(fp: NetworkFingerprint, nowMs: Long): LockedBinding? {
        val binding = map[fp.key] ?: return null
        val refreshed = binding.copy(lastHealthyAtMs = nowMs)
        map[fp.key] = refreshed
        return refreshed
    }

    /**
     * Drop a binding proven DEAD (the chosen transport/resolver stopped working) so the next entry onto [fp]
     * is forced to re-race rather than instant-reuse a rotted path. Returns the removed binding, or null.
     */
    fun invalidate(fp: NetworkFingerprint): LockedBinding? = map.remove(fp.key)

    /** Number of networks currently remembered (≤ [capacity]). */
    fun size(): Int = map.size

    /** Peek the cached binding for [fp] WITHOUT a freshness check or an LRU touch (diagnostics/tests only). */
    fun peek(fp: NetworkFingerprint): LockedBinding? = map[fp.key]

    /** Drop everything (e.g. an Expert "forget solved networks" action). */
    fun clear() = map.clear()

    // ---- the durable-mirror seams (#19 G10 — RAM ⊗ NAND, `solver-bindings` DurableTier record) ----

    /**
     * Snapshot EVERY live entry (opaque fingerprint key → binding), LRU-order (least-recent first) — the
     * write-through read the durable mirror persists after a [commit]/[invalidate] (control-plane only,
     * never per-query — F16). Pure: iterating the entry set does NOT count as an LRU access (only `get`
     * reorders an access-ordered [LinkedHashMap]), so a snapshot never perturbs eviction order. The keys
     * are the privacy-safe [NetworkFingerprint.key] digests — safe to persist (no raw SSID, T20).
     */
    fun snapshotEntries(): List<Pair<String, LockedBinding>> = map.entries.map { it.key to it.value }

    /**
     * Admit persisted entries at rehydrate — FRESH-only: a row whose `nowMs − lastHealthyAtMs ≥ ttlMs` is
     * DROPPED here, so a binding that expired while the process was dead misses exactly as it would have
     * in RAM (the #19 law: never serve a dead binding just because it survived on NAND). Later duplicates
     * of a key replace earlier ones (last-writer-wins, the persisted order is oldest-first); admission
     * count is returned for the rehydrate log line. Insertion counts as recency (the freshly-admitted set
     * IS the recent history). Bounded by [capacity] via the live LRU eviction — never over-fills.
     */
    fun rehydrateFrom(entries: List<Pair<String, LockedBinding>>, nowMs: Long): Int {
        var admitted = 0
        for ((key, binding) in entries) {
            if (key.isEmpty()) continue
            if (nowMs - binding.lastHealthyAtMs >= ttlMs) continue // stale corpse — miss, force a re-race
            map[key] = binding
            admitted++
        }
        return admitted
    }

    companion object {
        /** ~16 networks: a real user's home/work/phone/a few cafés, with a negligible footprint. */
        const val DEFAULT_CAPACITY = 16

        /** 6 hours. Long enough to ride a work-day reuse; short enough to re-validate a path that rotted off-net. */
        const val DEFAULT_TTL_MS = 6L * 60L * 60L * 1000L
    }
}

/**
 * The result of a [BindingCache.lookup]. A sealed type so the caller MUST handle the miss path (re-race) — a
 * silent "null = miss" is too easy to ignore where the whole point is "reuse when you can, race when you must".
 */
sealed interface CacheResult {
    /** A fresh cached binding exists → instant reuse, NO race (the anti-thrash short-circuit, invariant I6). */
    data class Hit(val binding: LockedBinding) : CacheResult
    /** No fresh binding → arm a fresh race for this network (cache miss or stale-expired). */
    data object Miss : CacheResult
}

/**
 * The binding the solver locked for a network — the immutable "this is the best path on THIS network" record
 * the [BindingCache] stores. Pure value type; the live commit of it (to the resolver pool) is DEFERRED
 * (Stage C+). The sibling [Solver.toLockedBinding] builds this from a solved [SolverBinding]
 * (`Solver.kt:311-320`) so the race output and the cache speak ONE shape.
 *
 * @param transport     the winning transport axis (the shared [TransportKind]).
 * @param resolverId    the winning resolver id (matches the `id` `ResolverRuntime.buildSpecsJson` emits,
 *                      `ResolverRuntime.kt:260-278`, and `RotationPing.Candidate.id`, `RotationPing.kt:75`).
 * @param relayId       the winning relay id, or null (no relay).
 * @param tunedCwnd     the cwnd the YeAH brain settled on for this binding (the Rust Beast
 *                      `beast/yeah.rs` `cwnd()`, surfaced via the pushed `BeastSnapshot.cwnd`);
 *                      carried so a reuse warm-starts the window instead of cold-starting at MIN_WINDOW.
 * @param tunedCodelTargetMs the CAKE COBALT CoDel target the binding tuned to (the Rust Beast
 *                      `beast/cake.rs` `codelTargetMs`); carried for the same warm-start reason.
 * @param score         the binding's quality, **LOWER = better** (the §4 governor blend convention the
 *                      sibling [Hysteresis.decideSwitch] reasons about — `Solver.toLockedBinding` feeds the
 *                      measured RTT here). Used as the incumbent-to-beat in the cost-of-switching gate.
 * @param lockedAtMs    wall-clock when this binding was first locked (provenance / age).
 * @param lastHealthyAtMs wall-clock of the last healthy observation; [BindingCache.lookup] freshness + the
 *                      dwell anchor. Refreshed by [BindingCache.touchHealthy].
 */
data class LockedBinding(
    val transport: TransportKind,
    val resolverId: String,
    val relayId: String? = null,
    val tunedCwnd: Int = 0,
    val tunedCodelTargetMs: Long = 0L,
    val score: Double = Double.MAX_VALUE,
    val lockedAtMs: Long = 0L,
    val lastHealthyAtMs: Long = 0L,
)

/**
 * The transport axis the solver races over (`MONSTER_ENHANCEMENT_PLAN.md:85` — "race transport × resolver ×
 * relay (DoH/DoH3/DoQ/DNSCrypt × pool × relays)"). A plain enum (the relay-capability fact lives on the
 * sibling [Solver.isRelayCapable] so this shared type stays minimal, `Solver.kt:162-166`). `ordinal` order
 * (DNSCRYPT first) is the deterministic enumeration order the sibling [Solver.enumerateRace] sorts by; the
 * stable `name` is the dedup/tiebreak token in [RaceCandidate.stableKey] (`SolverTypes.kt:143`).
 *
 * NOTE: the only transport the native swap builds TODAY is DNSCrypt/do53 (`RotationSelector.kt:60-63`); the
 * other arms are the solver's FUTURE race axes (gated on the resolver Stage-1 landing). The enum names them
 * now so the pure cache/decision core is complete; the LIVE race over them is DEFERRED.
 */
enum class TransportKind {
    DNSCRYPT,
    DOH,
    DOH3,
    DOQ,
}
