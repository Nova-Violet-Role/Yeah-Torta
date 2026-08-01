/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

/*
    This file is part of Yeah! Tortä. GPL-3.0-or-later. Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.solver

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Test
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.Hysteresis.Decision
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.Hysteresis.HysteresisConfig
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.Hysteresis.HysteresisState
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.Hysteresis.SwitchOutcome
import pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.NetworkFingerprint.Companion.LinkType

/**
 * The ANTI-THRASH refute-swarm home (Monster Plan §7 prime target — "a self-healer that flaps is a new bug",
 * `MONSTER_ENHANCEMENT_PLAN.md:88,94-95`). Pure JUnit-on-metal (no Android/clock/RNG — the
 * [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationManagerGateTest] precedent): every test feeds an ADVERSARIAL
 * sequence at the [Hysteresis] gate + the [BindingCache] + the [NetworkFingerprint] and asserts the
 * load-bearing no-flap invariant. The headline pair:
 *  - oscillation (signal in the dead-band, OR a candidate within the switch margin) ⇒ **ZERO switches**;
 *  - a genuine, sustained improvement past dwell ⇒ **exactly ONE switch**.
 *
 * Each invariant I1–I6 has at least one named, hostile test. The composite proofs at the end compose the FULL
 * pipeline (the sibling [Solver.detectObstruction] → this [Hysteresis.observe] → [Hysteresis.decideSwitch] →
 * [Hysteresis.applySolve]) so the no-flap claim is proven end-to-end against the real obstruction blend, not a
 * stub.
 */
class AntiThrashInvariantTest {

    private fun cfg(
        enter: Double = 0.70,
        exit: Double = 0.40,
        confirm: Int = 3,
        dwellMs: Long = 30_000L,
        cooldownMs: Long = 20_000L,
        margin: Double = 0.15,
    ) = HysteresisConfig(enter, exit, confirm, dwellMs, cooldownMs, margin)

    // A LockedBinding template (the cache record shape; copy()/score to perturb).
    private fun binding(resolverId: String = "alpha", score: Double = 100.0, healthyAt: Long = 0L) = LockedBinding(
        transport = TransportKind.DNSCRYPT,
        resolverId = resolverId,
        relayId = null,
        tunedCwnd = 8,
        tunedCodelTargetMs = 5L,
        score = score,
        lockedAtMs = healthyAt,
        lastHealthyAtMs = healthyAt,
    )

    /** Drive a sequence of (signal, nowMs) through [Hysteresis.observe]; return how many ticks said SOLVE. */
    private fun countSolves(config: HysteresisConfig, steps: List<Pair<Double, Long>>): Int {
        var state = HysteresisState()
        var solves = 0
        for ((signal, now) in steps) {
            val (decision, next) = Hysteresis.observe(state, signal, now, config)
            state = next
            if (decision == Decision.SOLVE) {
                solves++
                state = Hysteresis.applySolve(state, now, config)
            }
        }
        return solves
    }

    // ════════════════════════════════════════════════════════════════════════════════════════
    // I1 · HYSTERESIS (Schmitt dead-band) — oscillation in [exit, enter) NEVER re-triggers.
    // ════════════════════════════════════════════════════════════════════════════════════════

    @Test
    fun `I1 sawtooth strictly inside the dead-band yields ZERO solves`() {
        val c = cfg(confirm = 1) // confirm=1 isolates the Schmitt latch from debounce.
        // A vicious sawtooth: 0.45 ↔ 0.65, both strictly inside [0.40, 0.70). Never reaches enter, never below exit.
        val steps = (0 until 200).map { i -> (if (i % 2 == 0) 0.45 else 0.65) to (i * 1000L) }
        assertEquals("a dead-band oscillation MUST never trigger a solve (I1)", 0, countSolves(c, steps))
    }

    @Test
    fun `I1 the armed latch survives dead-band noise after a solve and never re-fires there`() {
        val c = cfg(confirm = 1, dwellMs = 0, cooldownMs = 0)
        var state = HysteresisState()
        val (d, s) = Hysteresis.observe(state, 0.80, 0L, c); state = s
        assertEquals(Decision.SOLVE, d)
        state = Hysteresis.applySolve(state, 0L, c) // latch resets after the solve.
        assertFalse(state.armed)
        for (i in 1..50) {
            val (dd, ss) = Hysteresis.observe(state, 0.55, i * 1000L, c); state = ss
            assertEquals("dead-band noise after a solve must not re-trigger (I1)", Decision.HOLD, dd)
            assertFalse("dead-band noise must not re-arm the latch (I1)", state.armed)
        }
    }

    // ════════════════════════════════════════════════════════════════════════════════════════
    // I5 · DEBOUNCE — a transient spike shorter than confirmSamples never triggers.
    // ════════════════════════════════════════════════════════════════════════════════════════

    @Test
    fun `I5 a single-tick spike above enter does NOT solve`() {
        val steps = listOf(0.1 to 0L, 0.9 to 1000L, 0.1 to 2000L, 0.1 to 3000L)
        assertEquals("a 1-tick transient must never solve (I5)", 0, countSolves(cfg(confirm = 3), steps))
    }

    @Test
    fun `I5 a sub-threshold tick resets the confirm run - 2 then break then 2 never reaches 3`() {
        val c = cfg(confirm = 3, dwellMs = 0, cooldownMs = 0)
        val steps = listOf(0.9 to 0L, 0.9 to 1000L, 0.1 to 2000L, 0.9 to 3000L, 0.9 to 4000L)
        assertEquals("a broken run must restart the debounce count (I5)", 0, countSolves(c, steps))
    }

    @Test
    fun `I5 exactly confirmSamples consecutive over-enter ticks triggers once`() {
        val c = cfg(confirm = 3, dwellMs = 0, cooldownMs = 0)
        val steps = listOf(0.9 to 0L, 0.9 to 1000L, 0.9 to 2000L) // the 3rd tick is the trigger.
        assertEquals("the Nth consecutive over-enter tick must solve (I5)", 1, countSolves(c, steps))
    }

    // ════════════════════════════════════════════════════════════════════════════════════════
    // I2 · DWELL — a storm of triggers during the dwell window commits at most once per window.
    // ════════════════════════════════════════════════════════════════════════════════════════

    @Test
    fun `I2 a trigger storm during dwell yields exactly one solve per dwell window`() {
        val c = cfg(confirm = 1, dwellMs = 30_000L, cooldownMs = 0L) // isolate dwell from cooldown.
        // 100 ticks of MAX obstruction, 1s apart = 100s. dwell=30s ⇒ solves at t=0,30000,60000,90000 = 4, NOT 100.
        val steps = (0 until 100).map { 1.0 to (it * 1000L) }
        assertEquals("dwell must bound commits to one per window, not one per tick (I2)", 4, countSolves(c, steps))
    }

    @Test
    fun `I2 a fresh obstruction strictly inside dwell is suppressed`() {
        val c = cfg(confirm = 1, dwellMs = 30_000L, cooldownMs = 0L)
        var state = HysteresisState()
        val (d0, s0) = Hysteresis.observe(state, 1.0, 0L, c); state = s0
        assertEquals(Decision.SOLVE, d0)
        state = Hysteresis.applySolve(state, 0L, c)
        // t=15000 (< dwellUntil=30000): even MAX obstruction must HOLD.
        val (d1, _) = Hysteresis.observe(state, 1.0, 15_000L, c)
        assertEquals("an obstruction inside the dwell window must be suppressed (I2)", Decision.HOLD, d1)
    }

    // ════════════════════════════════════════════════════════════════════════════════════════
    // I4 · COOLDOWN — solves-per-minute is bounded by cooldown, not by tick rate.
    // ════════════════════════════════════════════════════════════════════════════════════════

    @Test
    fun `I4 continuous max obstruction is rate-limited by cooldown not tick rate`() {
        val c = cfg(confirm = 1, dwellMs = 0L, cooldownMs = 20_000L) // isolate cooldown from dwell.
        // 61 ticks across 0..60000ms. cooldown=20s ⇒ solves at t=0,20000,40000,60000 = 4, NOT 61.
        val steps = (0..60).map { 1.0 to (it * 1000L) }
        val solves = countSolves(c, steps)
        assertEquals("cooldown must rate-limit solves (I4)", 4, solves)
        assertTrue("solve rate must be cooldown-bounded, far below the 61-tick count", solves <= 60_000L / 20_000L + 1)
    }

    // ════════════════════════════════════════════════════════════════════════════════════════
    // I3 · COST-OF-SWITCHING — a tied / marginally-better candidate does NOT switch.
    // ════════════════════════════════════════════════════════════════════════════════════════

    @Test
    fun `I3 a candidate tied with the incumbent does not switch`() {
        assertEquals(SwitchOutcome.KEEP, Hysteresis.decideSwitch(100.0, 100.0, config = cfg(margin = 0.15)))
    }

    @Test
    fun `I3 a candidate marginally better (below the margin) does not switch`() {
        val c = cfg(margin = 0.15)
        // incumbent 100; threshold = 100*(1-0.15)=85. A candidate at 90 (10% better) is NOT a 15% win ⇒ KEEP.
        assertEquals(SwitchOutcome.KEEP, Hysteresis.decideSwitch(90.0, 100.0, config = c))
        // Right at the boundary 85 → SWITCH (≤ threshold); 85.0001 → KEEP.
        assertEquals(SwitchOutcome.SWITCH, Hysteresis.decideSwitch(85.0, 100.0, config = c))
        assertEquals(SwitchOutcome.KEEP, Hysteresis.decideSwitch(85.0001, 100.0, config = c))
    }

    @Test
    fun `I3 a genuine improvement past the margin switches`() {
        assertEquals(SwitchOutcome.SWITCH, Hysteresis.decideSwitch(70.0, 100.0, config = cfg(margin = 0.15)))
    }

    @Test
    fun `I3 a dead incumbent is replaced even by a marginal (worse) winner`() {
        assertEquals(SwitchOutcome.SWITCH,
            Hysteresis.decideSwitch(150.0, 100.0, incumbentDead = true, config = cfg(margin = 0.15)))
    }

    @Test
    fun `I3 the first binding (no incumbent) always takes`() {
        assertEquals(SwitchOutcome.SWITCH, Hysteresis.decideSwitch(123.0, null))
    }

    @Test
    fun `hysteresis config rejects an inverted dead-band or bad dials`() {
        try { HysteresisConfig(triggerEnter = 0.4, triggerExit = 0.4); assertTrue("expected IAE", false) } catch (e: IllegalArgumentException) {}
        try { HysteresisConfig(triggerEnter = 0.3, triggerExit = 0.6); assertTrue("expected IAE", false) } catch (e: IllegalArgumentException) {}
        try { HysteresisConfig(confirmSamples = 0); assertTrue("expected IAE", false) } catch (e: IllegalArgumentException) {}
        try { HysteresisConfig(dwellMs = -1L); assertTrue("expected IAE", false) } catch (e: IllegalArgumentException) {}
        try { HysteresisConfig(switchMargin = -0.1); assertTrue("expected IAE", false) } catch (e: IllegalArgumentException) {}
    }

    // ════════════════════════════════════════════════════════════════════════════════════════
    // THE HEADLINE PAIR — oscillation ⇒ ZERO switches; sustained genuine improvement ⇒ ONE switch.
    // ════════════════════════════════════════════════════════════════════════════════════════

    @Test
    fun `HEADLINE oscillating candidate scores within the margin band produce ZERO switches`() {
        val c = cfg(margin = 0.15)
        var incumbent = 100.0
        var switches = 0
        // 500 races where the candidate oscillates 95↔105 around a 100 incumbent — pure measurement noise.
        for (i in 0 until 500) {
            val candidate = if (i % 2 == 0) 95.0 else 105.0 // both within ±5% — never a 15% win.
            if (Hysteresis.decideSwitch(candidate, incumbent, config = c) == SwitchOutcome.SWITCH) {
                switches++
                incumbent = candidate
            }
        }
        assertEquals("noise oscillating within the margin band MUST never switch (the headline no-flap)", 0, switches)
    }

    @Test
    fun `HEADLINE a sustained genuine improvement past dwell produces exactly ONE switch`() {
        val c = cfg(confirm = 3, dwellMs = 30_000L, cooldownMs = 20_000L, margin = 0.15)
        var state = HysteresisState()
        var incumbentScore: Double? = 100.0
        var committedSwitches = 0
        // 40 ticks @ 1s: a sustained MAX obstruction the whole time, and a genuinely better candidate (60, a 40%
        // win) available every race. WITHOUT dwell/cooldown this would switch many times; WITH them it commits
        // exactly ONE switch in the first eligible window, then dwell+cooldown suppress the rest.
        for (i in 0 until 40) {
            val now = i * 1000L
            val (d, next) = Hysteresis.observe(state, 0.9, now, c)
            state = next
            if (d == Decision.SOLVE) {
                if (Hysteresis.decideSwitch(60.0, incumbentScore, config = c) == SwitchOutcome.SWITCH) {
                    committedSwitches++
                    incumbentScore = 60.0 // now the incumbent; further 60-candidates tie ⇒ KEEP.
                }
                state = Hysteresis.applySolve(state, now, c)
            }
        }
        assertEquals(
            "a sustained genuine improvement must switch ONCE then hold (dwell+margin stop the flap)",
            1, committedSwitches
        )
        assertEquals("after the one switch the incumbent is the improved binding", 60.0, incumbentScore)
    }

    // ════════════════════════════════════════════════════════════════════════════════════════
    // FULL PIPELINE — Solver.detectObstruction → Hysteresis.observe → decideSwitch → applySolve.
    // The end-to-end no-flap proof, against the REAL obstruction blend (not a stub).
    // ════════════════════════════════════════════════════════════════════════════════════════

    /** A high-obstruction snapshot (sojourn far over the CoDel target) — detectObstruction ≈ 0.77 ≥ enter. */
    private fun obstructed() = SolverInput(sojournP95Ms = 200L, blueProb = 0.2, bestUpstreamScore = 180.0)
    /** A dead-band snapshot — detectObstruction ≈ 0.43 (in [exit, enter): never triggers). */
    private fun deadBand() = SolverInput(sojournP95Ms = 18L, blueProb = 0.05, bestUpstreamScore = 40.0)
    /** A fully calm snapshot — detectObstruction = 0.0 (< exit: clears the latch). */
    private fun calm() = SolverInput(sojournP95Ms = 0L, blueProb = 0.0, bestUpstreamScore = 10.0)
    /** A transient spike — detectObstruction ≈ 0.60 (< enter on its own: cannot even start a confirm run). */
    private fun spike() = SolverInput(sojournP95Ms = 999L, blueProb = 0.25)

    @Test
    fun `PIPELINE a sustained genuine improvement past dwell produces exactly ONE committed switch`() {
        val cc = cfg(confirm = 3, dwellMs = 30_000L, cooldownMs = 20_000L, margin = 0.15)
        var state = HysteresisState()
        var incumbentScore: Double? = 100.0
        var committedSwitches = 0
        for (i in 0 until 40) {
            val now = i * 1000L
            val verdict = Solver.detectObstruction(obstructed())
            val (d, next) = Hysteresis.observe(state, verdict.score, now, cc)
            state = next
            if (d != Decision.SOLVE) continue
            if (Hysteresis.decideSwitch(60.0, incumbentScore, config = cc) == SwitchOutcome.SWITCH) {
                committedSwitches++
                incumbentScore = 60.0
            }
            state = Hysteresis.applySolve(state, now, cc)
        }
        assertEquals("a sustained genuine improvement must switch ONCE then hold", 1, committedSwitches)
        assertEquals("after the one switch the incumbent is the improved binding", 60.0, incumbentScore)
    }

    @Test
    fun `PIPELINE a dead-band oscillation produces ZERO solves and ZERO switches`() {
        val cc = cfg()
        var state = HysteresisState()
        var committedSwitches = 0
        var solves = 0
        // A vicious sawtooth that NEVER crosses the enter rail: dead-band ↔ calm. The gate must never SOLVE.
        for (i in 0 until 200) {
            val input = if (i % 2 == 0) deadBand() else calm()
            val verdict = Solver.detectObstruction(input)
            val (d, next) = Hysteresis.observe(state, verdict.score, i * 1000L, cc)
            state = next
            if (d == Decision.SOLVE) {
                solves++
                if (Hysteresis.decideSwitch(50.0, 100.0, config = cc) == SwitchOutcome.SWITCH) committedSwitches++
                state = Hysteresis.applySolve(state, i * 1000L, cc)
            }
        }
        assertEquals("a dead-band/calm oscillation must never solve (hysteresis I1)", 0, solves)
        assertEquals("…and therefore never switch (the end-to-end no-flap)", 0, committedSwitches)
    }

    @Test
    fun `PIPELINE an adversarial mixed storm cannot make the binding flap`() {
        val cc = cfg(confirm = 3, dwellMs = 30_000L, cooldownMs = 20_000L, margin = 0.15)
        var state = HysteresisState()
        var incumbentScore: Double? = 100.0
        var committedSwitches = 0
        var solves = 0
        // 600 ticks @ 1s = 600s. Bursts of high obstruction, dead-band noise, transient spikes — and a candidate
        // that is a WASH (101, worse than the 100 incumbent) for the whole first half, then a genuine sustained
        // win (70) in the second half. The no-flap claim: across 600s of churn the binding switches EXACTLY ONCE
        // (when the real win finally arrives) and then holds — a wash candidate can never switch it back.
        for (i in 0 until 600) {
            val now = i * 1000L
            val input = when (i % 10) {
                0, 1, 2 -> obstructed()  // sustained high (can confirm a trigger)
                3 -> deadBand()          // dead-band noise (must not disarm a fresh latch mid-confirm)
                4 -> spike()             // a transient spike (sub-enter on its own)
                else -> calm()           // calm drift (clears the latch)
            }
            val verdict = Solver.detectObstruction(input)
            val (d, next) = Hysteresis.observe(state, verdict.score, now, cc)
            state = next
            if (d != Decision.SOLVE) continue
            solves++
            val candidate = if (i >= 300) 70.0 else 101.0
            if (Hysteresis.decideSwitch(candidate, incumbentScore, config = cc) == SwitchOutcome.SWITCH) {
                committedSwitches++
                incumbentScore = candidate
            }
            state = Hysteresis.applySolve(state, now, cc)
        }
        // (1) solves are cooldown/dwell-bounded: ≤ span/cooldown + 1 = 600000/20000 + 1 = 31 (measured: 20).
        assertTrue("solves must be cooldown-bounded ($solves)", solves <= 600_000L / 20_000L + 1)
        // (2) the binding switched EXACTLY ONCE across the whole storm — the no-flap headline under adversity.
        assertEquals("an adversarial 600s storm must commit exactly ONE switch (no flap)", 1, committedSwitches)
        // (3) and it settled on the genuine improvement; a wash candidate can never flap it back.
        assertEquals("after settling on the good binding it must never flap back", 70.0, incumbentScore)
    }

    // ════════════════════════════════════════════════════════════════════════════════════════
    // I6 · FINGERPRINT STICKINESS — a known-good network instant-reuses (NO race).
    // ════════════════════════════════════════════════════════════════════════════════════════

    @Test
    fun `I6 a fresh cached binding is an instant-reuse hit (no race)`() {
        val cache = BindingCache(capacity = 16, ttlMs = 6L * 60 * 60 * 1000)
        val fp = NetworkFingerprint.of(LinkType.WIFI, "\"HomeWifi\"", "192.168.1.1")
        cache.commit(fp, binding("alpha", healthyAt = 0L))
        val result = cache.lookup(fp, nowMs = 60_000L)
        assertTrue("a fresh binding must be an instant-reuse Hit (I6)", result is CacheResult.Hit)
        assertEquals("alpha", (result as CacheResult.Hit).binding.resolverId)
    }

    @Test
    fun `I6 the same network fingerprint twice is a cache hit - second entry needs no race`() {
        val cache = BindingCache()
        val fp1 = NetworkFingerprint.of(LinkType.WIFI, "CoffeeShop", "10.0.0.1")
        assertEquals(CacheResult.Miss, cache.lookup(fp1, 0L))
        cache.commit(fp1, binding("beta", healthyAt = 0L))
        // Walk away, walk back onto the SAME network (a fresh fingerprint of the same attrs): instant reuse.
        val fp2 = NetworkFingerprint.of(LinkType.WIFI, "CoffeeShop", "10.0.0.1")
        assertEquals("the same network must produce the same key", fp1, fp2)
        assertTrue("re-entry onto a known network must be a cache hit (I6)", cache.lookup(fp2, 1000L) is CacheResult.Hit)
    }

    // ════════════════════════════════════════════════════════════════════════════════════════
    // BINDING CACHE — TTL expiry, LRU eviction, invalidate-on-dead, touch-keeps-warm.
    // ════════════════════════════════════════════════════════════════════════════════════════

    @Test
    fun `cache a stale binding past TTL is a miss (forces a re-race)`() {
        val cache = BindingCache(ttlMs = 10_000L)
        val fp = NetworkFingerprint.of(LinkType.WIFI, "X", "1.1.1.1")
        cache.commit(fp, binding(healthyAt = 0L))
        assertTrue("within TTL → hit", cache.lookup(fp, 9_999L) is CacheResult.Hit)
        assertEquals("at/after TTL → miss", CacheResult.Miss, cache.lookup(fp, 10_000L))
        assertEquals("well past TTL → miss", CacheResult.Miss, cache.lookup(fp, 999_999L))
    }

    @Test
    fun `cache touchHealthy keeps a good lock warm against TTL`() {
        val cache = BindingCache(ttlMs = 10_000L)
        val fp = NetworkFingerprint.of(LinkType.WIFI, "X", "1.1.1.1")
        cache.commit(fp, binding(healthyAt = 0L))
        // At t=9000 (still fresh) refresh health → lastHealthy=9000, TTL window slides to 19000.
        assertNotNull(cache.touchHealthy(fp, 9_000L))
        assertTrue("refreshed lock is still fresh at t=18000 (would have been stale at 10000)",
            cache.lookup(fp, 18_000L) is CacheResult.Hit)
        assertEquals("but stale once the refreshed TTL passes", CacheResult.Miss, cache.lookup(fp, 19_000L))
    }

    @Test
    fun `cache LRU evicts the least-recently-used beyond capacity`() {
        val cache = BindingCache(capacity = 2, ttlMs = Long.MAX_VALUE)
        val a = NetworkFingerprint.of(LinkType.WIFI, "A", "1.0.0.1")
        val b = NetworkFingerprint.of(LinkType.WIFI, "B", "1.0.0.2")
        val cFp = NetworkFingerprint.of(LinkType.WIFI, "C", "1.0.0.3")
        cache.commit(a, binding("a"))
        cache.commit(b, binding("b"))
        // Touch A (lookup = access) so B becomes the LRU; inserting C must evict B, not A.
        assertTrue(cache.lookup(a, 0L) is CacheResult.Hit)
        cache.commit(cFp, binding("c"))
        assertEquals("capacity is enforced", 2, cache.size())
        assertNotNull("A was recently used → retained", cache.peek(a))
        assertNull("B was the LRU → evicted", cache.peek(b))
        assertNotNull("C just inserted → present", cache.peek(cFp))
    }

    @Test
    fun `cache invalidate drops a proven-dead binding so the next entry re-races`() {
        val cache = BindingCache()
        val fp = NetworkFingerprint.of(LinkType.WIFI, "X", "1.1.1.1")
        cache.commit(fp, binding(healthyAt = 0L))
        assertNotNull(cache.invalidate(fp))
        assertEquals("an invalidated binding is gone → next entry is a miss (re-race)",
            CacheResult.Miss, cache.lookup(fp, 0L))
    }

    @Test
    fun `cache rejects a non-positive capacity or ttl`() {
        try { BindingCache(capacity = 0); assertTrue("expected IAE", false) } catch (e: IllegalArgumentException) {}
        try { BindingCache(ttlMs = 0L); assertTrue("expected IAE", false) } catch (e: IllegalArgumentException) {}
    }

    // ════════════════════════════════════════════════════════════════════════════════════════
    // DURABLE MIRROR SEAMS (#19 G10) — snapshot → "process death" → rehydrate-admit, fresh-only.
    // ════════════════════════════════════════════════════════════════════════════════════════

    @Test
    fun `mirror a snapshot rehydrated into a fresh cache round-trips the fresh binding (warm re-entry)`() {
        val cache = BindingCache(ttlMs = 10_000L)
        val fp = NetworkFingerprint.of(LinkType.WIFI, "Home", "192.168.1.1")
        cache.commit(fp, binding("alpha", healthyAt = 5_000L))
        val persisted = cache.snapshotEntries() // what the write-through hands the durable record

        // "Process death": a brand-new cache (new process RAM) admits the persisted rows.
        val reborn = BindingCache(ttlMs = 10_000L)
        val admitted = reborn.rehydrateFrom(persisted, nowMs = 8_000L) // 3 s later, well within TTL
        assertEquals("the fresh row is admitted", 1, admitted)
        val hit = reborn.lookup(fp, nowMs = 9_000L)
        assertTrue("re-entry after a restart is an instant-reuse hit (no re-race)", hit is CacheResult.Hit)
        assertEquals("every field survives the round-trip", binding("alpha", healthyAt = 5_000L),
            (hit as CacheResult.Hit).binding)
    }

    @Test
    fun `mirror a binding that expired while the process was dead is DROPPED at rehydrate (stale = miss = re-race)`() {
        val cache = BindingCache(ttlMs = 10_000L)
        val fp = NetworkFingerprint.of(LinkType.WIFI, "Home", "192.168.1.1")
        cache.commit(fp, binding("alpha", healthyAt = 0L))
        val persisted = cache.snapshotEntries()

        // The process is dead PAST the TTL: the row must not be resurrected from NAND.
        val reborn = BindingCache(ttlMs = 10_000L)
        assertEquals("the stale corpse is dropped", 0, reborn.rehydrateFrom(persisted, nowMs = 10_000L))
        assertEquals("nothing admitted", 0, reborn.size())
        assertEquals("next entry re-races exactly as the in-RAM TTL law demands",
            CacheResult.Miss, reborn.lookup(fp, 10_001L))
    }

    @Test
    fun `mirror rehydrate admits fresh and drops stale in ONE persisted set`() {
        val cache = BindingCache(ttlMs = 10_000L)
        val fresh = NetworkFingerprint.of(LinkType.WIFI, "Fresh", "10.0.0.1")
        val stale = NetworkFingerprint.of(LinkType.WIFI, "Stale", "10.0.0.2")
        cache.commit(fresh, binding("f", healthyAt = 9_000L))
        cache.commit(stale, binding("s", healthyAt = 0L))
        val reborn = BindingCache(ttlMs = 10_000L)
        assertEquals("only the fresh row is admitted", 1, reborn.rehydrateFrom(cache.snapshotEntries(), nowMs = 12_000L))
        assertTrue(reborn.lookup(fresh, 12_000L) is CacheResult.Hit)
        assertEquals(CacheResult.Miss, reborn.lookup(stale, 12_000L))
    }

    @Test
    fun `mirror snapshot does not perturb LRU order (a pure read)`() {
        val cache = BindingCache(capacity = 2, ttlMs = Long.MAX_VALUE)
        val a = NetworkFingerprint.of(LinkType.WIFI, "A", "1.0.0.1")
        val b = NetworkFingerprint.of(LinkType.WIFI, "B", "1.0.0.2")
        val cFp = NetworkFingerprint.of(LinkType.WIFI, "C", "1.0.0.3")
        cache.commit(a, binding("a"))
        cache.commit(b, binding("b"))
        cache.snapshotEntries() // the write-through read — must NOT count as an access on A or B
        cache.commit(cFp, binding("c"))
        assertNull("A stays the LRU after a snapshot → still the one evicted", cache.peek(a))
        assertNotNull(cache.peek(b))
        assertNotNull(cache.peek(cFp))
    }

    // ════════════════════════════════════════════════════════════════════════════════════════
    // NETWORK FINGERPRINT — stable per network, distinct across networks, privacy-safe, no-flap on UNKNOWN.
    // ════════════════════════════════════════════════════════════════════════════════════════

    @Test
    fun `fingerprint is stable for the same network and quote-insensitive for the SSID`() {
        // Android wraps the SSID in quotes; both forms must collapse to ONE key (else a re-read would re-race).
        val quoted = NetworkFingerprint.of(LinkType.WIFI, "\"HomeNet\"", "192.168.0.1")
        val unquoted = NetworkFingerprint.of(LinkType.WIFI, "HomeNet", "192.168.0.1")
        val cased = NetworkFingerprint.of(LinkType.WIFI, "HOMENET", "192.168.0.1")
        assertEquals("quoting must not change the key", quoted, unquoted)
        assertEquals("case must not change the key", quoted, cased)
    }

    @Test
    fun `fingerprint differs across SSID and across gateway and across link type`() {
        val base = NetworkFingerprint.of(LinkType.WIFI, "Net", "192.168.0.1")
        assertNotEquals("different SSID → different key", base, NetworkFingerprint.of(LinkType.WIFI, "Other", "192.168.0.1"))
        assertNotEquals("different gateway (same SSID) → different key", base, NetworkFingerprint.of(LinkType.WIFI, "Net", "10.0.0.1"))
        assertNotEquals("different link type → different key", base, NetworkFingerprint.of(LinkType.CELLULAR, "Net", "192.168.0.1"))
    }

    @Test
    fun `fingerprint never stores the raw SSID (privacy)`() {
        val raw = "MySecretHomeSSID"
        val fp = NetworkFingerprint.of(LinkType.WIFI, raw, "192.168.0.1")
        assertFalse("the opaque key MUST NOT contain the raw SSID", fp.key.contains(raw, ignoreCase = true))
        assertTrue("the key is the opaque fp_ digest", fp.key.startsWith("fp_"))
    }

    @Test
    fun `fingerprint collapses unreadable wifi SSID to the gateway (still stable on a LAN)`() {
        // location-off → "<unknown ssid>"; a blank read; both degrade to the gateway → SAME stable key.
        val unknown = NetworkFingerprint.of(LinkType.WIFI, "<unknown ssid>", "192.168.1.1")
        val blank = NetworkFingerprint.of(LinkType.WIFI, "", "192.168.1.1")
        assertEquals("an unreadable SSID degrades to the gateway key", unknown, blank)
    }

    @Test
    fun `fingerprint UNKNOWN link folds to the single NONE sentinel (no cache thrash)`() {
        val a = NetworkFingerprint.of(LinkType.UNKNOWN, "whatever", "1.2.3.4")
        val b = NetworkFingerprint.of(LinkType.UNKNOWN, null, null)
        assertEquals("all UNKNOWN reads must share ONE key so they never thrash the cache", a, b)
        assertEquals("the NONE sentinel matches an UNKNOWN read", NetworkFingerprint.NONE, b)
    }

    @Test
    fun `fingerprint cellular ignores the unstable gateway, keys on the carrier`() {
        val gw1 = NetworkFingerprint.of(LinkType.CELLULAR, "Carrier", "100.64.0.1")
        val gw2 = NetworkFingerprint.of(LinkType.CELLULAR, "Carrier", "100.64.7.9")
        assertEquals("cellular must ignore the churny gateway and key on the carrier", gw1, gw2)
    }

    @Test
    fun `fingerprint hasChanged detects a network change and equality across a round-trip key`() {
        val home = NetworkFingerprint.of(LinkType.WIFI, "Home", "192.168.0.1")
        val cafe = NetworkFingerprint.of(LinkType.WIFI, "Cafe", "10.0.0.1")
        assertTrue("home → cafe is a change (re-solve trigger)", cafe.hasChanged(home))
        assertFalse("home → home is not a change", home.hasChanged(home))
        assertTrue("a first observation (null prev) counts as a change", home.hasChanged(null))
        assertEquals("a key round-trips to an equal fingerprint", home, NetworkFingerprint.fromKey(home.key))
    }
}
