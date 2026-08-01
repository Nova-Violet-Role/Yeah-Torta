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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import pillar.kuma_saimono.libumdnscrypt.dns_engine.BeastTunables
import uniffi.torta_core.TortaProfile

/**
 * Pins the Stage-E [Solver] PURE core (Monster Plan §7):
 *  - **obstruction detect** — the weighted blend of the engine's existing signals + the dominant-signal
 *    attribution + the captive hard-override + the no-false-obstruction-from-absent-telemetry guard;
 *  - **re-solve trigger (the ENTER side, anti-thrash I1 + I5)** — debounce + Schmitt hysteresis. The
 *    COMMIT side (dwell I2 / cooldown I4 / margin I3) is the sibling [Hysteresis] (pinned by
 *    [AntiThrashInvariantTest]); a composition test here proves the two seams interlock;
 *  - **race orchestration** — enumerate transport×resolver×relay + the measured-winner pick (fastest,
 *    unreachable-dropped, all-dead → null, deterministic tiebreak);
 *  - **binding selection** — pick optimal + the link-tuned cwnd (asked of an injected YeAH brain, never
 *    fabricated) / CAKE params + the conversion onto the sibling cache's [LockedBinding]. The brain is
 *    INJECTED (K2 — the Rust Beast is the sole live brain; the Kotlin canonicals are retired). Tests
 *    inject [STUB_BRAIN], a deterministic stand-in (no `.so` needed) — the Solver is pure orchestration,
 *    it owns no congestion math.
 *
 * All metal: no Android, no clock, no RNG, no socket (the live race + the brain are injected).
 */
class SolverTest {

    /**
     * A deterministic stub YeAH brain for the binding-tuning tests (K2). The Solver's `tuneBrain` is now
     * REQUIRED (no Kotlin default — the Rust Beast is the sole live brain); this stub stands in for the
     * Beast under pure JUnit, so the Solver's orchestration (ask-the-brain → fold the cwnd into the
     * binding) is exercised without a `.so`. Returns a window that grows with RTT up to a cap, floored at
     * `BeastTunables.MIN_WINDOW` — a sane, deterministic shape (NOT the real congestion math — the real
     * math lives in the Rust Beast, pinned by its own `beast/tests`).
     */
    private val STUB_BRAIN: (rttMs: Double, warmupSamples: Int) -> Int = { rttMs, _ ->
        // Deterministic: a low-RTT link gets a larger window, a high-RTT link a smaller one, clamped to the
        // Beast's [MIN_WINDOW..MAX_WINDOW] range (the documented algorithm bounds, `beast/yeah.rs:28-29`).
        val raw = (BeastTunables.MAX_WINDOW - (rttMs / 10.0).toInt()).coerceAtLeast(BeastTunables.MIN_WINDOW)
        raw.coerceAtMost(BeastTunables.MAX_WINDOW)
    }

    // A clean, healthy snapshot template; copy() to perturb a single dimension per test.
    private fun healthy() = SolverInput(
        sojournP95Ms = 0L,
        blueProb = 0.0,
        bestUpstreamScore = 10.0,   // below scoreHealthy → no collapse
        yeahCompeting = false,
        failovers = 0,
        captiveSignature = false,
    )

    // ====================================================================================
    // 1 · OBSTRUCTION DETECT (the weighted blend)
    // ====================================================================================

    @Test
    fun `a healthy snapshot scores zero and attributes no signal`() {
        val v = Solver.detectObstruction(healthy())
        assertEquals(0.0, v.score, 1e-9)
        assertEquals(ObstructionSignal.NONE, v.dominantSignal)
    }

    @Test
    fun `a captive signature is a HARD full obstruction regardless of healthy queues`() {
        val v = Solver.detectObstruction(healthy().copy(captiveSignature = true))
        assertEquals(1.0, v.score, 1e-9)
        assertEquals(ObstructionSignal.CAPTIVE, v.dominantSignal)
    }

    @Test
    fun `high sojourn drives the obstruction and is the dominant signal`() {
        // sojourn 100ms vs 5ms target → sojournNorm 1.0 → weighted by wSojourn(0.35) = the lone contributor.
        val v = Solver.detectObstruction(healthy().copy(sojournP95Ms = 100L))
        assertEquals(0.35, v.score, 1e-9)
        assertEquals(ObstructionSignal.SOJOURN, v.dominantSignal)
    }

    @Test
    fun `BLUE probability contributes and dominates when it is the only signal`() {
        // blueProb at the ceil (0.25) → blueNorm 1.0 → weighted by the sibling BLUE_WEIGHT(0.25).
        val v = Solver.detectObstruction(healthy().copy(blueProb = 0.25))
        assertEquals(ObstructionScore.BLUE_WEIGHT, v.score, 1e-9)
        assertEquals(ObstructionSignal.BLUE, v.dominantSignal)
    }

    @Test
    fun `a null best-upstream score (no governor map yet) adds NO false obstruction`() {
        // Stage-B not landed → bestUpstreamScore null → score-collapse contributes 0, not a phantom spike.
        val v = Solver.detectObstruction(healthy().copy(bestUpstreamScore = null))
        assertEquals(0.0, v.score, 1e-9)
        assertEquals(ObstructionSignal.NONE, v.dominantSignal)
    }

    @Test
    fun `a collapsed upstream score registers as score-collapse`() {
        // score 200 (== scoreCollapsed) → scoreNorm 1.0 → weighted by wScore(0.25).
        val v = Solver.detectObstruction(healthy().copy(bestUpstreamScore = 200.0))
        assertEquals(0.25, v.score, 1e-9)
        assertEquals(ObstructionSignal.SCORE_COLLAPSE, v.dominantSignal)
    }

    @Test
    fun `competing alone (no failovers) is a moderate, sub-trigger lift`() {
        val v = Solver.detectObstruction(healthy().copy(yeahCompeting = true))
        // the sibling COMPETING_LIFT with no queue/loss term — below enter(0.70): early-warning, not a trigger.
        assertEquals(ObstructionScore.COMPETING_LIFT, v.score, 1e-9)
        assertEquals(ObstructionSignal.COMPETING, v.dominantSignal)
    }

    @Test
    fun `a failover (no explicit competing flag) still lifts via the competing axis`() {
        val v = Solver.detectObstruction(healthy().copy(failovers = 2))
        assertEquals(ObstructionScore.COMPETING_LIFT, v.score, 1e-9)
        assertEquals(ObstructionSignal.COMPETING, v.dominantSignal)
    }

    @Test
    fun `combined signals saturate the obstruction past the enter threshold`() {
        val v = Solver.detectObstruction(
            healthy().copy(
                sojournP95Ms = 100L,        // 1.0 * wSojourn(0.35)
                blueProb = 0.25,            // 1.0 * BLUE_WEIGHT(0.25)
                bestUpstreamScore = 200.0,  // 1.0 * wScore(0.25)
                yeahCompeting = true,       // + COMPETING_LIFT
            )
        )
        val expected = 0.35 + ObstructionScore.BLUE_WEIGHT + 0.25 + ObstructionScore.COMPETING_LIFT
        assertEquals(expected, v.score, 1e-9)
        assertTrue("combined signals cross enter(0.70)", v.score >= 0.70)
    }

    // ====================================================================================
    // 2 · RE-SOLVE TRIGGER (ENTER side) — anti-thrash I5 (debounce) + I1 (hysteresis Schmitt)
    // ====================================================================================

    private fun verdict(score: Double) = ObstructionVerdict(score = score, dominantSignal = ObstructionSignal.SOJOURN)

    @Test
    fun `I5 debounce - a single over-threshold spike never triggers`() {
        val d = Solver.shouldTrigger(verdict(0.9), TriggerState())
        assertFalse("one tick over enter must NOT trigger (debounce)", d.trigger)
        assertEquals(1, d.next.confirmRun)
        assertFalse(d.next.armed)
    }

    @Test
    fun `I5 debounce - triggers only after confirmSamples consecutive over-threshold ticks`() {
        var st = TriggerState() // confirmSamples = 3
        var d = Solver.shouldTrigger(verdict(0.9), st); assertFalse(d.trigger); st = d.next // run 1
        d = Solver.shouldTrigger(verdict(0.9), st); assertFalse(d.trigger); st = d.next       // run 2
        d = Solver.shouldTrigger(verdict(0.9), st)                                            // run 3 → fire
        assertTrue("3rd consecutive over-enter tick fires the trigger", d.trigger)
        assertTrue("a fired trigger arms the latch", d.next.armed)
    }

    @Test
    fun `I1 hysteresis - once armed it does NOT re-fire while the signal stays high`() {
        var st = TriggerState(armed = true, confirmRun = 3) // already fired
        repeat(5) {
            val d = Solver.shouldTrigger(verdict(0.95), st)
            assertFalse("armed + still high must NOT re-trigger (one per crossing)", d.trigger)
            st = d.next
        }
    }

    @Test
    fun `I1 hysteresis - a dead-band sawtooth never triggers`() {
        var st = TriggerState(armed = true, confirmRun = 3) // dead-band is (0.40, 0.70)
        for (s in listOf(0.50, 0.65, 0.45, 0.60, 0.55, 0.68)) {
            val d = Solver.shouldTrigger(verdict(s), st)
            assertFalse("dead-band signal ($s) must never trigger", d.trigger)
            st = d.next
        }
    }

    @Test
    fun `I1 hysteresis - disarms only below the EXIT band, then can re-arm and re-fire`() {
        var st = TriggerState(armed = true, confirmRun = 9)
        // Drop below exit (0.40) → fully cleared + disarmed + confirm reset.
        var d = Solver.shouldTrigger(verdict(0.30), st)
        assertFalse(d.trigger)
        assertFalse("below exit disarms", d.next.armed)
        assertEquals(0, d.next.confirmRun)
        st = d.next
        // A fresh high episode must re-fire after a fresh debounce (a new crossing).
        d = Solver.shouldTrigger(verdict(0.9), st); st = d.next; assertFalse(d.trigger)
        d = Solver.shouldTrigger(verdict(0.9), st); st = d.next; assertFalse(d.trigger)
        d = Solver.shouldTrigger(verdict(0.9), st)
        assertTrue("after disarm a new sustained obstruction re-fires", d.trigger)
    }

    @Test
    fun `dead-band entry from below does not trigger and resets the confirm run`() {
        val d = Solver.shouldTrigger(verdict(0.55), TriggerState(armed = false, confirmRun = 0))
        assertFalse(d.trigger)
        assertFalse(d.next.armed)
        assertEquals(0, d.next.confirmRun)
    }

    @Test
    fun `detectObstruction feeds shouldTrigger - a sustained obstruction fires exactly once per crossing`() {
        // The owned ENTER path end-to-end: detectObstruction → shouldTrigger. A saturated, sustained
        // obstruction confirms after confirmSamples and then latches (one trigger per crossing).
        val obstructed = healthy().copy(sojournP95Ms = 200L, blueProb = 0.25, bestUpstreamScore = 200.0)
        var trig = TriggerState()
        var fires = 0
        for (i in 0 until 20) {
            val v = Solver.detectObstruction(obstructed)
            assertTrue("the obstruction must be over the enter rail", v.score >= 0.70)
            val d = Solver.shouldTrigger(v, trig)
            trig = d.next
            if (d.trigger) fires++
        }
        assertEquals("a sustained high obstruction fires ONCE (debounce + armed latch), not per-tick", 1, fires)
    }

    @Test
    fun `detectObstruction feeds shouldTrigger - a healthy snapshot never fires`() {
        var trig = TriggerState()
        repeat(20) {
            val v = Solver.detectObstruction(healthy())
            val d = Solver.shouldTrigger(v, trig)
            assertFalse("a healthy verdict must never trigger a solve", d.trigger)
            trig = d.next
        }
    }

    // ====================================================================================
    // 3 · RACE ORCHESTRATION — enumerate + pick
    // ====================================================================================

    private val dnscryptOnly = RaceResolver("dc1", listOf(TransportKind.DNSCRYPT), noLog = true, dnssec = true)
    private val dohResolver = RaceResolver("doh1", listOf(TransportKind.DOH, TransportKind.DOH3), noLog = true)

    @Test
    fun `DNSCrypt is relay-capable, plain DoH transports are not`() {
        assertTrue(Solver.isRelayCapable(TransportKind.DNSCRYPT))
        assertFalse(Solver.isRelayCapable(TransportKind.DOH))
        assertFalse(Solver.isRelayCapable(TransportKind.DOH3))
        assertFalse(Solver.isRelayCapable(TransportKind.DOQ))
    }

    @Test
    fun `enumerate produces the transport x resolver x relay cross-product`() {
        val relays = listOf<RaceRelay?>(null, RaceRelay("r1"))
        val race = Solver.enumerateRace(listOf(dnscryptOnly), relays)
        assertEquals(2, race.size) // DNSCRYPT relay-capable → direct(null) + r1
        assertTrue(race.any { it.relay == null })
        assertTrue(race.any { it.relay?.id == "r1" })
    }

    @Test
    fun `a non-relay-capable transport only pairs with the direct (null) relay`() {
        val relays = listOf<RaceRelay?>(null, RaceRelay("r1"))
        val race = Solver.enumerateRace(listOf(dohResolver), relays)
        assertEquals(2, race.size) // DOH + DOH3, each only relay-less
        assertTrue("no relay-capable transport here → never a relayed candidate", race.all { it.relay == null })
        assertEquals(setOf(TransportKind.DOH, TransportKind.DOH3), race.map { it.transport }.toSet())
    }

    @Test
    fun `empty relay axis is treated as direct-only`() {
        val race = Solver.enumerateRace(listOf(dnscryptOnly), emptyList())
        assertEquals(1, race.size)
        assertNull(race[0].relay)
    }

    @Test
    fun `enumerate is empty when there are no resolvers (fail-safe)`() {
        assertTrue(Solver.enumerateRace(emptyList(), listOf<RaceRelay?>(null)).isEmpty())
    }

    @Test
    fun `enumeration is deterministic and stable across runs`() {
        val relays = listOf<RaceRelay?>(null, RaceRelay("rZ"), RaceRelay("rA"))
        val a = Solver.enumerateRace(listOf(dohResolver, dnscryptOnly), relays).map { it.stableKey }
        val b = Solver.enumerateRace(listOf(dnscryptOnly, dohResolver), relays).map { it.stableKey }
        assertEquals("same axes (order-agnostic) → identical deterministic enumeration", a, b)
    }

    @Test
    fun `pick returns the fastest reachable candidate`() {
        val race = Solver.enumerateRace(listOf(dnscryptOnly, dohResolver), listOf<RaceRelay?>(null))
        val measured = race.map { c ->
            val rtt = if (c.transport == TransportKind.DOH3) 5 else 80 // make DoH3 clearly fastest
            RaceMeasurement(c, rtt)
        }
        val winner = Solver.pickRaceWinner(measured)
        assertNotNull(winner)
        assertEquals(TransportKind.DOH3, winner!!.candidate.transport)
        assertEquals(5, winner.rttMs)
    }

    @Test
    fun `pick drops unreachable candidates`() {
        val race = Solver.enumerateRace(listOf(dohResolver), listOf<RaceRelay?>(null))
        val measured = race.map { c ->
            val rtt = if (c.transport == TransportKind.DOH) -1 else 40 // DOH dead, DOH3 @ 40ms
            RaceMeasurement(c, rtt)
        }
        val winner = Solver.pickRaceWinner(measured)
        assertNotNull(winner)
        assertEquals(TransportKind.DOH3, winner!!.candidate.transport)
        assertTrue(winner.reachable)
    }

    @Test
    fun `pick returns null when every candidate is unreachable (keep-current fail-safe)`() {
        val race = Solver.enumerateRace(listOf(dnscryptOnly, dohResolver), listOf<RaceRelay?>(null))
        val measured = race.map { RaceMeasurement(it, -1) } // all dead
        assertNull("all-dead race must KEEP the current binding (null)", Solver.pickRaceWinner(measured))
    }

    @Test
    fun `pick is deterministic on an exact RTT tie (stable key tiebreak)`() {
        val r = RaceResolver("dcX", listOf(TransportKind.DNSCRYPT), noLog = true, dnssec = true)
        val race = Solver.enumerateRace(listOf(r), listOf<RaceRelay?>(RaceRelay("rB"), RaceRelay("rA")))
        val measured = race.map { RaceMeasurement(it, 30) } // identical RTT + props → exact tie
        val w1 = Solver.pickRaceWinner(measured)
        val w2 = Solver.pickRaceWinner(measured.reversed())
        assertNotNull(w1)
        assertEquals(
            "exact tie resolves to the SAME stable winner regardless of input order",
            w1!!.candidate.stableKey, w2!!.candidate.stableKey
        )
    }

    @Test
    fun `race score never lets props leapfrog a much faster binding (RTT dominates)`() {
        val fastNoProps = RaceMeasurement(
            RaceCandidate(TransportKind.DOH, RaceResolver("fast", listOf(TransportKind.DOH)), null), 10
        )
        val slowAllProps = RaceMeasurement(
            RaceCandidate(
                TransportKind.DNSCRYPT,
                RaceResolver("slow", listOf(TransportKind.DNSCRYPT), noLog = true, dnssec = true), null
            ), 200
        )
        assertTrue(
            "a 10ms no-props binding must outscore a 200ms full-props binding (RTT dominates)",
            Solver.raceScore(fastNoProps) > Solver.raceScore(slowAllProps)
        )
    }

    @Test
    fun `race score - props break a near-tie in favour of no-log + DNSSEC`() {
        val plain = RaceMeasurement(
            RaceCandidate(TransportKind.DOH, RaceResolver("plain", listOf(TransportKind.DOH)), null), 20
        )
        val trusted = RaceMeasurement(
            RaceCandidate(
                TransportKind.DOH,
                RaceResolver("trust", listOf(TransportKind.DOH), noLog = true, dnssec = true), null
            ), 20
        )
        assertTrue(
            "same RTT → the no-log+DNSSEC binding wins on the bounded props bonus",
            Solver.raceScore(trusted) > Solver.raceScore(plain)
        )
    }

    // ====================================================================================
    // 4 · BINDING SELECTION — pick optimal + tuned cwnd / CAKE params
    // ====================================================================================

    @Test
    fun `solveBinding races, picks, and returns a link-tuned binding`() {
        val resolvers = listOf(dnscryptOnly, dohResolver)
        val relays = listOf<RaceRelay?>(null, RaceRelay("r1"))
        val binding = Solver.solveBinding(resolvers, relays, tuneBrain = STUB_BRAIN) { c ->
            val rtt = if (c.transport == TransportKind.DNSCRYPT && c.relay == null) 8 else 90
            RaceMeasurement(c, rtt)
        }
        assertNotNull(binding)
        assertEquals(TransportKind.DNSCRYPT, binding!!.transport)
        assertEquals("dc1", binding.resolverId)
        assertNull(binding.relayId)
        assertEquals(8, binding.measuredRttMs)
        assertEquals(TortaProfile.BASELINE, binding.cakeProfile)
        assertEquals("the incumbent-to-beat score is lower-better = the measured RTT", 8.0, binding.score, 1e-9)
    }

    @Test
    fun `solveBinding returns null when all candidates are unreachable`() {
        val binding = Solver.solveBinding(
            listOf(dnscryptOnly), listOf<RaceRelay?>(null),
            tuneBrain = STUB_BRAIN,
        ) {
            RaceMeasurement(it, -1)
        }
        assertNull("nothing reachable → KEEP current binding", binding)
    }

    @Test
    fun `solveBinding returns null on an empty pool`() {
        assertNull(
            Solver.solveBinding(emptyList(), listOf<RaceRelay?>(null), tuneBrain = STUB_BRAIN) {
                RaceMeasurement(it, 10)
            }
        )
    }

    @Test
    fun `tuned cwnd is the injected brain's window for the won link (REUSE not invent)`() {
        val winner = RaceMeasurement(RaceCandidate(TransportKind.DNSCRYPT, dnscryptOnly, null), 25)
        val binding = Solver.tuneBinding(winner, tuneBrain = STUB_BRAIN)
        // The Solver asks the injected brain (the stub here; the Rust Beast on the live path) — it does not
        // fabricate a window. The stub is deterministic, so the tuned cwnd is the stub's output for rtt=25.
        val expected = STUB_BRAIN(25.0, SolverThresholds().tuneWarmupSamples)
        assertEquals(
            "tuned cwnd is the injected brain's window, not a fabricated number",
            expected, binding.tunedCwnd
        )
        assertTrue(
            "a sane window within the Beast's [MIN_WINDOW..MAX_WINDOW] bounds",
            binding.tunedCwnd in BeastTunables.MIN_WINDOW..BeastTunables.MAX_WINDOW
        )
    }

    @Test
    fun `CAKE CoDel interval scales with the link RTT (floor 20ms)`() {
        val fast = Solver.tuneBinding(
            RaceMeasurement(RaceCandidate(TransportKind.DNSCRYPT, dnscryptOnly, null), 5),
            tuneBrain = STUB_BRAIN,
        )
        val slow = Solver.tuneBinding(
            RaceMeasurement(RaceCandidate(TransportKind.DNSCRYPT, dnscryptOnly, null), 120),
            tuneBrain = STUB_BRAIN,
        )
        assertEquals("a 5ms link floors the interval at 20ms", 20L, fast.tunedCodelIntervalMs)
        assertEquals("a 120ms link sets interval = baseRtt", 120L, slow.tunedCodelIntervalMs)
        assertEquals("CoDel target is the link-appropriate default", 5L, slow.tunedCodelTargetMs)
    }

    @Test
    fun `a preferred transport nudges a near-tie but never beats a faster link`() {
        val t = SolverThresholds(preferredTransport = TransportKind.DOH3)
        val doh3Same = RaceMeasurement(
            RaceCandidate(TransportKind.DOH3, RaceResolver("a", listOf(TransportKind.DOH3)), null), 20
        )
        val dohSame = RaceMeasurement(
            RaceCandidate(TransportKind.DOH, RaceResolver("b", listOf(TransportKind.DOH)), null), 20
        )
        assertTrue(
            "same RTT → preferred DoH3 wins the nudge",
            Solver.raceScore(doh3Same, t) > Solver.raceScore(dohSame, t)
        )

        val doh3Slow = RaceMeasurement(
            RaceCandidate(TransportKind.DOH3, RaceResolver("a", listOf(TransportKind.DOH3)), null), 150
        )
        val dohFast = RaceMeasurement(
            RaceCandidate(TransportKind.DOH, RaceResolver("b", listOf(TransportKind.DOH)), null), 10
        )
        assertTrue(
            "preference must NOT beat a far faster link",
            Solver.raceScore(dohFast, t) > Solver.raceScore(doh3Slow, t)
        )
    }

    // ====================================================================================
    // 4b · BINDING → sibling cache LockedBinding conversion (REUSE the cache type)
    // ====================================================================================

    @Test
    fun `toLockedBinding maps a solved binding onto the sibling cache record (lower-better score)`() {
        val solved = Solver.tuneBinding(
            RaceMeasurement(RaceCandidate(TransportKind.DNSCRYPT, dnscryptOnly, null), 18),
            tuneBrain = STUB_BRAIN,
        )
        val locked: LockedBinding = Solver.toLockedBinding(solved, nowMs = 5_000L)
        assertEquals(TransportKind.DNSCRYPT, locked.transport)
        assertEquals("dc1", locked.resolverId)
        assertNull(locked.relayId)
        assertEquals(solved.tunedCwnd, locked.tunedCwnd)
        assertEquals(solved.tunedCodelTargetMs, locked.tunedCodelTargetMs)
        assertEquals("cache score is lower-better = the measured RTT", 18.0, locked.score, 1e-9)
        assertEquals(5_000L, locked.lockedAtMs)
        assertEquals(5_000L, locked.lastHealthyAtMs)
    }

    @Test
    fun `a solved binding round-trips into the sibling BindingCache as an instant-reuse hit`() {
        val solved = Solver.tuneBinding(
            RaceMeasurement(RaceCandidate(TransportKind.DNSCRYPT, dnscryptOnly, null), 12),
            tuneBrain = STUB_BRAIN,
        )
        val cache = BindingCache()
        val fp = NetworkFingerprint.of(NetworkFingerprint.Companion.LinkType.WIFI, "home", "192.168.1.1")
        cache.commit(fp, Solver.toLockedBinding(solved, nowMs = 1_000L))
        val hit = cache.lookup(fp, nowMs = 2_000L)
        assertTrue("a freshly-solved binding is an instant-reuse cache hit", hit is CacheResult.Hit)
        assertEquals("dc1", (hit as CacheResult.Hit).binding.resolverId)
    }
}
