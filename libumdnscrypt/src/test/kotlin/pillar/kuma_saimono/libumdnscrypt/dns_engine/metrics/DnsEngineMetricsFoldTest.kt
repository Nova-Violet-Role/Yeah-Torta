/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.metrics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * MONSTER §6 — the dashboard DATA fold (NO UI; the UI is Design-Finale). Plain JUnit4 on metal — the
 * [DnsEngineMetrics] DTO family is pure data (zero Android deps), so it exercises directly without
 * Robolectric/Mockito (the [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationManagerGateTest] precedent).
 *
 * The load-bearing law under test is **LEGACY byte-identical**: a governor/solver-absent snapshot (the
 * default-constructed metric, the resolver-absent / GOVERN-OFF path) MUST surface NOTHING new — empty
 * per-upstream list, a dormant STEADY Solver, zero §6 globals. Every new field default-constructs, so the
 * single-upstream snapshot the dashboard renders today is unchanged when the enrichment is off.
 */
class DnsEngineMetricsFoldTest {

    // ── LEGACY byte-identical: the default snapshot adds nothing (the GOVERN/SOLVER-OFF guarantee). ──

    @Test
    fun `default snapshot has an empty per-upstream list (governor absent = today)`() {
        val m = DnsEngineMetrics()
        assertTrue(
            "A governor-absent snapshot MUST carry an empty per-upstream list (no map built when GOVERN OFF)",
            m.perUpstream.isEmpty()
        )
    }

    @Test
    fun `default snapshot zeroes every section6 global`() {
        val m = DnsEngineMetrics()
        assertEquals(0.0, m.sojournP50Ms, 0.0)
        assertEquals(0.0, m.sojournP95Ms, 0.0)
        assertEquals(0.0, m.blueProb, 0.0)
        assertEquals(0, m.cobaltDropped)
        assertEquals(0, m.drrSparseServed)
        assertEquals(0.0, m.realQps, 0.0)
        assertEquals(0, m.inflightTotal)
        assertEquals(0, m.cwndTotal)
        assertEquals(0.0, m.pacingRateQps, 0.0)
        assertEquals(0.0, m.governedQps, 0.0)
        assertEquals(0.0, m.wouldHaveSentQps, 0.0)
    }

    @Test
    fun `default snapshot is not on the probe fallback flag (engine running normally)`() {
        // probeFallbackActive is published ONLY when resolver stats are absent; the bare default is "running".
        assertFalse(DnsEngineMetrics().probeFallbackActive)
    }

    @Test
    fun `default Solver snapshot is dormant STEADY with no binding`() {
        val s = DnsEngineMetrics().solver
        assertEquals(SolverPhase.STEADY, s.phase)
        assertFalse("default enabled flag is off until the manager publishes the live master state", s.enabled)
        assertEquals(0, s.solveCount)
        assertEquals(0, s.cacheHits)
        assertEquals(0.0, s.obstructionScore, 0.0)
        assertNull("a dormant Solver holds no binding", s.lockedBinding)
    }

    @Test
    fun `the original single-upstream fields are untouched by the fold (legacy shape intact)`() {
        // Spot-pin the pre-MONSTER contract the dashboard already renders — the fold is purely additive.
        val m = DnsEngineMetrics()
        assertEquals("INIT", m.mode)
        assertEquals(1, m.congestionWindow)
        assertEquals(16, m.windowMax)
        assertEquals(2000, m.adaptiveTimeoutMs)
        assertTrue(m.slowStartActive)
        assertEquals("—", m.preferredEndpoint)
        assertEquals(0, m.successRatePct)      // probesTotal==0 → guarded 0, not a divide-by-zero
        assertEquals(0, m.udpSuccessRatePct)
    }

    // ── The additive DTOs behave (the §6 enrichment is real data, not a stub). ──

    @Test
    fun `a folded per-upstream metric carries the governor view and a guarded success rate`() {
        val u = UpstreamMetric(
            name = "cloudflare", protocol = "DoH", cwnd = 8, inflight = 2,
            baseRttMs = 12.0, jitterMs = 1.5, p95RttMs = 30.0, mode = "FREE",
            sent = 100, ok = 97, fail = 1, timeout = 2, qps = 40.0, score = 0.21,
            governedCwnd = 6, pacingRateQps = 64.0,
        )
        val m = DnsEngineMetrics(perUpstream = listOf(u))
        assertEquals(1, m.perUpstream.size)
        assertEquals("cloudflare", m.perUpstream[0].name)
        assertEquals(97, m.perUpstream[0].successRatePct)             // 97/100
        assertEquals(6, m.perUpstream[0].governedCwnd)               // SHADOW would-be cap surfaced
    }

    @Test
    fun `an upstream metric with zero sends guards its success rate`() {
        assertEquals(0, UpstreamMetric(sent = 0, ok = 0).successRatePct)
    }

    @Test
    fun `a LOCKED Solver snapshot surfaces a shadow binding without claiming a live swap`() {
        val binding = LockedBindingView(
            transport = "DoH3", resolverId = "quad9", relayId = null,
            tunedCwnd = 10, tunedCodelTargetMs = 5L, score = 0.18, ageMs = 1200L,
        )
        val s = SolverSnapshot(
            phase = SolverPhase.LOCKED, enabled = true, shadow = true,
            solveCount = 1, lastSwitchReason = "p95-collapse", cacheHits = 0,
            cacheSize = 1, obstructionScore = 0.0, networkFingerprint = "fp-abc",
            lockedBinding = binding,
        )
        assertEquals(SolverPhase.LOCKED, s.phase)
        assertTrue("the live commit is DEFERRED — a LOCKED solver must report shadow=true until Stage-C", s.shadow)
        assertTrue(s.enabled)
        assertSame(binding, s.lockedBinding)
        assertEquals("DoH3", s.lockedBinding!!.transport)
        assertEquals("p95-collapse", s.lastSwitchReason)
    }

    @Test
    fun `a fingerprint cache-hit Solver snapshot reuses without a new solve`() {
        // I6 stickiness rendered: re-entering a known network = a cache hit, no new solveCount tick.
        val s = SolverSnapshot(
            phase = SolverPhase.STEADY, enabled = true, shadow = true,
            solveCount = 0, cacheHits = 1, cacheSize = 1, networkFingerprint = "fp-home",
        )
        assertEquals(0, s.solveCount)
        assertEquals(1, s.cacheHits)
        assertEquals(SolverPhase.STEADY, s.phase)
    }

    @Test
    fun `the shadow governed-vs-wouldhavesent globals carry the would-be pacing divergence`() {
        // While shadow/live-deferred the engine sends unthrottled; governedQps records the would-be cap.
        // Their inequality is the proof the governor WOULD have shaped (no real throttle yet, Stage-C deferred).
        val m = DnsEngineMetrics(governedQps = 32.0, wouldHaveSentQps = 50.0, perUpstream = emptyList())
        assertTrue("governed (would-be cap) below the unthrottled send = shadow shaping evidence",
            m.governedQps < m.wouldHaveSentQps)
    }
}
