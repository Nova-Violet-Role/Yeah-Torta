/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * P10 — hermetic unit test of the per-candidate RTT ranking ([RotationPing.rankByRtt] /
 * [RotationPing.fastest] / [RotationPing.RttSample.reachable]).
 *
 * This module has NO Robolectric / mockk — plain `junit:junit:4.13.2` only (libumdnscrypt/build.gradle:179),
 * so the SOCKET-touching methods ([RotationPing.rttFor]/[rankCandidates]) — which delegate to the live
 * `RelaysPingInteractor`/`ServersPingInteractor` ping seam — are NOT exercised here (they need a device
 * and a real network; the emu-soak proves them). What a JVM test CAN prove, and the load-bearing
 * selection invariant, is the PURE ranking: unreachable exclusion, fastest-first order, deterministic
 * tie-break, and the empty-on-all-dead fail-safe that makes RotationManager keep the current set.
 *
 * Hermetic: only the data classes + the `companion` ranking are touched; no Android type, no coroutine,
 * no socket. Runs on the plain `:libumdnscrypt:test*` gradle task (the VM build, JUnit on metal).
 */
class RotationPingTest {

    private fun cand(id: String) = RotationPing.Candidate(id = id, sdns = "sdns://$id")

    private fun sample(id: String, rtt: Int) = RotationPing.RttSample(cand(id), rtt)

    // --- reachable flag (NO_CONNECTION == -1 boundary) -------------------------------------------

    @Test
    fun reachable_true_for_zero_and_positive_rtt() {
        assertTrue("0 ms is reachable", sample("a", 0).reachable)
        assertTrue("42 ms is reachable", sample("a", 42).reachable)
    }

    @Test
    fun reachable_false_for_no_connection() {
        // SocketInternetChecker.NO_CONNECTION == -1 (SocketInternetChecker.kt:138)
        assertFalse("-1 (NO_CONNECTION) is unreachable", sample("a", -1).reachable)
    }

    // --- rankByRtt: order, exclusion, tie-break --------------------------------------------------

    @Test
    fun rankByRtt_orders_fastest_first() {
        val ranked = RotationPing.rankByRtt(
            listOf(sample("slow", 200), sample("fast", 10), sample("mid", 90))
        )
        assertEquals(listOf("fast", "mid", "slow"), ranked.map { it.candidate.id })
    }

    @Test
    fun rankByRtt_excludes_unreachable_candidates() {
        val ranked = RotationPing.rankByRtt(
            listOf(sample("dead", -1), sample("alive", 50), sample("dead2", -1))
        )
        assertEquals(listOf("alive"), ranked.map { it.candidate.id })
    }

    @Test
    fun rankByRtt_breaks_ties_deterministically_by_id() {
        // Same latency → stable order by id, so equal-RTT candidates never cause needless pool churn.
        val ranked = RotationPing.rankByRtt(
            listOf(sample("charlie", 30), sample("alpha", 30), sample("bravo", 30))
        )
        assertEquals(listOf("alpha", "bravo", "charlie"), ranked.map { it.candidate.id })
    }

    @Test
    fun rankByRtt_all_dead_yields_empty_failsafe() {
        // The fail-safe: every candidate unreachable ⇒ empty ⇒ RotationManager keeps the current set,
        // it does NOT swap onto an all-dead pool.
        val ranked = RotationPing.rankByRtt(
            listOf(sample("d1", -1), sample("d2", -1), sample("d3", -1))
        )
        assertTrue("all-dead set ranks to empty", ranked.isEmpty())
    }

    @Test
    fun rankByRtt_empty_input_yields_empty() {
        assertTrue(RotationPing.rankByRtt(emptyList()).isEmpty())
    }

    // --- fastest convenience ---------------------------------------------------------------------

    @Test
    fun fastest_returns_lowest_reachable_rtt() {
        val best = RotationPing.fastest(
            listOf(sample("slow", 300), sample("best", 5), sample("dead", -1))
        )
        assertEquals("best", best?.candidate?.id)
        assertEquals(5, best?.rttMs)
    }

    @Test
    fun fastest_is_null_when_no_candidate_reachable() {
        val best = RotationPing.fastest(listOf(sample("d1", -1), sample("d2", -1)))
        assertNull("no reachable candidate ⇒ null ⇒ keep current set", best)
    }

    @Test
    fun fastest_skips_unreachable_even_when_it_sorts_first_by_id() {
        // 'aaa' is unreachable but id-sorts before 'zzz'; fastest must still pick the reachable one.
        val best = RotationPing.fastest(listOf(sample("aaa", -1), sample("zzz", 77)))
        assertEquals("zzz", best?.candidate?.id)
    }

    // --- #22 s5B chooseRoutableRelays: the relay FAIL-OPEN decision ------------------------------

    @Test
    fun chooseRoutableRelays_keeps_blind_full_list_when_zero_reachable_failopen() {
        // The INVERSE of rankByRtt's fail-safe empty: a dead probe plane must never thin the
        // anonymization layer — 0 reachable ⇒ the ORIGINAL input list rides on, untouched.
        val input = listOf(cand("r1"), cand("r2"), cand("r3"))
        val chosen = RotationPing.chooseRoutableRelays(input, ranked = emptyList())
        assertEquals(input, chosen)
    }

    @Test
    fun chooseRoutableRelays_returns_reachable_survivors_fastest_first() {
        val input = listOf(cand("slow"), cand("fast"), cand("dead"))
        val ranked = RotationPing.rankByRtt(
            listOf(sample("slow", 200), sample("fast", 10), sample("dead", -1))
        )
        val chosen = RotationPing.chooseRoutableRelays(input, ranked)
        assertEquals(listOf("fast", "slow"), chosen.map { it.id })
    }

    @Test
    fun chooseRoutableRelays_empty_input_stays_empty() {
        assertEquals(emptyList<RotationPing.Candidate>(),
            RotationPing.chooseRoutableRelays(emptyList(), emptyList()))
    }
}
