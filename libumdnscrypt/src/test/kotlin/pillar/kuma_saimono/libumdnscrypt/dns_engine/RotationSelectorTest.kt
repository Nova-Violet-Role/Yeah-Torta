/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

/*
    This file is part of Yeah! Tortä. GPL-3.0-or-later. Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationSelector.ResolverCandidate
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationSelector.RotationPolicy

/**
 * Pins [RotationSelector]: the pure P10 rotation core. Trust-filter drops low-trust; operator-diversity
 * holds across a window; RTT weights the pick; an empty/bad pool fails to `null` (the keep-current-set
 * fail-safe). All metal — no Android, no clock, no RNG.
 */
class RotationSelectorTest {

    // A fully-trusted, fast, DNSCrypt candidate template; copy() to perturb a single dimension per test.
    // ipv4/ipv6 default (true,true) = Unknown family — never family-hidden, matching a hostname/undecodable
    // stamp; a test perturbs them to (true,false)=v4-literal or (false,true)=v6-literal for the family gate.
    private fun good(
        id: String = "alpha",
        family: String = "alpha-op",
        rtt: Int = 20,
        dnssec: Boolean = true,
        noLog: Boolean = true,
        noFilter: Boolean = false,
        dnsCrypt: Boolean = true,
        ipv4: Boolean = true,
        ipv6: Boolean = true,
    ) = ResolverCandidate(
        id = id,
        operatorFamily = family,
        dnssec = dnssec,
        noLog = noLog,
        noFilter = noFilter,
        dnsCrypt = dnsCrypt,
        rttMs = rtt,
        ipv4 = ipv4,
        ipv6 = ipv6,
    )

    // ---- TRUST-FILTER drops bad (resolver stamp props, not blocklist trust) ----

    @Test
    fun `trust-filter drops a logging resolver when no-log required`() {
        val pool = listOf(good(id = "keeper"), good(id = "logger", family = "logger-op", noLog = false))
        val kept = RotationSelector.filterTrusted(pool, RotationPolicy(requireNoLog = true))
        assertEquals(1, kept.size)
        assertEquals("keeper", kept[0].id)
    }

    @Test
    fun `trust-filter keeps a logging resolver when no-log NOT required`() {
        val pool = listOf(good(id = "logger", noLog = false))
        val kept = RotationSelector.filterTrusted(pool, RotationPolicy(requireNoLog = false))
        assertEquals(1, kept.size)
    }

    @Test
    fun `trust-filter drops a non-DNSSEC resolver when DNSSEC required`() {
        val pool = listOf(good(id = "secure"), good(id = "plain", family = "plain-op", dnssec = false))
        val kept = RotationSelector.filterTrusted(pool, RotationPolicy(requireDnssec = true))
        assertEquals(listOf("secure"), kept.map { it.id })
    }

    @Test
    fun `trust-filter drops a non-DNSCrypt resolver by default (only buildable transport)`() {
        val pool = listOf(good(id = "dc"), good(id = "doh", family = "doh-op", dnsCrypt = false))
        val kept = RotationSelector.filterTrusted(pool)
        assertEquals(listOf("dc"), kept.map { it.id })
    }

    // ---- #22 s5A-ext: the PROTOCOL gate (Socio: dnscrypt/doh selectable on the Rotation engine) ----

    @Test
    fun `protocol-gate keeps doh when allowed and can run doh-only`() {
        val pool = listOf(good(id = "dc"), good(id = "doh", family = "doh-op", dnsCrypt = false))
        val both = RotationSelector.filterTrusted(
            pool,
            RotationSelector.RotationPolicy(allowDnsCrypt = true, allowDoh = true, requireNoLog = false),
        )
        assertEquals(listOf("dc", "doh"), both.map { it.id })

        val dohOnly = RotationSelector.filterTrusted(
            pool,
            RotationSelector.RotationPolicy(allowDnsCrypt = false, allowDoh = true, requireNoLog = false),
        )
        assertEquals(listOf("doh"), dohOnly.map { it.id })
    }

    @Test
    fun `protocol-gate empties the pool when neither protocol is allowed (keep-current fail-safe)`() {
        val pool = listOf(good(id = "dc"), good(id = "doh", family = "doh-op", dnsCrypt = false))
        val none = RotationSelector.filterTrusted(
            pool,
            RotationSelector.RotationPolicy(allowDnsCrypt = false, allowDoh = false, requireNoLog = false),
        )
        assertEquals(emptyList<String>(), none.map { it.id })
    }

    @Test
    fun `trust-filter drops an unreachable candidate (rtt -1 = NO_CONNECTION)`() {
        val pool = listOf(good(id = "up"), good(id = "down", family = "down-op", rtt = -1))
        val kept = RotationSelector.filterTrusted(pool)
        assertEquals(listOf("up"), kept.map { it.id })
        assertFalse(pool.first { it.id == "down" }.reachable) // rtt<0 ⇒ reachable defaults false
    }

    @Test
    fun `trust-filter drops a blank-id candidate`() {
        val pool = listOf(good(id = ""), good(id = "real"))
        val kept = RotationSelector.filterTrusted(pool)
        assertEquals(listOf("real"), kept.map { it.id })
    }

    // ---- FAMILY GATE (mirror the manual picker's `family_ok = (allowIpv4 && v4) || (allowIpv6 && v6)`) ----

    @Test
    fun `family-filter keeps ipv4 and unknown, drops ipv6, when only ipv4 allowed`() {
        val pool = listOf(
            good(id = "v4", family = "v4op", ipv4 = true, ipv6 = false),
            good(id = "v6", family = "v6op", ipv4 = false, ipv6 = true),
            good(id = "unknown", family = "unop"), // Unknown = (true,true): matches whichever is allowed
        )
        val kept = RotationSelector.filterTrusted(pool, RotationPolicy(allowIpv4 = true, allowIpv6 = false))
        assertEquals(setOf("v4", "unknown"), kept.map { it.id }.toSet())
    }

    @Test
    fun `family-filter keeps ipv6 and unknown, drops ipv4, when only ipv6 allowed`() {
        val pool = listOf(
            good(id = "v4", family = "v4op", ipv4 = true, ipv6 = false),
            good(id = "v6", family = "v6op", ipv4 = false, ipv6 = true),
            good(id = "unknown", family = "unop"),
        )
        val kept = RotationSelector.filterTrusted(pool, RotationPolicy(allowIpv4 = false, allowIpv6 = true))
        assertEquals(setOf("v6", "unknown"), kept.map { it.id }.toSet())
    }

    @Test
    fun `family-filter keeps every family when both allowed (the default policy)`() {
        val pool = listOf(
            good(id = "v4", family = "v4op", ipv4 = true, ipv6 = false),
            good(id = "v6", family = "v6op", ipv4 = false, ipv6 = true),
            good(id = "unknown", family = "unop"),
        )
        // default RotationPolicy allows BOTH families ⇒ nothing family-dropped (backward-compatible).
        val kept = RotationSelector.filterTrusted(pool)
        assertEquals(setOf("v4", "v6", "unknown"), kept.map { it.id }.toSet())
    }

    @Test
    fun `family-filter empties the pool when neither family is allowed (even Unknown falls out)`() {
        val pool = listOf(
            good(id = "v4", family = "v4op", ipv4 = true, ipv6 = false),
            good(id = "v6", family = "v6op", ipv4 = false, ipv6 = true),
            good(id = "unknown", family = "unop"), // both toggles off ⇒ (false&&x)||(false&&y) = false
        )
        val kept = RotationSelector.filterTrusted(pool, RotationPolicy(allowIpv4 = false, allowIpv6 = false))
        assertTrue(kept.isEmpty())
    }

    @Test
    fun `select returns null when the family gate empties the pool (fail-safe keep-current)`() {
        // The operator disabled IPv6 servers and the only candidate is a v6-only literal ⇒ no survivor ⇒
        // the rotation declines and the caller keeps the current live set (never swap to nothing).
        val pool = listOf(good(id = "v6only", family = "v6op", ipv4 = false, ipv6 = true))
        val pick = RotationSelector.select(
            pool,
            lastOperatorFamily = null,
            policy = RotationPolicy(allowIpv4 = true, allowIpv6 = false),
        )
        assertNull(pick)
    }

    // ---- DIVERSITY holds (per-operator, not per-IP; case-insensitive) ----

    @Test
    fun `diversity excludes the last operator family`() {
        val pool = listOf(
            good(id = "a1", family = "cloudflare"),
            good(id = "a2", family = "cloudflare"), // same operator, different endpoint
            good(id = "b1", family = "quad9"),
        )
        val survivors = RotationSelector.excludeFamily(pool, "cloudflare")
        assertEquals(listOf("b1"), survivors.map { it.id }) // BOTH cloudflare endpoints fall out together
    }

    @Test
    fun `diversity exclusion is case-insensitive and trimmed`() {
        val pool = listOf(good(id = "a", family = "CloudFlare"), good(id = "b", family = "quad9"))
        val survivors = RotationSelector.excludeFamily(pool, "  cloudflare  ")
        assertEquals(listOf("b"), survivors.map { it.id })
    }

    @Test
    fun `null or blank last family excludes nothing (first pick)`() {
        val pool = listOf(good(id = "a", family = "x"), good(id = "b", family = "y"))
        assertEquals(2, RotationSelector.excludeFamily(pool, null).size)
        assertEquals(2, RotationSelector.excludeFamily(pool, "  ").size)
    }

    @Test
    fun `select never returns the last operator family across a rotation window`() {
        val pool = listOf(
            good(id = "cf", family = "cloudflare", rtt = 5),  // fastest — but excluded by diversity
            good(id = "q9", family = "quad9", rtt = 80),
            good(id = "nd", family = "nextdns", rtt = 90),
        )
        // Window N installed cloudflare; window N+1 must NOT re-pick it even though it is the fastest.
        val pick = RotationSelector.select(pool, lastOperatorFamily = "cloudflare")
        assertNotNull(pick)
        assertFalse("rotation re-landed the same operator", pick!!.operatorFamily == "cloudflare")
        assertEquals("q9", pick.id) // the faster of the two DIVERSE survivors
    }

    // ---- RTT weights the pick ----

    @Test
    fun `select picks the lowest-RTT survivor among equal-props candidates`() {
        val pool = listOf(
            good(id = "slow", family = "op-slow", rtt = 200),
            good(id = "fast", family = "op-fast", rtt = 20),
            good(id = "mid", family = "op-mid", rtt = 90),
        )
        val pick = RotationSelector.select(pool, lastOperatorFamily = null)
        assertEquals("fast", pick?.id)
    }

    @Test
    fun `RTT dominates score — props bonus cannot leapfrog a much faster resolver`() {
        // A slow resolver with every prop bonus must still lose to a much faster plainer one.
        val fastPlain = good(id = "fast", family = "f", rtt = 20, dnssec = false, noFilter = false)
        val slowRich = good(id = "slow", family = "s", rtt = 200, dnssec = true, noFilter = true)
        assertTrue(RotationSelector.score(fastPlain) > RotationSelector.score(slowRich))
        assertEquals("fast", RotationSelector.select(listOf(fastPlain, slowRich), null)?.id)
    }

    @Test
    fun `props bonus breaks a near-tie between equal-RTT resolvers (DNSSEC preferred)`() {
        val withDnssec = good(id = "sec", family = "a", rtt = 30, dnssec = true)
        val noDnssec = good(id = "ins", family = "b", rtt = 30, dnssec = false)
        // requireDnssec OFF so both survive the filter; preferDnssec ON so the score tips to the secure one.
        val pick = RotationSelector.select(
            listOf(noDnssec, withDnssec),
            lastOperatorFamily = null,
            policy = RotationPolicy(requireDnssec = false, preferDnssec = true),
        )
        assertEquals("sec", pick?.id)
        assertTrue(RotationSelector.score(withDnssec) > RotationSelector.score(noDnssec))
    }

    @Test
    fun `score decreases monotonically as RTT grows`() {
        val a = RotationSelector.score(good(rtt = 10))
        val b = RotationSelector.score(good(rtt = 50))
        val c = RotationSelector.score(good(rtt = 250))
        assertTrue(a > b)
        assertTrue(b > c)
    }

    @Test
    fun `exact ties break deterministically on stable id key`() {
        // Identical props + identical RTT ⇒ identical score; the id tiebreak must be stable & repeatable.
        val x = good(id = "xeon", family = "fx", rtt = 30)
        val y = good(id = "atom", family = "fy", rtt = 30)
        val pick1 = RotationSelector.select(listOf(x, y), null)
        val pick2 = RotationSelector.select(listOf(y, x), null) // reordered input
        assertEquals(pick1?.id, pick2?.id) // order-independent, deterministic
    }

    // ---- FAIL-SAFE: empty / fully-bad pool ⇒ null (keep current set, never tear down) ----

    @Test
    fun `select returns null on an empty pool (fail-safe keep-current)`() {
        assertNull(RotationSelector.select(emptyList(), lastOperatorFamily = "anything"))
    }

    @Test
    fun `select returns null when every candidate fails the trust-filter`() {
        val pool = listOf(
            good(id = "logger", noLog = false),     // dropped: logs
            good(id = "doh", dnsCrypt = false),      // dropped: not DNSCrypt
            good(id = "dead", rtt = -1),             // dropped: unreachable
        )
        assertNull(RotationSelector.select(pool, lastOperatorFamily = null))
    }

    @Test
    fun `select returns null when diversity exclusion empties the pool (only the same operator left)`() {
        // Every survivor is the SAME operator as the last window ⇒ a diverse pick is impossible ⇒ null
        // (do NOT silently re-pick the same family; the caller keeps the current set).
        val pool = listOf(
            good(id = "a1", family = "soleop"),
            good(id = "a2", family = "soleop"),
        )
        assertNull(RotationSelector.select(pool, lastOperatorFamily = "soleop"))
    }

    @Test
    fun `disabling diversity allows the same family when it is the only option`() {
        val pool = listOf(good(id = "a1", family = "soleop"))
        val pick = RotationSelector.select(
            pool,
            lastOperatorFamily = "soleop",
            policy = RotationPolicy(enforceDiversity = false),
        )
        assertEquals("a1", pick?.id) // diversity off ⇒ the only resolver is allowed
    }

    // ---- LOCKED-SPEC default pick count = 10 servers (Slice C) ----

    @Test
    fun `the rotation default draws exactly 10 servers from a larger filtered pool`() {
        // Socio spec (restated 4×): absent a count pref, a random pick lands EXACTLY 10 resolvers.
        assertEquals(10, RotationSelector.GEEK_SAFE_DEFAULT_SERVERS)
        val pool = (1..25).map { good(id = "srv" + it, family = "op" + it, rtt = 10 + it) }
        val picked = RotationSelector.selectRandomSet(
            pool, lastOperatorFamily = null, seed = 42L,
            max = RotationSelector.GEEK_SAFE_DEFAULT_SERVERS,
        )
        assertEquals(10, picked.size)
        assertEquals(10, picked.map { it.id }.toSet().size) // distinct, no duplication
    }

    @Test
    fun `the geek-safe ceiling of 20 still caps a larger pool, above the default of 10`() {
        val pool = (1..25).map { good(id = "srv" + it, family = "op" + it, rtt = 10 + it) }
        val capped = RotationSelector.selectRandomSet(
            pool, lastOperatorFamily = null, seed = 7L,
            max = RotationSelector.GEEK_SAFE_MAX_SERVERS,
        )
        assertEquals(20, capped.size)
        assertTrue(
            "the spec default must sit below the geek-safe ceiling",
            RotationSelector.GEEK_SAFE_DEFAULT_SERVERS < RotationSelector.GEEK_SAFE_MAX_SERVERS,
        )
    }

    @Test
    fun `a pool smaller than the default takes all survivors, never pads`() {
        val pool = (1..4).map { good(id = "srv" + it, family = "op" + it) }
        val picked = RotationSelector.selectRandomSet(
            pool, lastOperatorFamily = null, seed = 1L,
            max = RotationSelector.GEEK_SAFE_DEFAULT_SERVERS,
        )
        assertEquals(4, picked.size)
    }
}
