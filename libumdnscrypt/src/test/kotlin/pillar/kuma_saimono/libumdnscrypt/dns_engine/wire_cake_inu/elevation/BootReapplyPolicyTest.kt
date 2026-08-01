/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

/*
    This file is part of Yeah! Tortä. GPL-3.0-or-later. Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.BootReapplyPolicy.Durability
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation.BootReapplyPolicy.PowerState

/**
 * Pins [BootReapplyPolicy]: the pure boot-time decision — durable powers re-verify, drift-prone ones
 * re-apply, and an unprotected device opens NO connection (no nagging). Pure logic — no Android
 * BootCompleteManager, no clock.
 */
class BootReapplyPolicyTest {

    private val vpnApp = PowerState("always_on_vpn_app", Durability.DURABLE, lastVerified = true)
    private val lockdown = PowerState("always_on_vpn_lockdown", Durability.DURABLE, lastVerified = true)
    private val standby = PowerState("standby_bucket", Durability.DRIFT_PRONE, lastVerified = true)

    @Test
    fun `unprotected device does nothing - no reconnect, no work`() {
        val plan = BootReapplyPolicy.decide(isProtected = false, powers = listOf(vpnApp, standby))
        assertFalse(plan.shouldReconnect)
        assertTrue(plan.toReapply.isEmpty())
        assertTrue(plan.toReverify.isEmpty())
    }

    @Test
    fun `protected device re-applies drift-prone powers and re-verifies durable ones`() {
        val plan = BootReapplyPolicy.decide(
            isProtected = true,
            powers = listOf(vpnApp, lockdown, standby),
        )
        assertTrue(plan.shouldReconnect)
        assertEquals(listOf("standby_bucket"), plan.toReapply)
        assertEquals(listOf("always_on_vpn_app", "always_on_vpn_lockdown"), plan.toReverify)
    }

    @Test
    fun `unverified powers are skipped - only what was granted is re-established`() {
        val unapplied = PowerState("standby_bucket", Durability.DRIFT_PRONE, lastVerified = false)
        val plan = BootReapplyPolicy.decide(isProtected = true, powers = listOf(vpnApp, unapplied))
        assertTrue(plan.shouldReconnect) // vpnApp still needs re-verify
        assertTrue("never re-apply a power that was never verified", plan.toReapply.isEmpty())
        assertEquals(listOf("always_on_vpn_app"), plan.toReverify)
    }

    @Test
    fun `protected but every power unverified means no real work - no reconnect`() {
        val plan = BootReapplyPolicy.decide(
            isProtected = true,
            powers = listOf(
                PowerState("always_on_vpn_app", Durability.DURABLE, lastVerified = false),
                PowerState("standby_bucket", Durability.DRIFT_PRONE, lastVerified = false),
            ),
        )
        assertFalse("nothing verified to re-establish → don't open a connection", plan.shouldReconnect)
        assertTrue(plan.toReapply.isEmpty())
        assertTrue(plan.toReverify.isEmpty())
    }

    @Test
    fun `protected with an empty power set opens no connection`() {
        val plan = BootReapplyPolicy.decide(isProtected = true, powers = emptyList())
        assertFalse(plan.shouldReconnect)
    }

    @Test
    fun `only drift-prone powers exist - reapply only, still reconnects`() {
        val plan = BootReapplyPolicy.decide(isProtected = true, powers = listOf(standby))
        assertTrue(plan.shouldReconnect)
        assertEquals(listOf("standby_bucket"), plan.toReapply)
        assertTrue(plan.toReverify.isEmpty())
    }

    /**
     * The REAL boot consumer contract: feed the whole live [PowerCatalogue] (all 21 amplified powers)
     * through the policy exactly as [WireCakeInuManager.reapplyOnBoot] does — every previously-verified
     * power partitioned by its OWN `driftProne` flag. Pins that the S2 amplification (OS-durable global
     * settings + appops) stays on the RE-VERIFY side (survives a reboot, no needless rewrite), and only
     * the app-standby bucket re-applies. No connection is opened unless there is real work.
     */
    @Test
    fun `real PowerCatalogue partitions across the boot policy - drift-prone re-apply, durable re-verify`() {
        val ops = PowerCatalogue.build("app.torta.yeah", 10123)
        val states = ops.map {
            PowerState(
                id = it.id.key,
                durability = if (it.driftProne) Durability.DRIFT_PRONE else Durability.DURABLE,
                lastVerified = true,
            )
        }
        val plan = BootReapplyPolicy.decide(isProtected = true, powers = states)

        assertTrue("a protected device with verified powers must reconnect", plan.shouldReconnect)
        // Every verified power lands in exactly one bucket — the union is the whole catalogue, no drops.
        assertEquals(ops.size, plan.toReapply.size + plan.toReverify.size)
        // The catalogue's OWN drift flags are the source of truth for what re-applies vs re-verifies.
        assertEquals(ops.filter { it.driftProne }.map { it.id.key }, plan.toReapply)
        assertEquals(ops.filterNot { it.driftProne }.map { it.id.key }, plan.toReverify)
        // Drift stays NARROW: exactly the app-standby bucket re-applies; the amplified bulk re-verifies.
        assertEquals(listOf("battery_standby_bucket"), plan.toReapply)
        assertTrue("the amplified catalogue is overwhelmingly durable", plan.toReverify.size >= 15)
    }
}
