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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

/**
 * The pure decision for the boot re-apply hook (plan §3). On boot, a protected device should silently
 * re-establish the no-root powers WITHOUT re-pairing (the persisted ADB key/cert make reconnect
 * codeless). But not every power needs a write every boot:
 *
 *   - DURABLE powers (e.g. `always_on_vpn_app`, `always_on_vpn_lockdown`) survive a reboot in
 *     `secure` settings → on boot we only need to RE-VERIFY them (read-back), not rewrite.
 *   - DRIFT-PRONE powers (e.g. the app-standby bucket, which the OS demotes over time) must be
 *     RE-APPLIED on every boot.
 *
 * This object answers, from purely-local state, "given that we're protected, what should the boot
 * receiver do?" — so the [BootCompleteManager] WD branch (absent today) carries zero logic and is
 * just a thin call site. All pure — unit-testable on metal.
 */
object BootReapplyPolicy {

    /** A power's persistence durability across a reboot. */
    enum class Durability {
        /** Survives reboot in `secure` settings — re-verify only. */
        DURABLE,

        /** The OS drifts it back (standby bucket, appops on some ROMs) — re-apply every boot. */
        DRIFT_PRONE,
    }

    /** The minimal per-power record the boot policy reasons over (a slice of the persistence map). */
    data class PowerState(
        val id: String,
        val durability: Durability,
        /** True if this power was verified-applied at last grant (only such powers are re-established). */
        val lastVerified: Boolean,
    )

    /** What the boot receiver should do for the protected device. */
    data class Plan(
        /** True only when there is real work — skip the silent autoConnect entirely if false. */
        val shouldReconnect: Boolean,
        /** Powers to actively re-apply (set then verify). */
        val toReapply: List<String>,
        /** Powers to merely re-verify (read-back; set only if drifted). */
        val toReverify: List<String>,
    )

    /**
     * Decide the boot plan.
     *
     * - Not protected → do nothing (no nagging, no connection).
     * - Protected → re-establish only the powers that were verified at grant time; drift-prone ones go
     *   to [Plan.toReapply], durable ones to [Plan.toReverify]. [Plan.shouldReconnect] is false when
     *   there is nothing to do, so the boot receiver never opens an ADB connection for no reason.
     */
    fun decide(isProtected: Boolean, powers: List<PowerState>): Plan {
        if (!isProtected) {
            return Plan(shouldReconnect = false, toReapply = emptyList(), toReverify = emptyList())
        }
        val active = powers.filter { it.lastVerified }
        val reapply = active.filter { it.durability == Durability.DRIFT_PRONE }.map { it.id }
        val reverify = active.filter { it.durability == Durability.DURABLE }.map { it.id }
        return Plan(
            shouldReconnect = reapply.isNotEmpty() || reverify.isNotEmpty(),
            toReapply = reapply,
            toReverify = reverify,
        )
    }
}
