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

package pillar.kuma_saimono.libumdnscrypt.vpn.service

import uniffi.torta_core.WardenAppRow
import uniffi.torta_core.WardenCidrRule
import uniffi.torta_core.WardenConnFacts
import uniffi.torta_core.WardenDomainRule
import uniffi.torta_core.WardenInstallReport
import uniffi.torta_core.WardenNetworkType
import uniffi.torta_core.WardenObject
import uniffi.torta_core.WardenSnapshot
import uniffi.torta_core.WardenUniversalRule
import uniffi.torta_core.WardenUniversalToggles
import uniffi.torta_core.wardenDatapathEnforced
import uniffi.torta_core.wardenDatapathInstance
import uniffi.torta_core.wardenSetDatapathEnforced

/**
 * The per-connection datapath's hold of the already-built native Warden (REPOINT-1). The Garmatin
 * per-app allow-set firewall in [VpnRulesHolder] is re-pointed onto the native
 * `uniffi.torta_core.WardenObject` PURE-FIREWALL verdict here: ONE process-global, lazily +
 * infallibly constructed handle (the arg-less ctor is the cold allow-all fail-safe baseline), held
 * for the process lifetime — the single instance the datapath queries (and the same instance the
 * future settings→matrix feed must install rule rows into, so a UI-lit deny is seen by the
 * datapath).
 *
 * This is the established native-facade idiom of
 * [pillar.kuma_saimono.libumdnscrypt.rust.TortaCore] (a process-global object over a UniFFI handle), NOT
 * a DI binding — so it adds no Dagger binding and needs no Kotlin-Inject graph edit. It is the
 * Kotlin seam that owns the unsigned `WardenConnFacts` construction so the Java VPN datapath can
 * call in with plain ints.
 *
 * Crash-proof by contract (the TortaCore firewall): a missing `.so` for the running ABI or any
 * native fault degrades to [VERDICT_ABSTAIN], which the datapath treats as ALLOW — allow-by-default,
 * NEVER a brick, matching the reworked engine's additive-block posture (an empty matrix ALLOWs until
 * a block-row installs). Never throws.
 */
object WardenDatapathGate {

    /** The engine is unreachable, the UID is non-app (the engine abstains on a negative UID), or a
     *  native fault occurred — the datapath treats this as ALLOW (allow-by-default). */
    const val VERDICT_ABSTAIN = -1

    /** [uniffi.torta_core.WardenVerdict.ALLOW] — the firewall assents. */
    const val VERDICT_ALLOW = 0

    /** [uniffi.torta_core.WardenVerdict.DENY_BY_FIREWALL] — the only deny the pure-firewall verdict emits. */
    const val VERDICT_DENY_FIREWALL = 1

    /** [uniffi.torta_core.WardenVerdict.DENY_BY_BLOCKLIST] — the datapath's separate-gate report slot
     *  (the pure-firewall Object verdict never emits this). */
    const val VERDICT_DENY_BLOCKLIST = 2

    /** [uniffi.torta_core.WardenNetworkType.LAN] ordinal — a LAN-range destination (the orthogonal axis). */
    const val NET_LAN = 0

    /** [uniffi.torta_core.WardenNetworkType.WIFI] ordinal — Wi-Fi (also collapses Ethernet). */
    const val NET_WIFI = 1

    /** [uniffi.torta_core.WardenNetworkType.GSM] ordinal — cellular / mobile data (non-roaming). */
    const val NET_GSM = 2

    /** [uniffi.torta_core.WardenNetworkType.ROAMING] ordinal — cellular while roaming. */
    const val NET_ROAMING = 3

    /** [uniffi.torta_core.WardenNetworkType.VPN] ordinal — the tunnel-egress axis (this IS the VPN datapath). */
    const val NET_VPN = 4

    @Volatile
    private var warden: WardenObject? = null

    /**
     * Lazily fetch + hold THE CANONICAL process-global [WardenObject] — the instance minted by
     * `warden_datapath_instance()` inside libtorta_core.so (A6). This is the SAME engine the Rust
     * tunnel datapath consults when the firewall is armed, so rules/matrix/toggles installed
     * through this gate rule BOTH datapaths, and the stats every surface reads agree. Returns null
     * only if the lib is unreachable for the running ABI or the native call faults (touching the
     * binding auto-loads `libtorta_core.so`). Never throws.
     */
    @Synchronized
    private fun hold(): WardenObject? {
        warden?.let { return it }
        return try {
            wardenDatapathInstance().also { warden = it }
        } catch (t: Throwable) {
            null
        }
    }

    /**
     * Mirror the user's firewall ARM switch into the Rust tunnel datapath (A6). `true` makes the
     * Rust tunnel consult THE canonical engine (the instance this gate arms) before its legacy
     * flat-global ask; `false` (the boot default inside the .so) keeps the tunnel byte-identical
     * to its pre-A6 path. The Java datapath stays gated by `getFirewallEnabled()` on its own side —
     * this mirrors that SAME user intent to the side that cannot see Android prefs. Never throws.
     * Returns the bit actually armed (false when the lib is unreachable).
     */
    @JvmStatic
    fun setEnforced(on: Boolean): Boolean =
        try {
            // Hold first: an enforce-bit without the canonical instance denies nothing (the tunnel
            // consult needs BOTH), and hold() is what mints + rehydrates the engine.
            if (on) hold()
            wardenSetDatapathEnforced(on)
            wardenDatapathEnforced()
        } catch (t: Throwable) {
            false
        }

    /** Read the ARM bit back from the .so (the UI's posture read). Never throws. */
    @JvmStatic
    fun enforced(): Boolean =
        try {
            wardenDatapathEnforced()
        } catch (t: Throwable) {
            false
        }

    /**
     * The PURE-FIREWALL Warden verdict for ONE connection — the per-connection datapath re-point.
     * Builds a [WardenConnFacts] from the packet facts and returns the verdict CODE
     * ([VERDICT_ALLOW]/[VERDICT_DENY_FIREWALL]/[VERDICT_DENY_BLOCKLIST]) or [VERDICT_ABSTAIN] when the
     * engine is unreachable, [uid] is < 0 (the engine abstains on a non-app UID), or any native
     * fault. The caller treats ABSTAIN as ALLOW. The blocklist is the datapath's SEPARATE gate (the
     * Object verdict is pure-firewall — it only ever emits ALLOW or DENY_BY_FIREWALL).
     *
     * [netOrdinal] is the [WardenNetworkType] ordinal (0=LAN 1=WIFI 2=GSM 3=ROAMING 4=VPN). Never
     * throws.
     */
    @JvmStatic
    fun verdict(uid: Int, daddr: String, dport: Int, proto: Int, netOrdinal: Int): Int {
        // A negative UID is a non-app/unknown connection: the engine abstains on it, so short-circuit
        // the FFI and abstain (allow-by-default) here.
        val w = if (uid < 0) null else hold()
        if (w == null) return VERDICT_ABSTAIN
        return try {
            val net =
                when (netOrdinal) {
                    NET_LAN -> WardenNetworkType.LAN
                    NET_WIFI -> WardenNetworkType.WIFI
                    NET_GSM -> WardenNetworkType.GSM
                    NET_ROAMING -> WardenNetworkType.ROAMING
                    else -> WardenNetworkType.VPN
                }
            val conn =
                WardenConnFacts(
                    uid.toUInt(),
                    daddr,
                    dport.toUShort(),
                    proto.toUByte(),
                    null,
                    net,
                    // dnsBlocked — the TIER-5 resolver seam, set only in the resolver path. The
                    // packet-datapath gate carries no DNS-block signal, so it abstains to false
                    // (behavior-preserving: the field did not participate at this gate before).
                    false,
                )
            w.verdict(conn).value
        } catch (t: Throwable) {
            VERDICT_ABSTAIN
        }
    }

    // =====================================================================================================
    // THE SOVEREIGN RAIL (D01/D02/D03) — the control-plane surface on the ONE held instance
    // =====================================================================================================
    //
    // Before this, the Warden was a NO-OP: the datapath queried this held [WardenObject] (arg-less, empty
    // rule-sets → allow-forever), the dashboard polled the SEPARATE, permanently-disarmed flat
    // `warden_stats` global (the split-brain), and `bindDurable` had ZERO callers (no persistence, no
    // boot-rehydrate). This rail closes all three: EVERY control-plane op — arm the rules/matrix/toggles
    // (D01), read the typed stats (D02), bind the durable tier (D03) — lands on the SAME instance
    // [verdict] queries, so a UI-lit rule IS seen by the datapath and IS counted in the dashboard. Every
    // method is crash-proof by contract (a missing `.so` / native fault degrades to a safe default, NEVER
    // throws — the datapath must never brick).

    /**
     * D02 — the typed live snapshot of the SAME instance the datapath queries (kills the stats
     * split-brain: the dashboard no longer polls the disarmed flat `warden_stats` global). Returns the
     * real verdict tallies + per-tier deny attribution + armed rule/matrix counts, or null if the engine
     * is unreachable / a native fault. Pure read; never throws.
     */
    @JvmStatic
    fun snapshot(): WardenSnapshot? {
        val w = hold() ?: return null
        return try {
            w.snapshot()
        } catch (t: Throwable) {
            null
        }
    }

    /**
     * D03 — wire the per-app matrix + universal toggles to a DURABLE app-private dir AND boot-rehydrate the
     * persisted posture (RAM⊗NAND). Call ONCE at engine start, BEFORE any rule/toggle mutation (the
     * rehydrate REPLACES the in-memory posture). [nowMs] is the wall clock for the RULE19 TempAllow TTL
     * drop (a pause that lapsed while the device was OFF is restored expired). Returns the count of rows
     * rehydrated (0 = cold start / unreachable — fail-safe). Never throws.
     */
    @JvmStatic
    fun bindDurable(dir: String, nowMs: Long): Int {
        val w = hold() ?: return 0
        return try {
            w.bindDurable(dir, nowMs.toULong()).toInt()
        } catch (t: Throwable) {
            0
        }
    }

    /**
     * D03 — the RULE19 TempAllow TTL sweep (a control-plane tick): expire every per-app temp-allow whose
     * wall-clock expiry passed [nowMs] so a lapsed pause stops letting that app through. If a durable dir
     * is bound, an expiry gently write-throughs. Returns the count expired (0 = none / unreachable). NEVER
     * on the verdict hot path (the verdict holds no clock). Never throws.
     */
    @JvmStatic
    fun expireTempAllows(nowMs: Long): Int {
        val w = hold() ?: return 0
        return try {
            w.expireTempAllows(nowMs.toULong()).toInt()
        } catch (t: Throwable) {
            0
        }
    }

    /**
     * D01/D27 — install (REPLACE) the BLOCK domain rule-set, ARMING it on the SAME instance the datapath
     * queries. Returns the typed [WardenInstallReport] (accepted count + the BOUNDED list of rejected
     * rules with WHY each died at the RFC-1123 integrity gate) so a rules UI can render "3 of 100 rejected
     * because …" instead of a silent drop. An empty report (accepted=0) on any fault. Never throws.
     */
    @JvmStatic
    fun installDomainRules(rules: List<WardenDomainRule>): WardenInstallReport? {
        val w = hold() ?: return null
        return try {
            w.installDomainRules(rules)
        } catch (t: Throwable) {
            null
        }
    }

    /**
     * D01 — install (REPLACE) the BLOCK/Bypass CIDR rule-set, ARMING it on the held instance. Returns the
     * rule count (0 on any fault). Never throws.
     */
    @JvmStatic
    fun installCidrRules(rules: List<WardenCidrRule>): Long {
        val w = hold() ?: return 0L
        return try {
            w.installCidrRules(rules)
        } catch (t: Throwable) {
            0L
        }
    }

    /**
     * D01 — set (REPLACE) the armed universal rule set (TIER 2, the `|||` settings section), ARMING it on
     * the held instance. Returns the count armed (0 on any fault). Never throws.
     */
    @JvmStatic
    fun setUniversalRules(rules: List<WardenUniversalRule>): Long {
        val w = hold() ?: return 0L
        return try {
            w.setUniversalRules(rules)
        } catch (t: Throwable) {
            0L
        }
    }

    /**
     * D01 — install (REPLACE) a per-app matrix row (TIER 3) on the held instance. No-op on any fault.
     * Never throws.
     */
    @JvmStatic
    fun setAppRow(row: WardenAppRow) {
        val w = hold() ?: return
        try {
            w.setAppRow(row)
        } catch (t: Throwable) {
            // native fault ⇒ the row is not installed; the datapath keeps its prior posture.
        }
    }

    /** D01 — remove the per-app matrix row for [uid] on the held instance. No-op on any fault. Never throws. */
    @JvmStatic
    fun removeAppRow(uid: Int) {
        val w = hold() ?: return
        try {
            w.removeAppRow(uid.toUInt())
        } catch (t: Throwable) {
            // native fault ⇒ the row is left in place.
        }
    }

    /**
     * F1 (e-fix round 2) — READ the held per-app matrix rows (TIER 3) from the SAME instance the
     * datapath queries, UID-sorted. The read direction the per-app firewall UI
     * ([pillar.kuma_saimono.libumdnscrypt.settings.warden_apps.WardenAppsFragment]) renders its current
     * posture from — without it the UI could WRITE rows but never show them. Empty on any fault /
     * unreachable engine. Never throws.
     */
    @JvmStatic
    fun appRows(): List<WardenAppRow> {
        val w = hold() ?: return emptyList()
        return try {
            w.appRows()
        } catch (t: Throwable) {
            emptyList()
        }
    }

    /**
     * M2 — READ the armed BLOCK domain rules (reversed-label trie terminals + validated globs) from the
     * SAME instance the datapath queries, in the engine's deterministic (uid ASC, domain ASC) order. The
     * read direction the settings-pane rule LIST + per-index REMOVE ride ([installDomainRules] REPLACES the
     * whole set, so a remove is enumerate → drop → re-install). Empty on any fault / unreachable engine.
     * Never throws.
     */
    @JvmStatic
    fun domainRules(): List<WardenDomainRule> {
        val w = hold() ?: return emptyList()
        return try {
            w.domainRules()
        } catch (t: Throwable) {
            emptyList()
        }
    }

    /**
     * M2 — READ the armed BLOCK/Bypass CIDR rules (v4) from the held instance, in the finalized
     * most-specific-first order. The read direction the settings-pane rule LIST + per-index REMOVE ride.
     * Empty on any fault / unreachable engine. Never throws.
     */
    @JvmStatic
    fun cidrRules(): List<WardenCidrRule> {
        val w = hold() ?: return emptyList()
        return try {
            w.cidrRules()
        } catch (t: Throwable) {
            emptyList()
        }
    }

    /**
     * W-C (#86) — READ the armed CIDR rules as v6-CAPABLE wire rows `"<uid>\t<text>\t<status>"`, in the
     * finalized most-specific-first order (uids ASC). Where [cidrRules] silently DROPS every v6 rule (its
     * `WardenCidrRule.net` is a v4-only `u32`), this enumerates v4 AND v6 — so a v6 host block armed via
     * [blockIp] finally renders in the settings LIST. The `text` never holds a tab, so the split is safe.
     * Empty on any fault / unreachable engine. Never throws.
     */
    @JvmStatic
    fun cidrRulesWire(): List<String> {
        val w = hold() ?: return emptyList()
        return try {
            w.cidrRulesWire()
        } catch (t: Throwable) {
            emptyList()
        }
    }

    /**
     * W-C (#86) — REMOVE the CIDR rule at flat index [index] in the [cidrRulesWire] enumeration order
     * (uids ASC, then finalized in-bucket). The v6-capable settings REMOVE: an index-remove needs NO
     * reinstall, so a v6 rule (which the v4-only [installCidrRules] REPLACE wire could not re-carry) drops
     * cleanly. Returns `true` iff a rule was removed. `false` on any fault / out-of-range. Never throws.
     */
    @JvmStatic
    fun removeCidrRuleAt(index: UInt): Boolean {
        val w = hold() ?: return false
        return try {
            w.removeCidrRuleAt(index)
        } catch (t: Throwable) {
            false
        }
    }

    /**
     * D01 — install (REPLACE) the 9 universal DENY toggles (TIER 2) on the held instance. No-op on any
     * fault. Never throws.
     */
    @JvmStatic
    fun setUniversalToggles(toggles: WardenUniversalToggles) {
        val w = hold() ?: return
        try {
            w.setUniversalToggles(toggles)
            // #95 — a toggle bit ALONE never denies. The TIER-2 cascade gates 8 of the 9 toggles on
            // BOTH the bit AND the matching rule being ARMED (`warden/mod.rs:1457`:
            //     if t.lockdown && armed(UniversalRule::Lockdown)
            // where `armed()` = `universal_rules.contains(&rule)`). Setting the bit while the armed
            // set stays empty is precisely the state that renders "BLOCKING" over a firewall that
            // passes every packet — measured on device: Lockdown lit, 4 ALLOWED / 0 DENIED.
            // So the armed set is REPLACED from the bits on every flip: one call, one authority,
            // no drift between what the chip shows and what the cascade consults.
            w.setUniversalRules(rulesFor(toggles))
        } catch (t: Throwable) {
            // native fault ⇒ the toggles are unchanged.
        }
    }

    /**
     * #95 — the toggle-bit → armed-rule mapping the TIER-2 cascade consults.
     *
     * `blockUnknownConns` is deliberately ABSENT: it is the ONE toggle whose branch does not consult
     * `armed()` (`warden/mod.rs`, the RethinkDNS step-3 arm — `if t.block_unknown_conns && app_mode ==
     * Untracked`), so arming a rule for it would add a rule the engine never reads. The two table
     * markers (`BLOCK_UNIVERSAL_CIDR` / `BLOCK_UNIVERSAL_DOMAIN`) are likewise absent — they are armed
     * by the domain/CIDR rule installers, not by a user chip.
     */
    private fun rulesFor(t: WardenUniversalToggles): List<WardenUniversalRule> = buildList {
        if (t.blockNewApps) add(WardenUniversalRule.BLOCK_NEW_APPS)
        if (t.blockMetered) add(WardenUniversalRule.BLOCK_METERED)
        if (t.lockdown) add(WardenUniversalRule.LOCKDOWN)
        if (t.deviceLock) add(WardenUniversalRule.DEVICE_LOCK)
        if (t.blockBackground) add(WardenUniversalRule.BLOCK_BACKGROUND)
        if (t.blockUdpNtp) add(WardenUniversalRule.BLOCK_UDP_NTP)
        if (t.blockHttp) add(WardenUniversalRule.BLOCK_HTTP)
        if (t.blockDnsBypass) add(WardenUniversalRule.BLOCK_DNS_BYPASS)
    }

    /**
     * A6 — READ the 9 universal DENY toggles back from the held instance (the inverse of
     * [setUniversalToggles]): the SLINT chip state renders the ENGINE's own bits, so a durable
     * rehydrate or a preset write can never drift from what the cascade actually consults. `null`
     * on any fault / unreachable engine (the UI then keeps the honest all-off default). Never
     * throws.
     */
    @JvmStatic
    fun universalToggles(): WardenUniversalToggles? {
        val w = hold() ?: return null
        return try {
            w.universalToggles()
        } catch (t: Throwable) {
            null
        }
    }

    /** D01 — set the fail-CLOSED posture bit (the Nerd knob) on the held instance. No-op on fault. Never throws. */
    @JvmStatic
    fun setFailClosed(failClosed: Boolean) {
        val w = hold() ?: return
        try {
            w.setFailClosed(failClosed)
        } catch (t: Throwable) {
            // native fault ⇒ the posture bit is unchanged.
        }
    }

    /**
     * D03 — the LOGGED DNS-answer verdict (the review-channel seam): judge a resolved answer against the
     * armed UNIVERSAL block rules AND append one line to `query-warden.log` in the bound durable dir.
     * OFF the per-connection hot path — a CONTROL-PLANE call the resolver drives on a block event once
     * rules are armed (an UNARMED Warden is a silent Allow no-op; an UNBOUND Warden writes no log). Returns
     * the verdict code ([VERDICT_ALLOW]/[VERDICT_DENY_FIREWALL]) or [VERDICT_ABSTAIN] on any fault. Never
     * throws. (The plain DNS-answer verdict — no log — is [dnsVerdict].)
     */
    @JvmStatic
    fun logDnsVerdict(name: String, addrs: List<String>, nowMs: Long): Int {
        val w = hold() ?: return VERDICT_ABSTAIN
        return try {
            w.logDnsVerdict(name, addrs, nowMs.toULong()).value
        } catch (t: Throwable) {
            VERDICT_ABSTAIN
        }
    }

    /**
     * D03 — the PLAIN DNS-answer verdict (no log): judge a resolved answer against the armed UNIVERSAL
     * block rules. The advisory PRODUCER of the TIER-5 `dns_blocked` seam. Returns the verdict code, or
     * [VERDICT_ABSTAIN] on any fault. Never throws.
     */
    @JvmStatic
    fun dnsVerdict(name: String, addrs: List<String>): Int {
        val w = hold() ?: return VERDICT_ABSTAIN
        return try {
            w.dnsVerdict(name, addrs).value
        } catch (t: Throwable) {
            VERDICT_ABSTAIN
        }
    }

    // =====================================================================================================
    // W-D (#79) — THE PER-APP INSPECTOR block-ladder writers (single IP -> CIDR family -> whole country)
    // =====================================================================================================
    //
    // The inspector popup's block-granularity ladder lands here on the SAME held instance the datapath
    // queries: a /32 host block, its /24-/16 CIDR family, or a whole GEO country. All ADDITIVE (never a
    // clobber of the armed set) and crash-proof (a native fault degrades to a safe no-block, never a
    // brick). RAM-tier for W-D; the durable persistence of these rows is W-C (#78).

    /**
     * W-D — ADD one IP/CIDR block ADDITIVELY on the held instance (the block-ladder's single-IP + CIDR-
     * family rungs). [cidr] is a family-aware CIDR string: `"8.8.8.8"` = a `/32` host, `"8.8.8.0/24"` =
     * a family, `"2001:db8::/48"` = a v6 family. [uid] `0` blocks it for every app; a real uid scopes
     * it to one. Returns `true` iff the CIDR parsed + the rule armed; `false` on a malformed CIDR or any
     * native fault. Never throws.
     */
    @JvmStatic
    fun blockIp(uid: Int, cidr: String): Boolean {
        val w = hold() ?: return false
        return try {
            w.blockIp(uid.toUInt(), cidr)
        } catch (t: Throwable) {
            false
        }
    }

    /**
     * W-D — set (REPLACE) the GEO-family block set (ISO-3166 alpha-2 codes; the "block this country"
     * rung) on the held instance. The engine lowercases + gates each code to two ASCII letters. Returns
     * the count armed (0 on any fault). Never throws.
     */
    @JvmStatic
    fun setGeoBlocks(codes: List<String>): Long {
        val w = hold() ?: return 0L
        return try {
            w.setGeoBlocks(codes)
        } catch (t: Throwable) {
            0L
        }
    }

    /** W-D — the armed GEO-family block codes (lowercase, sorted) from the held instance (the inspector's
     *  posture read). Empty on any fault / unreachable engine. Never throws. */
    @JvmStatic
    fun geoBlocks(): List<String> {
        val w = hold() ?: return emptyList()
        return try {
            w.geoBlocks()
        } catch (t: Throwable) {
            emptyList()
        }
    }
}
