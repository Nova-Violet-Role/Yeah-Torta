/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

/*
    This file is part of Yeah! Tortä. GPL-3.0-or-later. Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM proofs for the P11 UID-2000 power set (builder "prefs-powerset"):
 *   - [AdbSentinel] wrap/parse — honest exit-code recovery from a merged `shell:` stream,
 *   - [PowerCatalogue] — the constant, self-targeted, hard-coded allow-list of commands + read-backs,
 *   - [GrantEngine] — the convergent verify→set→verify contract that NEVER fakes "protected",
 *   - [PowerStateCodec] — the per-power persistence map (fail-closed on garbled input).
 *
 * No Android, no real binder, no device — a scriptable fake [ElevationSession] that echoes the sentinel
 * exactly as a real merged-stream shell would drives everything. The live SPAKE2/mDNS pairing E2E is a
 * tracked device-only witness (the emulator is a LeakCanary tar pit).
 */
class PowerSetTest {

    private val pkg = "app.torta.yeah"

    // ---- a scriptable fake UID-2000 session ----------------------------------
    //
    // The GrantEngine wraps each command with AdbSentinel.wrap() and re-parses the returned stdout, so
    // the fake must behave like a merged-stream shell: append the marker line `__YT_ELEV_EXIT__<exit>`
    // after the simulated command output. `responder` maps the UNWRAPPED command → (output, exit).

    private class FakeSession(
        private val responder: (String) -> Pair<String, Int>,
    ) : ElevationSession {
        override val uid = ElevationSession.SHELL_UID
        private val _alive = MutableStateFlow(true)
        override val alive: StateFlow<Boolean> = _alive
        val ranCommands = mutableListOf<String>()
        var execThrowsOn: String? = null

        override suspend fun exec(command: String, timeoutMs: Long): ShellResult {
            // Recover the real command the GrantEngine wrapped (strip the sentinel echo suffix).
            val core = command.substringBefore("; echo \"${AdbSentinel.MARK}")
            ranCommands.add(core)
            execThrowsOn?.let { if (core.contains(it)) throw RuntimeException("boom on $core") }
            val (out, exit) = responder(core)
            // Emit exactly what a merged-stream shell would: output, then the sentinel marker line.
            val merged = if (out.isEmpty()) "${AdbSentinel.MARK}$exit" else "$out\n${AdbSentinel.MARK}$exit"
            return ShellResult(0, merged, "")
        }

        override fun close() {
            _alive.value = false
        }
    }

    private class MemStore(initial: List<PowerState> = emptyList()) : PowerStateStore {
        var states = initial
        override fun load() = states
        override fun save(states: List<PowerState>) { this.states = states }
    }

    /** A session where every settings/appops/am/pm command "takes" and reads back its desired value. */
    private fun happySession() = FakeSession { cmd ->
        when {
            cmd.startsWith("settings put") -> "" to 0
            cmd == "settings get secure always_on_vpn_app" -> pkg to 0
            cmd == "settings get secure always_on_vpn_lockdown" -> "1" to 0
            cmd == "settings get secure always_on_vpn_lockdown_whitelist" -> "null" to 0
            // #63 S2 amplification — global DNS/privacy/netstack sovereignty read-backs.
            cmd == "settings get global private_dns_mode" -> "off" to 0
            cmd == "settings get global private_dns_specifier" -> "null" to 0
            cmd == "settings get global captive_portal_mode" -> "0" to 0
            cmd == "settings get global wifi_scan_throttle_enabled" -> "0" to 0
            cmd == "settings get global network_recommendations_enabled" -> "0" to 0
            cmd.startsWith("cmd appops set") -> "" to 0
            cmd.startsWith("cmd appops get") -> "RUN_ANY_IN_BACKGROUND: allow" to 0
            cmd.startsWith("cmd deviceidle whitelist") -> "" to 0
            cmd.startsWith("dumpsys deviceidle whitelist") -> "system,com.android.shell,$pkg" to 0
            cmd.startsWith("am set-standby-bucket") -> "" to 0
            cmd.startsWith("am get-standby-bucket") -> "10" to 0
            cmd.startsWith("pm grant") -> "" to 0
            else -> "" to 0
        }
    }

    // ========================================================================
    // AdbSentinel — one round-trip smoke (full sentinel coverage lives in AdbSentinelTest,
    // the joint-seam owner). Kept here only to pin the wrap→merged-shell→parse path the GrantEngine
    // depends on, so a regression in this builder's read-back contract fails in this builder's suite.
    // ========================================================================

    @Test
    fun `wrap then merged-shell then parse round-trips the read-back path the GrantEngine relies on`() {
        // Exactly what the fake session reproduces: wrap a read-back, the merged shell echoes the
        // marker, parse recovers exit + value.
        val wrapped = AdbSentinel.wrap("settings get secure always_on_vpn_app")
        assertTrue(wrapped.endsWith("; echo \"${AdbSentinel.MARK}\$?\""))
        val merged = "$pkg\n${AdbSentinel.MARK}0"
        val r = AdbSentinel.parse(merged)
        assertTrue(r.ok)
        assertEquals(pkg, r.value)
    }

    // ========================================================================
    // PowerCatalogue — constant, self-targeted, hard-coded allow-list
    // ========================================================================

    @Test
    fun `every command targets the self package only - no other pkg appears`() {
        val ops = PowerCatalogue.build(pkg)
        ops.forEach { op ->
            val cmds = listOfNotNull(op.setCmd, op.readBackCmd)
            cmds.forEach { c ->
                // The only package token anywhere is our own — self-target only (plan §5.4).
                val tokens = c.split(" ").filter { it.contains(".") && it.count { ch -> ch == '.' } >= 2 }
                tokens.forEach { raw ->
                    // `cmd deviceidle whitelist +pkg` / `-pkg` prefix the package — strip it before the check.
                    val t = raw.trimStart('+', '-')
                    // android.permission.* and android.* settings names are allowed; any *package* is pkg.
                    if (!t.startsWith("android.") && !t.startsWith("\"")) {
                        assertEquals("only the self package may appear in: $c", pkg, t)
                    }
                }
            }
        }
    }

    @Test
    fun `the always-on VPN command matches the P6 grant verbatim (self-target)`() {
        val op = PowerCatalogue.build(pkg).first { it.id == PowerId.ALWAYS_ON_VPN }
        assertEquals("settings put secure always_on_vpn_app $pkg", op.setCmd)
        assertEquals("settings get secure always_on_vpn_app", op.readBackCmd)
        assertEquals(pkg, op.expected)
    }

    @Test
    fun `the lockdown kill-switch command matches the P6 grant verbatim`() {
        val op = PowerCatalogue.build(pkg).first { it.id == PowerId.LOCKDOWN }
        assertEquals("settings put secure always_on_vpn_lockdown 1", op.setCmd)
        assertEquals("1", op.expected)
    }

    @Test
    fun `lockdown is applied AFTER always-on (anti-brick ordering)`() {
        val tier1 = PowerCatalogue.tier1(pkg)
        val vpnIdx = tier1.indexOfFirst { it.id == PowerId.ALWAYS_ON_VPN }
        val lockIdx = tier1.indexOfFirst { it.id == PowerId.LOCKDOWN }
        assertTrue("always-on must precede lockdown", vpnIdx in 0 until lockIdx)
    }

    @Test
    fun `the explicit-empty lockdown allowlist anti-brick valve is in the default set`() {
        assertTrue(PowerCatalogue.tier1(pkg).any { it.id == PowerId.LOCKDOWN_ALLOWLIST_EMPTY })
    }

    @Test
    fun `standby-bucket is the drift-prone power flagged for boot re-apply`() {
        val drift = PowerCatalogue.driftProne(pkg)
        assertEquals(1, drift.size)
        assertEquals(PowerId.BATTERY_STANDBY_BUCKET, drift.single().id)
        assertTrue(drift.single().driftProne)
    }

    @Test
    fun `NOT-shipping powers are absent - no network ADB, no BIND_VPN, no pm disable`() {
        val allCmds = PowerCatalogue.build(pkg, appUid = 10123).joinToString(" ") { it.setCmd + " " + (it.readBackCmd ?: "") }
        assertFalse(allCmds.contains("adb_wifi_enabled"))         // network ADB — NOT shipping
        assertFalse(allCmds.contains("BIND_VPN_SERVICE"))         // consent-only
        assertFalse(allCmds.contains("pm disable"))               // never disable other packages
        // WRITE_SECURE_SETTINGS is allowed ONLY as a Tier-3 Expert opt-in — never in the default Tier-1 set.
        val tier1Cmds = PowerCatalogue.tier1(pkg).joinToString(" ") { it.setCmd }
        assertFalse(tier1Cmds.contains("WRITE_SECURE_SETTINGS"))
    }

    @Test
    fun `WRITE_SECURE_SETTINGS is a Tier-3 Expert opt-in via the shell, never a default`() {
        assertFalse(PowerCatalogue.tier1(pkg).any { it.id == PowerId.WRITE_SECURE_SETTINGS })
        assertTrue(PowerCatalogue.tier3(pkg).any { it.id == PowerId.WRITE_SECURE_SETTINGS })
        val op = PowerCatalogue.build(pkg).first { it.id == PowerId.WRITE_SECURE_SETTINGS }
        assertEquals("pm grant $pkg android.permission.WRITE_SECURE_SETTINGS", op.setCmd)
        assertEquals("pm revoke $pkg android.permission.WRITE_SECURE_SETTINGS", op.reverseCmd)
        assertFalse("granted via shell pm grant; exit-only, no read-back", op.readBackable)
    }

    // ========================================================================
    // #63 S2 AMPLIFICATION — the pillar-mapped Tier-3 power set. Guards: all Expert-only (never
    // default), all reversible + read-backable, the two DNS powers own DISTINCT keys (non-redundant),
    // and the consent-bypass is the ACTIVATE_VPN op — never the manifest BIND_VPN_SERVICE.
    // ========================================================================

    private val amplification = listOf(
        PowerId.PRIVATE_DNS_OFF,
        PowerId.IGNORE_SYSTEM_DNS,
        PowerId.CAPTIVE_PORTAL_OFF,
        PowerId.WIFI_SCAN_THROTTLE_OFF,
        PowerId.NETWORK_RECOMMENDATIONS_OFF,
        PowerId.USAGE_STATS,
        PowerId.SCHEDULE_EXACT_ALARM,
        PowerId.SYSTEM_ALERT_WINDOW,
        PowerId.ACTIVATE_VPN,
    )

    @Test
    fun `every S2 amplification power is Tier-3 Expert - never a default`() {
        val t1 = PowerCatalogue.tier1(pkg).map { it.id }.toSet()
        val t3 = PowerCatalogue.tier3(pkg, appUid = 10123).map { it.id }.toSet()
        for (id in amplification) {
            assertFalse("$id must NOT be a Tier-1 default", t1.contains(id))
            assertTrue("$id must be a Tier-3 Expert power", t3.contains(id))
        }
    }

    @Test
    fun `every S2 amplification power is reversible and read-backable - never claims held blind`() {
        val ops = PowerCatalogue.build(pkg, appUid = 10123).associateBy { it.id }
        for (id in amplification) {
            val op = ops.getValue(id)
            assertTrue("$id must carry a reverseCmd (fully revertible)", op.reverseCmd != null)
            assertTrue("$id must be read-backable", op.readBackable)
        }
    }

    @Test
    fun `the two DNS-sovereignty powers own DISTINCT global keys - no redundant elevation`() {
        val ops = PowerCatalogue.build(pkg).associateBy { it.id }
        val mode = ops.getValue(PowerId.PRIVATE_DNS_OFF)
        val spec = ops.getValue(PowerId.IGNORE_SYSTEM_DNS)
        assertEquals("settings put global private_dns_mode off", mode.setCmd)
        assertEquals("settings put global private_dns_specifier \"\"", spec.setCmd)
        assertFalse("distinct keys, not a duplicated command", mode.setCmd == spec.setCmd)
        assertEquals("settings put global private_dns_mode opportunistic", mode.reverseCmd)
        assertEquals("settings delete global private_dns_specifier", spec.reverseCmd)
    }

    @Test
    fun `advanced-VPN power is the ACTIVATE_VPN appop, self-target, NOT BIND_VPN_SERVICE`() {
        val op = PowerCatalogue.build(pkg).first { it.id == PowerId.ACTIVATE_VPN }
        assertEquals("cmd appops set $pkg ACTIVATE_VPN allow", op.setCmd)
        assertFalse(
            "consent-bypass is the ACTIVATE_VPN op, never the manifest BIND_VPN_SERVICE",
            op.setCmd.contains("BIND_VPN_SERVICE"),
        )
    }

    @Test
    fun `S2 appop read-backs are contains-token 'allow' and global settings are exact-equals`() {
        val ops = PowerCatalogue.build(pkg).associateBy { it.id }
        // appop: `cmd appops get` prints "OP: allow" → held on contains-token.
        val usage = ops.getValue(PowerId.USAGE_STATS)
        assertTrue(PowerCatalogue.isHeld(usage, ShellResult(0, "GET_USAGE_STATS: allow", "")))
        assertFalse(PowerCatalogue.isHeld(usage, ShellResult(0, "GET_USAGE_STATS: ignore", "")))
        // global: exact-equals on the read value.
        val dns = ops.getValue(PowerId.PRIVATE_DNS_OFF)
        assertTrue(PowerCatalogue.isHeld(dns, ShellResult(0, "off", "")))
        assertFalse(PowerCatalogue.isHeld(dns, ShellResult(0, "opportunistic", "")))
    }

    @Test
    fun `the catalogue grew to 21 powers (12 base + 9 S2 amplification)`() {
        assertEquals(20, PowerCatalogue.build(pkg).size) // no appUid → Data-Saver omitted
        assertEquals(21, PowerCatalogue.build(pkg, appUid = 10123).size)
    }

    @Test
    fun `the new battery-survival powers (doze, wake-lock, run-in-background) are Tier-1 defaults`() {
        val t1 = PowerCatalogue.tier1(pkg).map { it.id }
        assertTrue(t1.contains(PowerId.BATTERY_DOZE_WHITELIST))
        assertTrue(t1.contains(PowerId.BATTERY_WAKE_LOCK))
        assertTrue(t1.contains(PowerId.BATTERY_RUN_IN_BACKGROUND))
    }

    @Test
    fun `READ_LOGS and Data-Saver bypass are Tier-3 Expert (absent from the default set)`() {
        val t1 = PowerCatalogue.tier1(pkg).map { it.id }
        assertFalse(t1.contains(PowerId.READ_LOGS))
        assertFalse(t1.contains(PowerId.DATA_SAVER_BYPASS))
        val t3 = PowerCatalogue.tier3(pkg, appUid = 10123).map { it.id }
        assertTrue(t3.contains(PowerId.READ_LOGS))
        assertTrue(t3.contains(PowerId.DATA_SAVER_BYPASS))
    }

    @Test
    fun `Data-Saver bypass is omitted without a UID and UID-keyed when present`() {
        assertFalse(PowerCatalogue.build(pkg).any { it.id == PowerId.DATA_SAVER_BYPASS })
        val op = PowerCatalogue.build(pkg, appUid = 10123).first { it.id == PowerId.DATA_SAVER_BYPASS }
        assertEquals("cmd netpolicy add restrict-background-whitelist 10123", op.setCmd)
        assertEquals("10123", op.expected)
    }

    @Test
    fun `every power carries a reverse command so disable-protection is clean`() {
        PowerCatalogue.build(pkg, appUid = 10123).forEach { op ->
            assertFalse("power ${op.id} must have a reverseCmd", op.reverseCmd.isNullOrBlank())
        }
    }

    @Test
    fun `doze whitelist is held by contains-token on the package`() {
        val doze = PowerCatalogue.build(pkg).first { it.id == PowerId.BATTERY_DOZE_WHITELIST }
        assertEquals("cmd deviceidle whitelist +$pkg", doze.setCmd)
        assertTrue(PowerCatalogue.isHeld(doze, ShellResult(0, "system,com.x,$pkg,com.y", "")))
        assertFalse(PowerCatalogue.isHeld(doze, ShellResult(0, "system,com.x,com.y", "")))
        assertFalse(PowerCatalogue.isHeld(doze, ShellResult(1, pkg, ""))) // non-zero exit never held
    }

    @Test
    fun `standby-bucket is held at ACTIVE(10) or EXEMPTED(5), not at a throttled bucket`() {
        val sb = PowerCatalogue.build(pkg).first { it.id == PowerId.BATTERY_STANDBY_BUCKET }
        assertTrue("ACTIVE", PowerCatalogue.isHeld(sb, ShellResult(0, "10", "")))
        assertTrue("EXEMPTED (whitelisted → better than active)", PowerCatalogue.isHeld(sb, ShellResult(0, "5", "")))
        assertFalse("WORKING_SET is throttled", PowerCatalogue.isHeld(sb, ShellResult(0, "20", "")))
        assertFalse("non-zero exit never held", PowerCatalogue.isHeld(sb, ShellResult(1, "10", "")))
    }

    @Test
    fun `POST_NOTIFICATIONS is a non-read-backable runtime grant (exit-only)`() {
        val op = PowerCatalogue.build(pkg).first { it.id == PowerId.POST_NOTIFICATIONS }
        assertFalse(op.readBackable)
        assertEquals("pm grant $pkg android.permission.POST_NOTIFICATIONS", op.setCmd)
    }

    @Test
    fun `isHeld is exact-equals for settings and contains-token for appops`() {
        val vpn = PowerCatalogue.build(pkg).first { it.id == PowerId.ALWAYS_ON_VPN }
        assertTrue(PowerCatalogue.isHeld(vpn, ShellResult(0, " $pkg \n", "")))
        assertFalse(PowerCatalogue.isHeld(vpn, ShellResult(0, "other.app", "")))
        assertFalse(PowerCatalogue.isHeld(vpn, ShellResult(1, pkg, ""))) // non-zero exit never held

        val appops = PowerCatalogue.build(pkg).first { it.id == PowerId.BATTERY_BACKGROUND }
        assertTrue(PowerCatalogue.isHeld(appops, ShellResult(0, "RUN_ANY_IN_BACKGROUND: allow", "")))
        assertFalse(PowerCatalogue.isHeld(appops, ShellResult(0, "RUN_ANY_IN_BACKGROUND: ignore", "")))
    }

    // ========================================================================
    // GrantEngine — verify → set → verify, never fakes "protected"
    // ========================================================================

    @Test
    fun `applyAll converges every tier-1 power to held against a happy session`() = runBlocking {
        val store = MemStore()
        val engine = GrantEngine(store) { 1000L }
        val ops = PowerCatalogue.tier1(pkg)

        val outcomes = engine.applyAll(happySession(), ops)

        assertEquals(ops.size, outcomes.size)
        assertTrue("every tier-1 power must verify held", outcomes.all { it.held })
        assertTrue(engine.isFullyProtected(ops))
    }

    @Test
    fun `apply is idempotent - an already-held power runs NO set command`() = runBlocking {
        val session = happySession()
        val engine = GrantEngine(MemStore()) { 1L }
        val vpn = PowerCatalogue.build(pkg).first { it.id == PowerId.ALWAYS_ON_VPN }

        val outcome = engine.apply(session, vpn)

        assertTrue(outcome.held)
        assertFalse("already-held must not re-set", outcome.applied)
        assertEquals("already held", outcome.detail)
        // Only the read-back ran; no `settings put`.
        assertTrue(session.ranCommands.none { it.startsWith("settings put") })
    }

    @Test
    fun `apply sets then verifies when the power is initially absent`() = runBlocking {
        // First read-back is empty/"null" (absent); after the set it reads back the desired value.
        var applied = false
        val session = FakeSession { cmd ->
            when {
                cmd == "settings put secure always_on_vpn_app $pkg" -> { applied = true; "" to 0 }
                cmd == "settings get secure always_on_vpn_app" -> (if (applied) pkg else "null") to 0
                else -> "" to 0
            }
        }
        val engine = GrantEngine(MemStore()) { 1L }
        val vpn = PowerCatalogue.build(pkg).first { it.id == PowerId.ALWAYS_ON_VPN }

        val outcome = engine.apply(session, vpn)

        assertTrue(outcome.held)
        assertTrue(outcome.applied)
        assertEquals("set+verified", outcome.detail)
        assertTrue(session.ranCommands.contains("settings put secure always_on_vpn_app $pkg"))
    }

    @Test
    fun `apply NEVER claims held when the set silently fails the read-back (Done cannot lie)`() = runBlocking {
        // The set "succeeds" (exit 0) but the value never actually changes — the set-in-DB-not-applied
        // ROM bug (plan §7). A read-back is the only honest signal: this must report NOT held.
        val session = FakeSession { cmd ->
            when {
                cmd.startsWith("settings put") -> "" to 0           // claims success
                cmd == "settings get secure always_on_vpn_app" -> "null" to 0 // but value never took
                else -> "" to 0
            }
        }
        val engine = GrantEngine(MemStore()) { 1L }
        val vpn = PowerCatalogue.build(pkg).first { it.id == PowerId.ALWAYS_ON_VPN }

        val outcome = engine.apply(session, vpn)

        assertFalse("read-back mismatch must NOT be reported as held", outcome.held)
        assertEquals("set but read-back mismatch", outcome.detail)
    }

    @Test
    fun `apply records a non-zero set exit as not-held`() = runBlocking {
        val session = FakeSession { cmd ->
            when {
                cmd.startsWith("settings put") -> "Security exception" to 255
                cmd == "settings get secure always_on_vpn_app" -> "null" to 0
                else -> "" to 0
            }
        }
        val engine = GrantEngine(MemStore()) { 1L }
        val vpn = PowerCatalogue.build(pkg).first { it.id == PowerId.ALWAYS_ON_VPN }
        val outcome = engine.apply(session, vpn)
        assertFalse(outcome.held)
    }

    @Test
    fun `a non-read-backable power is held on a clean apply exit only`() = runBlocking {
        val ok = FakeSession { _ -> "" to 0 }
        val denied = FakeSession { _ -> "denied" to 1 }
        val engine = GrantEngine(MemStore()) { 1L }
        val perm = PowerCatalogue.build(pkg).first { it.id == PowerId.POST_NOTIFICATIONS }

        assertTrue(engine.apply(ok, perm).held)
        assertFalse(engine.apply(denied, perm).held)
    }

    @Test
    fun `a power that throws mid-exec is recorded as not-held, never aborts the pass`() = runBlocking {
        val session = happySession().apply { execThrowsOn = "always_on_vpn_lockdown" }
        val engine = GrantEngine(MemStore()) { 1L }
        val ops = PowerCatalogue.tier1(pkg)

        val outcomes = engine.applyAll(session, ops)

        assertEquals("the whole pass still completes", ops.size, outcomes.size)
        val lockdown = outcomes.first { it.id == PowerId.LOCKDOWN }
        assertFalse(lockdown.held)
        // Powers after the throwing one still ran.
        assertTrue(outcomes.any { it.id == PowerId.POST_NOTIFICATIONS })
    }

    @Test
    fun `applyAll persists the per-power map and isFullyProtected reflects a missing power`() = runBlocking {
        val store = MemStore()
        val engine = GrantEngine(store) { 42L }
        val ops = PowerCatalogue.tier1(pkg)

        engine.applyAll(happySession(), ops)
        assertEquals(ops.size, store.states.size)
        assertTrue(store.states.all { it.desired && it.lastResult && it.lastVerified == 42L })

        // Simulate one power slipping (drift): mark standby-bucket as no-longer-held in the store.
        store.states = store.states.map {
            if (it.id == PowerId.BATTERY_STANDBY_BUCKET) it.copy(lastResult = false) else it
        }
        assertFalse("a slipped power means NOT fully protected", engine.isFullyProtected(ops))
    }

    @Test
    fun `revertAll runs every reverse command and clears the persisted protection`() = runBlocking {
        val store = MemStore()
        val engine = GrantEngine(store) { 1L }
        val ops = PowerCatalogue.tier1(pkg)
        engine.applyAll(happySession(), ops)
        assertTrue(engine.isFullyProtected(ops))

        val session = happySession()
        val outcomes = engine.revertAll(session, ops)

        assertEquals(ops.size, outcomes.size)
        assertTrue("revert leaves nothing held", outcomes.none { it.held })
        ops.forEach { op ->
            op.reverseCmd?.let { rc -> assertTrue("reverse must run: $rc", session.ranCommands.contains(rc)) }
        }
        assertTrue("store cleared after revert", store.states.isEmpty())
        assertFalse("no longer protected after revert", engine.isFullyProtected(ops))
    }

    @Test
    fun `revertAll never throws on a single power and still completes the pass`() = runBlocking {
        val session = happySession().apply { execThrowsOn = "always_on_vpn_lockdown" }
        val engine = GrantEngine(MemStore()) { 1L }
        val ops = PowerCatalogue.tier1(pkg)
        val outcomes = engine.revertAll(session, ops)
        assertEquals("the whole revert pass still completes", ops.size, outcomes.size)
        assertTrue("revert never claims held", outcomes.none { it.held })
    }

    // ========================================================================
    // PowerStateCodec — the persistence map, fail-closed
    // ========================================================================

    @Test
    fun `codec round-trips the per-power map`() {
        val states = listOf(
            PowerState(PowerId.ALWAYS_ON_VPN, desired = true, lastVerified = 111L, lastResult = true),
            PowerState(PowerId.LOCKDOWN, desired = true, lastVerified = 222L, lastResult = false),
        )
        val decoded = PowerStateCodec.decode(PowerStateCodec.encode(states))
        assertEquals(states, decoded)
    }

    @Test
    fun `codec decodes empty or null as no powers (fail-closed, never fake protected)`() {
        assertTrue(PowerStateCodec.decode(null).isEmpty())
        assertTrue(PowerStateCodec.decode("").isEmpty())
        assertTrue(PowerStateCodec.decode("   ").isEmpty())
    }

    @Test
    fun `codec skips garbled or unknown-key lines, keeps valid ones`() {
        val raw = buildString {
            append("always_on_vpn|1|100|1\n")  // valid
            append("not_a_power|1|1|1\n")        // unknown key → skipped
            append("lockdown|1|broken|1\n")      // non-numeric ts → skipped
            append("garbage line with no pipes") // malformed → skipped
        }
        val decoded = PowerStateCodec.decode(raw)
        assertEquals(1, decoded.size)
        assertEquals(PowerId.ALWAYS_ON_VPN, decoded.single().id)
    }
}
