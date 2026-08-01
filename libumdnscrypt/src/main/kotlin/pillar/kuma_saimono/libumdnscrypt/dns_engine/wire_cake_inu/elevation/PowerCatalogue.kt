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
 * P11 — the UID-2000 **power set**: the exact, constant, hard-coded list of privileged shell commands
 * the no-root channel may run, each paired with a read-back that PROVES it took, and a reverse command
 * that cleanly UNDOES it on "disable protection" / uninstall (#8 — every power is reversible).
 *
 * This replaces the P6 stub — two display-string-keyed commands run with ZERO read-back
 * (WireCakeInuManager.kt `commandFor`, then `Done` written unconditionally). Here every power is a
 * [PowerOp] with a `setCmd`, a `readBackCmd`, the exact `expected` value, and a `reverseCmd`, so the
 * [GrantEngine] can do `verify → (if mismatch) set → verify` and never claim "protected" without a live
 * read-back (plan §3, §5.6) — and `revertAll` can put the device back exactly as it was.
 *
 * Security model (plan §5) baked into the shape:
 * - **Self-target only** — every command targets [pkg] = `BuildConfig.APPLICATION_ID` (passed in by the
 *   Android caller, never typed in the UI). The catalogue is built per-process from that one constant.
 * - **Hard-coded allow-list** — these are compile-time constants; **no user input is ever concatenated
 *   into a command** (the 6-digit pairing code feeds SPAKE2 crypto only, never a shell string). The only
 *   numeric ever substituted is [appUid] (the app's own `Process.myUid()`), for the Data-Saver bypass.
 * - **Run EVERYTHING in the UID-2000 shell** — never in-process `WRITE_SECURE_SETTINGS` (it throws on
 *   Android 14+: `Neither user 2000 nor current process has GRANT_RUNTIME_PERMISSIONS`). The default
 *   Tier-1 protection NEVER self-grants the app `WRITE_SECURE_SETTINGS` — the shell applies each secure
 *   setting itself. Self-granting it (so the app can self-manage secure settings thereafter — the Shizuku
 *   payoff) is available ONLY as a **Tier-3 Expert opt-in** (`pm grant` via the shell, Socio-approved
 *   2026-06-25); it is never in the default set (enforced by a regression test in PowerSetTest).
 *
 * Pure data + pure string assembly — no Android, no I/O — so the whole catalogue is unit-testable on
 * metal.
 */

/** Stable identity of one privileged power (also the key in the per-power persistence map). */
enum class PowerId(val key: String) {
    ALWAYS_ON_VPN("always_on_vpn"),
    LOCKDOWN("lockdown"),
    LOCKDOWN_ALLOWLIST_EMPTY("lockdown_allowlist_empty"),
    BATTERY_BACKGROUND("battery_background"),
    BATTERY_RUN_IN_BACKGROUND("battery_run_in_background"),
    BATTERY_WAKE_LOCK("battery_wake_lock"),
    BATTERY_DOZE_WHITELIST("battery_doze_whitelist"),
    BATTERY_STANDBY_BUCKET("battery_standby_bucket"),
    POST_NOTIFICATIONS("post_notifications"),
    READ_LOGS("read_logs"),
    DATA_SAVER_BYPASS("data_saver_bypass"),
    WRITE_SECURE_SETTINGS("write_secure_settings"),

    // #63 S2 AMPLIFICATION — pillar-mapped Tier-3 Expert powers (never default). The keys MUST stay in
    // lockstep with Rust `InuPowerId::key()` (torta_core/src/inu/mod.rs) — that is the durable-blob +
    // cross-store contract; the uniffi-generated `InuPowerId` entry is each key uppercased.
    // DNS/privacy sovereignty (GLOBAL OS scope — the one deliberate exception to self-target-only):
    PRIVATE_DNS_OFF("private_dns_off"),
    IGNORE_SYSTEM_DNS("ignore_system_dns"),
    CAPTIVE_PORTAL_OFF("captive_portal_off"),
    WIFI_SCAN_THROTTLE_OFF("wifi_scan_throttle_off"),
    NETWORK_RECOMMENDATIONS_OFF("network_recommendations_off"),
    // Self-target appops (per-pillar amplifiers):
    USAGE_STATS("usage_stats"),
    SCHEDULE_EXACT_ALARM("schedule_exact_alarm"),
    SYSTEM_ALERT_WINDOW("system_alert_window"),
    ACTIVATE_VPN("activate_vpn");

    companion object {
        fun fromKey(value: String?): PowerId? = entries.firstOrNull { it.key == value }
    }
}

/** Which tier a power ships in: Tier-1 powers are applied by default, Tier-3 only on Expert request. */
enum class PowerTier { TIER_1_DEFAULT, TIER_3_EXPERT }

/**
 * One privileged power: the command that grants it, the command that reads its live value back, the
 * value the read-back must equal for the power to count as held, and the command that cleanly undoes it.
 *
 * @param readBackCmd `null` for powers whose effect is not directly read-backable as a settings value
 *   (e.g. `pm grant` of a runtime perm); the GrantEngine treats a clean exit (`ShellResult.ok`) of the
 *   apply command as success for those, with [verifierExit] semantics. Prefer a real read-back wherever
 *   the platform exposes one.
 * @param reverseCmd the command that UNDOES [setCmd] (restores the OS default / deletes the secure key /
 *   revokes the grant). `null` only when the platform offers no clean undo. Consumed by
 *   `GrantEngine.revertAll` on "disable protection" / uninstall so nothing is left enforced.
 * @param driftProne the OS resets this over time (standby-bucket drifts back to a worse bucket) → it
 *   must be re-applied on boot. Persisted with this flag so [GrantEngine] knows what to re-run silently.
 */
data class PowerOp(
    val id: PowerId,
    val tier: PowerTier,
    val setCmd: String,
    val readBackCmd: String?,
    val expected: String,
    val reverseCmd: String? = null,
    val driftProne: Boolean = false,
) {
    /** True when this power is verified by reading a live value back (vs. apply-exit-only). */
    val readBackable: Boolean get() = readBackCmd != null

    /** Does [result] from [readBackCmd] prove the power is held? Trimmed, case-sensitive exact match. */
    fun isHeld(result: ShellResult): Boolean = result.ok && result.value == expected
}

/**
 * Builds the per-process power catalogue. The single source of truth for "the entire list — nothing
 * else is touched" (the transparency card, plan §4). `pkg` is the self-target package id.
 */
object PowerCatalogue {

    /** appops read-backs print "OP: <mode>"; the mode token that means the op is granted. */
    private const val ALLOW_TOKEN = "allow"

    /**
     * Tier-1 DEFAULT powers (applied when the user opts into protection) + Tier-3 EXPERT powers
     * (applied only on explicit Expert request). Order is the apply order; lockdown is applied AFTER
     * always-on so the kill-switch never engages before the VPN target is set (anti-brick).
     *
     * @param appUid the app's own UID (`Process.myUid()`); when non-null the Data-Saver bypass
     *   (UID-keyed `netpolicy`) Tier-3 power is included. Pure: the caller resolves the UID and passes
     *   it in — the catalogue never touches Android. When null, that one power is simply omitted.
     *
     * NOT in this list, by design (plan §3 "NOT shipping"): BIND_VPN_SERVICE (consent-only), self
     * `WRITE_SECURE_SETTINGS` as a default, network ADB (`adb_wifi_enabled`), disabling other packages.
     */
    fun build(pkg: String, appUid: Int? = null): List<PowerOp> = buildList {
        // ---- Tier 1 (default) -----------------------------------------------------------------------
        add(
            PowerOp(
                id = PowerId.ALWAYS_ON_VPN,
                tier = PowerTier.TIER_1_DEFAULT,
                setCmd = "settings put secure always_on_vpn_app $pkg",
                readBackCmd = "settings get secure always_on_vpn_app",
                expected = pkg,
                reverseCmd = "settings delete secure always_on_vpn_app",
            )
        )
        add(
            PowerOp(
                id = PowerId.LOCKDOWN,
                tier = PowerTier.TIER_1_DEFAULT,
                setCmd = "settings put secure always_on_vpn_lockdown 1",
                readBackCmd = "settings get secure always_on_vpn_lockdown",
                expected = "1",
                reverseCmd = "settings put secure always_on_vpn_lockdown 0",
            )
        )
        // Anti-brick safety valve: an explicit-empty lockdown allow-list. Without it, some ROMs treat
        // an absent allow-list as "block everything if the VPN is down" with no escape hatch.
        add(
            PowerOp(
                id = PowerId.LOCKDOWN_ALLOWLIST_EMPTY,
                tier = PowerTier.TIER_1_DEFAULT,
                setCmd = "settings put secure always_on_vpn_lockdown_whitelist \"\"",
                readBackCmd = "settings get secure always_on_vpn_lockdown_whitelist",
                // `settings get` prints "null" for an unset/empty string secure value on stock Android.
                expected = "null",
                reverseCmd = "settings delete secure always_on_vpn_lockdown_whitelist",
            )
        )
        // Battery durability so the VPN service is not killed in the background.
        add(
            PowerOp(
                id = PowerId.BATTERY_BACKGROUND,
                tier = PowerTier.TIER_1_DEFAULT,
                setCmd = "cmd appops set $pkg RUN_ANY_IN_BACKGROUND allow",
                readBackCmd = "cmd appops get $pkg RUN_ANY_IN_BACKGROUND",
                // `cmd appops get` prints e.g. "RUN_ANY_IN_BACKGROUND: allow" → matched as a contains-token
                // by isHeld (see ALLOW_TOKEN); the expected here is the token to look for.
                expected = ALLOW_TOKEN,
                reverseCmd = "cmd appops set $pkg RUN_ANY_IN_BACKGROUND default",
            )
        )
        // Legacy per-app background-run op (belt-and-suspenders for older ROMs that honor the specific op).
        add(
            PowerOp(
                id = PowerId.BATTERY_RUN_IN_BACKGROUND,
                tier = PowerTier.TIER_1_DEFAULT,
                setCmd = "cmd appops set $pkg RUN_IN_BACKGROUND allow",
                readBackCmd = "cmd appops get $pkg RUN_IN_BACKGROUND",
                expected = ALLOW_TOKEN,
                reverseCmd = "cmd appops set $pkg RUN_IN_BACKGROUND default",
            )
        )
        // The VPN service holds wakelocks to keep the tunnel alive; ensure the op is allowed.
        add(
            PowerOp(
                id = PowerId.BATTERY_WAKE_LOCK,
                tier = PowerTier.TIER_1_DEFAULT,
                setCmd = "cmd appops set $pkg WAKE_LOCK allow",
                readBackCmd = "cmd appops get $pkg WAKE_LOCK",
                expected = ALLOW_TOKEN,
                reverseCmd = "cmd appops set $pkg WAKE_LOCK default",
            )
        )
        // Doze battery-optimization exemption (modern `cmd deviceidle` form). The whitelist persists
        // across reboots; read-back via `dumpsys deviceidle whitelist` (a contains-token check on pkg).
        add(
            PowerOp(
                id = PowerId.BATTERY_DOZE_WHITELIST,
                tier = PowerTier.TIER_1_DEFAULT,
                setCmd = "cmd deviceidle whitelist +$pkg",
                readBackCmd = "dumpsys deviceidle whitelist",
                expected = pkg,
                reverseCmd = "cmd deviceidle whitelist -$pkg",
            )
        )
        // standby-bucket DRIFTS back over time → flagged drift-prone for boot re-apply.
        add(
            PowerOp(
                id = PowerId.BATTERY_STANDBY_BUCKET,
                tier = PowerTier.TIER_1_DEFAULT,
                setCmd = "am set-standby-bucket $pkg active",
                readBackCmd = "am get-standby-bucket $pkg",
                // `am get-standby-bucket` prints the numeric bucket; 10 == STANDBY_BUCKET_ACTIVE.
                expected = "10",
                reverseCmd = "am set-standby-bucket $pkg working_set",
                driftProne = true,
            )
        )
        // POST_NOTIFICATIONS is a NORMAL runtime perm → `pm grant` works (no read-back value; exit-only).
        add(
            PowerOp(
                id = PowerId.POST_NOTIFICATIONS,
                tier = PowerTier.TIER_1_DEFAULT,
                setCmd = "pm grant $pkg android.permission.POST_NOTIFICATIONS",
                readBackCmd = null,
                expected = "",
                reverseCmd = "pm revoke $pkg android.permission.POST_NOTIFICATIONS",
            )
        )

        // ---- Tier 3 (Expert request only) -----------------------------------------------------------
        // READ_LOGS lets the in-app query-log / debug surfaces read logcat. Power-user convenience, NOT
        // core protection → Expert-gated. Signature|privileged|development perm → grantable from shell.
        add(
            PowerOp(
                id = PowerId.READ_LOGS,
                tier = PowerTier.TIER_3_EXPERT,
                setCmd = "pm grant $pkg android.permission.READ_LOGS",
                readBackCmd = null,
                expected = "",
                reverseCmd = "pm revoke $pkg android.permission.READ_LOGS",
            )
        )
        // Self-grant WRITE_SECURE_SETTINGS so the app can manage secure settings ITSELF afterward (the
        // Shizuku payoff / self-sufficiency). Socio-approved (2026-06-25) as a Tier-3 EXPERT opt-in ONLY —
        // never a default. Granted via the SHELL (`pm grant`); we never run it in-process (that throws on
        // A14+). Exit-only (no clean read-back); reverse revokes it.
        add(
            PowerOp(
                id = PowerId.WRITE_SECURE_SETTINGS,
                tier = PowerTier.TIER_3_EXPERT,
                setCmd = "pm grant $pkg android.permission.WRITE_SECURE_SETTINGS",
                readBackCmd = null,
                expected = "",
                reverseCmd = "pm revoke $pkg android.permission.WRITE_SECURE_SETTINGS",
            )
        )
        // Data-Saver bypass: keep unrestricted background DATA when Data Saver is on. UID-keyed (netpolicy
        // is by UID, not package) → only included when the caller supplies the app's own UID.
        if (appUid != null) {
            add(
                PowerOp(
                    id = PowerId.DATA_SAVER_BYPASS,
                    tier = PowerTier.TIER_3_EXPERT,
                    setCmd = "cmd netpolicy add restrict-background-whitelist $appUid",
                    readBackCmd = "cmd netpolicy list restrict-background-whitelist",
                    // `netpolicy list` prints the whitelisted UIDs; contains-token on our UID.
                    expected = appUid.toString(),
                    reverseCmd = "cmd netpolicy remove restrict-background-whitelist $appUid",
                )
            )
        }

        // ==== #63 S2 AMPLIFICATION — pillar-mapped Tier-3 Expert powers (never default) ==============
        // These are the "elevation means MORE power" set. All reversible + read-backable, applied only
        // on explicit Expert request. The first block changes GLOBAL OS scope — the ONE deliberate
        // exception to self-target-only, justified by Tortä's DNS/privacy-sovereignty mission (each is
        // fully reversible via revertAll, so no lasting device-state footprint).

        // --- DNS sovereignty: kill every OS-level DNS leak vector -------------------------------------
        // Disable the OS private-DNS (DoT) resolver so the system never resolves queries around the
        // tunnel. Owns the `private_dns_mode` key; reverse restores Android's "opportunistic" default.
        add(
            PowerOp(
                id = PowerId.PRIVATE_DNS_OFF,
                tier = PowerTier.TIER_3_EXPERT,
                setCmd = "settings put global private_dns_mode off",
                readBackCmd = "settings get global private_dns_mode",
                expected = "off",
                reverseCmd = "settings put global private_dns_mode opportunistic",
            )
        )
        // The STRONG DNS-ignore (Socio §S2): purge any pinned DoT hostname on the DISTINCT
        // `private_dns_specifier` key, so no system resolver survives even a mode flip. Put-empty prints
        // "null" on read-back (mirrors the LOCKDOWN_ALLOWLIST_EMPTY anti-brick valve); reverse deletes it.
        add(
            PowerOp(
                id = PowerId.IGNORE_SYSTEM_DNS,
                tier = PowerTier.TIER_3_EXPERT,
                setCmd = "settings put global private_dns_specifier \"\"",
                readBackCmd = "settings get global private_dns_specifier",
                expected = "null",
                reverseCmd = "settings delete global private_dns_specifier",
            )
        )
        // Silence the connectivity-check / captive-portal probe so no HTTP(S) beacon escapes to Google.
        add(
            PowerOp(
                id = PowerId.CAPTIVE_PORTAL_OFF,
                tier = PowerTier.TIER_3_EXPERT,
                setCmd = "settings put global captive_portal_mode 0",
                readBackCmd = "settings get global captive_portal_mode",
                expected = "0",
                reverseCmd = "settings put global captive_portal_mode 1",
            )
        )

        // --- Netstack sovereignty: keep the OS from steering around our userspace stack --------------
        // Disable Wi-Fi scan throttling so network changes are sensed fast → the tunnel re-establishes
        // without a leak gap (helps Rotation + reconnect). Reverse restores the throttle default (1).
        add(
            PowerOp(
                id = PowerId.WIFI_SCAN_THROTTLE_OFF,
                tier = PowerTier.TIER_3_EXPERT,
                setCmd = "settings put global wifi_scan_throttle_enabled 0",
                readBackCmd = "settings get global wifi_scan_throttle_enabled",
                expected = "0",
                reverseCmd = "settings put global wifi_scan_throttle_enabled 1",
            )
        )
        // Stop the OS network-recommendation service from steering connectivity around the netstack.
        add(
            PowerOp(
                id = PowerId.NETWORK_RECOMMENDATIONS_OFF,
                tier = PowerTier.TIER_3_EXPERT,
                setCmd = "settings put global network_recommendations_enabled 0",
                readBackCmd = "settings get global network_recommendations_enabled",
                expected = "0",
                reverseCmd = "settings put global network_recommendations_enabled 1",
            )
        )

        // --- Per-pillar self-target appops (strictly $pkg-keyed) -------------------------------------
        // WARDEN: GET_USAGE_STATS so Warden can see per-app foreground/data usage for sharper verdicts.
        add(
            PowerOp(
                id = PowerId.USAGE_STATS,
                tier = PowerTier.TIER_3_EXPERT,
                setCmd = "cmd appops set $pkg GET_USAGE_STATS allow",
                readBackCmd = "cmd appops get $pkg GET_USAGE_STATS",
                expected = ALLOW_TOKEN,
                reverseCmd = "cmd appops set $pkg GET_USAGE_STATS default",
            )
        )
        // ROTATION: exact-alarm op so server rotations fire on the exact second even under Doze.
        add(
            PowerOp(
                id = PowerId.SCHEDULE_EXACT_ALARM,
                tier = PowerTier.TIER_3_EXPERT,
                setCmd = "cmd appops set $pkg SCHEDULE_EXACT_ALARM allow",
                readBackCmd = "cmd appops get $pkg SCHEDULE_EXACT_ALARM",
                expected = ALLOW_TOKEN,
                reverseCmd = "cmd appops set $pkg SCHEDULE_EXACT_ALARM default",
            )
        )
        // UI: overlay op so the always-on Tortä status bar can float over any screen (the #17 notify-bar).
        add(
            PowerOp(
                id = PowerId.SYSTEM_ALERT_WINDOW,
                tier = PowerTier.TIER_3_EXPERT,
                setCmd = "cmd appops set $pkg SYSTEM_ALERT_WINDOW allow",
                readBackCmd = "cmd appops get $pkg SYSTEM_ALERT_WINDOW",
                expected = ALLOW_TOKEN,
                reverseCmd = "cmd appops set $pkg SYSTEM_ALERT_WINDOW default",
            )
        )
        // ADVANCED VPN: the ACTIVATE_VPN op lets Tortä (re)establish its OWN VpnService with NO consent
        // dialog — seamless always-on across reinstall/reboot/crash (the Shizuku auto-consent pattern).
        // Self-target only; distinct from the manifest BIND_VPN_SERVICE we already hold (never shell-granted).
        add(
            PowerOp(
                id = PowerId.ACTIVATE_VPN,
                tier = PowerTier.TIER_3_EXPERT,
                setCmd = "cmd appops set $pkg ACTIVATE_VPN allow",
                readBackCmd = "cmd appops get $pkg ACTIVATE_VPN",
                expected = ALLOW_TOKEN,
                reverseCmd = "cmd appops set $pkg ACTIVATE_VPN default",
            )
        )
    }

    /** The Tier-1 default subset — what "Lock protection on" applies. */
    fun tier1(pkg: String): List<PowerOp> = build(pkg).filter { it.tier == PowerTier.TIER_1_DEFAULT }

    /** The Tier-3 Expert subset — applied only on explicit Expert request (needs [appUid] for netpolicy). */
    fun tier3(pkg: String, appUid: Int? = null): List<PowerOp> =
        build(pkg, appUid).filter { it.tier == PowerTier.TIER_3_EXPERT }

    /** Drift-prone powers — re-applied silently on boot (plan §3 BootComplete WD branch). */
    fun driftProne(pkg: String): List<PowerOp> = build(pkg).filter { it.driftProne }

    /**
     * Some read-backs are token-contains (appops prints "OP: allow", deviceidle/netpolicy list contain
     * the pkg/uid) rather than exact-equals. This is the canonical "held" check used by [GrantEngine],
     * applied per-op: appops + list-membership are contains-token, all others are exact-equals on
     * trimmed stdout.
     */
    fun isHeld(op: PowerOp, result: ShellResult): Boolean {
        if (!result.ok) return false
        return when (op.id) {
            PowerId.BATTERY_BACKGROUND,
            PowerId.BATTERY_RUN_IN_BACKGROUND,
            PowerId.BATTERY_WAKE_LOCK,
            PowerId.BATTERY_DOZE_WHITELIST,
            PowerId.DATA_SAVER_BYPASS,
            // #63 S2 self-target appops — `cmd appops get` prints "OP: allow" → contains-token check.
            PowerId.USAGE_STATS,
            PowerId.SCHEDULE_EXACT_ALARM,
            PowerId.SYSTEM_ALERT_WINDOW,
            PowerId.ACTIVATE_VPN -> result.value.contains(op.expected)
            // `am set-standby-bucket active` → ACTIVE(10). But once the app is also always-on VPN +
            // doze-whitelisted, the OS upgrades it to EXEMPTED(5) — un-throttled, even better. Measured
            // live on Android 14: the read-back returns 5, so accept BOTH (else an honest full-protection
            // pass false-negatives on standby after the battery powers land).
            PowerId.BATTERY_STANDBY_BUCKET -> result.value == "10" || result.value == "5"
            else -> result.value == op.expected
        }
    }
}
