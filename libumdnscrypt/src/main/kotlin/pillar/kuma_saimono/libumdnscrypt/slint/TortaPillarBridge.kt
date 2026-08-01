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

package pillar.kuma_saimono.libumdnscrypt.slint

import android.content.Context
import android.util.Log
import androidx.annotation.Keep
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.WireCakeInuService
import pillar.kuma_saimono.libumdnscrypt.dns_engine.CentauriCaTrust
import pillar.kuma_saimono.libumdnscrypt.dns_engine.CentauriMirrorManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationSelector
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RuntimeTierManager
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesActionSender
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesServiceActions
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.CENTAURI_SEED_POLICY
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.RESOLVER_ROTATION_CADENCE_MINUTES
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.RESOLVER_ROTATION_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.WARDEN_NATIVE_ENABLED
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper
import pillar.kuma_saimono.libumdnscrypt.vpn.service.WardenDatapathGate
import pillar.kuma_saimono.libumdnscrypt.vpn.tunnel.TunnelController
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import uniffi.torta_core.InuElevationStatus
import uniffi.torta_core.InuEvent
import uniffi.torta_core.InuPowerId
import uniffi.torta_core.InuProvider
import uniffi.torta_core.VerdictEvent
import uniffi.torta_core.WardenAppMode
import uniffi.torta_core.WardenAppRow
import uniffi.torta_core.WardenDomainRule
import uniffi.torta_core.WardenNetClass
import uniffi.torta_core.WardenUniversalToggles

/**
 * THE SLINT ↔ PILLAR DRIVE BRIDGE (SLINT substitution · 2-DRIVE-PILLARS) — the Rust→Kotlin seam
 * behind the SLINT pillar-dashboard ACTION controls, the twin of [TortaSlintBridge] (which drives
 * the HOME master switch). Where the master switch starts/stops the module, THIS bridge drives the
 * per-pillar operations the pure-Rust SLINT rail cannot perform itself (the rotation pool lives in
 * Kotlin's ModulesService authority — the D09 law). `torta_ui`'s `android_main` JNI-calls these
 * statics; each one MIRRORS the canonical UI path (the `.java`/`.kt` fragment being replaced),
 * minus the fragment chrome — the same recipe [TortaSlintBridge] follows for the engine switch.
 *
 * ROTATION (the flagship — the RotationDashboardFragment mirror): · [rotateResolversNow] fires the
 * SAME [ModulesServiceActions.ACTION_ROTATE_RESOLVERS_NOW] intent the fragment's "Rotate Now" fires
 * (RotationDashboardFragment.kt:88) → ModulesService.java:246 `rotateResolversNow()` →
 * ModulesStateLoop.java:326 `RotationManager.rotateNow()` → the real one-shot pool swap (dnscrypt
 * TOML rewrite + restart + the Rust MODE-2 pool) that flips the query.log SERVER column. Guarded
 * exactly like the fragment (engine RUNNING + rotation opted-in) so a tap can never mislead. ·
 * [setRotationEnabled] / [setRotationCadence] write the SAME default-prefs
 * ([RESOLVER_ROTATION_ENABLED] / [RESOLVER_ROTATION_CADENCE_MINUTES]) the fragment writes and the
 * [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationManager] gates on (picked up on the next start /
 * cadence tick). [rotationEnabled] / [rotationCadence] read them straight back so the SLINT
 * toggle/chips render HOST truth (the felt-truth law — no local echo).
 *
 * WHY a static bridge + WHY every guard: identical to [TortaSlintBridge]. The SLINT surface renders
 * on the NativeActivity native thread; the Rust side resolves THIS class through the Activity's
 * classloader and JNI-calls these statics. Every entry point is `@JvmStatic` (the JNI `CallStatic*`
 * path) + `@Keep` (R8 must never rename/strip them — the Rust side hard-codes the class + method
 * names) and FAIL-OPEN (never throw across the JNI boundary; a read failure returns the honest
 * default, never a fabricated success).
 */
@Keep
object TortaPillarBridge {

    private const val TAG = "TORTA_SLINT"

    // OUR stable Rotate-Now result contract the Rust side maps onto the pane's `rotate-status`
    // (rotation.slint): 1 SENT · 2 engine-off · 3 rotation-off · 5 error. Deliberately decoupled
    // from
    // any
    // internal enum so the Rust side never depends on a Kotlin reorder.
    private const val ROTATE_SENT = 1
    private const val ROTATE_NOT_RUNNING = 2
    private const val ROTATE_NOT_ENABLED = 3
    private const val ROTATE_ERROR = 5

    /**
     * Sensible cadence default/floor — mirrors RotationManager (DEFAULT 30 min; <=0 is treated as
     * 30).
     */
    private const val CADENCE_DEFAULT_MIN = 30

    /**
     * How many newest-first Centauri serve rows [liveCentauriServes] bridges to the dashboard's
     * recent-serve constellation. Matches the Slint `RECENT_SERVES_SHOWN` display cap (8) — no point
     * carrying more rows across the JNI wire than the `.slint` pane can render.
     */
    private const val CENTAURI_SERVES_MAX = 8

    /**
     * Fire ONE immediate resolver rotation — the SLINT "Rotate Now" control drives this. Mirrors
     * RotationDashboardFragment.rotateNow (RotationDashboardFragment.kt:88): only when DNSCrypt is
     * RUNNING AND rotation is opted-in (the exact conditions RotationManager.rotateNow guards on)
     * does it send [ModulesServiceActions.ACTION_ROTATE_RESOLVERS_NOW]; otherwise it returns the
     * honest "why not" code so the SLINT pane can say so. Returns the stable status code (never
     * throws; error ⇒ [ROTATE_ERROR]).
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun rotateResolversNow(): Int =
        try {
            val context: Context = App.instance.applicationContext
            val prefs = PreferenceManager.getDefaultSharedPreferences(context)
            val running = ModulesStatus.getInstance().dnsCryptState == ModuleState.RUNNING
            val enabled = prefs.getBoolean(RESOLVER_ROTATION_ENABLED, true)
            when {
                !running -> ROTATE_NOT_RUNNING
                !enabled -> ROTATE_NOT_ENABLED
                else -> {
                    ModulesActionSender.sendIntent(
                        context,
                        ModulesServiceActions.ACTION_ROTATE_RESOLVERS_NOW,
                    )
                    Log.i(TAG, "pillar-drive: ROTATE_RESOLVERS_NOW requested from SLINT")
                    ROTATE_SENT
                }
            }
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive rotateResolversNow failed", t)
            ROTATE_ERROR
        }

    /**
     * Write RESOLVER_ROTATION_ENABLED — the SLINT rotation on/off switch drives this (the
     * fragment's `swRotationEnabled` mirror). The RotationManager picks it up on the next DNSCrypt
     * start / cadence tick.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setRotationEnabled(enable: Boolean) {
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit()
                .putBoolean(RESOLVER_ROTATION_ENABLED, enable)
                .apply()
            Log.i(TAG, "pillar-drive: RESOLVER_ROTATION_ENABLED=$enable from SLINT")
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive setRotationEnabled($enable) failed", t)
        }
    }

    /**
     * Read RESOLVER_ROTATION_ENABLED so the SLINT toggle shows HOST truth. Fail-open to the pref
     * default (true).
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun rotationEnabled(): Boolean =
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .getBoolean(RESOLVER_ROTATION_ENABLED, true)
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive rotationEnabled failed", t)
            true
        }

    /**
     * Write RESOLVER_ROTATION_CADENCE_MINUTES — the SLINT cadence chips drive this (the fragment's
     * `btnCadence5/15/30/60` mirror). Clamped to the manager's floor (a non-positive minute is
     * coerced to 30).
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setRotationCadence(minutes: Int) {
        try {
            val safe = if (minutes <= 0) CADENCE_DEFAULT_MIN else minutes
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit()
                .putInt(RESOLVER_ROTATION_CADENCE_MINUTES, safe)
                .apply()
            Log.i(TAG, "pillar-drive: RESOLVER_ROTATION_CADENCE_MINUTES=$safe from SLINT")
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive setRotationCadence($minutes) failed", t)
        }
    }

    /**
     * Read RESOLVER_ROTATION_CADENCE_MINUTES so the SLINT chips light the live pick. Fail-open
     * to 30.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun rotationCadence(): Int =
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .getInt(RESOLVER_ROTATION_CADENCE_MINUTES, CADENCE_DEFAULT_MIN)
                .let { if (it <= 0) CADENCE_DEFAULT_MIN else it }
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive rotationCadence failed", t)
            CADENCE_DEFAULT_MIN
        }

    /**
     * #22 s5A — write the SERVERS-PER-ROTATION count ([RotationManager.MAX_SERVERS_PREF], the pref
     * [RotationManager]`.readMaxServers` consumes at every pick; "the count slider is not yet wired"
     * doc-debt closed). Floor-only clamp (≥1, NO upper limit — the Socio 2026-07-19 no-limits law)
     * via the pure [RotationManager.geekClampMaxServers]. Fail-open; never throws across JNI.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setRotationMaxServers(count: Int) {
        try {
            val safe = RotationManager.geekClampMaxServers(count)
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit()
                .putInt(RotationManager.MAX_SERVERS_PREF, safe)
                .apply()
            Log.i(TAG, "pillar-drive: rotation max servers=$safe from SLINT (#22 s5A)")
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive setRotationMaxServers($count) failed", t)
        }
    }

    /** #22 s5A — read the SERVERS-PER-ROTATION count for the SLINT stepper. Fail-open to the GEEK default. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun rotationMaxServers(): Int =
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .getInt(RotationManager.MAX_SERVERS_PREF, RotationSelector.GEEK_SAFE_DEFAULT_SERVERS)
                .coerceAtLeast(1)
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive rotationMaxServers failed", t)
            RotationSelector.GEEK_SAFE_DEFAULT_SERVERS
        }

    /**
     * #22 s5A — write the RELAYS-PER-RESOLVER count ([RotationManager.MAX_RELAYS_PREF], consumed by
     * `readMaxRelays` at every pick; 0 = a legal "direct, no relays" choice — the route builder then
     * emits no `via=[…]` lines). Floor-only clamp (≥0, NO upper limit — Socio no-limits law). Fail-open.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setRotationMaxRelays(count: Int) {
        try {
            val safe = RotationManager.geekClampMaxRelays(count)
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit()
                .putInt(RotationManager.MAX_RELAYS_PREF, safe)
                .apply()
            Log.i(TAG, "pillar-drive: rotation max relays=$safe from SLINT (#22 s5A)")
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive setRotationMaxRelays($count) failed", t)
        }
    }

    /** #22 s5A — read the RELAYS-PER-RESOLVER count for the SLINT stepper. Fail-open to the GEEK default. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun rotationMaxRelays(): Int =
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .getInt(RotationManager.MAX_RELAYS_PREF, RotationSelector.GEEK_SAFE_DEFAULT_RELAYS)
                .coerceAtLeast(0)
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive rotationMaxRelays failed", t)
            RotationSelector.GEEK_SAFE_DEFAULT_RELAYS
        }

    /**
     * #22 s5A-ext (Socio: "allow Connection only inside The Tunnel … another kill switch … Enforces
     * the Ignore-system-DNS even more, by not allowing any Internet Connection until the VPN is truly
     * Working and Resolver / Relays are already connected") — write the app-wide KILL SWITCH pref
     * ([TortaeKeys.KILL_SWITCH] "swKillSwitch", the SAME switch the legacy common settings own):
     * ROOT mode enforces it via iptables + the power-off radio cut (ModulesIptablesRules /
     * ModulesReceiver.powerOFFDetected); in no-root VPN mode the OS-side lockdown ("Block connections
     * without VPN" on the app's VPN profile) is the enforcement seat — the pillar hint says so
     * honestly. Fail-open; never throws across JNI.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setTunnelOnlyKillSwitch(on: Boolean) {
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit()
                .putBoolean(TortaeKeys.KILL_SWITCH, on)
                .apply()
            Log.i(TAG, "pillar-drive: tunnel-only kill switch=$on from SLINT (#22 s5A-ext)")
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive setTunnelOnlyKillSwitch($on) failed", t)
        }
    }

    /** #22 s5A-ext — read the tunnel-only KILL SWITCH pref for the SLINT pillar row. Fail-open false. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun tunnelOnlyKillSwitch(): Boolean =
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .getBoolean(TortaeKeys.KILL_SWITCH, false)
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive tunnelOnlyKillSwitch failed", t)
            false
        }


    /**
     * Read RESOLVER_NATIVE_ENABLED so the SLINT toggle shows HOST truth. Fail-open to the pref
     * default (true - resolver ships ON).
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun solverEnabled(): Boolean =
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .getBoolean(TortaeKeys.RESOLVER_NATIVE_ENABLED, true)
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive solverEnabled failed", t)
            true
        }

    /**
     * Read WARDEN_NATIVE_ENABLED so the SLINT toggle shows HOST truth. Fail-open to the pref
     * default (false - warden ships OFF).
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun wardenArmedPreference(): Boolean =
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .getBoolean(TortaeKeys.WARDEN_NATIVE_ENABLED, false)
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive wardenArmedPreference failed", t)
            false
        }

    /**
     * Write NETSTACK_FORWARDER_PREF ("swNetstackForwarder") — the SLINT ENGINE-tab forwarder switch
     * drives this. [TunnelController.start] latches the pref once per start (detachFd is a
     * one-shot; there is no mid-flight rebind), so the write alone applies on the NEXT tunnel start.
     *
     * ★ #3-EXT (netstack ENGAGE-ON-FLIP) — the field bug this cures: the switch wrote the pref and
     * then NOTHING restarted the tunnel, so a live session stayed on its start-time datapath forever
     * (pref ARMED + card DORMANT — the honest-but-useless split the N7 divergence hint renders).
     * The cure is the same lane every other VPN-affecting setting rides: [ServiceVPNHelper.reload]
     * — state-guarded (fires ONLY when the engine/VPN is RUNNING, silent no-op otherwise), it
     * re-establishes the tun (fresh routes: full-capture vs DNS-only picks up the pref in
     * VpnBuilder) and re-runs [TunnelController.start] (the pref latch → `rust.setNetstack` → the
     * forwarder fork). Result: flip = engage, both directions, no manual master-switch cycle.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setNetstackForwarder(enable: Boolean) {
        try {
            val context = App.instance.applicationContext
            PreferenceManager.getDefaultSharedPreferences(context)
                .edit()
                .putBoolean(TunnelController.NETSTACK_FORWARDER_PREF, enable)
                .apply()
            Log.i(TAG, "pillar-drive: ${TunnelController.NETSTACK_FORWARDER_PREF}=$enable from SLINT")
            if (TunnelController.isDatapathLive()) {
                ServiceVPNHelper.reload(
                    "SLINT netstack forwarder flip → engage now ($enable)",
                    context,
                )
            }
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive setNetstackForwarder($enable) failed", t)
        }
    }

    /**
     * Read NETSTACK_FORWARDER_PREF **and** ask the engine whether it can actually forward.
     *
     * ★ 2026-08-01 — this used to return the preference ALONE, and the preference defaults to
     * `true`. The engine `.so` shipped by CI was built `--features mirror` without `netstack`, so
     * `TunnelHandle::set_netstack` (`tunnel/mod.rs:933`) compiled to an EMPTY body, the forwarder
     * thread `"torta-netstack"` never existed (`grep -c -a torta-netstack <so>` = 0 on the .so this
     * repo last produced), and this function cheerfully answered `true`. The switch read ARMED
     * while nothing could forward a single packet.
     *
     * A preference is what the user WANTS. `tunnelNetstackCompiled()` is what this binary CAN DO.
     * They are different facts and only their conjunction is honest, which is exactly what the
     * comment below already demanded: "the SLINT switch must show the same truth the tunnel acts
     * on". It now does.
     *
     * The capability term fails CLOSED. If the engine call throws, we report not-armed rather than
     * inheriting the optimistic pref default — an unreachable engine is not evidence of a working
     * forwarder, and reporting ARMED on a failed query is how the original defect read to a user.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open on the PREF, fail-closed on the capability
    fun netstackForwarderArmed(): Boolean {
        val canForward = try {
            uniffi.torta_core.tunnelNetstackCompiled()
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive tunnelNetstackCompiled failed — reporting NOT armed", t)
            false
        }
        if (!canForward) return false
        return netstackForwarderPreference()
    }

    /** The user's intention, separated from the capability so each can be read on its own. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun netstackForwarderPreference(): Boolean =
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                // ON by default — the SLINT switch must show the same truth the tunnel acts on.
                .getBoolean(TunnelController.NETSTACK_FORWARDER_PREF, true)
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive netstackForwarderArmed failed", t)
            false
        }

    // ------------------------------------------------------------------------------------------------
    // SLINT substitution · 4-FIX-1 — THE LIVE-ENGINE BRIDGE (the .so-split fix).
    //
    // torta_ui is a SEPARATE .so (libtorta_ui.so) that statically links its OWN copy of torta_core;
    // the
    // RUNNING engine's counters live in a DIFFERENT .so (libtorta_core.so). So every SLINT snapshot
    // read
    // its OWN cold spike-local instance -> all zeros even while the resolver was running. These two
    // readers return the RUNNING engine's stats JSON (the SAME uniffi.torta_core process-globals
    // the
    // engine writes, via the [TortaCore] facade — ensureLoaded()+firewalled), which the pure-Rust
    // rail
    // JNI-reads + parses so the ledger/pillars show LIVE truth instead of this .so's cold copy.
    // FAIL-OPEN
    // to an empty string ("" -> the rail keeps the honest OFF state); never fabricates a running
    // count.
    // ------------------------------------------------------------------------------------------------

    /**
     * The RUNNING resolver's stats as a flat JSON string (queries/answered/blocked/cache_hits/
     * serve_stale_served + the D10 Beast budget witness) — the LIVE libtorta_core.so globals, not
     * this .so's cold copy. Empty string on any failure (the rail then holds the honest OFF state).
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun liveResolverStats(): String =
        try {
            TortaCore.resolverStats()
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveResolverStats failed", t)
            ""
        }

    /**
     * The RUNNING Warden firewall's stats as a flat JSON string — composed HERE from the CANONICAL
     * datapath instance ([WardenDatapathGate.snapshot]), the SAME `WardenObject` the Rust tunnel
     * consults when armed (A6). `TortaCore.wardenStats()` is retired from this seam: it read the
     * flat lib.rs GLOBAL the app never arms — a forever-`configured:false` zero feed (the
     * three-engine split-brain the A6 study mapped). Key names hold the torta_ui overlay contract
     * (`feed_warden_shell`'s android block) and ADD the A6 gauges (fail_closed + rule-set/matrix
     * counts) for the firewall-matrix screen. `configured` := the LIVE enforce bit
     * ([WardenDatapathGate.enforced]) — datapath truth, not user intent: TRUE only while the
     * canonical engine actually rules tunnel packets (pre-arm it stays false and the rail keeps the
     * honest disarmed state). Empty string on any failure.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun liveWardenStats(): String =
        try {
            val s = WardenDatapathGate.snapshot() ?: return ""
            "{\"configured\":${WardenDatapathGate.enforced()}," +
                "\"allow\":${s.allow},\"deny\":${s.deny}," +
                "\"deny_by_universal_toggle\":${s.denyByUniversalToggle}," +
                "\"deny_by_app\":${s.denyByApp}," +
                "\"deny_by_universal_rule\":${s.denyByUniversalRule}," +
                "\"deny_by_blocklist\":${s.denyByBlocklist}," +
                "\"policy_loaded\":${s.policyLoaded}," +
                "\"fail_closed\":${s.failClosed}," +
                "\"cache_entries\":${s.cacheEntries}," +
                "\"domain_rules\":${s.domainRules}," +
                "\"cidr_rules\":${s.cidrRules}," +
                "\"universal_rules\":${s.universalRules}," +
                "\"app_rows\":${s.appRows}}"
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveWardenStats failed", t)
            ""
        }

    /**
     * The RUNNING Centauri Mirror status as a flat `"libraries=<N> bytes=<M> full=<bool>"` string —
     * the LIVE libtorta_core.so content-addressed store (the SAME MIRROR_RUNTIME singleton the
     * loopback serves), not this .so's cold spike-local Centauri copy. SLINT substitution ·
     * 4-FIX-2: the CENTAURI pillar dashboard's live cross-.so reader (the gap the round-2 witness
     * flagged — "no live cross-.so reader yet"). Empty string on any failure (the rail then holds
     * the honest cold/OFF Centauri state).
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun liveMirrorStatus(): String =
        try {
            // Prefer the HELD Object snapshot — the manager arms the device-signed `.tcat` into the Centauri
            // OBJECT (its LIVE shared store), NOT the flat MIRROR_RUNTIME singleton, so the Object is the
            // truth the loopback serves. Fall back to the flat status only when no Object armed (base `.so`).
            val snap = CentauriMirrorManager.heldSnapshot()
            if (snap != null) {
                "libraries=" + snap.libraries + " bytes=" + snap.bytes + " full=" + snap.full
            } else {
                TortaCore.mirrorStatus()
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveMirrorStatus failed", t)
            ""
        }

    /**
     * The RUNNING Centauri Mirror's FULL typed snapshot, serialized as a flat-JSON object of
     * `"key":<int>` pairs — the whole CENTAURI dashboard's live cross-`.so` reader (the successor to
     * [liveMirrorStatus], which only carried libraries/bytes/full). The Rust rail reads this off the
     * live [CentauriMirrorManager.heldSnapshot] (the SAME armed Object the loopback serves + the D29
     * observer counts), so EVERY tile — serve-state header + port, THE CDN SAW, PRIVACY WITNESS
     * (served-locally / cdn-fetches / blocked-missing), SERVE QUALITY (exact / fallback), catalog +
     * resolve + rehydrate counters — populates from the running engine instead of this `.so`'s cold
     * spike-local Object. JSON not the space-`key=value` shape because the Rust `json_i32` scanner
     * (`"key":`) is collision-safe (`"bytes"` never matches inside `"served_bytes"`), which the naive
     * `kv_i64` substring scanner is not. Enum ordinals are the `.value` codes the `.slint` decodes
     * (serve-state 0 Stopped·1 Starting·2 Serving·3 Failed; cache-mode 0 leak-on-miss·1 block-missing).
     * `full` is emitted as 0/1. Empty string on any failure ⇒ the rail holds the honest cold read.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun liveCentauriStats(): String =
        try {
            val s = CentauriMirrorManager.heldSnapshot()
            if (s == null) {
                ""
            } else {
                "{" +
                    "\"libraries\":" + s.libraries + "," +
                    "\"bytes\":" + s.bytes + "," +
                    "\"full\":" + (if (s.full) 1 else 0) + "," +
                    "\"capacity\":" + s.capacity + "," +
                    "\"serve_port\":" + s.servePort + "," +
                    "\"serve_state\":" + s.serveState.value + "," +
                    "\"cache_mode\":" + s.cacheMode.value.toInt() + "," +
                    "\"catalog_assets\":" + s.catalogAssets + "," +
                    // ★ #22 slice 2 — the TCAT v2 freshness epoch (0 = unknown, renders as em-dash).
                    "\"catalog_authored_at_secs\":" + s.catalogAuthoredAtSecs + "," +
                    "\"catalog_installs_attempted\":" + s.catalogInstallsAttempted + "," +
                    "\"catalog_installs_verified\":" + s.catalogInstallsVerified + "," +
                    "\"resolve_queries\":" + s.resolveQueries + "," +
                    "\"resolve_hits\":" + s.resolveHits + "," +
                    "\"rehydrates_attempted\":" + s.rehydratesAttempted + "," +
                    "\"rehydrates_verified\":" + s.rehydratesVerified + "," +
                    "\"served_locally\":" + s.servedLocally + "," +
                    "\"served_bytes\":" + s.servedBytes + "," +
                    "\"cdn_fetches\":" + s.cdnFetches + "," +
                    "\"blocked_missing\":" + s.blockedMissing + "," +
                    "\"exact_serves\":" + s.exactServes + "," +
                    "\"fallback_serves\":" + s.fallbackServes + "," +
                    // CP-Centauri-Discovery — the living watch-list totals (the "N watched · M discovered").
                    "\"discovered\":" + s.discovered + "," +
                    "\"discovered_observed\":" + s.discoveredObserved + "," +
                    // CP-Centauri-Absorb — the absorbed-asset index, the promoted-cloak set and the
                    // TLS-distrust ledger all live in THIS (service) engine .so, armed by the tunnel.
                    // torta_ui statically links a second, never-armed torta_core whose absorb index is
                    // empty, so these must cross on the bridge — same law as the discovery totals above.
                    // CP-Centauri-Absorb — the absorbed-asset index, the promoted-cloak set and the
                    // TLS-distrust ledger all live in THIS (service) engine .so, armed by the tunnel.
                    // torta_ui statically links a second, never-armed torta_core whose absorb index is
                    // empty, so these must cross on the bridge — same law as the discovery totals above.
                    "\"absorbed\":" + TortaCore.centauriAbsorbCount().toInt() + "," +
                    "\"promoted_cloaks\":" + TortaCore.centauriPromotedCloakCount().toInt() + "," +
                    "\"tls_distrust\":" + TortaCore.centauriTlsDistrustCount().toInt() + "," +
                    // ...and the roster itself — pipe-delimited top hosts. JSON-string-escaped defensively
                    // (hostnames are [a-z0-9.-] by construction, so this only guards a future classify change).
                    "\"discovered_hosts\":\"" +
                    s.discoveredHosts.replace("\\", "\\\\").replace("\"", "\\\"") + "\"" +
                    "}"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveCentauriStats failed", t)
            ""
        }

    /**
     * The RUNNING Centauri Mirror's recent-serve ring (D29 — newest-first, self-fed by the live
     * loopback observer), serialized in the [liveWardenFlows] docket shape: line 1 `total=<N>`, then
     * up to N newest-first rows of 5 TAB-separated fields `host\tasset\toutcome\tsub\tbytes`. The
     * outcome/substitution are pre-mapped to the SAME short display tokens the `.slint` ServeRow
     * expects (LOCAL/LEAK/BLOCK/MISS/FAIL · exact/newer/older/incompat), so the Rust rail forwards
     * them verbatim. Read off [CentauriMirrorManager.heldRecentServes] (the armed Object's ring — the
     * one the cross-graph dashboard fragment cannot reach directly). Empty string when the bridge is
     * unreachable OR the ring is empty ⇒ the rail renders the honest empty constellation, never a
     * fabricated serve.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun liveCentauriServes(): String =
        try {
            val rows = CentauriMirrorManager.heldRecentServes(CENTAURI_SERVES_MAX)
            if (rows.isEmpty()) {
                ""
            } else {
                val sb = StringBuilder("total=" + rows.size)
                for (r in rows) {
                    val outcome = when (r.outcome) {
                        uniffi.torta_core.CentauriServeOutcome.SERVED_LOCAL -> "LOCAL"
                        uniffi.torta_core.CentauriServeOutcome.LEAKED_THEN_SERVED -> "LEAK"
                        uniffi.torta_core.CentauriServeOutcome.BLOCKED_MISSING -> "BLOCK"
                        uniffi.torta_core.CentauriServeOutcome.NOT_IN_CATALOG -> "MISS"
                        uniffi.torta_core.CentauriServeOutcome.FETCH_FAILED -> "FAIL"
                    }
                    val sub = when (r.substitution) {
                        uniffi.torta_core.CentauriSubstitution.EXACT -> "exact"
                        uniffi.torta_core.CentauriSubstitution.SAFE_NEWER -> "newer"
                        uniffi.torta_core.CentauriSubstitution.RISKY_OLDER -> "older"
                        uniffi.torta_core.CentauriSubstitution.INCOMPATIBLE -> "incompat"
                        // A non-serve miss carries no substitution verdict — emit an empty token so the
                        // SLINT ServeRow renders no phantom label next to a MISS/404.
                        uniffi.torta_core.CentauriSubstitution.NOT_APPLICABLE -> ""
                    }
                    sb.append('\n')
                        .append(r.host).append('\t')
                        .append(r.canonicalName).append('\t')
                        .append(outcome).append('\t')
                        .append(sub).append('\t')
                        .append(r.bytes)
                }
                sb.toString()
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveCentauriServes failed", t)
            ""
        }

    /**
     * The LIVE resolver-rotation cursor, serialized flat for the SLINT Rotation dashboard:
     * `"family=<f>|cadence_secs=<n>|index=<n>|next_flip_secs=<n>|warm=<bool>|hints=<id:ms;id:ms;…>"`.
     * Reads the REAL durable rotation record ([TortaCore.maskSolverRotationSnapshot] over the
     * app-private runtime-tier dir — the SAME record the [RotationManager] persists on every
     * committed pool swap), so the dashboard shows the running engine's ACTUAL rotation state
     * (operator family / diversity index / cadence / warm-RTT wheel) instead of a spike seed. A
     * COLD record (never rotated: no warm resume, empty family, index 0) returns "" — the SLINT
     * rail then keeps the honest DORMANT wheel, NEVER a fabricated family. Empty string on any
     * failure too. SLINT substitution · 4-FIX round 5 (Observation E — the rotation live bridge the
     * witness flagged missing).
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun liveRotationState(): String =
        try {
            val ctx = App.instance.applicationContext
            val dataDir = ctx.applicationInfo.dataDir ?: ("/data/data/" + ctx.packageName)
            val snap =
                TortaCore.maskSolverRotationSnapshot(
                    dataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR
                )
            // A cold record (never rotated) is DORMANT truth, not a state to render — return "" so
            // the
            // rail holds the honest empty wheel (mirrors the Rust `configured` derive).
            val cold =
                snap == null ||
                    (!snap.rehydratedWarm && snap.lastFamily.isEmpty() && snap.rotationIndex == 0L)
            if (cold || snap == null) {
                ""
            } else {
                val hints = snap.rttHints.joinToString(";") { "${it.id}:${it.rttMs}" }
                // The countdown is the LIVE RotationManager schedule — the host-computed value the durable
                // snapshot deliberately cannot carry (torta_core is clock-free: object.rs `next_flip_secs`
                // reports 0 and names the Kotlin host as the producer). `null` (cadence not armed: engine
                // stopped / rotation off) falls back to the durable 0 → the idle "—" dial. While armed the
                // cadence is the LIVE pref too (the timer's authority — a mid-window chip change must move
                // the dial window WITH the countdown, or the slint dial-anomaly guard false-alarms).
                val liveNextFlip = RotationManager.liveNextFlipSecs()
                val cadenceSecs =
                    if (liveNextFlip != null) rotationCadence() * 60L else snap.cadenceSecs
                // #22 s5C — `chain_relays` is the LIVE relay chain (distinct relay names the last
                // committed set's routes ride; RotationManager.liveRelayChain). "" until the first
                // commit of this process — the dashboard's chain tile then reads honest-cold.
                "family=${snap.lastFamily}|cadence_secs=$cadenceSecs" +
                    "|index=${snap.rotationIndex}|next_flip_secs=${liveNextFlip ?: snap.nextFlipSecs}" +
                    "|warm=${snap.rehydratedWarm}|hints=$hints" +
                    "|chain_relays=${RotationManager.liveRelayChain()}"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveRotationState failed", t)
            ""
        }

    /**
     * N6c · The RUNNING tunnel's netstack-forwarder counters for the ENGINE tab's NETSTACK FORWARDER
     * card, serialized flat (the rotation-cursor pipe shape the Rust side parses with
     * `rot_field_str`/`rot_field_i64`/`rot_field_bool`). `""` when no tunnel is live or the crossing
     * faults — the card then renders the honest DORMANT birth state. An `armed=false` record from a
     * LIVE tunnel is real truth (netstack switched off), so it ships as data, not as `""`.
     */
    @JvmStatic
    @Keep
    fun liveForwarderStats(): String =
        try {
            TunnelController.liveForwarderSnapshot()?.let { s ->
                "armed=${s.armed}|live=${s.live}|flows_tcp=${s.flowsTcp}|flows_udp=${s.flowsUdp}" +
                    "|flows_other=${s.flowsOther}|active_flows=${s.activeFlows}" +
                    // ★ #51 N9 — the ECHO lane. `icmp_echo` counts every ping the device sent
                    // through the tun; `icmp_replied` is the ones the REAL destination answered
                    // (a measured round trip, never a synthesized one); `icmp_failed` is the ones
                    // that did not come back. `flows_other` above now EXCLUDES ICMPv4 echo, so it
                    // reads as "protocols we do not carry" rather than "ping was dropped".
                    "|icmp_echo=${s.icmpEcho}|icmp_replied=${s.icmpReplied}" +
                    "|icmp_failed=${s.icmpFailed}" +
                    "|tin_critical=${s.tinCritical}|tin_high=${s.tinHigh}|tin_normal=${s.tinNormal}" +
                    "|dns_answered=${s.dnsAnswered}|paced_flows=${s.pacedFlows}" +
                    "|bytes_up=${s.bytesUp}|bytes_down=${s.bytesDown}" +
                    "|rtt_samples=${s.rttSamples}|stalls=${s.stalls}" +
                    "|warden_denied=${s.wardenDenied}|cwnd_last=${s.cwndLast}" +
                    // ★ #66-A — the Centauri HTTPS seam's three counters. `sni_peeked` is every cloaked
                    // :443 flow we could NAME from its ClientHello; `spliced` is every one carried
                    // end-to-end to the genuine CDN (each of these would have BROKEN under the old
                    // port-blind hairpin); `splice_failed` is unresolved/blocked/dial-failed.
                    "|centauri_sni_peeked=${s.centauriSniPeeked}" +
                    "|centauri_spliced=${s.centauriSpliced}" +
                    "|centauri_splice_failed=${s.centauriSpliceFailed}" +
                    "|centauri_tls_served=${s.centauriTlsServed}|centauri_tls_failed=${s.centauriTlsFailed}" +
                    // ★ N-dial — the two upstream-dial failure counters. Before these existed, a
                    // failed protected dial dropped the flow in silence: the browser saw
                    // ERR_CONNECTION_CLOSED and NOTHING moved on any panel. `protect_failed` means
                    // VpnService.protect() refused the socket (the VPN seam — DNS keeps working
                    // because in-loop DNS is never dialed); `connect_failed` means the destination
                    // was unreachable. Separate counters because they demand opposite fixes.
                    "|dial_protect_failed=${s.dialProtectFailed}" +
                    "|dial_connect_failed=${s.dialConnectFailed}" +
                    // ★ N-dial CLASSIFIED — `dial_connect_failed` above is the TOTAL and keeps its
                    // meaning; these four say WHY. The reason used to be discarded at `Err(_)` in
                    // upstream.rs, so the panel had to label every failure "DIAL unreachable" even
                    // when the peer had actively REFUSED us or the dial had TIMED OUT — three causes
                    // with three opposite fixes, shown as one number. Measured on a real AVD run:
                    // 1321 failures out of 1778 TCP flows, all indistinguishable.
                    //
                    // The four are a TOTAL, DISJOINT partition, so they always sum to the total —
                    // proved for every possible errno in D:/Lean/proofs/Proofs/DialFailure.lean
                    // (`buckets_sum_to_total`), not merely sampled by a test.
                    "|dial_refused=${s.dialRefused}" +
                    "|dial_unreachable=${s.dialUnreachable}" +
                    "|dial_timed_out=${s.dialTimedOut}" +
                    "|dial_other=${s.dialOther}" +
                    // ★ N-dial-UDP — the SAME blind spot on the transport that hides it best.
                    // `connect_udp_protected` kept FIVE silent `None` exits long after the TCP dial had
                    // been taught to witness itself, and the caller logged every one of them as
                    // "forward_tcp: connect_tcp_protected failed" — wrong function, wrong helper.
                    // For a browser UDP is HTTP/3, so a failing QUIC dial usually still renders the page
                    // over the TCP fallback: the symptom is intermittent slowness, not a clean error,
                    // and every log line points at TCP, which is healthy.
                    //
                    // The TOTALS are per-protocol because that separation is the whole diagnostic
                    // (HTTP/3 vs HTTP/2); the four buckets above are SHARED because
                    // `classify_dial_failure` maps an errno and an errno is transport-agnostic. So the
                    // proved invariant widens to
                    //   refused+unreachable+timed_out+other == dial_connect_failed+udp_dial_connect_failed
                    "|udp_dial_protect_failed=${s.udpDialProtectFailed}" +
                    "|udp_dial_connect_failed=${s.udpDialConnectFailed}" +
                    // ★ #65 — the TLS-termination capability must cross THIS bridge, like every counter
                    // above it. `torta_core` is linked TWICE (standalone `libtorta_core.so` + statically
                    // inside `libtorta_ui.so`, task #74), so each .so owns a SEPARATE `CENTAURI_TLS_CONFIG`.
                    // Kotlin arms the one in `libtorta_core.so`; the Slint feed used to read its OWN copy
                    // in-process, which nothing ever arms — so the ENGINE banner claimed "HTTPS serve leg
                    // DISARMED" while the datapath was demonstrably ARMED. Reading it here binds the
                    // banner to the SAME engine that actually terminates the TLS.
                    "|centauri_tls_armed=${TortaCore.centauriTlsArmed()}"
            } ?: ""
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveForwarderStats failed", t)
            ""
        }

    /**
     * ★ #47/#49 N8 · The netstack forwarder's PER-FLOW DOCKET for the FORWARDER dashboard — the
     * per-row twin of [liveForwarderStats], which carries only aggregates. Crosses the SAME bridge
     * for the SAME reason spelled out above: `torta_core` is linked TWICE (task #74), the forwarder
     * runs inside the SERVICE copy, and a Slint feed reading its own statically-linked copy would
     * enumerate an eternally empty docket. Kotlin holds the live controller, so Kotlin is the only
     * honest source.
     *
     * Wire shape — the [liveWardenFlows] row idiom: a `total=<n>` header line, then one TAB-separated
     * row per flow, rows joined by `\n`:
     *
     *   `total=<active_flows>\n<key>\t<proto_tcp>\t<tin>\t<paced>\t<cwnd>\t<up>\t<down>\t<rtt>\t<age>\t<stalls>`
     *
     * `total` is `active_flows` from the aggregate snapshot — the TRUE number of live flows, which
     * can exceed the rows shipped (Rust caps the docket at 256, and [FLOWS_WIRE_CAP] caps the wire).
     * The panel renders "N of M" from the pair instead of implying the list is complete.
     *
     * T20 holds end to end: a row carries the folded CAKE key, its tin and the engine's numbers —
     * never an address, port or hostname. `""` when no tunnel is live or the crossing faults; an
     * EMPTY docket from a LIVE tunnel ships as `total=0` (real "no flows right now" truth), which the
     * panel must not confuse with `""`.
     */
    @JvmStatic
    @Keep
    fun liveForwarderDocket(): String =
        try {
            val rows = TunnelController.liveForwarderFlowDocket()
            if (rows == null) {
                "" // no tunnel live, or the crossing faulted — DORMANT, not "zero flows"
            } else {
                val total = TunnelController.liveForwarderSnapshot()?.activeFlows ?: rows.size.toLong()
                val body =
                    rows.take(FLOWS_WIRE_CAP).joinToString("\n") { r ->
                        // ★ #51 — field 2 is the IANA protocol number (6 TCP · 17 UDP · 1 ICMPv4),
                        // not a TCP flag. The wire SHAPE is unchanged (still ten TAB-separated
                        // fields); only the domain of this one widened, because a boolean cannot
                        // name three protocols without misreporting one.
                        "${r.key}\t${r.proto}\t${r.tin}\t${if (r.paced) 1 else 0}" +
                            "\t${r.cwnd}\t${r.bytesUp}\t${r.bytesDown}\t${r.rttMs}\t${r.ageMs}\t${r.stalls}"
                    }
                if (body.isEmpty()) "total=$total" else "total=$total\n$body"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveForwarderDocket failed", t)
            ""
        }

    /**
     * CP-U · The Underground Layer licence store for the ENGINE tab's UNDERGROUND card: totals,
     * per-risk / per-source lane counts, sequestration + teeth counters, worst-offender rows —
     * serialized flat in the same rotation-cursor pipe shape. The snapshot is a free in-process
     * crossing (`undergroundSnapshot`, no controller instance); the store arms on the SAME
     * resolver boot edge as the cache rehydrate, so a disarmed snapshot means the engine has not
     * booted — DORMANT truth, rendered as `""`. Worst-offender rows arrive TAB-separated from
     * Rust and ship colon-joined (`host:risk:source:hits:points:seq:verdict`, the rttHints idiom),
     * rows joined by `;`. The `trusted=`/`distrusted=` header scalars carry the re-homed Trust
     * bands census (manual pins the user vouched for or condemned).
     */
    @JvmStatic
    @Keep
    fun liveUndergroundStats(): String =
        try {
            val s = uniffi.torta_core.undergroundSnapshot(10u)
            if (!s.armed) {
                ""
            } else {
                val top = s.top.joinToString(";") { it.replace('\t', ':') }
                "armed=${s.armed}|total=${s.total}|recorded=${s.recordedTotal}" +
                    "|recovered=${s.recoveredTotal}|teeth=${s.teethTotal}" +
                    "|sequestrated=${s.sequestrated}|probation=${s.onProbation}" +
                    "|content_lane=${s.contentLane}|content_hot=${s.contentHot}" +
                    "|trusted=${s.trustedTotal}|distrusted=${s.distrustedTotal}" +
                    "|r_analytics=${s.perRisk[0]}|r_ads=${s.perRisk[1]}|r_tracker=${s.perRisk[2]}" +
                    "|r_dnsleak=${s.perRisk[3]}|r_ipleak=${s.perRisk[4]}|r_sonar=${s.perRisk[5]}" +
                    "|r_mitm=${s.perRisk[6]}|r_spoof=${s.perRisk[7]}|r_malware=${s.perRisk[8]}" +
                    "|r_cdn=${s.perRisk[9]}" +
                    "|s_blocklist=${s.perSource[0]}|s_guard=${s.perSource[1]}" +
                    "|s_rebind=${s.perSource[2]}|s_suffix=${s.perSource[3]}" +
                    "|s_centauri=${s.perSource[4]}" +
                    "|ledger_bytes=${s.ledgerBytes}|mean=${s.meanScore}|top=$top" +
                    "|top_score=${s.topByScore.joinToString(";") { it.replace('\t', ':') }}"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveUndergroundStats failed", t)
            ""
        }

    /**
     * CP-U · #14 UNDERGROUND G — the LIVE verdict event stream as a cold [Flow]. Polls the
     * Rust RAM ring (`undergroundEvents`, cap 64: every applied accident, user correction and
     * quarantine retest) every [pollMs] and forwards ONLY seq-fresh rows — `seq` is the
     * monotonic dedup key, so a subscriber sees each event exactly once, in order, however the
     * poll cadence and the ring's own drop-at-cap interleave. Sub-tick live metrics for the
     * H-rung pillar dashboard, no snapshot round-trip. The flow never throws: a crossing
     * failure logs + keeps polling (the ring is RAM-only telemetry — the ledger/corrections
     * mirrors are the durable record). A disarmed store yields no events, DORMANT truth.
     */
    fun undergroundEventsFlow(pollMs: Long = 500L): Flow<VerdictEvent> = flow {
        var lastSeq = -1L
        while (true) {
            try {
                for (e in uniffi.torta_core.undergroundEvents()) {
                    if (e.seq.toLong() > lastSeq) {
                        lastSeq = e.seq.toLong()
                        emit(e)
                    }
                }
            } catch (t: Throwable) {
                Log.e(TAG, "live-bridge undergroundEventsFlow poll failed", t)
            }
            delay(pollMs)
        }
    }

    /**
     * CP-U · #15 UNDERGROUND H — the SAME verdict ring, serialized flat for the SLINT pillar
     * dashboard's live ticker (the UI `.so` polls this static over JNI, the `liveUndergroundStats`
     * idiom): rows `seq:host:verdict:delta:signal:ts` joined by `;`, newest last. The Rust side
     * dedups by `seq`, so re-polling the full ring is cheap + idempotent. `""` = disarmed/empty
     * ring/any throw — DORMANT truth, never fabricated events.
     */
    @JvmStatic
    @Keep
    fun liveUndergroundEvents(): String =
        try {
            uniffi.torta_core.undergroundEvents()
                .joinToString(";") { "${it.seq}:${it.host}:${it.verdict}:${it.scoreDelta}:${it.signal}:${it.ts}" }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveUndergroundEvents failed", t)
            ""
        }

    /**
     * CP-U · #15 UNDERGROUND H — the settings-pane RESET button: forget every learned reputation
     * row + the correction audit log (RAM + NAND alike; the licence ledger is untouched — the
     * engine returns to the compile-time law). True iff anything was actually forgotten.
     */
    @JvmStatic
    @Keep
    fun resetUndergroundReputation(): Boolean =
        try {
            uniffi.torta_core.undergroundReputationReset()
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge resetUndergroundReputation failed", t)
            false
        }

    /** The Underground's runtime law file — `<runtime_tier>/scoring.toml`, the SAME durable dir
     *  the resolver boot edge arms the licence store with ([ResolverRuntime.durableDir]). */
    private fun undergroundScoringFile(): java.io.File {
        val base = App.instance.applicationContext.applicationInfo.dataDir
        return java.io.File(base + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR, "scoring.toml")
    }

    /**
     * CP-U · #15 UNDERGROUND H — read the operator's scoring.toml (penalty weights, licence
     * thresholds, quarantine TTL, detection kill switches) for the settings pane's editor.
     * `""` = no file yet (the compile-time defaults sit) or any throw.
     */
    @JvmStatic
    @Keep
    fun undergroundScoringToml(): String =
        try {
            undergroundScoringFile().takeIf { it.isFile }?.readText() ?: ""
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge undergroundScoringToml failed", t)
            ""
        }

    /**
     * CP-U · #15 UNDERGROUND H — write the settings pane's edited law atomically (tmp + rename;
     * the Rust mtime watcher hot-reloads it on the next armed feed, ≤5 s). A BLANK text deletes
     * the file — back to the compile-time defaults. True iff the NAND write landed.
     */
    @JvmStatic
    @Keep
    fun setUndergroundScoringToml(text: String): Boolean =
        try {
            val f = undergroundScoringFile()
            if (text.isBlank()) {
                if (f.isFile) f.delete() else true
            } else {
                f.parentFile?.mkdirs()
                val tmp = java.io.File(f.parentFile, f.name + ".tmp")
                tmp.writeText(text)
                tmp.renameTo(f) || run { f.delete(); tmp.renameTo(f) }
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setUndergroundScoringToml failed", t)
            false
        }

    /**
     * #16 THE BEAST · The LIVE process-global congestion engine's snapshot for the ENGINE tab's TORTA
     * ENGINE card — the ONE Beast the DNS datapath feeds a measured RTT per live-forwarded resolve
     * (`beast_live_snapshot`, a free in-process crossing, no controller instance), NOT the UI `.so`'s
     * throwaway cold copy. Serialized flat in the same rotation-cursor pipe shape (`mode=…|cwnd=…|
     * base_rtt=…|…|yeah_profile=<0..2>|sched_profile=<0..2>`, profile as its `.value` int so the Rust
     * side maps the label + the Chroma F6 gating). Gated on [TunnelController.isDatapathLive] — the SAME
     * split-brain-cured live-holder [engineTunnelUp] reads: a dead datapath means no DNS RTTs are
     * feeding the Beast, so its window is stale -> DORMANT, rendered `""` (the card then keeps the
     * honest COLD baseline `feed_engine` seeded, `engine-live=false`). `""` fail-open on any throw.
     */
    @JvmStatic
    @Keep
    fun liveBeastStats(): String =
        try {
            if (!TunnelController.isDatapathLive()) {
                ""
            } else {
                val s = uniffi.torta_core.beastLiveSnapshot()
                // #16 THE BEAST (AQM retention) — the live Soft-cake AQM's session high-water: lifetime
                // per-tin throughput + session-peak depth + peak YeAH streaks, fixed 9-slot positional
                // order [thru_c,h,n, peak_c,h,n, peak_zeta,shed,reno]. Overlaid onto the CAKE tin rows so a
                // burst leaves an honest durable mark despite the 100 ms pump drain. `getOrElse` keeps the
                // wire well-formed if the vec ever short-returns (it never does; [0;9] worst case).
                val r = uniffi.torta_core.beastLiveAqmRetention()
                fun ret(i: Int): Long = r.getOrElse(i) { 0L }
                "mode=${s.mode}|slow_start=${s.slowStartActive}|fast_mode=${s.fastMode}" +
                    "|cwnd=${s.cwnd}|window_max=${s.windowMax}" +
                    "|base_rtt=${s.baseRttMs}|udp_rtt=${s.udpBaseRttMs}|floor_rtt=${s.rttBaseFloorMs}" +
                    "|adaptive_timeout=${s.adaptiveTimeoutMs}|pacing=${s.pacingRate}" +
                    "|q_packets=${s.qPackets}|reno=${s.renoCount}|pipeline=${s.pipelineDepth}" +
                    "|q_critical=${s.queueCritical}|q_high=${s.queueHigh}|q_normal=${s.queueNormal}" +
                    "|blue_critical=${s.valveCritical}|blue_high=${s.valveHigh}|blue_normal=${s.valveNormal}" +
                    "|yeah_profile=${s.yeahProfile.value}|sched_profile=${s.schedProfile.value}" +
                    "|thru_critical=${ret(0)}|thru_high=${ret(1)}|thru_normal=${ret(2)}" +
                    "|peak_critical=${ret(3)}|peak_high=${ret(4)}|peak_normal=${ret(5)}" +
                    "|peak_zeta=${ret(6)}|peak_shed=${ret(7)}|peak_reno=${ret(8)}" +
                    // #3-EXT (Beast dashboard live overlay) — the TEN fields the pipe was missing, so the
                    // BEAST pillar DASHBOARD (`bdash-*`, beast.slint BeastPane) renders the SAME live
                    // engine the ENGINE tab witnesses: the busiest-tin valve + the three lifetime CoBALT
                    // counters it consumes today, plus the LineRate depth telemetry (q_smooth EWMA, the
                    // per-family UDP floor, the zeta/shed/valve streaks, soft-memory) so the wire carries
                    // the FULL BeastSnapshot — every metric, no consumer starved (the completeness law).
                    "|blue_prob=${s.valveProb}|shed=${s.shedDropped}|aqm=${s.aqmDropped}" +
                    "|sparse=${s.drrSparseServed}|q_smooth=${s.qSmooth}|udp_floor=${s.udpFloorMs}" +
                    "|zeta_streak=${s.zetaStreak}|shed_streak=${s.shedStreak}" +
                    "|valve_streak=${s.valveStreak}|soft_memory=${s.softMemory}" +
                    // #3-EXT (twin-RTT cure) — the TCP display lane: base EWMA + true-min floor fed by
                    // the netstack forwarder's REAL dial RTTs (SYN→established), the per-family twin of
                    // udp_rtt/udp_floor. 0.0 until the forwarder dials its first TCP flow — the two
                    // families can never again render one shared estimator as two identical tiles.
                    "|tcp_rtt=${s.tcpBaseRttMs}|tcp_floor=${s.tcpFloorMs}" +
                    // ★ #52 — THE SHAPED PLANE: the per-flow FlowShaper return leg. tcp_rtt above is
                    // HANDSHAKE latency (SYN→established); these are STEADY-STATE — the RTT the
                    // engine is actually reacting to under load, and the window each real forwarded
                    // flow's own YeAH brain converged on. shaped_samples is the honesty gate: 0 means
                    // "no flow shaped yet", NOT "the window is zero".
                    "|shaped_rtt=${s.shapedRttMs}|shaped_cwnd=${s.shapedCwndLast}" +
                    "|shaped_cwnd_mean=${s.shapedCwndMean}|shaped_samples=${s.shapedSamples}" +
                    "|shaped_losses=${s.shapedLosses}" +
                    // ★ #22 slice 3 · Rung E — the 5th sch_cake gap on the wire: heads shed by the
                    // SoftCake global-overload law (cake_drop parity + stalest-head tie-break).
                    // Honest zero in normal operation; non-zero = the AQM capacity ceiling FIRED.
                    "|overload_sheds=${s.overloadSheds}"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveBeastStats failed", t)
            ""
        }

    // ------------------------------------------------------------------------------------------------
    // #49 THE BEAST SETTINGS — the Yeah TCP/UDP + Soft-cake/Mochi-Dango tune STAGE + APPLY + READ edges.
    // The SLINT Beast SETTINGS pane STAGES picks/steps here (durable BEAST_* prefs, no engine touch), and
    // Apply COMMITS the staged config onto the ONE live process-global Beast via the [TortaCore] facade.
    // The [ResolverRuntime] restore re-pushes the same prefs on every datapath start (#51 durability law).
    // All fail-open — a bad pref / native fault leaves the compiled default (LineRate × SoftCake). -------
    // ------------------------------------------------------------------------------------------------

    /**
     * STAGE the Beast SETTINGS selection — persist all 7 fields to the durable BEAST_* prefs WITHOUT
     * touching the live engine (that is [applyBeastConfig]'s job). Called on every pick/step so the pane's
     * selection survives VPN-off / app-kill / reboot. Fail-open (a write fault leaves the prior prefs).
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun stageBeastConfig(
        yeah: Int,
        cake: Int,
        preset: Int,
        cycleMs: Int,
        maxWindow: Int,
        freeThreshMilli: Int,
        competeThreshMilli: Int,
    ) {
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit()
                .putInt(TortaeKeys.BEAST_YEAH_PROFILE, yeah)
                .putInt(TortaeKeys.BEAST_CAKE_PROFILE, cake)
                .putInt(TortaeKeys.BEAST_PRESET, preset)
                .putInt(TortaeKeys.BEAST_CYCLE_MS, cycleMs)
                .putInt(TortaeKeys.BEAST_MAX_WINDOW, maxWindow)
                .putInt(TortaeKeys.BEAST_FREE_THRESH, freeThreshMilli)
                .putInt(TortaeKeys.BEAST_COMPETE_THRESH, competeThreshMilli)
                .apply()
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive stageBeastConfig failed", t)
        }
    }

    /**
     * APPLY (commit) the staged Beast config onto the LIVE overhauled Beast + re-persist it. Order is
     * LOAD-BEARING: the two profile swaps re-seed their controllers (a re-seed RESETS the YeAH window to
     * the profile default), so the tunable override runs LAST — otherwise Apply would silently drop the
     * user's window ceiling. cycleMs is persisted (durable + shown) though the overhauled scheduler has no
     * live interval setter yet. Fail-open.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun applyBeastConfig(
        yeah: Int,
        cake: Int,
        cycleMs: Int,
        maxWindow: Int,
        freeThreshMilli: Int,
        competeThreshMilli: Int,
    ) {
        try {
            // re-persist — Apply confirms the staged pick as the applied config the restore re-pushes.
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit()
                .putInt(TortaeKeys.BEAST_YEAH_PROFILE, yeah)
                .putInt(TortaeKeys.BEAST_CAKE_PROFILE, cake)
                .putInt(TortaeKeys.BEAST_CYCLE_MS, cycleMs)
                .putInt(TortaeKeys.BEAST_MAX_WINDOW, maxWindow)
                .putInt(TortaeKeys.BEAST_FREE_THRESH, freeThreshMilli)
                .putInt(TortaeKeys.BEAST_COMPETE_THRESH, competeThreshMilli)
                .apply()
            // COMMIT onto the live Beast — profiles FIRST (they re-seed), tunables LAST (survive the re-seed).
            TortaCore.beastSetYeahProfile(yeah)
            TortaCore.beastSetCakeProfile(cake)
            TortaCore.beastSetTunables(maxWindow, freeThreshMilli, competeThreshMilli)
            Log.i(
                TAG,
                "pillar-drive: Beast applied yeah=$yeah cake=$cake maxWin=$maxWindow " +
                    "free=$freeThreshMilli compete=$competeThreshMilli from SLINT",
            )
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive applyBeastConfig failed", t)
        }
    }

    /**
     * READ the durable staged Beast config for the SETTINGS feed — the BEAST_* prefs as a flat pipe
     * record `yeah=…|cake=…|preset=…|cycle=…|maxwin=…|free=…|compete=…`. Empty string BEFORE the user
     * ever staged a change (the yeah pref still the -1 sentinel) so the Rust feed SEEDS the pane off the
     * live engine snapshot instead (cold agreement, profile-dirty false). Fail-open to "".
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun stagedBeastConfig(): String =
        try {
            val p = PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
            val yeah = p.getInt(TortaeKeys.BEAST_YEAH_PROFILE, -1)
            if (yeah < 0) {
                "" // never staged — the feed seeds off live truth
            } else {
                "yeah=$yeah" +
                    "|cake=${p.getInt(TortaeKeys.BEAST_CAKE_PROFILE, 1)}" +
                    "|preset=${p.getInt(TortaeKeys.BEAST_PRESET, 0)}" +
                    "|cycle=${p.getInt(TortaeKeys.BEAST_CYCLE_MS, 5000)}" +
                    "|maxwin=${p.getInt(TortaeKeys.BEAST_MAX_WINDOW, 16)}" +
                    "|free=${p.getInt(TortaeKeys.BEAST_FREE_THRESH, 1050)}" +
                    "|compete=${p.getInt(TortaeKeys.BEAST_COMPETE_THRESH, 1250)}"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive stagedBeastConfig failed", t)
            ""
        }

    // ------------------------------------------------------------------------------------------------
    // #50 WIRE CAKE INU SETTINGS — the elevation surface WRITE + READ edges (the SIXTH + FINAL per-pillar
    // SETTINGS pane, the #23 umbrella closer). The SLINT Inu SETTINGS pane drives these statics: the three
    // KOTLIN-owned durability prefs (boot-reapply / always-on / provider-pref) STAGE to durable INU_* prefs
    // and read back via [stagedInuConfig]; the grant-flow intents (pair / unpair / per-power desired / manual)
    // route to the REAL WireCakeInu machinery (the DI [WireCakeInuComponent] manager + the typed InuStore).
    // All fail-open — a native fault / absent component leaves the prior state, never a crash. The typed
    // InuState half is fed to the pane from the SAME spike-local store the dashboard reads (SPIKE HONESTY —
    // the running-engine store lands with the single-.so unification); these writes hit the REAL Kotlin store,
    // durable + correct, though not reflected in the spike-fed pane until that unification. ----------------
    // ------------------------------------------------------------------------------------------------

    /**
     * READ the durable Inu SETTINGS prefs for the pane feed — the three KOTLIN-owned durability prefs as a
     * flat pipe record `bootreapply=<0/1>|alwayson=<0/1>|providerpref=<i>`. Always returns the record (unlike
     * the Beast -1 sentinel) — the defaults (off / off / AUTO) are meaningful cold state. Fail-open to "".
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun stagedInuConfig(): String =
        try {
            val p = PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
            // #21 G7-RESIDUAL: boot-reapply reads the TYPED InuState (hdr bit2) off the shared
            // component InuStore (RAM read — the provider rehydrated + absorbed the legacy pref at
            // open). always-on / provider-pref stay Kotlin SETTINGS prefs by design.
            val boot = if (App.instance.wireCakeInuComponent.inuStore.bootReapply()) 1 else 0
            val always = if (p.getBoolean(TortaeKeys.INU_ALWAYS_ON, false)) 1 else 0
            val pref = p.getInt(TortaeKeys.INU_PROVIDER_PREF, 0)
            "bootreapply=$boot|alwayson=$always|providerpref=$pref"
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive stagedInuConfig failed", t)
            ""
        }

    /** STAGE the boot-reapply durability pref (the Genesis #1 gap — re-establish elevation silently at boot). */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun inuBootReapply(on: Boolean) {
        try {
            // #21 G7-RESIDUAL: the arm flips InuState hdr bit2 through the shared component
            // InuStore (control-plane write-through, RAM⊗NAND) — no SharedPreferences.
            App.instance.wireCakeInuComponent.inuStore.setBootReapply(on)
            Log.i(TAG, "pillar-drive: Inu boot-reapply=$on from SLINT (typed InuState bit2)")
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuBootReapply failed", t)
        }
    }

    /**
     * ALWAYS-ON pairing notification — two independent halves. (1) DURABLE: persist the INU_ALWAYS_ON pref
     * (read back by `stagedInuConfig` + survives restart). (2) EFFECT: raise / tear the Shizuku-style FGS
     * pairing notification (`WireCakeInuService`) so the user can type the 6-digit wireless code straight in
     * the shade (RemoteInput) with no app open — the Inu identity. ON → start(); OFF → stop(). A fault in the
     * service half never drops the pref (and vice-versa). Fail-open.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun inuAlwaysOn(on: Boolean) {
        val ctx = App.instance.applicationContext
        try {
            PreferenceManager.getDefaultSharedPreferences(ctx)
                .edit().putBoolean(TortaeKeys.INU_ALWAYS_ON, on).apply()
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuAlwaysOn pref failed", t)
        }
        try {
            if (on) {
                // The user opted into a notification — ask for POST_NOTIFICATIONS (Android 13+) so the
                // in-shade code entry is visible, not suppressed. The Activity hosts the consent dialog.
                TortaSlintActivity.requestNotificationPermission()
                WireCakeInuService.start(ctx)
            } else {
                WireCakeInuService.stop(ctx)
            }
            Log.i(TAG, "pillar-drive: Inu always-on notification=$on from SLINT")
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuAlwaysOn service failed", t)
        }
    }

    /** STAGE the elevation-path preference (0 AUTO · 1 SHIZUKU · 2 SELF-ADB) — coerced into range. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun inuProviderPref(pref: Int) {
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit().putInt(TortaeKeys.INU_PROVIDER_PREF, pref.coerceIn(0, 2)).apply()
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuProviderPref failed", t)
        }
    }

    /**
     * The GENERAL-section boot-autostart pair, read live for the SLINT burger seed — the SAME two prefs
     * `BootCompleteManager` consumes on BOOT_COMPLETED: `swAutostartDNS` (the keep-on-boot gate, the
     * legacy key the receiver reads verbatim) and `TortaeKeys.AUTO_START_DELAY`
     * (`pref_fast_autostart_delay`, stored as a SECONDS STRING — `parseAutostartDelayMs` reads it via
     * `getString`, so the string shape is the wire truth, never an Int). Pipe record `on=<0/1>|delay=<secs>`
     * (the `stagedInuConfig()` shape precedent). Fail-open: any fault returns the honest-off record.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun bootAutostartConfig(): String =
        try {
            val prefs = PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
            val on = if (prefs.getBoolean("swAutostartDNS", false)) 1 else 0
            val delay = (prefs.getString(TortaeKeys.AUTO_START_DELAY, "0") ?: "0")
                .trim().toIntOrNull()?.coerceIn(0, 300) ?: 0
            "on=$on|delay=$delay"
        } catch (e: Throwable) {
            Log.e(TAG, "pillar-drive bootAutostartConfig failed", e)
            "on=0|delay=0"
        }

    /**
     * PERSIST the keep-on-boot gate — `swAutostartDNS`, the exact key `BootCompleteManager` gates
     * autostart on. Fixes the Socio report: the SLINT toggle flipped the prop but never crossed the
     * seam, so the pref stayed false and the tunnel died on reboot. Fail-open.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun setBootAutostart(on: Boolean) {
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit().putBoolean("swAutostartDNS", on).apply()
        } catch (e: Throwable) {
            Log.e(TAG, "pillar-drive setBootAutostart failed", e)
        }
    }

    /**
     * PERSIST the boot delay — `TortaeKeys.AUTO_START_DELAY` as a SECONDS STRING (the
     * `parseAutostartDelayMs` contract; a putInt here would make `getString` throw and the delay
     * silently die — the Socio stepper bug's second half). Clamped 0..300 s host-side too. Fail-open.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun setBootAutostartDelay(secs: Int) {
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit().putString(TortaeKeys.AUTO_START_DELAY, secs.coerceIn(0, 300).toString()).apply()
        } catch (e: Throwable) {
            Log.e(TAG, "pillar-drive setBootAutostartDelay failed", e)
        }
    }

    /**
     * STAGE the Expert reveal — the WIRELESS_DEBUG_EXPERT pref (durable, the existing key) AND the typed
     * InuState.expertEnabled flag (so the collar's expert lens survives once the store is unified). Each
     * half is guarded independently so one fault never drops the other. Fail-open.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun inuExpertToggled(on: Boolean) {
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit().putBoolean(TortaeKeys.WIRELESS_DEBUG_EXPERT, on).apply()
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuExpertToggled pref failed", t)
        }
        try {
            val store = App.instance.wireCakeInuComponent.inuStore
            store.persist(store.rehydrate().copy(expertEnabled = on))
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuExpertToggled store failed", t)
        }
    }

    /**
     * RE-PAIR — surface the Shizuku-style pairing NOTIFICATION (`WireCakeInuService`), the Inu identity: the
     * FGS runs its own discovery and shows the in-shade RemoteInput 6-digit code field, so the user types the
     * wireless code straight in the notification (no app open). The service's onStart already calls
     * `startDiscovery`, so this is the single entry — starting it twice would double-discover. Fail-open.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun inuPairNow() {
        try {
            TortaSlintActivity.requestNotificationPermission()
            WireCakeInuService.start(App.instance.applicationContext)
            Log.i(TAG, "pillar-drive: Inu re-pair — pairing notification raised from SLINT")
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuPairNow failed", t)
        }
    }

    /**
     * UNPAIR — clear the elevation from the typed InuStore (paired=false, IDLE, provider NONE, no powers) +
     * drop the legacy WIRELESS_DEBUG_* prefs. A real durable write (survives restart); the spike-fed pane
     * won't reflect it until store unification. Fail-open on each half.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun inuUnpair() {
        try {
            val store = App.instance.wireCakeInuComponent.inuStore
            store.persist(
                store.rehydrate().copy(
                    paired = false,
                    grantedAt = 0L,
                    provider = InuProvider.NONE,
                    elevationStatus = InuElevationStatus.IDLE,
                    powers = emptyList(),
                    fullyProtected = false,
                )
            )
            store.logEvent(
                InuEvent.REVERT,
                InuProvider.NONE,
                "unpaired from SLINT settings",
                System.currentTimeMillis(),
            )
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuUnpair store failed", t)
        }
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit()
                .putBoolean(TortaeKeys.WIRELESS_DEBUG_GRANTED, false)
                .remove(TortaeKeys.WIRELESS_DEBUG_GRANTED_AT)
                .remove(TortaeKeys.WIRELESS_DEBUG_POWER_MAP)
                .apply()
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuUnpair pref failed", t)
        }
    }

    /**
     * PER-POWER intent — set/revert the `desired` flag on one power in the typed InuStore (the GrantEngine
     * PowerState.desired semantics: intent recorded now, applied on the next elevation). `id` is the Rust
     * InuPowerId.key() (snake_case) → mapped to the enum by uppercase name. A power not yet in the store is a
     * no-op (nothing to intend until it is catalogued at grant). Fail-open.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun inuPowerToggled(id: String, desired: Boolean) {
        try {
            val powerId = runCatching { InuPowerId.valueOf(id.trim().uppercase()) }.getOrNull() ?: run {
                Log.w(TAG, "pillar-drive inuPowerToggled: unknown power id '$id'")
                return
            }
            val store = App.instance.wireCakeInuComponent.inuStore
            val cur = store.rehydrate()
            val powers = cur.powers.map { if (it.id == powerId) it.copy(desired = desired) else it }
            store.persist(cur.copy(powers = powers))
            Log.i(TAG, "pillar-drive: Inu power $powerId desired=$desired from SLINT")
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuPowerToggled failed", t)
        }
    }

    /**
     * MANUAL PAIR (Expert) — log the raw host:port pair intent, then surface the pairing NOTIFICATION so the
     * code is typed in the shade like every other pair entry. The full manual-ENDPOINT feed (dialling the
     * typed host:port instead of mDNS auto-discovery) lands with the Expert wizard wiring; until then the
     * host:port is recorded as intent and the service runs its own discovery. Fail-open on each half.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun inuManualPair(host: String, port: String, code: String) {
        try {
            App.instance.wireCakeInuComponent.inuStore.logEvent(
                InuEvent.PAIR,
                InuProvider.SELF_ADB,
                // the pairing code is NEVER logged (secret) — only its presence, for the diagnostics trail
                "manual $host:$port (expert, code ${if (code.isBlank()) "absent" else "present"})",
                System.currentTimeMillis(),
            )
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuManualPair log failed", t)
        }
        try {
            TortaSlintActivity.requestNotificationPermission()
            WireCakeInuService.start(App.instance.applicationContext)
            Log.i(TAG, "pillar-drive: Inu manual pair — pairing notification raised from SLINT")
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive inuManualPair failed", t)
        }
    }

    /**
     * CP-U · The re-homed Trust bands WRITE edge — manually pin one host's standing in the
     * Underground licence store. `code`: 0 = Neutral (clear the pin, hand the host back to the
     * automatic engine), 1 = Trusted (immune — un-sequester + pin the licence full), 2 =
     * Distrusted (condemned — sequester + force NXDOMAIN at the resolver's teeth). A never-seen
     * host is created, so the user can pre-allow or pre-block ahead of the first witness. Crosses
     * to the SAME `libtorta_core.so` process-globals the snapshot reads (`undergroundSetVerdict`,
     * no controller instance) and persists the ledger atomically. Returns the engine's own landed
     * bit; `false` fail-open on a disarmed store, a blank host, or any throw.
     */
    @JvmStatic
    @Keep
    fun setUndergroundVerdict(host: String, code: Int): Boolean =
        try {
            uniffi.torta_core.undergroundSetVerdict(host, code.toUByte())
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setUndergroundVerdict failed", t)
            false
        }

    /**
     * Wire-row cap for [liveWardenFlows] — MUST track the Rust panel cap (`FLOWS_SHOWN` in
     * torta_ui's `warden_feed`): the parser breaks after that many rows, so emitting more is
     * pure JNI weight. The `total=` header still carries the FULL retained count.
     */
    private const val FLOWS_WIRE_CAP = 12

    /**
     * uid → package-name cache for the flows docket. PackageManager lookups are binder calls —
     * never per-row per-second. A failed/unattributable lookup caches `""` (kernel uids, races);
     * a NEW app install arrives under a NEW uid, so staleness cannot mislabel a flow.
     */
    private val uidAppCache = java.util.concurrent.ConcurrentHashMap<Int, String>()

    private fun appForUid(uid: Int): String {
        if (uid < 0) return "" // -1 = the engine's unresolved sentinel
        return uidAppCache.getOrPut(uid) {
            try {
                App.instance.applicationContext.packageManager
                    .getPackagesForUid(uid)
                    ?.firstOrNull()
                    .orEmpty()
            } catch (t: Throwable) {
                ""
            }
        }
    }

    /**
     * A5 slice-5 · The RUNNING engine's judged-flow ring for the Warden dashboard's LIVE FLOWS
     * docket — the LIVE libtorta_core.so [uniffi.torta_core.connTracker] singleton (the SAME ring
     * the tunnel verdict path feeds), not this .so's cold copy. Wire format (what the Rust
     * `parse_flow_feed` reads): line 1 `total=<retained count>`, then per row — NEWEST FIRST,
     * capped at [FLOWS_WIRE_CAP] — TAB-separated
     * `cc\tapp\tip\tport\tproto\tverdict\tasn\tcarried\tdomain` with `verdict` = the Kotlin
     * enum's `.name` (`ALLOW` / `DENY_BY_FIREWALL` / `DENY_BY_BLOCKLIST`) and `carried` = `1`/`0`
     * (#20 ROW HONESTY — the datapath disposition rides BESIDE the verdict, never inside it: the
     * sync loop judges flows it then drops, and the docket renders those DROPPED, never a false
     * ALLOW). `domain` is the A4 attribution — the qname the engine's verdict seam knew for this
     * flow (`""` = unattributed), LAST on the wire so every #20 column keeps its position; it
     * rides VERBATIM (a domain never contains TAB/newline — the engine canonicalizes qnames).
     * `cc` rides as lowercase ASCII; the FLAG
     * GLYPH is derived Rust-side (`flag_emoji`) so no supplementary-plane codepoint ever crosses
     * JNI. `app` is resolved HERE (PackageManager lives Kotlin-side; the engine ring stamps `""`).
     * An EMPTY ring returns `""` — the docket then renders the honest DORMANT state, never a
     * fabricated flow.
     */
    @JvmStatic
    @Keep
    fun liveWardenFlows(): String =
        try {
            val tracker = uniffi.torta_core.connTracker()
            val total = tracker.count()
            if (total == 0L) {
                ""
            } else {
                val rows =
                    tracker.snapshot().take(FLOWS_WIRE_CAP).joinToString("\n") { r ->
                        val app = appForUid(r.uid).ifEmpty { r.app }
                        "${r.cc}\t$app\t${r.ip}\t${r.port}\t${r.proto}\t${r.verdict.name}\t${r.asn}\t${if (r.carried) 1 else 0}\t${r.domain}"
                    }
                "total=$total\n$rows"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveWardenFlows failed", t)
            ""
        }

    // ── A6 · THE WARDEN ARM + MATRIX SEAM (the firewall-matrix screen's write path) ─────────────
    // The SLINT Warden dashboard stops being a viewer here: ARM switch, universal-toggle chips and
    // the per-app matrix all land on the CANONICAL datapath instance (WardenDatapathGate — the SAME
    // WardenObject the Rust tunnel consults via ask_canonical), through the same chokepoints the
    // boot path uses. GENESIS-pillar-warden.md:285-298 (the firewall-matrix screen).

    /**
     * A6 — is Warden enforcement LIVE on the datapath right now? Reads the canonical instance's
     * enforce bit ([WardenDatapathGate.enforced]) — NOT the pref. Felt-truth law: after a process
     * rebirth the bit is 0 until the next engine start re-asserts it
     * (`ModulesStarterHelper.applyWardenNativeFromPref`); rendering the pref instead would show ON
     * while nothing enforces.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun wardenArmed(): Boolean =
        try {
            WardenDatapathGate.enforced()
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge wardenArmed failed", t)
            false
        }

    /**
     * A6 — the ARM switch write path: persist the intent + arm the datapath NOW. Writes
     * [WARDEN_NATIVE_ENABLED] to default prefs (the SAME pref `applyWardenNativeFromPref` re-asserts
     * on every DNSCrypt start, and the SAME bit the legacy [pillar.kuma_saimono.libumdnscrypt
     * .utils.preferences.TortaeKeys.FIREWALL_ENABLED] key aliases to via PreferenceRepositoryImpl —
     * so the Java datapath (VpnRulesHolder) follows the same intent at its next VPN restart), then
     * pushes the live bit through the boot path's own chokepoint
     * ([VpnUtils.setWardenNativeEnabled] → [WardenDatapathGate.setEnforced] — one process, so the
     * tunnel feels it instantly). Returns the LIVE bit read back (never a local echo): `true` when
     * arming landed, `false` when disarming landed or the push failed.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun setWardenArmed(on: Boolean): Boolean =
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit()
                .putBoolean(WARDEN_NATIVE_ENABLED, on)
                .apply()
            VpnUtils.setWardenNativeEnabled(on)
            WardenDatapathGate.enforced()
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setWardenArmed failed", t)
            false
        }

    /**
     * A6 — the ACTIONABLE app universe for the firewall-matrix screen: the held per-app matrix
     * (TIER 3, UID-sorted) UNIONED with the apps the LIVE FLOWS ring has actually seen (so the
     * matrix is never a chicken-and-egg empty list — an observed app renders as a default `NONE`
     * row the user can tap-cycle into a REAL held row). Wire format (the [liveWardenFlows]
     * recipe): line 1 `total=<row count>`, then per row TAB-separated
     * `uid\tapp\tmode\tmetered\ttemp_allow_until\tarmed` with `mode`/`metered` = the Kotlin enum
     * ORDINALS (= the Rust declaration order the bindgen preserves; the Rust side maps them
     * through its ordinal label helpers) and `armed` = `1` for a HELD engine row / `0` for a
     * flow-derived default (the pane dims those — they enforce nothing yet). `app` is resolved
     * HERE ([appForUid] — PackageManager lives Kotlin-side). No rows at all returns `""` — the
     * pane renders the honest no-rows state.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun liveWardenMatrix(): String =
        try {
            val held = WardenDatapathGate.appRows()
            val heldUids = held.mapTo(HashSet()) { it.uid.toInt() }
            val seen =
                try {
                    uniffi.torta_core
                        .connTracker()
                        .snapshot()
                        .map { it.uid }
                        .distinct()
                        .filter { it >= 0 && it !in heldUids }
                        .sorted()
                } catch (_: Throwable) {
                    emptyList() // ring unreachable ⇒ the held rows still render
                }
            if (held.isEmpty() && seen.isEmpty()) {
                ""
            } else {
                val heldWire =
                    held.map { r ->
                        val uid = r.uid.toInt()
                        "$uid\t${appForUid(uid)}\t${r.mode.ordinal}\t${r.meteredness.ordinal}\t${r.tempAllowUntil}\t1"
                    }
                val seenWire =
                    seen.map { uid ->
                        "$uid\t${appForUid(uid)}\t${WardenAppMode.NONE.ordinal}\t${WardenNetClass.ALLOW.ordinal}\t0\t0"
                    }
                val rows = heldWire + seenWire
                "total=${rows.size}\n${rows.joinToString("\n")}"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveWardenMatrix failed", t)
            ""
        }

    /**
     * A6 — write ONE app's firewall mode (the matrix tap-cycle). `mode` = the [WardenAppMode]
     * ordinal the wire carries (see [liveWardenMatrix]); an existing row's meteredness + temp-allow
     * are PRESERVED (the cycle only moves the mode axis). Cycling back to the all-default row
     * (`NONE` + [WardenNetClass.ALLOW] + no temp-allow) REMOVES the row — the matrix holds
     * exceptions, not the app universe. Returns `true` iff the write landed.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun setWardenAppMode(uid: Int, mode: Int): Boolean =
        try {
            val newMode = WardenAppMode.values().getOrNull(mode)
            if (uid < 0 || newMode == null) {
                false
            } else {
                val existing = WardenDatapathGate.appRows().firstOrNull { it.uid.toInt() == uid }
                val row =
                    WardenAppRow(
                        uid = uid.toUInt(),
                        mode = newMode,
                        meteredness = existing?.meteredness ?: WardenNetClass.ALLOW,
                        tempAllowUntil = existing?.tempAllowUntil ?: 0u,
                    )
                if (
                    row.mode == WardenAppMode.NONE &&
                        row.meteredness == WardenNetClass.ALLOW &&
                        row.tempAllowUntil == 0uL
                ) {
                    WardenDatapathGate.removeAppRow(uid)
                } else {
                    WardenDatapathGate.setAppRow(row)
                }
                true
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setWardenAppMode failed", t)
            false
        }

    // ── W-D (#79) · THE PER-APP INSPECTOR seam (the separate block-ladder popup) ────────────────
    // The inspector browses apps (liveWardenAppFlows), drills into ONE app's WHOLE endpoint list with
    // GEO flags (liveWardenAppDests), and acts on the block-ladder: block one IP / a CIDR family / a
    // whole country (wardenBlockIp + wardenSetGeoBlocks), and block an app on WiFi / on mobile data
    // (wardenSetAppBlockWifi/Mobile, composing the meteredness NetClass). All writes land on the SAME
    // canonical WardenDatapathGate instance the datapath queries, through the proven idioms above.

    /**
     * W-D — the app browser feed: the LIVE flow ring folded BY SOURCE APP
     * ([uniffi.torta_core.connTracker]'s `appFlowSummary`) UNIONED with the held per-app matrix rows
     * (so an app the user blocked but which has no recent flows still renders, and every row carries
     * its BLOCK POSTURE, not just its activity). Wire format (what torta_ui's `parse_inspector_apps`
     * reads): line 1 `total=<row count>`, then per row — most-recently-active first — TAB-separated
     * `uid\tapp\tflows\tallowed\tdenied\tdistinct_ips\tcountries\tup\tdown\tlast_ts\tblock_wifi\tblock_mobile\tmode_ord`
     * with `app` resolved HERE ([appForUid] — PackageManager lives Kotlin-side), `block_wifi`/
     * `block_mobile` = `1`/`0` decomposed from the held row's meteredness ([blocksWifi]/[blocksMobile];
     * absent held row ⇒ `0`/`0`), and `mode_ord` = the [WardenAppMode] ordinal (absent ⇒ `NONE`). No
     * activity AND no held rows returns `""` — the inspector renders the honest DORMANT state.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun liveWardenAppFlows(): String =
        try {
            val summ = uniffi.torta_core.connTracker().appFlowSummary()
            val held = WardenDatapathGate.appRows()
            val heldByUid = held.associateBy { it.uid.toInt() }
            // The union: every uid the ring saw, plus every held-row uid not already there (zero-activity).
            val summUids = summ.mapTo(HashSet()) { it.uid }
            val extraHeld = held.map { it.uid.toInt() }.filter { it >= 0 && it !in summUids }
            if (summ.isEmpty() && extraHeld.isEmpty()) {
                ""
            } else {
                fun posture(uid: Int): Triple<Int, Int, Int> {
                    val row = heldByUid[uid]
                    val m = row?.meteredness ?: WardenNetClass.ALLOW
                    val mode = row?.mode ?: WardenAppMode.NONE
                    return Triple(
                        if (blocksWifi(m)) 1 else 0,
                        if (blocksMobile(m)) 1 else 0,
                        mode.ordinal,
                    )
                }
                val summWire =
                    summ.map { r ->
                        val app = appForUid(r.uid).ifEmpty { r.app }
                        val (bw, bm, mo) = posture(r.uid)
                        "${r.uid}\t$app\t${r.flows}\t${r.allowed}\t${r.denied}\t${r.distinctIps}\t${r.countries}\t${r.up}\t${r.down}\t${r.lastTs}\t$bw\t$bm\t$mo"
                    }
                val extraWire =
                    extraHeld.sorted().map { uid ->
                        val (bw, bm, mo) = posture(uid)
                        "$uid\t${appForUid(uid)}\t0\t0\t0\t0\t0\t0\t0\t0\t$bw\t$bm\t$mo"
                    }
                val rows = summWire + extraWire
                "total=${rows.size}\n${rows.joinToString("\n")}"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveWardenAppFlows failed", t)
            ""
        }

    /**
     * W-D — ONE app's WHOLE endpoint list, folded by destination IP
     * ([uniffi.torta_core.connTracker]'s `appDestinations`), the rows the block-ladder acts on. Wire
     * format (what torta_ui's `parse_inspector_dests` reads): line 1 `total=<row count>`, then per row
     * TAB-separated `ip\tcc\tasn\tdomain\tport\tproto\tdenied\tcarried\thits\tup\tdown\tlast_ts`.
     * `cc` rides as lowercase ASCII; the FLAG GLYPH is derived torta_ui-side (`flag_emoji`) so no
     * supplementary-plane codepoint crosses JNI (the [liveWardenFlows] convention). `denied`/`carried`
     * ride as `1`/`0`. An EMPTY list returns `""`.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun liveWardenAppDests(uid: Int): String =
        try {
            val rows = uniffi.torta_core.connTracker().appDestinations(uid)
            if (rows.isEmpty()) {
                ""
            } else {
                val wire =
                    rows.joinToString("\n") { r ->
                        "${r.ip}\t${r.cc}\t${r.asn}\t${r.domain}\t${r.port}\t${r.proto}\t${if (r.denied) 1 else 0}\t${if (r.carried) 1 else 0}\t${r.hits}\t${r.up}\t${r.down}\t${r.lastTs}"
                    }
                "total=${rows.size}\n$wire"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveWardenAppDests failed", t)
            ""
        }

    /**
     * W-D — the block-ladder's single-IP + CIDR-family rungs: ADD one IP/CIDR block additively on the
     * canonical instance ([WardenDatapathGate.blockIp]). [cidr] is a family-aware string (`"8.8.8.8"`
     * = /32, `"8.8.8.0/24"` = family); [uid] `0` = universal, a real uid = per-app. Returns `true` iff
     * armed. Never throws across JNI.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun wardenBlockIp(uid: Int, cidr: String): Boolean =
        try {
            WardenDatapathGate.blockIp(uid, cidr)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge wardenBlockIp failed", t)
            false
        }

    /**
     * W-D — the "block this country" rung: set (REPLACE) the GEO-family block set from a comma-
     * separated list of ISO-3166 alpha-2 codes ([WardenDatapathGate.setGeoBlocks]). An empty/blank
     * string CLEARS the set (arms zero). Returns the count armed. Never throws across JNI.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun wardenSetGeoBlocks(csv: String): Int =
        try {
            val codes = csv.split(',').map { it.trim() }.filter { it.isNotEmpty() }
            WardenDatapathGate.setGeoBlocks(codes).toInt()
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge wardenSetGeoBlocks failed", t)
            0
        }

    /** W-D — the armed GEO-family block codes ([WardenDatapathGate.geoBlocks]) comma-joined for the
     *  inspector's posture read. Empty string on any failure. Never throws across JNI. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun wardenGeoBlocks(): String =
        try {
            WardenDatapathGate.geoBlocks().joinToString(",")
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge wardenGeoBlocks failed", t)
            ""
        }

    /**
     * W-D — compose the meteredness [WardenNetClass] from the two independent inspector toggles. The
     * engine's binding (`meteredness_blocks`): `Unmetered` blocks Wifi|Vpn (block-WiFi), `Metered`
     * blocks Gsm|Roaming (block-mobile), `Both` blocks all, `Allow` blocks nothing.
     */
    private fun composeNetClass(blockWifi: Boolean, blockMobile: Boolean): WardenNetClass =
        when {
            blockWifi && blockMobile -> WardenNetClass.BOTH
            blockWifi -> WardenNetClass.UNMETERED
            blockMobile -> WardenNetClass.METERED
            else -> WardenNetClass.ALLOW
        }

    private fun blocksWifi(m: WardenNetClass): Boolean =
        m == WardenNetClass.UNMETERED || m == WardenNetClass.BOTH

    private fun blocksMobile(m: WardenNetClass): Boolean =
        m == WardenNetClass.METERED || m == WardenNetClass.BOTH

    /**
     * W-D — set ONE app's meteredness axis by composing the two toggles onto the existing row (read-
     * modify-write, so mode + temp-allow are preserved). [axisWifi] `true` writes the WiFi-block bit,
     * `false` writes the mobile-block bit; [on] is the new value for that bit. Cycling the row back to
     * the all-default (mode NONE + Allow + no temp-allow) REMOVES it (the matrix holds exceptions).
     * Returns `true` iff the write landed.
     */
    private fun setAppNetAxis(uid: Int, axisWifi: Boolean, on: Boolean): Boolean =
        try {
            if (uid < 0) {
                false
            } else {
                val existing = WardenDatapathGate.appRows().firstOrNull { it.uid.toInt() == uid }
                val cur = existing?.meteredness ?: WardenNetClass.ALLOW
                val newClass =
                    if (axisWifi) composeNetClass(on, blocksMobile(cur))
                    else composeNetClass(blocksWifi(cur), on)
                val row =
                    WardenAppRow(
                        uid = uid.toUInt(),
                        mode = existing?.mode ?: WardenAppMode.NONE,
                        meteredness = newClass,
                        tempAllowUntil = existing?.tempAllowUntil ?: 0u,
                    )
                if (
                    row.mode == WardenAppMode.NONE &&
                        row.meteredness == WardenNetClass.ALLOW &&
                        row.tempAllowUntil == 0uL
                ) {
                    WardenDatapathGate.removeAppRow(uid)
                } else {
                    WardenDatapathGate.setAppRow(row)
                }
                true
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setAppNetAxis failed", t)
            false
        }

    /** W-D — block/unblock ONE app on WiFi (the meteredness `Unmetered`/`Both` bit). Returns true iff
     *  the write landed. Never throws across JNI. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun wardenSetAppBlockWifi(uid: Int, on: Boolean): Boolean = setAppNetAxis(uid, true, on)

    /** W-D — block/unblock ONE app on mobile data (the meteredness `Metered`/`Both` bit). Returns true
     *  iff the write landed. Never throws across JNI. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught")
    fun wardenSetAppBlockMobile(uid: Int, on: Boolean): Boolean = setAppNetAxis(uid, false, on)

    /**
     * A6 — the 9 universal DENY toggles (TIER 2) as armed in the LIVE engine, for the chip bar.
     * Wire format: flat `key=0|1` pipes,
     * `new_apps=_|unknown=_|metered=_|lockdown=_|device_lock=_|background=_|udp_ntp=_|http=_|dns_bypass=_`.
     * Empty string on any failure (the pane keeps the honest all-off default).
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun wardenUniversalToggles(): String =
        try {
            val t = WardenDatapathGate.universalToggles()
            if (t == null) {
                ""
            } else {
                fun b(v: Boolean) = if (v) 1 else 0
                "new_apps=${b(t.blockNewApps)}|unknown=${b(t.blockUnknownConns)}|" +
                    "metered=${b(t.blockMetered)}|lockdown=${b(t.lockdown)}|" +
                    "device_lock=${b(t.deviceLock)}|background=${b(t.blockBackground)}|" +
                    "udp_ntp=${b(t.blockUdpNtp)}|http=${b(t.blockHttp)}|" +
                    "dns_bypass=${b(t.blockDnsBypass)}"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge wardenUniversalToggles failed", t)
            ""
        }

    /**
     * A6 — flip ONE universal toggle (the chip tap). Read-mutate-write against the LIVE engine bits
     * (`universalToggles()` → flip `key` → `setUniversalToggles`, the REPLACE setter) so a chip tap
     * never clobbers its 8 siblings. `key` = the wire key from [wardenUniversalToggles]. Returns
     * `true` iff the write landed (`false` on an unknown key / unreachable engine).
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun setWardenUniversalToggle(key: String, on: Boolean): Boolean =
        try {
            val cur = WardenDatapathGate.universalToggles() ?: WardenUniversalToggles()
            val next =
                when (key) {
                    "new_apps" -> cur.copy(blockNewApps = on)
                    "unknown" -> cur.copy(blockUnknownConns = on)
                    "metered" -> cur.copy(blockMetered = on)
                    "lockdown" -> cur.copy(lockdown = on)
                    "device_lock" -> cur.copy(deviceLock = on)
                    "background" -> cur.copy(blockBackground = on)
                    "udp_ntp" -> cur.copy(blockUdpNtp = on)
                    "http" -> cur.copy(blockHttp = on)
                    "dns_bypass" -> cur.copy(blockDnsBypass = on)
                    else -> null
                }
            if (next == null) {
                false
            } else {
                WardenDatapathGate.setUniversalToggles(next)
                true
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setWardenUniversalToggle failed", t)
            false
        }

    // ---- WARDEN ||| SETTINGS (2-FEED-Warden SETTINGS): the control WRITES the in-shell settings pane rides.
    // Each targets the CANONICAL live WardenObject via WardenDatapathGate (the SAME instance the datapath
    // consults) — the pane edits the running firewall, never a detached copy. The (uid)-only matrix callbacks
    // read-cycle-write here so the SLINT row need not thread the enum ordinal. Fail-open: any throwable degrades
    // to `false` (the pane's next refresh re-reads HOST truth and snaps the control back). ----

    /** The per-app mode tap-cycle order (user-facing, NOT the wire ordinal): the useful arms in sequence. */
    private val WARDEN_MODE_CYCLE =
        listOf(
            WardenAppMode.NONE,
            WardenAppMode.ISOLATE,
            WardenAppMode.UNTRACKED,
            WardenAppMode.BYPASS_UNIVERSAL,
            WardenAppMode.BYPASS_DNS_FIREWALL,
            WardenAppMode.EXCLUDE,
        )

    /** The meteredness tap-cycle order: ALLOW (no block) → block cellular → block Wi-Fi → block both → wrap. */
    private val WARDEN_METERED_CYCLE =
        listOf(
            WardenNetClass.ALLOW,
            WardenNetClass.METERED,
            WardenNetClass.UNMETERED,
            WardenNetClass.BOTH,
        )

    /** A tap-pause temp-allows the app for this window (epoch-ms expiry the datapath honors, then clears). */
    private const val WARDEN_PAUSE_TTL_MS = 3_600_000L // 1 hour

    /**
     * Write ONE matrix row through the gate, holding the "matrix holds EXCEPTIONS, not the app universe"
     * invariant: an all-default row (`NONE` + `ALLOW` + no temp-allow) REMOVES the row instead of storing an
     * inert one (the exact rule [setWardenAppMode] follows). Returns `true` iff the write path ran.
     */
    private fun writeWardenAppRow(
        uid: Int,
        mode: WardenAppMode,
        metered: WardenNetClass,
        tempAllow: ULong,
    ): Boolean {
        if (uid < 0) return false
        val row =
            WardenAppRow(
                uid = uid.toUInt(),
                mode = mode,
                meteredness = metered,
                tempAllowUntil = tempAllow,
            )
        if (
            row.mode == WardenAppMode.NONE &&
                row.meteredness == WardenNetClass.ALLOW &&
                row.tempAllowUntil == 0uL
        ) {
            WardenDatapathGate.removeAppRow(uid)
        } else {
            WardenDatapathGate.setAppRow(row)
        }
        return true
    }

    /**
     * SETTINGS · the POSTURE toggle — arm/disarm the fail-CLOSED bit (the Nerd knob: on a policy-load miss,
     * fail-closed DENIES; fail-open ALLOWS). Writes the canonical instance. Fail-open on a fault.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun setWardenFailClosed(on: Boolean): Boolean =
        try {
            WardenDatapathGate.setFailClosed(on)
            true
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setWardenFailClosed failed", t)
            false
        }

    /**
     * SETTINGS · cycle ONE app's firewall MODE (the matrix mode tap). Reads the current held row (or the
     * default `NONE` for a flow-derived app), advances one step in [WARDEN_MODE_CYCLE], and writes —
     * PRESERVING the row's meteredness + temp-allow (the cycle moves only the mode axis). Returns `true`
     * iff the write landed.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun cycleWardenAppMode(uid: Int): Boolean =
        try {
            if (uid < 0) {
                false
            } else {
                val existing = WardenDatapathGate.appRows().firstOrNull { it.uid.toInt() == uid }
                val cur = existing?.mode ?: WardenAppMode.NONE
                val idx = WARDEN_MODE_CYCLE.indexOf(cur).let { if (it < 0) 0 else it }
                val next = WARDEN_MODE_CYCLE[(idx + 1) % WARDEN_MODE_CYCLE.size]
                writeWardenAppRow(
                    uid,
                    next,
                    existing?.meteredness ?: WardenNetClass.ALLOW,
                    existing?.tempAllowUntil ?: 0uL,
                )
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge cycleWardenAppMode failed", t)
            false
        }

    /**
     * SETTINGS · cycle ONE app's METEREDNESS block (the matrix metered tap). Advances [WARDEN_METERED_CYCLE],
     * PRESERVING mode + temp-allow. Returns `true` iff the write landed.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun cycleWardenAppMetered(uid: Int): Boolean =
        try {
            if (uid < 0) {
                false
            } else {
                val existing = WardenDatapathGate.appRows().firstOrNull { it.uid.toInt() == uid }
                val cur = existing?.meteredness ?: WardenNetClass.ALLOW
                val idx = WARDEN_METERED_CYCLE.indexOf(cur).let { if (it < 0) 0 else it }
                val next = WARDEN_METERED_CYCLE[(idx + 1) % WARDEN_METERED_CYCLE.size]
                writeWardenAppRow(
                    uid,
                    existing?.mode ?: WardenAppMode.NONE,
                    next,
                    existing?.tempAllowUntil ?: 0uL,
                )
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge cycleWardenAppMetered failed", t)
            false
        }

    /**
     * SETTINGS · toggle ONE app's PAUSE (temp-allow). Off → temp-allow for [WARDEN_PAUSE_TTL_MS] (the app's
     * per-app denies are suspended until the wall-clock passes the expiry); on → clear it. PRESERVES mode +
     * meteredness. Returns `true` iff the write landed.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun toggleWardenAppPause(uid: Int): Boolean =
        try {
            if (uid < 0) {
                false
            } else {
                val existing = WardenDatapathGate.appRows().firstOrNull { it.uid.toInt() == uid }
                val cur = existing?.tempAllowUntil ?: 0uL
                val next =
                    if (cur != 0uL) {
                        0uL
                    } else {
                        (System.currentTimeMillis() + WARDEN_PAUSE_TTL_MS).toULong()
                    }
                writeWardenAppRow(
                    uid,
                    existing?.mode ?: WardenAppMode.NONE,
                    existing?.meteredness ?: WardenNetClass.ALLOW,
                    next,
                )
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge toggleWardenAppPause failed", t)
            false
        }

    /**
     * SETTINGS · arm ONE universal DENY DOMAIN rule (TIER 4, `uid=0`). The engine canonicalizes + RFC-1123
     * validates on insert; `wildcard` = the `*.domain` apex+subdomain form. Returns `true` iff the rule
     * PASSED the gate (the armed-rule count the pane header reads then reflects it). Fail-open on a fault.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun addWardenDomainRule(text: String, wildcard: Boolean): Boolean =
        try {
            val domain = text.trim()
            if (domain.isEmpty()) {
                false
            } else {
                val report =
                    WardenDatapathGate.installDomainRules(
                        listOf(WardenDomainRule(domain = domain, uid = 0u, wildcard = wildcard))
                    )
                (report?.accepted ?: 0L) > 0L
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge addWardenDomainRule failed", t)
            false
        }

    /**
     * SETTINGS · arm ONE universal DENY CIDR rule (TIER 4, `uid=0`, `BLOCK`). W-C (#86): rides the SAME
     * family-aware ADDITIVE path the per-app inspector uses — [WardenDatapathGate.blockIp] -> `block_ip` ->
     * `add_cidr_rule` — so it accepts BOTH `a.b.c.d[/prefix]` AND IPv6 `xxxx::yyyy[/prefix]` (a bare IP =
     * `/32` v4 or `/128` v6; the Rust `CidrMatch::parse` validates the family + prefix). The retired path
     * parsed v4-only into a 32-bit net AND used install-REPLACE (which CLOBBERED inspector-armed rules);
     * `blockIp` is additive, so a settings-add now ACCRETES rather than nukes. A malformed / empty string
     * is REJECTED (`false`, never a bad rule). Returns `true` iff the rule armed. Fail-open on a fault.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun addWardenCidrRule(text: String): Boolean =
        try {
            val cidr = text.trim()
            if (cidr.isEmpty()) false else WardenDatapathGate.blockIp(0, cidr)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge addWardenCidrRule failed", t)
            false
        }

    // W-C (#86): netToDotted + protoLabel retired — the CIDR row TEXT (v4 AND v6, incl proto/port) is now
    // formatted in Rust (WardenObject::format_cidr_rule) and arrives pre-shaped via cidrRulesWire().

    /**
     * M2 · SETTINGS — the armed BLOCK rule LIST for the pane's per-rule editor. Reads the LIVE engine's
     * enumerated rules (domain: trie terminals + globs, in (uid, domain) order; then CIDR: v4 rules, in
     * most-specific-first order) through the gate. Wire: a `total=<N>` header then one tab-row per rule —
     * `kind\ttext\tscope\twildcard(0|1)\tstatus` — DOMAINS FIRST, then CIDRS, so the flat row index the
     * SLINT `for entry[idx]` yields maps 1:1 onto [removeWardenRule]'s enumerate-drop-reinstall index.
     * `""` when no rule is armed (the pane renders the honest "none armed" empty-state). Fail-open ⇒ `""`.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun liveWardenRules(): String =
        try {
            val domains = WardenDatapathGate.domainRules()
            // W-C (#86): the v6-CAPABLE wire — cidrRules() (v4 u32) would DROP any v6 rule, so a v6 host
            // block armed from the inspector never rendered here. cidrRulesWire() emits v4 AND v6 rows,
            // already formatted "<uid>\t<text>\t<status>", in the SAME order removeCidrRuleAt indexes.
            val cidrRows = WardenDatapathGate.cidrRulesWire()
            if (domains.isEmpty() && cidrRows.isEmpty()) {
                ""
            } else {
                fun scope(uid: UInt) = if (uid == 0u) "universal" else "uid ${uid.toInt()}"
                val domainWire =
                    domains.map { r ->
                        val wc = if (r.wildcard) 1 else 0
                        "domain\t${r.domain}\t${scope(r.uid)}\t$wc\tBLOCK"
                    }
                val cidrWire =
                    cidrRows.map { row ->
                        val parts = row.split('\t')
                        val uid = parts.getOrNull(0)?.toUIntOrNull() ?: 0u
                        val text = parts.getOrElse(1) { "" }
                        val status = parts.getOrElse(2) { "BLOCK" }
                        "cidr\t$text\t${scope(uid)}\t0\t$status"
                    }
                val rows = domainWire + cidrWire
                "total=${rows.size}\n${rows.joinToString("\n")}"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge liveWardenRules failed", t)
            ""
        }

    /**
     * M2 · SETTINGS — REMOVE the armed rule at flat list index [idx] (the SLINT `remove-rule(idx)` tap).
     * The engine's install REPLACES the whole set, so a remove is enumerate → drop index → re-install the
     * remainder. The flat index space matches [liveWardenRules]: `0..<domainCount` are DOMAIN rules,
     * `domainCount..<domainCount+cidrCount` are CIDR rules. Both directions read the SAME deterministic
     * enumerators, so the index the pane rendered still points at the same rule. Returns `true` iff a rule
     * was removed. Fail-open ⇒ `false`.
     */
    @JvmStatic
    @Keep
    @Suppress(
        "TooGenericExceptionCaught"
    ) // deliberate fail-open: never throw across the JNI boundary
    fun removeWardenRule(idx: Int): Boolean =
        try {
            if (idx < 0) {
                false
            } else {
                val domains = WardenDatapathGate.domainRules()
                // W-C (#86): count via the v6-capable wire (matches liveWardenRules' flat index space).
                val cidrCount = WardenDatapathGate.cidrRulesWire().size
                when {
                    idx < domains.size -> {
                        val remaining = domains.filterIndexed { i, _ -> i != idx }
                        WardenDatapathGate.installDomainRules(remaining)
                        true
                    }
                    idx < domains.size + cidrCount -> {
                        // v6-capable index-remove: NO enumerate-drop-reinstall (the v4-only installCidrRules
                        // wire could not re-carry a v6 rule). removeCidrRuleAt walks the SAME rules() order
                        // cidrRulesWire renders, so the pane's flat index points at the same rule.
                        WardenDatapathGate.removeCidrRuleAt((idx - domains.size).toUInt())
                    }
                    else -> false
                }
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge removeWardenRule failed", t)
            false
        }

    // ---- CENTAURI ||| SETTINGS: the 3 control WRITES + 2 control-plane READS the in-shell settings pane
    // rides (the Rust rail JNI-calls these; each targets the LIVE armed engine — the held Centauri Object /
    // the flat resolver cloak / the durable SeedPolicy pref — NOT this bridge's own state). Fail-open: any
    // throwable degrades to a no-op / honest sentinel, never a throw across the JNI boundary.
    // (No setCentauriStrict / centauriInstallCatalog: the CROWN is always-on LeakOnMiss — BlockMissing would
    //  freeze the growing encyclopedia — and the signed catalog auto-arms on every engine start. Removed
    //  end-to-end so privacy is not opt-in and the catalog is never a user chore.) ----

    /**
     * SETTINGS · arm/disarm the P9 DNS-plane cloak (the flat resolver atomic the armed resolver consults
     * per-query) + record it for the dashboards. Fail-open — a fault leaves the cloak in its prior state.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never throw across the JNI boundary
    fun setCentauriCloak(on: Boolean) {
        try {
            CentauriMirrorManager.setCloak(on)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setCentauriCloak failed", t)
        }
    }

    // ---- 2-FEED-MaskSolver SETTINGS (#47): the in-shell MaskSolverSettingsPane's 15 controls drive these
    // @JvmStatic seams (the torta_ui engine_bridge JNI-calls them by name), each forwarding straight to the
    // matching `TortaCore.resolverSet*` UniFFI export — a live process-global the ARMED resolver
    // (libtorta_core.so) consults per query. The 7 booleans arm instantly on tap; the 5 cache/deadline
    // ints commit on the pane's reapply (each is also a real live setter, so the change bites the running
    // engine + records a durable intent that survives the next reconfigure/rotation). Fail-open — a fault
    // leaves the control in its prior state, never a throw across the JNI boundary.
    //
    // #51 DURABILITY: the live global is process-scoped — it resets to the Rust compiled default on every
    // engine (.so) restart (VPN-off / app-kill / reboot). So each setter ALSO mirrors the user's pick to a
    // SharedPreference; ResolverRuntime.applyDnsmasqTogglesFromPref re-pushes them on the next configure
    // (the rotation-cadence durability law, applied to the engine plane). The pref write comes FIRST (its
    // own fail-safe helper) so the durable INTENT lands even if the live JNI call throws. Six knobs reuse
    // the existing DNSMASQ_*/DNS_REBIND_PROTECTION keys the classic Dnsmasq dashboard already restores
    // (single source of truth — both UIs stay consistent); the other six use the RESOLVER_* keys (#51). ----

    /** Write a boolean Expert-toggle pref (durable intent). Fail-safe — never throws across the JNI seam. */
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    private fun putBoolPref(key: String, v: Boolean) {
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit().putBoolean(key, v).apply()
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive putBoolPref($key) failed", t)
        }
    }

    /** Write an int Expert-knob pref (durable intent). Fail-safe — never throws across the JNI seam. */
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    private fun putIntPref(key: String, v: Int) {
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .edit().putInt(key, v).apply()
        } catch (t: Throwable) {
            Log.e(TAG, "pillar-drive putIntPref($key) failed", t)
        }
    }

    /** SOLVE resilient ladder (`--solve-ladder`) — the verdict-gated, health-ordered retry ladder. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverSolveLadder(on: Boolean) {
        putBoolPref(TortaeKeys.RESOLVER_SOLVE_LADDER, on) // #51 durable intent, then the live push
        try {
            TortaCore.setSolveLadder(on)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverSolveLadder failed", t)
        }
    }

    /** `--all-servers` — race every upstream concurrently vs the strict-order ladder. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverAllServers(on: Boolean) {
        putBoolPref(TortaeKeys.DNSMASQ_ALL_SERVERS, on) // #51 durable (shared with the classic dnsmasq dashboard)
        try {
            TortaCore.setAllServers(on)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverAllServers failed", t)
        }
    }

    /** `--stop-dns-rebind` — enforce (drop) public names resolving to a private IP. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverRebindEnforce(on: Boolean) {
        putBoolPref(TortaeKeys.DNS_REBIND_PROTECTION, on) // #51 durable (shared with the common rebind toggle)
        try {
            TortaCore.setRebindEnforce(on)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverRebindEnforce failed", t)
        }
    }

    /** `--bogus-priv` — NXDOMAIN reverse (PTR) lookups of RFC1918/ULA/link-local IPs locally. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverBogusPriv(on: Boolean) {
        putBoolPref(TortaeKeys.DNSMASQ_BOGUS_PRIV, on) // #51 durable (shared with the classic dnsmasq dashboard)
        try {
            TortaCore.setBogusPriv(on)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverBogusPriv failed", t)
        }
    }

    /** `--proxy-dnssec` — pass the upstream AD bit through on a live forward (awareness, never validation). */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverProxyDnssec(on: Boolean) {
        putBoolPref(TortaeKeys.DNSMASQ_PROXY_DNSSEC, on) // #51 durable (shared with the classic dnsmasq dashboard)
        try {
            TortaCore.setProxyDnssec(on)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverProxyDnssec failed", t)
        }
    }

    /** `--never-forward` — keep RFC 6761/8375 special-use + private PTR names LOCAL (never egress). */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverNeverForward(on: Boolean) {
        putBoolPref(TortaeKeys.DNSMASQ_NEVER_FORWARD, on) // #51 durable (shared with the classic dnsmasq dashboard)
        try {
            TortaCore.setNeverForward(on)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverNeverForward failed", t)
        }
    }

    /** `--cache-rr` — cache SVCB/HTTPS answer records (speeds modern sites). */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverCacheRr(on: Boolean) {
        putBoolPref(TortaeKeys.DNSMASQ_CACHE_RR, on) // #51 durable (shared with the classic dnsmasq dashboard)
        try {
            TortaCore.setCacheRr(on)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverCacheRr failed", t)
        }
    }

    /** `--cache-size` — the RAM-hot cache capacity (live-resizes the held cache + durable intent). */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverCacheCap(cap: Int) {
        putIntPref(TortaeKeys.RESOLVER_CACHE_CAP, cap) // #51 durable Expert override
        try {
            TortaCore.setCacheCap(cap)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverCacheCap($cap) failed", t)
        }
    }

    /** The per-query deadline in ms (0 = engine default) — bites the next query, no reconfigure. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverQueryTimeout(ms: Int) {
        putIntPref(TortaeKeys.RESOLVER_QUERY_TIMEOUT_MS, ms) // #51 durable Expert override
        try {
            TortaCore.setQueryTimeout(ms)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverQueryTimeout($ms) failed", t)
        }
    }

    /** RFC 8767 serve-stale window in seconds (0 = OFF) — arms the held cache + durable intent. */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverServeStale(secs: Int) {
        putIntPref(TortaeKeys.RESOLVER_SERVE_STALE_SECS, secs) // #51 durable Expert override
        try {
            TortaCore.setServeStale(secs)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverServeStale($secs) failed", t)
        }
    }

    /** Positive-TTL floor `min-cache-ttl` in seconds (0 = no floor). */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverTtlFloor(secs: Int) {
        putIntPref(TortaeKeys.RESOLVER_TTL_FLOOR_SECS, secs) // #51 durable Expert override
        try {
            TortaCore.setTtlFloor(secs)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverTtlFloor($secs) failed", t)
        }
    }

    /** Positive-TTL ceiling `max-cache-ttl` in seconds (0 -> the 24h default). */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open
    fun setResolverTtlCeiling(secs: Int) {
        putIntPref(TortaeKeys.RESOLVER_TTL_CEILING_SECS, secs) // #51 durable Expert override
        try {
            TortaCore.setTtlCeiling(secs)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge setResolverTtlCeiling($secs) failed", t)
        }
    }

    /**
     * SETTINGS · cycle the durable SeedPolicy (CatalogOnly 0 ⇄ WarmUpBatch 1) — read-flip-write the
     * default prefs. The manager reads it at the NEXT arm to gate the proactive warm-up batch. Returns the
     * NEW policy code; on any fault returns the current (or default WarmUpBatch) code unchanged.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never throw across the JNI boundary
    fun cycleCentauriSeedPolicy(): Int =
        try {
            val prefs = PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
            val cur = prefs.getInt(CENTAURI_SEED_POLICY, CentauriMirrorManager.SEED_POLICY_WARM_UP_BATCH)
            val next =
                if (cur == CentauriMirrorManager.SEED_POLICY_WARM_UP_BATCH) {
                    CentauriMirrorManager.SEED_POLICY_CATALOG_ONLY
                } else {
                    CentauriMirrorManager.SEED_POLICY_WARM_UP_BATCH
                }
            prefs.edit().putInt(CENTAURI_SEED_POLICY, next).apply()
            next
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge cycleCentauriSeedPolicy failed", t)
            CentauriMirrorManager.SEED_POLICY_WARM_UP_BATCH
        }

    /**
     * SETTINGS · run a TIER-B warm-up batch on the held Object NOW (bounded, ≤1 fetch/asset ever). The batch
     * is BLOCKING (up to [CentauriMirrorManager] targets of network I/O), so it is dispatched to a background
     * thread — calling it inline on the Slint UI thread would ANR. Fire-and-forget: returns 0 ("kicked off")
     * immediately; the real filled count surfaces on the next live overlay tick (libraries / served climb).
     * -1 only if the dispatch itself fails.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never throw across the JNI boundary
    fun centauriWarmUpNow(): Int =
        try {
            Thread({
                try {
                    val filled = CentauriMirrorManager.heldWarmUp()
                    Log.i(TAG, "live-bridge centauriWarmUpNow: $filled filled")
                } catch (t: Throwable) {
                    Log.e(TAG, "live-bridge centauriWarmUpNow (bg) failed", t)
                }
            }, "centauri-warmup").start()
            0
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge centauriWarmUpNow dispatch failed", t)
            -1
        }

    /**
     * ★ #65 · CA TRUST · is the device CA trusted RIGHT NOW?
     *
     * Read from the live `AndroidCAStore` on every call rather than cached, so the dashboard's prompt
     * clears the instant the user grants trust and returns if they later revoke it. Fail-open ⇒ false,
     * which shows the prompt: telling a user their CDN is private when it is not would be the worse lie.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never throw across the JNI boundary
    fun centauriCaTrusted(): Boolean =
        try {
            CentauriCaTrust.isTrusted()
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge centauriCaTrusted failed", t)
            false
        }

    /** ★ #65 · CA TRUST · has the serve leg armed at least once, i.e. is there a CA to install? */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never throw across the JNI boundary
    fun centauriCaMinted(): Boolean =
        try {
            App.instance.applicationContext.let { ctx ->
                // Cheap and idempotent: the first Centauri tick is the earliest point we hold an app
                // Context on this path, so it is where the trust-store watch gets armed.
                CentauriCaTrust.armTrustWatch(ctx)
                CentauriCaTrust.isMinted(ctx)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge centauriCaMinted failed", t)
            false
        }

    /**
     * ★ #65 · CA TRUST · hand the CA to the OS installer.
     *
     * The OS shows its OWN confirmation sheet — this cannot install anything silently, by construction.
     * Returns true only when the sheet was actually launched.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never throw across the JNI boundary
    fun centauriCaInstall(): Boolean =
        try {
            CentauriCaTrust.requestInstall(App.instance.applicationContext)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge centauriCaInstall failed", t)
            false
        }

    /**
     * ★ #22 · CENTAURI · hand every TLS-refused host back to the cloak, and clear the durable ledger.
     *
     * A refusal is recorded permanently on purpose — a client that rejected our leaf must not be re-cloaked
     * on the next boot and broken all over again. The cost of that correctness is that the user had no way
     * out: the dashboard could report `N untrusted` forever, with a reinstall the only escape. This is the
     * escape, and it runs in the SERVICE process where the forwarder records refusals — clearing the UI's
     * own statically-linked copy would move the tile without freeing a single host.
     *
     * Returns the number of hosts handed back. Fail-open ⇒ 0, never a throw across the JNI boundary.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never throw across the JNI boundary
    fun centauriTlsRetrust(): Int =
        try {
            TortaCore.centauriTlsRetrust().toInt()
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge centauriTlsRetrust failed", t)
            0
        }

    /**
     * SETTINGS · read whether the DNS-plane cloak is armed (the manager's live @Volatile witness). Fail-open
     * ⇒ false, so the pane holds its last honest value rather than flipping on a transient fault.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never throw across the JNI boundary
    fun centauriCloakArmed(): Boolean =
        try {
            CentauriMirrorManager.cloakArmed
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge centauriCloakArmed failed", t)
            false
        }

    /**
     * SETTINGS · read the durable SeedPolicy code (0 CatalogOnly · 1 WarmUpBatch, the default). Fail-open
     * ⇒ the default WarmUpBatch, matching the pre-settings behavior.
     */
    @JvmStatic
    @Keep
    @Suppress("TooGenericExceptionCaught") // deliberate fail-open: never throw across the JNI boundary
    fun centauriSeedPolicy(): Int =
        try {
            PreferenceManager.getDefaultSharedPreferences(App.instance.applicationContext)
                .getInt(CENTAURI_SEED_POLICY, CentauriMirrorManager.SEED_POLICY_WARM_UP_BATCH)
        } catch (t: Throwable) {
            Log.e(TAG, "live-bridge centauriSeedPolicy failed", t)
            CentauriMirrorManager.SEED_POLICY_WARM_UP_BATCH
        }
}
