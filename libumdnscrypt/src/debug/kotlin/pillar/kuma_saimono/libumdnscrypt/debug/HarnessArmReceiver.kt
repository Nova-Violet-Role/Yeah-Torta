/*
    This file is part of Yeah! Tortä.

    Yeah! Tortä is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Copyright (C) 2026 Saimono
*/

package pillar.kuma_saimono.libumdnscrypt.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHelper

/**
 * DEBUG-ONLY arming entry point for the automated routing harness.
 *
 * ## Why this exists
 *
 * Every routing measurement is vacuous unless the engine is actually armed, and three separate
 * readings had to be WITHDRAWN this session for exactly that reason — `net_error -100 = 0`,
 * `tun_count = 0`, and a resolver verdict delta of `0` were all zero only because nothing was
 * running. A zero measured on an empty path is not evidence.
 *
 * Both alternative arming routes were MEASURED dead, not assumed:
 *  - the UI is Slint, rendered into a single surface, so there is no accessibility node tree.
 *    `uiautomator dump` finds nothing tappable, and `input tap` can only be aimed by pixels read
 *    off a screenshot — the guessed coordinate opened the PILLARS drawer instead of the switch.
 *  - `ModulesService`'s own `ACTION_START_ENGINE` is not exported, so `am start-foreground-service`
 *    fails with `Requires permission not exported from uid 10218`.
 *
 * ## Why it is safe
 *
 * It is declared ONLY in the debug manifest overlay (`torta_res_gen.gradle`), so the release
 * manifest gains no exported surface, and it is guarded by a `signature`-level permission, so only
 * a package signed with the same key can send the intent. An arbitrary app on the device cannot
 * toggle the tunnel even on a debug build.
 *
 * ## What it does NOT do
 *
 * It does not bypass the system VPN consent dialog — that is enforced by Android and cannot be
 * automated away. On a fresh install the consent still has to be accepted once; afterwards the OS
 * remembers it and this receiver is sufficient. So this closes the arming gap, not the consent gap,
 * and saying otherwise would be an overclaim.
 */
class HarnessArmReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            ACTION_ARM -> {
                Log.i(TAG, "harness ARM received")
                forward(context, ACTION_START_ENGINE)
                raiseTunnel(context)
            }

            ACTION_DISARM -> {
                Log.i(TAG, "harness DISARM received")
                forward(context, ACTION_STOP_ENGINE)
                lowerTunnel(context)
            }

            else -> Log.w(TAG, "harness receiver ignored action=${intent.action}")
        }
    }

    /**
     * Hand the request to the app's OWN service action — the same one the master switch drives.
     * Deliberately a forward and not a reimplementation: a second start path would be a second
     * lifecycle to keep correct, and the tun-leak invariant
     * (D:/Lean/proofs/Proofs/TunLeakInvariant.lean) is stated about ONE lifecycle. Two would give
     * the harness a code path the user never exercises, which is the definition of a test that
     * proves nothing about the product.
     */
    private fun forward(context: Context, action: String) {
        try {
            val svc = Intent(action).apply {
                setClassName(context.packageName, MODULES_SERVICE)
            }
            context.startService(svc)
            Log.i(TAG, "forwarded $action to $MODULES_SERVICE")
        } catch (e: RuntimeException) {
            // Logged rather than swallowed: a harness that fails silently reports "armed" when it
            // is not, which is precisely the false-green this receiver exists to prevent.
            Log.e(TAG, "harness forward of $action FAILED", e)
        }
    }

    /**
     * Raise the VPN datapath.
     *
     * ## Why ARM alone was not enough
     *
     * `ACTION_START_ENGINE` starts the STANDALONE DNS ENGINE — it is not a VPN start. The tunnel is
     * carried by `tunnel::TunnelController`, started from `ServiceVPN.startNative` when the VPN
     * establishes (`ModulesStarterHelper.kt:100-103`). Measured on the x86_64 AVD with the engine
     * fully armed and the resolver serving (`ready=9 transports=…`, 305/365 relays reachable):
     *
     *     ip link -> NO tun0, through 8 polls / 2 minutes
     *
     * So every routing measurement taken through this harness before 2026-07-31 was taken with NO
     * TUNNEL. That is exactly the vacuity the receiver's own docstring says it exists to prevent, and
     * it went unnoticed because "engine armed" reads like "traffic is flowing".
     *
     * ## Why this calls the helper directly instead of broadcasting
     *
     * `ServiceVPNHelper.start` puts `VPNCommand.START` — a **Serializable enum** — into the intent
     * (`ServiceVPNHelper.kt:52`). `adb shell am startservice` cannot carry a Serializable extra, so
     * there is no shell-only route to a VPN start; `--es Command START` would deliver a String and
     * `getSerializableExtra(...) as VPNCommand?` would throw. This receiver runs IN-PROCESS, where
     * that limitation does not apply, so it calls the app's OWN start path — the same one the master
     * switch drives. Deliberately a call and not a reimplementation, for the same reason `forward()`
     * is: a second lifecycle would be a second thing to keep correct, and the tun-leak invariant
     * (D:/Lean/proofs/Proofs/TunLeakInvariant.lean) is stated about ONE lifecycle.
     *
     * ## What it still does NOT do
     *
     * It does not bypass the system VPN consent dialog. On a fresh install consent must be accepted
     * once (or pre-granted out-of-band with `appops set <pkg> ACTIVATE_VPN allow`); afterwards the OS
     * remembers it. Saying otherwise would be an overclaim.
     */
    private fun raiseTunnel(context: Context) {
        try {
            ServiceVPNHelper.start("harness ARM", context)
            Log.i(TAG, "requested VPN start via ServiceVPNHelper (tunnel datapath)")
        } catch (e: RuntimeException) {
            // Logged, never swallowed: a harness that fails silently here reports "armed" while the
            // tunnel is down, which is the false-green this whole receiver exists to prevent.
            Log.e(TAG, "harness VPN start FAILED", e)
        }
    }

    private fun lowerTunnel(context: Context) {
        try {
            ServiceVPNHelper.stop("harness DISARM", context)
            Log.i(TAG, "requested VPN stop via ServiceVPNHelper")
        } catch (e: RuntimeException) {
            Log.e(TAG, "harness VPN stop FAILED", e)
        }
    }

    companion object {
        private const val TAG = "TortaHarness"

        const val ACTION_ARM = "pillar.kuma_saimono.libumdnscrypt.harness.ARM"
        const val ACTION_DISARM = "pillar.kuma_saimono.libumdnscrypt.harness.DISARM"

        private const val MODULES_SERVICE =
            "pillar.kuma_saimono.libumdnscrypt.modules.ModulesService"

        // Mirrors ModulesServiceActions; referenced as literals so the debug source set does not
        // widen the visibility of the main-source constants.
        private const val ACTION_START_ENGINE =
            "pillar.kuma_saimono.libumdnscrypt.action.START_ENGINE"
        private const val ACTION_STOP_ENGINE =
            "pillar.kuma_saimono.libumdnscrypt.action.STOP_ENGINE"
    }
}
