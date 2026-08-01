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

package pillar.kuma_saimono.libumdnscrypt

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import dagger.Lazy
import pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.WireCakeInuService
import pillar.kuma_saimono.libumdnscrypt.utils.bootcomplete.BootCompleteManager
import pillar.kuma_saimono.libumdnscrypt.utils.bootcomplete.BootCompleteManager.Companion.ALWAYS_ON_VPN
import pillar.kuma_saimono.libumdnscrypt.utils.bootcomplete.BootCompleteManager.Companion.SHELL_SCRIPT_CONTROL
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import javax.inject.Inject

class BootCompleteReceiver : BroadcastReceiver() {

    @Inject
    lateinit var bootCompleteManager: Lazy<BootCompleteManager>

    override fun onReceive(context: Context, intent: Intent?) {

        App.instance.daggerComponent.inject(this)

        if (intent == null) {
            return
        }

        val action = intent.action ?: return

        if (action.equals(BOOT_COMPLETE, ignoreCase = true)
            || action.equals(QUICKBOOT_POWERON, ignoreCase = true)
            || action.equals(HTC_QUICKBOOT_POWERON, ignoreCase = true)
            || action.equals(REBOOT, ignoreCase = true)
            || action.equals(MY_PACKAGE_REPLACED, ignoreCase = true)
            || action == ALWAYS_ON_VPN
            || action == SHELL_SCRIPT_CONTROL
        ) {
            bootCompleteManager.get().performAction(context, intent)
        }

        // Wire Cake Inu (P11 §3): on a genuine fresh boot / self-update, silently re-arm the no-root
        // powers if the user armed "keep after reboot". NOT on the ALWAYS_ON_VPN / SHELL_SCRIPT_CONTROL
        // control broadcasts — those are VPN-revoke / shell hooks, not a device boot.
        if (action.equals(BOOT_COMPLETE, ignoreCase = true)
            || action.equals(QUICKBOOT_POWERON, ignoreCase = true)
            || action.equals(HTC_QUICKBOOT_POWERON, ignoreCase = true)
            || action.equals(REBOOT, ignoreCase = true)
            || action.equals(MY_PACKAGE_REPLACED, ignoreCase = true)
        ) {
            maybeInuBootReapply(context)
        }
    }

    /**
     * The boot-side consumer of the persisted Inu grant: if the user armed boot-reapply (the typed
     * `InuState.bootReapply` bit — #21; was [TortaeKeys.INU_BOOT_REAPPLY]),
     * dispatch the silent re-arm. Only a cheap RAM read here — the service + manager self-gate on the
     * durable posture (paired + previously-verified powers via [BootReapplyPolicy]), so a non-protected
     * device opens no ADB connection. Fail-open like the rest of the wireless-debug stack: never throws
     * out of the boot receiver.
     */
    private fun maybeInuBootReapply(context: Context) {
        try {
            // #21 G7-RESIDUAL: the arm reads the TYPED InuState (hdr bit2) off the shared
            // component InuStore — first access constructs the component, which rehydrates the
            // NAND record + absorbs the legacy pref (LegacyInuMigration). Still a cheap gate.
            val armed = App.instance.wireCakeInuComponent.inuStore.bootReapply()
            if (!armed) return
            Log.i(INU_BOOT_TAG, "keep-after-reboot armed -> dispatching silent Inu re-arm")
            WireCakeInuService.bootReapply(context)
        } catch (t: Throwable) {
            Log.i(INU_BOOT_TAG, "Inu boot re-arm gate skipped: ${t.message}")
        }
    }

    companion object {
        private const val INU_BOOT_TAG = "WireCakeInuBoot"
        const val MY_PACKAGE_REPLACED = "android.intent.action.MY_PACKAGE_REPLACED"
        private const val BOOT_COMPLETE = "android.intent.action.BOOT_COMPLETED"
        private const val QUICKBOOT_POWERON = "android.intent.action.QUICKBOOT_POWERON"
        private const val HTC_QUICKBOOT_POWERON = "com.htc.intent.action.QUICKBOOT_POWERON"
        private const val REBOOT = "android.intent.action.REBOOT"
    }
}
