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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.settings

import android.content.Context
import android.graphics.Typeface
import android.text.InputType
import android.view.Gravity
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.appcompat.app.AlertDialog
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RuntimeTierManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge

/**
 * D33a/D33b (P12) — the ONE tiny text-store editor dialog the local-records and conditional-routing
 * rows share (a monospace multiline editor over a Rust-owned durable record; the settings pillar's
 * value-only contract — saving writes the store, never arms anything).
 *
 * The two stores are NOT SharedPreferences: the text lives in the integrity-framed
 * `resolver-local-records` / `resolver-routes` DurableTier records under the shared runtime-tier
 * root (RAM⊗NAND — the same family as the resolver cache/rotation records), loaded/saved through
 * the typed [pillar.kuma_saimono.libumdnscrypt.rust.TortaCore] façades. Every path is try/catch +
 * loge, fail-open (a fault shows/saves nothing, never crashes the settings screen).
 */
internal object DnsmasqStoreEditor {

    /**
     * The app-private durable runtime-tier root — the SAME dir every RAM⊗NAND pillar shares
     * ([RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR] under the app data dir). "" on a fault
     * (the editor then no-ops rather than inventing a path).
     */
    fun durableDir(): String =
        try {
            App.instance.daggerComponent.getPathVars().get().appDataDir +
                RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR
        } catch (e: Exception) {
            loge("DnsmasqStoreEditor durableDir", e)
            ""
        }

    /**
     * Show the editor: [load] fills the text from the durable store, OK runs [save] (which returns
     * the human feedback line, or null when the native engine is unreachable — surfaced honestly).
     * Cancel discards. Crash-safe end to end.
     */
    fun show(
        context: Context,
        @StringRes titleRes: Int,
        @StringRes hintRes: Int,
        load: (String) -> String,
        save: (String, String) -> String?,
    ) {
        try {
            val dir = durableDir()
            if (dir.isEmpty()) return
            val input =
                EditText(context).apply {
                    setText(load(dir))
                    hint = context.getString(hintRes)
                    typeface = Typeface.MONOSPACE
                    textSize = EDITOR_TEXT_SIZE_SP
                    gravity = Gravity.TOP
                    minLines = EDITOR_MIN_LINES
                    maxLines = EDITOR_MAX_LINES
                    inputType =
                        InputType.TYPE_CLASS_TEXT or
                            InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                }
            val pad = (EDITOR_PAD_DP * context.resources.displayMetrics.density).toInt()
            val container =
                FrameLayout(context).apply {
                    setPadding(pad, pad / 2, pad, 0)
                    addView(input)
                }
            AlertDialog.Builder(context)
                .setTitle(titleRes)
                .setView(container)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    try {
                        val feedback = save(input.text?.toString() ?: "", dir)
                        Toast.makeText(
                                context,
                                feedback ?: uniffi.torta_core.tortaText("dnsmasq_editor_unavailable"),
                                Toast.LENGTH_LONG,
                            )
                            .show()
                    } catch (e: Exception) {
                        loge("DnsmasqStoreEditor save", e)
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        } catch (e: Exception) {
            loge("DnsmasqStoreEditor show", e)
        }
    }

    private const val EDITOR_TEXT_SIZE_SP = 13f
    private const val EDITOR_MIN_LINES = 6
    private const val EDITOR_MAX_LINES = 12
    private const val EDITOR_PAD_DP = 16
}
