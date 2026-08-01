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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintActivity
import pillar.kuma_saimono.libumdnscrypt.R

/**
 * The "Bring me a slice of tortä" trampoline (#8A): tapped from the "Soft-Cäke is baked" notification, it
 * bounces the user back to Tortä ([TortaSlintActivity]) AND fires a ~10-second "now the Tortä is screaming
 * YEAH!!" Toast. Transparent + no-history — it finishes immediately. The Toasts ride the main looper with
 * the APPLICATION context (not this activity), so they keep showing after `finish()`; ~10s is three
 * back-to-back `LENGTH_LONG` (~3.3s each) re-posts.
 */
class TortaSliceActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val app = applicationContext
        val message = uniffi.torta_core.tortaText("torta_slice_toast")
        val handler = Handler(Looper.getMainLooper())
        for (i in 0..2) {
            handler.postDelayed({
                try {
                    Toast.makeText(app, message, Toast.LENGTH_LONG).show()
                } catch (_: Exception) {
                }
            }, i * 3300L)
        }

        try {
            startActivity(
                Intent(this, TortaSlintActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            )
        } catch (_: Exception) {
        }
        finish()
    }
}
