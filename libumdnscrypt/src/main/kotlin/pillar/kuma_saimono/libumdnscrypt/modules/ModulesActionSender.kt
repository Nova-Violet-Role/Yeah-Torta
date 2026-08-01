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

package pillar.kuma_saimono.libumdnscrypt.modules

import android.content.Context
import android.content.Intent
import android.os.Build
import pillar.kuma_saimono.libumdnscrypt.utils.Utils.isShowNotification
import pillar.kuma_saimono.libumdnscrypt.utils.app
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge

object ModulesActionSender {
    fun sendIntent(context: Context, action: String) = try {

        val intent = Intent(context, ModulesService::class.java)
        intent.action = action

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            intent.putExtra("showNotification", true)

            if (context.app.isAppForeground) {
                try {
                    context.startService(intent)
                } catch (e: Exception) {
                    loge("ModulesActionSender sendIntent with action $action", e)
                    context.startForegroundService(intent)
                }
            } else {
                context.startForegroundService(intent)
            }
        } else {
            intent.putExtra("showNotification", isShowNotification(context))
            context.startService(intent)
        }
    } catch (e: Exception) {
        loge("ModulesActionSender sendIntent", e, true)
    }
}
