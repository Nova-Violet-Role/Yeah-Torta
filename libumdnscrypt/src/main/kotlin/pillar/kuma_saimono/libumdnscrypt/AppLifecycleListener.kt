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

import android.os.Build
import androidx.lifecycle.*
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesAux
import pillar.kuma_saimono.libumdnscrypt.tiles.BaseTileService
import pillar.kuma_saimono.libumdnscrypt.tiles.TilesLimiter

class AppLifecycleListener(private val app: App): DefaultLifecycleObserver {

    override fun onStart(owner: LifecycleOwner) {
        super.onStart(owner)

        app.isAppForeground = true

        ModulesAux.speedupModulesStateLoopTimer(app)
    }

    override fun onStop(owner: LifecycleOwner) {
        super.onStop(owner)

        app.isAppForeground = false

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            BaseTileService.releaseTilesSubcomponent()
            TilesLimiter.resetActiveTiles()
        }
    }
}
