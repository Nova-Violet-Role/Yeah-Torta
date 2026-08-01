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

package pillar.kuma_saimono.libumdnscrypt.tiles

import android.os.Build
import androidx.annotation.RequiresApi
import javax.inject.Inject

@RequiresApi(Build.VERSION_CODES.N)
class DNSCryptTileService : BaseTileService() {

    @Inject
    lateinit var tileManager: dagger.Lazy<ModulesControlTileManager>

    override fun onCreate() {
        tilesSubcomponent?.inject(this)
        super.onCreate()
    }

    override fun onStartListening() {
        super.onStartListening()

        val tile = qsTile ?: return
        tileManager.get().startUpdatingState(tile, ModulesControlTileManager.ManageTask.MANAGE_DNSCRYPT)
    }

    override fun onStopListening() {
        super.onStopListening()

        tileManager.get().stopUpdatingState()
    }

    override fun onDestroy() {
        tileManager.get().stopUpdatingState()
        super.onDestroy()
    }

    override fun onClick() {
        super.onClick()

        val tile = qsTile ?: return
        tileManager.get().manageModule(tile, ModulesControlTileManager.ManageTask.MANAGE_DNSCRYPT)
    }
}
