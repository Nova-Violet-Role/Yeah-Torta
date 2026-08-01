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
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.di.tiles.TilesSubcomponent
import javax.inject.Inject

@RequiresApi(Build.VERSION_CODES.N)
abstract class BaseTileService : TileService() {

    @Inject
    lateinit var tilesLimiter: TilesLimiter

    override fun onCreate() {
        tilesSubcomponent?.inject(this)
        super.onCreate()
    }

    override fun onStartListening() {
        tilesLimiter.listenTile(this)
    }

    override fun onDestroy() {
        tilesLimiter.unlistenTile(this)
    }

    override fun onClick() {
        tilesLimiter.checkActiveTilesCount(this)
    }

    override fun onTileRemoved() {
        tilesLimiter.reset()
    }

    companion object {
        var tilesSubcomponent: TilesSubcomponent? = null
            get() = field ?: App.instance.daggerComponent.tilesSubcomponent().create()
                .also { field = it }
            private set

        fun releaseTilesSubcomponent() {
            tilesSubcomponent = null
        }
    }
}
