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

package pillar.kuma_saimono.libumdnscrypt.settings.tor_apps

import android.graphics.drawable.Drawable
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import java.util.ArrayList
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

data class TorAppData(
    val names: Set<String>,
    val pack: String,
    val uid: Int,
    val icon: Drawable?,
    val system: Boolean,
    val archived: Boolean,
    val user: Int,
    val hasInternetPermission: Boolean,
    var torifyApp: Boolean,
    var directUdp: Boolean,
    var excludeFromAll: Boolean
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TorAppData

        return uid == other.uid
    }

    override fun hashCode(): Int {
        return uid
    }

    companion object {

        @JvmStatic
        fun CopyOnWriteArrayList<TorAppData>.sortByName() = sortListBy(this) { o1, o2 ->
            if (!o1.excludeFromAll && o2.excludeFromAll && !isRootMode()) {
                1
            } else if (o1.excludeFromAll && !o2.excludeFromAll && !isRootMode()) {
                -1
            } else if (!o1.torifyApp && o2.torifyApp) {
                1
            } else if (o1.torifyApp && !o2.torifyApp) {
                -1
            } else if (!o1.directUdp && o2.directUdp) {
                1
            } else if (o1.directUdp && !o2.directUdp) {
                -1
            } else {
                o1.names.first().lowercase(Locale.getDefault()).compareTo(
                    o2.names.first().lowercase(Locale.getDefault())
                )
            }
        }

        @JvmStatic
        fun CopyOnWriteArrayList<TorAppData>.sortByUid() = sortListBy(this) { o1, o2 ->
            if (!o1.excludeFromAll && o2.excludeFromAll && !isRootMode()) {
                1
            } else if (o1.excludeFromAll && !o2.excludeFromAll && !isRootMode()) {
                -1
            } else if (!o1.torifyApp && o2.torifyApp) {
                1
            } else if (o1.torifyApp && !o2.torifyApp) {
                -1
            } else if (!o1.directUdp && o2.directUdp) {
                1
            } else if (o1.directUdp && !o2.directUdp) {
                -1
            } else {
                o1.uid - o2.uid
            }
        }

        @JvmStatic
        fun ApplicationData.mapToTorAppData() =
            TorAppData(
                names = names,
                pack = pack,
                uid = uid,
                icon = icon,
                system = system,
                archived = archived,
                user = user,
                hasInternetPermission = hasInternetPermission,
                torifyApp = active,
                directUdp = false,
                excludeFromAll = false
            )

        private fun <T> sortListBy(list: CopyOnWriteArrayList<T>?, comparator: Comparator<T>) {
            if (list != null && list.size > 1) {
                val sortedList = ArrayList(list)
                sortedList.sortWith(comparator)
                list.clear()
                list.addAll(sortedList)
            }
        }

        private fun isRootMode() = ModulesStatus.getInstance().mode == OperationMode.ROOT_MODE
    }
}
