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
import java.util.*
import java.util.concurrent.ConcurrentSkipListSet

data class ApplicationData(
    private val name: String = "",
    val pack: String = "",
    val uid: Int = -1000,
    val icon: Drawable? = null,
    val system: Boolean = false,
    val hasInternetPermission: Boolean = false,
    var active: Boolean = false,
    val archived: Boolean = false,
    val user: Int = 0
) : Comparable<ApplicationData> {

    val names = ConcurrentSkipListSet(setOf(name))

    fun addName(name: String) {
        names.add(name)
    }

    fun addAllNames(names: ConcurrentSkipListSet<String>) {
        this.names.addAll(names)
    }

    companion object {
        const val SPECIAL_UID_KERNEL = -1
        const val SPECIAL_UID_NTP = -14
        const val SPECIAL_PORT_NTP = 123
        const val SPECIAL_UID_AGPS = -15
        const val SPECIAL_PORT_AGPS1 = 7275
        const val SPECIAL_PORT_AGPS2 = 7276
        const val SPECIAL_UID_CONNECTIVITY_CHECK = -16
    }

    override fun compareTo(other: ApplicationData): Int {
        return if (!active && other.active) {
            1
        } else if (active && !other.active) {
            -1
        } else {
            names.first().lowercase(Locale.getDefault()).compareTo(
                other.names.first()
                    .lowercase(Locale.getDefault())
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ApplicationData

        return uid == other.uid
    }

    override fun hashCode(): Int {
        return uid
    }

    override fun toString(): String {
        return names.joinToString()
    }
}
