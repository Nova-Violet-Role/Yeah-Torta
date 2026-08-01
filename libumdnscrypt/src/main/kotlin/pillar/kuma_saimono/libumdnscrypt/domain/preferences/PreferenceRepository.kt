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

package pillar.kuma_saimono.libumdnscrypt.domain.preferences

interface PreferenceRepository {
    fun getBoolPreference(key: String): Boolean
    fun setBoolPreference(key: String, value: Boolean)
    fun getIntPreference(key: String): Int
    fun setIntPreference(key: String, value: Int)
    fun getFloatPreference(key: String): Float
    fun setFloatPreference(key: String, value: Float)
    fun getStringPreference(key: String): String
    fun setStringPreference(key: String, value: String)
    fun getStringSetPreference(key: String): HashSet<String>
    fun setStringSetPreference(key: String, value: Set<String>)
}
