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

package pillar.kuma_saimono.libumdnscrypt.utils.delegates

import kotlin.reflect.KProperty

class MutableLazy<T : Any>(
    private val initializer: () -> T
) {

    @Volatile
    private var value: T? = null

    operator fun getValue(thisRef: Any?, property: KProperty<*>): T =
        value ?: synchronized(this) {
            value ?: initializer().also { this.value = it }
        }

    operator fun setValue(thisRef: Any?, property: KProperty<*>, value: T?) {
        synchronized(this) {
            this.value = value
        }
    }

}
