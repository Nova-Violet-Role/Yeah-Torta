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

package pillar.kuma_saimono.libumdnscrypt.utils.session

import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.collections.emptyMap

@Singleton
class AppSessionStore @Inject constructor() {
    private val keyToValue = ConcurrentHashMap<String, Any?>()

    fun <T> save(key: String, value: T?) {
        keyToValue[key] = value
    }

    fun <T> save(key: String, value: MutableSet<T>) {
        keyToValue[key] = value
    }

    fun <T, V> save(key: String, value: HashMap<T, V>) {
        keyToValue[key] = value
    }

    fun <T> restore(key: String): T? = try {
        keyToValue[key] as? T
    } catch (e: Exception) {
        loge("AppSessionStore restore", e)
        null
    }

    fun <T> restoreSet(key: String): Set<T> = try {
        val value = keyToValue[key]
        if (value != null) {
            value as Set<T>
        } else {
            emptySet()
        }
    } catch (e: Exception) {
        loge("AppSessionStore restoreSet", e)
        emptySet()
    }

    fun clearSet(key: String) = try {
        (keyToValue[key] as? MutableSet<*>)?.clear()
    } catch (e: Exception) {
        loge("AppSessionStore clearSet", e)
    }

    fun <T, V> restoreMap(key: String): Map<T, V> = try {
        val value = keyToValue[key]
        if (value != null) {
            value as Map<T, V>
        } else {
            emptyMap()
        }
    } catch (e: Exception) {
        loge("AppSessionStore restoreMap", e)
        emptyMap()
    }

    fun clearMap(key: String) = try {
        (keyToValue[key] as? MutableMap<*, *>)?.clear()
    } catch (e: Exception) {
        loge("AppSessionStore clearMap", e)
    }
}
