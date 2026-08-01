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

    // The three casts below are UNCHECKED because of JVM generic erasure, not because of a shortcut:
    // this is a heterogeneous store (String -> Any), and at runtime `T` does not exist. The
    // @Suppress is an acknowledgement of a language limit, and it is deliberately paired with the
    // strongest check that IS possible -- the CONTAINER type is now verified with `is` before the
    // cast, so a value stored as a List and restored as a Set returns empty instead of throwing a
    // ClassCastException later, at some unrelated call site. Only the ELEMENT type stays unverified,
    // and no amount of code can verify it without walking every element.
    @Suppress("UNCHECKED_CAST")
    fun <T> restore(key: String): T? = try {
        keyToValue[key] as? T
    } catch (e: Exception) {
        loge("AppSessionStore restore", e)
        null
    }

    @Suppress("UNCHECKED_CAST")
    fun <T> restoreSet(key: String): Set<T> = try {
        val value = keyToValue[key]
        if (value is Set<*>) {
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

    @Suppress("UNCHECKED_CAST")
    fun <T, V> restoreMap(key: String): Map<T, V> = try {
        val value = keyToValue[key]
        if (value is Map<*, *>) {
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
