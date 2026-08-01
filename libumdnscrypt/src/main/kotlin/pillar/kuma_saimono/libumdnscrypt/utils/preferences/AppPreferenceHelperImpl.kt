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

package pillar.kuma_saimono.libumdnscrypt.utils.preferences

import android.content.SharedPreferences
import kotlinx.coroutines.*
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule.Companion.SUPERVISOR_JOB_MAIN_DISPATCHER_SCOPE
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.APP_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceType
import java.lang.UnsupportedOperationException
import javax.inject.Inject
import javax.inject.Named
import javax.inject.Singleton

@Singleton
class AppPreferenceHelperImpl @Inject constructor(
    @Named(APP_PREFERENCES_NAME)
    private val appPreferences: SharedPreferences,
    @Named(SUPERVISOR_JOB_MAIN_DISPATCHER_SCOPE)
    private val mainCoroutineScope: CoroutineScope
) : AppPreferenceHelper {

    override fun setPreference(key: String, value: Any) = mainCoroutineScope.launch {
        val editor = appPreferences.edit()
        when (value) {
            is Boolean -> editor.putBoolean(key, value)
            is Int -> editor.putInt(key, value)
            is Float -> editor.putFloat(key, value)
            is String -> editor.putString(key, null).putString(key, value)
            is Set<*> -> {
                if (value.all { it is String }) {
                    @Suppress("UNCHECKED_CAST")
                    editor.putStringSet(key, null).putStringSet(key, value as Set<String>)
                } else {
                    throw UnsupportedOperationException("AppPreferenceHelper Only String Set is allowed")
                }
            }
            else -> throw UnsupportedOperationException(
                "AppPreferenceHelper Type ${value.javaClass.canonicalName} is not implemented"
            )
        }
        editor.apply()
    }

    override fun getPreference(@PreferenceType type: Int, key: String): Any =
        when (type) {
            PreferenceType.BOOL_PREFERENCE -> appPreferences.getBoolean(key, false)
            PreferenceType.INT_PREFERENCE -> appPreferences.getInt(key, 0)
            PreferenceType.FLOAT_PREFERENCE -> appPreferences.getFloat(key, 0f)
            PreferenceType.STRING_PREFERENCE -> appPreferences.getString(key, "") as Any
            PreferenceType.STRING_SET_PREFERENCE -> appPreferences.getStringSet(
                key,
                emptySet()
            ) as Any
            else -> throw UnsupportedOperationException(
                "AppPreferenceHelper Preference Type $type is not implemented"
            )
        }
}
