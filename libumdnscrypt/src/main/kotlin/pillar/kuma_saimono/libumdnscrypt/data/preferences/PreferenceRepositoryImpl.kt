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

package pillar.kuma_saimono.libumdnscrypt.data.preferences

import android.content.SharedPreferences
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceType.Companion.BOOL_PREFERENCE
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceType.Companion.FLOAT_PREFERENCE
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceType.Companion.INT_PREFERENCE
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceType.Companion.STRING_PREFERENCE
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceType.Companion.STRING_SET_PREFERENCE
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import javax.inject.Inject
import javax.inject.Named
import javax.inject.Singleton

@Singleton
class PreferenceRepositoryImpl @Inject constructor(
    private val preferenceDataSource: PreferenceDataSource,
    @Named(DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: SharedPreferences
) : PreferenceRepository {
    override fun getBoolPreference(key: String): Boolean {
        // FORK-3 alias: the legacy Garmatin firewall master key FIREWALL_ENABLED ("FirewallEnabled") now
        // DELEGATES to the Warden native-firewall arm WARDEN_NATIVE_ENABLED ("pref_warden_native"). The Warden
        // arm lives in DEFAULT SharedPreferences (the androidx SwitchPreference + ModulesStarterHelper
        // .applyWardenNativeFromPref read it there, default-OFF), NOT the named APP_PREFERENCES_NAME store this
        // repository normally reads — so the alias crosses the store boundary and reads default prefs directly,
        // honoring the same default-OFF contract (getBoolean(..., false)). Every surviving reader of
        // FIREWALL_ENABLED (the MainFragment VPN-start gate, VpnPreferenceHolder, ModulesStatus, ModulesAux,
        // ModulesReceiver, MainActivity, VpnBuilder, ServiceVPNHandler, ConnectionRecordsConverter) now reads
        // the live Warden state through this single chokepoint.
        if (key == TortaeKeys.FIREWALL_ENABLED) {
            return defaultPreferences.getBoolean(TortaeKeys.WARDEN_NATIVE_ENABLED, false)
        }
        return preferenceDataSource.getPreference(BOOL_PREFERENCE, key) as Boolean
    }

    override fun setBoolPreference(key: String, value: Boolean) {
        // FORK-3 alias (write side): a legacy write to FIREWALL_ENABLED retargets the Warden arm in default
        // prefs, keeping a single source of truth so the legacy key and WARDEN_NATIVE_ENABLED can never diverge.
        if (key == TortaeKeys.FIREWALL_ENABLED) {
            defaultPreferences.edit().putBoolean(TortaeKeys.WARDEN_NATIVE_ENABLED, value).apply()
            return
        }
        preferenceDataSource.setPreference(key, value)
    }

    override fun getIntPreference(key: String): Int {
        return preferenceDataSource.getPreference(INT_PREFERENCE, key) as Int
    }

    override fun setIntPreference(key: String, value: Int) {
        preferenceDataSource.setPreference(key, value)
    }

    override fun getFloatPreference(key: String): Float {
        return preferenceDataSource.getPreference(FLOAT_PREFERENCE, key) as Float
    }

    override fun setFloatPreference(key: String, value: Float) {
        preferenceDataSource.setPreference(key, value)
    }

    override fun getStringPreference(key: String): String {
        return preferenceDataSource.getPreference(STRING_PREFERENCE, key) as String
    }

    override fun setStringPreference(key: String, value: String) {
        preferenceDataSource.setPreference(key, value)
    }

    @Synchronized
    override fun getStringSetPreference(key: String): HashSet<String> {
        return HashSet(
            preferenceDataSource.getPreference(STRING_SET_PREFERENCE, key) as Set<String>
        )
    }

    override fun setStringSetPreference(key: String, value: Set<String>) {
        preferenceDataSource.setPreference(key, value)
    }
}
