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

package pillar.kuma_saimono.libumdnscrypt.di

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager
import dagger.Module
import dagger.Provides
import javax.inject.Named
import javax.inject.Singleton

@Module
class SharedPreferencesModule {

    @Provides
    @Singleton
    @Named(APP_PREFERENCES_NAME)
    fun provideAppSharedPreferences(context: Context): SharedPreferences {
        return context.getSharedPreferences(
            APP_PREFERENCES_NAME,
            Context.MODE_PRIVATE
        )
    }

    @Provides
    @Singleton
    @Named(DEFAULT_PREFERENCES_NAME)
    fun provideDefaultSharedPreferences(context: Context): SharedPreferences {
        return PreferenceManager.getDefaultSharedPreferences(context)
    }

    companion object {
        const val DEFAULT_PREFERENCES_NAME = "DefaultSharedPreferences"
        const val APP_PREFERENCES_NAME = "TorPlusDNSCryptPref"
    }
}
