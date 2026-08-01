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

package pillar.kuma_saimono.libumdnscrypt.language

import android.content.ContextWrapper
import android.content.SharedPreferences
import android.content.res.Configuration
import android.content.res.Resources
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.util.Locale

object Language {

    // save the original default locale so that we can reference it later
    private val mOriginalLocale: Locale = Locale.getDefault()

    /**
     * Sets the language/locale for the current application and its process from the given preference
     *
     * @param context the Application instance that you call this from
     * @param languagePreferenceKey the key of the `LanguagePreference`, `ListPreference` or `EditTextPreference` that contains the desired language's code
     * @param forceUpdate whether to force an update when the default language (empty language code) is requested
     */
    @JvmStatic
    @JvmOverloads
    fun setFromPreference(context: ContextWrapper, languagePreferenceKey: String, forceUpdate: Boolean = false) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        setFromPreference(context, languagePreferenceKey, forceUpdate, prefs)
    }

    /**
     * Sets the language/locale for the current application and its process from the given preference
     *
     * @param context the Application instance that you call this from
     * @param languagePreferenceKey the key of the `LanguagePreference`, `ListPreference` or `EditTextPreference` that contains the desired language's code
     * @param forceUpdate whether to force an update when the default language (empty language code) is requested
     * @param prefs a SharedPreferences instance that should be re-used
     */
    private fun setFromPreference(context: ContextWrapper, languagePreferenceKey: String, forceUpdate: Boolean, prefs: SharedPreferences) {
        val languageCode = prefs.getString(languagePreferenceKey, "")
        if (languageCode != null) {
            set(context, languageCode, forceUpdate)
        }
    }

    /**
     * Sets the language/locale for the current application and its process to the given language code
     *
     * @param context the `ContextWrapper` instance to get a `Resources` instance from
     * @param languageCode the language code in the form `[a-z]{2}` (e.g. `es`) or `[a-z]{2}-r?[A-Z]{2}` (e.g. `pt-rBR`)
     * @param forceUpdate whether to force an update when the default language (empty language code) is requested
     */
    @JvmStatic
    @JvmOverloads
    @Suppress("DEPRECATION")
    fun set(context: ContextWrapper, languageCode: String, forceUpdate: Boolean = false) {
        // if a custom language is requested (non-empty language code) or a forced update is requested
        if (languageCode != "" || forceUpdate) {
            try {
                // create a new Locale instance
                val newLocale: Locale

                // if the default language is requested (empty language code)
                if (languageCode == "") {
                    // set the new Locale instance to the default language
                    newLocale = mOriginalLocale
                }
                // if a custom language is requested (non-empty language code)
                else {
                    // if the language code does also contain a region
                    if (languageCode.contains("-r") || languageCode.contains("-")) {
                        // split the language code into language and region
                        val language_region = languageCode.split("-(r)?".toRegex())
                        // construct a new Locale object with the specified language and region
                        newLocale = Locale(language_region[0], language_region[1])
                    }
                    // if the language code does not contain a region
                    else {
                        // simply construct a new Locale object from the given language code
                        newLocale = Locale(languageCode)
                    }
                }

                // update the app's configuration to use the new Locale
                val resources: Resources = context.baseContext.resources
                val conf: Configuration = resources.configuration

                // Configuration.locale (the FIELD) is deprecated; setLocale() is the supported
                // setter and has existed since API 17, well below this minSdk of 21.
                conf.setLocale(newLocale)

                // Reading conf.locale back was a second use of the same deprecated field, and it
                // could only ever return what was just written. Using newLocale directly is both
                // non-deprecated and one less way for the two to disagree.
                conf.setLayoutDirection(newLocale)

                resources.updateConfiguration(conf, resources.displayMetrics)

                // overwrite the default Locale
                Locale.setDefault(newLocale)
            } catch (e: Exception) {
                loge("Language Set", e)
            }
        }
    }

    /**
     * Returns the original Locale instance that was in use before any custom selection may have been applied
     *
     * @return the original Locale instance
     */
    @JvmStatic
    fun getOriginalLocale(): Locale {
        return mOriginalLocale
    }
}
