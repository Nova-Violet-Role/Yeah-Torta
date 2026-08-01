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

package pillar.kuma_saimono.libumdnscrypt.vpn

import android.content.Context
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.proxy.CLEARNET_APPS_FOR_PROXY
import pillar.kuma_saimono.libumdnscrypt.settings.tor_apps.ApplicationData
import pillar.kuma_saimono.libumdnscrypt.utils.apps.InstalledApplicationsManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.CLEARNET_APPS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.USE_PROXY
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock

class Rule private constructor(info: ApplicationData) {
    @JvmField
    var uid: Int = info.uid

    @JvmField
    var packageName: String = info.pack

    @JvmField
    var appName: String = info.toString()

    @JvmField
    var apply: Boolean = true

    companion object {
        private val lock = ReentrantLock()
        private val savedRules: MutableList<Rule> = ArrayList()

        @JvmStatic
        fun getRules(context: Context): List<Rule> {
            try {
                if (lock.tryLock(3, TimeUnit.SECONDS)) {
                    savedRules.clear()
                    savedRules.addAll(getAppRules(context))
                }
            } catch (e: Exception) {
                loge("Rule getAppRules", e)
            } finally {
                if (lock.isLocked && lock.isHeldByCurrentThread) {
                    lock.unlock()
                }
            }
            return ArrayList(savedRules)
        }

        private fun getAppRules(context: Context): List<Rule> {
            val prefs = PreferenceManager.getDefaultSharedPreferences(context)
            val unlockAppsStr = CLEARNET_APPS

            val preferences = App.instance.daggerComponent.getPreferenceRepository().get()

            val setUnlockApps = preferences.getStringSetPreference(unlockAppsStr)

            val useProxy = prefs.getBoolean(USE_PROXY, false)
            val setBypassProxy: Set<String> = if (useProxy) {
                preferences.getStringSetPreference(CLEARNET_APPS_FOR_PROXY)
            } else {
                HashSet()
            }

            // Build rule list
            val listRules: MutableList<Rule> = ArrayList()

            val installedApps = InstalledApplicationsManager.Builder()
                .build()
                .getInstalledApps()

            for (info in installedApps) {
                try {
                    val rule = Rule(info)

                    val uid = info.uid.toString()
                    rule.apply = !setUnlockApps.contains(uid) && !setBypassProxy.contains(uid)

                    listRules.add(rule)
                } catch (ex: Throwable) {
                    loge("Rule getRules", ex, true)
                }
            }

            return listRules
        }
    }
}
