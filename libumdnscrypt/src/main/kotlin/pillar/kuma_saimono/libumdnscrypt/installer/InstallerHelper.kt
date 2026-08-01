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

package pillar.kuma_saimono.libumdnscrypt.installer

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import javax.inject.Inject
import javax.inject.Named
import pillar.kuma_saimono.libumdnscrypt.assistance.AccelerateDevelop
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.FIREWALL_NO_BLOCK_NEW_APP

class InstallerHelper @Inject constructor(
    private val context: Context,
    @Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME) private val defaultPreferences: SharedPreferences
) {

    @SuppressLint("SdCardPath")
    fun prepareDNSCryptForGP(lines: List<String>): List<String> {

        val preferences = defaultPreferences.edit()
        preferences.putBoolean(FIREWALL_NO_BLOCK_NEW_APP, true)
        if (!AccelerateDevelop.accelerated) {
            preferences.putBoolean("require_nofilter", true)
        }
        preferences.apply()

        val prepared = ArrayList<String>()

        for (rawLine in lines) {

            var line = rawLine

            if (line.contains("blacklist_file")) {
                line = ""
            } else if (line.contains("whitelist_file")) {
                line = ""
            } else if (line.contains("blocked_names_file")) {
                line = ""
            } else if (line.contains("blocked_ips_file")) {
                line = ""
            } else if (line.matches("(^| )\\{ ?server_name([ =]).+".toRegex())) {
                line = ""
            } else if (line.contains("require_nofilter") && !AccelerateDevelop.accelerated) {
                line = "require_nofilter = true"
            } else if (line.contains("require_dnssec")) {
                // G1 (#97 exhaustive orange): enforce the privacy/security contract in the prepared TOML —
                // require_dnssec/require_nolog were neither start- nor install-enforced (only require_nofilter
                // here + ignore_system_dns/http3 at start). NOT gated on !accelerated: DNSSEC validation +
                // no-log are universal privacy-first defaults, ON for every mode. (No leak existed — curated
                // encrypted resolvers, loopback-only — this is defense-in-depth on the stated require-matrix.)
                line = "require_dnssec = true"
            } else if (line.contains("require_nolog")) {
                line = "require_nolog = true"
            }

            if (line.isNotEmpty()) {
                prepared.add(line)
            }
        }

        return prepared
    }
}
