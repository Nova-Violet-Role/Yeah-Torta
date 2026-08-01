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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
sealed class DnsRulesDownloadProgress : Parcelable {

    data class DownloadProgress(
        val name: String,
        val url: String,
        val size: Long,
        val progress: Int
    ): DnsRulesDownloadProgress()

    data class DownloadFinished(
        val name: String,
        val url: String,
        val size: Long
    ): DnsRulesDownloadProgress()

    data class DownloadFailure(
        val name: String,
        val url: String,
        val error: String
    ): DnsRulesDownloadProgress()
}
