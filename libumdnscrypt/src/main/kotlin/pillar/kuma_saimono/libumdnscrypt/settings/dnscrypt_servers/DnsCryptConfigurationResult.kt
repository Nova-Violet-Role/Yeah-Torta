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

package pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_servers

import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_relays.DnsServerRelay

sealed interface DnsCryptConfigurationResult {
    data object Loading: DnsCryptConfigurationResult
    data class DnsCryptProxyToml(val lines: List<String>): DnsCryptConfigurationResult
    data class DnsCryptServers(val servers: List<String>): DnsCryptConfigurationResult
    data class DnsCryptRoutes(val routes: List<DnsServerRelay>): DnsCryptConfigurationResult
    data class DnsCryptPublicResolvers(val resolvers: List<DnsCryptResolver>): DnsCryptConfigurationResult
    data class DnsCryptOwnResolvers(val resolvers: List<DnsCryptResolver>): DnsCryptConfigurationResult
    data class DnsCryptOdohResolvers(val resolvers: List<DnsCryptResolver>): DnsCryptConfigurationResult
    data object Finished: DnsCryptConfigurationResult
    data object Undefined: DnsCryptConfigurationResult
}
