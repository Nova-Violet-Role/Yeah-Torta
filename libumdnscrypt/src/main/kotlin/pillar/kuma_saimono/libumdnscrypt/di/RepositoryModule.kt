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

import dagger.Binds
import dagger.Module
import pillar.kuma_saimono.libumdnscrypt.data.connection_checker.ConnectionCheckerRepositoryImpl
import pillar.kuma_saimono.libumdnscrypt.data.dns_resolver.DnsRepositoryImpl
import pillar.kuma_saimono.libumdnscrypt.data.dns_rules.DnsRulesRepositoryImpl
import pillar.kuma_saimono.libumdnscrypt.data.dnscrypt_relays.RelaysPingRepositoryImpl
import pillar.kuma_saimono.libumdnscrypt.data.dnscrypt_servers.ServersPingRepositoryImpl
import pillar.kuma_saimono.libumdnscrypt.data.preferences.PreferenceRepositoryImpl
import pillar.kuma_saimono.libumdnscrypt.data.resources.ResourceRepositoryImpl
import pillar.kuma_saimono.libumdnscrypt.domain.connection_checker.ConnectionCheckerRepository
import pillar.kuma_saimono.libumdnscrypt.domain.dns_resolver.DnsRepository
import pillar.kuma_saimono.libumdnscrypt.domain.dns_rules.DnsRulesRepository
import pillar.kuma_saimono.libumdnscrypt.domain.dnscrypt_relays.RelaysPingRepository
import pillar.kuma_saimono.libumdnscrypt.domain.dnscrypt_servers.ServersPingRepository
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.domain.resources.ResourceRepository

@Module
abstract class RepositoryModule {

    @Binds
    abstract fun providePreferenceRepository(repository: PreferenceRepositoryImpl): PreferenceRepository

    @Binds
    abstract fun provideDnsRepository(repository: DnsRepositoryImpl): DnsRepository

    @Binds
    abstract fun provideInternetCheckingRepository(
        repository: ConnectionCheckerRepositoryImpl
    ): ConnectionCheckerRepository

    @Binds
    abstract fun provideResourceRepository(
        resourcesRepository: ResourceRepositoryImpl
    ): ResourceRepository

    @Binds
    abstract fun provideDnsRulesRepository(
        dnsRulesRepository: DnsRulesRepositoryImpl
    ): DnsRulesRepository

    @Binds
    abstract fun provideDnsCryptServersPingRepository(
        dnsCryptServersPingRepository: ServersPingRepositoryImpl
    ): ServersPingRepository

    @Binds
    abstract fun provideDnsCryptRelaysPingRepository(
        dnsCryptRelaysPingRepository: RelaysPingRepositoryImpl
    ): RelaysPingRepository
}
