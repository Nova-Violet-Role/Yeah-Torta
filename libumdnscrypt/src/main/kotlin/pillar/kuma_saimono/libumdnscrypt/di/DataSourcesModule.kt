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
import pillar.kuma_saimono.libumdnscrypt.data.connection_checker.ConnectionCheckerDataSource
import pillar.kuma_saimono.libumdnscrypt.data.connection_checker.ConnectionCheckerDataSourceImpl
import pillar.kuma_saimono.libumdnscrypt.data.dns_resolver.DnsDataSource
import pillar.kuma_saimono.libumdnscrypt.data.dns_resolver.DnsDataSourceImpl
import pillar.kuma_saimono.libumdnscrypt.data.dns_rules.DnsRulesDataSource
import pillar.kuma_saimono.libumdnscrypt.data.dns_rules.DnsRulesDataSourceImpl
import pillar.kuma_saimono.libumdnscrypt.data.dnscrypt_relays.RelaysPingDataSource
import pillar.kuma_saimono.libumdnscrypt.data.dnscrypt_relays.RelaysPingDataSourceImpl
import pillar.kuma_saimono.libumdnscrypt.data.dnscrypt_servers.ServersPingDataSource
import pillar.kuma_saimono.libumdnscrypt.data.dnscrypt_servers.ServersPingDataSourceImpl
import pillar.kuma_saimono.libumdnscrypt.data.preferences.PreferenceDataSource
import pillar.kuma_saimono.libumdnscrypt.data.preferences.PreferenceDataSourceImpl

@Module
abstract class DataSourcesModule {
    @Binds
    abstract fun providePreferencesDataSource(
        preferenceDataSource: PreferenceDataSourceImpl
    ): PreferenceDataSource

    @Binds
    abstract fun provideDnsDataSource(
        dnsDataSource: DnsDataSourceImpl
    ): DnsDataSource

    @Binds
    abstract fun provideInternetCheckerDataSource(
        internetCheckerDataSource: ConnectionCheckerDataSourceImpl
    ): ConnectionCheckerDataSource

    @Binds
    abstract fun provideDnsRulesDataSource(
        dnsDataSource: DnsRulesDataSourceImpl
    ): DnsRulesDataSource

    @Binds
    abstract fun provideDnsCryptServersPingDataSource(
        dnsCryptServersPingDataSource: ServersPingDataSourceImpl
    ): ServersPingDataSource

    @Binds
    abstract fun provideDnsCryptRelaysPingDataSource(
        dnsCryptRelaysPingDataSource: RelaysPingDataSourceImpl
    ): RelaysPingDataSource
}
