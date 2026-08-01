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

package pillar.kuma_saimono.libumdnscrypt.di.logreader

import dagger.Binds
import dagger.Module
import pillar.kuma_saimono.libumdnscrypt.data.connection_records.ConnectionRecordsRepositoryImpl
import pillar.kuma_saimono.libumdnscrypt.data.log_reader.ModulesLogRepositoryImpl
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.ConnectionRecordsRepository
import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.ModulesLogRepository

@Module
abstract class LogReaderRepositoryModule {
    @Binds
    abstract fun provideModulesLogRepository(
        repository: ModulesLogRepositoryImpl
    ): ModulesLogRepository

    @Binds
    abstract fun provideConnectionRecordsRepository(
        repository: ConnectionRecordsRepositoryImpl
    ): ConnectionRecordsRepository
}
