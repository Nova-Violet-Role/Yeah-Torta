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
import androidx.annotation.Keep
import dagger.BindsInstance
import dagger.Component
import pillar.kuma_saimono.libumdnscrypt.BootCompleteReceiver
import pillar.kuma_saimono.libumdnscrypt.di.arp.ArpSubcomponent
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceSubcomponent
import pillar.kuma_saimono.libumdnscrypt.di.tiles.TilesSubcomponent
import pillar.kuma_saimono.libumdnscrypt.dialogs.*

import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.dnscrypt.DNSCryptLogParser
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.installer.Installer
import pillar.kuma_saimono.libumdnscrypt.iptables.IptablesReceiver
import pillar.kuma_saimono.libumdnscrypt.iptables.Tethering
import pillar.kuma_saimono.libumdnscrypt.modules.*
import pillar.kuma_saimono.libumdnscrypt.settings.*
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_settings.RulesEraser
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_binary.CheckDnsCryptBinaryUpdateWorker
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.local.UpdateLocalDnsRulesWorker
import pillar.kuma_saimono.libumdnscrypt.update.DownloadTask
import pillar.kuma_saimono.libumdnscrypt.update.UpdateService
import pillar.kuma_saimono.libumdnscrypt.utils.apps.InstalledApplicationsManager
import pillar.kuma_saimono.libumdnscrypt.utils.executors.CachedExecutor
import pillar.kuma_saimono.libumdnscrypt.utils.executors.CoroutineExecutor
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileManager
import pillar.kuma_saimono.libumdnscrypt.utils.integrity.Verifier
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootExecService
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.remote.UpdateRemoteDnsRulesWorker
import pillar.kuma_saimono.libumdnscrypt.settings.dnscrypt_rules.existing.RemixExistingDnsRulesWorker
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPNHandler
import javax.inject.Singleton

@Singleton
@Component(
    modules = [SharedPreferencesModule::class, RepositoryModule::class,
        DataSourcesModule::class, HelpersModule::class, CoroutinesModule::class,
        HandlerModule::class, InteractorsModule::class, ViewModelModule::class,
        AppSubcomponentModule::class]
)
@Keep
interface AppComponent {
    fun tilesSubcomponent(): TilesSubcomponent.Factory
    fun arpSubcomponent(): ArpSubcomponent.Factory
    fun modulesServiceSubcomponent(): ModulesServiceSubcomponent.Factory

    fun getPathVars(): dagger.Lazy<PathVars>
    fun getPreferenceRepository(): dagger.Lazy<PreferenceRepository>
    fun getCachedExecutor(): CachedExecutor
    fun getCoroutineExecutor(): CoroutineExecutor

    @Component.Builder
    interface Builder {
        @BindsInstance
        fun appContext(context: Context): Builder
        fun build(): AppComponent
    }


    fun inject(service: ModulesService)
    fun inject(service: RootExecService)
    fun inject(service: UpdateService)
    fun inject(receiver: BootCompleteReceiver)
    fun inject(receiver: IptablesReceiver)
    fun inject(dialogFragment: RequestIgnoreBatteryOptimizationDialog)
    fun inject(dialogFragment: RequestIgnoreDataRestrictionDialog)
    fun inject(dialogFragment: SendCrashReport)
    fun inject(usageStatistic: UsageStatistic)
    fun inject(modulesKiller: ModulesKiller)
    fun inject(contextUIDUpdater: ContextUIDUpdater)
    fun inject(downloadTask: DownloadTask)
    fun inject(fileManager: FileManager)
    fun inject(verifier: Verifier)
    fun inject(modulesStarterHelper: ModulesStarterHelper)
    fun inject(tethering: Tethering)
    fun inject(serviceVPNHandler: ServiceVPNHandler)
    fun inject(installer: Installer)
    fun inject(installedApplicationsManager: InstalledApplicationsManager)
    fun inject(rulesEraser: RulesEraser)
    fun inject(worker: UpdateRemoteDnsRulesWorker)
    fun inject(worker: UpdateLocalDnsRulesWorker)
    fun inject(worker: RemixExistingDnsRulesWorker)
    fun inject(worker: CheckDnsCryptBinaryUpdateWorker)
    fun inject(parser: DNSCryptLogParser)
}
