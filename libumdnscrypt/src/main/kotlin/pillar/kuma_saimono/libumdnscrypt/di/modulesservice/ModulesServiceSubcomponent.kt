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

package pillar.kuma_saimono.libumdnscrypt.di.modulesservice

import dagger.Subcomponent
import pillar.kuma_saimono.libumdnscrypt.di.logreader.LogReaderSubcomponent
import pillar.kuma_saimono.libumdnscrypt.dialogs.ChangeModeDialog
import pillar.kuma_saimono.libumdnscrypt.iptables.ModulesIptablesRules
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPN

@ModulesServiceScope
@Subcomponent(modules = [ModulesServiceSubcomponentModule::class])
interface ModulesServiceSubcomponent {

    fun logReaderSubcomponent(): LogReaderSubcomponent.Factory

    @Subcomponent.Factory
    interface Factory {
        fun create(): ModulesServiceSubcomponent
    }

    fun inject(service: ServiceVPN)
    fun inject(modulesIptablesRules: ModulesIptablesRules)
    fun inject(changeModeDialog: ChangeModeDialog)
}
