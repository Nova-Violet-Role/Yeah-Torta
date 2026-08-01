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

package pillar.kuma_saimono.libumdnscrypt.domain.log_reader

import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.ConnectionRecordsInteractor
import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.dnscrypt.DNSCryptInteractor
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState

class LogReaderFacade(
    private val dnsCryptInteractor: DNSCryptInteractor,
    private val connectionRecordsInteractor: ConnectionRecordsInteractor
) {
    private val modulesStatus = ModulesStatus.getInstance()

    fun parseDNSCryptLog() {
        if (dnsCryptInteractor.hasAnyListener()) {
            dnsCryptInteractor.parseDNSCryptLog()
        } else {
            dnsCryptInteractor.resetParserState()
        }
    }

    fun convertConnectionRecords() {
        if (connectionRecordsInteractor.hasAnyListener()) {
            connectionRecordsInteractor.convertRecords()
        }
    }

    fun isAnyListenerAvailable(): Boolean {
        return dnsCryptInteractor.hasAnyListener()
                || connectionRecordsInteractor.hasAnyListener()
    }

    fun isModulesStateNotChanging(): Boolean {
        return (modulesStatus.dnsCryptState == ModuleState.STOPPED ||
                modulesStatus.dnsCryptState == ModuleState.FAULT ||
                modulesStatus.dnsCryptState == ModuleState.RUNNING && modulesStatus.isDnsCryptReady)
    }
}
