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

package pillar.kuma_saimono.libumdnscrypt.data.connection_records

import kotlinx.coroutines.ExperimentalCoroutinesApi
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.ConnectionRecordsRepository
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionData
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.utils.enums.OperationMode
import javax.inject.Inject

@ExperimentalCoroutinesApi
class ConnectionRecordsRepositoryImpl @Inject constructor(
    private val connectionRecordsGetter: ConnectionRecordsGetter,
    private val nflogRecordsGetter: NflogRecordsGetter
) : ConnectionRecordsRepository {

    private val modulesStatus = ModulesStatus.getInstance()

    @Volatile
    private var savedMode = modulesStatus.mode

    override fun getRawConnectionRecords(): List<ConnectionData> =
        if (isVpnMode()) {

            if (modulesStatus.mode != savedMode) {
                stopNflogRecordsGetter()
                savedMode = modulesStatus.mode
            }

            connectionRecordsGetter.getConnectionRawRecords().toSortedKeysList()

        } else if (isFixTTL()) {

            (connectionRecordsGetter.getConnectionRawRecords() + nflogRecordsGetter.getConnectionRawRecords())
                .toSortedKeysList()


        } else if (isRootMode()) {

            if (modulesStatus.mode != savedMode) {
                stopConnectionRecordsGetter()
                savedMode = modulesStatus.mode
            }

            nflogRecordsGetter.getConnectionRawRecords().toSortedKeysList()
        } else {
            emptyList()
        }

    override fun clearConnectionRawRecords() {
        if (isVpnMode() || isFixTTL()) {
            connectionRecordsGetter.clearConnectionRawRecords()
        } else if (isRootMode()) {
            nflogRecordsGetter.clearConnectionRawRecords()
        }
    }

    override fun connectionRawRecordsNoMoreRequired() {
        if (isVpnMode() || isFixTTL()) {
            connectionRecordsGetter.connectionRawRecordsNoMoreRequired()
        }
    }

    private fun stopConnectionRecordsGetter() = with(connectionRecordsGetter) {
        clearConnectionRawRecords()
        connectionRawRecordsNoMoreRequired()
    }

    private fun stopNflogRecordsGetter() = with(nflogRecordsGetter) {
        clearConnectionRawRecords()
    }

    private fun isVpnMode() = modulesStatus.mode == OperationMode.VPN_MODE

    private fun isRootMode() = modulesStatus.mode == OperationMode.ROOT_MODE
            && !modulesStatus.isUseModulesWithRoot

    private fun isFixTTL() = modulesStatus.isFixTTL
            && modulesStatus.mode == OperationMode.ROOT_MODE
            && !modulesStatus.isUseModulesWithRoot

    private fun Map<ConnectionData, Long>.toSortedKeysList(): List<ConnectionData> = let { map ->
        map.entries.sortedBy { it.value }.map { it.key }
    }

}
