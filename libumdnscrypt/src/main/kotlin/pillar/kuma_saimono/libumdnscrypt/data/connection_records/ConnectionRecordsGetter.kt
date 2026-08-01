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

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.util.Log
import pillar.kuma_saimono.libumdnscrypt.domain.connection_records.entities.ConnectionData
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPN
import pillar.kuma_saimono.libumdnscrypt.vpn.service.ServiceVPN.VPNBinder
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicBoolean
import javax.inject.Inject

class ConnectionRecordsGetter @Inject constructor(
    private val context: Context
) {

    private val bound = AtomicBoolean(false)

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            if (service is VPNBinder) {
                serviceVPN = WeakReference(service.service)
            }
        }

        override fun onServiceDisconnected(name: ComponentName) {
            if (bound.compareAndSet(true, false)) {
                serviceVPN = null
            }
        }
    }

    @Volatile
    private var serviceVPN: WeakReference<ServiceVPN?>? = null

    fun getConnectionRawRecords(): Map<ConnectionData, Long> {
        if (bound.compareAndSet(false, true)) {
            logi("ConnectionRecordsGetter bind to VPN service")
            bindToVPNService()
        }

        val rawRecords = try {
            serviceVPN?.get()?.dnsQueryRawRecords ?: emptyMap<ConnectionData, Long>()
        } catch (e: Exception) {
            logw("ConnectionRecordsGetter getConnectionRawRecords", e)
            emptyMap<ConnectionData, Long>()
        }

        return rawRecords
    }

    fun clearConnectionRawRecords() {
        try {
            serviceVPN?.get()?.clearDnsQueryRawRecords()
        } catch (e: java.lang.Exception) {
            logw("ConnectionRecordsGetter clearConnectionRawRecords", e)
        }
    }

    fun connectionRawRecordsNoMoreRequired() {
        unbindVPNService()
    }

    @Synchronized
    private fun bindToVPNService() {
        val intent = Intent(context, ServiceVPN::class.java)
        serviceConnection.let {
            context.bindService(intent, it, Context.BIND_IMPORTANT)
        }
    }

    private fun unbindVPNService() {
        if (bound.compareAndSet(true, false)) {
            logi("ConnectionRecordsGetter unbind VPN service")

            try {
                serviceConnection.let { context.unbindService(it) }
            } catch (e: Exception) {
                logw(
                    "ConnectionRecordsGetter unbindVPNService exception "
                            + e.message + " "
                            + e.cause + "\n"
                            + Log.getStackTraceString(e)
                )
            }
        }

    }
}
