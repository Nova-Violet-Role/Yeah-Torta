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

package pillar.kuma_saimono.libumdnscrypt.backup

import android.annotation.SuppressLint
import android.content.Context
import androidx.annotation.WorkerThread
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.installer.ChmodCommand
import pillar.kuma_saimono.libumdnscrypt.installer.DNSCryptExtractCommand
import pillar.kuma_saimono.libumdnscrypt.installer.InstallerHelper
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleName
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import javax.inject.Inject

class ResetModuleHelper @Inject constructor(
    private val context: Context,
    pathVars: PathVars,
    private val installerHelper: InstallerHelper
) {

    private val dataDir = pathVars.appDataDir

    @WorkerThread
    fun resetModuleSettings(moduleName: ModuleName) = try {
        logw("Resetting ${moduleName.moduleName} settings")

        cleanModuleFolder(moduleName)
        extractModuleData(moduleName)
        correctAppDir(moduleName)

        logw("Reset ${moduleName.moduleName} settings success")
    } catch (e: Exception) {
        loge("Reset ${moduleName.moduleName} settings error", e)
    }

    private fun cleanModuleFolder(moduleName: ModuleName) {
        when (moduleName) {
            ModuleName.DNSCRYPT_MODULE -> {
                FileManager.deleteDirSynchronous(
                    context,
                    "$dataDir/app_data/dnscrypt-proxy"
                )
            }

            else -> {}
        }
    }

    private fun extractModuleData(moduleName: ModuleName) {
        when (moduleName) {
            ModuleName.DNSCRYPT_MODULE -> {
                DNSCryptExtractCommand(context, dataDir).execute()
                ChmodCommand.dirChmod("$dataDir/app_data/dnscrypt-proxy", false)
            }

            else -> {}
        }


    }

    private fun correctAppDir(moduleName: ModuleName) {
        val path = when (moduleName) {
            ModuleName.DNSCRYPT_MODULE -> "$dataDir/app_data/dnscrypt-proxy/dnscrypt-proxy.toml"
            else -> return
        }
        updateAppDir(path)
    }

    @SuppressLint("SdCardPath")
    private fun updateAppDir(path: String) {
        var lines = FileManager.readTextFileSynchronous(context, path)
        var line: String
        for (i in lines.indices) {
            line = lines[i]
            if (line.contains("/data/user/0/pillar.kuma_saimono.libumdnscrypt")) {
                line = line.replace(
                    "/data/user/0/pillar.kuma_saimono.libumdnscrypt.*?/".toRegex(),
                    "$dataDir/"
                )
                lines[i] = line
            }
        }

        if (context.isGpVersion() && path.contains("dnscrypt-proxy.toml")) {
            lines = installerHelper.prepareDNSCryptForGP(lines).toMutableList()
        }

        FileManager.writeTextFileSynchronous(context, path, lines)
    }

    private fun Context.isGpVersion() = getString(R.string.package_name).contains(".gp")
}
