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

package pillar.kuma_saimono.libumdnscrypt.installer

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.TopFragmentState.TOP_BROADCAST
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesAux
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesStatus
import pillar.kuma_saimono.libumdnscrypt.modules.ModulesVersions
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.executors.CoroutineExecutor
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.MAIN_ACTIVITY_RECREATE
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark.Companion.INSTALLER_MARK
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootExecService.Companion.COMMAND_RESULT
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Named

class Installer(private val activity: Activity) {

    @Inject
    lateinit var pathVars: dagger.Lazy<PathVars>
    @Inject
    @field:Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    lateinit var defaultPreferences: dagger.Lazy<SharedPreferences>
    @Inject
    lateinit var preferenceRepository: dagger.Lazy<PreferenceRepository>
    @Inject
    lateinit var executor: CoroutineExecutor
    @Inject
    lateinit var modulesVersions: dagger.Lazy<ModulesVersions>
    @Inject
    lateinit var installerHelper: dagger.Lazy<InstallerHelper>

    private var br: InstallerReceiver? = null
    private val appDataDir: String

    init {
        App.instance.daggerComponent.inject(this)

        appDataDir = pathVars.get().appDataDir
    }

    fun installModules() {

        try {
            registerReceiver(activity)

            if (ModulesStatus.getInstance().isRootAvailable
                    && ModulesStatus.getInstance().isUseModulesWithRoot) {
                stopAllRunningModulesWithRootCommand()
            } else {
                stopAllRunningModulesWithNoRootCommand()
            }

            if (!waitUntilAllModulesStopped()) {
                throw IllegalStateException("Unexpected interruption")
            }

            if (interruptInstallation) {
                throw IllegalStateException("Installation interrupted")
            }

            unRegisterReceiver(activity)

            removeInstallationDirsIfExists()
            createLogsDir()

            extractDNSCrypt()

            chmodExtractedDirs()

            correctAppDir()

            savePreferencesModulesInstalled(true)

            refreshModulesStatus(activity)

            TimeUnit.SECONDS.sleep(1)

        } catch (e: Exception) {
            loge("Installation fault", e)

            savePreferencesModulesInstalled(false)
        }


    }

    private fun extractDNSCrypt() {
        var command: Command = DNSCryptExtractCommand(activity, appDataDir)
        command.execute()

        changeDnsCryptFilesDateToForceUpdate()

        // BUSYBOX REMOVED (checkpoint 100). `assets/busyb.mp3` was a ZIP-renamed-to-.mp3 carrying a
        // busybox binary dated 2020-01-11. It is gone, and the measurements that justified removing it
        // rather than "wiring" it are worth keeping:
        //   * this device has NO `app_bin/` at all after a full run with the VPN up and DNS resolving,
        //     so nothing ever extracted it;
        //   * `Installer` is instantiated NOWHERE in the tree and `installModules()` has no callers,
        //     so the only path that could extract it is itself unreachable;
        //   * Tortä debugs with TOYBOX (`toybox nc`), which Android ships in /system/bin — a second,
        //     five-year-old shell multiplexer earns nothing but 850 KB of APK.
        // The `.mp3` extension bought nothing either: this build declares no `noCompress`/`aaptOptions`,
        // so the extension was inherited disguise, not a packaging optimisation.

        logi("Installer: extractDNSCrypt OK")
    }

    private fun changeDnsCryptFilesDateToForceUpdate() {

        val files: MutableList<String> = ArrayList()
        val dnsCryptFilesPath = appDataDir + "/app_data/dnscrypt-proxy/"
        files.add(dnsCryptFilesPath + "odoh-relays.md")
        files.add(dnsCryptFilesPath + "odoh-servers.md")
        files.add(dnsCryptFilesPath + "public-resolvers.md")
        files.add(dnsCryptFilesPath + "relays.md")

        try {
            for (path in files) {
                val file = File(path)
                if (file.isFile) {
                    //noinspection ResultOfMethodCallIgnored
                    file.setLastModified(
                        System.currentTimeMillis() - DNSCRYPT_FILES_TIME_BEFORE_NOW_DAYS * 24 * 60 * 60 * 1000
                    )
                }
            }
        } catch (e: Exception) {
            loge("Installer changeDnsCryptFilesDate", e)
        }
    }

    private fun savePreferencesModulesInstalled(installed: Boolean) {

        val preferences = preferenceRepository.get()

        if (installed) {
            preferences.setBoolPreference("DNSCrypt Installed", true)
        } else {
            preferences.setBoolPreference("DNSCrypt Installed", false)
        }

    }

    private fun waitUntilAllModulesStopped(): Boolean {
        countDownLatch = CountDownLatch(1)
        logi("Installer: waitUntilAllModulesStopped")

        var result = true
        try {
            if (countDownLatch != null) {
                //noinspection ResultOfMethodCallIgnored
                countDownLatch!!.await(10, TimeUnit.SECONDS)
            }
        } catch (e: InterruptedException) {
            loge("Installer CountDownLatch interrupted")
            result = false
        } catch (e: Exception) {
            loge("Installer waitUntilAllModulesStopped", e, true)
        }

        return result
    }

    private fun removeInstallationDirsIfExists() {
        val app_bin = File(appDataDir + "/app_bin")
        val app_data = File(appDataDir + "/app_data")

        var warn = ""

        if (app_bin.isDirectory) {
            if (!FileManager.deleteDirSynchronous(activity, app_bin.absolutePath)) {
                warn = app_bin.absolutePath + " delete failed"
            }
        } else if (app_bin.isFile) {
            if (FileManager.deleteFileSynchronous(activity, app_bin.parent, app_bin.name)) {
                warn = app_bin.absolutePath + " delete failed"
            }
        }

        if (app_data.isDirectory) {
            if (!FileManager.deleteDirSynchronous(activity, app_data.absolutePath)) {
                warn = app_bin.absolutePath + " delete failed"
            }
        } else if (app_data.isFile) {
            if (FileManager.deleteFileSynchronous(activity, app_data.parent, app_data.name)) {
                warn = app_bin.absolutePath + " delete failed"
            }
        }

        if (warn.isEmpty()) {
            logi("Installer: removeInstallationDirsIfExists OK")
        } else {
            logw(warn)
        }

    }

    private fun chmodExtractedDirs() {
        ChmodCommand.dirChmod(appDataDir + "/app_bin", true)
        ChmodCommand.dirChmod(appDataDir + "/app_data", false)

        logi("Installer: chmodExtractedDirs OK")
    }

    private fun correctAppDir() {
        val dnsTomlPath = appDataDir + "/app_data/dnscrypt-proxy/dnscrypt-proxy.toml"
        fixAppDirLinesList(dnsTomlPath, FileManager.readTextFileSynchronous(activity, dnsTomlPath))

        logi("Installer: correctAppDir OK")
    }

    @SuppressLint("SdCardPath")
    private fun fixAppDirLinesList(path: String, lines: MutableList<String>?) {
        if (lines != null) {
            var line: String
            for (i in lines.indices) {
                line = lines[i]
                if (line.contains("/data/user/0/pillar.kuma_saimono.libumdnscrypt")) {
                    line = line.replace("/data/user/0/pillar.kuma_saimono.libumdnscrypt.*?/".toRegex(), appDataDir + "/")
                    lines[i] = line
                }
            }

            var result: List<String> = lines
            // `activity != null` dropped (constant); the .gp / path / not-installed terms stay.
            if (activity.getText(R.string.package_name).toString().contains(".gp")
                    && path.contains("dnscrypt-proxy.toml")
                    && !PathVars.isModulesInstalled(preferenceRepository.get())) {
                result = installerHelper.get().prepareDNSCryptForGP(lines)
            }

            FileManager.writeTextFileSynchronous(activity, path, result)
        } else {
            throw IllegalStateException("correctAppDir readTextFile return null " + path)
        }
    }

    private fun stopAllRunningModulesWithRootCommand() {
        logi("Installer: stopAllRunningModulesWithRootCommand")

        ModulesAux.saveDNSCryptStateRunning(false)

        var busyboxNative = ""
        if (preferenceRepository.get().getBoolPreference("bbOK")
                && pathVars.get().busyboxPath == "busybox ") {
            busyboxNative = "busybox "
        }

        val commandsInstall = arrayListOf(
            "ip6tables -D OUTPUT -j DROP 2> /dev/null || true",
            "ip6tables -I OUTPUT -j DROP 2> /dev/null",
            "iptables -t nat -F libumdnscrypt_nat_output 2> /dev/null",
            "iptables -t nat -D OUTPUT -j libumdnscrypt_nat_output 2> /dev/null || true",
            "iptables -F libumdnscrypt 2> /dev/null",
            "iptables -D OUTPUT -j libumdnscrypt 2> /dev/null || true",
            "iptables -t nat -F libumdnscrypt_prerouting 2> /dev/null",
            "iptables -F libumdnscrypt_forward 2> /dev/null",
            "iptables -t nat -D PREROUTING -j libumdnscrypt_prerouting 2> /dev/null || true",
            "iptables -D FORWARD -j libumdnscrypt_forward 2> /dev/null || true",
            busyboxNative + "pkill -SIGTERM /libdnscrypt-proxy.so 2> /dev/null || true",
            busyboxNative + "sleep 7 2> /dev/null",
            busyboxNative + "pgrep -l /libdnscrypt-proxy.so 2> /dev/null",
            busyboxNative + "echo 'checkModulesRunning' 2> /dev/null"
        )

        RootCommands.execute(activity, commandsInstall, INSTALLER_MARK)
    }

    private fun stopAllRunningModulesWithNoRootCommand() {

        executor.submit("Installer stopAllRunningModulesWithNoRootCommand") {
            ModulesAux.stopModulesIfRunning(activity)

            var counter = 15

            while (counter > 0) {
                // `activity != null` dropped (constant); the DNSCrypt state check is the real one.
                if (!ModulesAux.isDnsCryptSavedStateRunning()) {
                    sendModulesStopResult("checkModulesRunning")
                    break
                } else {
                    try {
                        TimeUnit.SECONDS.sleep(1)
                        counter--
                    } catch (ignored: InterruptedException) {
                        counter = 0
                        break
                    }
                }
            }

            if (counter <= 0) {
                sendModulesStopResult("")
            }
        }


    }

    private fun sendModulesStopResult(result: String) {
        val comResult = RootCommands(arrayListOf(result))
        val intent = Intent(COMMAND_RESULT)
        intent.putExtra("CommandsResult", comResult)
        intent.putExtra("Mark", INSTALLER_MARK)
        LocalBroadcastManager.getInstance(activity).sendBroadcast(intent)
    }

    private fun createLogsDir() {
        val logDir = File(appDataDir + "/logs")
        if (!logDir.isDirectory) {
            if (logDir.mkdir()) {
                ChmodCommand.dirChmod(logDir.absolutePath, false)
            } else {
                throw IllegalStateException("Installer Create log dir failed")
            }
        }

        logi("Installer: createLogsDir OK")
    }

    private fun refreshModulesStatus(activity: Activity) {
        if (ModulesStatus.getInstance().isRootAvailable
                && ModulesStatus.getInstance().isUseModulesWithRoot) {
            val intent = Intent(TOP_BROADCAST)
            LocalBroadcastManager.getInstance(activity).sendBroadcast(intent)
        } else {
            modulesVersions.get().refreshVersions(activity)
        }

        preferenceRepository.get().setBoolPreference(MAIN_ACTIVITY_RECREATE, true)
    }

    private fun registerReceiver(activity: Activity) {
        br = InstallerReceiver()
        val intentFilter = IntentFilter(COMMAND_RESULT)
        LocalBroadcastManager.getInstance(activity).registerReceiver(br!!, intentFilter)

        logi("Installer: registerReceiver OK")
    }

    private fun unRegisterReceiver(activity: Activity) {
        if (br != null) {
            LocalBroadcastManager.getInstance(activity).unregisterReceiver(br!!)

            logi("Installer: unregisterReceiver OK")
        }
    }

    companion object {

        private const val DNSCRYPT_FILES_TIME_BEFORE_NOW_DAYS = 5

        @Volatile
        private var countDownLatch: CountDownLatch? = null

        private var interruptInstallation = false

        fun continueInstallation(interruptInstallation: Boolean) {
            if (countDownLatch != null) {
                countDownLatch!!.countDown()
                countDownLatch = null
                Installer.interruptInstallation = interruptInstallation
            }
        }
    }

}
