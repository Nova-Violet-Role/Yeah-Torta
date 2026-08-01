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

package pillar.kuma_saimono.libumdnscrypt.modules

import android.app.Service
import android.content.Context
import android.content.Intent
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import dagger.Lazy
import eu.chainfire.libsuperuser.Shell
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RESTARTING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.RUNNING
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPED
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleState.STOPPING
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark.Companion.DNSCRYPT_RUN_FRAGMENT_MARK
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootExecService.Companion.COMMAND_RESULT
import java.io.File
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import javax.inject.Inject

class ModulesKiller(
    private val service: Service,
    pathVars: PathVars
) {

    @Inject
    lateinit var preferenceRepository: Lazy<PreferenceRepository>

    private val appDataDir: String
    private val busyboxPath: String
    private val dnscryptPath: String

    private val modulesStatus: ModulesStatus

    private val reentrantLock: ReentrantLock

    init {
        App.instance.daggerComponent.inject(this)
        appDataDir = pathVars.appDataDir
        busyboxPath = pathVars.busyboxPath
        dnscryptPath = pathVars.dnsCryptPath
        modulesStatus = ModulesStatus.getInstance()
        reentrantLock = ReentrantLock()
    }

    private fun sendResultIntent(moduleMark: Int, moduleKeyWord: String, binaryPath: String) {
        val comResult = RootCommands(arrayListOf(moduleKeyWord, binaryPath))
        val intent = Intent(COMMAND_RESULT)
        intent.putExtra("CommandsResult", comResult)
        intent.putExtra("Mark", moduleMark)
        LocalBroadcastManager.getInstance(service).sendBroadcast(intent)
    }

    private fun makeDelay(sec: Int) {
        try {
            TimeUnit.SECONDS.sleep(sec.toLong())
        } catch (e: InterruptedException) {
            loge("Modules killer makeDelay interrupted!", e)
        }
    }

    fun setDnsCryptThread(dnsCryptThread: Thread?) {
        Companion.dnsCryptThread = dnsCryptThread
    }

    fun getDnsCryptThread(): Thread? {
        return dnsCryptThread
    }

    fun getDNSCryptKillerRunnable(): Runnable {
        return Runnable {

            // ★ STAGE 2 (2026-07-04): DNSCrypt IS the pure-Rust tunnel — there is NO Go dnscrypt-proxy
            // process to kill (libdnscrypt-proxy.so is DELETED). The legacy pkill dance below wasted
            // 6-13s trying to `pkill /libdnscrypt-proxy.so` (always "result false"), then interrupted a
            // thread that isn't a process — disrupting the LIVE Rust tunnel. The real teardown is owned
            // by ServiceVPN.stopNative() → tunnelController.stop(). So the killer just marks the module
            // STOPPED cleanly (or leaves RUNNING if a RESTARTING edge) and returns — no process kill.
            if (modulesStatus.dnsCryptState != RESTARTING) {
                ModulesAux.saveDNSCryptStateRunning(false)
                modulesStatus.dnsCryptState = STOPPED
                sendResultIntent(DNSCRYPT_RUN_FRAGMENT_MARK, ModulesService.DNSCRYPT_KEYWORD, "")
                logw("DNSCrypt stopped — pure-Rust tunnel (no process to kill; teardown via "
                        + "ServiceVPN.stopNative → tunnelController.stop)")
            }
            Thread.currentThread().interrupt()
            if (true) return@Runnable
            /*
            if (modulesStatus.getDnsCryptState() != RESTARTING) {
                modulesStatus.setDnsCryptState(STOPPING);
            }

            reentrantLock.lock();

            try {
                String dnsCryptPid = readPidFile(appDataDir + "/dnscrypt-proxy.pid");

                boolean moduleStartedWithRoot = preferenceRepository.get()
                        .getBoolPreference("DNSCryptStartedWithRoot");
                boolean rootIsAvailable = modulesStatus.isRootAvailable();

                boolean result = doThreeAttemptsToStopModule(dnscryptPath, dnsCryptPid, dnsCryptThread, moduleStartedWithRoot);

                if (!result) {

                    if (rootIsAvailable) {
                        logw("ModulesKiller cannot stop DNSCrypt. Stop with root method!");
                        result = killModule(dnscryptPath, dnsCryptPid, dnsCryptThread, true, "SIGKILL", 10);
                    }

                    if (!moduleStartedWithRoot && !result) {
                        logw("ModulesKiller cannot stop DNSCrypt. Stop with interrupt thread!");

                        makeDelay(5);

                        result = stopModuleWithInterruptThread(dnsCryptThread);
                    }
                }

                if (moduleStartedWithRoot) {
                    if (!result) {
                        if (modulesStatus.getDnsCryptState() != RESTARTING) {
                            ModulesAux.saveDNSCryptStateRunning(true);
                            makeDelay(1);
                            sendResultIntent(DNSCRYPT_RUN_FRAGMENT_MARK, DNSCRYPT_KEYWORD, dnscryptPath);
                        }

                        modulesStatus.setDnsCryptState(RUNNING);

                        loge("ModulesKiller cannot stop DNSCrypt!");

                    } else {
                        if (modulesStatus.getDnsCryptState() != RESTARTING) {
                            ModulesAux.saveDNSCryptStateRunning(false);
                            modulesStatus.setDnsCryptState(STOPPED);
                            makeDelay(1);
                            sendResultIntent(DNSCRYPT_RUN_FRAGMENT_MARK, DNSCRYPT_KEYWORD, "");
                        }
                    }
                } else {
                    if (dnsCryptThread != null && dnsCryptThread.isAlive()) {

                        if (modulesStatus.getDnsCryptState() != RESTARTING) {
                            ModulesAux.saveDNSCryptStateRunning(true);
                            makeDelay(1);
                            sendResultIntent(DNSCRYPT_RUN_FRAGMENT_MARK, DNSCRYPT_KEYWORD, dnscryptPath);
                        }

                        modulesStatus.setDnsCryptState(RUNNING);

                        loge("ModulesKiller cannot stop DNSCrypt!");
                    } else {

                        if (modulesStatus.getDnsCryptState() != RESTARTING) {
                            ModulesAux.saveDNSCryptStateRunning(false);
                            modulesStatus.setDnsCryptState(STOPPED);
                            makeDelay(1);
                            sendResultIntent(DNSCRYPT_RUN_FRAGMENT_MARK, DNSCRYPT_KEYWORD, "");
                        }
                    }
                }
            } catch (Exception e){
                loge("ModulesKiller getDNSCryptKillerRunnable", e);
            } finally {
                reentrantLock.unlock();
            }
            */
        }
    }

    private fun killModule(module: String, pid: String, thread: Thread?, killWithRoot: Boolean, signal: String, delaySec: Int): Boolean {
        var module = module
        var result = false

        if (module.contains("/")) {
            module = module.substring(module.lastIndexOf("/"))
        }

        val preparedCommands = prepareKillCommands(module, pid, signal, killWithRoot)

        if ((thread == null || !thread.isAlive) && modulesStatus.isRootAvailable
            || killWithRoot
        ) {

            val sleep = busyboxPath + "sleep " + delaySec
            val checkString = busyboxPath + "pgrep -l " + module

            val commands = ArrayList(preparedCommands)
            commands.add(sleep)
            commands.add(checkString)

            val shellResult = killWithSU(module, commands)

            if (shellResult != null) {
                result = !shellResult.toString().lowercase(Locale.getDefault()).contains(module.lowercase(Locale.getDefault()).trim())
            }

            if (shellResult != null) {
                logi("Kill " + module + " with root: result " + result + "\n" + shellResult)
            } else {
                logi("Kill " + module + " with root: result false")
            }
        } else {

            if (!pid.isEmpty()) {
                killWithPid(signal, pid, delaySec)
            }

            if (thread != null) {
                result = !thread.isAlive
            }

            var shellResult: List<String>? = null
            if (!result) {
                shellResult = killWithSH(module, preparedCommands, delaySec)

                if (thread != null) {
                    result = !thread.isAlive
                }
            }

            if (shellResult != null) {
                logi("Kill " + module + " without root: result " + result + "\n" + shellResult)
            } else {
                logi("Kill " + module + " without root: result " + result)
            }
        }

        return result
    }

    private fun killWithPid(signal: String, pid: String, delay: Int) {
        try {
            if (signal.isEmpty()) {
                android.os.Process.sendSignal(pid.toInt(), 15)
            } else {
                android.os.Process.killProcess(pid.toInt())
            }
            makeDelay(delay)
        } catch (e: Exception) {
            loge("ModulesKiller killWithPid", e)
        }
    }

    @Suppress("DEPRECATION")
    private fun killWithSH(module: String, commands: List<String>, delay: Int): List<String>? {
        var shellResult: List<String>? = null
        try {
            shellResult = Shell.SH.run(commands)
            makeDelay(delay)
        } catch (e: Exception) {
            loge("Kill " + module + " without root", e)
        }
        return shellResult
    }

    @Suppress("DEPRECATION")
    private fun killWithSU(module: String, commands: List<String>): List<String>? {
        var shellResult: List<String>? = null
        try {
            shellResult = Shell.SU.run(commands)
        } catch (e: Exception) {
            loge("Kill " + module + " with root", e)
        }
        return shellResult
    }

    //kill default signal SIGTERM - 15, SIGKILL -9, SIGQUIT - 3
    private fun prepareKillCommands(module: String, pid: String, signal: String, killWithRoot: Boolean): List<String> {
        val shell: String
        if (modulesStatus.isRootAvailable) {
            shell = "su"
        } else {
            shell = "sh"
        }

        val result: List<String>

        if (pid.isEmpty() || killWithRoot) {
            var killStringToyBox = "toybox pkill " + module + " || true"
            var killString = "pkill " + module + " || true"
            var killStringBusybox = busyboxPath + "pkill " + module + " || true"
            var killAllStringBusybox = busyboxPath + shell + " -c \"kill \$(" + busyboxPath + "pgrep " + module + ")\" || true"
            if (!signal.isEmpty()) {
                killStringToyBox = "toybox pkill -" + signal + " " + module + " || true"
                killString = "pkill -" + signal + " " + module + " || true"
                killStringBusybox = busyboxPath + "pkill -" + signal + " " + module + " || true"
                killAllStringBusybox = busyboxPath + shell + " -c \"kill -s " + signal + " \$(" + busyboxPath + "pgrep " + module + ")\" || true"
            }

            result = arrayListOf(
                killStringBusybox,
                killAllStringBusybox,
                killStringToyBox,
                killString
            )
        } else {
            var killAllStringToolBox = "toolbox kill " + pid + " || true"
            var killStringToyBox = "toybox kill " + pid + " || true"
            var killString = "kill " + pid + " || true"
            var killStringBusyBox = busyboxPath + "kill " + pid + " || true"
            if (!signal.isEmpty()) {
                killAllStringToolBox = "toolbox kill -s " + signal + " " + pid + " || true"
                killStringToyBox = "toybox kill -s " + signal + " " + pid + " || true"
                killString = "kill -s " + signal + " " + pid + " || true"
                killStringBusyBox = busyboxPath + "kill -s " + signal + " " + pid + " || true"
            }

            result = arrayListOf(
                killStringBusyBox,
                killAllStringToolBox,
                killStringToyBox,
                killString
            )
        }

        return result
    }

    private fun doThreeAttemptsToStopModule(modulePath: String, pid: String, thread: Thread?, moduleStartedWithRoot: Boolean): Boolean {
        var result = false
        var attempts = 0
        while (attempts < 3 && !result) {
            if (attempts < 2) {
                result = killModule(modulePath, pid, thread, moduleStartedWithRoot, "", attempts + 2)
            } else {
                result = killModule(modulePath, pid, thread, moduleStartedWithRoot, "SIGKILL", attempts + 1)
            }

            attempts++
        }
        return result
    }

    private fun stopModuleWithInterruptThread(thread: Thread?): Boolean {
        var result = false
        var attempts = 0

        try {
            while (attempts < 3 && !result) {
                if (thread != null && thread.isAlive) {
                    thread.interrupt()
                    makeDelay(3)
                }

                if (thread != null) {
                    result = !thread.isAlive
                }

                attempts++
            }
        } catch (e: Exception) {
            loge("Kill with interrupt thread", e)
        }

        return result
    }

    private fun readPidFile(path: String): String {
        var pid = ""

        val file = File(path)
        if (file.isFile) {
            val lines = FileManager.readTextFileSynchronous(service, path)

            for (line in lines) {
                if (!line.trim().isEmpty()) {
                    pid = line.trim()
                    break
                }
            }
        }
        return pid
    }

    companion object {

        private var dnsCryptThread: Thread? = null

        @JvmStatic
        fun stopDNSCrypt(context: Context) {
            sendStopIntent(context, ModulesServiceActions.ACTION_STOP_DNSCRYPT)
        }

        private fun sendStopIntent(context: Context, action: String) {
            ModulesActionSender.sendIntent(context, action)
        }

        @Suppress("DEPRECATION")
        @JvmStatic
        fun forceCloseApp(pathVars: PathVars) {
            val modulesStatus = ModulesStatus.getInstance()
            if (modulesStatus.isRootAvailable) {

                val iptablesPath = pathVars.getIptablesPath()
                val ip6tablesPath = pathVars.getIp6tablesPath()
                val busyboxPath = pathVars.busyboxPath

                modulesStatus.isUseModulesWithRoot = true
                modulesStatus.dnsCryptState = STOPPED

                val commands = arrayOf(
                    ip6tablesPath + "-D OUTPUT -j DROP 2> /dev/null || true",
                    ip6tablesPath + "-I OUTPUT -j DROP",
                    iptablesPath + "-t nat -F libumdnscrypt_nat_output 2> /dev/null",
                    iptablesPath + "-t nat -D OUTPUT -j libumdnscrypt_nat_output 2> /dev/null || true",
                    iptablesPath + "-F libumdnscrypt 2> /dev/null",
                    iptablesPath + "-D OUTPUT -j libumdnscrypt 2> /dev/null || true",
                    iptablesPath + "-t nat -F libumdnscrypt_prerouting 2> /dev/null",
                    iptablesPath + "-F libumdnscrypt_forward 2> /dev/null",
                    iptablesPath + "-t nat -D PREROUTING -j libumdnscrypt_prerouting 2> /dev/null || true",
                    iptablesPath + "-D FORWARD -j libumdnscrypt_forward 2> /dev/null || true",
                    busyboxPath + "killall -s SIGKILL libdnscrypt-proxy.so || true"
                )

                Thread { Shell.SU.run(commands) }.start()
            }
        }
    }
}
