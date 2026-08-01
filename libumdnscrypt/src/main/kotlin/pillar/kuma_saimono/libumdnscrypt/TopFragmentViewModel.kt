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

package pillar.kuma_saimono.libumdnscrypt

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import eu.chainfire.libsuperuser.Shell
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import pillar.kuma_saimono.libumdnscrypt.backup.ResetModuleHelper
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleName
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import javax.inject.Inject
import javax.inject.Named

private const val CHECK_ROOT_TIMEOUT_SEC = 5

class TopFragmentViewModel @Inject constructor(
    @Named(CoroutinesModule.DISPATCHER_IO)
    private val dispatcherIo: CoroutineDispatcher,
    private val resetModuleHelper: dagger.Lazy<ResetModuleHelper>
): ViewModel() {

    private val rootStateMutableLiveData = MutableLiveData<RootState>(RootState.Undefined)
    val rootStateLiveData: LiveData<RootState> get() = rootStateMutableLiveData

    @Volatile
    var rootCheckResultSuccess = false

    private var checkRootJob: Job? = null

    fun checkRootAvailable() {

        if (checkRootJob?.isActive == true) {
            return
        }

        checkRootJob = viewModelScope.launch(dispatcherIo) {
            try {
                withTimeout(CHECK_ROOT_TIMEOUT_SEC * 1000L) {
                    checkRootParams()
                }
            } catch (e: Exception) {
                rootCheckResultSuccess = false
                rootStateMutableLiveData.postValue(RootState.RootNotAvailable)
            }
        }
    }

    fun cancelRootChecking() {
        if (checkRootJob?.isActive == true) {
            checkRootJob?.cancel()
        }
    }

    private fun checkRootParams() {
        val suAvailable = try {
            Shell.SU.available()
        } catch (e: Exception) {
            loge("TopFragmentViewModel suAvailable exception", e)
            false
        }

        var suVersion = ""
        val suResult = mutableListOf<String>()
        val bbResult = mutableListOf<String>()

        if (suAvailable) {
            try {
                suVersion = Shell.SU.version(false) ?: ""
                // TWO SHELL LIBRARIES ARE IN THIS BUILD, and that is the whole explanation.
                //   eu.chainfire:libsuperuser:1.1.1      (build.gradle:227) -- Shell.SU.run is
                //                                         deprecated in EVERY overload: String,
                //                                         String[] and List all carry it.
                //   com.jrummyapps:android-shell:1.0.1   (build.gradle:228) -- not deprecated, and
                //                                         already used for root commands by
                //                                         NflogManager, CommandExecutor and
                //                                         ModulesVersions.
                //
                // I first "fixed" this by switching the String overload for the array one and
                // recorded that the array form was the replacement. IT IS NOT -- the warning simply
                // changed identity and the count stayed at 2. The files I cited as evidence were
                // not using a better overload, they were importing the OTHER LIBRARY. Measuring
                // which import each file used is what settled it; the overload theory never
                // survived contact with the compiler.
                //
                // So the command execution moves to the non-deprecated library, fully qualified so
                // the swap is visible at the call site. Root DETECTION (available/version, above)
                // stays on libsuperuser deliberately: it is not deprecated, and silently changing
                // which library decides whether this device is rooted is a behaviour change nobody
                // asked for.
                //
                // jrummyapps' run() returns CommandResult, whose `stdout` is the same List<String>
                // libsuperuser returned directly -- so the two `addAll` calls receive exactly what
                // they received before.
                suResult.addAll(
                    com.jrummyapps.android.shell.Shell.SU.run("id")?.stdout ?: emptyList()
                )
                bbResult.addAll(
                    com.jrummyapps.android.shell.Shell.SU.run("busybox | head -1")?.stdout
                        ?: emptyList()
                )
            } catch (e: java.lang.Exception) {
                loge("TopFragmentViewModel suParam exception", e)
            }

            rootCheckResultSuccess = true
            rootStateMutableLiveData.postValue(RootState.RootAvailable(suVersion, suResult, bbResult))
        } else {
            rootCheckResultSuccess = true
            rootStateMutableLiveData.postValue(RootState.RootNotAvailable)
        }
    }

    fun resetModuleSettings(moduleName: ModuleName) {
        viewModelScope.launch(dispatcherIo) {
            try {
                resetModuleHelper.get().resetModuleSettings(moduleName)
            } catch (e: Exception) {
                loge("TopFragmentViewModel resetModuleSettings", e)
            }
        }
    }
}
