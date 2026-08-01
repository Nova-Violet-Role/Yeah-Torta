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
                // The single-String overload is deprecated in libsuperuser 1.1.1; the ARRAY form
                // is the documented replacement and is what every other Shell.SU call in this
                // module already uses (ModulesKiller, NflogManager, ModulesStarterHelper -- none
                // of which warn, for exactly this reason). One command per element, same shell,
                // same result list.
                suResult.addAll(Shell.SU.run(arrayOf("id")) ?: emptyList())
                bbResult.addAll(Shell.SU.run(arrayOf("busybox | head -1")) ?: emptyList())
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
