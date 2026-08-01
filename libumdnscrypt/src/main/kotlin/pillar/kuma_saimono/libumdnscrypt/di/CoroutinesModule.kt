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

import dagger.Module
import dagger.Provides
import kotlinx.coroutines.*
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import javax.inject.Named
import javax.inject.Singleton

@Module
class CoroutinesModule {

    @Provides
    @Named(SUPERVISOR_JOB_MAIN_DISPATCHER_SCOPE)
    fun provideSupervisorMainDispatcherCoroutineScope(
        dispatcherMain: MainCoroutineDispatcher
    ): CoroutineScope {
        return CoroutineScope(SupervisorJob() + dispatcherMain)
    }

    @Provides
    @Named(SUPERVISOR_JOB_IO_DISPATCHER_SCOPE)
    fun provideSupervisorIoDispatcherCoroutineScope(
        @Named(DISPATCHER_IO) dispatcherIo: CoroutineDispatcher
    ): CoroutineScope {
        return CoroutineScope(SupervisorJob() + dispatcherIo)
    }

    @Provides
    @Singleton
    @Named(SUPERVISOR_JOB_IO_DISPATCHER_SCOPE_SINGLETON)
    fun provideSupervisorIoDispatcherCoroutineScopeSingleton(
        @Named(DISPATCHER_IO) dispatcherIo: CoroutineDispatcher
    ): CoroutineScope {
        return CoroutineScope(SupervisorJob() + dispatcherIo)
    }

    @Provides
    fun provideDispatcherMain(): MainCoroutineDispatcher = Dispatchers.Main.immediate

    @Provides
    @Named(DISPATCHER_IO)
    fun provideDispatcherIo(): CoroutineDispatcher = Dispatchers.IO

    @Provides
    @Named(DISPATCHER_COMPUTATION)
    fun provideDispatcherComputation(): CoroutineDispatcher = Dispatchers.Default

    @Provides
    fun provideCoroutineExceptionHandler(): CoroutineExceptionHandler {
        return CoroutineExceptionHandler { coroutine, throwable ->
            loge("Coroutine ${coroutine[CoroutineName]} unhandled exception", throwable)
        }
    }

    companion object {
        const val SUPERVISOR_JOB_MAIN_DISPATCHER_SCOPE = "SUPERVISOR_JOB_MAIN_DISPATCHER_SCOPE"
        const val SUPERVISOR_JOB_IO_DISPATCHER_SCOPE = "SUPERVISOR_JOB_IO_DISPATCHER_SCOPE"
        const val SUPERVISOR_JOB_IO_DISPATCHER_SCOPE_SINGLETON = "SUPERVISOR_JOB_IO_DISPATCHER_SCOPE_SINGLETON"
        const val DISPATCHER_IO = "DISPATCHER_IO"
        const val DISPATCHER_COMPUTATION = "DISPATCHER_COMPUTATION"
    }
}
