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

package pillar.kuma_saimono.libumdnscrypt.data.dns_engine_metrics

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import pillar.kuma_saimono.libumdnscrypt.dns_engine.metrics.DnsEngineMetrics
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Scope bridge for the CAKE/YeAH engine metrics. The engine manager is @ModulesServiceScope while
 * the dashboard UI is injected from the root AppComponent — the two graphs never meet. This
 * @Singleton lives in both (concrete @Inject ctor, auto-provided everywhere), so the manager can
 * push snapshots and the UI can observe them without crossing subcomponent boundaries.
 *
 * `null` means the engine is stopped → the dashboard renders its idle state.
 */
@Singleton
class DnsEngineMetricsRepository @Inject constructor() {

    private val _metrics = MutableStateFlow<DnsEngineMetrics?>(null)
    val metrics: StateFlow<DnsEngineMetrics?> = _metrics.asStateFlow()

    fun publish(metrics: DnsEngineMetrics?) {
        _metrics.value = metrics
    }
}
