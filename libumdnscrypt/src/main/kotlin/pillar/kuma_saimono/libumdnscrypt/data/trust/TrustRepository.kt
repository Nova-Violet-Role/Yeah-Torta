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

package pillar.kuma_saimono.libumdnscrypt.data.trust

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Immutable snapshot of the installed blocklist's TRUST verdict (P8 Wave B1). Pure model — no
 * presentation, exactly like [pillar.kuma_saimono.libumdnscrypt.dns_engine.metrics.DnsEngineMetrics].
 *
 * **The fingerprint is an IDENTITY/DEDUP handle, never a trust input.** [fingerprint] is the Rust
 * `installed_fingerprint()` (a non-crypto FNV fold of the SET) read straight off [TortaCore]. It tells
 * us *which* list is installed (so two installs of the same set collapse to one trust value, trust=max,
 * never double-counted) — it does NOT, and must NEVER, raise the trust ceiling. Only a signature-
 * verified source ([signed]) lifts the ceiling; minisign verification lands in C3, so today [signed] is
 * false and an unsigned list is capped BELOW any signed source's band (see [TrustManager]).
 *
 * @param fingerprint   set-deterministic content fingerprint (the dedup/identity handle; 0 = none).
 * @param domainCount   number of domains armed in the installed list.
 * @param score         0..100 trust score for the installed list (ceiling-gated; see TrustManager).
 * @param signed        true once a signature-verified source backs this list (C3 minisign; false today).
 * @param sourceCount   how many distinct sources contributed (1 = a single list, no corroboration yet).
 * @param corroboration corroboration signal: distinct independent sources agreeing on the shared core.
 */
data class TrustState(
    val fingerprint: Long,
    val domainCount: Int,
    val score: Int,
    val signed: Boolean,
    val sourceCount: Int,
    val corroboration: Int,
)

/**
 * Scope bridge for the blocklist trust verdict (the seam P10's RotationManager subscribes to). The
 * [pillar.kuma_saimono.libumdnscrypt.dns_engine.TrustManager] owner is @ModulesServiceScope while UI/rotation
 * consumers inject from the root AppComponent — the two graphs never meet. This @Singleton lives in both
 * (concrete @Inject ctor, auto-provided everywhere), so the manager can push the trust snapshot and a
 * consumer can observe it without crossing subcomponent boundaries. Cloned from
 * [pillar.kuma_saimono.libumdnscrypt.data.dns_engine_metrics.DnsEngineMetricsRepository] — the only sanctioned
 * cross-graph bridge.
 *
 * `null` means idle (engine/blocklist not running) → a subscriber renders/treats it as "no list".
 */
@Singleton
class TrustRepository @Inject constructor() {

    private val _trust = MutableStateFlow<TrustState?>(null)
    val trust: StateFlow<TrustState?> = _trust.asStateFlow()

    fun publish(state: TrustState?) {
        _trust.value = state
    }
}
