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

package pillar.kuma_saimono.libumdnscrypt.slint

import kotlinx.coroutines.flow.Flow
import me.tatarka.inject.annotations.Inject
import uniffi.torta_core.UndergroundSnapshot
import uniffi.torta_core.VerdictEvent

/**
 * CP-U · #15 UNDERGROUND H — the Underground pillar's typed view-model (the Kotlin-Inject ⇄
 * SLINT constructor pattern, [SlintUiComponent] provides it): ONE object exposing everything the
 * pillar's Dashboard + Settings panes consume — the licence-store snapshot, the live verdict
 * stream (the G-rung [Flow], seq-deduped), the operator's scoring.toml law and its write-back,
 * the verdict pins and the reputation amnesty. Every read crosses to the SAME
 * `libtorta_core.so` process-globals the resolver datapath feeds — no engine fork, no cache.
 * All calls fail-open through [TortaPillarBridge]'s crash-firewalled statics.
 */
@Inject
class UndergroundViewModel {

    /** The licence-store panel snapshot ([topN] worst offenders, hits- AND score-ordered). */
    fun snapshot(topN: UInt = 12u): UndergroundSnapshot = uniffi.torta_core.undergroundSnapshot(topN)

    /** The live verdict event stream — the G-rung cold [Flow], one [VerdictEvent] each, seq-fresh. */
    fun events(pollMs: Long = 500L): Flow<VerdictEvent> = TortaPillarBridge.undergroundEventsFlow(pollMs)

    /** Pin one host's Trust band: 0 = Neutral, 1 = Trusted, 2 = Distrusted. True iff landed. */
    fun setVerdict(host: String, code: Int): Boolean = TortaPillarBridge.setUndergroundVerdict(host, code)

    /** The operator's runtime law (scoring.toml text; `""` = compile-time defaults sit). */
    fun scoringToml(): String = TortaPillarBridge.undergroundScoringToml()

    /** Write the edited law atomically (blank deletes — defaults return). True iff landed. */
    fun saveScoringToml(text: String): Boolean = TortaPillarBridge.setUndergroundScoringToml(text)

    /** The settings-pane RESET: forget the learned reputation + correction log (ledger untouched). */
    fun resetReputation(): Boolean = TortaPillarBridge.resetUndergroundReputation()
}
