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

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.domain.dnscrypt_relays.RelaysPingInteractor
import pillar.kuma_saimono.libumdnscrypt.domain.dnscrypt_servers.ServersPingInteractor
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.SocketInternetChecker.Companion.NO_CONNECTION
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import javax.inject.Inject
import javax.inject.Named

/**
 * P10 — the per-candidate RTT adapter for resolver rotation.
 *
 * This is a THIN ADAPTER over the existing ping/RTT seam, NOT a new pinger. It exists because the
 * engine's own real-time RTT (`MonokumaDnsEngine.selectBestEndpoint` → `engineMetrics`,
 * MonokumaDnsEngine.kt:174-197 / MonokumaDnsEngineManager.kt:72-73) measures ONLY the CURRENT pool
 * (loopback dnscrypt-proxy or `DEFAULT_ENDPOINTS`, MonokumaDnsEngineManager.kt:90-97) — it cannot
 * rank an arbitrary OFF-POOL rotation candidate before the swap. The right reuse for candidate
 * ranking is the DNSCrypt servers/relays ping pipeline already in tree:
 *
 *   RelaysPingInteractor.getTimeout(name, sdns)        [RelaysPingInteractor.kt:37-45]
 *     → DnsCryptSDNSParser.getRelayAddress(sdns)        [DnsCryptSDNSParser.kt:27-60]  (relay stamp → ip:port)
 *     → ServersPingRepository.getTimeout(address)       [ServersPingRepositoryImpl.kt:47-78]
 *     → ServersPingDataSourceImpl.checkTimeoutDirectly  [ServersPingDataSourceImpl.kt:29-37]
 *     → SocketInternetChecker.checkConnectionPing       [SocketInternetChecker.kt:79-130]  (TCP-connect ms; NO_CONNECTION -1)
 *
 *   ServersPingInteractor.getTimeout(address)          [ServersPingInteractor.kt:33-35]  (already-resolved ip:port → same TCP ping)
 *
 * The RTT it yields is a **TCP-connect latency in ms**, not a DNS-query RTT — identical to what the
 * DNSCrypt server/relay ping cards in the app already show, so a rotation choice ranks on the SAME
 * metric the rest of the app trusts. `NO_CONNECTION` (-1) means the candidate is unreachable and is
 * excluded from selection (never ranked best).
 *
 * P10 rule (fail-safe): an unreachable candidate is dropped from the ranked set, never the chosen
 * upstream. If EVERY candidate is unreachable, [rankByRtt] yields an empty list and the caller
 * (RotationManager) keeps the current live set — it does NOT swap.
 *
 * DI: `@ModulesServiceScope @Inject` ctor on the TrustManager / MonokumaDnsEngineManager template
 * (TrustManager.kt:61-70, MonokumaDnsEngineManager.kt:44-53) — never hand-`new` (ADR-001). The two
 * ping interactors and the IO dispatcher are auto-supplied by the ModulesService subcomponent graph
 * (the interactors carry `@Inject` ctors: RelaysPingInteractor.kt:31, ServersPingInteractor.kt:28).
 */
@ModulesServiceScope
@ExperimentalCoroutinesApi
class RotationPing @Inject constructor(
    private val relaysPingInteractor: RelaysPingInteractor,
    private val serversPingInteractor: ServersPingInteractor,
    @Named(CoroutinesModule.DISPATCHER_IO)
    private val dispatcherIo: CoroutineDispatcher,
) {

    /**
     * A rotation candidate to measure. Exactly ONE address source is required:
     *  - [sdns]: an sdns:// stamp (relay 0x81/0x85 or — once a server-stamp seam lands — a server
     *    stamp); parsed to ip:port by the existing [RelaysPingInteractor]/[DnsCryptSDNSParser] seam.
     *  - [address]: an already-resolved `ip:port` (e.g. the loopback do53 `127.0.0.1:<port>` from
     *    PathVars.getDNSCryptPort, PathVars.java:201) — pinged via [ServersPingInteractor] directly.
     *
     * [id] is the stable identity P10 uses to compose the upstream JSON (matches the `id` field that
     * ResolverRuntime.buildSpecsJson emits, ResolverRuntime.kt:260-278).
     */
    data class Candidate(
        val id: String,
        val sdns: String? = null,
        val address: String? = null,
    )

    /** One measured candidate. [rttMs] is the TCP-connect latency in ms, or [NO_CONNECTION] (-1). */
    data class RttSample(val candidate: Candidate, val rttMs: Int) {
        /** Reachable iff the ping returned a real, non-negative latency. */
        val reachable: Boolean get() = rttMs >= 0
    }

    /**
     * Measure ONE candidate's RTT by delegating to the existing ping seam (no new socket logic).
     * Returns [NO_CONNECTION] (-1) on any failure or for a candidate with neither stamp nor address.
     * Runs on the IO dispatcher; crash-proof (the underlying repos already swallow socket exceptions
     * to NO_CONNECTION, ServersPingRepositoryImpl.kt:47-56 — this is belt-and-braces).
     */
    suspend fun rttFor(candidate: Candidate): Int = withContext(dispatcherIo) {
        try {
            when {
                !candidate.sdns.isNullOrEmpty() ->
                    relaysPingInteractor.getTimeout(candidate.id, candidate.sdns)
                !candidate.address.isNullOrEmpty() ->
                    serversPingInteractor.getTimeout(candidate.address)
                else -> NO_CONNECTION
            }
        } catch (e: Exception) {
            loge("RotationPing rttFor ${candidate.id}", e)
            NO_CONNECTION
        }
    }

    /**
     * Measure every candidate concurrently (the same fan-out shape the engine's selectBestEndpoint
     * uses, MonokumaDnsEngine.kt:175-180) and return the reachable survivors ordered fastest-first.
     * Unreachable candidates ([NO_CONNECTION]) are excluded. An empty result ⇒ the caller keeps the
     * current set (fail-safe atomic — never swaps onto an all-dead candidate pool).
     */
    suspend fun rankCandidates(candidates: List<Candidate>): List<RttSample> = coroutineScope {
        val samples = candidates
            .map { c -> async { RttSample(c, rttFor(c)) } }
            .awaitAll()
        rankByRtt(samples)
    }

    /**
     * #22 s5B relay-reachability substrate — probe every relay candidate (sdns lane →
     * [RelaysPingInteractor] via [rttFor]) and keep only the reachable ones, fastest-first.
     *
     * FAIL-OPEN, not fail-safe: ZERO reachable ⇒ return the INPUT list untouched (the blind full
     * list). Rationale: this filter feeds the anonymized-relay pick — a dead probe plane (airplane
     * mode, captive portal, a filtered TCP path that the DNSCrypt UDP path would still cross) must
     * never strip the anonymization layer and silently send queries DIRECT. Wrong-but-private beats
     * fast-but-naked. The per-candidate probe already swallows every socket exception to
     * NO_CONNECTION ([rttFor]), so this can only widen, never throw.
     */
    suspend fun filterRoutableRelays(relays: List<Candidate>): List<Candidate> {
        if (relays.isEmpty()) return relays
        val ranked = rankCandidates(relays)
        if (ranked.isEmpty()) {
            logi("RotationPing filterRoutableRelays: 0/${relays.size} relays probed reachable — FAIL-OPEN, keeping the blind full list")
        } else {
            logi("RotationPing filterRoutableRelays: ${ranked.size}/${relays.size} relays reachable")
        }
        return chooseRoutableRelays(relays, ranked)
    }

    companion object {
        /**
         * Pure, hermetic ranking — the part worth unit-testing (no sockets, no Android, no coroutines).
         * Drops unreachable samples (rttMs < 0 == [NO_CONNECTION]), orders the survivors fastest-first,
         * and breaks ties deterministically by candidate id so the result is stable across runs (a
         * stable order avoids needless pool churn when two candidates measure the same latency).
         */
        fun rankByRtt(samples: List<RttSample>): List<RttSample> =
            samples
                .filter { it.reachable }
                .sortedWith(compareBy({ it.rttMs }, { it.candidate.id }))

        /** The fastest reachable candidate, or null if none is reachable (caller keeps current set). */
        fun fastest(samples: List<RttSample>): RttSample? = rankByRtt(samples).firstOrNull()

        /**
         * #22 s5B — the pure FAIL-OPEN decision behind [filterRoutableRelays] (the part worth
         * unit-testing): zero reachable ⇒ the ORIGINAL input list (blind full list — a dead probe
         * plane must never thin the anonymization layer); otherwise the reachable survivors,
         * fastest-first. Contrast [rankByRtt]'s fail-SAFE empty (resolvers: never swap onto dead);
         * relays invert the default because dropping them silently sends queries DIRECT.
         */
        fun chooseRoutableRelays(input: List<Candidate>, ranked: List<RttSample>): List<Candidate> =
            if (ranked.isEmpty()) input else ranked.map { it.candidate }
    }
}
