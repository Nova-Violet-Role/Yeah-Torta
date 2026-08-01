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

import android.content.SharedPreferences
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import pillar.kuma_saimono.libumdnscrypt.data.trust.TrustRepository
import pillar.kuma_saimono.libumdnscrypt.data.trust.TrustState
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import org.json.JSONArray
import org.json.JSONObject
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import java.io.File
import javax.inject.Inject
import javax.inject.Named

/**
 * ModulesService-scoped owner of the P8 blocklist **trust verdict** (Wave B1). Mirrors
 * [MonokumaDnsEngineManager]/[ResolverRuntime]'s lifecycle exactly — armed when DNSCrypt goes RUNNING,
 * cleared (published `null` = idle) when it stops — but it governs **nothing** on the datapath: it is a
 * pure, no-egress READ of the already-installed Rust matcher, scored on the Kotlin side and published to
 * the cross-graph [TrustRepository] for P10's RotationManager to subscribe to.
 *
 * **The fingerprint is an IDENTITY/DEDUP handle — one-directional.** [TortaCore.blocklistFingerprint] is
 * the Rust `installed_fingerprint()` (a non-crypto FNV fold of the SET). We READ it as the dedup/identity
 * key — *which* list is installed, so the same set always yields the same trust value (trust = max over a
 * fingerprint bucket, never summed) — and we NEVER feed score/provenance back into Rust's finalize() hash.
 * The fingerprint is consumed BY the score, never produced FROM it; that is the A2 fingerprint invariant
 * (`a2_provenance_never_perturbs_the_fingerprint` stays green) and this class preserves it by construction.
 *
 * **The security boundary (load-bearing).** A signature-verified source gates the trust CEILING; the FNV
 * fingerprint is forgeable (non-crypto) and can NEVER raise that ceiling. An UNSIGNED source is therefore
 * capped strictly BELOW any signed source's achievable band ([UNSIGNED_CEILING] < signed floor). Minisign
 * verification lands in C3 — until then [TrustState.signed] is false and every list sits in the unsigned
 * band. Two sources with the SAME fingerprint are the SAME list ⇒ trust = max, not double-counted; high
 * mutual overlap between DIFFERENT sources is corroboration (mirrors trust.rs `corroboration()` popcount).
 *
 * No root, no `@Provides`: the `@ModulesServiceScope` + `@Inject` ctor is auto-supplied by the
 * ModulesService subcomponent (same as the engine/resolver). start/stop are `@Synchronized` and
 * idempotent, so the state-loop can call them on any transition edge without races.
 *
 * **★ #18 G6 — scoring routes through the [GithubTrustEngine] crown (RAM⊗NAND).** The per-source
 * registry the constants below waited for is the Rust crown (`github.rs`): [InstalledListTrust] consults
 * its DurableTier-backed cache for the installed set's investigated reputation (`cachedFor` warm /
 * `investigateBytes`+`arm` once cold), so the verdict survives process death and re-boots serve from
 * NAND with zero re-parse. Fail-open: any crown miss/failure falls back to the flat defaults (the exact
 * pre-crown path). The security ceiling is untouched — the crown feeds reputation INSIDE the unsigned
 * band; only C3 minisign lifts [UNSIGNED_CEILING].
 */
@ModulesServiceScope
@ExperimentalCoroutinesApi
class TrustManager @Inject constructor(
    @Named(CoroutinesModule.DISPATCHER_IO)
    private val dispatcherIo: CoroutineDispatcher,
    private val trustRepository: TrustRepository,
    private val pathVars: dagger.Lazy<PathVars>,
    @Named(DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: SharedPreferences,
) {
    private val coroutineScope by lazy {
        CoroutineScope(
            SupervisorJob() +
                    dispatcherIo +
                    CoroutineName("TrustManager") +
                    CoroutineExceptionHandler { _, t ->
                        loge("TrustManager uncaught exception", t)
                    }
        )
    }

    /**
     * Last fingerprint we successfully published trust for. Doubles as the idempotency guard: a `null`
     * means "idle/stopped" (start will (re)score), a non-null means "already scored this list" so a
     * repeated start edge for the same installed set is a no-op. @Volatile because the scoring runs on
     * [dispatcherIo] while the state-loop drives start/stop from another thread.
     */
    @Volatile
    private var scoredFingerprint: Long? = null

    /**
     * P8 **Wave B2 — CDN / public-suffix over-block safety warnings**, surfaced *before arming*.
     *
     * The warnings are **advisory only** and ride strictly ALONGSIDE the trust score — they never lower
     * it (a warning is not a penalty; coupling the forgeable-FNV identity world into the security band is
     * exactly what [trustScore] must not do). They are read from a plain-data **sidecar** that Centauri's
     * offline Score/Emit step writes next to the installed `.tblk` artifact (`<artifact>.meta`); the
     * device never fetches it and the read is pure (no native call, no datapath touch, no egress).
     *
     * **The load-bearing invariant:** the safety score is a WARNING in the sidecar, NEVER a mutation of
     * the `.tblk` bytes or the blocked SET. This Kotlin side is a faithful, additive READER — it surfaces
     * exactly the warnings the sidecar carries (including `UNKNOWN_SUFFIX`/uncertain entries) and never
     * re-derives, clears, or suppresses them (warn-on-uncertainty lives entirely in the Centauri producer).
     *
     * This is TrustManager's OWN seam (the immutable [TrustState] in `TrustRepository` is unchanged), so a
     * UI/rotation subscriber observes it alongside [TrustRepository.trust] without crossing graphs. Empty
     * means "no warnings / no sidecar / idle".
     */
    private val _overBlockWarnings = MutableStateFlow<List<OverBlockWarning>>(emptyList())
    val overBlockWarnings: StateFlow<List<OverBlockWarning>> = _overBlockWarnings.asStateFlow()

    /**
     * DNSCrypt reached RUNNING (or the engine started standalone): the blocklist is (being) installed,
     * so score it and publish. Idempotent — re-scoring the SAME installed fingerprint republishes the
     * SAME verdict (trust = max over the fingerprint bucket; never accumulates).
     */
    @Synchronized
    fun start() {
        try {
            // The whole trust readout is gated on the blocklist intelligence being active at all — same
            // master switch the engine respects. Off ⇒ idle (publish null once), exactly like a stop.
            val armed = defaultPreferences.getBoolean(
                pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNS_ENGINE_ENABLED,
                true
            )
            // #133 — query-blocklist.log: the Trust pillar's per-DNSCrypt-start readout (armed + the live
            // compiled-list count, counts only — no domains, T20).
            PillarLog.event(
                pathVars.get().appDataDir, PillarLog.Pillar.BLOCKLIST, "score",
                "armed" to armed,
                "count" to pillar.kuma_saimono.libumdnscrypt.rust.TortaCore.blocklistCount(),
            )
            if (!armed) {
                publishIdle()
                return
            }
            // Off the main thread: reading the native fingerprint/count is cheap but the load-library
            // ensure is best kept off any caller thread that might be the lifecycle/state-loop thread.
            coroutineScope.launch { scoreAndPublish() }
        } catch (e: Exception) {
            loge("TrustManager start", e)
        }
    }

    /** DNSCrypt stopped (and the engine is not standalone): clear the verdict → idle. Idempotent. */
    @Synchronized
    fun stop() {
        try {
            publishIdle()
        } catch (e: Exception) {
            loge("TrustManager stop", e)
        }
    }

    /** DNSCrypt reached RUNNING: (re)score the freshly (re)installed list. */
    fun onDnsCryptStarted() = start()

    /**
     * DNSCrypt stopped. If the user runs the engine standalone the blocklist stays installed, so keep
     * the verdict live (re-score); otherwise clear it. Mirrors [MonokumaDnsEngineManager.onDnsCryptStopped].
     */
    fun onDnsCryptStopped() {
        if (defaultPreferences.getBoolean(
                pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNS_ENGINE_STANDALONE,
                false
            )
        ) {
            start()
        } else {
            stop()
        }
    }

    /** True once a non-null verdict has been published (the state-loop need not read this, but symmetric). */
    fun isRunning(): Boolean = scoredFingerprint != null

    /**
     * Read the installed list's IDENTITY (fingerprint + domain count) off the native matcher, compute a
     * ceiling-gated trust score on the Kotlin side, and publish it. Reading the same fingerprint twice
     * yields the same score (trust = max over the bucket), so this is safe to call on any RUNNING edge.
     *
     * ★ E-FIX r4 — the identity-read + scoring now lives in the shared [InstalledListTrust] (this file),
     * so the #93 BlocklistSearchFragment can re-score the SAME way after a live paste→ADD merge (the
     * repository's only publisher used to be this RUNNING-edge manager, so an ADD armed the matcher and
     * blocked live while the trust row still read "No list" — AVD round-4). ONE scorer, two publishers.
     */
    private fun scoreAndPublish() {
        try {
            // IDENTITY/DEDUP handle ONLY — never written back into any Rust fingerprint (A2 invariant).
            // #18 G6 — the appDataDir arms the crown route: cached-serve from the RAM⊗NAND registry, or
            // ONE cold investigate for a genuinely-new fingerprint (then NAND fronts every later boot).
            val state = InstalledListTrust.scoreInstalledList(pathVars.get().appDataDir)
            if (state == null) {
                // No list installed yet → idle. (A blocklist with 0 domains is "no list", not "trusted".)
                publishIdle()
                return
            }

            // P8 B2 — read the CDN/public-suffix over-block warnings from the artifact sidecar and surface
            // them BEFORE arming (same scoreAndPublish pass that scores the freshly-installed set, on the
            // RUNNING edge). Best-effort and side-effect-free with respect to the SET: a missing/malformed
            // sidecar yields an empty list and never throws, so it can never block scoring or arming. The
            // score above is NOT touched by these warnings — they ride alongside it (advisory), mirroring
            // how A2 provenance rides alongside the SET.
            val overBlockWarnings = readOverBlockWarnings()
            _overBlockWarnings.value = overBlockWarnings

            scoredFingerprint = state.fingerprint
            trustRepository.publish(state)
            logi(
                "TrustManager — blocklist trust scored (fp=${state.fingerprint} domains=${state.domainCount} " +
                        "score=${state.score} signed=${state.signed} sources=${state.sourceCount} " +
                        "corroboration=${state.corroboration})"
            )
            if (overBlockWarnings.isNotEmpty()) {
                logw(
                    "TrustManager — ${overBlockWarnings.size} CDN/public-suffix over-block warning(s) " +
                            "for the armed list (advisory, score unchanged): " +
                            overBlockWarnings.joinToString(separator = ", ", limit = 8) {
                        "${it.suffix}[${it.kind}]"
                    }
                )
            }
        } catch (e: Exception) {
            loge("TrustManager scoreAndPublish — staying idle", e)
            publishIdle()
        }
    }

    /** Publish the idle (null) state and clear the idempotency guard. Mirrors `publish(null)` on stop. */
    private fun publishIdle() {
        scoredFingerprint = null
        _overBlockWarnings.value = emptyList()
        trustRepository.publish(null)
    }

    /**
     * Best-effort, no-egress read of the P8 B2 over-block **sidecar** (`<artifact>.meta`) that Centauri's
     * offline Score/Emit step writes beside the installed `.tblk`. Returns the parsed warnings, or an
     * EMPTY list if the sidecar is absent / unreadable / malformed — it NEVER throws, so a bad sidecar
     * can never block scoring or arming (the caller wraps it, and this stays defensive in its own right).
     *
     * **It reads only the sidecar data file.** It does not touch the `.tblk` bytes, the blocked SET, or
     * the native matcher — there is no [TortaCore] call here, so the fingerprint is provably unaffected
     * by the presence or absence of this read (the C2 byte-parity invariant is honored by construction).
     *
     * **Format — the real Centauri producer schema (`torta.blocklist.meta/1`), verified on the build VM.**
     * UTF-8 JSON written by `centauri-emit` (Haskell `Centauri.Score.renderSidecar`) beside the `.tblk`:
     * ```
     * {
     *   "schema": "torta.blocklist.meta/1",
     *   "fingerprint": "86a6e99c783ccc28",
     *   "domain_count": 4,
     *   "psl_snapshot_version": "2026-06-10_05-34-24_UTC",
     *   "over_block_warning_count": 2,
     *   "over_block_warnings": [
     *     {"kind": "PUBLIC_SUFFIX", "domain": "co.uk", "matched_rule": "co.uk"},
     *     {"kind": "CDN_APEX", "domain": "github.io", "matched_rule": "github.io"}
     *   ]
     * }
     * ```
     * Parsed defensively with the platform [JSONObject]/[JSONArray] (no new dependency): an absent/extra
     * field, an unrecognized `kind`, or a non-array `over_block_warnings` degrades to fewer/empty warnings
     * rather than throwing. An unrecognized `kind` maps to [WarnKind.UNKNOWN_SUFFIX] (flag-on-doubt). The
     * `psl_snapshot_version` is carried onto every warning so a stale-snapshot notice is showable. This is
     * a faithful READER: it surfaces exactly what the (versioned, bundled-PSL) producer wrote — including
     * `UNKNOWN_SUFFIX`/uncertain entries — and never re-derives, clears, or suppresses warn-on-uncertainty.
     */
    private fun readOverBlockWarnings(): List<OverBlockWarning> {
        return try {
            val pv = pathVars.get()
            val artifactPath = pv.appDataDir + ARTIFACT_RELATIVE_PATH
            val sidecar = File(artifactPath + SIDECAR_SUFFIX)
            if (!sidecar.isFile || !sidecar.canRead()) return emptyList()
            // Bounded read: a hostile/corrupt sidecar must not be slurped whole (mirror the Rust line cap
            // discipline). Over the cap ⇒ ignored (a faithful producer's sidecar is tiny JSON).
            if (sidecar.length() > MAX_SIDECAR_BYTES) {
                logw("TrustManager — over-block sidecar exceeds ${MAX_SIDECAR_BYTES}B, ignoring")
                return emptyList()
            }
            val text = sidecar.readText(Charsets.UTF_8)
            if (text.isBlank()) return emptyList()
            parseSidecarJson(text)
        } catch (e: Exception) {
            // Never let a bad sidecar break scoring/arming — warn-on-uncertainty is the producer's job;
            // here a read/parse failure is simply "no warnings surfaced this pass".
            loge("TrustManager — over-block sidecar read failed (ignored)", e)
            emptyList()
        }
    }

    /**
     * Parse the `torta.blocklist.meta/1` JSON into [OverBlockWarning]s. Tolerant by construction: a missing
     * `over_block_warnings` array, malformed entries, or unknown `kind` strings yield fewer/empty warnings,
     * never a throw. Each warning carries the top-level `psl_snapshot_version` so a stale-snapshot notice is
     * showable. The reader does NOT validate the `fingerprint`/`domain_count` against the native matcher —
     * those stay [TrustState]'s job; the sidecar is advisory and rides alongside.
     */
    private fun parseSidecarJson(text: String): List<OverBlockWarning> {
        val root = JSONObject(text)
        val pslVersion = root.optString("psl_snapshot_version").takeIf { it.isNotEmpty() }
        val arr: JSONArray = root.optJSONArray("over_block_warnings") ?: return emptyList()
        val warnings = ArrayList<OverBlockWarning>(minOf(arr.length(), MAX_WARNINGS))
        var i = 0
        while (i < arr.length() && warnings.size < MAX_WARNINGS) {
            val obj = arr.optJSONObject(i)
            i++
            if (obj == null) continue
            // The producer keys the offending terminal as "domain"; tolerate "suffix" as an alias.
            val suffix = obj.optString("domain").ifEmpty { obj.optString("suffix") }
            if (suffix.isEmpty()) continue
            val kind = WarnKind.fromToken(obj.optString("kind"))
            val matchedRule = obj.optString("matched_rule").takeIf { it.isNotEmpty() }
            warnings.add(
                OverBlockWarning(
                    suffix = suffix,
                    kind = kind,
                    matchedRule = matchedRule,
                    pslSnapshotVersion = pslVersion,
                )
            )
        }
        return warnings
    }

    /**
     * One CDN / public-suffix over-block warning surfaced from the P8 B2 sidecar. Immutable, presentation-
     * free (a pure model, exactly like [TrustState]). It is ADVISORY metadata that rides alongside the
     * trust score — it is NOT a trust input and NEVER lowers the score.
     *
     * @param suffix             the offending terminal sitting AT a public suffix / shared CDN apex (the
     *                           sidecar's `domain`).
     * @param kind               why it was flagged (see [WarnKind]); [WarnKind.UNKNOWN_SUFFIX] means the
     *                           producer could not clear it against its bundled PSL snapshot (flag-on-doubt).
     * @param matchedRule        the PSL rule that triggered the flag (the sidecar's `matched_rule`); for an
     *                           [WarnKind.UNKNOWN_SUFFIX] entry it is the terminal itself. `null` if absent.
     * @param pslSnapshotVersion the version of the bundled PSL snapshot the producer scored against, when
     *                           known — lets a stale-snapshot notice be shown. `null` if the sidecar
     *                           didn't carry it.
     */
    data class OverBlockWarning(
        val suffix: String,
        val kind: WarnKind,
        val matchedRule: String? = null,
        val pslSnapshotVersion: String? = null,
    )

    /**
     * The reason a terminal was flagged as a potential over-block. [UNKNOWN_SUFFIX] is the warn-on-
     * uncertainty bucket: a suffix the producer's bundled PSL snapshot did not recognize is flagged, never
     * silently cleared. An unrecognized token from the sidecar maps here too ([fromToken]).
     */
    enum class WarnKind {
        /** Terminal sits AT a registered public suffix (e.g. `co.uk`) — blocks every tenant beneath it. */
        PUBLIC_SUFFIX,

        /** Terminal sits AT a known shared CDN apex (e.g. `github.io`, `s3.amazonaws.com`). */
        CDN_APEX,

        /** Suffix absent from the bundled PSL snapshot — uncertain, flagged (warn-on-uncertainty). */
        UNKNOWN_SUFFIX;

        companion object {
            /**
             * Case-insensitive map from the sidecar `kind` string (`PUBLIC_SUFFIX` / `CDN_APEX` /
             * `UNKNOWN_SUFFIX`, per `Centauri.Score.kindTag`). Any unrecognized token ⇒ [UNKNOWN_SUFFIX]
             * (flag-on-doubt — a producer kind the reader doesn't know is treated as uncertain, never
             * silently dropped to "cleared").
             */
            fun fromToken(token: String): WarnKind = when (token.trim().uppercase()) {
                "PUBLIC_SUFFIX" -> PUBLIC_SUFFIX
                "CDN_APEX" -> CDN_APEX
                else -> UNKNOWN_SUFFIX
            }
        }
    }

    companion object {
        /**
         * On-device path (relative to [PathVars.getAppDataDir]) of the installed `.tblk` artifact whose
         * over-block sidecar we read. Same `dnscrypt-proxy` dir family as `blacklist.txt` (PathVars). The
         * sidecar is this path + [SIDECAR_SUFFIX].
         */
        const val ARTIFACT_RELATIVE_PATH = "/app_data/dnscrypt-proxy/blocklist.tblk"

        /** Suffix Centauri appends to the artifact path for the over-block sidecar manifest. */
        const val SIDECAR_SUFFIX = ".meta"

        /** Hard cap on the sidecar file size we will read (a corrupt/hostile sidecar is ignored). */
        const val MAX_SIDECAR_BYTES = 1L shl 20 // 1 MiB

        /** Hard cap on the number of warnings surfaced from one sidecar (bounded, advisory). */
        const val MAX_WARNINGS = 4096

        /**
         * The trust ceiling for an UNSIGNED source. Strictly BELOW any signed source's achievable floor
         * (a signed source blends to at least its base and is ceiling-100), so no amount of reputation or
         * corroboration can push an unsigned list into a signed list's band. This is the security
         * boundary the FNV fingerprint (forgeable) must never breach — only C3's minisign lifts the gate.
         */
        const val UNSIGNED_CEILING = 60

        /** Default operator/base weight for an installed list (the operator registry is still future). */
        const val DEFAULT_SOURCE_TRUST = 50

        /**
         * FALLBACK reputation for an installed list when the #18 G6 crown holds no verdict for it (crown
         * unreachable / raw list unreadable / never investigated). When the crown HAS investigated the
         * set, its `trust_score` replaces this (see [InstalledListTrust.scoreInstalledList]).
         */
        const val DEFAULT_SOURCE_REPUTATION = 50

        /** Per-corroborating-source bonus (diminishing/capped, see [CORR_CAP]). */
        const val CORR_STEP = 5

        /** Hard cap on the corroboration bonus so corroboration cannot blow past the unsigned band. */
        const val CORR_CAP = 20
    }
}

/**
 * ★ E-FIX r4 — the ONE shared installed-list trust scorer (K4/dedup law: one scorer, two publishers).
 *
 * Extracted from [TrustManager] (whose private `trustScore` this replaces) so BOTH publish paths score
 * identically:
 *  - [TrustManager.scoreAndPublish] — the DNSCrypt RUNNING-edge readout (`@ModulesServiceScope`);
 *  - the #93 [BlocklistSearchFragment] — the live paste→ADD merge, which previously never republished, so
 *    the "Current blocklist" trust row still read "No list" while the freshly-armed matcher was blocking
 *    live (AVD round-4: blocked 17→22 with the row stuck on "No list").
 *
 * Pure + read-only: [scoreInstalledList] READS the native matcher's identity (fingerprint/count — the
 * A2 one-directional IDENTITY handle, never written back) and computes the ceiling-gated score. All
 * constants stay on [TrustManager]'s companion (the single source for the security boundary).
 */
object InstalledListTrust {

    /**
     * Read the installed list's IDENTITY (fingerprint + domain count) off the native matcher and score it.
     * Returns `null` when no list is armed (fingerprint 0 / count 0 — "no list", not "trusted"). An
     * installed list is a single UNSIGNED source: signed=false, one source, no cross-source corroboration
     * (B1/C3 provenance contract — the scoring boundary guarantees an unsigned list can never reach a
     * signed band). Cheap native reads, but callers keep it off the main thread (the load-library ensure).
     *
     * ★ #18 G6 — the per-source registry the pre-crown comment promised IS the [GithubTrustEngine] crown
     * (`github.rs`), and this ONE scorer now consults it: the installed list's reputation comes from the
     * crown's investigated `trust_score` (the value github.rs documents as "fed to SourceMeta::reputation")
     * instead of the flat [TrustManager.DEFAULT_SOURCE_REPUTATION]. The crown round-trip is RAM⊗NAND —
     * rehydrated at construction (boot pillar 7), write-through on investigate/arm — so a warm boot serves
     * the SAME verdict from NAND with ZERO re-parse/re-score of the raw list. Keyed by the installed
     * fingerprint (`torta://installed/<fp-hex>`): a CHANGED list is a genuinely-new investigation (cache
     * miss → one cold investigate), an UNCHANGED list is a pure cache hit across process death.
     *
     * [appDataDir] non-null (the RUNNING-edge manager) ⇒ full crown route: open-once (idempotent; the
     * SAME `runtime_tier` root as every durable pillar — G9 law, never a third root), cached-serve, or
     * cold-investigate the raw `blacklist.txt` bytes (bounded [MAX_RAW_LIST_BYTES]) + arm. `null` (the
     * #93 fragment's live-ADD republish) ⇒ cached-only consult of the already-open crown — both publishers
     * still score IDENTICALLY whenever the crown holds a verdict (K4 one-scorer law). EVERY crown failure
     * — unloadable `.so`, absent raw file, oversized, any throwable — degrades to the pre-crown default
     * path (fail-open; trust never breaks on registry trouble). The crown NEVER dials out here: the
     * network legs stay on the explicit investigation trigger (underground law), and `investigateBytes`
     * is a pure offline parse of bytes already on flash.
     */
    fun scoreInstalledList(appDataDir: String? = null): TrustState? {
        val fingerprint = TortaCore.blocklistFingerprint()
        val domainCount = TortaCore.blocklistCount()
        if (fingerprint == 0L || domainCount == 0) return null
        val signed = false // minisign verification is C3; the forgeable FNV never lifts this.
        // #18 G6 — the crown's investigated reputation for THIS installed set, or null ⇒ the flat default.
        // The crown's `signed`/`curated` hints NEVER touch the ceiling gate above (the security boundary
        // stays minisign-only, C3): the crown feeds reputation INSIDE the unsigned band, nothing more.
        val crownReputation = crownReputation(fingerprint, appDataDir)
        return TrustState(
            fingerprint = fingerprint,
            domainCount = domainCount,
            score = computeScore(
                signed = signed,
                baseTrust = TrustManager.DEFAULT_SOURCE_TRUST,
                reputation = crownReputation ?: TrustManager.DEFAULT_SOURCE_REPUTATION,
                corroboration = 0,
            ),
            signed = signed,
            sourceCount = 1, // a single installed list until the multi-source registry lands.
            corroboration = 0, // distinct independent sources agreeing — none until B-later.
        )
    }

    /**
     * The crown leg of [scoreInstalledList]: the installed set's investigated 0..=100 reputation, or
     * `null` on ANY miss/failure (⇒ caller uses the pre-crown default — fail-open by construction).
     * Warm path: `cachedFor` on the fingerprint key (RAM, rehydrated from NAND at boot). Cold path
     * (manager only, `appDataDir != null`): ONE bounded read of the raw `blacklist.txt` bytes →
     * `investigateBytes` (parse → RFC-1123 validate → CDN-overlap → deterministic score, then the crown
     * write-throughs the verdict to NAND itself) → `arm` (the installed list IS the armed list — record
     * intent so the `armed` flag survives with the verdict). Logs the pillar's `query-github-trust.log`
     * line per serve (counts only — no domains, T20; the key embeds only the FNV fingerprint hex).
     */
    private fun crownReputation(fingerprint: Long, appDataDir: String?): Int? {
        return try {
            val crown = if (appDataDir != null) {
                TortaCore.trustCrownOpen(appDataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR)
            } else {
                TortaCore.trustCrownOrNull()
            } ?: return null
            val key = "torta://installed/%016x".format(fingerprint)
            crown.cachedFor(key)?.let { hit ->
                if (appDataDir != null) {
                    PillarLog.event(
                        appDataDir, PillarLog.Pillar.GITHUB_TRUST, "cached",
                        "score" to hit.trustScore.toInt(),
                        "band" to hit.band,
                        "valid" to hit.validEntryCount.toInt(),
                        "cdn_overlap" to hit.cdnOverlap.toInt(),
                    )
                }
                return hit.trustScore.toInt()
            }
            // Cache miss. Only the RUNNING-edge manager may cold-investigate (it has the dir); the
            // fragment's cached-only consult stops here (its default-path score converges on the next
            // RUNNING edge once the manager has investigated).
            if (appDataDir == null) return null
            val raw = File(appDataDir + RAW_LIST_RELATIVE_PATH)
            if (!raw.isFile || !raw.canRead()) return null
            if (raw.length() == 0L || raw.length() > MAX_RAW_LIST_BYTES) return null
            val safety = crown.investigateBytes(
                name = "installed-blocklist",
                url = key,
                rawList = raw.readBytes(),
                hints = uniffi.torta_core.SourceHints(
                    signed = false, // C3 pending — a maintained-source nudge only, never claimed here.
                    curated = false,
                    ageDays = 0u, // unknown ⇒ neutral recency.
                    fetchedAtMs = System.currentTimeMillis().toULong(),
                ),
            )
            crown.arm(key, true)
            PillarLog.event(
                appDataDir, PillarLog.Pillar.GITHUB_TRUST, "investigate",
                "score" to safety.trustScore.toInt(),
                "band" to safety.band,
                "valid" to safety.validEntryCount.toInt(),
                "malformed" to safety.malformedCount.toInt(),
                "cdn_overlap" to safety.cdnOverlap.toInt(),
            )
            safety.trustScore.toInt()
        } catch (t: Throwable) {
            // Fail-open: registry trouble NEVER breaks trust scoring — the flat default stands.
            null
        }
    }

    /**
     * The raw domain-list text the engine compiles from ([PathVars.dnsCryptBlackListPath] shape), read
     * ONCE per genuinely-new fingerprint for the crown's offline investigate. Relative so this object
     * stays `Context`-free/pure (the caller passes `appDataDir`).
     */
    const val RAW_LIST_RELATIVE_PATH = "/app_data/dnscrypt-proxy/blacklist.txt"

    /** Bound on the raw-list read — mirrors the crown's own 8 MiB capped network leg (github.rs). */
    const val MAX_RAW_LIST_BYTES = 8L * 1024L * 1024L

    /**
     * The trust score (pure, deterministic, integer-only — no float dep). Mirrors the Rust
     * `trust.rs::trust_score` shape on the Kotlin side:
     *
     *   ceiling = if (signed) 100 else [TrustManager.UNSIGNED_CEILING]  ← the load-bearing security boundary
     *   base    = (baseTrust + reputation) / 2               ← operator weight blended with source rep
     *   corrBonus = min((corroboration - 1) * [TrustManager.CORR_STEP], [TrustManager.CORR_CAP])
     *   raw     = base + corrBonus
     *   score   = min(raw, ceiling).coerceIn(0, 100)
     *
     * Monotone under corroboration (more agreeing sources never lowers the score, and the bonus is
     * capped so a flood of corroboration cannot blow past the band) and — critically — an UNSIGNED
     * source can NEVER reach a signed source's band regardless of base/reputation/corroboration, because
     * [TrustManager.UNSIGNED_CEILING] is strictly below any signed source's achievable floor.
     */
    fun computeScore(
        signed: Boolean,
        baseTrust: Int,
        reputation: Int,
        corroboration: Int,
    ): Int {
        val ceiling = if (signed) 100 else TrustManager.UNSIGNED_CEILING
        val base = (baseTrust.coerceIn(0, 100) + reputation.coerceIn(0, 100)) / 2
        val corrBonus = (maxOf(corroboration - 1, 0) * TrustManager.CORR_STEP)
            .coerceAtMost(TrustManager.CORR_CAP)
        val raw = base + corrBonus
        return minOf(raw, ceiling).coerceIn(0, 100)
    }
}
