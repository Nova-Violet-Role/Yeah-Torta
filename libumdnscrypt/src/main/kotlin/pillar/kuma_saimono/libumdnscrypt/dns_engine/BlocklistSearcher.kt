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
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.web.HttpsConnectionManager
import java.io.BufferedInputStream
import java.io.IOException

/**
 * P10 / #93 — the Custom-blocklist Expert **searcher logic**, ALL in this one file (the contract).
 *
 * Four user-initiated, one-shot operations behind the Expert Custom-blocklist screen — never auto-fired,
 * never background, never silent. DNSCrypt's own encrypted/anonymized DNS path is **untouched**; the two
 * network operations here ([searchGitHub], [fetchListText]) are an **opt-in, Expert-gated, surfaced**
 * channel SEPARATE from DNS resolution. Every method that hits the network runs off the main thread on
 * the injected IO dispatcher ([dispatcherIo]) and is crash-proof (returns a safe empty/null/false on any
 * fault — never propagates a throw to the UI).
 *
 * **Privacy invariants (load-bearing).**
 *  - No background/auto fetch: every network call is a `suspend fun` the SCREEN calls in direct response to
 *    a user tap; there is no timer, no service, no WorkManager, no observe-and-fetch. The class holds no
 *    coroutine scope of its own — the caller owns the lifecycle (lifecycleScope).
 *  - The DNS query path never routes through here; this class only compiles/merges a list the user pasted
 *    or explicitly fetched, and (separately) queries GitHub's public search API at the user's request.
 *  - The local trust score + the preview count + the over-block warnings are computed **with no egress at
 *    all** ([previewFromText] makes zero network and zero native-matcher mutation).
 *
 * **No new dependency.** Network reuses the app's [HttpsConnectionManager] (correct SOCKS-proxy + TLS-compat
 * + Chrome-UA posture for free); JSON uses the platform `org.json`; the compiler/merge reuses the live P7
 * `TortaCore.compileBlocklistText` / Rust matcher.
 *
 * Plain (no Dagger `@Inject`) by design so the host fragment can stay DI-free, mirroring `EngineSettingsFragment`.
 * The fragment constructs it with the manager + the IO dispatcher + the default SharedPreferences it already holds.
 *
 * @param httpsConnectionManager the app's shared HTTP client (utils/web/HttpsConnectionManager.kt) — reused, no new dep.
 * @param dispatcherIo           the IO dispatcher (di/CoroutinesModule DISPATCHER_IO) — every net call hops to it.
 * @param defaultPreferences     the default SharedPreferences store, for the 1h GitHub search cache.
 * @param pathVars               ★ E-FIX r3 — the app paths (nullable, host-supplied): when present, a
 *                               successful Add ALSO appends the list to the on-disk DNSCrypt LOCAL
 *                               blacklist file so it survives an engine restart (the RUNNING-edge
 *                               recompile reads the on-disk files and wiped a RAM-only merge).
 */
class BlocklistSearcher(
    private val httpsConnectionManager: HttpsConnectionManager,
    private val dispatcherIo: CoroutineDispatcher,
    private val defaultPreferences: SharedPreferences,
    private val pathVars: dagger.Lazy<pillar.kuma_saimono.libumdnscrypt.settings.PathVars>? = null,
) {

    /**
     * The outcome of a PREVIEW or an ADD of a blocklist text.
     *
     * @param count    distinct compilable domains in the text (parsed exactly as the Rust compiler would).
     * @param score    the LOCAL, deterministic, no-network trust score 0..100 for an unsigned custom list
     *                 (see [localUnsignedScore]); an unsigned custom list is capped at [UNSIGNED_CEILING].
     * @param warnings human-readable over-block / parse advisories (e.g. a public-suffix / shared-CDN apex,
     *                 or "nothing compilable"); ADVISORY only — they never lower [score].
     */
    data class AddResult(
        val count: Int,
        val score: Int,
        val warnings: List<String>,
    )

    /**
     * One GitHub repository search hit. [rawCandidateUrl] is a BEST-GUESS raw URL for a likely blocklist
     * file in the repo's default branch — the user still reviews + previews before any Add (no auto-apply).
     *
     * @param name            the repo's short name.
     * @param fullName        "owner/name".
     * @param rawCandidateUrl a candidate raw.githubusercontent.com URL to fetch + preview (user-confirmed).
     * @param stars           stargazers (the only ranking signal; NOT a trust/reputation number — see the flag).
     */
    data class RepoHit(
        val name: String,
        val fullName: String,
        val rawCandidateUrl: String,
        val stars: Int,
    )

    // ---- (1) PREVIEW — local, no network, no native-matcher mutation ----

    /**
     * Compile-PREVIEW a pasted/fetched blocklist [text]: report the distinct-domain count, the LOCAL trust
     * score, and any over-block warnings — WITHOUT merging into (or otherwise touching) the live armed
     * matcher. A true preview: it makes **no network call and no native call**.
     *
     * **Why a local parse instead of the native compiler:** every Kotlin-reachable native compile entry
     * (`BlocklistRuntime` → `TortaCore.compileBlocklistText` → Rust `compile_and_install_text`,
     * lib.rs:149 / blocklist.rs:555) INSTALLS into the process-global matcher. There is no non-installing
     * native count export today (the pure `blocklist::compile_text`, blocklist.rs:470, has no JNI seam).
     * So a preview that "does NOT merge" must NOT call the installing path. [countDomains] re-implements the
     * exact line rules of the Rust `parse_line` (blocklist.rs:373-408) so the previewed count matches the
     * count [applyFromText] will arm. (FLAGGED to the wave lead: a `nativeBlocklistPreviewText` over the
     * pure `compile_text` is the clean follow-up to make the count natively authoritative.)
     */
    suspend fun previewFromText(text: String): AddResult = withContext(dispatcherIo) {
        // K4 dedup: the Rust parser (blocklist::preview_text, reusing parse_line) is the SINGLE source of truth.
        // The Kotlin countDomains/parseLine/localUnsignedScore reimplementation is RETIRED — the dedup.
        val preview = uniffi.torta_core.blocklistPreviewText(text)
        val warnings = ArrayList<String>(preview.sample.size + 1)
        if (preview.count == 0) {
            warnings.add(WARN_EMPTY)
        }
        warnings.addAll(preview.sample)
        AddResult(count = preview.count, score = preview.score, warnings = warnings)
    }

    // ---- (2) ADD / MERGE — the actual Add, local, no network ----

    /**
     * Compile [text] and MERGE it into the live Rust matcher (stack onto the existing armed list, never
     * replace) via the live P7 [BlocklistRuntime.compileFromText] (merge=true). Returns true if at least
     * one domain ended up armed for this text. Local-only: no network. Off the main thread.
     *
     * MANUAL-REVIEW gate is the caller's job: the screen calls this ONLY after the user previews and taps
     * "Add" — there is no auto-apply here (and no auto-apply anywhere; flagged for Socio).
     */
    suspend fun applyFromText(text: String): Boolean = withContext(dispatcherIo) {
        try {
            // Live armed count BEFORE (authoritative, read straight off the native matcher).
            val before = TortaCore.blocklistCount()
            // Reuse the live P7 in-memory compile + MERGE flag (TortaCore.compileBlocklistText, merge=true):
            // stack the user's list ON TOP of the armed set (never replace), into the SAME process-global
            // matcher BlocklistRuntime/the resolver read. A null return (bad/empty text, missing .so → the
            // crash-proof wrapper) is a no-op that leaves the matcher untouched.
            val summary = TortaCore.compileBlocklistText(text, merge = true)
            val after = TortaCore.blocklistCount()
            // Success = the compile ran (non-null summary) AND domains landed: either the live count grew,
            // or the text carried compilable domains already present in the set (a re-add of an armed list).
            val ok = summary != null && (after > before || hasCompilableDomain(text))
            // ★ E-FIX r3 — make the Add DURABLE: the RUNNING-edge loadBlocklist() recompiles the
            // matcher from the ON-DISK blacklist files (first path merge=false = REPLACE), so a
            // RAM-only merge silently evaporated on every engine restart — the block path went back
            // to un-exercisable (AVD round 3: count=0, zero BLOCK verdicts possible). Best-effort +
            // fail-open: a persist fault never fails the Add (the live matcher is already armed).
            if (ok) {
                val persisted = persistToLocalBlacklist(text)
                // ★ E-FIX r4 — #133 query-blocklist.log: record the LIVE merge in the pillar log
                // (round-4: after an ADD armed a list and 22 queries were blocked, the file still held
                // only TrustManager's engine-start "score" line — the merge was structurally invisible,
                // unlike query-rotation.log which records every swap). COUNTS ONLY — no domains (T20).
                // PillarLog is bounded + never throws; pathVars-null (a host without paths) skips.
                pathVars?.let { pv ->
                    PillarLog.event(
                        pv.get().appDataDir, PillarLog.Pillar.BLOCKLIST, "merge",
                        "before" to before,
                        "after" to after,
                        "added" to (after - before),
                        "persisted" to persisted,
                    )
                }
            }
            ok
        } catch (e: Throwable) {
            loge("BlocklistSearcher applyFromText", e)
            false
        }
    }

    /**
     * ★ E-FIX r3 — append the Add's compilable lines to the on-disk DNSCrypt LOCAL blacklist file
     * (`PathVars.getDNSCryptLocalBlackListPath`, one of the three paths the RUNNING-edge
     * [MonokumaDnsEngineManager.loadBlocklist] recompile reads) so an installed list SURVIVES an
     * engine restart. Line-set-deduped against the file (a re-add appends nothing), bounded by the
     * user's own action, fail-open (any IO fault logs + returns — the RAM matcher stays armed).
     * ★ E-FIX r4 — reports its outcome (true = durable on disk, incl. the nothing-new re-add; false =
     * no paths / IO fault ⇒ RAM-only this run) so the query-blocklist.log merge line can carry it.
     */
    private fun persistToLocalBlacklist(text: String): Boolean {
        val pv = pathVars ?: return false
        return try {
            val file = java.io.File(pv.get().dnsCryptLocalBlackListPath)
            file.parentFile?.mkdirs()
            val existing: Set<String> = if (file.exists()) {
                file.readLines().map { it.trim() }.filter { it.isNotEmpty() }.toHashSet()
            } else {
                emptySet()
            }
            val fresh = text.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") && it !in existing }
                .toList()
            if (fresh.isNotEmpty()) {
                file.appendText(fresh.joinToString(separator = "\n", prefix = "\n", postfix = "\n"))
            }
            true
        } catch (e: Exception) {
            loge("BlocklistSearcher persistToLocalBlacklist — Add stays RAM-only this run", e)
            false
        }
    }

    // ---- (3) SEARCH GITHUB — one-shot, surfaced, 1h cached, rate-limit-degrade ----

    /**
     * One-shot HTTPS GET to `api.github.com/search/repositories` for blocklist repos matching [query]
     * (top ~[MAX_HITS] by stars). User-initiated + surfaced by the caller (a "Connecting to GitHub…"
     * progress + the one-time privacy disclosure live at the call site). Off the main thread (the
     * suspend map-GET already hops to IO, and we wrap defensively too). No auth token.
     *
     * **1h cache:** a fresh result for the same normalized query is served from SharedPreferences without a
     * network call (privacy: fewer requests reveal less). On a cache miss it does ONE GET, then writes back.
     *
     * **Rate-limit / failure degrade:** GitHub returns 403/422 when rate-limited (unauthenticated quota);
     * [HttpsConnectionManager.get] turns a non-200 into an [IOException]. We catch it (and any throw),
     * return an EMPTY list, and never crash. (A "rate-limited" hint is surfaced via [lastSearchRateLimited]
     * so the screen can show an honest notice instead of "no results".)
     */
    suspend fun searchGitHub(query: String): List<RepoHit> = withContext(dispatcherIo) {
        lastSearchRateLimited = false
        val normalized = query.trim()
        if (normalized.isEmpty()) return@withContext emptyList()

        // 1h cache hit?
        readFreshCache(normalized)?.let { return@withContext it }

        val body = try {
            // The app client URL-encodes the map → "?q=<query>+blocklist" and returns the JSON body lines.
            // Lower the timeouts for an interactive search so the surfaced progress can't hang 180s.
            withReducedTimeouts {
                httpsConnectionManager.get(
                    GITHUB_SEARCH_URL,
                    mapOf(
                        "q" to "$normalized $GITHUB_QUERY_QUALIFIER",
                        "sort" to "stars",
                        "order" to "desc",
                        "per_page" to MAX_HITS.toString(),
                    ),
                ).joinToString("\n")
            }
        } catch (e: IOException) {
            // 403/422 = rate-limited (unauthenticated quota), or any transport error → degrade to empty.
            lastSearchRateLimited = true
            loge("BlocklistSearcher searchGitHub (rate-limited / transport)", e)
            return@withContext emptyList()
        } catch (e: Throwable) {
            loge("BlocklistSearcher searchGitHub", e)
            return@withContext emptyList()
        }

        val hits = parseGitHubSearch(body)
        if (hits.isNotEmpty()) writeCache(normalized, hits)
        hits
    }

    /** True if the LAST [searchGitHub] returned empty due to a rate-limit / transport failure (vs. genuinely 0 hits). */
    @Volatile
    var lastSearchRateLimited: Boolean = false
        private set

    // ---- (4) FETCH RAW LIST — one-shot, surfaced, bounded ----

    /**
     * One-shot SURFACED GET of a raw blocklist URL (a selected [RepoHit.rawCandidateUrl] or a user-pasted
     * raw URL). Bounded read ([MAX_FETCH_BYTES]) so a hostile/huge body can't OOM the device. Off the main
     * thread (the streaming `get` is blocking, so we wrap it in [withContext]). Returns the text, or null on
     * any non-200 / [IOException] / fault. User-initiated; the user previews + manually Adds the result.
     */
    suspend fun fetchListText(rawUrl: String): String? = withContext(dispatcherIo) {
        val url = rawUrl.trim()
        if (!url.startsWith("https://")) {
            // Privacy-first: only https; a plain-http blocklist URL is refused (no silent downgrade).
            return@withContext null
        }
        try {
            val sb = StringBuilder()
            withReducedTimeouts {
                // Blocking streaming GET — consume the stream fully INSIDE the block (it disconnects after).
                httpsConnectionManager.get(url) { input ->
                    val buffered = BufferedInputStream(input)
                    val chunk = ByteArray(READ_CHUNK)
                    var total = 0
                    while (true) {
                        val n = buffered.read(chunk)
                        if (n < 0) break
                        if (total + n > MAX_FETCH_BYTES) {
                            // Bounded: take up to the cap, then stop (a custom blocklist over a few MB is
                            // pathological — arm what fits, the preview count tells the truth).
                            sb.append(String(chunk, 0, MAX_FETCH_BYTES - total, Charsets.UTF_8))
                            total = MAX_FETCH_BYTES
                            break
                        }
                        sb.append(String(chunk, 0, n, Charsets.UTF_8))
                        total += n
                    }
                }
            }
            sb.toString().takeIf { it.isNotBlank() }
        } catch (e: IOException) {
            loge("BlocklistSearcher fetchListText (transport)", e)
            null
        } catch (e: Throwable) {
            loge("BlocklistSearcher fetchListText", e)
            null
        }
    }

    // ---- internals: local domain parsing (parity with Rust parse_line) ----

    /**
     * Count distinct compilable domains in [text] AND collect over-block warnings, mirroring the Rust
     * `parse_line` (blocklist.rs:373-408) + `compile_reader` line discipline (blocklist.rs:419-461):
     *  - skip blanks, `#`/`!` comments, over-long lines (> [MAX_LINE_BYTES]);
     *  - hosts format `<ip> domain` → take the domain; `||domain^` adblock wrappers; strip leading `*.`;
     *  - reject mid-label wildcards, bare IPv4, tokens with no `.` or with `/`, and over-DNS-bound names;
     *  - de-dup the resulting domain SET (the trie collapses duplicates).
     * Over-block warnings flag terminals AT a known public suffix / shared CDN apex (a small built-in set;
     * the authoritative PSL-scored warnings ship from the Centauri sidecar via TrustManager — this is the
     * lightweight paste-time hint the contract asks for).
     */
    private fun countDomains(text: String): Pair<Int, List<String>> {
        val domains = LinkedHashSet<String>()
        val warnings = LinkedHashSet<String>()
        for (raw in text.lineSequence()) {
            if (raw.length > MAX_LINE_BYTES) continue // mirror the streaming cap
            val domain = parseLine(raw) ?: continue
            domains.add(domain)
            overBlockWarningFor(domain)?.let { warnings.add(it) }
        }
        return domains.size to warnings.toList()
    }

    /** True if at least one line of [text] yields a compilable domain (used to confirm a real Add). */
    private fun hasCompilableDomain(text: String): Boolean =
        text.lineSequence().any { it.length <= MAX_LINE_BYTES && parseLine(it) != null }

    /** Kotlin port of Rust `parse_line` (blocklist.rs:373-408). Returns the domain, or null to skip. */
    private fun parseLine(line: String): String? {
        var s = line.trim()
        if (s.isEmpty() || s.startsWith('#') || s.startsWith('!')) return null
        // hosts format: "<ip> domain" → take the domain when the first token parses as an IP sink.
        val ws = s.indexOfFirst { it.isWhitespace() }
        if (ws >= 0) {
            val first = s.substring(0, ws)
            val rest = s.substring(ws).trim()
            if (isHostSink(first)) s = rest
        }
        // adblock-ish wrappers: ||domain^
        s = s.removePrefix("||").trimEnd('^')
        // first whitespace token, then drop an inline comment
        s = s.split(Regex("\\s+")).firstOrNull().orEmpty()
        s = s.substringBefore('#').trim()
        // adblock wildcard "*.zone" → the trie already subsumes the zone
        s = s.removePrefix("*.")
        if (s.contains('*')) return null
        if (s.isEmpty() || !s.contains('.') || s.contains('/')) return null
        if (s.length > MAX_NAME_LEN || s.split('.').size > MAX_LABELS) return null
        // reject a bare IPv4 (all labels are non-empty digits)
        if (s.split('.').all { it.isNotEmpty() && it.all(Char::isDigit) }) return null
        return s.lowercase()
    }

    /** True if [addr] parses as an IPv4/IPv6 sink address (mirror Rust `is_host_sink`, blocklist.rs:412). */
    private fun isHostSink(addr: String): Boolean {
        // IPv4 dotted-quad
        val v4 = addr.split('.')
        if (v4.size == 4 && v4.all { it.isNotEmpty() && it.all(Char::isDigit) && it.toIntOrNull() in 0..255 }) {
            return true
        }
        // IPv6 (compact check: hex groups + ':')
        return addr.contains(':') && addr.all { it.isDigit() || it in "abcdefABCDEF:." }
    }

    /**
     * Lightweight paste-time over-block hint: flag a terminal that sits AT a known public suffix / shared
     * CDN apex (blocking it would block every tenant beneath). NOT the authoritative PSL — that is the
     * Centauri sidecar (TrustManager.WarnKind). A small, honest built-in set, advisory only.
     */
    private fun overBlockWarningFor(domain: String): String? =
        if (KNOWN_OVER_BLOCK_SUFFIXES.contains(domain)) {
            "$WARN_OVER_BLOCK_PREFIX$domain"
        } else {
            null
        }

    /**
     * The LOCAL unsigned trust score for a custom paste/fetch list. Faithful to the live
     * [TrustManager.trustScore] shape + constants: an unsigned, single, un-corroborated source →
     * `min((baseTrust + reputation) / 2, UNSIGNED_CEILING)`. With the same defaults (50/50, ceiling 60)
     * this is **50** — measured/derived, never invented; a custom unsigned list lands AMBER by construction
     * (no path to green without C3 minisign). Deterministic, no network, no native call.
     */
    private fun localUnsignedScore(): Int {
        val ceiling = UNSIGNED_CEILING // unsigned: minisign is C3; the forgeable FNV never lifts this.
        val base = (DEFAULT_SOURCE_TRUST.coerceIn(0, 100) + DEFAULT_SOURCE_REPUTATION.coerceIn(0, 100)) / 2
        // corroboration = 0 (a single pasted/fetched list) ⇒ no bonus.
        return minOf(base, ceiling).coerceIn(0, 100)
    }

    // ---- internals: GitHub JSON parse + 1h cache ----

    /** Parse the GitHub search JSON body into [RepoHit]s (top [MAX_HITS] by stars). Tolerant; never throws. */
    private fun parseGitHubSearch(body: String): List<RepoHit> {
        return try {
            if (body.isBlank()) return emptyList()
            val items = JSONObject(body).optJSONArray("items") ?: return emptyList()
            val hits = ArrayList<RepoHit>(minOf(items.length(), MAX_HITS))
            var i = 0
            while (i < items.length() && hits.size < MAX_HITS) {
                val o = items.optJSONObject(i); i++
                if (o == null) continue
                val fullName = o.optString("full_name").trim()
                if (fullName.isEmpty() || !fullName.contains('/')) continue
                val name = o.optString("name").ifEmpty { fullName.substringAfterLast('/') }
                val stars = o.optInt("stargazers_count", 0)
                val branch = o.optString("default_branch").ifEmpty { "master" }
                hits.add(
                    RepoHit(
                        name = name,
                        fullName = fullName,
                        rawCandidateUrl = rawCandidate(fullName, branch),
                        stars = stars,
                    )
                )
            }
            hits
        } catch (e: Throwable) {
            loge("BlocklistSearcher parseGitHubSearch", e)
            emptyList()
        }
    }

    /** A best-guess raw URL for a likely blocklist file in [fullName]@[branch] — the user confirms via preview. */
    private fun rawCandidate(fullName: String, branch: String): String =
        "https://raw.githubusercontent.com/$fullName/$branch/hosts"

    /** Serve a non-expired cached result for [query], or null if absent/stale/malformed. */
    private fun readFreshCache(query: String): List<RepoHit>? {
        return try {
            val ts = defaultPreferences.getLong(PREF_CACHE_TS, 0L)
            if (ts <= 0L || System.currentTimeMillis() - ts >= CACHE_TTL_MS) return null
            val json = defaultPreferences.getString(PREF_CACHE, null) ?: return null
            val root = JSONObject(json)
            if (root.optString("q") != query) return null // cache is for one query at a time
            val arr = root.optJSONArray("hits") ?: return null
            val out = ArrayList<RepoHit>(arr.length())
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                out.add(
                    RepoHit(
                        name = o.optString("name"),
                        fullName = o.optString("fullName"),
                        rawCandidateUrl = o.optString("rawCandidateUrl"),
                        stars = o.optInt("stars", 0),
                    )
                )
            }
            out.takeIf { it.isNotEmpty() }
        } catch (e: Throwable) {
            loge("BlocklistSearcher readFreshCache (ignored)", e)
            null
        }
    }

    /** Persist [hits] for [query] with a fresh timestamp (the 1h cache). Best-effort; never throws. */
    private fun writeCache(query: String, hits: List<RepoHit>) {
        try {
            val arr = JSONArray()
            for (h in hits) {
                arr.put(
                    JSONObject()
                        .put("name", h.name)
                        .put("fullName", h.fullName)
                        .put("rawCandidateUrl", h.rawCandidateUrl)
                        .put("stars", h.stars)
                )
            }
            val root = JSONObject().put("q", query).put("hits", arr)
            defaultPreferences.edit()
                .putString(PREF_CACHE, root.toString())
                .putLong(PREF_CACHE_TS, System.currentTimeMillis())
                .apply()
        } catch (e: Throwable) {
            loge("BlocklistSearcher writeCache (ignored)", e)
        }
    }

    /**
     * Run [block] with the shared HTTP client's timeouts temporarily lowered to [INTERACTIVE_TIMEOUT_SEC]
     * (the default 180s is far too long for an interactive, surfaced search/fetch), restoring them after.
     * NOTE: the timeout fields are shared state on the (singleton-ish) manager — set + restore tightly.
     */
    private inline fun <T> withReducedTimeouts(block: () -> T): T {
        val savedConnect = httpsConnectionManager.connectTimeoutSec
        val savedRead = httpsConnectionManager.readTimeoutSec
        httpsConnectionManager.connectTimeoutSec = INTERACTIVE_TIMEOUT_SEC
        httpsConnectionManager.readTimeoutSec = INTERACTIVE_TIMEOUT_SEC
        return try {
            block()
        } finally {
            httpsConnectionManager.connectTimeoutSec = savedConnect
            httpsConnectionManager.readTimeoutSec = savedRead
        }
    }

    companion object {
        // --- compiler parity constants (Rust blocklist.rs) ---
        /** Rust `MAX_NAME_LEN` (blocklist.rs:36) — DNS name byte bound. */
        private const val MAX_NAME_LEN = 253
        /** Rust `MAX_LABELS` (blocklist.rs:37) — label-count bound. */
        private const val MAX_LABELS = 127
        /** Rust `MAX_LINE_BYTES` (blocklist.rs:39) — a single over-long line is skipped, not allocated. */
        private const val MAX_LINE_BYTES = 8192

        // --- local trust score (parity with TrustManager.kt:439-445) ---
        /** Unsigned trust ceiling — TrustManager.UNSIGNED_CEILING (TrustManager.kt:439). Custom lists cap here. */
        private const val UNSIGNED_CEILING = 60
        /** Default operator/base weight — TrustManager.DEFAULT_SOURCE_TRUST (TrustManager.kt:442). */
        private const val DEFAULT_SOURCE_TRUST = 50
        /** Default curated reputation — TrustManager.DEFAULT_SOURCE_REPUTATION (TrustManager.kt:445). */
        private const val DEFAULT_SOURCE_REPUTATION = 50

        // --- GitHub search ---
        private const val GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
        /** Query qualifier appended to the user's terms (host-list / blocklist repos). No auth token. */
        private const val GITHUB_QUERY_QUALIFIER = "blocklist hosts"
        /** Top-N hits surfaced (also `per_page`). */
        private const val MAX_HITS = 15
        /** 1h SharedPreferences cache TTL. */
        private const val CACHE_TTL_MS = 3_600_000L
        /**
         * SharedPreferences keys for the 1h GitHub-search cache (JSON body + epoch-ms). Defined locally so
         * this file is independently compilable; the values MATCH the screen-shell lane's PreferenceKeys
         * (`pref_blocklist_search_cache` / `…_ts`) so they share the one default store cleanly.
         */
        private const val PREF_CACHE = "pref_blocklist_search_cache"
        private const val PREF_CACHE_TS = "pref_blocklist_search_cache_ts"

        // --- fetch bounds ---
        /** Hard cap on a fetched raw blocklist body (a few MB) — bounded read, anti-OOM. */
        private const val MAX_FETCH_BYTES = 8 * 1024 * 1024
        /** Stream read chunk. */
        private const val READ_CHUNK = 8192
        /** Interactive (surfaced) timeout — far below the client's 180s default. */
        private const val INTERACTIVE_TIMEOUT_SEC = 30

        // --- warnings ---
        private const val WARN_EMPTY = "No compilable domains found in this list."
        private const val WARN_OVER_BLOCK_PREFIX =
            "Over-block risk — blocks every site under a shared suffix: "

        /**
         * A small, honest built-in set of public suffixes / shared CDN apexes for the paste-time over-block
         * HINT. This is intentionally minimal — the authoritative, PSL-scored over-block warnings ship from
         * the Centauri sidecar (TrustManager.WarnKind, the versioned bundled PSL), surfaced separately.
         */
        private val KNOWN_OVER_BLOCK_SUFFIXES = setOf(
            "co.uk", "com.au", "co.jp", "co.in",
            "github.io", "githubusercontent.com",
            "amazonaws.com", "s3.amazonaws.com", "cloudfront.net",
            "azurewebsites.net", "blob.core.windows.net",
            "herokuapp.com", "appspot.com", "web.app", "firebaseapp.com",
            "cloudflare.net", "fastly.net", "akamaihd.net",
            "googleusercontent.com", "blogspot.com", "wordpress.com",
        )
    }
}
