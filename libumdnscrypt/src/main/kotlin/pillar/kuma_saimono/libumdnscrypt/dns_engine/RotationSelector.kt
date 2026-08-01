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

/**
 * P10 — the **pure, deterministic resolver-rotation selection core**. Given a pool of already-decoded
 * candidate resolvers, it (1) **trust-filters** the pool on the privacy/security signals, (2) **excludes
 * the operator family used in the last rotation window** for diversity, then (3) **picks one survivor,
 * RTT-weighted** (faster reachable resolvers are favoured). It is the cognitive heart of `RotationManager`,
 * split out as a side-effect-free, Android-free unit so it runs under plain JUnit on the metal.
 *
 * **Why a pure unit (the ground-truth boundary).** Everything the live datapath touches stays in
 * `RotationManager` (the `@ModulesServiceScope @Inject` owner — same template as
 * [MonokumaDnsEngineManager]/[TrustManager]) and the seams it reuses:
 *   - candidates come from `PathVars` sources (`public-resolvers.md`/`relays.md`,
 *     `PathVars.java:325-331`) decoded by the EXISTING stamp reader — the props byte
 *     (`bin[1]` bit0=DNSSEC / bit1=no-log / bit2=no-filter, `DnsServerItem.java:76-84`) and the proto
 *     byte (`bin[0]` 0x01=DNSCrypt / 0x02=DoH / 0x05=ODoH, `DnsServerItem.java:66-72`) are the REAL
 *     per-resolver trust dimension (the roadmap "Resolver score": privacy/security/no-log/DNSSEC,
 *     `roadmap-rust-blocklist.md:41`). RotationManager hands those decoded bits in as [ResolverCandidate]
 *     so this selector NEVER re-parses a stamp (no `android.util.Base64` here → JUnit-on-metal clean).
 *   - per-candidate RTT comes from the EXISTING off-pool ping seam
 *     (`RelaysPingInteractor.getTimeout` → `SocketInternetChecker.checkConnectionPing`,
 *     `NO_CONNECTION = -1` = unreachable); the active-pool RTT is the engine's own
 *     `MonokumaDnsEngine.selectBestEndpoint` EWMA (`MonokumaDnsEngine.kt:174-197`). This selector does
 *     NOT open probes — it ranks the RTTs the seam already measured.
 *   - the chosen set is installed by **re-calling** the atomic pool-swap
 *     (`TortaCore.configureResolver`, `TortaCore.kt:219-228` → `nativeResolverConfigure` `:47`); a bad /
 *     empty selection returns `null` here so RotationManager keeps the CURRENT live set (fail-safe —
 *     rotation must never tear down a live resolution).
 *
 * **No blocklist trust here.** The P8 `TrustManager`/`TrustState`
 * (`TrustManager.kt:178-220`, `TrustRepository.kt:33-40`) scores the installed **blocklist** per
 * fingerprint, NOT resolvers — it carries no per-resolver privacy signal. This selector therefore trusts
 * on the resolver stamp props, the only real resolver-trust dimension in tree today.
 *
 * Deterministic by construction: no clock, no RNG. Ties (equal score, equal RTT bucket) break on a stable
 * key so the same pool always yields the same pick — reproducible tests, and friendly to a sandboxed
 * orchestrator. The caller supplies the rotation window's "current/last operator family" for the diversity
 * exclusion; the selector never reads time.
 */
object RotationSelector {

    /**
     * One decoded rotation candidate. Pure data — every field is something `RotationManager` already has
     * from a reused seam, so the selector adds **no** parsing/IO of its own.
     *
     * @param id              stable resolver id (the `public-resolvers.md` name) — the swap JSON `id`
     *                        and the deterministic tiebreak key. Must be non-blank to be considered.
     * @param operatorFamily  the diversity key — a per-**operator** family handle (e.g. the registrable
     *                        base of the provider), NOT the IP. Derived by `RotationManager` from the
     *                        stamp/name; the selector only compares it for the family exclusion.
     * @param dnssec          stamp props bit0 (`DnsServerItem.java:76-78`): the resolver validates DNSSEC.
     * @param noLog           stamp props bit1 (`DnsServerItem.java:79-81`): the resolver keeps no logs.
     * @param noFilter        stamp props bit2 (`DnsServerItem.java:82-84`): the resolver does not filter.
     * @param dnsCrypt        proto byte 0x01 (`DnsServerItem.java:66-67`): a DNSCrypt resolver. DNSCrypt
     *                        is the only transport the native swap builds today
     *                        (`nativeResolverConfigure` dnscrypt/do53 arms) — a non-DNSCrypt candidate is
     *                        kept eligible only when the [RotationPolicy.allowDoh] protocol gate is on
     *                        (#22 s5A-ext; it then rides the Go TOML lane).
     * @param rttMs           measured RTT in ms from the reused ping seam; `< 0` = unreachable (the seam's
     *                        `NO_CONNECTION = -1`) ⇒ dropped before selection. Lower is better.
     * @param reachable       explicit reachability override; defaults to `rttMs >= 0`. A candidate that
     *                        is decoded/buildable but proven dead is excluded (swap only known-buildable).
     * @param ipv4            the stamp's address family carries an IPv4 literal (decoded host-side by
     *                        `RotationPoolSource.stampFamily` — the LP(addr) at proto-relative offset,
     *                        classified V4/V6/Unknown). Defaults `true` so a candidate whose family is
     *                        UNKNOWN (a hostname target, ODoH 0x05, an undecodable/relayed addr) is NEVER
     *                        family-hidden — fail-open, the SAME rule as the manual picker's `family_ok`
     *                        (`torta_core::stamp_addr_family` → `(true,true)` on Unknown). A V6-literal
     *                        resolver decodes to `(ipv4=false, ipv6=true)`; a V4 literal to `(true,false)`.
     * @param ipv6            the stamp's address family carries an IPv6 literal (see [ipv4]). Defaults
     *                        `true` for the same fail-open reason.
     */
    data class ResolverCandidate(
        val id: String,
        val operatorFamily: String,
        val dnssec: Boolean,
        val noLog: Boolean,
        val noFilter: Boolean,
        val dnsCrypt: Boolean,
        val rttMs: Int,
        val reachable: Boolean = rttMs >= 0,
        val ipv4: Boolean = true,
        val ipv6: Boolean = true,
    )

    /**
     * The rotation policy knobs. All raw cadence/policy/diversity dials live behind the ONE Expert toggle
     * (`pref_engine_expert`, `TortaeKeys.java:152`) per SIMPLE-UX; the noob "rotate for privacy" switch
     * (default OFF) only flips rotation on/off in `RotationManager`. Defaults here are the privacy-first
     * "noob" posture: require no-log, prefer DNSSEC, enforce operator diversity.
     *
     * @param requireNoLog     trust-filter: drop any candidate that does NOT advertise no-log. Privacy is
     *                        the headline reason a user rotates, so this is ON by default.
     * @param preferDnssec     scoring: a DNSSEC-validating resolver scores higher (preference, not a hard
     *                        drop — a no-log non-DNSSEC resolver is still better than nothing).
     * @param requireDnssec    trust-filter: drop any candidate lacking DNSSEC. OFF by default (preference,
     *                        not a wall — mirrors `DnsServerFeatures` requireDnssec being opt-in).
     * @param allowDnsCrypt    protocol gate: DNSCrypt (0x01-stamp) candidates are eligible. ON by default
     *                        (the transport the native swap builds; the Go TOML lane carries it too).
     * @param allowDoh         protocol gate: DoH (0x02-stamp) candidates are eligible. OFF by default —
     *                        when armed, DoH picks ride the Go TOML lane (server_names); the typed Rust
     *                        swap stays dnscrypt-only until the DoH-spec lane lands (#22 s5A-ext).
     * @param enforceDiversity exclude the [lastOperatorFamily] so a rotation never lands the SAME operator
     *                        twice in a row (the 12h-diversity rule). ON by default.
     */
    data class RotationPolicy(
        val requireNoLog: Boolean = true,
        val preferDnssec: Boolean = true,
        val requireDnssec: Boolean = false,
        // #22 s5A-ext (Socio: "the Rotation engine must also include as filters, wich protocol!
        // Dnscrpyt,ODOH,DOH!") — the PROTOCOL gate, replacing the blunt requireDnsCrypt bool: a
        // candidate survives when its stamp protocol is ALLOWED. `allowDnsCrypt` covers 0x01 stamps,
        // `allowDoh` covers 0x02 (decodeStampBytes flags them dnsCrypt=false). Defaults reproduce the
        // pre-s5A posture bit-exact (dnscrypt-only). ODoH (0x05) rides its OWN lane
        // (ResolverRuntime.deriveOdohUpstreams gated by cfg.odoh_servers) — not the random pick.
        // NOTE both-off ⇒ nothing survives ⇒ selection declines ⇒ keep-current fail-safe (the same
        // posture as the both-off family gate below).
        val allowDnsCrypt: Boolean = true,
        val allowDoh: Boolean = false,
        val enforceDiversity: Boolean = true,
        // require_nofilter (the DNSCrypt server-props bit2, decoded into ResolverCandidate.noFilter):
        // when armed, only NON-filtering resolvers survive. Default false = backward-compatible with the
        // rotation path (policyFromPrefs never set it); the config path (policyFromConfig) drives it from
        // the user's Require-no-filter toggle so the toggle reaches the LIVE pool.
        val requireNoFilter: Boolean = false,
        // The address-family gate — the SAME filter set that gates the MANUAL picker (torta_ui
        // build_server_rows `family_ok = (cfg.ipv4_servers && v4) || (cfg.ipv6_servers && v6)`) now gates
        // ROTATION auto-pick too (the LOCKED SPEC: one filter set, both paths). Mirror the dnscrypt-proxy
        // `ipv4_servers`/`ipv6_servers` config bits. BOTH default true = permissive: the legacy prefs path
        // (policyFromPrefs) leaves them true ⇒ no family drop ⇒ zero regression; the typed-config path
        // (policyFromConfig/Odoh) drives them from cfg.ipv4Servers/cfg.ipv6Servers so the SLINT SERVER-TYPES
        // toggle reaches the LIVE rotation pool. A candidate survives the gate when at least one ALLOWED
        // family matches its decoded family (Unknown = (ipv4,ipv6)=(true,true) matches whichever is allowed;
        // both-off ⇒ nothing survives ⇒ selection declines ⇒ keep-current fail-safe).
        val allowIpv4: Boolean = true,
        val allowIpv6: Boolean = true,
    )

    /**
     * Run the selection. Returns the chosen [ResolverCandidate], or `null` when no diverse, trusted,
     * reachable survivor exists — the caller's fail-safe signal to **keep the current set** and abort the
     * rotation (never swap to nothing, never tear down a live resolution).
     *
     * Pipeline (each stage is independently unit-tested):
     *   1. **Sanitize** — drop blank-id and unreachable candidates (`reachable == false` / `rttMs < 0`).
     *   2. **Trust-filter** — drop candidates failing the policy's hard requirements (no-log / DNSSEC /
     *      DNSCrypt). This is the resolver-trust gate (stamp props), NOT the P8 blocklist trust.
     *   3. **Diversity** — exclude [lastOperatorFamily] when [RotationPolicy.enforceDiversity] is on, so
     *      the new pick is a DIFFERENT operator than the last window. If exclusion empties the pool, the
     *      selection fails (`null`) rather than silently re-picking the same family.
     *   4. **RTT-weighted pick** — among survivors, choose the best by [score]: lower RTT wins, DNSSEC is
     *      a tiebreaker bonus when [RotationPolicy.preferDnssec], no-filter is a minor bonus, and a stable
     *      id key breaks exact ties (deterministic — no RNG/clock).
     *
     * @param candidates         the decoded pool (from `PathVars` sources via the reused stamp reader).
     * @param lastOperatorFamily the operator family of the CURRENTLY-installed set (the last rotation);
     *                          excluded for diversity. `null`/blank ⇒ no family is excluded (first pick).
     * @param policy             the rotation policy (Expert-gated dials; privacy-first defaults).
     */
    fun select(
        candidates: List<ResolverCandidate>,
        lastOperatorFamily: String?,
        policy: RotationPolicy = RotationPolicy(),
    ): ResolverCandidate? {
        val survivors = filterTrusted(candidates, policy)
            .let { if (policy.enforceDiversity) excludeFamily(it, lastOperatorFamily) else it }
        if (survivors.isEmpty()) return null
        // Deterministic best: maximize score; the score folds RTT (primary) + props bonuses, and the id
        // breaks exact ties so the same pool always yields the same pick.
        return survivors.maxWithOrNull(
            compareBy<ResolverCandidate> { score(it, policy) }.thenByDescending { it.id }
        )
    }

    /**
     * #2 (Socio 2026-06-25) — the COMPLETELY-RANDOM bounded pick. Filter by trust + operator-diversity
     * (reusing [filterTrusted] + [excludeFamily]), then RANDOMLY choose up to [max] survivors. Seeded by
     * [seed] so a unit test is reproducible (fixed seed ⇒ fixed pick) while each rotation window — a fresh
     * seed from the advancing rotation cursor — yields a DIFFERENT set: the Socio's "≤20 servers, everything
     * random; dnscrypt does the per-query rest." Input is stably ordered by id BEFORE the seeded shuffle so
     * the seed alone determines the result regardless of source-file order. Returns ≤[max] candidates, or
     * EMPTY when no trusted/diverse/reachable survivor exists — the caller's fail-safe: keep the current pool,
     * NEVER write an empty server_names (a rotation must never break a live resolution).
     */
    fun selectRandomSet(
        candidates: List<ResolverCandidate>,
        lastOperatorFamily: String?,
        seed: Long,
        max: Int = GEEK_SAFE_MAX_SERVERS,
        policy: RotationPolicy = RotationPolicy(),
    ): List<ResolverCandidate> {
        val survivors = filterTrusted(candidates, policy)
            .let { if (policy.enforceDiversity) excludeFamily(it, lastOperatorFamily) else it }
        if (survivors.isEmpty()) return emptyList()
        return survivors
            .sortedBy { it.id }                       // stable base order → the seed fully determines the pick
            .shuffled(java.util.Random(seed))         // completely random within the criteria-filtered pool
            .take(max.coerceAtLeast(1))
    }

    /**
     * Stage 1+2: sanitize then trust-filter. Pure list→list, exposed for direct unit assertions.
     *
     * Drops: blank id; unreachable (`!reachable` or `rttMs < 0`); and — per [policy] — non-no-log,
     * non-DNSSEC, non-DNSCrypt, wrong-family candidates. The order is irrelevant (all are conjunctive
     * drops). The family gate `(allowIpv4 && ipv4) || (allowIpv6 && ipv6)` is the EXACT mirror of the
     * manual picker's `family_ok` (torta_ui `build_server_rows`), so the SAME filter gates both paths.
     */
    fun filterTrusted(
        candidates: List<ResolverCandidate>,
        policy: RotationPolicy = RotationPolicy(),
    ): List<ResolverCandidate> = candidates.filter { c ->
        c.id.isNotBlank() &&
            c.reachable && c.rttMs >= 0 &&
            (!policy.requireNoLog || c.noLog) &&
            (!policy.requireDnssec || c.dnssec) &&
            (!policy.requireNoFilter || c.noFilter) &&
            ((policy.allowDnsCrypt && c.dnsCrypt) || (policy.allowDoh && !c.dnsCrypt)) &&
            ((policy.allowIpv4 && c.ipv4) || (policy.allowIpv6 && c.ipv6))
    }

    /**
     * Stage 3: operator-diversity exclusion. Removes every candidate whose [ResolverCandidate.operatorFamily]
     * equals [lastOperatorFamily] (case-insensitive, trimmed). A `null`/blank last family excludes nothing
     * (the first-ever pick). The family key is per-**operator**, not per-IP, so two endpoints of the same
     * provider both fall out together.
     */
    fun excludeFamily(
        candidates: List<ResolverCandidate>,
        lastOperatorFamily: String?,
    ): List<ResolverCandidate> {
        val last = lastOperatorFamily?.trim()?.lowercase()
        if (last.isNullOrEmpty()) return candidates
        return candidates.filter { it.operatorFamily.trim().lowercase() != last }
    }

    /**
     * The RTT-weighted score (higher = picked). Pure and deterministic.
     *
     * RTT is the dominant term: it is mapped to a positive weight that DECREASES as RTT grows, so a faster
     * reachable resolver always outscores a slower sibling with the same props. Privacy/security props add
     * small, bounded bonuses that act as tiebreakers between resolvers of comparable latency — they never
     * let a much slower resolver leapfrog a much faster one (the bonuses are capped well below the RTT
     * spread). Unreachable candidates never reach here (filtered in stage 1).
     *
     *   rttWeight = RTT_WEIGHT_BASE / (1 + rttMs)            // 1000 @ 0ms → ~10 @ 99ms → →0 as RTT↑
     *   bonus     = (preferDnssec && dnssec ? DNSSEC_BONUS : 0)
     *             + (noFilter ? NOFILTER_BONUS : 0)
     *   score     = rttWeight + bonus
     */
    fun score(candidate: ResolverCandidate, policy: RotationPolicy = RotationPolicy()): Double {
        val rtt = candidate.rttMs.coerceAtLeast(0)
        val rttWeight = RTT_WEIGHT_BASE / (1.0 + rtt)
        var bonus = 0.0
        if (policy.preferDnssec && candidate.dnssec) bonus += DNSSEC_BONUS
        if (candidate.noFilter) bonus += NOFILTER_BONUS
        return rttWeight + bonus
    }

    /**
     * Base numerator of the RTT weight. At 0 ms a candidate weighs [RTT_WEIGHT_BASE]; the weight falls off
     * as `BASE / (1 + rttMs)`, so RTT dominates the score across the realistic 0–500 ms band. Sized so the
     * RTT spread between a fast (~20 ms) and a slow (~200 ms) resolver (≈ 47.6 − 4.98 ≈ 42.6) dwarfs the
     * total props bonus ([DNSSEC_BONUS] + [NOFILTER_BONUS] = 6.0) — props only break near-ties.
     */
    const val RTT_WEIGHT_BASE = 1000.0

    /** Tiebreak bonus for a DNSSEC-validating resolver when the policy prefers DNSSEC. Bounded, small. */
    const val DNSSEC_BONUS = 5.0

    /** Minor tiebreak bonus for a no-filter (unfiltered/uncensored) resolver. Bounded, smaller. */
    const val NOFILTER_BONUS = 1.0

    /**
     * #2 rotation pool consts — HISTORY: born as the ACADEMIC-WALL GEEK-tier slider ceilings (Socio
     * 2026-06-25); RETIRED as ceilings by the Socio 2026-07-19 no-limits law ("remove any Limit to the
     * Number of Resolver / Relays Selectable by the User … its not Genuine for the sake of the user").
     * Every count clamp is now FLOOR-ONLY (servers ≥1, relays ≥0, free upward) on BOTH surfaces —
     * these consts remain only as named reference points for docs/tests. The ACTUAL count is read from
     * the user pref at rotation time and passed as [selectRandomSet]'s `max`; dnscrypt does the
     * per-query LB within the chosen pool. NEVER hard-code the count.
     */
    const val GEEK_SAFE_MAX_SERVERS = 20

    /**
     * The LOCKED-SPEC rotation DEFAULT server count (Socio, restated 4×): a random pick draws EXACTLY this many
     * resolvers from the wired lists after the filters, when the user has expressed no count pref. Distinct from
     * [GEEK_SAFE_MAX_SERVERS] — that is the GEEK slider's upper CEILING (20), this is the default landing (10).
     * Absent the (not-yet-wired) count pref, EVERY rotation lands here, so this value is load-bearing.
     */
    const val GEEK_SAFE_DEFAULT_SERVERS = 10

    /**
     * HISTORY: the relays-per-server GEEK slider ceiling (Socio 2026-06-25, 10; raised to 20 by Socio
     * 2026-07-19 "even 20 Relays per 1 Resolver"; then RETIRED as a ceiling the same day by the
     * no-limits law — relay counts are floor-only ≥0, free upward). Kept as a named reference point
     * for docs/tests only. The LOCKED-SPEC relay DEFAULT stays [GEEK_SAFE_DEFAULT_RELAYS].
     */
    const val GEEK_SAFE_MAX_RELAYS = 20

    /**
     * The LOCKED-SPEC relays-per-server DEFAULT (the pre-s5A value, kept when the user has expressed
     * no relay-count pref): 10 relays/server = 100 relays over the 10-server default pick.
     */
    const val GEEK_SAFE_DEFAULT_RELAYS = 10
}
