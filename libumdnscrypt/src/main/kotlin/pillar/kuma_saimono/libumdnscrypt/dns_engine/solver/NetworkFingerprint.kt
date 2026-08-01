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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.solver

/**
 * Monster Plan §7 (Stage E — the SOLVER reflex) — the **network fingerprint**: a stable, opaque, PRIVACY-SAFE
 * key for "which network am I on right now" so a solved binding can be CACHED per network and instantly
 * reused on re-entry (`MONSTER_ENHANCEMENT_PLAN.md:86` — "CACHE the solution per network fingerprint
 * (SSID/gateway → instant reuse), re-solve on change").
 *
 * **Pure by construction — the ground-truth boundary.** The IMPURE part (asking Android for the live SSID /
 * gateway via `WifiManager`/`ConnectivityManager`) lives in the future live `SolverManager`
 * (`@ModulesServiceScope @Inject`, the [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationManager]/
 * [pillar.kuma_saimono.libumdnscrypt.dns_engine.MonokumaDnsEngineManager] template). THIS object takes the raw
 * link attributes as plain strings and folds them into a stable opaque key with **no clock, no RNG, no
 * Android, no IO** — so it runs under plain JUnit on the metal (the
 * [pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationSelector] precedent: a side-effect-free cognitive unit
 * the Android owner drives).
 *
 * **Privacy (simple-UX + no PII leak, `feedback-simple-ux.md`).** The raw SSID is sensitive (it can name a
 * home/workplace and is a known geolocation signal). It is therefore **never stored raw** — [of] hashes the
 * normalized attributes into a non-reversible decimal digest and the [NetworkFingerprint.key] the cache is
 * keyed on contains NO raw SSID. The cache ([BindingCache]) only ever sees this opaque key.
 *
 * **Stability (why caching works at all).** The key is deterministic: the same {linkType, SSID-or-carrier,
 * gateway} always yields the same key, and two *different* networks (different SSID OR different gateway)
 * yield different keys with overwhelming probability. That stability is what turns a 1–2 s solver race into a
 * 0-cost map lookup when you walk back onto a network you already solved — and what lets [hasChanged] detect
 * a genuine network change (the "re-solve on change" verb) without ever comparing raw identifiers.
 */
data class NetworkFingerprint(
    /** The opaque, privacy-safe, deterministic key. Contains no raw SSID; safe to log/persist/compare. */
    val key: String,
) {
    companion object {

        /** Link transport class — the coarse axis of the fingerprint (Wi-Fi vs cellular vs ethernet/other). */
        enum class LinkType(val tag: String) {
            WIFI("wifi"),
            CELLULAR("cell"),
            ETHERNET("eth"),
            /** No link / unknown transport — every UNKNOWN folds to ONE shared key so it never thrashes the cache. */
            UNKNOWN("none"),
        }

        /**
         * Build a fingerprint from the live link attributes. PURE — the caller (the live manager) reads these
         * three values from Android and hands them in; this never touches Android itself.
         *
         * Normalization (so cosmetically-different reads of the SAME network collapse to one key):
         *  - [linkType] picks the coarse axis.
         *  - WIFI: the identity is the **SSID** — trimmed, surrounding quotes stripped (Android's
         *    `WifiInfo.getSSID()` returns the SSID wrapped in double-quotes), lower-cased; a blank/`<unknown ssid>`
         *    read degrades the wifi identity to the gateway alone (still a stable per-network key on that LAN).
         *  - CELLULAR: there is no SSID; the identity is the **carrier** handle (also trimmed/lower-cased). The
         *    gateway on cellular is unstable, so it is IGNORED for cellular (carrier alone is the stable axis).
         *  - ETHERNET/UNKNOWN: identity is the **gateway** alone.
         *  - the **gateway** (default-route IP, e.g. `192.168.1.1`) is trimmed/lower-cased and folded in for
         *    WIFI/ETHERNET (it disambiguates two networks that happen to share an SSID, and is the per-LAN
         *    anchor when the SSID is unreadable).
         *
         * The normalized `"<linkTag>|<identity>|<gateway>"` triple is then [hashKey]'d into the opaque digest.
         *
         * @param linkType   the transport class.
         * @param ssidOrCarrier  Wi-Fi SSID (WIFI) or carrier name (CELLULAR); ignored for ETHERNET/UNKNOWN.
         * @param gateway    default-route IP; folded for WIFI/ETHERNET, ignored for CELLULAR/UNKNOWN.
         */
        fun of(
            linkType: LinkType,
            ssidOrCarrier: String?,
            gateway: String?,
        ): NetworkFingerprint {
            val gw = normalize(gateway)
            val ident = when (linkType) {
                LinkType.WIFI -> {
                    val ssid = normalizeSsid(ssidOrCarrier)
                    // A readable SSID is the identity; an unreadable one degrades to the gateway (still stable on a LAN).
                    if (ssid.isNotEmpty()) ssid else gw
                }
                LinkType.CELLULAR -> normalize(ssidOrCarrier)
                LinkType.ETHERNET -> gw
                // UNKNOWN MUST collapse to the single NONE sentinel — no gateway leaks into its identity, or a
                // no/changing-link device would spawn a fresh cache key per gateway read (cache thrash). See the
                // class contract (every UNKNOWN folds to ONE shared key) + AntiThrashInvariantTest I6 / NONE.
                LinkType.UNKNOWN -> ""
            }
            // Gateway is folded in only where it is a STABLE per-network anchor (not on cellular).
            val gwAxis = when (linkType) {
                LinkType.WIFI, LinkType.ETHERNET -> gw
                LinkType.CELLULAR, LinkType.UNKNOWN -> ""
            }
            val canonical = "${linkType.tag}|$ident|$gwAxis"
            return NetworkFingerprint(hashKey(canonical))
        }

        /**
         * Build a fingerprint directly from an already-opaque key (e.g. one previously persisted). Pure
         * pass-through — no re-hashing — so a round-tripped key compares equal to its origin.
         */
        fun fromKey(opaqueKey: String): NetworkFingerprint = NetworkFingerprint(opaqueKey)

        /**
         * The fingerprint for "no usable network identity" — a single shared sentinel so an unknown/absent
         * link never spawns a parade of distinct cache keys (which would defeat the cache and invite churn).
         */
        val NONE: NetworkFingerprint = of(LinkType.UNKNOWN, null, null)

        /** Trim + lower-case a raw attribute; null/blank → "". */
        private fun normalize(raw: String?): String = raw?.trim()?.lowercase() ?: ""

        /**
         * SSID-specific normalization: strip the surrounding double-quotes Android wraps an SSID in, drop the
         * `<unknown ssid>` placeholder Android returns when location is off, then trim + lower-case.
         */
        private fun normalizeSsid(raw: String?): String {
            val s = raw?.trim().orEmpty()
            if (s.isEmpty()) return ""
            val unquoted = if (s.length >= 2 && s.first() == '"' && s.last() == '"') s.substring(1, s.length - 1) else s
            val cleaned = unquoted.trim()
            if (cleaned.isEmpty() || cleaned.equals("<unknown ssid>", ignoreCase = true)) return ""
            return cleaned.lowercase()
        }

        /**
         * Hash the canonical triple to a NON-REVERSIBLE opaque key. Uses a stable, dependency-free 64-bit
         * FNV-1a fold rendered as an unsigned decimal — deterministic across runs/processes/JVMs and free of
         * `String.hashCode()`'s 32-bit collision pressure, with NO Android (`MessageDigest`/`android.util`)
         * dependency so the producer stays JUnit-clean. Cryptographic strength is NOT required — the goal is
         * a stable, collision-resistant, privacy-preserving cache key, not a secret.
         */
        internal fun hashKey(canonical: String): String {
            var hash = FNV_OFFSET_BASIS
            // Hash the UTF-8 bytes so non-ASCII SSIDs fold deterministically (charset-independent of the JVM default).
            for (b in canonical.toByteArray(Charsets.UTF_8)) {
                hash = hash xor (b.toLong() and 0xff)
                hash *= FNV_PRIME
            }
            // Render as UNSIGNED decimal so the key is a stable, log-safe token with no leading sign.
            return "fp_" + java.lang.Long.toUnsignedString(hash)
        }

        /** FNV-1a 64-bit offset basis. */
        private const val FNV_OFFSET_BASIS: Long = -3750763034362895579L // 0xcbf29ce484222325
        /** FNV-1a 64-bit prime. */
        private const val FNV_PRIME: Long = 1099511628211L // 0x100000001b3
    }
}

/**
 * Did the network change between two fingerprints? The "re-solve on change" trigger
 * (`MONSTER_ENHANCEMENT_PLAN.md:86`). Pure equality on the opaque key — no raw identifiers compared.
 * A `null` previous fingerprint (first observation) counts as a change (there is nothing to reuse yet).
 */
fun NetworkFingerprint.hasChanged(previous: NetworkFingerprint?): Boolean = this != previous
