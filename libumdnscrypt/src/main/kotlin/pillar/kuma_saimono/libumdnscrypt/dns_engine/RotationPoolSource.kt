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
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge

/**
 * D06 — the ONE shared source of rotation-pool candidates: the signed, auto-updating
 * `public-resolvers.md` / `relays.md` scan + the `sdns://` stamp decode + the user's require_*
 * policy read. Extracted from [RotationManager]'s private parsers so BOTH consumers read one
 * implementation (never two drifting copies):
 *
 *  - [RotationManager.composeRotatedUpstreams] — the periodic random pick (cadence-driven);
 *  - [ResolverRuntime]'s MODE-2 pool derivation — `server_names ∩ public-resolvers.md`, the fix
 *    that retires the hardcoded two-stamp production pool (the D06(a) seam).
 *
 * Everything here is pure parsing + pref reads: no network, no native calls, no hot-path use —
 * both consumers run it on the control plane only (a lifecycle edge or a cadence tick). Every
 * entry point is fail-safe: a malformed file/stamp yields an empty list / a skipped candidate,
 * never a throw into the caller.
 */
object RotationPoolSource {

    /**
     * One decoded candidate: the [RotationSelector.ResolverCandidate] the pure selector ranks,
     * PLUS the two fields the selector deliberately does not carry —
     *  - [sdns]: the RAW `sdns://` stamp (verbatim from the signed md) — what the Rust DNSCrypt
     *    transport consumes ([uniffi.torta_core.UpstreamSpec.stamp]);
     *  - [address]: the `ip:port` decoded out of a DNSCrypt (0x01) stamp — what the existing
     *    TCP-connect ping seam ([RotationPing]) dials to measure a warm-RTT hint (D30). Empty
     *    when the stamp carries no parsable address (the candidate is simply not pinged).
     */
    data class StampedCandidate(
        val candidate: RotationSelector.ResolverCandidate,
        val sdns: String,
        val address: String,
    )

    /**
     * Scan a signed source file (`public-resolvers.md` / `relays.md`) into `(name, sdns)` pairs.
     * Format: a `## <name>` line names an entry; the NEXT `sdns://` line carries its stamp (an
     * entry with several stamps keeps the FIRST — the [RotationManager] precedent). Read directly
     * via java.io.File (the path is app-private; no Context needed). Never throws — a read fault
     * yields an empty list (the caller declines / falls back).
     */
    fun readNamedStamps(path: String): List<Pair<String, String>> = try {
        val file = java.io.File(path)
        if (!file.exists()) emptyList() else scanNamedStamps(file.readLines())
    } catch (e: Exception) {
        loge("RotationPoolSource readNamedStamps", e)
        emptyList()
    }

    /** The pure `## name` + `sdns://` line scan behind [readNamedStamps] (unit-testable). */
    fun scanNamedStamps(lines: List<String>): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>()
        var pendingName: String? = null
        for (raw in lines) {
            val line = raw.trim()
            when {
                line.startsWith("## ") -> pendingName = line.removePrefix("## ").trim()
                line.startsWith("sdns://") && !pendingName.isNullOrBlank() -> {
                    val stamp = line.substringBefore(' ')
                    val name = pendingName
                    // `name != null` dropped (proven constant); BOTH isCleanToken guards stay --
                    // they are the actual sanitiser on the pool entry.
                    if (isCleanToken(name) && isCleanToken(stamp)) {
                        out.add(name to stamp)
                    }
                    pendingName = null
                }
            }
        }
        return out
    }

    /**
     * Parse the AUTO-UPDATING, minisig-verified `public-resolvers.md` at [path] into decoded
     * rotation candidates (stamp props + raw stamp + ping address). A malformed stamp is skipped,
     * never a crash; a missing/unreadable file is an empty pool (the caller keeps its current
     * set / falls back to the default pool).
     */
    fun readStampedCandidates(path: String): List<StampedCandidate> =
        readNamedStamps(path).mapNotNull { (name, sdns) -> decodeStamped(name, sdns) }

    /**
     * Decode one `sdns://` stamp into a [StampedCandidate], or null to skip it. Thin
     * android-Base64 wrapper over the pure [decodeStampBytes] (URL-safe alphabet, padding
     * optional — the DNS Stamp spec's b64url). Never throws.
     */
    fun decodeStamped(name: String, sdns: String): StampedCandidate? = try {
        val bin = android.util.Base64.decode(
            sdns.removePrefix("sdns://"), android.util.Base64.URL_SAFE
        )
        decodeStampBytes(name, sdns, bin)
    } catch (e: Exception) {
        null // a malformed stamp is skipped, never crashes the derivation/rotation
    }

    /**
     * The pure stamp decode (unit-testable — no android.util dependency). DNS Stamp v2 layout
     * (DNSCrypt, proto `0x01`): `0x01 | props u64 LE (8 bytes) | LP(addr) | LP(pk) | LP(provider)`.
     * `bin[1]` is the LOW byte of the little-endian props — bit0 DNSSEC / bit1 no-log / bit2
     * no-filter (the DnsServerItem.java:66-85 read, unchanged). The `addr` field is the resolver's
     * `ip[:port]` (port optional → the spec default 443) — decoded so [RotationPing] can dial the
     * candidate over the SAME TCP-connect seam the app's ping cards use (the D30 warm-RTT feed).
     * A non-DNSCrypt proto (DoH 0x02, relays 0x81/0x85…) still yields a candidate with
     * `dnsCrypt=false` — [RotationSelector.filterTrusted]'s `requireDnsCrypt` gate drops it.
     * RTT is left 0/reachable: the pick is "completely random" (no RTT ranking, the Socio's spec);
     * the RTT measurement happens AFTER the pick, on the committed set only.
     */
    fun decodeStampBytes(name: String, sdns: String, bin: ByteArray): StampedCandidate? {
        if (bin.size < 2) return null
        val proto = bin[0].toInt() and BYTE_MASK
        val props = bin[1].toInt()
        // The address FAMILY, decoded host-side EXACTLY as the manual picker decodes it
        // (torta_core::stamp_addr_family): a V4 literal → (true,false), a V6 literal → (false,true),
        // an UNKNOWN family (hostname/ODoH-0x05/undecodable) → (true,true) fail-open. This is the
        // signal RotationSelector.filterTrusted's family gate reads so ROTATION honours the SAME
        // IPv4/IPv6 filter as build_server_rows (the LOCKED SPEC: one filter set, both paths).
        val fam = stampFamily(proto, bin)
        return StampedCandidate(
            candidate = RotationSelector.ResolverCandidate(
                id = name,
                operatorFamily = name.substringBefore('-').substringBefore('.').lowercase(),
                dnssec = (props and 1) == 1,
                noLog = ((props shr 1) and 1) == 1,
                noFilter = ((props shr 2) and 1) == 1,
                dnsCrypt = proto == PROTO_DNSCRYPT,
                rttMs = 0, // completely random pick — no RTT ranking at selection time
                reachable = true,
                ipv4 = fam.first,
                ipv6 = fam.second,
            ),
            sdns = sdns,
            address = if (proto == PROTO_DNSCRYPT) decodeDnscryptAddr(bin) else "",
        )
    }

    /**
     * The user's rotation/pool trust policy from the LIVE DNSCrypt criteria prefs (the
     * Academic-Wall: never hard-coded — the user owns require_*). ONE implementation for both the
     * rotation pick and the MODE-2 derivation, so the pool the resolver answers with can never be
     * filtered differently than the pool rotation lands. requireDnsCrypt is ON (the Rust DNSCrypt
     * transport consumes 0x01 stamps); operator-diversity is OFF for a "completely random" SET
     * pick (the set is diverse by being many random servers). Crash-safe: a pref-read fault
     * degrades to the permissive defaults (require nothing the user did not ask for).
     */
    fun policyFromPrefs(prefs: SharedPreferences): RotationSelector.RotationPolicy = try {
        RotationSelector.RotationPolicy(
            requireNoLog = prefs.getBoolean(REQUIRE_NOLOG_PREF, false),
            preferDnssec = true,
            requireDnssec = prefs.getBoolean(REQUIRE_DNSSEC_PREF, false),
            allowDnsCrypt = true,
            allowDoh = false,
            enforceDiversity = false,
        )
    } catch (e: Exception) {
        loge("RotationPoolSource policyFromPrefs — permissive defaults", e)
        RotationSelector.RotationPolicy(
            requireNoLog = false,
            preferDnssec = true,
            requireDnssec = false,
            allowDnsCrypt = true,
            allowDoh = false,
            enforceDiversity = false,
        )
    }

    /**
     * The require-filter policy driven by the TYPED config (the SLINT DNSCrypt-section toggles →
     * `DnscryptProxyConfig.require_*`), NOT the legacy Android prefs. This is the require→pool wiring:
     * the SLINT `Require DNSSEC / no-log / no-filter` toggles write the typed config (→ the toml), and
     * `ResolverRuntime.deriveConfiguredUpstreams(Typed)` builds THIS policy so the armed requirements
     * actually filter the LIVE pool (previously [policyFromPrefs] read a pref the SLINT never set). Now
     * carries `requireNoFilter` too (the props bit2), PLUS the `ipv4Servers`/`ipv6Servers` family gate
     * (`DnscryptProxyConfig.ipv4_servers`/`ipv6_servers` → the SLINT SERVER-TYPES toggle) so ROTATION
     * honours the SAME family filter as the manual picker. Never throws — a caller passes plain bools.
     */
    fun policyFromConfig(
        requireNolog: Boolean,
        requireDnssec: Boolean,
        requireNofilter: Boolean,
        ipv4Servers: Boolean = true,
        ipv6Servers: Boolean = true,
        // #22 s5A-ext (Socio: "the Rotation engine must also include as filters, wich protocol!") —
        // the PROTOCOL gate driven by the SAME typed-config bits the SLINT SERVER-TYPES chips edit
        // (cfg.dnscrypt_servers / cfg.doh_servers). Defaults = the pre-s5A dnscrypt-only posture so
        // legacy callers keep their exact behavior.
        dnscryptServers: Boolean = true,
        dohServers: Boolean = false,
    ): RotationSelector.RotationPolicy =
        RotationSelector.RotationPolicy(
            requireNoLog = requireNolog,
            preferDnssec = true,
            requireDnssec = requireDnssec,
            allowDnsCrypt = dnscryptServers,
            allowDoh = dohServers,
            enforceDiversity = false,
            requireNoFilter = requireNofilter,
            allowIpv4 = ipv4Servers,
            allowIpv6 = ipv6Servers,
        )

    /**
     * The ODoH twin of [policyFromConfig] — identical require_* gates but with `requireDnsCrypt = OFF`.
     * ODoH targets are 0x05 (not DNSCrypt 0x01) stamps, so [decodeStampBytes] flags them `dnsCrypt=false`;
     * [policyFromConfig]'s `requireDnsCrypt=true` gate would drop EVERY ODoH candidate. The privacy
     * criteria (no-log / DNSSEC / no-filter, read from the SAME props word) still apply — an ODoH resolver
     * that fails the user's require_* is filtered exactly like a DNSCrypt one. Used only for the oblivious
     * lane derived from `odoh-servers.md`. Carries the `ipv4Servers`/`ipv6Servers` family gate too (for a
     * one-shaped policy across lanes); ODoH 0x05 targets are hostnames ⇒ Unknown ⇒ fail-open, so in
     * practice the family gate never hides an oblivious target — but the wiring stays uniform.
     */
    fun policyFromConfigOdoh(
        requireNolog: Boolean,
        requireDnssec: Boolean,
        requireNofilter: Boolean,
        ipv4Servers: Boolean = true,
        ipv6Servers: Boolean = true,
    ): RotationSelector.RotationPolicy =
        RotationSelector.RotationPolicy(
            requireNoLog = requireNolog,
            preferDnssec = true,
            requireDnssec = requireDnssec,
            // was requireDnsCrypt=false = "any protocol eligible" — the s5A-ext gate pair keeps that
            // exact fail-open posture for the ODoH lane (its 0x05 targets decode dnsCrypt=false).
            allowDnsCrypt = true,
            allowDoh = true,
            enforceDiversity = false,
            requireNoFilter = requireNofilter,
            allowIpv4 = ipv4Servers,
            allowIpv6 = ipv6Servers,
        )

    /**
     * Pull the `ip[:port]` out of a DNSCrypt (0x01) stamp's LP(addr) field — bytes
     * `[9] = len, [10..10+len) = addr` — with the spec's `:443` default when the port is omitted
     * (IPv6 `[…]` aware, the [pillar.kuma_saimono.libumdnscrypt.utils.parsers.DnsCryptSDNSParser]
     * port shape). Returns "" on any malformed layout (the candidate is simply never pinged).
     */
    internal fun decodeDnscryptAddr(bin: ByteArray): String {
        val lenPos = 1 + PROPS_LEN
        val len = if (bin.size > lenPos) bin[lenPos].toInt() and BYTE_MASK else 0
        val from = lenPos + 1
        val address =
            if (len == 0 || from + len > bin.size) {
                ""
            } else {
                try {
                    String(bin, from, len, Charsets.UTF_8).takeIf { isCleanToken(it) }.orEmpty()
                } catch (e: Exception) {
                    ""
                }
            }
        if (address.isEmpty()) return ""
        val isV6 = address.contains("[") && address.contains("]")
        return when {
            isV6 && !address.matches(Regex(".+:\\d{1,5}$")) -> "$address:443"
            !isV6 && !address.contains(":") -> "$address:443"
            else -> address
        }
    }

    /**
     * The stamp's address FAMILY — the Kotlin port of `torta_core::stamp_addr_family` (the manual
     * picker's decoder), so the ROTATION pool classifies IPv4/IPv6 IDENTICALLY to `build_server_rows`.
     * Returns `(ipv4, ipv6)`: a V4 literal → `(true, false)`, a V6 literal → `(false, true)`, and an
     * UNKNOWN family (a hostname target, an ODoH 0x05 stamp, an empty/undecodable addr, or a relay's
     * addr) → `(true, true)` — fail-open, NEVER family-hidden (the SAME rule the manual gate applies).
     * The LP(addr) field sits at proto-relative offset 1 for a bare relay stamp (0x81 — no props word)
     * and `1 + PROPS_LEN` for a props-bearing server stamp (0x01/0x02/0x05, the only protos
     * [decodeStampBytes] feeds here). Pure + android-free (JUnit-on-metal); never throws.
     */
    internal fun stampFamily(proto: Int, bin: ByteArray): Pair<Boolean, Boolean> {
        val lenPos = if (proto == PROTO_RELAY) 1 else 1 + PROPS_LEN
        val len = if (bin.size > lenPos) bin[lenPos].toInt() and BYTE_MASK else 0
        val from = lenPos + 1
        if (len == 0 || from + len > bin.size) return true to true // no/short addr → Unknown, fail-open
        val addr = try {
            String(bin, from, len, Charsets.UTF_8)
        } catch (e: Exception) {
            return true to true
        }
        return familyOfAddr(addr)
    }

    /**
     * Classify a decoded stamp addr into `(ipv4, ipv6)`, mirroring `torta_core::family_of_addr`. A
     * bracketed `[…]` host or a bare token with ≥2 colons is an IPv6 literal → `(false, true)`; a host
     * of four dot-separated decimal octets (each 0-255) is an IPv4 literal → `(true, false)`; everything
     * else (a hostname, an empty/port-only, an unparsable token) is UNKNOWN → `(true, true)`, fail-open.
     * String heuristics only (no `InetAddress` — keeps the unit hermetic; a stamp addr is a single
     * printable token by the time it reaches here).
     */
    internal fun familyOfAddr(addr: String): Pair<Boolean, Boolean> {
        val a = addr.trim()
        if (a.isEmpty()) return true to true                       // Unknown → fail-open
        if (a.startsWith("[")) return false to true                // [::1] / [2001:db8::1]:443 → IPv6
        if (a.count { it == ':' } >= 2) return false to true       // bare v6 (a v4 host:port has ONE ':')
        val host = a.substringBefore(':')                          // strip an optional :port
        val octets = host.split('.')
        val isV4 = octets.size == 4 && octets.all { o ->
            o.isNotEmpty() && o.length <= 3 && o.all { it in '0'..'9' } && o.toInt() in 0..255
        }
        return if (isV4) true to false else true to true          // v4 literal, else hostname → Unknown
    }

    /**
     * A defensive token gate for values embedded downstream (JSON spec fragments / TOML route
     * lines): a real server/relay name, stamp, or address is a single printable token — anything
     * carrying quotes, backslashes, or control characters is malformed input and is SKIPPED
     * (fail-safe: one bad entry never poisons the pool).
     */
    private fun isCleanToken(s: String): Boolean =
        s.isNotEmpty() && s.none { it == '"' || it == '\'' || it == '\\' || it.code < CTRL_BOUND }

    /** DNS Stamp proto byte for a DNSCrypt v2 resolver (`sdns://AQ…`). */
    private const val PROTO_DNSCRYPT = 0x01

    /** DNS Stamp proto byte for an anonymized-DNSCrypt relay (`0x81`) — no props word, so [stampFamily]
     * reads its LP(addr) at offset 1 (vs `1 + PROPS_LEN` for a props-bearing server stamp). */
    private const val PROTO_RELAY = 0x81

    /** The DNS Stamp props field width — a u64 little-endian (low byte carries bits 0-2). */
    private const val PROPS_LEN = 8

    /** Unsigned-byte mask (Kotlin `Byte` is signed; stamp fields are unsigned octets). */
    private const val BYTE_MASK = 0xFF

    /** First non-control codepoint — anything below is a control char, never a valid token byte. */
    private const val CTRL_BOUND = 0x20

    /** The require-no-log criteria pref (the SAME key the DNSCrypt servers screen writes). */
    const val REQUIRE_NOLOG_PREF = "require_nolog"

    /** The require-DNSSEC criteria pref (the SAME key the DNSCrypt servers screen writes). */
    const val REQUIRE_DNSSEC_PREF = "require_dnssec"
}
