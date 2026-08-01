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

package pillar.kuma_saimono.libumdnscrypt.education

/**
 * #90a — the In-app Education registry (the **ACCURACY LAW** content source).
 *
 * One enum constant per privacy/speed guard the app actually ships. Each carries four catalog **keys**
 * — a **title**, the always-visible noob **simple** line, the Expert-gated **geek** detail, and an
 * honest **status** badge. The copy itself lives in Rust ([`crate::ui_text::torta_text`]); a renderer
 * resolves each key via `uniffi.torta_core.tortaText(key)` — the `.xml`-free string trio, NEVER an
 * Android `strings.xml` resource. So [EducationNoteSheet] and the DashboardsHub chooser render the SAME
 * single source of truth (no scattered lookups, no drift, no resource ids).
 *
 * **GROUND_TRUTH (cite, never fabricate).** Every note describes what the code ACTUALLY does, verified
 * file:line against the live tree. **7 are LIVE; 2 are honest PARTIALS** flagged in `_status`/`_geek` —
 * never marketing-overclaimed:
 *  - [ARPA] — LIVE today = passive reverse-DNS rebind *exemption* only
 *    (`resolver/mod.rs:470-492` `is_private_or_local_name`). Proactive outbound PTR-block is NOT in
 *    code → flagged "Planned (#91)".
 *  - [CENTAURI] — opt-in, default OFF, verify+status only; the loopback bind/serve seam is DEFERRED
 *    (`CentauriMirrorManager.kt:44-48` "no native bind to call yet" + `lib.rs:730-732`) → "serve coming (#92)".
 *
 * Order is FIXED — it drives the hub chooser list order. [EducationNoteSheet.newInstance] passes the
 * enum constant [name] as the fragment argument; the receiver resolves it back via [valueOf].
 */
enum class EducationTopic(
    val titleKey: String,
    val simpleKey: String,
    val geekKey: String,
    val statusKey: String,
) {
    // 1 — LIVE: no system/ISP DNS leak at bootstrap (ModulesStarterHelper.java:354-384, default true → Quad9 9.9.9.9)
    IGNORE_SYSTEM_DNS(
        "edu_ignore_system_dns_title",
        "edu_ignore_system_dns_simple",
        "edu_ignore_system_dns_geek",
        "edu_ignore_system_dns_status",
    ),

    // 2 — LIVE: DoH over QUIC/HTTP-3, http3=true patched on start (ModulesStarterHelper.java:284-331 + resolver/doh3.rs RFC 9114)
    DOH3(
        "edu_doh3_title",
        "edu_doh3_simple",
        "edu_doh3_geek",
        "edu_doh3_status",
    ),

    // 3 — LIVE (default OFF): 12h trust-filtered RTT-ranked atomic pool swap, fail-safe (RotationManager.kt:32-82)
    ROTATION(
        "edu_rotation_title",
        "edu_rotation_simple",
        "edu_rotation_geek",
        "edu_rotation_status",
    ),

    // 4 — LIVE: public-name→private-IP rebind detect (resolver/rebind.rs); observe by default, enforce under Expert (resolver/mod.rs)
    REBIND(
        "edu_rebind_title",
        "edu_rebind_simple",
        "edu_rebind_geek",
        "edu_rebind_status",
    ),

    // 5 — PARTIAL: .in-addr.arpa/.ip6.arpa rebind-exemption ONLY (resolver/mod.rs:470-492); proactive PTR-block = #91
    ARPA(
        "edu_arpa_title",
        "edu_arpa_simple",
        "edu_arpa_geek",
        "edu_arpa_status",
    ),

    // 6 — PARTIAL: opt-in (default OFF) verify+status only; loopback serve seam DEFERRED (CentauriMirrorManager.kt:44-48) = #92
    CENTAURI(
        "edu_centauri_title",
        "edu_centauri_simple",
        "edu_centauri_geek",
        "edu_centauri_status",
    ),

    // 7 — LIVE: encrypted+authenticated DNS, require no-log/DNSSEC/no-filter matrix
    DNSCRYPT(
        "edu_dnscrypt_title",
        "edu_dnscrypt_simple",
        "edu_dnscrypt_geek",
        "edu_dnscrypt_status",
    ),

    // 8 — LIVE: reversed-label trie (blocklist.rs:7-18) → synthesized NXDOMAIN RCODE=3, no egress (dns.rs:128-144)
    BLOCKLIST(
        "edu_blocklist_title",
        "edu_blocklist_simple",
        "edu_blocklist_geek",
        "edu_blocklist_status",
    ),

    // 9 — LIVE (toggleable): CAKE·YeAH, runs alongside DNSCrypt
    BEAST(
        "edu_beast_title",
        "edu_beast_simple",
        "edu_beast_geek",
        "edu_beast_status",
    );
}
