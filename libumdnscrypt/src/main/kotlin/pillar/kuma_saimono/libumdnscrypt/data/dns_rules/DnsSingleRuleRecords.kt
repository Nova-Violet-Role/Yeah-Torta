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

package pillar.kuma_saimono.libumdnscrypt.data.dns_rules

/**
 * W5 #12 slice 2 (RAMxNAND Opt-2) — the frozen DurableTier record basenames for the five user-authored
 * DNSCrypt single-rule lists. ONE source of truth shared by the writer/reader seam
 * ([DnsRulesDataSourceImpl] persist on save / recover on read) and the engine-start durability sweep
 * ([pillar.kuma_saimono.libumdnscrypt.dns_engine.ResolverRuntime.syncDurableSingleLists]) so a rename can
 * never desync persist from recover. Bare names — the Rust DurableTier `sanitize_name`s them traversal-free.
 * These are the ONLY DNSCrypt rule files not re-derivable from a signed remote source, so their mirror is
 * the user's sole safety net across an `app_data` wipe. Frozen once shipped: changing a value orphans an
 * existing mirror.
 */
object DnsSingleRuleRecords {
    const val BLACKLIST = "dnscrypt-single-blacklist"
    const val WHITELIST = "dnscrypt-single-whitelist"
    const val IP_BLACKLIST = "dnscrypt-single-ipblacklist"
    const val FORWARDING = "dnscrypt-single-forwarding"
    const val CLOAKING = "dnscrypt-single-cloaking"
}
