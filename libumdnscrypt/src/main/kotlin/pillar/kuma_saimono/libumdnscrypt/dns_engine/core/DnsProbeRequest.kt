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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.core

/**
 * One DNS probe queued in a CAKE tin. [priority] picks the tin; [protocol] picks the path.
 *
 * [endpointIdx] + [domain] together key the 8-way set-associative flow buckets used by the COBALT
 * profile (per-upstream isolation + cross-domain HOL-block kill). [enqueuedAtMs] is the queue-entry
 * timestamp the COBALT profile measures CoDel sojourn against (sojourn = now − enqueuedAtMs); it
 * defaults to 0L so the LEGACY scheduler and every 2-arg test construction stay byte-identical.
 */
data class DnsProbeRequest(
    val domain: String,
    val priority: DnsProbePriority,
    val endpointIdx: Int = 0,
    val protocol: ProbeProtocol = ProbeProtocol.TCP,
    val enqueuedAtMs: Long = 0L
)

/** CAKE tins, highest first. ordinal is the tin index (0=Critical … 2=Normal). */
enum class DnsProbePriority { CRITICAL, HIGH, NORMAL }

enum class ProbeProtocol { TCP, UDP }
