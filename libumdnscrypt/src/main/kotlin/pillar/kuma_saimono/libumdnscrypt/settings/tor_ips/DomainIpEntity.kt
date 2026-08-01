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

package pillar.kuma_saimono.libumdnscrypt.settings.tor_ips

sealed class DomainIpEntity(
    open var isActive: Boolean
): Comparable<DomainIpEntity> {
    override fun compareTo(other: DomainIpEntity): Int {
        return when {
            this is DomainEntity && other is IpEntity -> -1
            this is IpEntity && other is DomainEntity -> 1
            this is DomainEntity && other is DomainEntity -> domain.compareTo(other.domain)
            this is IpEntity && other is IpEntity -> ip.compareTo(other.ip)
            else -> 0
        }
    }
}

data class DomainEntity(
    val domain: String,
    val ips: Set<String>,
    override var isActive: Boolean
): DomainIpEntity(isActive) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DomainEntity

        if (domain != other.domain) return false

        return true
    }

    override fun hashCode(): Int {
        return domain.hashCode()
    }
}

data class IpEntity(
    val ip: String,
    val domain: String,
    override var isActive: Boolean
): DomainIpEntity(isActive) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IpEntity

        if (ip != other.ip) return false

        return true
    }

    override fun hashCode(): Int {
        return ip.hashCode()
    }
}
