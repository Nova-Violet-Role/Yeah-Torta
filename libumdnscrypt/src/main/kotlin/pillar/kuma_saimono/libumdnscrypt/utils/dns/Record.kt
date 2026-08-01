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

package pillar.kuma_saimono.libumdnscrypt.utils.dns

import java.util.Date
import java.util.Locale
import kotlin.math.max

class Record {

    @JvmField
    val value: String?

    @JvmField
    val type: Int

    @JvmField
    val ttl: Int

    @JvmField
    val timeStamp: Long

    /**
     * Record source, httpDns or System
     * [Source]
     */
    @JvmField
    val source: Int

    @JvmField
    val server: String?

    constructor(value: String?, type: Int, ttl: Int) {
        this.value = value
        this.type = type
        this.ttl = ttl
        this.timeStamp = Date().time / 1000
        this.source = Source.Unknown
        this.server = null
    }

    constructor(value: String?, type: Int, ttl: Int, timeStamp: Long, source: Int) {
        this.value = value
        this.type = type
        this.ttl = max(ttl, TTL_MIN_SECONDS)
        this.timeStamp = timeStamp
        this.source = source
        this.server = null
    }

    constructor(value: String?, type: Int, ttl: Int, timeStamp: Long, source: Int, server: String?) {
        this.value = value
        this.type = type
        this.ttl = max(ttl, TTL_MIN_SECONDS)
        this.timeStamp = timeStamp
        this.source = source
        this.server = server
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other !is Record) {
            return false
        }
        return value == other.value &&
                type == other.type &&
                ttl == other.ttl &&
                timeStamp == other.timeStamp
    }

    val isA: Boolean get() = type == TYPE_A

    val isAAAA: Boolean get() = type == TYPE_AAAA

    val isCname: Boolean get() = type == TYPE_CNAME

    val isPointer: Boolean get() = type == TYPE_PTR

    fun isExpired(): Boolean = isExpired(System.currentTimeMillis() / 1000)

    fun isExpired(time: Long): Boolean {
        if (ttl == TTL_Forever) {
            return false
        }
        return timeStamp + ttl < time
    }

    override fun toString(): String =
        String.format(
            Locale.getDefault(),
            "{type:%s, value:%s, source:%s, server:%s, timestamp:%d, ttl:%d}",
            type, value, source, server, timeStamp, ttl
        )

    object Source {
        const val Unknown = 0
        const val Custom = 1
        const val System = 3
        const val Udp = 4
        const val Doh = 5
    }

    companion object {
        const val TTL_MIN_SECONDS = 600
        const val TTL_Forever = -1

        const val TYPE_A = 1

        const val TYPE_AAAA = 28

        const val TYPE_CNAME = 5

        const val TYPE_PTR = 12

        const val TYPE_TXT = 16
    }
}
