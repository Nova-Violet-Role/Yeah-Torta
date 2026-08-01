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

import kotlin.math.sqrt

/**
 * Welford's online variance — single-pass running mean + sample standard deviation (jitter).
 * Port of the C# MonokumaTcpDnsEngine UpdateWelfordJitter accumulators. Pure, allocation-free,
 * unit-testable, no Android dependency. Not thread-safe by itself; the engine guards calls.
 */
class WelfordAccumulator {
    var count: Long = 0L
        private set
    var mean: Double = 0.0
        private set
    private var m2: Double = 0.0

    fun add(value: Double) {
        count++
        val delta = value - mean
        mean += delta / count
        val delta2 = value - mean
        m2 += delta * delta2
    }

    /** Sample standard deviation (σ). Zero until at least 2 samples — matches the C# guard. */
    val stdDev: Double
        get() = if (count >= 2) sqrt(m2 / (count - 1)) else 0.0

    fun reset() {
        count = 0L
        mean = 0.0
        m2 = 0.0
    }
}
