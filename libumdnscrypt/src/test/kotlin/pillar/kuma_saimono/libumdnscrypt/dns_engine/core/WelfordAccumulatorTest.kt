/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

/*
    This file is part of Yeah! Tortä. GPL-3.0-or-later. Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.core

import org.junit.Assert.assertEquals
import org.junit.Test

class WelfordAccumulatorTest {

    @Test
    fun `stddev is zero below two samples`() {
        val w = WelfordAccumulator()
        assertEquals(0.0, w.stdDev, 0.0)
        w.add(5.0)
        assertEquals(0.0, w.stdDev, 0.0)
        assertEquals(5.0, w.mean, 1e-9)
    }

    @Test
    fun `mean and sample stddev match a known data set`() {
        val w = WelfordAccumulator()
        // {2,4,4,4,5,5,7,9}: mean 5, sum of squared deviations 32, sample variance 32/7
        listOf(2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0).forEach(w::add)
        assertEquals(8L, w.count)
        assertEquals(5.0, w.mean, 1e-9)
        assertEquals(2.138089935, w.stdDev, 1e-6) // sqrt(32/7)
    }

    @Test
    fun `reset clears state`() {
        val w = WelfordAccumulator()
        w.add(1.0); w.add(2.0)
        w.reset()
        assertEquals(0L, w.count)
        assertEquals(0.0, w.mean, 0.0)
        assertEquals(0.0, w.stdDev, 0.0)
    }
}
