/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys

/**
 * MONSTER §4/§7 prefs contract — DNS_ENGINE_GOVERN + QMAX_FRAC + RHO + the self-healing Solver toggle.
 * Plain JUnit4 against a tiny in-memory [SharedPreferences] fake (the
 * [RotationManagerGateTest]/[CentauriArtifactManagerGovernanceTest] precedent: exercise the REAL key
 * strings + the REAL default discipline, not a copy — no Robolectric, no Mockito).
 *
 * Two load-bearing properties:
 *  - **simple-UX default discipline** — GOVERN is an Expert master DEFAULT OFF (an untouched install never
 *    builds the per-upstream governor map = today's single-yeah 6-probe loop), while the Solver is the noob
 *    "auto-heal my connection" switch DEFAULT ON (a safe self-healer — anti-thrash makes default-ON safe,
 *    and with GOVERN OFF it runs SHADOW-only). This is the [feedback-simple-ux] law: one noob switch, the
 *    dials behind Expert.
 *  - **key-string stability** — the pref keys ARE the on-disk contract; a silent rename loses a user's saved
 *    value, so the literal strings are pinned (the same guarantee the existing keys carry implicitly).
 */
class DnsEngineGovernPrefsTest {

    // ── simple-UX default discipline (the exact getBoolean(KEY, default) a consumer reads). ──

    @Test
    fun `GOVERN is default OFF on an untouched install (no governor map = today)`() {
        assertFalse(
            "An untouched install MUST NOT enable per-upstream governors (GOVERN default OFF)",
            FakePrefs().getBoolean(TortaeKeys.DNS_ENGINE_GOVERN, false)
        )
    }

    @Test
    fun `explicit GOVERN opt-in is honoured`() {
        val prefs = FakePrefs().apply { setBoolean(TortaeKeys.DNS_ENGINE_GOVERN, true) }
        assertTrue(prefs.getBoolean(TortaeKeys.DNS_ENGINE_GOVERN, false))
    }

    @Test
    fun `the Solver auto-heal switch is default ON (safe self-healer)`() {
        // The noob master defaults ON: anti-thrash (hysteresis/dwell/cost-of-switch) makes a default-ON
        // self-healer safe, and with GOVERN OFF (the default) it runs SHADOW-only (no live commit).
        assertTrue(
            "The 'auto-heal my connection' Solver master is the safe default-ON noob switch",
            FakePrefs().getBoolean(TortaeKeys.DNS_ENGINE_SOLVER, true)
        )
    }

    @Test
    fun `the Solver can be turned off explicitly`() {
        val prefs = FakePrefs().apply { setBoolean(TortaeKeys.DNS_ENGINE_SOLVER, false) }
        assertFalse(prefs.getBoolean(TortaeKeys.DNS_ENGINE_SOLVER, true))
    }

    @Test
    fun `the noob default pair is GOVERN-off SOLVER-on (the shadow self-heal posture)`() {
        // The whole point of the default posture: the Solver self-heals (shadow), the heavy per-upstream
        // governor stays opt-in. An untouched install is exactly: GOVERN off, Solver on.
        val prefs = FakePrefs()
        assertFalse(prefs.getBoolean(TortaeKeys.DNS_ENGINE_GOVERN, false))
        assertTrue(prefs.getBoolean(TortaeKeys.DNS_ENGINE_SOLVER, true))
    }

    @Test
    fun `QMAX_FRAC and RHO fall back to their documented expert defaults when unset`() {
        // The expert dials are absent on an untouched install → the consumer's defaults stand.
        // QMAX_FRAC is the Q-cap fraction ×100 (50 = 0.50); RHO is the CoDel/COBALT window (default 16).
        val prefs = FakePrefs()
        assertEquals(50, prefs.getInt(TortaeKeys.DNS_ENGINE_QMAX_FRAC, 50))
        assertEquals(16, prefs.getInt(TortaeKeys.DNS_ENGINE_RHO, 16))
    }

    @Test
    fun `solver anti-thrash expert knobs fall back to their documented defaults when unset`() {
        val prefs = FakePrefs()
        assertEquals(700, prefs.getInt(TortaeKeys.DNS_ENGINE_SOLVER_TRIGGER_ENTER, 700)) // 0.70 ×1000 (I1)
        assertEquals(400, prefs.getInt(TortaeKeys.DNS_ENGINE_SOLVER_TRIGGER_EXIT, 400))  // 0.40 ×1000 (I1)
        assertEquals(3, prefs.getInt(TortaeKeys.DNS_ENGINE_SOLVER_CONFIRM_SAMPLES, 3))   // debounce (I5)
        assertEquals(150, prefs.getInt(TortaeKeys.DNS_ENGINE_SOLVER_SWITCH_MARGIN, 150)) // 1.15× (I3)
        assertEquals(5000L, prefs.getLong(TortaeKeys.DNS_ENGINE_SOLVER_DWELL_MS, 5000L)) // dwell (I2)
        assertEquals(30000L, prefs.getLong(TortaeKeys.DNS_ENGINE_SOLVER_COOLDOWN_MS, 30000L)) // cooldown (I4)
        assertEquals(900000L, prefs.getLong(TortaeKeys.DNS_ENGINE_SOLVER_CACHE_TTL_MS, 900000L)) // TTL (I6)
    }

    // ── key-string stability: the literal pref keys are the on-disk contract (a rename loses saved state). ──

    @Test
    fun `pref key strings are stable (a silent rename would lose a user's saved value)`() {
        assertEquals("pref_engine_govern", TortaeKeys.DNS_ENGINE_GOVERN)
        assertEquals("pref_engine_qmax_frac", TortaeKeys.DNS_ENGINE_QMAX_FRAC)
        assertEquals("pref_engine_rho", TortaeKeys.DNS_ENGINE_RHO)
        assertEquals("pref_engine_solver", TortaeKeys.DNS_ENGINE_SOLVER)
        assertEquals("pref_engine_solver_dwell_ms", TortaeKeys.DNS_ENGINE_SOLVER_DWELL_MS)
        assertEquals("pref_engine_solver_cooldown_ms", TortaeKeys.DNS_ENGINE_SOLVER_COOLDOWN_MS)
        assertEquals("pref_engine_solver_trigger_enter", TortaeKeys.DNS_ENGINE_SOLVER_TRIGGER_ENTER)
        assertEquals("pref_engine_solver_trigger_exit", TortaeKeys.DNS_ENGINE_SOLVER_TRIGGER_EXIT)
        assertEquals("pref_engine_solver_confirm_samples", TortaeKeys.DNS_ENGINE_SOLVER_CONFIRM_SAMPLES)
        assertEquals("pref_engine_solver_switch_margin", TortaeKeys.DNS_ENGINE_SOLVER_SWITCH_MARGIN)
        assertEquals("pref_engine_solver_cache_ttl_ms", TortaeKeys.DNS_ENGINE_SOLVER_CACHE_TTL_MS)
    }

    @Test
    fun `the new keys are distinct from each other and from the existing engine keys`() {
        val newKeys = listOf(
            TortaeKeys.DNS_ENGINE_GOVERN,
            TortaeKeys.DNS_ENGINE_QMAX_FRAC,
            TortaeKeys.DNS_ENGINE_RHO,
            TortaeKeys.DNS_ENGINE_SOLVER,
            TortaeKeys.DNS_ENGINE_SOLVER_DWELL_MS,
            TortaeKeys.DNS_ENGINE_SOLVER_COOLDOWN_MS,
            TortaeKeys.DNS_ENGINE_SOLVER_TRIGGER_ENTER,
            TortaeKeys.DNS_ENGINE_SOLVER_TRIGGER_EXIT,
            TortaeKeys.DNS_ENGINE_SOLVER_CONFIRM_SAMPLES,
            TortaeKeys.DNS_ENGINE_SOLVER_SWITCH_MARGIN,
            TortaeKeys.DNS_ENGINE_SOLVER_CACHE_TTL_MS,
        )
        assertEquals("new pref keys must be unique", newKeys.size, newKeys.toSet().size)
        // No collision with the existing engine keys (they share the pref_engine_ prefix).
        val existing = setOf(
            TortaeKeys.DNS_ENGINE_ENABLED, TortaeKeys.DNS_ENGINE_STANDALONE,
            TortaeKeys.DNS_ENGINE_EXPERT, TortaeKeys.DNS_ENGINE_PRESET,
            TortaeKeys.DNS_ENGINE_CADENCE_MS, TortaeKeys.DNS_ENGINE_MAX_WINDOW,
            TortaeKeys.DNS_ENGINE_FREE_THRESH, TortaeKeys.DNS_ENGINE_COMPETE_THRESH,
        )
        assertTrue("no new key collides with an existing engine key",
            newKeys.none { it in existing })
    }

    // ── Fake. ──

    /**
     * A minimal in-memory [SharedPreferences] supporting the boolean/int/long surface these defaults read;
     * everything else throws so an accidental dependency fails loudly rather than silently passing (the
     * [RotationManagerGateTest.FakePrefs] discipline).
     */
    private class FakePrefs : SharedPreferences {
        private val booleans = HashMap<String, Boolean>()
        private val ints = HashMap<String, Int>()
        private val longs = HashMap<String, Long>()

        fun setBoolean(key: String, value: Boolean) { booleans[key] = value }

        override fun getBoolean(key: String?, defValue: Boolean): Boolean = booleans[key] ?: defValue
        override fun getInt(key: String?, defValue: Int): Int = ints[key] ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = longs[key] ?: defValue

        // --- Unused surface: fail loudly if the contract ever grows a dependency on these. ---
        override fun getAll(): MutableMap<String, *> = throw notImplemented()
        override fun getString(key: String?, defValue: String?): String? = throw notImplemented()
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
            throw notImplemented()
        override fun getFloat(key: String?, defValue: Float): Float = throw notImplemented()
        override fun contains(key: String?): Boolean = throw notImplemented()
        override fun edit(): SharedPreferences.Editor = throw notImplemented()
        override fun registerOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?
        ) = throw notImplemented()
        override fun unregisterOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?
        ) = throw notImplemented()

        private fun notImplemented() =
            UnsupportedOperationException("FakePrefs: only boolean/int/long getters are supported")
    }
}
