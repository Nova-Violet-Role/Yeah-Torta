/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import android.content.SharedPreferences
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys

/**
 * P8 **Wave C3 — the default-path-unchanged GUARD** (the `EnginePresetTest`-style guard the plan
 * references; none existed, so this wave CREATES it).
 *
 * The single load-bearing governance property: a **default (untouched) install never silently fetches or
 * installs a remote artifact**. The Centauri remote channel is OPT-IN — [CentauriArtifactManager.shouldFetchRemote]
 * is the gate the manager consults FIRST in `start()`, before any network or native call, so proving it
 * returns `false` on default prefs is proving the manager is INERT by default. With the gate inert, the
 * manual/DNSCrypt `compileFromFiles` path stays the byte-identical default: the device fingerprint with C3
 * present == the device fingerprint pre-C3.
 *
 * Pure JVM: the gate was deliberately extracted Context-free, so this exercises the REAL production code
 * path (not a re-implementation) against a tiny in-memory [SharedPreferences] fake — no Robolectric, no
 * Mockito, no Android runtime (the project's test framework is plain JUnit4).
 */
@OptIn(ExperimentalCoroutinesApi::class) // CentauriArtifactManager carries the engine-wide opt-in marker.
class CentauriArtifactManagerGovernanceTest {

    /**
     * THE GUARD. A default install (no preference ever set) must NOT trigger a remote fetch. This is the
     * "default install fingerprint == pre-C3" invariant in its causal root: no fetch ⇒ no remote install
     * ⇒ only the legacy manual/DNSCrypt path arms the matcher ⇒ identical fingerprint to pre-C3.
     */
    @Test
    fun `default install never fetches a remote artifact`() {
        val prefs = FakePrefs() // nothing set — exactly an untouched install
        assertFalse(
            "An untouched install MUST NOT fetch a remote Centauri artifact (opt-in default OFF)",
            CentauriArtifactManager.shouldFetchRemote(prefs)
        )
    }

    /** Explicit opt-in (Expert toggle ON) is the ONLY thing that enables the channel. */
    @Test
    fun `explicit opt-in enables the remote channel`() {
        val prefs = FakePrefs().apply {
            setBoolean(TortaeKeys.CENTAURI_REMOTE_ENABLED, true)
        }
        assertTrue(
            "With the Expert opt-in ON, the remote channel is enabled",
            CentauriArtifactManager.shouldFetchRemote(prefs)
        )
    }

    /**
     * The remote opt-in NEVER overrides the master blocklist switch: with the DNS engine intelligence
     * turned off, the channel stays inert even if the operator also opted in. (Defense in depth — a user
     * who disabled the engine entirely gets no surprise remote installs.)
     */
    @Test
    fun `master engine switch off keeps the channel inert even when opted in`() {
        val prefs = FakePrefs().apply {
            setBoolean(TortaeKeys.CENTAURI_REMOTE_ENABLED, true)
            setBoolean(TortaeKeys.DNS_ENGINE_ENABLED, false)
        }
        assertFalse(
            "Engine master switch OFF must keep the remote channel inert regardless of the opt-in",
            CentauriArtifactManager.shouldFetchRemote(prefs)
        )
    }

    /**
     * Explicitly setting the opt-in to `false` is the same as the default — no fetch. (Pins that the
     * default branch and the explicit-off branch agree, so a future default flip can't silently arm it.)
     */
    @Test
    fun `explicit opt-out matches the default - no fetch`() {
        val prefs = FakePrefs().apply {
            setBoolean(TortaeKeys.CENTAURI_REMOTE_ENABLED, false)
        }
        assertFalse(
            "An explicit opt-out behaves exactly like the untouched default",
            CentauriArtifactManager.shouldFetchRemote(prefs)
        )
    }

    /**
     * A minimal in-memory [SharedPreferences] — only the boolean surface [CentauriArtifactManager.shouldFetchRemote]
     * touches is implemented; everything else throws so an accidental dependency on un-faked behavior fails
     * loudly rather than silently passing. This keeps the test honest (it runs the production gate, not a copy).
     */
    private class FakePrefs : SharedPreferences {
        private val booleans = HashMap<String, Boolean>()

        fun setBoolean(key: String, value: Boolean) {
            booleans[key] = value
        }

        override fun getBoolean(key: String?, defValue: Boolean): Boolean =
            booleans[key] ?: defValue

        // --- Unused surface: fail loudly if the gate ever grows a dependency on these. ---
        override fun getAll(): MutableMap<String, *> = throw notImplemented()
        override fun getString(key: String?, defValue: String?): String? = throw notImplemented()
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
            throw notImplemented()
        override fun getInt(key: String?, defValue: Int): Int = throw notImplemented()
        override fun getLong(key: String?, defValue: Long): Long = throw notImplemented()
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
            UnsupportedOperationException("FakePrefs: only getBoolean is supported by the governance guard")
    }
}
