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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.settings

import android.content.Context
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.dns_engine.EnginePreset
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys

/**
 * 🍰 Higher-level "one-tap setup" bundles for the CAKE · YeAH engine (Pillar 13 §B).
 *
 * **This is THE live canonical preset source-of-truth.** [PresetApplier.applyPreset] is the single
 * write-path every caller delegates to (PresetFirstRun seed + the one-root settings picker), so the
 * per-tier design intent narrated here is authoritative. (A historical `PresetBundles` object once
 * carried the same intent but was measured-dead/unwired — superseded by this canonical plus the
 * http3 start-patch default — and has since been retired.)
 *
 * A [TortaPreset] is a *meta*-preset: a single tap that writes SEVERAL existing pref keys together,
 * so a non-geek lands on a sensible whole-engine posture without ever opening Expert mode. It is a
 * **starting point, not a lock** — every key a bundle sets stays individually toggleable afterwards
 * (USER-FREEDOM), and choosing [TortaPreset.CUSTOM] writes nothing (it simply unlocks manual tuning).
 *
 * **Why a goal isn't a fifth [EnginePreset]:** a base [EnginePreset] (default|ping|bandwidth|
 * upload_download) bundles ONLY the four YeAH knobs (cycle/window/free/compete) read by the engine.
 * It cannot, by itself, express *privacy* — rotation and the self-heal Solver are ORTHOGONAL keys,
 * each consumed by its own subsystem. So a friendly goal like "Privacy" or "Gaming" is a BUNDLE of
 * several existing pref keys written together, not a fifth engine flavour.
 *
 * **Socio law: privacy is the default.** The out-of-box pick is [TortaPreset.PRIVACY] (always-rotate),
 * with DoH3 (encrypted/QUIC) and `ignore_system_dns` (no bootstrap leak to system DNS) as universal
 * privacy defaults applied at dnscrypt start (the http3/ignore-system-dns start-patches), not via a
 * bundle. Encrypted + no-log + DNSSEC are inherent to DNSCrypt — no key to set.
 *
 * **The everything-ON contract (Socio default-ON, 2026-06-20):** the pillar SET is CONSTANT across
 * every preset — all core pillars are armed (native resolver #85, rotation, governors #91, self-heal
 * Solver). Presets differ ONLY in DATA (the four YeAH/CAKE engine dials), never in which pillars exist.
 * The Solver self-healer is an *enhancer* (a noob superpower — always ON across every tier, never a
 * cost). Rotation is privacy-*enhancing* and is now ON for every preset too (no single resolver sees
 * all queries); Gaming expresses its low-latency character through its FAST_PING dials, not by dropping
 * the rotation pillar.
 *
 * DATAPATH-SAFE by construction: this writes pref **values** only — the same default
 * SharedPreferences that [pillar.kuma_saimono.libumdnscrypt.dns_engine.MonokumaDnsEngineManager] (the
 * engine preset, read at start) and the resolver [RotationManager]/[Solver] master-gates already
 * read **when their subsystem arms**. Writing a value here changes nothing live; the engine and the
 * rotation/solver subsystems act on the next (re)start — the same shape as the existing card picker
 * [EngineSettingsFragment.bindPresets]. No datapath/leak/arm change is performed.
 *
 * The bundle deliberately touches ONLY value-only, reversible keys:
 *  - [TortaeKeys.DNS_ENGINE_PRESET]      — the YeAH/CAKE base bundle (default|ping), value-only,
 *                                              read by readEngineConfig on engine start (Expert OFF path).
 *  - [TortaeKeys.DNS_ENGINE_CADENCE_MS] / [TortaeKeys.DNS_ENGINE_MAX_WINDOW] /
 *    [TortaeKeys.DNS_ENGINE_FREE_THRESH] / [TortaeKeys.DNS_ENGINE_COMPETE_THRESH]
 *                                              — the 4 raw engine dials, seeded FROM the chosen preset
 *                                              (thresholds ×1000) so the Expert-ON read (which ignores
 *                                              the base preset) still gets the preset's engine half.
 *  - [TortaeKeys.RESOLVER_ROTATION_ENABLED] — privacy-enhancing always-rotate master (constant
 *                                              pillar, ON for every preset; no-op when its subsystem is unarmed).
 *  - [TortaeKeys.RESOLVER_NATIVE_ENABLED] — the #85 Stage-1 native-resolver keystone (constant
 *                                              pillar, ON for every preset). Value-only + fail-safe
 *                                              (r≤0 → unchanged sendto) + encrypted-only; the
 *                                              ModulesStateLoop release-arm guard governs the live arm,
 *                                              so writing the value is inert/fail-safe, not a datapath arm.
 *  - [TortaeKeys.DNS_ENGINE_GOVERN]      — the #91 per-upstream governors (constant pillar, ON for
 *                                              every preset). Shadow/observability only until Stage-C
 *                                              (zero live risk), value-only.
 *  - [TortaeKeys.DNS_ENGINE_SOLVER]      — the noob "auto-heal" enhancer (always ON across tiers).
 *  - [TortaeKeys.CENTAURI_MIRROR_ENABLED] — the Centauri self-filling loopback CDN serve-loop (constant
 *                                              pillar, ON for every preset; Socio default-ON 2026-06-20).
 *                                              Value-only + loopback-only (127.0.0.1, no egress) +
 *                                              self-heal-not-block + inert on a base `.so` (no `mirror`
 *                                              feature) ⇒ never breaks a page, never throws; reversible.
 *                                              (The Centauri REMOTE channel stays OPT-IN — not written.)
 *  - [TortaeKeys.WARDEN_NATIVE_ENABLED]  — the native firewall-verdict seam (constant pillar, ON for
 *                                              every preset; Socio default-ON 2026-06-24). Value-only +
 *                                              arming-never-enforces (Rust global None ⇒ ABSTAIN until a
 *                                              pinned-key-signed policy is bundled) + additive-block-only ⇒
 *                                              never spurious-blocks; reversible via its switch.
 *
 * It does NOT write [TortaeKeys.DNS_ENGINE_EXPERT] (the geek-master) — that is out of a friendly
 * one-tap bundle's scope and is reversible per-key by the user. (Previously the bundle also withheld
 * RESOLVER_NATIVE_ENABLED and DNS_ENGINE_GOVERN; the Socio default-ON contract 2026-06-20 makes those
 * constant pillars written here — fail-safe, since the #85 release-arm guard governs any live arm.)
 * ⚠️ Expert ON makes readEngineConfig IGNORE the base preset and read the 4 raw dials instead;
 * the bundle therefore leaves the Expert toggle itself as-is but ALSO seeds those 4 dials from the
 * preset, so an Expert-ON user no longer silently loses the engine half (the dials stay individually
 * re-tunable afterwards — preset = starting point, not a lock).
 * [TortaeKeys.DNS_ENGINE_ENABLED] is left untouched (the master is assumed/kept ON).
 */
enum class TortaPreset(val id: String) {

    /**
     * 🔒 PRIVACY (the out-of-box DEFAULT ⭐ — Socio law: privacy is the default). The everything-ON
     * baseline: all core pillars armed (native resolver #85, always-rotate, governors #91, self-heal),
     * so no single resolver sees a long-lived view of your queries; DoH3 (encrypted/QUIC) preferred and
     * `ignore_system_dns` ON (no bootstrap leak) as universal start-time defaults. Base engine stays
     * Balanced ([EnginePreset.DEFAULT]) — low latency without starving throughput. Encrypted + no-log +
     * DNSSEC are inherent to DNSCrypt (no key to set).
     */
    PRIVACY("privacy"),

    /**
     * 🎮 GAMING (one-tap chip): lowest-ping DATA flavor ([EnginePreset.FAST_PING], small window/fast
     * cadence → lowest ping). Same constant pillar SET as every preset (native resolver, rotation,
     * governors, self-heal all ON) — Gaming differentiates ONLY through its low-latency engine dials,
     * not by dropping a pillar. This is the historical out-of-box default, demoted to a chip in #88.
     */
    GAMING("gaming"),

    /**
     * ⚖️ BALANCED (the middle path): the as-built base beast ([EnginePreset.DEFAULT]) DATA flavor, with
     * the same constant all-ON pillar SET as every preset (native resolver, rotation, governors,
     * self-heal). The neutral DATA pick — identical pillars to Privacy, balanced engine dials.
     */
    BALANCED("balanced"),

    /**
     * 🤓 CUSTOM: no bundle is written. Picking this UNLOCKS manual tuning — every individual switch and
     * the raw Expert dials stay exactly as the user left them (reversible, no overwrite).
     */
    CUSTOM("custom");

    companion object {

        /** The tier an untouched install lands on — Privacy-first (always-rotate). */
        val DEFAULT_TORTA_PRESET = PRIVACY

        /** Safe lookup: an unknown/null id falls back to the Privacy default. */
        fun fromId(id: String?): TortaPreset =
            entries.firstOrNull { it.id == id } ?: DEFAULT_TORTA_PRESET
    }
}

/**
 * Applies a higher-level [TortaPreset] bundle to the default SharedPreferences.
 *
 * Pure value-write, idempotent (re-applying the same tier yields the same prefs), reversible
 * ([TortaPreset.CUSTOM] writes nothing; any single key can be flipped back afterwards), and
 * datapath-safe (the engine/rotation/solver subsystems read these values only when they arm).
 */
object PresetApplier {

    /**
     * Write the [preset] bundle. Returns true if any pref value was written (false for
     * [TortaPreset.CUSTOM], which intentionally leaves everything as-is = the "unlock" tier).
     *
     * @param context any context; the default SharedPreferences are used (the same store the engine,
     *                rotation and solver read).
     */
    fun applyPreset(context: Context, preset: TortaPreset): Boolean {
        // CUSTOM = no writes: unlock manual tuning, never overwrite the user's individual choices.
        if (preset == TortaPreset.CUSTOM) {
            return false
        }

        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        val editor = prefs.edit()

        // The engine base bundle (YeAH/CAKE) is value-only, read by readEngineConfig on engine start.
        // Gaming → FAST_PING (low latency); Privacy/Balanced → the balanced DEFAULT beast.
        val enginePreset: EnginePreset = when (preset) {
            TortaPreset.GAMING -> EnginePreset.FAST_PING
            else -> EnginePreset.DEFAULT // PRIVACY, BALANCED
        }
        editor.putString(TortaeKeys.DNS_ENGINE_PRESET, enginePreset.key)

        // FIX 1 — close the Expert-ON silent-drop: readEngineConfig IGNORES DNS_ENGINE_PRESET when
        // DNS_ENGINE_EXPERT is ON, reading the 4 raw knob ints instead. So ALSO seed those 4 ints from
        // the chosen preset's [EngineConfig], so an Expert-ON user gets the preset's engine half (not
        // stale/default dials). Thresholds are stored ×1000 (the read divides by 1000.0). Every value is
        // already inside the read's clamp ranges for both reachable presets (DEFAULT / FAST_PING), so the
        // round-trip is lossless. Preset = starting point — the geek can re-tune these dials afterward.
        val cfg = enginePreset.config
        editor.putInt(TortaeKeys.DNS_ENGINE_CADENCE_MS, cfg.cycleMs.toInt())
        editor.putInt(TortaeKeys.DNS_ENGINE_MAX_WINDOW, cfg.maxWindow)
        editor.putInt(TortaeKeys.DNS_ENGINE_FREE_THRESH, Math.round(cfg.freeThresh * 1000).toInt())
        editor.putInt(TortaeKeys.DNS_ENGINE_COMPETE_THRESH, Math.round(cfg.competeThresh * 1000).toInt())

        // Privacy pillar — always-rotate is now a CONSTANT pillar across EVERY preset (the everything-ON
        // baseline; Socio default-ON contract 2026-06-20). The pillar SET is constant; presets differ in
        // DATA (the engine dials above), never in which pillars exist. Rotation is privacy-enhancing (no
        // single resolver sees all queries) and is a no-op master-gate when its subsystem is unarmed —
        // pure value, no live arm. Gaming differentiates via its FAST_PING dials, not by dropping rotation.
        editor.putBoolean(TortaeKeys.RESOLVER_ROTATION_ENABLED, true)

        // #85 native resolver — the Stage-1 keystone, now a CONSTANT pillar (default-ON across every
        // preset). Value-only + fail-safe (r≤0 → unchanged sendto) + encrypted-only (loopback-only do53,
        // ignore_system_dns stays true); the ModulesStateLoop release-arm guard
        // (BuildConfig.DEBUG || isNativeResolverArmed()) governs the actual arm, so writing the value is
        // inert/fail-safe, not a live datapath arm. Reversible via its own SwitchPreference.
        editor.putBoolean(TortaeKeys.RESOLVER_NATIVE_ENABLED, true)

        // SOVEREIGN DNSCRYPT REWIRE — the Rust DNSCrypt transport is the PRODUCTION DEFAULT (constant pillar,
        // ON for every preset; Socio sovereign-rewire vision 2026-06-25). When ON + DNSCrypt RUNNING the Rust
        // pool is built with the DNSCrypt v2 stamps (MODE 2); the Go binary stays spawned as the loopback
        // listener + the per-query automatic fallback (udp.c:497, r≤0 → unchanged sendto to Go). Value-only:
        // the pool is reconfigured on the next RUNNING edge (ResolverRuntime.onDnsCryptStarted), never
        // mid-flight, and the C bridge is fail-safe. Reversible via its Expert switch (force Go-only).
        editor.putBoolean(TortaeKeys.RESOLVER_USE_RUST_DNSCRYPT, true)

        // #91 per-upstream governors — a CONSTANT pillar (default-ON everywhere). Shadow/observability
        // only until Stage-C (zero live risk); value-only, reversible via its switch.
        editor.putBoolean(TortaeKeys.DNS_ENGINE_GOVERN, true)

        // The self-healer enhancer stays ON across every tier (its default is ON; we keep it explicit
        // so a bundle re-asserts the healthy posture without ever gating the datapath — Solver runs
        // shadow-only until GOVERN + Stage-C land).
        editor.putBoolean(TortaeKeys.DNS_ENGINE_SOLVER, true)

        // Centauri Local Mirror serve-loop — a CONSTANT pillar (default-ON everywhere; Socio default-ON
        // contract 2026-06-20). The self-filling content-addressed loopback CDN (127.0.0.1-only, NOT an
        // egress path). SAFE: SELF-HEAL-not-block fail-safe (missing-local ⇒ fetch-once+cache, never blocks
        // a page; the CDN sees ≤1 request ever) + inert on a base `.so` without the `mirror` cargo feature
        // (façade catches UnsatisfiedLinkError ⇒ "did not start", never a throw). Value-only, reversible via
        // its switch. The CentauriMirrorManager.shouldStartMirror gate is now default-ON too (the braces);
        // this write is the belt for a seeded fresh install. (The Centauri REMOTE channel stays OPT-IN —
        // network/trust trade-off — NOT written here.)
        editor.putBoolean(TortaeKeys.CENTAURI_MIRROR_ENABLED, true)

        // Warden native firewall-verdict seam — a CONSTANT pillar (default-ON everywhere; Socio default-ON
        // contract 2026-06-24). SAFE: arming alone NEVER enforces — the Rust Warden global ships UNCONFIGURED
        // (None ⇒ ABSTAIN), so until a pinned-key-signed policy is bundled every verdict is ABSTAIN and the
        // datapath is byte-identical (no spurious block); the additive-block-only + last-known-good guards
        // stay. Value-only, reversible via its `pref_warden_native` switch. The runtime-tier rehydrate
        // + the ModulesStarterHelper JNI arm-pass are now default-ON too; this write is the belt for a seeded
        // fresh install.
        editor.putBoolean(TortaeKeys.WARDEN_NATIVE_ENABLED, false)

        // P12 Dnsmasq-hygiene pillars — CONSTANT (default-ON everywhere; Socio always-on contract). Closes the
        // Kotlin↔Rust DRIFT (audit R0, 2026-06-27): the toggles showed ON in the UI but the Rust AtomicBool
        // defaults were OFF, so the engine ran weakened until the bridge fired. Belt-for-seed + the Rust default
        // flip (resolver/mod.rs) together make them ON from boot. Value-only, reversible per-switch.
        editor.putBoolean(TortaeKeys.DNS_REBIND_PROTECTION, true)
        editor.putBoolean(TortaeKeys.DNSMASQ_BOGUS_PRIV, true)
        editor.putBoolean(TortaeKeys.DNSMASQ_PROXY_DNSSEC, true)
        editor.putBoolean(TortaeKeys.DNSMASQ_FILTER_RR, true)

        // G2 active-preset marker (Socio 2026-06-24): record the EXPLICITLY-tapped row id so the one-root
        // picker (PreferencesTortaFragment.reflectActivePreset) highlights the chosen row DIRECTLY instead of
        // inferring it from (enginePreset, rotation) — that inference collides now that rotation is a constant
        // pillar (every preset rotates) and PRIVACY/BALANCED share the DEFAULT engine key. UI-only marker, no
        // datapath. Written for the first-run seed too, so a fresh install honestly shows its starred Privacy
        // default selected. CUSTOM never reaches here (it early-returns above), so this is only ever a named id.
        editor.putString(TortaeKeys.DNS_ENGINE_PRESET_ACTIVE, preset.id)

        editor.apply()
        return true
    }

    /**
     * Convenience id-based applier for callers wiring a string id (e.g. a ListPreference / chip tag).
     * An unknown id falls back to the Privacy default per [TortaPreset.fromId].
     */
    fun applyPreset(context: Context, presetId: String?): Boolean =
        applyPreset(context, TortaPreset.fromId(presetId))
}
