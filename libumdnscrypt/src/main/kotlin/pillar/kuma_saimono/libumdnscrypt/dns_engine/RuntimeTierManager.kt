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

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import android.content.SharedPreferences
import android.util.Base64
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.vpn.service.WardenDatapathGate
import javax.inject.Inject
import javax.inject.Named

/**
 * THE WARDEN **W5 — the Kotlin boot-rehydrate of the shared RAM⊗NAND runtime tier.** ModulesService-scoped
 * owner of the W5 **boot-rehydrate** edge (the Android-lean port of the Sanctum-Mirror R:→D: write-through,
 * #100). Mirrors [CentauriMirrorManager]/[MonokumaDnsEngineManager]
 * exactly: `@ModulesServiceScope` + `@Inject` ctor auto-supplied by the ModulesService subcomponent, fired
 * when DNSCrypt goes RUNNING (or the engine runs standalone), idempotent `@Synchronized` start/stop so the
 * state-loop can call it on any transition edge without races. **Never hand-`new`** — the @Inject ctor is the
 * canonical template (ADR-001).
 *
 * **TWO PILLAR KINDS — this owner drives the (b) signed-source rehydrate + the (a) rotation boot-warm.** The
 * W5 tier serves two kinds of pillar (charter §"KEY design distinction"):
 *  - **(a) NEW-durable** (resolver rotation/RTT hints, Fortress attest cache, Beast/CAKE metrics): in-memory
 *    only today → a gentle atomic NAND write-through + boot-rehydrate over the shared `runtime_tier::DurableTier`
 *    facility (a self-owned record, NO pinned key, NO global native install). The P10 **resolver rotation**
 *    cursor (`"resolver-rotation"` record: last operator family + cadence + index + warm RTT hints) is warmed
 *    on the SAME boot edge here ([rehydrateTier] pillar 4) so its read is warm without a boot-IO scan on the
 *    engine thread — OBSERVABILITY only: the live diversity cursor is consumed by [RotationManager] (which owns
 *    the functional `@Volatile lastOperatorFamily` rehydrate + the persist-at-rotation-commit). The other (a)
 *    pillars (Fortress attest, metrics) rehydrate INSIDE their own Rust seam when their configure/arm path runs.
 *  - **(b) REHYDRATE-FROM-SIGNED-SOURCE** (blocklist ← `.tblk`, Centauri ← `.tcat`): the
 *    durable tier IS the signed artifact already on app-private flash, so "rehydrate" is the W4 verify-sig-FIRST
 *    re-verify+re-install of the SIGNED bytes on boot — NOT a raw NAND dump of the in-RAM trie/policy (that
 *    would be a SECOND, unsigned, drift-prone copy). THIS manager owns (b): on the DNSCrypt-start / boot edge
 *    it drives the two consolidated W5 exports ([TortaCore.rehydrateBlocklistFromSigned] /
 *    [TortaCore.rehydrateCentauriFromSigned]), each of which reads the
 *    on-flash signed pair, verifies it against the pinned key FIRST, and installs ONLY on a genuine signature.
 *
 * **The on-flash layout (Rust lib.rs:1310-1318).** The W5 durable dir is the app-private `filesDir`
 * ([RUNTIME_TIER_RELATIVE_DIR] under [PathVars.getAppDataDir], `allowBackup=false`). Each signed pillar lives
 * as a pair: `<dir>/<base>` (the RAW signed artifact bytes — EXACTLY what the offline brain signed) +
 * `<dir>/<base>.sig` (the base64-DECODED 74-byte minisign blob; the W5 BuildCapture executor stages both).
 * The pinned pubkey is the base64-DECODED 42-byte blob, passed as a swappable PARAMETER (no key baked into
 * Rust; production key swaps at #95). Until the BuildCapture executor stages the pairs, every export reads an
 * ABSENT pair and returns the cold-start no-op (count 0 / false) — additive + inert, byte-identical.
 *
 * **ANDROID-LEAN LAW (load-bearing — do NOT violate).** No RAMdisk (the "RAM tier" = the app heap / native /
 * mmap). The durable tier is the app-private `filesDir` on flash; the gentle atomic tmp+rename writes are the
 * Rust side's. Rehydrate runs EXPLICITLY here on the start/boot edge, off the caller thread on [dispatcherIo]
 * — NEVER on the hot DNS/connection/verdict path (no flash write-amplification, battery-frugal). Bounded
 * reads on the Rust side (hostile/oversized artifacts refused). No boot IO scan beyond the named pairs.
 *
 * **Governance — additive + inert, NO new switch (the W5 charter).** Re-installing a verified signed source
 * loses nothing and changes no behavior (a re-install of the same artifact is idempotent at the matcher), so
 * — unlike the OPT-IN attest/mirror — there is NO new Expert flag and NO UI switch: it is gated ONLY by the
 * master DNS-engine switch ([TortaeKeys.DNS_ENGINE_ENABLED], default on). The signed-source exports are
 * verify-sig-FIRST + fail-safe + panic-firewalled on the Rust side (a forged/absent/tampered source leaves
 * the in-memory tier UNCHANGED), and the Centauri export is `mirror`-feature-gated (inert on a base `.so`).
 * Even a Warden install's boot-rehydrate does NOT flip enforcement by itself — that is the separate
 * `WARDEN_NATIVE_ENABLED` enforce seam (default-ON, the Socio all-ON contract 2026-06-24, asserted at engine
 * start via `applyWardenNativeFromPref`); this boot-rehydrate only replays the durable policy, never arms. The pure, Android-free
 * [shouldRehydrate] gate makes "engine off ⇒ no rehydrate" unit-testable without a `Context`.
 *
 * **DOES NOT double-arm the live managers.** [CentauriArtifactManager] owns the LIVE
 * arm path (their own legacy on-disk layout + their own arm flags); this W5 manager reads the SEPARATE W5
 * durable layout ([RUNTIME_TIER_RELATIVE_DIR]) and is the lose-nothing boot replay — additive to, never a
 * replacement of, those managers. A signed source genuinely staged in BOTH places installs the same verified
 * bytes idempotently; an absent W5 pair (the default until BuildCapture stages it) is a silent no-op.
 *
 * **FAIL-SAFE throughout (GROUND_TRUTH).** A missing `.so`, a native fault, an absent/cold pair, a malformed
 * pin, or any throwable all degrade to "did not rehydrate" — the in-memory tier still works (the durable tier
 * is best-effort), DNS / firewall / arming never break. Crash-safe: every path is wrapped in `try/catch`;
 * nothing thrown ever reaches the state-loop caller. No root, no `@Provides`, no egress (all on-device,
 * app-private).
 */
@ModulesServiceScope
@ExperimentalCoroutinesApi
class RuntimeTierManager @Inject constructor(
    @Named(CoroutinesModule.DISPATCHER_IO)
    private val dispatcherIo: CoroutineDispatcher,
    private val pathVars: dagger.Lazy<PathVars>,
    @Named(DEFAULT_PREFERENCES_NAME)
    private val defaultPreferences: SharedPreferences,
) {
    private val coroutineScope by lazy {
        CoroutineScope(
            SupervisorJob() +
                    dispatcherIo +
                    CoroutineName("RuntimeTierManager") +
                    CoroutineExceptionHandler { _, t ->
                        loge("RuntimeTierManager uncaught exception", t)
                    }
        )
    }

    /**
     * `true` once the signed-source tier has been rehydrated this RUNNING edge. Doubles as the idempotency
     * guard: a repeated RUNNING edge with the tier already rehydrated is a no-op (we never re-replay NAND on
     * the same start — the in-memory tier is already warm). `@Volatile` because the rehydrate runs on
     * [dispatcherIo] while the state-loop drives start/stop from another thread.
     */
    @Volatile
    private var rehydrated: Boolean = false

    /**
     * DNSCrypt reached RUNNING (or the engine started standalone), or the device booted (the boot path runs
     * DNSCrypt, which lands here on the same RUNNING transition: `BootCompleteManager` → `runDNSCrypt` →
     * DNSCrypt RUNNING → `ModulesStateLoop`). If the master engine switch is on, boot-rehydrate the
     * signed-source tier from its app-private NAND pairs off the caller thread. Idempotent. With the engine
     * off this returns immediately; on a cold install (no staged pairs) the rehydrate is a silent no-op —
     * byte-identical to today.
     */
    @Synchronized
    fun start() {
        try {
            // GOVERNANCE GATE FIRST — the pure, Context-free check (master engine switch only; NO new flag).
            if (!shouldRehydrate(defaultPreferences)) {
                return
            }
            if (rehydrated) {
                // Already replayed the durable tier this RUNNING edge — re-rehydrating is a no-op.
                return
            }
            // Off the caller (state-loop) thread: the bounded NAND reads + the native verify/install belong on
            // IO, NEVER on the hot DNS/connection path (the Android-lean law).
            coroutineScope.launch { rehydrateTier() }
        } catch (e: Exception) {
            loge("RuntimeTierManager start", e)
        }
    }

    /**
     * DNSCrypt stopped (and the engine is not standalone). The durable NAND tier persists across the stop (the
     * signed artifacts stay on app-private flash); we simply clear the idempotency guard so a later RUNNING
     * edge / reboot re-rehydrates. Idempotent; never throws. The installed in-memory tier stays as-is (each
     * pillar owns its own lifecycle — additive-block-only preserved); this manager only drives the boot replay.
     */
    @Synchronized
    fun stop() {
        try {
            rehydrated = false
        } catch (e: Exception) {
            loge("RuntimeTierManager stop", e)
        }
    }

    /** DNSCrypt reached RUNNING (or the device booted into DNSCrypt-start): rehydrate the signed-source tier. */
    fun onDnsCryptStarted() = start()

    /**
     * DNSCrypt stopped. If the user runs the engine standalone, the resolver/blocklist/Warden tier stays
     * relevant, so keep it rehydrated (re-arm the guard for the next edge); otherwise clear the guard. Mirrors
     * the other managers' standalone-aware stop edge.
     */
    fun onDnsCryptStopped() {
        if (defaultPreferences.getBoolean(TortaeKeys.DNS_ENGINE_STANDALONE, false)) {
            start()
        } else {
            stop()
        }
    }

    /** True once the signed-source tier has been rehydrated this RUNNING edge. */
    fun isRunning(): Boolean = rehydrated

    /**
     * Boot-rehydrate the runtime tier, on [dispatcherIo]. Drives the SEVEN pillars over the app-private
     * durable dir (D03 closed the pillar-2 hole — the body was 1→3→4; D14 added pillar 5; D33a added
     * pillar 6; #18 added pillar 7):
     *  - 1) blocklist ← signed `.tblk` (verify-sig-FIRST, base `.so`),
     *  - 2) **Warden** matrix + universal toggles ← the (a) NEW-durable `warden-matrix` record via
     *    [WardenDatapathGate.bindDurable] (NO pubkey; rehydrates posture + drops lapsed TempAllows),
     *  - 3) Centauri catalog ← signed `.tcat` (verify-sig-FIRST, mirror-feature only),
     *  - 4) resolver rotation cursor ← the (a) NEW-durable `"resolver-rotation"` record (observability;
     *    the live cursor is consumed by [RotationManager]),
     *  - 5) DNSCrypt version-sync state ← the (a) NEW-durable `"dnscrypt-sync"` record (D14; the
     *    "layer is at version X with capabilities Y" coordinate the update worker persists),
     *  - 6) P12 local records ← the (a) NEW-durable `"resolver-local-records"` record (D33a; the
     *    user's hosts-text re-pinned into the live process-global store so a pinned name answers
     *    locally from the first query after boot),
     *  - 7) GithubTrust crown ← the (a) NEW-durable `"github-trust-crown"` record (#18 G6; the ONE
     *    process-global [TortaCore.trustCrownOpen] construction rehydrates every investigated source
     *    verdict so [TrustManager] scores from NAND instead of re-spending network/CPU).
     * Each pillar degrades to a silent no-op (count 0 / false / null) on an absent record (cold start), a
     * bad signature/corrupt record, a missing `.so`, or a native fault — never throwing, never leaving a
     * partial install. Even one pillar rehydrating is a win; an all-cold boot is byte-identical to today.
     */
    private fun rehydrateTier() {
        try {
            // App-private, durable runtime-tier root: /data/data/app.torta.yeah/app_data/runtime_tier — the
            // established no-Context app-private convention ([PathVars.getAppDataDir], the dnscrypt root). On
            // flash (`filesDir`); the W5 BuildCapture executor stages the signed <base>+<base>.sig pairs here;
            // allowBackup=false keeps it private. Until staged, every read is an absent-pair no-op.
            val durableDir = pathVars.get().appDataDir + RUNTIME_TIER_RELATIVE_DIR

            // The pinned 42-byte pubkey blobs (base64-DECODED), passed as swappable PARAMETERs — the SAME
            // single trust anchors the live channels pin (no fabricated key). Blocklist + Centauri pin to the
            // Centauri anchor (clean key separation, W4 charter §6). A
            // malformed/placeholder pin decodes to the wrong shape → the Rust verify fails closed (no install).
            val centauriPubkey = decodeBase64(CentauriArtifactManager.PINNED_MINISIGN_PUBKEY_BASE64)

            var any = false

            // 1) Blocklist ← signed `.tblk` (base `.so`). Returns the armed domain count (0 = cold/fail).
            if (centauriPubkey != null) {
                val count = TortaCore.rehydrateBlocklistFromSigned(
                    durableDir, BLOCKLIST_BASE, centauriPubkey, /* merge = */ false,
                )
                if (count > 0) {
                    any = true
                    logi("RuntimeTierManager — blocklist rehydrated from signed source ($count domains)")
                }
            }

            // 2) Warden matrix + universal toggles ← the app-private durable dir (RAM⊗NAND, D03 — the
            // pillar-2 slot the dossier flagged as MISSING: the body numbered 1→3→4). UNLIKE the (b)
            // signed-source pillars, this is a (a) NEW-durable pillar (NO pubkey, NO signature): the
            // Warden Object's own integrity-framed `warden-matrix` record via the shared
            // `runtime_tier::DurableTier`. `bindDurable(dir, now)` is driven on the SAME process-global
            // WardenObject instance the datapath queries ([WardenDatapathGate]) — it REPLACES the
            // in-memory matrix/toggles from the persisted blob AND drops any RULE19 TempAllow whose
            // wall-clock expiry lapsed while the device was OFF ([now]). Call ONCE at boot, off the hot
            // path; it also establishes the durable dir the per-pillar `query-warden.log` lands beside.
            // Additive + inert: binding rehydrates posture, it never ARMS a firewall (the datapath's
            // isAllowedByWarden runs only when the user's firewall switch is on). Cold (no persisted
            // record) ⇒ 0 rows, a silent no-op — byte-identical to today.
            val now = System.currentTimeMillis()
            val wardenRows = WardenDatapathGate.bindDurable(durableDir, now)
            // The RULE19 TempAllow control-plane sweep at the boot edge (bind's own rehydrate already
            // drops lapsed pauses via `now`; this is the explicit sweep the state loop's control plane
            // owns — never the verdict hot path, which holds no clock).
            WardenDatapathGate.expireTempAllows(now)
            if (wardenRows > 0) {
                any = true
                logi("RuntimeTierManager — Warden matrix rehydrated from durable source ($wardenRows rows)")
            }

            // 3) Centauri catalog ← signed `.tcat` (mirror-feature ONLY; inert on a base `.so`). Re-auth only.
            if (centauriPubkey != null) {
                val verified = TortaCore.rehydrateCentauriFromSigned(durableDir, CENTAURI_BASE, centauriPubkey)
                if (verified) {
                    any = true
                    logi("RuntimeTierManager — Centauri catalog re-authenticated from signed source")
                }
            }

            // 3b) #61C Underground antivirus lanes ← signed `underground_<lane>.tcat` pairs
            // (mirror-feature ONLY; honestly-empty lanes on a base `.so`). The SAME verify-sig-FIRST
            // minisign gate as pillar 3, merge-installed with per-lane provenance (each blocked name
            // remembers WHICH lane armed it). Absent / refused pair ⇒ that lane stays 0 and the
            // global matcher is untouched (fail-closed) — an empty log line is a true cold start,
            // never an error.
            if (centauriPubkey != null) {
                val laneCounts = TortaCore.undergroundLoadLanes(durableDir, centauriPubkey)
                if (laneCounts.any { it > 0uL }) {
                    any = true
                    logi(
                        "RuntimeTierManager — Underground lanes rehydrated from signed source " +
                            "(ads=${laneCounts[0]} trackers=${laneCounts[1]} " +
                            "malware=${laneCounts[2]} phishing=${laneCounts[3]})"
                    )
                }
            }

            // 4) Resolver rotation cursor ← the NEW-durable self-owned `"resolver-rotation"` record (P10).
            // UNLIKE the (b) signed-source pillars above, this is a (a) NEW-durable pillar: there is NO pinned
            // pubkey and NO global native install — the durable tier is the app's OWN tiny rotation record
            // (the shared `runtime_tier::DurableTier`, atomic + integrity-framed + bounded). This boot-edge
            // call WARMS that record off the hot path (alongside the signed-source pillars, same dispatcherIo,
            // same try/catch fail-safe) so the cursor read the live [RotationManager.start] makes is warm at
            // boot WITHOUT a boot-IO scan on the engine thread. The summary is OBSERVABILITY only — the live
            // diversity cursor (last_family + cadence + index) is consumed by [RotationManager], which owns the
            // functional rehydrate of its own `@Volatile lastOperatorFamily`. Cold (no record / absent / corrupt)
            // ⇒ null ⇒ a silent no-op, byte-identical to today. ADDITIVE + INERT: no pubkey, no datapath change,
            // no new perm; the persist that writes this record fires only on a committed rotation swap (dormant
            // until the live arm, Socio-reserved). Crash-proof: the façade never throws (cold ⇒ null sentinel).
            val rotationSummary = TortaCore.rehydrateResolverRotation(durableDir)
            if (rotationSummary != null) {
                any = true
                logi("RuntimeTierManager — resolver rotation cursor warmed from durable source ($rotationSummary)")
            }

            // 5) DNSCrypt version-sync state ← the (a) NEW-durable `dnscrypt-sync` record (D14 —
            // the pillar-5 slot the dossier flagged as never inserted). Same family as the rotation
            // cursor: NO pubkey, NO signature — the integrity-framed DurableTier record the update
            // worker's applyDnscryptSyncPlan writes. Warms the "the DNSCrypt layer is at version X
            // with capabilities Y" coordinate at boot (typed DnscryptSyncState Record — no summary
            // string parse) so update decisions can consult the persisted plan without a re-fetch.
            // Cold (never synced) ⇒ empty version / zero counts ⇒ a silent no-op, byte-identical to
            // today. Crash-proof: the façade never throws (unreachable `.so` ⇒ null sentinel).
            val syncState = TortaCore.rehydrateDnscryptSync(durableDir)
            if (syncState != null &&
                (syncState.applyCount > 0 || syncState.lastAppliedVersion.isNotEmpty())
            ) {
                any = true
                logi(
                    "RuntimeTierManager — DNSCrypt version-sync rehydrated (layer at " +
                        "${syncState.lastAppliedVersion}, ${syncState.appliedCapabilities.size} caps, " +
                        "${syncState.applyCount} applies)"
                )
            }

            // 6) P12 local records ← the (a) NEW-durable `resolver-local-records` record (D33a — the
            // dnsmasq `--address=`/`host-record`/`--addn-hosts` pins). Same family as pillars 4/5:
            // NO pubkey, NO signature — the integrity-framed DurableTier record the local-records
            // editor writes. The rehydrate RE-PINS the persisted hosts-text into the live
            // process-global store (`local.rs`), so a pinned name answers locally (step 1.5a, zero
            // egress) from the FIRST query after boot — without this, pins would exist on NAND but
            // the RAM store would sit empty until the next editor save. Cold (never edited) ⇒ an
            // all-zero report ⇒ a silent no-op, byte-identical to today. Crash-proof (null on an
            // unreachable `.so`).
            val localRecords = TortaCore.localRecordsRehydrate(durableDir)
            if (localRecords != null && localRecords.names > 0) {
                any = true
                logi(
                    "RuntimeTierManager — P12 local records rehydrated " +
                        "(${localRecords.names} names, ${localRecords.records} pins)"
                )
            }

            // 7) GithubTrustEngine crown ← the (a) NEW-durable `github-trust-crown` record (#18 G6 —
            // the per-source trust registry the B5 dossier flagged as never constructed). Same family
            // as pillars 4/5/6: NO pubkey, NO signature — the crown Object's own integrity-framed
            // DurableTier record. CONSTRUCTION IS THE REHYDRATE (github.rs `new` reads the record
            // before returning), so this one [TortaCore.trustCrownOpen] call both creates the ONE
            // process-global engine and warms every previously-investigated source verdict from NAND —
            // [TrustManager]'s scoring then serves from the RAM cache with zero network/CPU re-spend.
            // Cold (never investigated) ⇒ 0 cached sources, a silent no-op — byte-identical to today.
            // Control-plane only: the crown NEVER dials out from here (its network legs run solely on
            // the explicit investigation trigger) and never touches a datapath verdict.
            val crown = TortaCore.trustCrownOpen(durableDir)
            if (crown != null) {
                val cachedSources = try { crown.cachedCount().toInt() } catch (t: Throwable) { 0 }
                // #18 — query-github-trust.log goes LIVE: the crown pillar's boot-rehydrate readout
                // (counts only — no urls, no domains, T20).
                PillarLog.event(
                    pathVars.get().appDataDir, PillarLog.Pillar.GITHUB_TRUST, "rehydrate",
                    "cached_sources" to cachedSources,
                )
                if (cachedSources > 0) {
                    any = true
                    logi("RuntimeTierManager — GithubTrust crown rehydrated ($cachedSources scored sources)")
                }
            }

            rehydrated = true
            if (!any) {
                // All cold (no staged pairs yet) — additive + inert, byte-identical to today. Logged once so
                // the boot path is observable without implying a fault.
                logi("RuntimeTierManager — no signed source staged in $durableDir; runtime tier inert (cold start)")
            }
        } catch (e: Exception) {
            loge("RuntimeTierManager rehydrateTier — staying idle", e)
        }
    }

    /** Base64-decode the pinned pubkey, or null (fail-closed) on a malformed/placeholder value; never throws. */
    private fun decodeBase64(text: String): ByteArray? = try {
        Base64.decode(text, Base64.DEFAULT)
    } catch (t: Throwable) {
        null
    }

    companion object {
        /**
         * On-device path (relative to [PathVars.getAppDataDir]) of the app-private durable runtime-tier
         * directory — the W5 signed-source staging root, the SAME app-private family the Centauri cache +
         * dnscrypt config live in (`appDataDir + /app_data/...`). On flash (`filesDir`); the W5 BuildCapture
         * executor stages the `<base>` + `<base>.sig` pairs here. `allowBackup=false` keeps it private.
         * Context-free so it stays unit-testable.
         */
        const val RUNTIME_TIER_RELATIVE_DIR = "/app_data/runtime_tier"

        /** The W5 durable-source base filenames (each with a sibling `<base>.sig` decoded-minisign blob). */
        const val BLOCKLIST_BASE = "blocklist.tblk"
        const val CENTAURI_BASE = "catalog.tcat"

        /**
         * THE GOVERNANCE GATE, extracted pure so it is unit-testable without an Android `Context`. W5
         * boot-rehydrate is ADDITIVE + inert (it re-installs only verified signed sources and loses nothing),
         * so — unlike the OPT-IN attest/mirror — there is NO new Expert flag and NO UI switch (the W5
         * charter). It is gated ONLY by the master DNS-engine switch ([TortaeKeys.DNS_ENGINE_ENABLED],
         * default on): with the engine fully off, do nothing (honor user freedom); otherwise rehydrate. The
         * native exports are themselves verify-sig-FIRST + fail-safe (and the Centauri one is mirror-gated),
         * so even when this returns `true` an unsigned/absent/base-`.so` source is a safe no-op. This is the
         * property a default-path-unchanged guard test pins.
         */
        @JvmStatic
        fun shouldRehydrate(prefs: SharedPreferences): Boolean {
            // Engine intelligence off ⇒ do nothing (the only gate; no new flag, no UI switch).
            return prefs.getBoolean(TortaeKeys.DNS_ENGINE_ENABLED, true)
        }
    }
}
