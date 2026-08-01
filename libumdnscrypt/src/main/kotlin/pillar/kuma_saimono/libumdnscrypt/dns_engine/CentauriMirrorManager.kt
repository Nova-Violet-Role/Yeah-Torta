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
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.di.CoroutinesModule
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule.Companion.DEFAULT_PREFERENCES_NAME
import pillar.kuma_saimono.libumdnscrypt.di.modulesservice.ModulesServiceScope
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import java.io.File
import javax.inject.Inject
import javax.inject.Named

/**
 * **Centauri Local Mirror** — ModulesService-scoped owner of the OPT-IN in-app, content-addressed,
 * self-filling CDN loopback server (the Decentraleyes/LocalCDN-**evolved** local mirror: the Haskell brain
 * signs the catalog, the in-app loopback serves the hash-verified cache so the upstream CDN sees ≤1 request
 * ever). Mirrors [CentauriArtifactManager]/[TrustManager]/[MonokumaDnsEngineManager]/[ResolverRuntime]
 * exactly: `@ModulesServiceScope` + `@Inject` ctor auto-supplied by the ModulesService subcomponent, armed
 * when DNSCrypt goes RUNNING (or the engine runs standalone), idempotent `@Synchronized` start/stop. **Never
 * hand-`new`** — the @Inject ctor is the canonical template (ADR-001).
 *
 * **Native is GATED under the Rust `mirror` cargo feature (load-bearing).** Every mirror symbol lives only
 * in a `--features mirror` build — the BASE android `.so` is byte-identical and carries NO mirror symbols.
 * The [TortaCore] mirror façades catch the resulting UnsatisfiedLinkError and return the inert fallback
 * ("unavailable"), so on a base build this manager simply never binds — **inert, never an
 * UnsatisfiedLinkError taking down the app.** A mirror-feature build carries the symbols and the loopback
 * server binds when opted in.
 *
 * **The loopback bind/accept seam is LIVE (#92).** The Rust side ships the verify+status exports
 * (`nativeMirrorInstallCatalog`, `nativeMirrorStatus`) AND the #92 start export
 * (`nativeCentauriMirrorStart(cacheDir)`, `--features mirror` only) which builds the on-disk-backed cache,
 * spawns the hyper accept loop on a mirror-local runtime, and returns the bound 127.0.0.1 ephemeral port.
 * [startMirror] now calls it through the crash-proof [TortaCore.centauriMirrorStart] façade and sets
 * [boundPort] on success. On a BASE `.so` (no `mirror` feature) the symbol is absent → the façade returns
 * null → the manager stays inert. The manager is AVAILABLE/inert by default, only armed behind the opt-in.
 *
 * **Governance (load-bearing): OPT-IN and INERT BY DEFAULT.** An untouched install never opens the loopback
 * server — [start] returns immediately unless the Expert [TortaeKeys.CENTAURI_MIRROR_ENABLED] flag is
 * ON (default `false`). So the default install behaviour is byte-identical (no loopback, no listener): the
 * mirror is made AVAILABLE for the Design Finale + datapath to consume later, never forced on now. The
 * opt-in gate lives in the pure, Android-free [shouldStartMirror] so a unit test can prove "default ⇒ no
 * mirror" without a `Context`.
 *
 * The loopback bind is purely local (127.0.0.1, ephemeral port) — it serves the on-device verified cache;
 * it is not an egress path. Crash-proof throughout: a missing `.so`, a base build without the mirror
 * feature, or a native fault all degrade to "did not start" and never throw into the state-loop. No root,
 * no `@Provides`.
 */
@ModulesServiceScope
@ExperimentalCoroutinesApi
class CentauriMirrorManager @Inject constructor(
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
                    CoroutineName("CentauriMirrorManager") +
                    CoroutineExceptionHandler { _, t ->
                        loge("CentauriMirrorManager uncaught exception", t)
                    }
        )
    }

    /**
     * The loopback port the mirror bound to (>0), or null while not running. Doubles as the idempotency
     * guard: a repeated RUNNING edge with the mirror already bound is a no-op. `@Volatile` because the bind
     * runs on [dispatcherIo] while the state-loop drives start/stop from another thread.
     */
    @Volatile
    private var boundPort: Int? = null

    /**
     * THE CENTAURI OBJECT (D07 — the Object awakened): constructed ONCE per process at the first arming
     * edge, rooted at the app-private content-addressed cache dir. The Object's `start()` serves its LIVE
     * shared store (a `warmUp` fill is servable immediately) and SELF-FEEDS the serve review channel
     * (recent ring + CROWN counters + `query-centauri.log` — D29). Mirrored into the companion [heldObject]
     * so the root-graph dashboard card/fragment (which cannot reach this `@ModulesServiceScope` instance —
     * the documented cross-graph wall) read the SAME typed snapshot (the WardenDatapathGate `hold()`
     * precedent). `@Volatile`: built on [dispatcherIo], read from the UI.
     */
    @Volatile
    private var centauri: TortaCore.CentauriHandle? = null

    /**
     * DNSCrypt reached RUNNING (or the engine started standalone). If — and ONLY if — the operator opted
     * into the local mirror, start the loopback mirror server off the caller thread. Idempotent. By default
     * (flag OFF) this returns immediately and does nothing, so the live DNS flow is byte-identical (no
     * loopback listener). On a base `.so` (no mirror feature) the native start returns the inert sentinel
     * and the manager stays dormant.
     */
    @Synchronized
    fun start() {
        try {
            if (boundPort != null) return  // already bound — idempotent
            // GOVERNANCE GATE FIRST — the pure, Context-free opt-in check. Off ⇒ no mirror.
            if (!shouldStartMirror(defaultPreferences)) {
                return
            }
            // Off the caller (state-loop) thread: the bind + accept-loop belong on IO.
            coroutineScope.launch { startMirror() }
        } catch (e: Exception) {
            loge("CentauriMirrorManager start", e)
        }
    }

    /**
     * DNSCrypt stopped (and the engine is not standalone). DISARM the DNS-plane cloak FIRST (D05 — a
     * watched-CDN host must resolve normally the instant the pillar goes idle; the cloak never outlives
     * the serving mirror), then clear the idempotency guard so a later RUNNING edge re-binds + re-arms.
     * (The native accept-loop is owned by the parked runtime; clearing the port marks this manager idle
     * so a re-arm re-checks the opt-in.) Idempotent; never throws.
     */
    @Synchronized
    fun stop() {
        try {
            disarmCloak()
            boundPort = null
            lastBoundPort = null
        } catch (e: Exception) {
            loge("CentauriMirrorManager stop", e)
        }
    }

    /** DNSCrypt reached RUNNING: (re)start the mirror if opted in. */
    fun onDnsCryptStarted() = start()

    /**
     * DNSCrypt stopped. If the user runs the engine standalone, the local mirror stays relevant, so re-arm;
     * otherwise clear the guard. Mirrors the other managers' standalone-aware stop edge.
     */
    fun onDnsCryptStopped() {
        if (defaultPreferences.getBoolean(TortaeKeys.DNS_ENGINE_STANDALONE, false)) {
            start()
        } else {
            stop()
        }
    }

    /** True once the mirror has bound this RUNNING edge. */
    fun isRunning(): Boolean = boundPort != null

    /** The bound loopback port (for an in-app HTTP client), or null while not running. */
    fun port(): Int? = boundPort

    /**
     * Start the loopback mirror, on [dispatcherIo] — the FULL pillar arming chain (D04/D05/D07):
     *  1. **Seed** ([stageSeedCatalogFromAssets]): first boot copies a shipped `assets/centauri/catalog.tcat`
     *     (+ `.sig`) into the W5 durable dir if present — the assets→durable-dir seed channel. Absent asset
     *     ⇒ silent no-op (the channel is complete; the signed artifact is the offline brain's drop-in).
     *  2. **Construct** the Centauri OBJECT rooted at the app-private content-addressed cache dir
     *     (`appDataDir/app_data/centauri_cache`) — rehydrates the on-disk verified cache at construction.
     *  3. **Install** ([installStagedCatalog]): read the staged signed pair from the W5 durable dir
     *     (`runtime_tier/catalog.tcat` + `.sig` — the SAME channel shape the `.tblk` blocklist artifact
     *     rides) and verify-sig-FIRST install it into the Object (retained ⇒ the loopback SERVES it).
     *  3.25. **Sovereign rehydrate**: with no pinned catalog, rehydrate the DEVICE-authored pair
     *     (`centauri_cache/device-catalog.tcat` + `.sig` — born on-device by a prior boot's arming pass)
     *     against THIS install's OWN DeviceKey — the RAM⊗NAND fast boot, no re-stage, no re-hash.
     *  3.5. **Device arming** (First Boot / no pair): author + device-sign + install + PERSIST the pair.
     *  4. **Start** the loopback via the Object — serves the LIVE shared store, self-feeds the review
     *     channel (recent ring + CROWN counters + query-centauri.log — D29).
     *  5. **Warm up** (D04): a bounded TIER-B self-fill batch over the installed catalog (≤1 CDN request
     *     EVER per asset; zero-target no-op with no catalog).
     *  6. **Arm the cloak** (D05): ONLY when the mirror is serving AND the verified catalog authorizes
     *     assets, flip `resolverSetCentauriCloak(true)` — watched-CDN hosts then resolve to the loopback
     *     (the crown: the CDN sees ≤1 request). An EMPTY catalog NEVER cloaks (the F9 no-blackhole law) —
     *     the pillar stays honestly "dormant" until a genuine signed catalog lands.
     *
     * **Inert/off-graceful by every failure mode (GROUND_TRUTH):** a base `.so` (no `mirror` feature) fails
     * Object construction → the legacy flat [TortaCore.centauriMirrorStart] fallback runs (NO-BREAK); a
     * placeholder/unsigned staged pair fail-closes at the minisign gate (nothing installed, cloak stays
     * off); any throwable degrades to "did not start" — NEVER a crash into the state-loop. Loopback-only.
     */
    private fun startMirror() {
        try {
            // App-private, content-addressed cache root: /data/data/app.torta.yeah/app_data/centauri_cache —
            // the established no-Context app-private convention (PathVars.getAppDataDir, the dnscrypt root).
            val appDataDir = pathVars.get().appDataDir
            val cacheDir = "$appDataDir/app_data/centauri_cache"

            // (1) the assets→durable seed channel (first boot only; silent no-op when no asset ships).
            CentauriCatalogChannel.stageSeedFromAssets(appDataDir)

            // (2) the Object — constructed once per process, held for the dashboards.
            val handle = centauri ?: TortaCore.centauriCreate(cacheDir)?.also {
                centauri = it
                heldObject = it
            }

            if (handle == null) {
                startMirrorFlat(cacheDir) // base .so / construction fault ⇒ the legacy flat path (NO-BREAK).
            } else {
                startMirrorObject(handle, appDataDir, cacheDir)
            }
        } catch (e: Exception) {
            loge("CentauriMirrorManager startMirror — staying idle", e)
        }
    }

    /** The legacy flat start path (NO-BREAK fallback for a base `.so` / Object-construction fault). */
    private fun startMirrorFlat(cacheDir: String) {
        val port = TortaCore.centauriMirrorStart(cacheDir)
        if (port != null && port > 0) {
            boundPort = port
            lastBoundPort = port
            logi("CentauriMirrorManager — mirror bound on 127.0.0.1:$port (flat path; cache: $cacheDir)")
        } else {
            logi("CentauriMirrorManager — mirror not started (inert; status: ${TortaCore.centauriMirrorStats()})")
        }
    }

    /** Steps 3–6 of the arming chain over the constructed Object: install → start → warm-up → cloak. */
    private fun startMirrorObject(
        handle: TortaCore.CentauriHandle,
        appDataDir: String,
        cacheDir: String,
    ) {
        // (3) verify-sig-FIRST install of the staged signed catalog (fail-closed; absent pair = cold start).
        var installed = CentauriCatalogChannel.installStaged(handle, appDataDir)

        // (3.25) THE SOVEREIGN FAST LANE — rehydrate the DEVICE-authored pair (`device-catalog.tcat` +
        // `.sig`, born ON this device by a prior boot's arming pass, persisted into the cache dir by the
        // Rust side) against THIS install's OWN DeviceKey. The pubkey never crosses the FFI. A verified
        // pair RETAINS as the serve authority WITHOUT re-staging assets or re-hashing content — the
        // RAM⊗NAND fast boot (ctor already rehydrated the content-addressed bytes; this restores the
        // catalog half). First boot has no pair yet (the honest cold miss) → the arming pass below
        // authors + persists it, so every LATER boot lands here. Fail-open, never throws.
        //
        // The device pair ALWAYS gets the last word: it is a strict superset of the shipped seed
        // (seed pages + every ABSORBED CDN transplant grown since arming), so even when an APK
        // reinstall re-stages `assets/centauri/catalog.tcat` and installStaged() returns true, the
        // rehydrated device catalog must install OVER it — otherwise a reinstall silently amnesias
        // every transplant (owned pages 200, transplants 404: the shadowed-encyclopedia bug).
        val keyDir = appDataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR
        if (TortaCore.centauriRehydrateDeviceCatalog(handle, keyDir)) {
            installed = true
            logi("CentauriMirrorManager — DEVICE catalog rehydrated from its RAM⊗NAND pair (sovereign fast lane)")
        }

        // (3.5) SOVEREIGN DEVICE ARMING — the living CDN-encyclopedia's boot faculty. With no externally
        // signed catalog installed AND no device pair to rehydrate (First Boot), Centauri arms its OWN
        // device-signed catalog on-device: extract the seed content, mint-or-reload this install's DeviceKey
        // under the durable tier, seed the Object's shared cache with the OWNED pages + transplanted CDN
        // bytes (`content.tsv`), grow the SEEN cloak roster over every watched CDN host, then install the
        // device-signed catalog AND persist the signed pair (the RAM⊗NAND birth — the artifact exists
        // nowhere until THIS device authors it). MUST precede the bind (step 4 clones the installed
        // catalog into the serve loop). Fail-open, never throws.
        if (!installed) {
            val contentDir = CentauriCatalogChannel.stageContentFromAssets(appDataDir)
            val arm = TortaCore.centauriArmDeviceCatalog(handle, contentDir, keyDir)
            if (arm != null && arm.installed) {
                installed = true
                logi(
                    "CentauriMirrorManager — DEVICE catalog armed [key " + arm.keyIdHex +
                            (if (arm.minted) " MINTED" else " reloaded") + "]: " +
                            arm.cachedAssets + " transplanted / " + arm.cloakHosts + " SEEN cloak-hosts / " +
                            arm.catalogEntries + " catalog entries" +
                            (if (arm.persisted) " / pair PERSISTED (next boot rehydrates)" else " / pair NOT persisted")
                )
            } else {
                logw("CentauriMirrorManager — device arming installed no catalog (cold; serving stays dormant)")
            }
        }

        // (4) bind the loopback — the Object serves its LIVE shared store + self-feeds the review channel.
        val port = TortaCore.centauriStartObject(handle)
        if (port != null && port > 0) {
            boundPort = port
            lastBoundPort = port
            logi("CentauriMirrorManager — mirror bound on 127.0.0.1:$port (Object; cache: $cacheDir)")
        } else {
            logi("CentauriMirrorManager — mirror not started (inert; Object bind failed)")
        }

        // (5) the TIER-B warm-up batch (D04) — bounded, ≤1 request EVER per asset, no-op with no catalog.
        // GATED on the durable SeedPolicy (SETTINGS · the seed-policy chip): WarmUpBatch (1, the default)
        // runs the proactive top-N self-fill; CatalogOnly (0) installs the catalog but SKIPS the batch —
        // on-demand serve + rehydrate still fill the cache lazily, so a CatalogOnly user opted out of the
        // proactive fetch (their bandwidth choice), never out of serving. The manual "Warm up now" control
        // ([heldWarmUp]) still runs on demand regardless.
        val catalogAssets = TortaCore.centauriSnapshotObject(handle)?.catalogAssets ?: 0L
        val seedPolicy = defaultPreferences.getInt(TortaeKeys.CENTAURI_SEED_POLICY, SEED_POLICY_WARM_UP_BATCH)
        if (installed && catalogAssets > 0 && seedPolicy == SEED_POLICY_WARM_UP_BATCH) {
            val report = TortaCore.centauriWarmUp(handle, WARM_UP_MAX_TARGETS)
            if (report != null) {
                logi(
                    "CentauriMirrorManager — warm-up: ${report.filled} filled / " +
                            "${report.alreadyCached} cached / ${report.notInCatalog} skipped / " +
                            "${report.failed} failed (${report.targets} targets)"
                )
            }
        }

        // (5b) ★ #65 HTTPS serve leg — arm local TLS termination BEFORE the cloak.
        //
        // Order is load-bearing: the cloak is what redirects a watched CDN host at the DNS layer, and
        // once it is armed a browser's `:443` flow arrives here needing an answer. Arming TLS first
        // means the serve leg is ready the instant the first cloaked HTTPS flow lands, rather than the
        // first few assets falling through to the real CDN during a startup race.
        armTlsLeg()

        // (6) the opt-out local-CDN cloak (D05) — armed ONLY serving + catalog-backed (F9 no-blackhole).
        if (boundPort != null && catalogAssets > 0) {
            TortaCore.resolverSetCentauriCloak(true)
            cloakArmed = true
            logi("CentauriMirrorManager — DNS-plane cloak ARMED ($catalogAssets assets → 127.0.0.1:$boundPort)")
        } else {
            disarmCloak()
            if (boundPort != null) {
                logi("CentauriMirrorManager — serving but DORMANT (no verified catalog; cloak disarmed)")
            }
        }
    }

    /**
     * ★ #65 HTTPS serve leg — mint-or-reload the device CA and arm local TLS termination.
     *
     * ## Why this makes Centauri work on `:443`
     * Without it a cloaked `https://` asset cannot be served from the local store at all — the browser
     * opens TLS, we have no certificate for the CDN's name, and the flow falls back to the real CDN on
     * EVERY page load. With it, the asset is absorbed at most once and served from this device forever,
     * which is the entire point of the pillar.
     *
     * ## Persistence, and why it matters for safety
     * The PEM pair is written to app-private storage ([Context.getFilesDir], `MODE_PRIVATE`, not
     * external, never a log) and re-supplied on the next launch. Re-minting instead would force the
     * user to re-trust a fresh CA every launch — training exactly the "just accept the certificate"
     * reflex that makes people vulnerable. One deliberate trust decision, honored across restarts.
     *
     * Arming does NOT grant trust: until the user installs [caCertFile] into the OS trust store,
     * browsers reject the minted leaves and those flows fall back. That is by design — nothing is
     * installed behind the user's back.
     *
     * Crash-proof: any failure leaves the leg disarmed and serving continues on the `:80` path.
     */
    /**
     * ★ DOES THE SERVE LEG ACTUALLY ANSWER?
     *
     * MEASURED 2026-08-01: with the CA trusted and the cloak armed, `ajax.googleapis.com` resolved
     * to the tun address and Brave reported ERR_CONNECTION_TIMED_OUT. Bound is not serving, and
     * armed is not answering -- the same distinction the rotation health gate was built on after a
     * green "reachable" slate could not open a single page.
     *
     * This is a REAL request against the bound mirror on loopback (plain `:80` path, no TLS: we are
     * asking "is something there and does it hand back bytes", not "does TLS terminate"), with a
     * short timeout so a dead leg costs a fraction of a second rather than a hung tick. Any
     * failure answers NO, which keeps the cloak dark.
     *
     * Cached for [PROBE_TTL_MS] because it is consulted from the trust path on every dashboard
     * tick, and a per-tick socket would be a self-inflicted load.
     */
    private fun armTlsLeg() {
        try {
            val filesDir = App.instance.applicationContext.filesDir
            val dir = File(filesDir, CA_DIR_NAME).apply { if (!exists()) mkdirs() }
            val certFile = File(dir, CA_CERT_FILE)
            val keyFile = File(dir, CA_KEY_FILE)

            // Reload a previously trusted CA when both halves survive; otherwise mint fresh.
            val existingCert = certFile.takeIf { it.isFile }?.readText()
            val existingKey = keyFile.takeIf { it.isFile }?.readText()

            val material = TortaCore.centauriTlsArm(existingCert, existingKey)
            if (material == null) {
                logi("CentauriMirrorManager — HTTPS serve leg DISARMED (arm returned null; :80 serving unaffected)")
                return
            }

            // Persist only when something actually changed — a no-op rewrite would churn storage on
            // every start and, worse, rewrite the key file the user's trust is anchored to.
            if (existingCert != material.certPem) certFile.writeText(material.certPem)
            if (existingKey != material.keyPem) {
                keyFile.writeText(material.keyPem)
                // The signing key is app-private material: strip group/other access explicitly rather
                // than relying on the default umask.
                @Suppress("SetWorldReadable")
                keyFile.setReadable(false, false)
                keyFile.setReadable(true, true)
                keyFile.setWritable(false, false)
            }
            val reused = existingCert != null && existingCert == material.certPem
            logi(
                "CentauriMirrorManager — HTTPS serve leg ARMED (device CA ${if (reused) "reused" else "minted"}; " +
                        "install ${certFile.absolutePath} to have HTTPS CDN assets served locally)"
            )
        } catch (t: Throwable) {
            loge("CentauriMirrorManager armTlsLeg", Exception(t))
        }
    }

    /** Disarm the DNS-plane cloak (idempotent, crash-proof) + record it for the dashboards. */
    private fun disarmCloak() {
        try {
            TortaCore.resolverSetCentauriCloak(false)
        } catch (e: Exception) {
            loge("CentauriMirrorManager disarmCloak", e)
        }
        cloakArmed = false
    }

    companion object {
        /**
         * ★ #65 — app-private home of the device CA. Under `filesDir` (NOT external, NOT cache: the
         * user's trust decision must not be evictable by the OS reclaiming cache space).
         */
        private const val CA_DIR_NAME = "centauri_ca"

        /** The PUBLIC CA certificate the user installs into the OS trust store. */
        private const val CA_CERT_FILE = "centauri-ca.pem"

        /** The CA signing key. App-private storage ONLY — never logged, never leaves the device. */
        private const val CA_KEY_FILE = "centauri-ca-key.pem"

        /**
         * THE GOVERNANCE GATE, extracted pure so it is unit-testable without an Android `Context`. The
         * local mirror is now a CONSTANT pillar (Socio default-ON contract 2026-06-20): a default
         * (untouched) install returns `true` here — the self-filling loopback mirror arms (the Centauri
         * serve-loop, ModulesStateLoop.java:431-435). This is SAFE-by-construction: the bind is purely local
         * (127.0.0.1 ephemeral port, NOT an egress path), and the SELF-HEAL-not-block fail-safe is intact —
         * a missing-local artifact triggers a fetch-once+cache (the CDN sees ≤1 request ever), it NEVER
         * blocks the page. Native is gated under the Rust `mirror` cargo feature: a BASE `.so` has no mirror
         * symbol, the [TortaCore] façade catches the UnsatisfiedLinkError and returns the inert sentinel, so
         * [startMirror] degrades to "did not start" — never an UnsatisfiedLinkError, never a throw into the
         * state-loop. The master DNS-engine switch still wins ([TortaeKeys.DNS_ENGINE_ENABLED], default
         * on): engine off ⇒ no mirror. Reversible — the user can flip
         * [TortaeKeys.CENTAURI_MIRROR_ENABLED] OFF via its switch (USER FREEDOM). FAIL-SAFE PRESERVED:
         * the value moves to default-ON; the self-heal-not-block + inert-on-base-`.so` guards are unchanged.
         */
        @JvmStatic
        fun shouldStartMirror(prefs: SharedPreferences): Boolean {
            // Never override the master engine switch: engine intelligence off ⇒ do nothing.
            if (!prefs.getBoolean(TortaeKeys.DNS_ENGINE_ENABLED, true)) return false
            // Default-ON constant pillar. Loopback-only (no egress) + self-heal-not-block + inert on a base
            // `.so` (no `mirror` feature) ⇒ arming the default never breaks a page and never throws.
            return prefs.getBoolean(TortaeKeys.CENTAURI_MIRROR_ENABLED, true)
        }

        /**
         * The HELD Centauri Object (D07 — the WardenDatapathGate `hold()` precedent): the manager mirrors
         * its constructed handle here so the root-graph dashboard card/fragment — which can NOT reach the
         * `@ModulesServiceScope` instance (the documented cross-graph wall) — read the SAME live typed
         * state the loopback serves. `null` until the first arming edge (base `.so` / mirror never armed).
         */
        @Volatile
        private var heldObject: TortaCore.CentauriHandle? = null

        /**
         * The port the mirror last bound, mirrored out of the `@ModulesServiceScope` instance so the
         * companion-level probe below can reach it (the same cross-graph wall [heldObject] exists for).
         */
        @Volatile
        private var lastBoundPort: Int? = null

        /** Result of the last serve probe and when it was taken (elapsed-realtime millis). */
        @Volatile
        private var probeCache: Pair<Boolean, Long>? = null

        private const val PROBE_TTL_MS = 15_000L
        private const val PROBE_TIMEOUT_MS = 1_200

        /**
         * The tun sentinel the DNS cloak collapses every watched CDN host onto — kept in step with
         * `resolver::local::CLOAK_SENTINEL_V4` on the Rust side (`forwarder/sni.rs:11`). This is the
         * address the BROWSER dials, which is why the probe dials it too.
         */
        private const val CLOAK_SENTINEL_V4 = "10.1.10.3"

        /**
         * The port the #65 hairpin accepts on. `80` deliberately, not `443`: the probe asks "does a
         * server answer on the cloak path", and the plain leg answers that without dragging TLS
         * termination and certificate policy into a health check.
         */
        private const val MIRROR_HAIRPIN_PORT = 80

        /**
         * ★ DOES THE SERVE LEG ACTUALLY ANSWER?
         *
         * MEASURED 2026-08-01, minutes after the cloak's trust conjunct was first wired: with the
         * correct CA anchored the cloak fired (`ajax.googleapis.com -> 10.1.10.3`, sinkholes 0 -> 11)
         * and Brave answered **ERR_CONNECTION_TIMED_OUT**. Bound is not serving and armed is not
         * answering -- the same distinction the rotation health gate was built on after a green
         * "reachable" slate could not open a single page.
         *
         * A trusted CA proves the browser would ACCEPT our certificate. It proves nothing about
         * anything being there to present one. So trust alone must not open the cloak, or a pillar
         * being armed DROPS connections -- strictly worse than the feature being off.
         *
         * This is a real request against the bound mirror on loopback, with a short timeout so a
         * dead leg costs a fraction of a second rather than a hung tick. Any failure answers NO,
         * which keeps the cloak dark. Cached for [PROBE_TTL_MS] because the trust path consults it
         * on every dashboard tick and a per-tick socket would be a self-inflicted load.
         */
        @JvmStatic
        @Suppress("TooGenericExceptionCaught") // a probe that throws is a probe that answered NO
        fun serveLegAnswers(): Boolean {
            // Still require a bound mirror: no mirror, nothing for the hairpin to splice to.
            lastBoundPort ?: return false
            val now = android.os.SystemClock.elapsedRealtime()
            probeCache?.let { if (now - it.second < PROBE_TTL_MS) return it.first }
            // ★ PROBE THE PATH THE BROWSER TAKES, NOT THE ONE THAT IS EASY TO REACH.
            //
            // My first version of this probe dialled `127.0.0.1:$port` and would have PASSED:
            // `/proc/net/tcp` shows `0100007F:A8C9 0A` -- the mirror is genuinely LISTENING on
            // loopback. The browser never goes there. The DNS cloak hands out the tun sentinel
            // `10.1.10.3:443` (`resolver::local::CLOAK_SENTINEL_V4`), and the flow only reaches the
            // mirror if the forwarder's #65 hairpin + SNI splice (`forwarder/run.rs:456`,
            // `forwarder/sni.rs`) carries it. That is the leg that was silent, so a loopback probe
            // would have reported a healthy pillar while Brave timed out -- an instrument agreeing
            // with the wish instead of the user.
            //
            // Fail-closed by construction: if this app's own sockets bypass its tun, the connect
            // fails and the answer is NO, which leaves the cloak dark. The worst case is a feature
            // that stays off; the worst case of the easy probe was a browser that cannot load.
            val ok = try {
                val conn = java.net.URL("http://$CLOAK_SENTINEL_V4:$MIRROR_HAIRPIN_PORT/")
                    .openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = PROBE_TIMEOUT_MS
                conn.readTimeout = PROBE_TIMEOUT_MS
                conn.requestMethod = "HEAD"
                try {
                    // ANY HTTP status is a YES: a 404 means the signed catalog refused this
                    // particular name, which still proves a live server answered on the socket.
                    // Only a TRANSPORT failure (nothing listening, timeout) is a NO -- and that is
                    // exactly the condition that produced ERR_CONNECTION_TIMED_OUT in the browser.
                    conn.responseCode > 0
                } finally {
                    conn.disconnect()
                }
            } catch (t: Throwable) {
                false
            }
            probeCache = ok to now
            return ok
        }

        /**
         * Is the P9 DNS-plane cloak armed (D05)? Set ONLY by the manager on the serving+catalog-backed
         * edge; the dashboards render the honest "live cloaking" vs "dormant" copy from it.
         */
        @Volatile
        var cloakArmed: Boolean = false
            private set

        /** The held Object's typed snapshot, or null (crash-proof) — the dashboards' typed read (D07). */
        @JvmStatic
        fun heldSnapshot(): uniffi.torta_core.CentauriSnapshot? =
            TortaCore.centauriSnapshotObject(heldObject)

        /** The held Object's recent-serve feed (newest-first, self-fed by the live loop — D29). */
        @JvmStatic
        fun heldRecentServes(max: Int): List<uniffi.torta_core.CentauriServeRecord> =
            TortaCore.centauriRecentServes(heldObject, max)

        // ---- SETTINGS · the 2 held-Object control-plane actions the Centauri ||| SETTINGS pane drives
        // (through TortaPillarBridge → the Rust rail). Each targets the SAME live held Object the loopback
        // serves + the dashboards read, so a flip changes serving behavior immediately. Crash-proof; a
        // null/never-armed Object degrades every control to an honest no-op sentinel, never a throw.
        // (No held cache-mode / install control: the CROWN is always-on LeakOnMiss and the signed catalog
        //  auto-arms inside startMirrorObject on every engine start — neither is ever a user action.) ----

        /**
         * SETTINGS · the DNS-plane cloak arm/disarm (the manual twin of the arm-chain step 6) + records it
         * for the dashboards. Idempotent, crash-proof. Returns true iff the write landed.
         */
        @JvmStatic
        fun setCloak(on: Boolean): Boolean =
            try {
                TortaCore.resolverSetCentauriCloak(on)
                cloakArmed = on
                true
            } catch (e: Exception) {
                loge("CentauriMirrorManager setCloak", e)
                false
            }

        /**
         * SETTINGS · run a TIER-B warm-up batch on the held Object NOW (D04 — bounded, ≤1 fetch/asset ever).
         * BLOCKING for the batch — the bridge calls it off the main thread. Returns the count of assets
         * FILLED (≥0), or -1 on a null/never-armed Object or native fault.
         */
        @JvmStatic
        fun heldWarmUp(): Int {
            val report = TortaCore.centauriWarmUp(heldObject, WARM_UP_MAX_TARGETS) ?: return -1
            return report.filled.toInt()
        }

        /** The TIER-B warm-up batch bound (D04) — a curated top-N self-fill, never a whole-catalog crawl. */
        private const val WARM_UP_MAX_TARGETS = 64

        /**
         * The durable [TortaeKeys.CENTAURI_SEED_POLICY] codes (SETTINGS · the seed-policy chip). CatalogOnly
         * = install the catalog, serve/rehydrate lazily, NO proactive fetch batch. WarmUpBatch (the default,
         * preserving the pre-settings behavior) = also run the bounded TIER-B self-fill at arm.
         */
        const val SEED_POLICY_CATALOG_ONLY = 0
        const val SEED_POLICY_WARM_UP_BATCH = 1
    }
}

/**
 * The Centauri CATALOG CHANNEL (D04 — the wire that was missing), file-private beside its one consumer:
 * the assets→durable first-boot SEED copy + the verify-sig-FIRST INSTALL of the staged signed pair.
 * Mirrors the `.tblk` blocklist artifact channel bit-for-bit: the W5 durable dir
 * ([RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR]) holds `catalog.tcat` + `catalog.tcat.sig` (the
 * `<base>`+`<base>.sig` convention), the pinned Centauri anchor is the ONLY trust root, and EVERY path
 * fail-closes (absent ⇒ cold start · unsigned ⇒ never staged · oversize ⇒ refused · bad/placeholder
 * signature ⇒ the Rust minisign gate rejects, nothing installed, the cloak never arms). Bounded reads,
 * crash-proof, no egress — the signed artifact itself is the offline Haskell brain's drop-in.
 */
@OptIn(ExperimentalCoroutinesApi::class) // consts on the @ExperimentalCoroutinesApi-marked siblings
private object CentauriCatalogChannel {

    /** The shipped seed catalog asset name (OPTIONAL — the offline brain's signed drop-in). */
    private const val SEED_CATALOG_ASSET = "centauri/catalog.tcat"

    /** The detached-signature suffix of the W5 signed pair (`<base>` + `<base>.sig`). */
    private const val SIG_SUFFIX = ".sig"

    /** Bounded-read caps for the staged catalog + signature (a hostile file is never slurped whole). */
    private const val MAX_CATALOG_BYTES = 8L shl 20 // 8 MiB — a catalog is KiBs; generous fail-closed cap
    private const val MAX_SIG_BYTES = 4L shl 10 // 4 KiB — a decoded minisign blob is 74 bytes

    /** The shipped seed CONTENT dir (`assets/centauri/content`) — the OWNED pages + transplanted CDN bytes
     *  the device-arming pass content-addresses + serves 0-egress. Its `content.tsv` names each asset. */
    private const val CONTENT_ASSET_DIR = "centauri/content"

    /** The durable, app-private dir the seed content extracts to (sibling of the cache + runtime tier). */
    private const val CONTENT_RELATIVE_DIR = "/app_data/centauri_content"

    /** Bounded per-file read for the seed content (jQuery ≈ 87 KiB; a fat asset is never slurped whole). */
    private const val MAX_CONTENT_FILE_BYTES = 4 shl 20 // 4 MiB

    /**
     * First-boot seed (D04): copy the shipped `assets/centauri/catalog.tcat` + `.sig` pair into the W5
     * durable dir IF not already staged. Absent asset ⇒ silent no-op (the default until the offline brain
     * signs a production catalog — the same posture as the `.tblk` channel's placeholder key).
     */
    fun stageSeedFromAssets(appDataDir: String) {
        try {
            val durableDir = File(appDataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR)
            val catalogFile = File(durableDir, RuntimeTierManager.CENTAURI_BASE)
            val sigFile = File(durableDir, RuntimeTierManager.CENTAURI_BASE + SIG_SUFFIX)
            val alreadyStaged = catalogFile.isFile && sigFile.isFile // first boot done ⇒ no-op.
            val pair = if (alreadyStaged) null else readSeedPairFromAssets()
            if (pair != null) {
                durableDir.mkdirs()
                catalogFile.writeBytes(pair.first)
                sigFile.writeBytes(pair.second)
                logi("CentauriMirrorManager — seed catalog staged from assets (${pair.first.size} B)")
            }
        } catch (e: Exception) {
            loge("CentauriCatalogChannel stageSeedFromAssets", e)
        }
    }

    /**
     * Verify-sig-FIRST install of the staged signed catalog into the Object (retained ⇒ the loopback
     * SERVES it). Returns true IFF a genuine catalog verified + installed.
     */
    fun installStaged(handle: TortaCore.CentauriHandle, appDataDir: String): Boolean {
        return try {
            val durableDir = File(appDataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR)
            val catalogFile = File(durableDir, RuntimeTierManager.CENTAURI_BASE)
            val sigFile = File(durableDir, RuntimeTierManager.CENTAURI_BASE + SIG_SUFFIX)
            val stagedOk = catalogFile.isFile && sigFile.isFile &&
                    catalogFile.length() <= MAX_CATALOG_BYTES && sigFile.length() <= MAX_SIG_BYTES
            val pubkey = decodePinnedPubkey()
            if (stagedOk && pubkey != null) {
                val ok = TortaCore.centauriInstallCatalogObject(
                    handle, catalogFile.readBytes(), sigFile.readBytes(), pubkey
                )
                if (ok) {
                    logi("CentauriMirrorManager — signed catalog VERIFIED + installed (the loopback serves it)")
                } else {
                    logw("CentauriMirrorManager — staged catalog did NOT verify (fail-closed; nothing installed)")
                }
                ok
            } else {
                false // cold start (nothing staged / over-cap) or a malformed pin — nothing installed.
            }
        } catch (e: Exception) {
            loge("CentauriCatalogChannel installStaged", e)
            false
        }
    }

    /**
     * Extract the shipped Centauri seed CONTENT (the `assets/centauri/content` dir) into the durable, app-private
     * content dir and return its absolute path — the source the device-arming pass reads (its `content.tsv`
     * manifest + the OWNED pages + transplanted CDN bytes). Overwrite-idempotent so an app update refreshes
     * the transplant; fail-open (a missing/oversize asset is skipped, the dir is created regardless, the
     * path is ALWAYS returned so arming can still mint the key + grow the SEEN cloak roster). Flat-only —
     * a name with a separator is refused (no traversal). Never throws.
     */
    fun stageContentFromAssets(appDataDir: String): String {
        val contentDir = File(appDataDir + CONTENT_RELATIVE_DIR)
        try {
            contentDir.mkdirs()
            val assets = App.instance.applicationContext.assets
            val names = assets.list(CONTENT_ASSET_DIR) ?: emptyArray()
            var staged = 0
            for (name in names) {
                if (name.isEmpty() || name.contains('/') || name.contains("..")) continue
                val bytes = readAssetOrNull(assets, "$CONTENT_ASSET_DIR/$name") ?: continue
                if (bytes.size > MAX_CONTENT_FILE_BYTES) continue
                File(contentDir, name).writeBytes(bytes)
                staged++
            }
            logi("CentauriMirrorManager — staged $staged seed content file(s) → ${contentDir.absolutePath}")
        } catch (e: Exception) {
            loge("CentauriCatalogChannel stageContentFromAssets", e)
        }
        return contentDir.absolutePath
    }

    /**
     * Read the OPTIONAL shipped seed pair from assets, fail-closed: absent seed ⇒ null (the channel stays
     * cold, honestly); a seed WITHOUT its signature is never staged (verify-sig-FIRST discipline); an
     * over-cap read is refused (bounded — a hostile asset is never slurped whole).
     */
    private fun readSeedPairFromAssets(): Pair<ByteArray, ByteArray>? {
        val assets = App.instance.applicationContext.assets
        val seedBytes = readAssetOrNull(assets, SEED_CATALOG_ASSET) ?: return null
        val seedSig = readAssetOrNull(assets, SEED_CATALOG_ASSET + SIG_SUFFIX)
        return when {
            seedSig == null -> {
                logw("CentauriMirrorManager — seed catalog asset present but unsigned; NOT staging")
                null
            }
            seedBytes.size > MAX_CATALOG_BYTES || seedSig.size > MAX_SIG_BYTES -> {
                logw("CentauriMirrorManager — seed catalog/sig exceeds the bounded-read caps; NOT staging")
                null
            }
            else -> seedBytes to seedSig
        }
    }

    /** Read one asset whole, or null when absent/unreadable (an optional asset is never an error). */
    private fun readAssetOrNull(assets: android.content.res.AssetManager, name: String): ByteArray? =
        try {
            assets.open(name).use { it.readBytes() }
        } catch (t: Throwable) {
            null
        }

    /** Base64-decode the pinned Centauri pubkey anchor, or null (fail-closed); never throws. */
    private fun decodePinnedPubkey(): ByteArray? = try {
        Base64.decode(CentauriArtifactManager.PINNED_MINISIGN_PUBKEY_BASE64, Base64.DEFAULT)
    } catch (t: Throwable) {
        null
    }
}
