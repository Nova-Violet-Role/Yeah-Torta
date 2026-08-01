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

package pillar.kuma_saimono.libumdnscrypt.rust

/**
 * Kotlin face of the single Rust horsepower lib (`libtorta_core.so`), shared by P7 (speed) and P9
 * (security). Loading is lazy and crash-proof: if the `.so` is missing for the running ABI, or a
 * native call fails, callers get a safe fallback rather than an [UnsatisfiedLinkError] taking down
 * the app — matching the Rust side's panic firewall.
 */
object TortaCore {

    /** Decoded minisign signature-blob length: algo(2) + key_id(8) + ed25519_sig(64). */
    private const val MINISIG_SIG_BLOB_LEN = 74
    /** Decoded minisign public-key-blob length: algo(2) + key_id(8) + ed25519_pk(32). */
    private const val MINISIG_PUBKEY_BLOB_LEN = 42

    @Volatile private var loaded = false

    /**
     * Is the native engine available RIGHT NOW (loading it if this is the first ask)?
     *
     * Every accessor below fails soft — an absent engine answers 0/false/empty, exactly like a live engine
     * with nothing to report. That is right for metrics (a dashboard tile should read 0, not crash) but
     * WRONG for edge-triggered work, where "the engine was not up yet" must be retried and "there was
     * nothing to do" must not. MEASURED: the CA-trust edge in [CentauriCaTrust] consumed itself on the
     * first dashboard tick because the retrust returned 0 from an engine that had not finished loading,
     * so the automatic hand-back never ran for the rest of the process. Callers that latch MUST gate on
     * this instead of inferring liveness from a zero.
     */
    fun isEngineLoaded(): Boolean = ensureLoaded()

    @Synchronized
    private fun ensureLoaded(): Boolean {
        if (loaded) return true
        return try {
            System.loadLibrary("torta_core")
            loaded = true
            true
        } catch (t: Throwable) {
            false
        }
    }

    // ---- #18 G6 — the GithubTrustEngine crown (the per-source trust registry, RAM⊗NAND) ----
    // The ONE process-global crown Object. Rust-side it is COMPLETE and waiting (github.rs:842):
    // rehydrate-at-construction from the `github-trust-crown` DurableTier record, gentle write-through
    // on every investigate/arm, zero fs on any verdict path. This holder closes the G6 gap (the Object
    // was never constructed in app Kotlin): ONE construction, early (RuntimeTierManager pillar 7),
    // shared by every consumer (TrustManager scoring, future Warden SLINT trust-crown feed). The
    // construction IS the rehydrate — a warm boot serves cached verdicts from NAND with zero network.

    @Volatile private var trustCrown: uniffi.torta_core.GithubTrustEngine? = null

    /**
     * Open (construct-once) the crown over [durableDir] — the SAME `app_data/runtime_tier` root the
     * other durable pillars share ([RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR]; G9 law: never a
     * third root). Idempotent + double-checked: the first caller constructs (which rehydrates the
     * `github-trust-crown` record from NAND), every later caller gets the same handle. Fail-safe null
     * on a missing `.so` or any construction throwable — a caller degrades to its crown-less path.
     */
    @Synchronized
    fun trustCrownOpen(durableDir: String): uniffi.torta_core.GithubTrustEngine? {
        trustCrown?.let { return it }
        return if (ensureLoaded()) {
            try {
                val engine = uniffi.torta_core.GithubTrustEngine(durableDir)
                trustCrown = engine
                engine
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }
    }

    /** The already-opened crown, or null if pillar 7 has not run (or the `.so` is unreachable). Pure read. */
    fun trustCrownOrNull(): uniffi.torta_core.GithubTrustEngine? = trustCrown

    // ---- #21 G7-RESIDUAL — the AppStateStore (the app-level typed DurableTier record) ----
    // The LAST load-bearing app flags leaving SharedPreferences (`savedDNSCryptState`, the preset-seeded
    // latch; schema seats for OPERATION_MODE / VPN_SERVICE_ENABLED), folded into ONE typed `app-state`
    // record (Rust app_state.rs, the trustCrown holder shape). Unlike the crown (which rehydrates at
    // construction), the AppStateStore ctor is IO-FREE by law — so the open here does the ONE explicit
    // boot rehydrate. Consumers go through [pillar.kuma_saimono.libumdnscrypt.rust.AppStateBridge] (which
    // owns the durable dir + the one-shot legacy-pref absorb), never this holder directly.

    @Volatile private var appStateStore: uniffi.torta_core.AppStateStore? = null

    /**
     * Open (construct-once + rehydrate-once) the app-state store over [durableDir] — the SAME
     * `app_data/runtime_tier` root every durable pillar shares (G9 law: never a third root).
     * Idempotent + double-checked like [trustCrownOpen]. Fail-safe null on a missing `.so` or any
     * construction/rehydrate throwable — the caller degrades to its legacy-prefs path.
     */
    @Synchronized
    fun appStateOpen(durableDir: String): uniffi.torta_core.AppStateStore? {
        appStateStore?.let { return it }
        return if (ensureLoaded()) {
            try {
                val store = uniffi.torta_core.AppStateStore(durableDir)
                store.rehydrate() // the ONE boot NAND read (IO-free ctor law)
                appStateStore = store
                store
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }
    }

    /** The already-opened app-state store, or null if never opened / `.so` unreachable. Pure read. */
    fun appStateOrNull(): uniffi.torta_core.AppStateStore? = appStateStore

    // ---- #9/#130 batch-2+3 — the ENTIRE version + Blocklist surface is now UniFFI (ZERO JNI) ----
    // version + blocklistCompileFile/CompileText/IsBlocked/Count/Fingerprint (batch-2) + the two
    // ByteArray
    // artifact fns CompileArtifact/VerifyArtifact (batch-3) are all generated `uniffi.torta_core.*`
    // bindings; their `external fun native*` decls are GONE. GROUND_TRUTH (batch-3): UniFFI's
    // `#[uniffi::export]` macro maps `Vec<u8>` → Kotlin **`ByteArray`** (Type::Bytes — MEASURED,
    // not
    // `List<UByte>`), so the byte fns port with zero conversion (see uniffi-bytes-mapping).

    // ---- THE WARDEN (the non-signed configure surface) ----
    // The signed-policy loader (the old verify-sig-FIRST signed-artifact JNI) was RETIRED in slice 4 —
    // the decision source moved to the Trust-scored blocklists. The remaining warden surface is the
    // non-signed `wardenConfigure` enable flag, the C-ABI `torta_firewall_verdict` seam, and the W6
    // observe-only stats read-back below.

    // ---- THE WARDEN W6 — the aggregate verdict-stream stats read-back (slice-1 SEAM) ----
    // The Warden's missing equivalent of `nativeResolverStats`/`nativeMirrorStatus`: a JSON
    // read-back of the
    // block-wins verdict tally so the W6 dashboard card has a LIVE surface to render. The Rust core
    // records a
    // small allow/deny + gate-split counter AT the `verdict_at` resolve point (warden.rs), behind
    // the SAME
    // OnceLock<Mutex<Option<Warden>>> singleton the W3 bridge consults. AGGREGATE COUNTS ONLY —
    // never a
    // qname/domain/UID (the `nativeResolverStats` "no qname ever" law, T20). When the Warden is
    // disarmed/None
    // (the user having disarmed it — `WARDEN_NATIVE_ENABLED` is default-ON, the Socio all-ON contract
    // 2026-06-24) the counters are simply
    // zero and the
    // JSON reports `configured:false` — inert-graceful, so the card shows an honest "off" headline.
    // On a base
    // .so without this export (or a native fault) the call throws UnsatisfiedLinkError → caught →
    // "unavailable".

    // ---- #9/#130 batch-1+3 — the ENTIRE resolver surface is now UniFFI (ZERO JNI) ----
    // configure / stats / shutdown + the P12 Expert toggles
    // (rebind/bogus/proxy/filter/cloak/cache-rr/
    // all-servers/never-forward) + the RAM⊗NAND cache persist/rehydrate (batch-1) + the ByteArray
    // DATAPATH
    // fns resolverResolve / buildQuery (batch-3) are all generated `uniffi.torta_core.*` bindings;
    // their
    // `external fun nativeResolver*` / `nativeBuildQuery` decls are GONE. GROUND_TRUTH (batch-3):
    // UniFFI
    // maps `Vec<u8>` → Kotlin **`ByteArray`** (Type::Bytes — MEASURED), so even the wire-DNS
    // datapath ports
    // with no conversion. The Rust globals still ship at the privacy-first DEFAULT
    // (rebind/bogus/proxy/
    // filter/all-servers OFF; cache-rr/never-forward ON; cloak=NXDOMAIN), so an un-pushed flag is
    // correct.

    // ---- #120 RAM⊗NAND log fast-tier (base .so — NOT feature-gated) ----
    // Incremental tail of an on-NAND log into a bounded RAM ring (lib.rs log_tier), so the Kotlin
    // log
    // reader stops full-re-reading the file every ~10s tick. On a stale/base .so without these
    // symbols the
    // facades below catch UnsatisfiedLinkError -> null -> the caller falls back to OwnFileReader
    // (no regression).
    // logTailRecent / logStartedOk → UniFFI (#9/#130 batch-4); the hand-JNI decls are gone.

    // #126 anti-stale: seconds since the log was last modified (-1 = absent/unreadable). The
    // freshness twin
    // of the RAM⊗NAND tail; pairs with dnscrypt-proxy's own size/age rotation (the anti-bloat
    // half).
    // nativeLogStaleSecs → MIGRATED to UniFFI (#9/#10 Phase B): the hand-JNI external fun is gone;
    // the facade
    // below calls the generated uniffi.torta_core.logStaleSecs(path) binding instead.

    // P7 Wave 3 Stage-1 — arm/disarm the native resolver INSIDE the live C/UDP-53 datapath is NOT a
    // TortaCore
    // native. The `g_resolver_native_enabled` flag udp.c reads lives in libinvizible.so (where
    // udp.c is
    // compiled), NOT in this lib (libtorta_core.so). A TortaCore external here would mangle to a
    // symbol that
    // does NOT exist in libtorta_core.so → UnsatisfiedLinkError → a dead, silently-swallowed
    // arm-wire. The
    // real arm path is VpnUtils.setResolverNativeEnabled → VpnUtils.jni_set_resolver_native
    // (libinvizible.so),
    // called from ModulesStarterHelper.applyResolverNativeFromPref at DNSCrypt start.

    // ---- Signature verification (base .so — NOT feature-gated) ----
    // fortressVerifyFile / fortressVerifyList / fortressVerifyDnscryptProxy → UniFFI (#9/#130
    // batch-4): thin faces over the Rust `signature::verify_minisign` engine.

    // ---- Centauri Local Mirror (Rust `mirror` cargo feature) ----
    // Declared UNCONDITIONALLY in Kotlin; the BASE android .so (built WITHOUT --features mirror)
    // simply has
    // no matching symbols, so ensureLoaded()+native call throws UnsatisfiedLinkError → caught →
    // safe
    // fallback (the crash-proof contract). The base .so stays byte-identical; only a mirror-feature
    // build
    // carries these symbols. The facades below degrade to inert (null/false/-1) when the symbol is
    // absent.
    // Rust export names (lib.rs:710 / :748 / the #92 start export, all #[cfg(feature="mirror")]).
    // Aligned
    // Kotlin↔Rust (mag1 mismatches #5/#7). The START seam (nativeCentauriMirrorStart) LANDS this
    // cut: the Rust
    // #92 export `Java_…_TortaCore_uniffi.torta_core.centauriMirrorStart(cacheDir)` builds/holds
    // the on-disk
    // CacheStore
    // (with_dir+load_from_disk), spawns the loopback server on a mirror-local runtime, and returns
    // the bound
    // 127.0.0.1 ephemeral port as a jint (or the NEGATIVE sentinel MIRROR_START_FAILED on any
    // failure). On a
    // BASE .so (no --features mirror) this symbol is absent → UnsatisfiedLinkError → caught → inert
    // (null).

    // ---- THE WARDEN W5 — the shared RAM⊗NAND runtime tier (boot-rehydrate of the
    // REHYDRATE-FROM-SIGNED pillars) ----
    // The Kotlin face of the W5 rehydrate-from-signed-source seam (Rust lib.rs:1419-1523). TWO
    // kinds of pillar
    // share the W5 tier (charter §"KEY design distinction"): the NEW-durable bits (resolver
    // rotation/RTT,
    // metrics) get a gentle atomic NAND write-through + boot-rehydrate INSIDE each
    // pillar's own
    // Rust seam (the shared `runtime_tier::DurableTier` facility — library-internal, NO separate
    // JNI export); and
    // the SIGNED-SOURCE pillars (blocklist <- .tblk, Centauri <- .tcat), whose
    // durable tier IS
    // the signed artifact already on app-private flash, get THESE three boot-rehydrate exports.
    // "Rehydrate" here
    // is NOT a raw NAND dump of the in-RAM trie/policy (that would be a SECOND, unsigned,
    // drift-prone copy) — it
    // re-runs the W4 verify-sig-FIRST re-verify+re-install of the SIGNED bytes on boot.
    //
    // The on-flash layout each export reads (Rust lib.rs:1310-1318): the app-private durable `dir`
    // holds a pair
    //   <dir>/<base>       = the RAW signed artifact bytes (the EXACT bytes the offline brain
    // signed)
    //   <dir>/<base>.sig   = the base64-DECODED 74-byte minisign blob (KOTLIN writes the decoded
    // bytes)
    // The pinned pubkey is the base64-DECODED 42-byte blob, passed as a swappable PARAMETER (no key
    // baked into
    // Rust — same discipline as nativeBlocklistVerifyArtifact, production
    // key at #95).
    //
    // CRASH-PROOF / ADDITIVE: blocklist/Warden are in the BASE .so; Centauri is
    // `mirror`-feature-gated (absent
    // from a base .so → UnsatisfiedLinkError → caught → inert). Every export is verify-sig-FIRST +
    // fail-safe +
    // panic-firewalled on the Rust side (a forged/absent/tampered source leaves the in-memory tier
    // UNCHANGED).
    // Blocklist returns the armed domain count (jint, 0 = no-op/fail); Warden/Centauri return a
    // boolean install
    // verdict. The Kotlin façades add the established ensureLoaded()+try/catch firewall so a
    // missing symbol /
    // native fault degrades to the safe sentinel (0 / false), never an UnsatisfiedLinkError taking
    // down the app.

    // ---- THE WARDEN W5 — the resolver's NEW-durable rotation pillar (P10 rotation cursor + warm
    // RTT) ----
    // The Kotlin face of the resolver's NEW-durable rotation/RTT state (Rust
    // `resolver::rotation::RotationState`,
    // base `.so`). UNLIKE the THREE rehydrate-from-signed exports above (which re-verify a SIGNED
    // artifact already
    // on flash), this pillar OWNS its own durable record ("resolver-rotation") via the shared
    // `runtime_tier::DurableTier` (atomic tmp+rename, integrity-framed, bounded, non-failing) — so
    // there is NO
    // pubkey, NO verify-sig boundary. It carries TWO tiny bits across a power-off/reboot so the
    // next boot starts
    // WARM (W5 CHARTER §"the Resolver + Rotation rows"): the rotation cursor (last operator family
    // + cadence +
    // rotation index, so a reboot RESUMES the diversity schedule instead of re-landing family 0) +
    // a bounded
    // warm-RTT map. NOT on the resolve() hot path (rotation.rs §"the no-hot-path-write law"):
    // rehydrate is read
    // ONCE at start, persist fires ONLY on the control plane (a rotation flip), the GENTLE
    // write-through.
    //
    //   uniffi.torta_core.rehydrateResolverRotation(dir) → `RotationState::rehydrate(dir)`
    // (rotation.rs:124) →
    // a tiny summary
    //     "family=<s> cadence=<u64> index=<u64> hints=<n>" of the warm cursor (or the cold baseline
    // string when
    //     there is no record — a true cold start, NOT an error). Read at RotationManager.start() to
    // warm the
    //     diversity-exclusion cursor + cadence/index across a reboot.
    //   uniffi.torta_core.persistResolverRotation(dir, lastFamily, cadenceSecs, rotationIndex,
    // rttHints) →
    //     `RotationState::persist(dir)` (rotation.rs:135) → true on a durable write, false on any
    // refusal
    //     (best-effort — the in-memory tier is unaffected). [rttHints] is the same line-oriented
    // `<id>:<ms>`
    //     payload the Rust decoder reads (rotation.rs:184-194), one hint per '\n'-joined entry; an
    // empty string =
    //     no warm hints. Called on the rotateOnce() commit (the control plane) — DORMANT-correct
    // until the live
    //     swap arms (composeRotatedUpstreams() declines today), then it makes the chosen family
    // durable.
    //
    // CRASH-PROOF: both are panic-firewalled on the Rust side (a corrupt/half-written record
    // degrades to a cold
    // start; persist refuses an oversized/blocked write). The Kotlin façades add the established
    // ensureLoaded()+try/catch firewall so a missing symbol / native fault degrades to the safe
    // sentinel
    // (the cold-summary "family= cadence=0 index=0 hints=0" / false), never an UnsatisfiedLinkError
    // taking down
    // the app — exactly the [rehydrateBlocklistFromSigned] shape.

    /** The native core's self-attestation seed, or "unavailable" if the lib can't be reached. */
    fun versionSafe(): String =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.version() ?: "unavailable"
            } catch (t: Throwable) {
                "unavailable"
            }
        } else {
            "unavailable"
        }

    /**
     * Compile a LOCAL blocklist file (manual .txt pick) into the matcher. [merge] stacks it onto
     * the current list instead of replacing. Returns a "count=… fp=…" summary, or null on failure.
     */
    fun compileBlocklist(path: String, merge: Boolean = false): String? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.blocklistCompileFile(path, merge)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * Compile an IN-MEMORY blocklist — injected text, a fetched URL's bytes, or a GitHub search hit
     * — with no temp file. [merge] stacks it. The Zero Fatigue Zone transcode for non-file sources.
     */
    fun compileBlocklistText(text: String, merge: Boolean = false): String? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.blocklistCompileText(text, merge)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * Compile a PRE-COMPILED blocklist ARTIFACT (the P8 additive binary surface: a `TBLK` header +
     * sorted, length-prefixed domain bodies, self-verified by an embedded fingerprint) directly
     * into the matcher — no re-parse of raw rule text. [merge] stacks it onto the current list
     * instead of replacing. Returns the same "count=… fp=…" summary as the text/file paths, or null
     * on failure (bad magic/version, truncation, or a fingerprint mismatch all come back as null).
     * The remote artifact channel is signature-verified before these bytes ever reach here (later
     * P8 wave).
     */
    fun compileBlocklistArtifact(bytes: ByteArray, merge: Boolean = false): String? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.blocklistCompileArtifact(bytes, merge)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * P8 Wave C3 — the minisign PROVENANCE GATE for the opt-in remote artifact channel. Verify that
     * [artifactBytes] (the raw `.tblk`) carries a genuine minisign Ed25519 signature from the
     * pinned Centauri key, BEFORE any of those bytes reach [compileBlocklistArtifact] / Rust
     * `from_artifact`.
     *
     * [minisigText] is the full `.minisig` text file; [pinnedPubKeyBase64] is the base64 of the
     * pinned 42-byte public-key blob (`Ed`(2) ‖ key_id(8) ‖ pk(32)). This wrapper does the trivial
     * text work on the Kotlin side — extract the `.minisig` second line, base64-decode both blobs —
     * then hands raw bytes to the native verifier, which does the real Ed25519 `verify_strict` over
     * [artifactBytes].
     *
     * **The verify ORDER is the security boundary:** signature FIRST (provenance), then the FNV
     * self-check in `from_artifact` (set-integrity only, forgeable). A tampered artifact with a
     * valid FNV but a bad/ absent signature returns `false` HERE and must never be compiled.
     * Crash-proof: a missing `.so`, malformed input, or a native fault yields `false` (= "do not
     * arm"), never a thrown exception.
     */
    fun verifyArtifactSignature(
        artifactBytes: ByteArray,
        minisigText: String,
        pinnedPubKeyBase64: String,
    ): Boolean {
        if (!ensureLoaded()) return false
        return try {
            val sigBlob = decodeMinisigBlob(minisigText) ?: return false
            // The pinned public key is a compile-time constant base64; decode it to the 42-byte
            // blob.
            val pubkeyBlob =
                try {
                    android.util.Base64.decode(pinnedPubKeyBase64, android.util.Base64.DEFAULT)
                } catch (t: Throwable) {
                    return false
                }
            if (
                sigBlob.size != MINISIG_SIG_BLOB_LEN || pubkeyBlob.size != MINISIG_PUBKEY_BLOB_LEN
            ) {
                // Reject obviously-wrong shapes before the native call (the native side re-checks
                // too).
                return false
            }
            uniffi.torta_core.blocklistVerifyArtifact(artifactBytes, sigBlob, pubkeyBlob)
        } catch (t: Throwable) {
            false
        }
    }

    /**
     * Extract and base64-decode the SIGNATURE line of a `.minisig` text file → the 74-byte blob, or
     * null on any structural problem. minisign `.minisig` is: line 1 = `untrusted comment: …`, line
     * 2 = base64(signature_blob), then optional trusted-comment / global-signature lines. We take
     * the SECOND non-blank line (the signature blob — the only line a pinned-key verify needs).
     * Tolerant of CRLF/LF and surrounding whitespace; never throws.
     */
    private fun decodeMinisigBlob(minisigText: String): ByteArray? =
        try {
            val line =
                minisigText
                    .lineSequence()
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                    .drop(1) // line 1 is the untrusted comment
                    .firstOrNull() ?: return null
            android.util.Base64.decode(line, android.util.Base64.DEFAULT)
        } catch (t: Throwable) {
            null
        }

    /**
     * True if [domain] (or a parent domain) is blocked by the compiled list. Safe default: false.
     */
    fun isBlocked(domain: String): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.blocklistIsBlocked(domain)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /** Number of domains armed in the compiled list (0 if none / unavailable). */
    fun blocklistCount(): Int =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.blocklistCount()
            } catch (t: Throwable) {
                0
            }
        } else {
            0
        }

    /**
     * Set-deterministic content fingerprint of the compiled list (0 if none) — P8 trust/dedup
     * handle.
     */
    fun blocklistFingerprint(): Long =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.blocklistFingerprint()
            } catch (t: Throwable) {
                0L
            }
        } else {
            0L
        }

    // ---- In-app resolver (P7 Wave 2b — DoH/HTTP-2 shadow) ----
    // Symmetrical, crash-proof façades over the native resolver singleton. DNS is bytes, so
    // [resolve]
    // takes/returns a raw ByteArray — never a String round-trip. A null answer is the contract for
    // "fall through to dnscrypt-proxy"; the ServiceVPN shadow seam is wired in a later wave.

    /**
     * Configure the native resolver from an upstream-set JSON
     * (`{"upstreams":[{"id","transport","url"}]}`). [timeoutMs] bounds each query; [cacheCap] sizes
     * the answer cache. Returns a "ready=N transports=…" summary, or null if no usable upstream /
     * unavailable.
     */
    fun configureResolver(
        specsJson: String,
        timeoutMs: Long = 5000L,
        cacheCap: Int = 1024,
    ): String? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverConfigure(specsJson, timeoutMs, cacheCap)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * D06/D15 — the TYPED configure twin ([uniffi.torta_core.resolverConfigureTyped]): a
     * `List<UpstreamSpec>` + `List<RouteSpec>` in, a typed
     * [uniffi.torta_core.ConfigureReport] (`ready`/`transports`/`rejected`) out — no hand-built
     * JSON, no `"ready=N …"` summary parse (the full-power UniFFI law on the configure seam).
     * Rust-side it builds the SAME specs JSON (escaped) and delegates to the ONE tested
     * `resolver::configure` — byte-identical behaviour to [configureResolver]. Null = no usable
     * upstream / unavailable (the caller's fail-safe "no swap"). The rotation swap
     * (`ResolverRuntime.applyRotatedPool`) is the first production caller. Crash-proof.
     */
    fun configureResolverTyped(
        specs: List<uniffi.torta_core.UpstreamSpec>,
        routes: List<uniffi.torta_core.RouteSpec> = emptyList(),
        timeoutMs: Long = 5000L,
        cacheCap: Int = 1024,
    ): uniffi.torta_core.ConfigureReport? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverConfigureTyped(specs, routes, timeoutMs, cacheCap)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * D33b/D06 — the user's persisted conditional-routing rules as a TYPED
     * `List<RouteSpec>` (the [resolverRoutesJson] flat twin's typed successor) — what
     * [configureResolverTyped] carries so a rotated pool keeps the user's routes. Empty when
     * cold/cleared/unavailable. Crash-proof.
     */
    fun resolverRoutesList(dir: String): List<uniffi.torta_core.RouteSpec> =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverRoutesList(dir)
            } catch (t: Throwable) {
                emptyList()
            }
        } else {
            emptyList()
        }

    /**
     * #120 RAM⊗NAND log fast-tier — incrementally tail the on-NAND log at [path] (read ONLY the
     * bytes appended since the last poll) and return its most-recent [maxLines] lines, '\n'-joined;
     * or null. Null means "fall back to the Kotlin reader" (a stale/base .so without the export, or
     * a native fault → caught). The NAND file is the durable source; the Rust per-path ring is the
     * hot tier. Never throws.
     */
    fun logTailRecent(path: String, maxLines: Int): String? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.logTailRecent(path, maxLines)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * #120 — the dnscrypt-proxy readiness signal (`" OK "` / `"lowest initial latency"`) latched by
     * the SAME RAM⊗NAND tailer, computed once in Rust. Returns null when the native is unavailable
     * so the caller distinguishes "Rust says not-ready-yet" (false) from "Rust unavailable" (null →
     * use the Kotlin parser).
     */
    fun logStartedOk(path: String): Boolean? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.logStartedOk(path)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * #126 anti-stale — seconds since the log at [path] was last modified (real-time freshness of
     * query.log / DnsCrypt.log), or -1 if absent/unreadable/unavailable. A growing log → small; a
     * log that stopped getting real-time updates (dnscrypt stalled, or genuinely idle) → large.
     * Pairs with dnscrypt-proxy's own size/age rotation (the anti-bloat half) so the RAM⊗NAND log
     * tier is bounded AND freshness-aware. Crash-proof. Never throws.
     */
    fun logStaleSecs(path: String): Long =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.logStaleSecs(path)
            } catch (t: Throwable) {
                -1L
            }
        } else {
            -1L
        }

    /**
     * #133 the per-pillar log WRITE path — the symmetric twin of [logTailRecent]'s read. Append ONE
     * already-formatted event [line] to the per-pillar log file at [path] through the SAME RAM⊗NAND
     * substrate (lib.rs `log_append`): the NAND file is the durable tier, bounded by a
     * line-boundary-preserving tail-rewrite at 256 KiB (a chatty pillar can never grow it without
     * bound). Every pillar writes its own `query-<pillar>.log` through this ONE substrate, so they
     * all share one format + one read/debug path ([logTailRecent]) — exactly how dnscrypt-proxy's
     * `query.log` / `DnsCrypt.log` feed every dashboard, now generalized to our pillars.
     * Caller-facing dispatch + formatting live in
     * [pillar.kuma_saimono.libumdnscrypt.dns_engine.PillarLog]. Crash-proof: a missing `.so` / native
     * fault is a silent no-op (a debug log must NEVER break a pillar's hot path). Never throws.
     */
    fun logAppend(path: String, line: String) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.logAppend(path, line)
            } catch (t: Throwable) {}
    }

    /**
     * Resolve one wire-format DNS [query]. Returns the wire-format response bytes, or null — null
     * means "fall through" (blocked-name NXDOMAIN, a cache hit, or a validated upstream answer come
     * back as bytes; anything else, including a rejected/poisoned answer, is null). Never throws.
     */
    fun resolve(query: ByteArray): ByteArray? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverResolve(query)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * Synthesize a wire-format recursive A/AAAA query for [qname] ([qtype] 1 = A, 28 = AAAA) — the
     * SINGLE SOURCE OF TRUTH for the DNS query codec, wrapping the already-tested Rust
     * `dns::build_query` (`dns.rs:107`) so the Stage-0 shadow seam never maintains a second,
     * hand-kept-byte-identical wire builder. Returns the query bytes, or null on a bad qname /
     * native fault / missing `.so` for the running ABI — null is the façade contract for "fall back
     * to the Kotlin codec" (the seam stays live even if native is unreachable). Same crash-proof
     * shape as [resolve]: never throws.
     */
    fun buildQuery(qname: String, qtype: Int): ByteArray? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.buildQuery(qname, qtype)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /** Native resolver stats as a JSON string (no qname ever), or "unavailable" if unreachable. */
    fun resolverStats(): String =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverStats() ?: "unavailable"
            } catch (t: Throwable) {
                "unavailable"
            }
        } else {
            "unavailable"
        }

    /**
     * The LIVE Centauri Mirror status as a flat `"libraries=<N> bytes=<M> full=<bool>"` string off
     * the running `libtorta_core.so` content-addressed store (the SAME `MIRROR_RUNTIME` singleton
     * the loopback serves — the flat [crate::mirror_status] export). The SLINT rail bridges this so
     * the CENTAURI pillar dashboard reads the REAL running-engine cache instead of its own cold
     * spike-local copy (the .so-split fix, SLINT substitution · 4-FIX-2). REAL cache stats only,
     * never faked. Empty string on any failure (a base `.so` without the mirror export, an unloaded
     * lib, or a panic) — the rail then holds the honest cold/OFF state. Mirror-gated on the Rust
     * side, but the Kotlin binding always carries the function; a `.so` missing the symbol surfaces
     * as the caught throwable ⇒ "".
     */
    fun mirrorStatus(): String =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.mirrorStatus() ?: ""
            } catch (t: Throwable) {
                ""
            }
        } else {
            ""
        }

    /**
     * Idempotently tear down the native resolver's pool + sockets (keeps the parked runtime). Never
     * throws.
     */
    fun shutdownResolver() {
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverShutdown()
            } catch (t: Throwable) {
                // a shutdown failure must never crash the app — swallow it
            }
        }
    }

    /**
     * D28 / PHASE-1 VPN-TUNNELING — bind the in-app loopback DNS listener on `127.0.0.1:<port>`
     * (the sovereign-rewire keystone: the VpnService tun forwards system DNS here so the encrypted
     * DNSCrypt resolver answers, NOT a public server). `port == 53` is the standard bind; returns
     * the BOUND port (> 0) on success, or 0 on any failure (lib unloaded, bind fault, runtime
     * error, panic-firewall trip). IDEMPOTENT — a second call returns the already-bound port.
     * Crash-firewalled like every sibling façade; the call site never sees a throw. Underlying fn
     * is `resolver_start_loopback` (torta_core/src/lib.rs:1840 → resolver::listener::start_loopback).
     * #9/#130-class → UniFFI.
     */
    fun resolverStartLoopback(port: Int): Int =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverStartLoopback(port)
            } catch (t: Throwable) {
                // a bind failure must never crash the app — return 0 (listener unbound, the tun
                // forward falls through to the prior posture)
                0
            }
        } else {
            0
        }

    /**
     * D10 — the Beast→resolver pool budget: the YeAH window finally governs the PRODUCTION
     * datapath, not only the engine's own probes. [MonokumaDnsEngine] pushes Beast-derived numbers
     * once per ~5-s cycle (control-plane, NEVER per-query): [cwndCap] bounds concurrent upstream
     * exchanges (≤ 0 = uncapped), [timeoutMs] is the adaptive per-query deadline (Rust clamps to
     * 50..60_000 ms; ≤ 0 restores the configure-time deadline), [pacingQps] is recorded + surfaced
     * in [resolverStats] (the window itself enforces pacing — throughput ≈ cwnd/RTT). The engine's
     * stop() MUST push the release-all `(0, 0, 0.0)`. Fail-open on the Rust side (a full window
     * delays a query at most 250 ms); crash-proof here like every sibling façade.
     */
    fun resolverSetPoolBudget(cwndCap: Int, timeoutMs: Long, pacingQps: Double) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetPoolBudget(cwndCap, timeoutMs, pacingQps)
            } catch (t: Throwable) {}
    }

    // ---- P12 dnsmasq Expert-toggle façades (base .so) ----
    // Each pushes one Kotlin pref into the resolver's process-global flag, crash-proof (a missing
    // symbol /
    // native fault no-ops, the flag keeps its current/default value). INERT-safe by construction:
    // the Rust
    // global already holds the privacy-first default, so a swallowed call leaves correct behaviour.
    // Called
    // from [pillar.kuma_saimono.libumdnscrypt.dns_engine.ResolverRuntime.applyDnsmasqTogglesFromPref] at
    // configure.

    /**
     * P12 `--stop-dns-rebind`: enforce (drop) public names that resolve to a private IP. Default
     * OFF (observe-only).
     */
    fun setRebindEnforce(on: Boolean) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetRebindEnforce(on)
            } catch (t: Throwable) {}
    }

    /**
     * The CLIENT-DoH BOOTSTRAP SINKHOLE. A browser with Secure DNS on resolves its OWN DoH
     * endpoint through Tortä exactly once and then tunnels every subsequent name to that provider —
     * invisible to Warden, the blocklist, Centauri and MaskSolver alike. MEASURED 2026-08-01: a
     * page rendered fully while `cache/query.log` recorded ZERO rows for it; the only rows for the
     * whole page were three lookups of `brave.cloudflare-dns.com`.
     *
     * Armed, the resolver denies the curated bootstrap set with zero egress, so the browser falls
     * back to system DNS (Tortä) and the pillars see the traffic again. Default OFF — a user
     * deliberately running DoH is making a legitimate choice.
     */
    fun setDohSinkhole(on: Boolean) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetDohSinkhole(on)
            } catch (t: Throwable) {}
    }

    /** The LIVE armed state of the DoH sinkhole, so a switch renders its real state. */
    fun dohSinkholeOn(): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverDohSinkholeOn()
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /**
     * How many DoH bootstrap queries the sinkhole has denied this process. The only honest answer
     * to "is it doing anything": a tile reading 0 while a browser browses means the sinkhole is not
     * reaching the bypass.
     */
    fun dohSinkholeDenied(): Long =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverDohSinkholeDenied()
            } catch (t: Throwable) {
                0L
            }
        } else {
            0L
        }

    /**
     * P12 R5 `--bogus-priv`: NXDOMAIN reverse (PTR) lookups of RFC1918/ULA/link-local IPs locally.
     * Default OFF.
     */
    fun setBogusPriv(on: Boolean) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetBogusPriv(on)
            } catch (t: Throwable) {}
    }

    /**
     * P12 N3 `--proxy-dnssec`: pass the upstream AD bit through on a live forward (awareness, never
     * validation). Default OFF.
     */
    fun setProxyDnssec(on: Boolean) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetProxyDnssec(on)
            } catch (t: Throwable) {}
    }

    /**
     * P12 N1 `--filter-rr`: strip the [dropTypesCsv] RR TYPE codes (comma-separated, e.g. "65,64")
     * from the answer section and, when [anyDefang], defang ANY replies (RFC 8482) before caching.
     * An empty CSV with [anyDefang]=false disables the filter. Safe default (the dashboard bool
     * maps to ANY-defang only — it never strips A/AAAA, so apps never break).
     */
    fun setFilterRr(dropTypesCsv: String, anyDefang: Boolean) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetFilterRr(dropTypesCsv, anyDefang)
            } catch (t: Throwable) {}
    }

    /**
     * P12 R2 cloak/block action for a blocked name: [action] 0 = NXDOMAIN (deny), 1 = ZeroSink
     * (0.0.0.0/::), 2 = CustomIp parsed from [customIp]. A bad/empty [customIp] under action 2
     * safe-falls to NXDOMAIN on the Rust side. Default NXDOMAIN.
     */
    fun setCloakAction(action: Int, customIp: String) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetCloakAction(action, customIp)
            } catch (t: Throwable) {}
    }

    /** P12 N2 `--cache-rr`: cache SVCB/HTTPS answer records (speeds modern sites). Default ON. */
    fun setCacheRr(on: Boolean) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetCacheRr(on)
            } catch (t: Throwable) {}
    }

    /**
     * ★ E-FIX r5 (R5-Q1) — arm (non-blank [file]) or DISARM (blank) the `cache/query.log` FEED for
     * Rust-answered datapath queries. [file] is the EFFECTIVE `dnscrypt-proxy.toml`
     * `[query_log] file` value — the SAME enable the Go producer obeys — so the feed exists exactly
     * when query logging was explicitly opted into (DEBUG enabler / the user's query-log toggle);
     * release default stays OFF with zero writes. Rust then appends one Go-shape TSV row per query
     * the sovereign MODE-2 pool ANSWERS (rows the Go writer structurally cannot see — the round-5
     * foreign-traffic regression), while MODE-1 loopback forwards stay the Go writer's own rows.
     * Driven on the DNSCrypt RUNNING edge; disarmed ("") on STOP. Crash-proof facade.
     */
    fun resolverArmQueryFeed(file: String) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverArmQueryFeed(file)
            } catch (t: Throwable) {}
    }

    /**
     * P12 R6 `--all-servers`: race every upstream concurrently (first Ok wins) vs the strict-order
     * ladder. Default OFF.
     */
    fun setAllServers(on: Boolean) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetAllServers(on)
            } catch (t: Throwable) {}
    }

    /**
     * P12 `--never-forward`: keep RFC 6761/8375 special-use + private PTR names LOCAL (never
     * egress). Default ON.
     */
    fun setNeverForward(on: Boolean) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetNeverForward(on)
            } catch (t: Throwable) {}
    }

    /**
     * SOLVE-cross `--solve-ladder`: arm the verdict-gated, health-ordered, bounded resolution ladder
     * (retry a soft-failed upstream down the ranked slate before conceding). Default OFF (byte-identical
     * egress). The MaskSolver SETTINGS Expert toggle (#47) drives this through TortaPillarBridge.
     */
    fun setSolveLadder(on: Boolean) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetSolveLadder(on)
            } catch (t: Throwable) {}
    }

    /**
     * RFC 8767 serve-stale window (seconds): when > 0, an EXPIRED cache entry may still be served up to
     * this bound (epoch-gated — a re-armed blocklist still invalidates), buying resilience on a flaky
     * upstream. 0 = OFF (default). Live-arms the held cache + records the durable intent so a reconfigure
     * preserves it. The MaskSolver SETTINGS Expert cache knob (#47).
     */
    fun setServeStale(secs: Int) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetServeStale(secs)
            } catch (t: Throwable) {}
    }

    /**
     * Positive-TTL floor `min-cache-ttl` (seconds): clamp an answer's stored TTL up to at least this, so
     * a short-TTL name is not re-fetched every few seconds. 0 = no floor (default). The MaskSolver
     * SETTINGS Expert cache knob (#47).
     */
    fun setTtlFloor(secs: Int) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetTtlFloor(secs)
            } catch (t: Throwable) {}
    }

    /**
     * Positive-TTL ceiling `max-cache-ttl` (seconds): clamp an answer's stored TTL down to at most this,
     * bounding how long a stale/rotated IP survives. 0 -> the 24h default. The MaskSolver SETTINGS
     * Expert cache knob (#47).
     */
    fun setTtlCeiling(secs: Int) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetTtlCeiling(secs)
            } catch (t: Throwable) {}
    }

    /**
     * `--cache-size` — the RAM-hot cache capacity (clamped >= 1 on the Rust side). Records the durable
     * intent so a reconfigure keeps the size AND resizes the held cache immediately (shrinking evicts the
     * coldest evictable entries now). The MaskSolver SETTINGS staged cache-cap commits here (#47).
     */
    fun setCacheCap(cap: Int) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetCacheCap(cap)
            } catch (t: Throwable) {}
    }

    /**
     * The per-query deadline OVERRIDE in milliseconds (0 = honour the Pool's own configured timeout). Every
     * exchange path consults it on the NEXT query — no reconfigure. The MaskSolver SETTINGS staged
     * `timeout` commits here (#47).
     */
    fun setQueryTimeout(ms: Int) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.resolverSetQueryTimeout(ms)
            } catch (t: Throwable) {}
    }

    // ---- #49 THE BEAST live-tune write edges — the Yeah TCP/UDP congestion brain + the Soft-cake /
    // Mochi-Dango scheduler, re-tuned on the ONE process-global Beast (LIVE_BEAST) the DNS datapath
    // feeds. Crossing the SAME libtorta_core.so the snapshot reads, firewalled ensureLoaded()+catch so a
    // missing symbol / native fault degrades to the compiled default (LineRate × SoftCake). The Beast
    // SETTINGS pane's Apply commits here; the ResolverRuntime restore re-pushes on every datapath start.

    /**
     * Swap the live Yeah TCP/UDP congestion BRAIN: 0 Legacy · 1 Canonical · 2 LineRate (the new
     * line-rate congestion algorithm bound to Yeah). Re-seeds the controller — the window resets to the
     * profile default, so tunables must be re-applied AFTER (see [beastSetTunables]).
     */
    fun beastSetYeahProfile(id: Int) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.beastSetYeahProfile(id)
            } catch (t: Throwable) {}
    }

    /**
     * Swap the live Soft-cake / Mochi-Dango scheduler QUEUE law: 0 Legacy-AQM · 1 CoBALT (the SoftCake
     * profile). Re-seeds the scheduler.
     */
    fun beastSetCakeProfile(id: Int) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.beastSetCakeProfile(id)
            } catch (t: Throwable) {}
    }

    /**
     * Override the live YeAH tunables: window ceiling + free / compete thresholds (both milli — 1050 =
     * 1.05). Each arg 0 = leave the engine's current value untouched (don't-clobber), so a partial
     * restore never stomps a live default. Apply this AFTER a profile swap (a re-seed resets the window).
     */
    fun beastSetTunables(maxWindow: Int, freeThreshMilli: Int, competeThreshMilli: Int) {
        if (ensureLoaded())
            try {
                uniffi.torta_core.beastSetTunables(maxWindow, freeThreshMilli, competeThreshMilli)
            } catch (t: Throwable) {}
    }

    /**
     * P12 RAM⊗NAND — GENTLE control-plane persist of the live answer cache to the NAND [dir] (the
     * app-private durable dir). Returns bytes written (0 = nothing/unavailable). Call on a
     * control-plane edge (DNSCrypt stop / a checkpoint), NEVER per-query — the Rust side releases
     * the cache lock before the NAND IO. Crash-proof.
     */
    fun persistCache(dir: String): Int =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverPersistCache(dir)
            } catch (t: Throwable) {
                0
            }
        } else {
            0
        }

    /**
     * P12 RAM⊗NAND — rehydrate the answer cache from the NAND [dir] into the freshly-configured
     * cache. Returns the count of still-valid entries restored (0 = cold start / unavailable). Call
     * once at configure time (after the pool is up). A missing/corrupt snapshot is a cold start,
     * never a fault. Crash-proof.
     */
    fun rehydrateCache(dir: String): Int =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverRehydrateCache(dir)
            } catch (t: Throwable) {
                0
            }
        } else {
            0
        }

    // ---- D33a/D33b · P12 local records + conditional routing façades ----
    // The three engine-complete dnsmasq features FED: the local-record pin store (`local.rs`, the
    // step-1.5a zero-egress positive answers), the conditional-routing store (`routes_store.rs`,
    // feeding `routing::parse_routes` through the specs `"routes"` key), and DNS64 (already driven
    // by dnscryptConfigApply, D09). Typed Records across the FFI — never a summary-string parse.
    // All control-plane: editor saves + the boot rehydrate; the resolve hot path never crosses here.

    /**
     * D33a — the local-records editor SAVE: parse the `/etc/hosts`-style [text], REPLACE the live
     * pin store (a deleted line unpins — effective on the very next query; ttl 0 = dnsmasq's
     * `local-ttl` do-not-cache default, Rust-side), and persist the raw text into the durable
     * `resolver-local-records` record under [dir] (empty text clears both). Returns the typed
     * report, or null when the `.so` is unreachable. Crash-proof.
     */
    fun localRecordsSet(text: String, dir: String): uniffi.torta_core.LocalRecordsReport? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverLocalRecordsSet(text, 0L, dir)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * D33a — the local-records editor LOAD: the persisted hosts-text verbatim (comments kept), or
     * "" when cold/cleared/unavailable. Crash-proof.
     */
    fun localRecordsText(dir: String): String =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverLocalRecordsText(dir)
            } catch (t: Throwable) {
                ""
            }
        } else {
            ""
        }

    /**
     * D33a — the BOOT edge (RuntimeTierManager pillar 6): re-apply the persisted local records to
     * the live pin store. Cold record ⇒ an all-zero report (silent no-op, byte-identical to a
     * fresh install); unreachable `.so` ⇒ null. Crash-proof.
     */
    fun localRecordsRehydrate(dir: String): uniffi.torta_core.LocalRecordsReport? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverLocalRecordsRehydrate(dir)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * D33a — the live pinned-NAME count (the dashboard gauge; one relaxed atomic read Rust-side).
     * 0 on empty/unavailable. Crash-proof.
     */
    fun localRecordsCount(): Long =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverLocalRecordsCount()
            } catch (t: Throwable) {
                0L
            }
        } else {
            0L
        }

    /**
     * D33b — the conditional-routing editor SAVE: parse the dnsmasq-style rules
     * (`server=/suffix/upstream-id` · `address=/suffix/ip`), persist the raw text into the durable
     * `resolver-routes` record under [dir] (empty clears). Rules feed the Router at the NEXT
     * configure edge (the value-only settings contract — never a live re-arm). Typed report, or
     * null when unreachable. Crash-proof.
     */
    fun resolverRoutesSet(text: String, dir: String): uniffi.torta_core.RouteLinesReport? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverRoutesSet(text, dir)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * D33b — the routing editor LOAD: the persisted rule text verbatim, or "" when
     * cold/cleared/unavailable. Crash-proof.
     */
    fun resolverRoutesText(dir: String): String =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverRoutesText(dir)
            } catch (t: Throwable) {
                ""
            }
        } else {
            ""
        }

    /**
     * D33b — the ready `"routes"` specs-JSON array (Rust-parsed + Rust-escaped from the durable
     * store), or "" when no usable rule exists. [ResolverRuntime]'s `buildSpecsJson` embeds it
     * verbatim so `resolver::configure`'s `parse_routes` finally receives production rules. Dies
     * with the flat specs seam when the typed configure migration lands (`resolverRoutesList` is
     * the typed successor, already exported). Crash-proof.
     */
    fun resolverRoutesJson(dir: String): String =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverRoutesJson(dir)
            } catch (t: Throwable) {
                ""
            }
        } else {
            ""
        }

    // ---- D07 (read side) · the MaskSolver typed snapshot façade ----

    /**
     * D07 — the ONE held MaskSolver delegating handle (NO-FORK law: the Object wraps the same
     * process-global RESOLVER the flat fns read — `resolver/object.rs`, a cold handle over the
     * already-inited global, zero engine fork). Lazily constructed, crash-proof (an unreachable
     * `.so` / a ctor fault leaves it null and every read falls back to the flat path).
     */
    private val maskSolverHandle: uniffi.torta_core.MaskSolver? by lazy {
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.MaskSolver()
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }
    }

    /**
     * D07 (read side) — the typed [uniffi.torta_core.MaskSolverSnapshot] over the SAME live stats
     * the flat [resolverStats] JSON renders (single-source, Rust-computed rates, panic-firewalled
     * Rust-side to honest zeros). Null when the `.so`/handle is unavailable — callers fall back to
     * the flat parse (NO-BREAK). The dnsmasq dashboard card reads THIS instead of hand-parsing
     * JSON; the remaining two flat-parse sites (ResolverRuntime, DnsEngineMetrics) migrate on
     * their own waves.
     */
    fun maskSolverSnapshot(): uniffi.torta_core.MaskSolverSnapshot? =
        try {
            maskSolverHandle?.snapshot()
        } catch (t: Throwable) {
            null
        }

    /**
     * D34 — THE ROTATION headline read over the MaskSolver Object: the typed
     * [uniffi.torta_core.RotationSnapshot] (family/cadence/index + the FULL warm-RTT
     * [uniffi.torta_core.RttHint] list + the `rehydratedWarm` #98 crown flag) of the
     * LAST-PERSISTED durable rotation record — the full-power twin of the flat
     * `"family=… cadence=… index=… hints=<n>"` summary string [rehydrateResolverRotation]
     * returns (which stays a NO-BREAK twin for the boot-driver log line). Binds the ONE held
     * [maskSolverHandle] to [dir] first (idempotent config — every durable consumer passes the
     * SAME process-wide runtime-tier root; `bind_durable` sets a read target and arms nothing on
     * the datapath). A control-plane READ, never the resolve hot path. Null when the
     * `.so`/handle is unavailable — the caller falls back to the flat parse (NO-BREAK).
     */
    fun maskSolverRotationSnapshot(dir: String): uniffi.torta_core.RotationSnapshot? =
        try {
            maskSolverHandle?.let {
                it.bindDurable(dir)
                it.rotationSnapshot()
            }
        } catch (t: Throwable) {
            null
        }

    // ---- Signature-verify façades (base .so) ----
    // Crash-proof faces over the Rust `signature::verify_minisign` engine (the same one the
    // blocklist trust channel uses): a boolean verdict, fail-closed to `false` on any
    // tamper/mismatch/fault/missing `.so`. INERT until invoked — a caller verifies a bundled
    // artifact on demand; nothing on the live DNS flow calls them.

    /**
     * Verify a minisign Ed25519 signature [sig] over [bytes] against the pinned [pubkey] blob (the
     * Rust `signature::verify_minisign` engine). Returns true ONLY for a genuine, pinned-key
     * signature; false on any tamper/mismatch/malformed input, a native fault, or a missing `.so`.
     * Safe default: false ("unverified").
     */
    fun fortressVerifyBytes(bytes: ByteArray, sig: ByteArray, pubkey: ByteArray): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.fortressVerifyFile(bytes, sig, pubkey)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /**
     * Verify a signed blocklist artifact [listBytes] against its detached [sig] and pinned [pubkey]
     * (the Rust `signature::verify_minisign` engine). The blocklist-trust seam. Returns true
     * ONLY for a genuine pinned-key signature; false on any tamper/mismatch/fault/missing `.so`.
     * Safe default: false.
     */
    fun fortressVerifyList(listBytes: ByteArray, sig: ByteArray, pubkey: ByteArray): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.fortressVerifyList(listBytes, sig, pubkey)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /**
     * Verify the bundled `dnscrypt-proxy` binary [binBytes] against its detached [sig] and pinned
     * [pubkey] (the Rust `signature::verify_minisign` engine — a binary is just a signed file). The
     * binary-attestation seam. Returns true ONLY for a genuine pinned-key
     * signature; false on any fault. Default: false.
     */
    fun fortressVerifyDnscryptProxy(
        binBytes: ByteArray,
        sig: ByteArray,
        pubkey: ByteArray,
    ): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.fortressVerifyDnscryptProxy(binBytes, sig, pubkey)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    // ---- THE WARDEN façade (W6 — the observe-only verdict-stream stats read-back) ----

    /**
     * The Warden's aggregate verdict-stream stats as a JSON string (W6 slice-1), or "unavailable"
     * if the lib can't be reached. The block-wins verdict tally — allow/deny counts split by which
     * gate denied (firewall vs blocklist) — read straight off the Rust core's `verdict_at` counter
     * behind the W3 global Warden singleton. **AGGREGATE COUNTS ONLY** — no qname, no domain, no
     * UID, no per-connection history ever leaves the engine (the same "no qname ever" privacy law
     * as [resolverStats], T20).
     *
     * When the Warden is **disarmed/None** (the user having disarmed it — `WARDEN_NATIVE_ENABLED` is
     * default-ON, the Socio all-ON contract 2026-06-24; when disarmed the verdict path is never reached) the JSON
     * reports `configured:false` with zero counts: the W6 card renders an honest "off" headline.
     * Crash-proof, exactly the [resolverStats] shape: a base `.so` without `nativeWardenStats`, or
     * any native fault, degrades to "unavailable" — never an UnsatisfiedLinkError taking down the
     * app, never a fabricated number. Cheap (an in-memory counter read, no IO), so it is safe to
     * poll on the dashboard metrics cadence. Never throws.
     */
    fun wardenStats(): String =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.wardenStats() ?: WARDEN_STATS_UNAVAILABLE
            } catch (t: Throwable) {
                WARDEN_STATS_UNAVAILABLE
            }
        } else {
            WARDEN_STATS_UNAVAILABLE
        }

    // ---- Centauri Local Mirror façades (Rust `mirror` cargo feature; inert on a base .so) ----
    // The symbols exist ONLY in a `--features mirror` build. On the BASE android .so the native
    // call throws
    // UnsatisfiedLinkError → caught here → the safe fallback. So a no-mirror build degrades to
    // inert (the
    // facade returns null/false/-1), exactly the crash-proof contract — never an
    // UnsatisfiedLinkError escapes.

    /**
     * Verify a Centauri catalog: [bytes] (the catalog body) against its detached signature [sig]
     * under the pinned [pubkey] — verify-sig-FIRST (the same boundary as the C3 artifact channel),
     * via `mirror::Catalog::parse_verified`. Returns true ONLY for a genuine pinned-key catalog;
     * false on any tamper/malformed/fault/missing-symbol (base .so). Safe default: false.
     */
    fun centauriCatalogVerify(bytes: ByteArray, sig: ByteArray, pubkey: ByteArray): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.mirrorInstallCatalog(bytes, sig, pubkey)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /**
     * Start the OPT-IN in-app loopback mirror server, binding 127.0.0.1 on an OS-assigned ephemeral
     * port. The Rust #92 start export (`nativeCentauriMirrorStart`, `--features mirror` only)
     * lazily builds/holds the on-disk-backed native `CacheStore` rooted at [cacheDir]
     * (`with_dir`+`load_from_disk` rehydration), spawns the hyper accept loop on a mirror-local
     * runtime, and returns the bound port (>0). Loopback-only by contract (never `0.0.0.0`/LAN);
     * fail-closed serve (verify-sig-FIRST catalog, hash-only cache); panic-firewalled Rust side.
     *
     * Returns the bound port (>0) on success, or **null** on every failure mode — a missing/base
     * `.so` (UnsatisfiedLinkError on a no-mirror build), the negative sentinel
     * [MIRROR_START_FAILED] the Rust side returns on any bind/runtime fault, or any thrown error.
     * Null is the manager's "did not start" contract: it degrades to inert, never crashes. Same
     * crash-proof shape as [centauriMirrorStats]; never throws.
     */
    fun centauriMirrorStart(cacheDir: String): Int? =
        if (ensureLoaded()) {
            try {
                val port = uniffi.torta_core.centauriMirrorStart(cacheDir)
                if (port > 0) port else null // negative sentinel (MIRROR_START_FAILED) ⇒ inert
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * Mirror dashboard feed — "libraries=<N> bytes=<X> full=<bool>" from the live cache stats (the
     * numbers are REAL cache stats only, never faked). Returns "unavailable" on a fault / a base
     * .so without the mirror feature. Never throws.
     */
    fun centauriMirrorStats(): String =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.mirrorStatus() ?: "unavailable"
            } catch (t: Throwable) {
                "unavailable"
            }
        } else {
            "unavailable"
        }

    /**
     * The Centauri LocalCDN cloak host set (#134) — the ~65 CDN hosts the local mirror covers (the
     * opt-out local-CDN binding). Each listed host, when cloaked, answers as 127.0.0.1 so the
     * request lands on the loopback mirror instead of the real CDN (the CDN sees <=1 request — the
     * crown). The Rust `centauriCdnHosts` export (`--features mirror` only) returns the
     * sorted+deduped STATIC set (the host list is not secret — only served content is signed +
     * content-addressed). This is the source the dnscrypt cloaking-rules write + the Centauri
     * dashboard consume. Returns an empty list on a base .so / any fault. Never throws.
     */
    fun centauriCdnHosts(): List<String> =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.centauriCdnHosts()
            } catch (t: Throwable) {
                emptyList()
            }
        } else {
            emptyList()
        }

    /**
     * Resolve a CDN URL (a cloaked CDN [host] + its `/lib/version/file` [path]) to the canonical
     * Centauri asset name (`<library>/<servedVersion>/<file>`, host-independent, version-fallback
     * applied), or null if the URL is not a mapped LocalCDN library. The "what would be served"
     * query (#134), via the Rust `centauriResolveCdn` export (`--features mirror` only). Returns
     * null on an unmapped URL / a base .so / any fault. Never throws.
     */
    fun centauriResolveCdn(host: String, path: String): String? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.centauriResolveCdn(host, path)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * The dnscrypt cloaking-rules block (#134) for the opt-out local-CDN binding — one `<host>
     * 127.0.0.1` line per cloaked CDN host, fenced by `# BEGIN/END Centauri LocalCDN cloak` markers
     * so a writer splices it into `app_data/dnscrypt-proxy/cloaking-rules.txt` without clobbering
     * the user's own rules. This is the rules TEXT only — writing it + reloading dnscrypt is the
     * arming step gated behind the Expert `CENTAURI_MIRROR_ENABLED` flag (default-off), so fetching
     * the rules changes no DNS behaviour on its own. Returns an empty string on a base .so / any
     * fault. Never throws.
     */
    fun centauriCloakingRules(): String =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.centauriCloakingRules()
            } catch (t: Throwable) {
                ""
            }
        } else {
            ""
        }

    // ---- R1.x.2 THE CENTAURI OBJECT (the stateful Object lift — the Beast pattern applied to P9 E')
    // ----
    // The Centauri mirror is now a `#[derive(uniffi::Object)]` on the Rust side (mirror-gated,
    // `--features mirror` only): Kotlin will hold an `Arc<Centauri>` handle, construct it ONCE at
    // boot with the app-private cache_dir, and drive its methods. This is ADDITIVE to the flat fns
    // above (which stay live — CentauriMirrorManager's `centauriMirrorStart`/`centauriMirrorStats`
    // + CentauriArtifactManager consume them today; the resolver/serve datapath is Rust-INTERNAL:
    // `centauri_resolve_cdn` → `mirror::resolve_full` → `localcdn::resolve_full`, and the loopback
    // `serve_cdn_url` calls the SAME `localcdn::resolve_full` server-side — NO Kotlin path resolves
    // CDN URLs at runtime). The Object gives the CentauriMirrorManager a LIVED accumulator (the
    // content-addressed CacheStore + the bound loopback port + the catalog/resolve counters) instead
    // of the process-global OnceLock singleton reachable only through the flat exports. The
    // MIRROR_RUNTIME singleton keeps driving the LIVE serve loop + `mirror_status` reads the SAME
    // store the loopback serves — the Object is alongside, NOT a replacement, so the read-stats-vs-
    // serve-bytes identity invariant holds for the flat path until the Socio's bindgen regen swaps
    // the call-sites. Math UNCHANGED: every Object method delegates to the SAME pure fns the flat
    // exports wrap (`mirror::Catalog::parse_verified`, `cdn_hosts`, `resolve_full`, `cloaking_rules`,
    // `CacheStore::len/total_bytes/is_full/capacity`, `load_centauri_from_signed`).
    //
    // **LIVE (D07 — the Object AWAKENED).** The `uniffi.torta_core.Centauri` / `CentauriSnapshot` /
    // `CentauriServeRecord` / `CentauriWarmUpReport` Kotlin types ARE generated (the Stage-C regen off
    // the `--features mirror,pure_rust` non-stripped dll — the R-Beast-Wire.1 lesson honored), so the
    // facades below are REAL: CentauriMirrorManager constructs ONE handle at its RUNNING edge, installs
    // the staged signed catalog, starts the loopback (which serves the Object's LIVE shared store +
    // self-feeds the recent-serve ring / CROWN counters / query-centauri.log — D29), drives the TIER-B
    // `warmUp` batch (D04), and the dashboards read the typed snapshot instead of the flat stats string.
    // The flat fns above STAY LIVE as the NO-BREAK fallback (a base `.so` degrades to them).

    /**
     * Construct the stateful Centauri Object rooted at the app-private [cacheDir] (rehydrates the
     * on-disk content-addressed cache at construction). Returns null if the lib is missing (base
     * `.so`) or construction faults. Never throws.
     */
    fun centauriCreate(cacheDir: String): CentauriHandle? =
        if (ensureLoaded()) {
            try {
                CentauriHandle(uniffi.torta_core.Centauri(cacheDir))
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * Verify-sig-FIRST catalog install via the Object (retains the verified catalog so the loopback
     * SERVES it). Tallies the attempt + the verified outcome into the Object's lived counters.
     * Returns false on any fault (a bad signature surfaces as the typed CentauriException, caught +
     * logged as false — fail-closed, nothing installed). Never throws.
     */
    fun centauriInstallCatalogObject(
        centauri: CentauriHandle?, bytes: ByteArray, sig: ByteArray, pubkey: ByteArray
    ): Boolean {
        val handle = centauri ?: return false
        return if (ensureLoaded()) {
            try {
                handle.delegate.installCatalog(bytes, sig, pubkey)
                true
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }
    }

    /**
     * Start the loopback mirror via the Object (idempotent — returns the already-bound port on a
     * second call). The loopback serves the Object's LIVE shared store + the retained installed
     * catalog, and self-feeds the serve review channel (recent ring + CROWN counters +
     * query-centauri.log — D29). Returns the bound port (>0) or null on any failure. Never throws.
     */
    fun centauriStartObject(centauri: CentauriHandle?): Int? {
        val handle = centauri ?: return null
        return if (ensureLoaded()) {
            try {
                val port = handle.delegate.start()
                if (port > 0) port else null
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }
    }

    /**
     * The structured Centauri status snapshot via the Object (cache stats + serve port + catalog
     * assets + the lived CROWN counters) — the typed read the dashboards render instead of the flat
     * stats string (D07). Returns null on any fault. Never throws.
     */
    fun centauriSnapshotObject(centauri: CentauriHandle?): uniffi.torta_core.CentauriSnapshot? {
        val handle = centauri ?: return null
        return if (ensureLoaded()) {
            try {
                handle.delegate.snapshot()
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }
    }

    /**
     * The most recent serve events via the Object (newest-first, bounded ring — self-fed by the LIVE
     * accept loop, D29): the dashboard's "what the mirror just served" feed. Empty on any fault.
     * Never throws.
     */
    fun centauriRecentServes(
        centauri: CentauriHandle?, max: Int
    ): List<uniffi.torta_core.CentauriServeRecord> {
        val handle = centauri ?: return emptyList()
        return if (ensureLoaded()) {
            try {
                handle.delegate.recentServes(max.coerceIn(0, 256).toUInt())
            } catch (t: Throwable) {
                emptyList()
            }
        } else {
            emptyList()
        }
    }

    /**
     * Run a TIER-B warm-up batch via the Object (D04): self-fill up to [maxTargets] catalog assets
     * from their real CDNs (each ≤1 hash-gated request EVER; already-cached/uncatalogued targets cost
     * 0). BLOCKING for the batch duration — call from Dispatchers.IO only. With no installed catalog
     * it is an honest zero-target no-op (no egress). Returns null on any fault. Never throws.
     */
    fun centauriWarmUp(
        centauri: CentauriHandle?, maxTargets: Int
    ): uniffi.torta_core.CentauriWarmUpReport? {
        val handle = centauri ?: return null
        return if (ensureLoaded()) {
            try {
                handle.delegate.warmUp(maxTargets.coerceIn(0, 256).toUInt())
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }
    }

    /**
     * Sovereign on-device catalog ARMING via the Object — the living CDN-encyclopedia's boot faculty.
     * Load-or-MINT this install's DeviceKey under [keyDir], seed the Object's shared cache with the
     * app-OWNED + transplanted content the `content.tsv` manifest under [contentDir] names, grow the SEEN
     * cloak roster over every watched CDN host, then author + install a device-signed catalog so the
     * loopback SERVES it all with ZERO egress. RAM⊗NAND-durable: the seeded bytes write through to the
     * content-addressed cache dir and the device key persists under [keyDir], so a reboot rehydrates the
     * transplanted content + reloads the SAME authority. Panic-firewalled on the Rust side to a zeroed
     * report; returns null only on a native fault / base `.so`. Never throws.
     */
    fun centauriArmDeviceCatalog(
        centauri: CentauriHandle?, contentDir: String, keyDir: String
    ): uniffi.torta_core.CentauriArmReport? {
        val handle = centauri ?: return null
        return if (ensureLoaded()) {
            try {
                handle.delegate.armDeviceCatalog(contentDir, keyDir)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }
    }

    /**
     * THE SOVEREIGN BOOT LANE — rehydrate the DEVICE-authored catalog pair (`device-catalog.tcat`
     * + `.sig`, the RAM⊗NAND artifact [centauriArmDeviceCatalog]'s arming pass persists) against
     * THIS device's OWN key under [keyDir]. The pubkey never crosses the FFI — the Rust side loads
     * (or First-Boot mints) the DeviceKey and verifies sig-FIRST; a genuine pair RETAINS as the
     * serve authority WITHOUT re-hashing the content dir (the fast boot). Returns true IFF verified
     * + retained; false on the honest First-Boot absent pair / tamper / foreign key / native fault
     * (the caller falls back to the arming pass, which re-authors + re-persists). Never throws.
     */
    fun centauriRehydrateDeviceCatalog(centauri: CentauriHandle?, keyDir: String): Boolean {
        val handle = centauri ?: return false
        return if (ensureLoaded()) {
            try {
                handle.delegate.rehydrateDeviceCatalog(keyDir)
                true
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }
    }

    /**
     * The on-disk path of the per-pillar `query-centauri.log` via the Object (a sibling of the
     * content-addressed cache dir — the D29 review channel; feed it to the log-tail readers).
     * Empty on any fault. Never throws.
     */
    fun centauriQueryLogPath(centauri: CentauriHandle?): String {
        val handle = centauri ?: return ""
        return if (ensureLoaded()) {
            try {
                handle.delegate.queryCentauriLogPath()
            } catch (t: Throwable) {
                ""
            }
        } else {
            ""
        }
    }

    /**
     * Arm/disarm the P9 Centauri DNS-plane cloak (D05): armed, the Rust resolver answers every
     * watched-CDN host (the LocalCDN map set) LOCALLY as `127.0.0.1` at resolve step 1.5b-cdn — the
     * request lands on the in-app loopback mirror, ZERO egress, the CDN never sees it (the opt-out
     * local-CDN crown). OFF by default; CentauriMirrorManager arms it ONLY when the mirror is serving
     * AND a verified catalog authorizes assets (the F9 no-blackhole law — an empty catalog never
     * cloaks). Lock-free + idempotent on the Rust side; inert on a base `.so`. Never throws.
     */
    fun resolverSetCentauriCloak(on: Boolean) {
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.resolverSetCentauriCloak(on)
            } catch (t: Throwable) {
                // base .so / native fault ⇒ the cloak stays in its previous (default-off) state.
            }
        }
    }

    /**
     * ★ #65 HTTPS serve leg — arm local TLS termination so a cloaked `https://` CDN asset can be
     * SERVED FROM THIS DEVICE instead of fetched from the CDN on every page load.
     *
     * This is what makes Centauri's promise hold on `:443`: absorb the asset at most ONCE, then serve
     * it from the local content-addressed store forever, so the CDN never sees the user again.
     *
     * Pass a previously persisted PEM pair to REUSE the CA the user already trusts; pass `null` on
     * first run to mint one. Returns the material to persist (cert = public, key = app-private ONLY),
     * or `null` if arming failed — the seam then stays disarmed rather than half-armed.
     */
    fun centauriTlsArm(certPem: String?, keyPem: String?): uniffi.torta_core.CentauriCaMaterial? {
        if (!ensureLoaded()) return null
        return try {
            uniffi.torta_core.centauriTlsArm(certPem, keyPem)
        } catch (t: Throwable) {
            // base .so (no `mirror` feature) / native fault ⇒ HTTPS serve leg simply stays disarmed.
            null
        }
    }

    /**
     * ★ #65 — how many CDN assets this engine has absorbed into the content-addressed store.
     *
     * MUST be read from the SERVICE's engine: `torta_ui` statically links its own `torta_core`
     * whose `absorb::arm()` never ran, so asking that copy always answers 0 (task #74).
     */
    fun centauriAbsorbCount(): UInt {
        if (!ensureLoaded()) return 0u
        return try {
            uniffi.torta_core.centauriAbsorbCount()
        } catch (t: Throwable) {
            // base .so (no `mirror` feature) / native fault ⇒ report nothing rather than guess.
            0u
        }
    }

    /**
     * ★ #22 — hand every TLS-refused host back to the cloak and wipe the durable refusal ledger.
     *
     * Returns how many hosts were freed. The engine clears RAM and the on-disk ledger together, so a host
     * freed here stays free across process death instead of being re-refused on the next arm.
     */
    /**
     * Publish whether this device's client store actually trusts the Centauri device CA.
     *
     * The first conjunct of the engine's `is_servable_cloak_host` gate. It defaults to FALSE and,
     * until 2026-08-01, nothing in the app ever set it — the publisher existed in Rust but was
     * reachable only from test code and was absent from the UniFFI surface. The result was a
     * permanently dark offline-CDN behind a dashboard that said "serving".
     */
    fun centauriPublishCloakTlsTrust(trusted: Boolean) {
        if (!ensureLoaded()) return
        try {
            uniffi.torta_core.centauriPublishCloakTlsTrust(trusted)
        } catch (t: Throwable) {
            // base .so (no `mirror` feature) ⇒ there is no cloak to gate, so silence is correct.
        }
    }

    /** The trust conjunct alone, so a dashboard can EXPLAIN a dark offline-CDN. */
    fun centauriCloakTlsTrusted(): Boolean {
        if (!ensureLoaded()) return false
        return try {
            uniffi.torta_core.centauriCloakTlsTrusted()
        } catch (t: Throwable) {
            false
        }
    }

    /** How many watched hosts are BOTH catalogued and servable from the store. */
    fun centauriServableCloakCount(): Long {
        if (!ensureLoaded()) return 0L
        return try {
            uniffi.torta_core.centauriServableCloakCount()
        } catch (t: Throwable) {
            0L
        }
    }

    fun centauriTlsRetrust(): UInt {
        if (!ensureLoaded()) return 0u
        return try {
            uniffi.torta_core.centauriTlsRetrust()
        } catch (t: Throwable) {
            // base .so (no `mirror` feature) / native fault ⇒ freed nothing, and say so honestly.
            0u
        }
    }

    /** ★ #65 — how many hosts were PROMOTED into the cloak set by the discovery walk. */
    fun centauriPromotedCloakCount(): UInt {
        if (!ensureLoaded()) return 0u
        return try {
            uniffi.torta_core.centauriPromotedCloakCount()
        } catch (t: Throwable) {
            0u
        }
    }

    /** ★ #65 — how many hosts sit in the TLS-DISTRUST ledger (refused our CA, so left uncloaked). */
    fun centauriTlsDistrustCount(): UInt {
        if (!ensureLoaded()) return 0u
        return try {
            uniffi.torta_core.centauriTlsDistrustCount()
        } catch (t: Throwable) {
            0u
        }
    }

    /** ★ #65 — is local TLS termination live? A capability witness, never a remembered UI flag. */
    fun centauriTlsArmed(): Boolean {
        if (!ensureLoaded()) return false
        return try {
            uniffi.torta_core.centauriTlsArmed()
        } catch (t: Throwable) {
            false
        }
    }

    // (No `centauriSetCacheMode`: the CROWN is always-on `LeakOnMiss` — the Object's own Rust-side default
    //  where a miss tops up from the real CDN at most ONCE then serves locally forever, the growing-
    //  encyclopedia engine. `BlockMissing` would freeze growth, so no Kotlin path ever sets the cache mode;
    //  the strict toggle was removed end-to-end. The generated `Centauri.setCacheMode` binding still exists
    //  in `uniffi.torta_core` — it is simply never called from Kotlin.)

    /** Thin Kotlin wrapper over the generated Centauri Object handle (keeps CentauriMirrorManager
     * free of a direct generated-type dependency). */
    class CentauriHandle internal constructor(internal val delegate: uniffi.torta_core.Centauri)

    // ---- R1.x.3 THE WARDEN OBJECT (the stateful Object lift — the Beast pattern applied to the
    // ---- pure-firewall pillar; the 4th #[derive(uniffi::Object)] after Beast/Centauri) ----
    //
    // The Warden verdict engine is now a `#[derive(uniffi::Object)] WardenObject` on the Rust side
    // (ALWAYS-built — NOT feature-gated, the Beast precedent): Kotlin will hold an `Arc<WardenObject>`
    // handle, construct it ONCE at boot, install the device policy + the W-A rule-sets, drive the
    // per-connection `verdict`, and pull a `WardenSnapshot` for the dashboard. This is ADDITIVE to the
    // flat fns (`wardenConfigure`/`wardenStats` + the C-ABI `torta_firewall_verdict` stay live —
    // WardenStatsRepository consumes them today). The Object gives a LIVED handle
    // (policy + decision cache + stats + the W-A DomainRuleSet/CidrRuleSet/UniversalRule layer) instead
    // of the process-global `OnceLock<Mutex<Option<Warden>>>` reachable only through the flat exports.
    //
    // ** THE REWORKED PURE-FIREWALL VERDICT (Warden-REWORKED-design.md §2/§3). ** The Object's
    // `verdict(conn)` takes NO blocklist param — it is the PURE firewall (the blocklist is a SEPARATE
    // co-equal gate the datapath consults independently; the caller AND-s the two). Math UNCHANGED: the
    // Rust Object delegates to the EXISTING `Warden::verdict` with an empty no-op blocklist, so the
    // firewall half alone decides + the engine arithmetic is untouched (the W-B wave reworks the engine
    // signature + wires the held rule-sets into the compose; THIS wave HOLDS + COUNTS them).
    //
    // ** REALIZED (D01/D02/D03 — the bindgen regen landed). ** The `uniffi.torta_core.WardenObject` /
    // `WardenSnapshot` / `WardenVerdict` / `WardenConnFacts` / `WardenNetworkType` / `WardenDomainRule` /
    // `WardenCidrRule` / `WardenAppRow` / `WardenUniversalToggles` / `WardenUniversalRule` /
    // `WardenInstallReport` / `WardenException` Kotlin types are GENERATED and live. The Object is NOT held
    // here (a TortaCore-side handle would FORK a THIRD instance beside the datapath's): the SINGLE
    // process-global `WardenObject` the datapath queries is held + driven by
    // [pillar.kuma_saimono.libumdnscrypt.vpn.service.WardenDatapathGate] (the established native-facade idiom).
    // Its SOVEREIGN RAIL there is the one place every control-plane op lands — the arm rail (D01:
    // `installDomainRules`/`installCidrRules`/`setUniversalRules`/`setAppRow`/`setUniversalToggles`/
    // `setFailClosed`), the typed stats read (D02: `snapshot` — WardenStatsRepository consumes it,
    // killing the disarmed-flat-`warden_stats` split-brain), and durability (D03: `bindDurable` +
    // `expireTempAllows`, driven by RuntimeTierManager pillar 2). The flat `warden_stats` export stays a
    // NO-BREAK C-ABI twin (it reads the separate disarmed global — honest "off" — no live consumer now).

    /**
     * D27 — UI PRE-FLIGHT: validate ONE Warden domain rule against the RFC-1123 integrity gate WITHOUT
     * arming anything, for the add-rule screen (catch a poisoned `*.com` / bare TLD / illegal char BEFORE
     * install, with a human-legible reason). Returns `null` when the rule would arm, or the rejection
     * REASON string ([uniffi.torta_core.WardenException] message) when it would be refused. Crash-proof:
     * a missing `.so` / native fault returns `null` (fail-open on the pre-flight — the real gate still runs
     * at [WardenDatapathGate.installDomainRules] arm time). Never throws.
     */
    fun wardenValidatePattern(rule: String): String? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.wardenValidatePattern(rule)
                null // Ok(()) ⇒ the rule is valid.
            } catch (e: uniffi.torta_core.WardenException) {
                e.message ?: "invalid rule"
            } catch (t: Throwable) {
                null // base `.so` / native fault ⇒ fail-open pre-flight (the arm-time gate is authoritative).
            }
        } else {
            null
        }

    // ---- THE WARDEN W5 façades — boot-rehydrate the signed-source pillars (verify-sig-FIRST) ----

    /**
     * W5 boot-rehydrate of the BLOCKLIST from its signed `.tblk` durable source (Rust
     * `nativeRehydrateBlocklistFromSigned`, base `.so`). On the DNSCrypt-start / boot edge, reads
     * the on-flash pair `[dir]/[base]` (raw `.tblk`) + `[dir]/[base].sig` (the base64-DECODED
     * 74-byte minisign blob), runs the minisign gate over the RAW artifact against [pubkey] (the
     * base64-DECODED 42-byte pinned blob) FIRST, and ONLY on a genuine signature installs it into
     * the global matcher via the EXISTING artifact path. [merge] stacks onto the current list,
     * identical to the live install.
     *
     * Returns the armed domain count (> 0 typically) on a genuine rehydrate, or 0 on ANY failure —
     * an absent pair (a true cold start, NOT an error), a forged/tampered/wrong-key/truncated
     * signature, a malformed body, a missing `.so`, or a native fault. On 0 the global matcher is
     * left UNCHANGED (fail-safe: the in-memory tier still works; the durable source is
     * best-effort). NO raw NAND dump — the signed `.tblk` IS the durable tier. Crash-proof: never
     * throws.
     */
    fun rehydrateBlocklistFromSigned(
        dir: String,
        base: String,
        pubkey: ByteArray,
        merge: Boolean = false,
    ): Int =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.rehydrateBlocklistFromSigned(dir, base, pubkey, merge)
            } catch (t: Throwable) {
                0
            }
        } else {
            0
        }

    /**
     * W5 boot-rehydrate of the CENTAURI catalog from its signed `.tcat` durable source (Rust
     * `nativeRehydrateCentauriFromSigned`, `--features mirror` ONLY). Re-AUTHENTICATES the durable
     * catalog on boot — reads the `[dir]/[base]` + `[dir]/[base].sig` pair and re-runs the
     * verify-sig-FIRST catalog parse against the pinned [pubkey] blob (proving the signed source is
     * intact). The content cache's own durable tier is the content-addressed `cache.rs` store
     * (rehydrated by the mirror start seam), NOT re-dumped here.
     *
     * Returns true IFF a genuine `.tcat` verifies + parses; false on ANY failure (absent pair / bad
     * signature / malformed body), AND false on a BASE `.so` (no `mirror` feature → the symbol is
     * absent → UnsatisfiedLinkError caught → inert), or any native fault. Crash-proof: never
     * throws.
     */
    fun rehydrateCentauriFromSigned(dir: String, base: String, pubkey: ByteArray): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.rehydrateCentauriFromSigned(dir, base, pubkey)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /**
     * #61C — OFFLINE rehydrate of the Underground Layer's four SIGNED antivirus lane catalogs
     * (ads / trackers-analytics / malware / phishing) from [dir]: each lane's
     * `underground_<lane>.tcat` + `.tcat.sig` pair runs the SAME verify-sig-FIRST minisign gate as
     * [mirrorInstallCatalog], then merge-installs into the global matcher with per-lane provenance
     * (Rust `undergroundLoadLanes`, `--features mirror` ONLY).
     *
     * Returns the four TRUTHFUL per-lane armed domain counts in index order
     * ads/trackers-analytics/malware/phishing. Absent pair / bad signature / malformed body ⇒ that
     * lane is 0 and NOTHING was installed (fail-closed, matcher untouched). Four zeros on a BASE
     * `.so` (symbol absent → caught → honestly-empty lanes) or any native fault. Crash-proof:
     * never throws.
     */
    /**
     * Days since the Unix epoch, UTC — the `now_days` the Rust trust surfaces take.
     *
     * The engine deliberately NEVER reaches for a wall clock of its own: `now_days` is injected by
     * the caller at every trust-scoring surface (`blocklist/catalogs.rs:179` says so in as many
     * words) so a test can drive the clock. That makes supplying it the CALLER's duty, and this is
     * the caller.
     *
     * Integer division floors, so the value only ever advances — a lane ingested today can never be
     * scored as first-seen tomorrow. The `.toInt()` is safe for any clock this app will meet:
     * Int.MAX_VALUE days is over 5.8 million years past 1970. A clock set before 1970 would yield a
     * negative day, which Rust already clamps (`now_days.max(0)`), so the pair is fail-safe at both
     * ends rather than only one.
     *
     * These properties are PROVED for every representable millisecond in
     * `D:/Lean/proofs/Proofs/EpochDay.lean` — monotonicity, the absence of Int overflow, and
     * agreement with the Rust-side clamp — because a cast and a bound are exactly the kind of claim
     * a sampled test cannot settle.
     */
    private fun epochDayNow(): Int = (System.currentTimeMillis() / MILLIS_PER_DAY).toInt()

    /** 24 * 60 * 60 * 1000. Named rather than inlined so the unit is visible at the call site. */
    private const val MILLIS_PER_DAY: Long = 86_400_000L

    fun undergroundLoadLanes(dir: String, pubkey: ByteArray): List<ULong> =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.undergroundLoadLanes(dir, pubkey, epochDayNow())
            } catch (t: Throwable) {
                listOf(0uL, 0uL, 0uL, 0uL)
            }
        } else {
            listOf(0uL, 0uL, 0uL, 0uL)
        }

    /**
     * #61C — the Underground pane's four antivirus-lane counters
     * (ads / trackers-analytics / malware / phishing), read straight from the counters the
     * verify-sig-FIRST lane ingest alone writes — never derived, never fabricated. Four zeros on a
     * BASE `.so` / native fault (honestly-empty lanes). Crash-proof: never throws.
     */
    fun undergroundLaneCounts(): List<ULong> =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.undergroundLaneCounts()
            } catch (t: Throwable) {
                listOf(0uL, 0uL, 0uL, 0uL)
            }
        } else {
            listOf(0uL, 0uL, 0uL, 0uL)
        }

    /**
     * #61C — live single-lane ingest (the CentauriMirrorManager fresh-catalog push edge): verify
     * the minisign [sig] over the raw [tcat] against the pinned [pubkey] FIRST, then merge-install
     * the lane under [slug] ("ads" / "trackers-analytics" / "malware" / "phishing"). Returns the
     * lane's armed domain count (> 0) on a GENUINELY taken ingest, 0 on ANY refusal (unknown slug /
     * bad signature / malformed / base `.so` / native fault) with the global matcher untouched —
     * the [rehydrateBlocklistFromSigned] return contract. Crash-proof: never throws.
     */
    fun undergroundIngestLane(slug: String, tcat: ByteArray, sig: ByteArray, pubkey: ByteArray): Long =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.undergroundIngestLane(slug, tcat, sig, pubkey, epochDayNow())
            } catch (t: Throwable) {
                0L
            }
        } else {
            0L
        }

    // ---- THE WARDEN W5 façade — the resolver's NEW-durable rotation pillar (rehydrate/persist)
    // ----

    /**
     * W5 rehydrate of the resolver's NEW-durable rotation cursor + warm RTT from its own durable
     * record (Rust `nativeRehydrateResolverRotation` → `RotationState::rehydrate`, base `.so`).
     * UNLIKE the rehydrate-from-signed façades, this pillar owns its own integrity-framed
     * `"resolver-rotation"` record (NO pubkey, NO signature) via the shared
     * `runtime_tier::DurableTier`. Reads the warm cursor ONCE at RotationManager.start() so a
     * reboot RESUMES the diversity schedule (cadence + index + the last operator family the next
     * pick must EXCLUDE) instead of cold-starting at family 0.
     *
     * Returns a tiny summary string `"family=<s> cadence=<u64> index=<u64> hints=<n>"` of the warm
     * state, or **null** on ANY no-op (the cold sentinel — an absent record = a true cold start NOT
     * an error, a corrupt/tampered/oversized record the DurableTier integrity frame degrades to
     * cold, a missing `.so`, or a native fault). Null is the existing caller's contract
     * ([RuntimeTierManager.rehydrateTier]:252 null-checks it) for "no warm cursor this boot". The
     * functional warm of the live diversity cursor is owned by [RotationManager.start] (which
     * parses this same summary into its cadence/index/lastOperatorFamily); this summary is
     * OBSERVABILITY. NEVER on the resolve() hot path. Crash-proof: never throws.
     */
    fun rehydrateResolverRotation(dir: String): String? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.rehydrateResolverRotation(dir)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * W5 GENTLE persist of the resolver's rotation cursor + warm RTT to its own durable record
     * (Rust `nativePersistResolverRotation` → `RotationState::persist`, base `.so`). A
     * CONTROL-PLANE call — fire it ONLY on a committed rotation flip
     * (RotationManager.rotateOnce()'s commit), NEVER from resolve(). The write is a single atomic
     * tmp+rename (no fsync loop — gentle), bounded (an oversized blob is refused before IO), and
     * best-effort: a refusal leaves the in-memory tier untouched.
     *
     * [lastFamily] the operator family just committed (the next-cycle diversity exclusion);
     * [cadenceSecs] the rotation cadence in SECONDS (the Kotlin pref is in HOURS — convert at the
     * call site); [rotationIndex] the monotonically-advancing cursor; [rttHints] the line-oriented
     * `<id>:<ms>` warm-RTT payload ('\n'-joined, one hint per line; "" = none) the Rust decoder
     * reads (rotation.rs:184-194). Returns true on a durable write, false on ANY refusal (a
     * blocked/oversized write, a missing `.so`, or a native fault) — false is best-effort, never a
     * brick. Crash-proof: never throws.
     */
    fun persistResolverRotation(
        dir: String,
        lastFamily: String,
        cadenceSecs: Long,
        rotationIndex: Long,
        rttHints: String = "",
    ): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.persistResolverRotation(
                    dir,
                    lastFamily,
                    cadenceSecs,
                    rotationIndex,
                    rttHints,
                )
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /**
     * D30 — the W5/#98 PERIODIC warm-RTT checkpoint (Rust `checkpoint_resolver_rotation`):
     * refresh the durable rotation record's RTT hints from the LIVE pool's per-transport RTT
     * EWMA while PRESERVING the last-persisted cursor (it rehydrates first — it can never
     * regress the family/cadence/index a rotation flip owns). Fired from the rotation cadence
     * tick ([pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationManager]) — NEVER the resolve
     * path. `true` on a durable write, `false` when there is nothing fresh to checkpoint (no
     * pool / no learned RTT yet) or the write was refused (best-effort). Crash-proof.
     */
    fun checkpointResolverRotation(dir: String): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.checkpointResolverRotation(dir)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /**
     * D30 — the W5/#98 BOOT pool RTT warm-start (Rust `warm_start_resolver_rtt`): seed each
     * UNLEARNED transport's RTT EWMA from the durable rotation record's warm hints so
     * `Strategy::Fastest` starts warm instead of cold. Call ONCE after a successful
     * [configureResolver]/[configureResolverTyped] (a fresh pool starts unlearned), never on
     * the resolve path. Returns the count seeded (0 = cold / unconfigured / no matching hint).
     * `resolve_inner` is byte-identical — this pre-warms a stat only the (default-OFF)
     * Fastest ranking reads. Crash-proof.
     */
    fun warmStartResolverRtt(dir: String): Long =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.warmStartResolverRtt(dir)
            } catch (t: Throwable) {
                0L
            }
        } else {
            0L
        }

    /**
     * #22 capstone slice 4 — the DIRECT pool RTT warm-seed (Rust `seed_resolver_rtt`): hand the
     * rotation swap's OWN pre-commit probe samples (D30(3)) straight to the freshly-configured
     * pool's per-transport RTT EWMA — the LIVE twin of the durable [warmStartResolverRtt].
     * Closes the ordering gap where the fresh pool warm-started from the PREVIOUS window's
     * durable hints while THIS committed set's just-measured RTTs only reached the record after
     * the swap (orphaned under a completely-random pick). TYPED end-to-end
     * (`List<uniffi.torta_core.RttHint>` keyed on the same spec-id label both sides carry).
     * Unlearned-only Rust-side (live data wins — a learned transport is never stomped). Call on
     * the rotation-swap edge ([pillar.kuma_saimono.libumdnscrypt.dns_engine.RotationManager]),
     * never on the resolve path. Returns the count seeded (0 = empty / unconfigured / no
     * matching id). Crash-proof.
     */
    fun seedResolverRtt(hints: List<uniffi.torta_core.RttHint>): Long =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.seedResolverRtt(hints)
            } catch (t: Throwable) {
                0L
            }
        } else {
            0L
        }

    // ---- DNSCRYPT-CONFIG (K5) — the typed config authority reaching the LIVE engine (D09) ----

    /**
     * K5 — import a `dnscrypt-proxy.toml` into the typed config authority, FAIL-SOFT to the
     * upstream Default (Rust `dnscryptConfigImportOrDefault`): a corrupt/absent TOML degrades to
     * the safe upstream baseline, never an error — the boot path that must never brick. Returns
     * null ONLY when the `.so` itself is unreachable / a binding fault (the façade's load
     * firewall). Crash-proof: never throws.
     */
    fun dnscryptConfigImportOrDefault(toml: String): uniffi.torta_core.DnscryptProxyConfig? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.dnscryptConfigImportOrDefault(toml)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * K5 — write the held typed config authority (the STAGE half; does NOT touch the live
     * transport — that is [dnscryptConfigApply]'s job). Crash-proof: never throws.
     */
    fun dnscryptConfigSet(cfg: uniffi.torta_core.DnscryptProxyConfig) {
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.dnscryptConfigSet(cfg)
            } catch (t: Throwable) {
                // Best-effort: a set fault leaves the prior authority — the apply/read paths
                // degrade gracefully.
            }
        }
    }

    /**
     * K5 — export the typed config to the `dnscrypt-proxy.toml` COMPATIBILITY VIEW (the Go
     * fallback + upstream ecosystem read it). Returns the TOML text, or null on a (guarded-against)
     * serialize failure / unreachable `.so`. Crash-proof: never throws.
     */
    fun dnscryptConfigToToml(cfg: uniffi.torta_core.DnscryptProxyConfig): String? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.dnscryptConfigToToml(cfg)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * K5 D09 — THE WIRING POINT the dossier flagged with ZERO callers: store [cfg] as the typed
     * authority AND drive the LIVE resolver from it. Fans to the EXISTING seams — DNS64 prefixes
     * ALWAYS (empty ⇒ OFF), and the `[static]` `sdns://` pins → the proven `resolver::configure`
     * path; with NO pins the live pool is left UNTOUCHED (an empty set never tears down a
     * source-configured pool), so this COMPOSES with the pool the RUNNING edge just configured.
     * Control-plane only — NEVER on the resolve hot path. Returns the human summary, or null on a
     * panic / unreachable `.so`. Crash-proof: never throws.
     */
    fun dnscryptConfigApply(cfg: uniffi.torta_core.DnscryptProxyConfig): String? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.dnscryptConfigApply(cfg)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    // ---- DNSCRYPT-CONFIG DURABILITY (W5 #12 / RAMxNAND Opt-2) — the RAM⊗NAND durable authority ----

    /**
     * W5 #12 — persist the held typed DNSCrypt config authority to its OWN framed `"dnscrypt-config"`
     * record in the app-private W5 root [dir] (Rust `persistDnscryptConfig` → the DurableTier atomic
     * tmp+rename, integrity-framed, 256 KiB-capped). A CONTROL-PLANE call — fire it on a committed
     * config edit (a K5 apply, the outbound-proxy flip) or once per lifecycle edge, NEVER from
     * resolve(). [dir] is the SAME root [RotationManager.durableDir]/[RuntimeTierManager] use
     * ([PathVars.getAppDataDir] + [RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR]). Returns true on a
     * durable write, false on ANY refusal (an oversized blob, a missing `.so`, a native fault) —
     * false is best-effort, never a brick. Crash-proof: never throws.
     */
    fun persistDnscryptConfig(dir: String): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.persistDnscryptConfig(dir)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /**
     * W5 #12 — rehydrate the typed DNSCrypt config authority from its durable record under [dir]
     * (Rust `rehydrateDnscryptConfig` → DurableTier read → install into the process-global authority).
     * Returns true IFF a durable record was found AND installed; false on a TRUE cold start (no
     * record — a fresh install), a corrupt/tampered/oversized record (the integrity frame degrades to
     * cold), a missing `.so`, or a native fault. A false is the caller's cue to SEED the authority
     * from the on-disk compatibility toml. Call ONCE at a lifecycle edge, off the resolve path.
     * Crash-proof: never throws.
     */
    fun rehydrateDnscryptConfig(dir: String): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.rehydrateDnscryptConfig(dir)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /**
     * W5 #12 — materialize the `dnscrypt-proxy.toml` COMPATIBILITY VIEW at [path] from the held typed
     * authority, Rust-side and ATOMICALLY (create_dir_all parent → write `.tmp` → fsync → rename),
     * REPLACING the fragile Kotlin FileManager write. The many on-disk-toml readers (ResolverRuntime
     * upstream derivation, RotationManager policy, the query-log arm) keep their unchanged
     * `File(...).readText()` contract — this regenerates the derived view from the durable authority.
     * Returns true on a durable write, false on a serialize/IO fault or an unreachable `.so`.
     * Crash-proof: never throws.
     */
    fun materializeDnscryptToml(path: String): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.materializeDnscryptToml(path)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    // ---- DNSCRYPT single-rule-list DURABILITY (W5 #12 slice 2 / RAMxNAND Opt-2) — the user's own rules ----

    /**
     * W5 #12 slice 2 — persist a user-authored DNSCrypt single-rule list ([lines]) to its OWN framed
     * [record] DurableTier blob under the app-private W5 root [dir] (Rust `persistDnsRuleList` → the
     * DurableTier atomic tmp+rename, integrity-framed, 256 KiB-capped). The durable payload is the EXACT
     * loose-file bytes (each line + `'\n'`, byte-identical to [FileManager.writeTextFileSynchronous]'s
     * `atomicWriteLines`), so a round trip reproduces a file the reader already accepts. A CONTROL-PLANE
     * call — fire it on a committed rule edit (`saveSingle*Rules`), NEVER from resolve(). [dir] is the SAME
     * root the config authority + rotation use ([PathVars.getAppDataDir] +
     * [RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR]); [record] is a per-list basename (DurableTier
     * sanitizes it traversal-free). Returns true on a durable write, false on ANY refusal (an oversized
     * blob, a missing `.so`, a native fault) — false is best-effort, the loose file is untouched.
     * Crash-proof: never throws.
     */
    fun persistDnsRuleList(dir: String, record: String, lines: List<String>): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.persistDnsRuleList(dir, record, lines)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /**
     * W5 #12 slice 2 — restore a user-authored DNSCrypt single-rule loose file at [path] from its framed
     * [record] DurableTier blob under [dir], Rust-side + ATOMICALLY (create parent → write `.tmp` → fsync →
     * rename). The caller invokes this ONLY when it finds the loose file ABSENT (a wipe/corruption
     * recovery) — NEVER when the file is present, so an intentionally-emptied list stays empty and recovery
     * never resurrects deleted rules. Returns true IFF a durable record was found AND the file was written
     * (the caller then reads it back through its unchanged `File(path).reader()` contract); false on a
     * cold/corrupt/absent record, an IO fault, or an unreachable `.so` (the caller treats the list as a
     * true cold-start empty). Off the resolve path. Crash-proof: never throws.
     */
    fun materializeDnsRuleList(dir: String, record: String, path: String): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.materializeDnsRuleList(dir, record, path)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    // ---- DNSCRYPT version-sync (slice 5, D14) — the typed envelope→plan→apply→rehydrate chain ----

    /**
     * D14 — the capability envelope THIS build's DNSCrypt layer speaks (typed
     * `DnscryptEnvelope` Record: protocol version + capability flags + relay/stamp sources —
     * Kotlin reads the fields, never parses a `"version=… caps=…"` summary). Pure, no IO. Null
     * only on an unreachable `.so` / a binding fault. Crash-proof: never throws.
     */
    fun currentDnscryptEnvelope(): uniffi.torta_core.DnscryptEnvelope? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.currentDnscryptEnvelopeTyped()
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * D14 — diff a distilled upstream envelope (line-oriented `version=…`/`cap=…`/`source=…` — the
     * worker's distillation of the GitHub releases feed; the network + JSON stay on the Kotlin
     * side) against THIS build's envelope. Returns the typed `DnscryptSyncPlan`
     * (`isNewer == false` ⇒ a no-op plan), or null on a malformed upstream (the typed
     * `DnscryptSyncException` swallowed — the caller retries next cadence), an unreachable `.so`,
     * or a native fault. Crash-proof: never throws.
     */
    fun buildDnscryptSyncPlan(upstreamEnvelope: String): uniffi.torta_core.DnscryptSyncPlan? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.buildDnscryptSyncPlanTyped(upstreamEnvelope)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    /**
     * D14 — the GENTLE control-plane apply: advance the durable `dnscrypt-sync` record under [dir]
     * to mark the layer at the upstream version with its capabilities merged (persisting through
     * the shared `runtime_tier::DurableTier`). The ONLY mutation — no binary swap, no
     * pool/cache/hot-path touch, no restart (the Rust module enforces core-isolation statically).
     * True on a durable write; false on ANY refusal / malformed upstream / fault (best-effort —
     * the in-memory state is unaffected). Crash-proof: never throws.
     */
    fun applyDnscryptSyncPlan(dir: String, upstreamEnvelope: String, nowSecs: Long): Boolean =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.applyDnscryptSyncPlan(dir, upstreamEnvelope, nowSecs)
            } catch (t: Throwable) {
                false
            }
        } else {
            false
        }

    /**
     * D14 — the pillar-5 boot-rehydrate: read the durable `dnscrypt-sync` record under [dir] into
     * the typed `DnscryptSyncState` (cold ⇒ empty version / zero counts — a true cold start, never
     * an error; the DurableTier integrity frame degrades a corrupt/tampered record to cold).
     * Boot-only ([pillar.kuma_saimono.libumdnscrypt.dns_engine.RuntimeTierManager.rehydrateTier]
     * pillar 5), NEVER on the resolve path. Null only on an unreachable `.so` / a native fault.
     * Crash-proof: never throws.
     */
    fun rehydrateDnscryptSync(dir: String): uniffi.torta_core.DnscryptSyncState? =
        if (ensureLoaded()) {
            try {
                uniffi.torta_core.rehydrateDnscryptSyncTyped(dir)
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    // ---- Façade constants ----
    /**
     * The sentinel [wardenStats] returns when the lib is unreachable / a native fault occurred (W6
     * slice-1). A reader (the W6 [pillar.kuma_saimono.libumdnscrypt.data.warden.WardenStatsRepository])
     * treats this exact string as "no aggregate this tick" (idle), never as a verdict — so the
     * magic string lives in ONE place instead of drifting between the wrapper and its parser.
     */
    const val WARDEN_STATS_UNAVAILABLE = "unavailable"

    /**
     * Negative sentinel the Rust #92 `nativeCentauriMirrorStart` export returns on any bind/runtime
     * failure (a valid port is always >0). The [centauriMirrorStart] façade maps this — and any
     * UnsatisfiedLinkError / throwable — to `null` ("did not start"), so the manager degrades to
     * inert rather than treating −1 as a port. Mirrors the Rust-side `MIRROR_START_FAILED = -1`.
     */
    const val MIRROR_START_FAILED = -1

    /**
     * The cold-baseline summary [rehydrateResolverRotation] returns on any no-op (an absent/corrupt
     * record, a missing `.so`, or a native fault) — the zero cursor a boot starts from when there
     * is no warm state. Mirrors the Rust cold baseline ([RotationState::cold]: empty family,
     * cadence 0, index 0, no hints). The caller treats this as "cold start" (begin the diversity
     * schedule fresh), never an error.
     */
    const val ROTATION_COLD_SUMMARY = "family= cadence=0 index=0 hints=0"
}
