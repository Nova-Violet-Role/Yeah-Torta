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
import pillar.kuma_saimono.libumdnscrypt.rust.BlocklistRuntime
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
 * P8 **Wave C3 — the closer.** ModulesService-scoped owner of the OPT-IN Centauri **signed remote
 * artifact** channel. Mirrors [TrustManager]/[MonokumaDnsEngineManager]/[ResolverRuntime] exactly:
 * `@ModulesServiceScope` + `@Inject` ctor auto-supplied by the ModulesService subcomponent, armed when
 * DNSCrypt goes RUNNING (or the engine runs standalone), idempotent `@Synchronized` start/stop so the
 * state-loop can call them on any transition edge without races.
 *
 * **Governance (load-bearing): this channel is OPT-IN and INERT BY DEFAULT.** An untouched install never
 * reaches the network — [start] returns immediately unless the Expert
 * [TortaeKeys.CENTAURI_REMOTE_ENABLED] flag is ON (default `false`). So the default install fingerprint
 * is exactly pre-C3: the manual / DNSCrypt [MonokumaDnsEngineManager.loadBlocklist] → [BlocklistRuntime.compileFromFiles]
 * path stays the byte-identical default and is NEVER touched here. The opt-in gate lives in the pure,
 * Android-free [shouldFetchRemote] so a unit test can prove "default ⇒ no fetch" without a `Context`.
 *
 * **The security boundary — VERIFY ORDER (load-bearing).** When (and only when) the channel is enabled,
 * [start] does, OFF the caller thread:
 *   1. GOVERNANCE GATE — [shouldFetchRemote]; off ⇒ return, no fetch, no install.
 *   2. fetch the `.tblk` artifact + its `.minisig` (bounded reads, no unbounded slurp).
 *   3. **VERIFY MINISIGN FIRST** — [TortaCore.verifyArtifactSignature] with the in-app PINNED public key.
 *      A bad/absent/truncated/swapped signature ⇒ REJECT, log, return. `from_artifact` MUST NOT run.
 *      This authenticates PROVENANCE (real Ed25519). It is the first gate precisely because the artifact's
 *      embedded FNV self-check is non-crypto (forgeable) and authenticates only SET-INTEGRITY — a tampered
 *      artifact with a valid FNV but a bad signature is rejected HERE, before any byte reaches the matcher.
 *   4. ONLY THEN [BlocklistRuntime.compileFromArtifact] → Rust `compile_and_install_artifact` (the FNV
 *      self-check is the second, weaker gate) → the SAME `GLOBAL` matcher the resolver enforces from.
 *   5. record the installed fingerprint as the idempotency guard.
 *
 * No root, no `@Provides`, no egress unless the operator opted in. Crash-proof throughout: a missing `.so`,
 * a malformed artifact, a network failure, or a verify fault all degrade to "did not arm" and never throw.
 */
@ModulesServiceScope
@ExperimentalCoroutinesApi
class CentauriArtifactManager @Inject constructor(
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
                    CoroutineName("CentauriArtifactManager") +
                    CoroutineExceptionHandler { _, t ->
                        loge("CentauriArtifactManager uncaught exception", t)
                    }
        )
    }

    /**
     * Fingerprint of the remote artifact we last successfully verified + installed. Doubles as the
     * idempotency guard: a repeated RUNNING edge for the same installed artifact is a no-op. `@Volatile`
     * because the work runs on [dispatcherIo] while the state-loop drives start/stop from another thread.
     */
    @Volatile
    private var installedFingerprint: Long? = null

    /**
     * DNSCrypt reached RUNNING (or the engine started standalone). If — and ONLY if — the operator opted
     * into the Centauri remote channel, fetch → verify-signature-first → install the signed artifact off
     * the caller thread. Idempotent. By default (flag OFF) this returns immediately and does nothing, so
     * the manual/DNSCrypt blocklist path remains the byte-identical default.
     */
    @Synchronized
    fun start() {
        try {
            // GOVERNANCE GATE FIRST — the pure, Context-free opt-in check. Off ⇒ no fetch, no install.
            if (!shouldFetchRemote(defaultPreferences)) {
                return
            }
            // Off the caller (state-loop) thread: network + verify + native install belong on IO.
            coroutineScope.launch { fetchVerifyAndInstall() }
        } catch (e: Exception) {
            loge("CentauriArtifactManager start", e)
        }
    }

    /**
     * DNSCrypt stopped (and the engine is not standalone). The installed list stays in the matcher GLOBAL
     * (the resolver/observe path keeps the last set); we simply clear the idempotency guard so a later
     * RUNNING edge re-verifies + re-installs. Idempotent; never throws.
     */
    @Synchronized
    fun stop() {
        try {
            installedFingerprint = null
        } catch (e: Exception) {
            loge("CentauriArtifactManager stop", e)
        }
    }

    /** DNSCrypt reached RUNNING: (re)check the remote channel. */
    fun onDnsCryptStarted() = start()

    /**
     * DNSCrypt stopped. If the user runs the engine standalone, the blocklist intelligence stays active,
     * so keep checking the remote channel (re-arm); otherwise clear the guard. Mirrors the other managers'
     * standalone-aware stop edge.
     */
    fun onDnsCryptStopped() {
        if (defaultPreferences.getBoolean(TortaeKeys.DNS_ENGINE_STANDALONE, false)) {
            start()
        } else {
            stop()
        }
    }

    /** True once a remote artifact has been verified + installed this RUNNING edge. */
    fun isRunning(): Boolean = installedFingerprint != null

    /**
     * The full opt-in pipeline, on [dispatcherIo]. Each stage degrades to a silent no-op rather than
     * throwing, so a hostile/absent artifact or a network failure can never break arming. THE ORDER is the
     * point: signature verification precedes any artifact decode/install.
     */
    private fun fetchVerifyAndInstall() {
        try {
            // 1) Locate the channel inputs. C3 ships the on-device fetch as a bounded local read of the
            //    files a (future) downloader/updater lands beside the installed `.tblk` — keeping this
            //    wave free of a new HTTP stack on the datapath. A real network fetch is a drop-in here
            //    behind the SAME governance + verify-first discipline (the security boundary is unchanged).
            val pv = pathVars.get()
            val artifactPath = pv.appDataDir + ARTIFACT_RELATIVE_PATH
            val artifactFile = File(artifactPath)
            val minisigFile = File(artifactPath + MINISIG_SUFFIX)

            if (!artifactFile.isFile || !artifactFile.canRead()) {
                // No staged remote artifact ⇒ nothing to do (the manual path already armed the default).
                return
            }
            if (!minisigFile.isFile || !minisigFile.canRead()) {
                // An artifact with NO signature is rejected outright — never install an unsigned remote set.
                logw("CentauriArtifactManager — remote artifact present but no .minisig; rejecting (unsigned)")
                return
            }

            // Bounded reads: a hostile artifact/sig must not be slurped whole.
            if (artifactFile.length() > MAX_ARTIFACT_BYTES) {
                logw("CentauriArtifactManager — remote artifact exceeds ${MAX_ARTIFACT_BYTES}B, ignoring")
                return
            }
            if (minisigFile.length() > MAX_MINISIG_BYTES) {
                logw("CentauriArtifactManager — .minisig exceeds ${MAX_MINISIG_BYTES}B, ignoring")
                return
            }
            val artifactBytes = artifactFile.readBytes()
            val minisigText = minisigFile.readText(Charsets.UTF_8)

            // 2) VERIFY MINISIGN FIRST — the provenance gate. A bad/absent/swapped sig ⇒ reject, never
            //    reaching from_artifact. The pinned PUBLIC key is the only trust anchor; the private key
            //    lives offline on the Centauri side and never ships.
            val verified = TortaCore.verifyArtifactSignature(
                artifactBytes = artifactBytes,
                minisigText = minisigText,
                pinnedPubKeyBase64 = PINNED_MINISIGN_PUBKEY_BASE64,
            )
            if (!verified) {
                loge("CentauriArtifactManager — minisign verification FAILED; rejecting remote artifact " +
                        "(provenance unproven — from_artifact will NOT run)")
                return
            }

            // 3) ONLY THEN compile + install. This routes through the same Rust matcher GLOBAL the
            //    resolver enforces from; the FNV self-check inside from_artifact is the second, weaker gate.
            val armed = BlocklistRuntime.compileFromArtifact(artifactBytes, merge = false)
            if (armed <= 0) {
                // from_artifact rejected the bytes (bad header / fp mismatch) even after a valid signature —
                // stay idle rather than claim an install. (A valid-signature, empty-set artifact is rare.)
                logw("CentauriArtifactManager — signature valid but artifact did not arm (count=$armed)")
                return
            }

            // 4) Record the installed fingerprint (idempotency guard); TrustManager re-scores on its own
            //    RUNNING edge by reading the matcher fingerprint — we do not cross into its seam here.
            val fingerprint = TortaCore.blocklistFingerprint()
            installedFingerprint = fingerprint
            logi(
                "CentauriArtifactManager — signed remote artifact verified + armed " +
                        "(fp=$fingerprint domains=$armed)"
            )
        } catch (e: Exception) {
            loge("CentauriArtifactManager fetchVerifyAndInstall — staying idle", e)
        }
    }

    companion object {
        /**
         * THE GOVERNANCE GATE, extracted pure so it is unit-testable without an Android `Context`. The
         * Centauri remote channel is OPT-IN: a default (untouched) install returns `false` here — no
         * fetch, no install, no egress — so the manual/DNSCrypt blocklist path stays the byte-identical
         * default. Only an explicit Expert opt-in ([TortaeKeys.CENTAURI_REMOTE_ENABLED] = `true`) AND
         * the master blocklist switch being on ([TortaeKeys.DNS_ENGINE_ENABLED], default on) returns
         * `true`. This is the property the default-path-unchanged guard test pins.
         */
        @JvmStatic
        fun shouldFetchRemote(prefs: SharedPreferences): Boolean {
            // The remote channel never overrides the master blocklist switch: if the user turned the DNS
            // engine intelligence off, we do nothing regardless of the opt-in.
            if (!prefs.getBoolean(TortaeKeys.DNS_ENGINE_ENABLED, true)) return false
            // The load-bearing default: OFF. An untouched install can never silently fetch a remote list.
            return prefs.getBoolean(TortaeKeys.CENTAURI_REMOTE_ENABLED, false)
        }

        /**
         * On-device path (relative to [PathVars.getAppDataDir]) of the staged remote `.tblk` — the SAME
         * artifact path family the B2 sidecar reader uses ([TrustManager.ARTIFACT_RELATIVE_PATH]).
         */
        const val ARTIFACT_RELATIVE_PATH = "/app_data/dnscrypt-proxy/blocklist.tblk"

        /** Suffix Centauri appends for the detached minisign signature (`blocklist.tblk.minisig`). */
        const val MINISIG_SUFFIX = ".minisig"

        /** Hard caps so a hostile artifact / signature cannot be slurped whole. */
        const val MAX_ARTIFACT_BYTES = 64L shl 20  // 64 MiB — a huge but bounded blocklist artifact
        const val MAX_MINISIG_BYTES = 4L shl 10     // 4 KiB — a `.minisig` is a tiny text file

        /**
         * The PINNED minisign **public** key (base64 of the 42-byte `Ed`‖key_id‖pk blob), the ONLY trust
         * anchor for the remote channel. The matching PRIVATE key lives OFFLINE on the Centauri side and
         * never ships. The placeholder below is replaced with the real key blob produced by
         * `centauri-keygen` before any signed channel goes live; until then, verification fail-closes
         * (governance is OFF by default anyway, so the channel is inert). Pinning the key — not a CA — is
         * what makes a swapped-key attack fail at the on-device verify.
         */
        const val PINNED_MINISIGN_PUBKEY_BASE64 =
            "RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    }
}
