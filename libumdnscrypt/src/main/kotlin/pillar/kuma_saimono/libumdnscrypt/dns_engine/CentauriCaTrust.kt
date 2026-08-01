/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

package pillar.kuma_saimono.libumdnscrypt.dns_engine

import android.content.Context
import android.content.Intent
import android.security.KeyChain
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * ★ #65 — the CA trust seam: the ONE thing standing between an armed HTTPS serve leg and an
 * actually-working offline CDN.
 *
 * ## Why this file exists
 * [CentauriMirrorManager.armTlsLeg] mints a device CA and writes it to `filesDir/centauri_ca/`, and
 * its own doc comment says "until the user installs it into the OS trust store, browsers reject the
 * minted leaves". Nothing ever offered to do that. The leg armed, the leaf was minted, and every
 * HTTPS flow died at the interstitial — measured on the emulator as `ERR_CERT_AUTHORITY_INVALID`.
 * An offline CDN nobody can trust is an offline CDN that never serves.
 *
 * ## What CAN and CANNOT reach the trust store
 * Measured on Android 14 (API 34), where the live system store moved into the conscrypt APEX:
 *
 *  - **System store** (`/apex/com.android.conscrypt/cacerts`) — needs a bind-mount as **root**.
 *    Not reachable by this app, and NOT reachable by Wire Cake Inu either: Inu's ADB self-elevation
 *    grants the `shell` uid (2000), and shell cannot write the APEX or `/data/misc/user/0/cacerts-added`
 *    (both are `system:system`). Elevation is not root. On an already-rooted device it becomes possible,
 *    but that is a minority path and must never be a requirement.
 *  - **User store** — reachable with ZERO privilege through [KeyChain.createInstallIntent]: the OS shows
 *    its own confirmation sheet and the user taps once. Chrome and every other browser honour user CAs,
 *    which is exactly the traffic Centauri serves.
 *
 * So the shippable path is the user store, by explicit consent, through the OS's own dialog. Nothing is
 * installed behind the user's back — the app cannot do it silently even if it wanted to, and that
 * property is worth keeping rather than engineering around.
 *
 * ## The honest limit
 * Apps that target API 24+ do not trust user CAs for their OWN traffic unless they opt in. Centauri
 * therefore serves BROWSER flows locally and lets in-app CDN flows pass through untouched — which is
 * the correct, non-destructive behaviour, not a workaround.
 */
object CentauriCaTrust {

    /**
     * The CA's Common Name, authored by the Rust minter (`mirror/tlsca.rs`). Kept byte-identical here
     * because [isTrusted] recognises our certificate by this string and nothing else — the CA carries no
     * O, L, SAN or e-mail on purpose (it must leak nothing about the device).
     */
    const val CA_SUBJECT_CN = "Yeah Tortae Centauri Device CA"

    /** Label the OS shows the user in its install sheet and later in Settings → Encryption & credentials. */
    private const val INSTALL_LABEL = "Yeah Tortä Centauri"

    private const val CA_DIR_NAME = "centauri_ca"
    private const val CA_CERT_FILE = "centauri-ca.pem"

    /** The name the user sees in the picker. `.crt` is load-bearing — Settings filters on it. */
    private const val STAGED_FILE_NAME = "centauri-ca.crt"

    /** The mime type that routes an ACTION_VIEW to `com.android.certinstaller`. */
    private const val CA_MIME = "application/x-x509-ca-cert"

    /** Where [CentauriMirrorManager.armTlsLeg] persists the PUBLIC half. */
    fun caCertFile(context: Context): File =
        File(File(context.filesDir, CA_DIR_NAME), CA_CERT_FILE)

    /** True once the CA exists on disk — i.e. the serve leg has armed at least once. */
    fun isMinted(context: Context): Boolean = caCertFile(context).isFile

    /**
     * Is our CA actually trusted by this device right now?
     *
     * Reads `AndroidCAStore`, which merges the system and user stores, so this returns true whether the
     * user installed it through the OS sheet or a rooted device placed it in the system set. Answering
     * from the live store (rather than remembering that we once showed a dialog) means the banner
     * disappears the moment trust is granted and reappears if the user later revokes it.
     */
    fun isTrusted(): Boolean = noteTrust(
        try {
            // Our own certificate's DER. When it cannot be read we FAIL CLOSED (see below) rather
            // than falling back to a name comparison -- a name is not an identity.
            val ours = ourCaDer()
            val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            store.aliases().asSequence().any { alias ->
                val cert = store.getCertificate(alias) as? X509Certificate
                // The CN test stays as a cheap pre-filter (it skips ~150 system anchors without
                // decoding them), but it is NO LONGER the verdict. The verdict is byte equality
                // with the certificate this device actually minted.
                cert?.subjectX500Principal?.name?.contains(CA_SUBJECT_CN) == true &&
                    ours != null &&
                    cert.encoded.contentEquals(ours)
            }
        } catch (t: Throwable) {
            // A store we cannot read is a store we must not claim is trusted: fail toward showing the prompt.
            loge("CentauriCaTrust isTrusted", Exception(t))
            false
        }
    )

    /** Edge detector for the trust flip. Only a false -> true TRANSITION fires the re-trust. */
    private val trustObserved = java.util.concurrent.atomic.AtomicBoolean(false)

    @Volatile private var storeWatch: android.content.BroadcastReceiver? = null

    /**
     * The application context, captured when the trust watch arms, so [isTrusted] can read OUR OWN
     * certificate off disk and compare the real bytes.
     */
    @Volatile private var appCtx: Context? = null

    /** Cached DER of our minted CA, with the file stamp it was read at. */
    @Volatile private var pinnedCaDer: ByteArray? = null

    @Volatile private var pinnedCaStamp: Long = -1L

    /**
     * The DER of the CA this device has ACTUALLY minted, or null if it cannot be read.
     *
     * MEASURED 2026-08-01, and it is why this exists: after an app reinstall the private CA is
     * re-minted with a fresh key, while the anchor previously installed in the user store is the
     * OLD certificate. Both carry the identical subject `CN=Yeah Tortae Centauri Device CA`,
     * because the minter authors a constant CN on purpose. Two certificates, same name:
     *   installed anchor   E2:57:82:4F...
     *   app's current CA   43:84:0D:E1...
     * A CN-only trust test calls that TRUSTED, the serve leg then presents a cert chaining to a CA
     * the device does not have, and every cloaked HTTPS flow dies at the handshake -- the exact
     * "3 sinkholes / 0 served" black hole the servability gate was built to prevent.
     *
     * Re-read whenever the file's stamp changes, so a re-mint invalidates the pin by itself.
     */
    private fun ourCaDer(): ByteArray? {
        // `appCtx` is set by `armTrustWatch`, which only runs on a Centauri dashboard tick — so
        // `isTrusted()` can legitimately be asked BEFORE it exists (the pillar bridge calls
        // `centauriCaTrusted` and `centauriCaMinted` independently). Falling back to the
        // application singleton removes that ordering dependency entirely, instead of leaving a
        // window where trust reads false for a reason that has nothing to do with trust.
        val ctx = appCtx
            ?: runCatching { pillar.kuma_saimono.libumdnscrypt.App.instance.applicationContext }
                .getOrNull()
                ?.also { appCtx = it }
            ?: return null
        return try {
            val f = caCertFile(ctx)
            if (!f.isFile) return null
            val stamp = f.lastModified() xor (f.length() shl 20)
            val cached = pinnedCaDer
            if (cached != null && stamp == pinnedCaStamp) return cached
            val der = f.inputStream().use { ins ->
                (java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(ins) as X509Certificate).encoded
            }
            pinnedCaDer = der
            pinnedCaStamp = stamp
            der
        } catch (t: Throwable) {
            loge("CentauriCaTrust ourCaDer", Exception(t))
            null
        }
    }

    /**
     * ★ #22 · listen for the OS's OWN trust-store-changed signal.
     *
     * The dashboard tick already re-reads trust, but only while the Centauri panel is on screen, and the
     * user grants trust in SETTINGS — i.e. in another app, with our panel not ticking. `TRUST_STORE_CHANGED`
     * is the supported notification that the set changed; on it we re-arm the edge (a change may be an
     * install OR a revoke) and re-read immediately, so the hand-back happens the moment the user returns.
     *
     * MEASURED, and worth writing down because it misled me: revoking by moving files with `su` produces
     * NO broadcast and no framework invalidation, so trust reads stale afterwards. That is an artifact of
     * bypassing the framework, not the user-facing path — a real revoke goes through Settings, which does
     * signal. The app cannot read `/data/misc/user/0/cacerts-added` to check for itself either: the parent
     * is `drwxr-x--- system:everybody` and the app uid is denied (measured, not assumed).
     *
     * Idempotent: registers at most one receiver for the process.
     */
    @Synchronized
    fun armTrustWatch(context: Context) {
        // Captured unconditionally, BEFORE the idempotence guard: `isTrusted` needs it to read our
        // own certificate, and a second arm call must never leave it null.
        appCtx = context.applicationContext
        if (storeWatch != null) return
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                trustObserved.set(false)
                isTrusted() // re-reads, and fires the hand-back if this change was the CA being installed
            }
        }
        try {
            androidx.core.content.ContextCompat.registerReceiver(
                context.applicationContext,
                receiver,
                android.content.IntentFilter(KeyChain.ACTION_TRUST_STORE_CHANGED),
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED,
            )
            storeWatch = receiver
        } catch (t: Throwable) {
            // A missing receiver only costs us immediacy — the dashboard tick still re-reads trust.
            loge("CentauriCaTrust armTrustWatch", Exception(t))
        }
    }

    /**
     * ★ #22 · the moment this device starts trusting our CA, hand back every host that refused us BEFORE
     * the install.
     *
     * Without this, installing the certificate mid-session fixes nothing the user already browsed: those
     * hosts were recorded as refusals and un-cloaked permanently, so they keep going straight to the real
     * CDN until a reinstall. Measured on the AVD — after a successful CA install, five hosts stayed
     * distrusted and served nothing until the ledger was cleared by hand.
     *
     * Edge-triggered, so a dashboard that polls trust every tick does not re-run this every tick. Revoking
     * trust re-arms the edge, because a re-install must be able to trigger the hand-back again.
     */
    @Suppress("TooGenericExceptionCaught") // trust reporting must never fail because the engine is absent
    private fun noteTrust(trusted: Boolean): Boolean {
        // ★ THE WIRE THAT WAS NEVER CONNECTED — publish the observation to the ENGINE.
        //
        // `is_servable_cloak_host` (mirror/localcdn.rs:638) is a four-conjunct gate whose FIRST
        // conjunct is `CLOAK_TLS_TRUSTED`, defaulting to false. MEASURED 2026-08-01:
        // `publish_cloak_tls_trust` was reachable ONLY from `#[cfg(test)]` code, was not on the
        // UniFFI surface, and no Kotlin file referenced it. So the conjunct was permanently false
        // in the shipped app, the DNS-plane cloak could NEVER fire, and Centauri's offline-CDN was
        // dark while the dashboard read "LIVE — offline-CDN serving". This object already KNEW the
        // answer -- it reads AndroidCAStore on every tick -- and simply never told the engine.
        //
        // Published on EVERY tick, both directions, before the edge logic below: this is a live
        // reading of the real store, so a revocation must re-darken the cloak just as an install
        // lights it. Publishing `trusted` unconditionally (rather than only on the rising edge)
        // is what makes that true, and it costs one relaxed atomic store.
        // ★ TRUSTED IS NOT SERVING — the second half of the same lesson the rotation gate taught
        // ("reachable is not answering"). MEASURED 2026-08-01, minutes after the wire above was
        // connected: with the correct anchor installed the cloak fired
        // (`ajax.googleapis.com -> 10.1.10.3`, sinkholes 0 -> 11) and Brave answered
        // ERR_CONNECTION_TIMED_OUT. A trusted CA proves the browser would ACCEPT our certificate;
        // it proves nothing about anything being there to present one. Publishing trust alone
        // therefore re-opened the exact black hole the four-conjunct gate exists to prevent --
        // a connection dropped BECAUSE a pillar was armed, which is strictly worse than the
        // feature being off.
        //
        // So trust is published as `trusted AND the serve leg has actually answered`. The probe
        // (`CentauriMirrorManager.serveLegAnswers`) is a real request against the bound mirror, not
        // a flag saying it was started. Until it answers, the cloak stays dark and browsing is
        // untouched: a dark optimisation beats a black hole, every time.
        val serving = try {
            CentauriMirrorManager.serveLegAnswers()
        } catch (t: Throwable) {
            false
        }
        try {
            pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
                .centauriPublishCloakTlsTrust(trusted && serving)
        } catch (t: Throwable) {
            // Never let trust REPORTING break trust DETECTION. A failure here leaves the engine's
            // flag at its previous value, and the fail-closed default means the worst case is a
            // dark optimisation rather than a dropped connection.
            loge("CentauriCaTrust publish", Exception(t))
        }
        if (!trusted) {
            trustObserved.set(false)
            return false
        }
        if (!trustObserved.get()) {
            try {
                // MEASURED on the AVD: the dashboard polls trust from its very first tick, which lands
                // BEFORE the native engine finishes loading. `centauriTlsRetrust()` fails soft to 0 there
                // — indistinguishable from "nothing to free" — so latching on that zero consumed the edge
                // and the hand-back never ran again for the life of the process. Gate on liveness, and
                // leave the edge ARMED until a live engine has actually answered.
                if (pillar.kuma_saimono.libumdnscrypt.rust.TortaCore.isEngineLoaded()) {
                    val freed = pillar.kuma_saimono.libumdnscrypt.rust.TortaCore.centauriTlsRetrust()
                    // Latch ONLY on work actually done. A loaded engine is still not a READY one: the
                    // refusal ledger is bound to disk by `centauri_discovery::arm()`, which runs when the
                    // service arms — after the dashboard's first ticks. MEASURED on the AVD: retrust at
                    // tick one hit an engine whose ledger store was not yet bound, freed 0, and latching
                    // there consumed the edge before the ledger had even been read off disk. A zero is
                    // therefore "not ready OR nothing to do", and both want the same answer: try again.
                    // The retry costs one atomic read against an empty set per tick.
                    if (freed > 0u) {
                        trustObserved.set(true)
                        logi("CentauriCaTrust: CA now trusted -> re-trusted $freed refused host(s)")
                    }
                }
            } catch (t: Throwable) {
                // Edge deliberately left ARMED: a transient failure must be retried on the next tick, or
                // installing the CA mid-session silently fixes nothing the user already browsed.
                loge("CentauriCaTrust retrust-on-trust", Exception(t))
            }
        }
        return true
    }

    /**
     * Build the direct [KeyChain] install intent, or null when there is nothing to install.
     *
     * MEASURED on Android 14: this route is REFUSED for CA certificates — the OS answers with
     * "Install CA certificates in Settings / This certificate from null must be installed in Settings".
     * Since Android 11 an app may install a client credential this way but never a trust anchor. It is
     * kept because it still works on older releases and costs one cheap attempt before the fallback.
     */
    fun installIntent(context: Context): Intent? = try {
        val cert = readCert(context)
        if (cert == null) {
            null
        } else {
            KeyChain.createInstallIntent().apply {
                putExtra(KeyChain.EXTRA_CERTIFICATE, cert.encoded)
                putExtra(KeyChain.EXTRA_NAME, INSTALL_LABEL)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        }
    } catch (t: Throwable) {
        loge("CentauriCaTrust installIntent", Exception(t))
        null
    }

    /** Parse the on-disk PEM. Parsing validates it: a corrupt file surfaces here, not in the OS dialog. */
    private fun readCert(context: Context): X509Certificate? =
        caCertFile(context).takeIf { it.isFile }?.readBytes()?.inputStream()?.use { stream ->
            CertificateFactory.getInstance("X.509").generateCertificate(stream) as X509Certificate
        }

    /**
     * Stage the CA where the OS certificate installer and the Settings file picker can both reach it.
     *
     * Two copies, because the two routes see different filesystems:
     *  - `cacheDir/centauri-ca.crt`, handed out through the app's existing FileProvider (`cache-path`),
     *    for the direct `ACTION_VIEW` attempt;
     *  - `Downloads/centauri-ca.crt` through MediaStore, because the Settings picker browses shared
     *    storage and cannot see app-private cache.
     *
     * The `.crt` extension is load-bearing: the Settings picker filters by it.
     */
    private fun stage(context: Context): android.net.Uri? = try {
        val pem = caCertFile(context).takeIf { it.isFile }?.readBytes()
        if (pem == null) {
            null
        } else {
            // Shared-storage copy for the Settings picker. Best-effort: failure must not block the
            // direct route, which does not need it.
            try {
                val values = android.content.ContentValues().apply {
                    put(android.provider.MediaStore.Downloads.DISPLAY_NAME, STAGED_FILE_NAME)
                    put(android.provider.MediaStore.Downloads.MIME_TYPE, CA_MIME)
                }
                val collection = android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI
                context.contentResolver.insert(collection, values)?.let { dst ->
                    context.contentResolver.openOutputStream(dst)?.use { it.write(pem) }
                }
            } catch (t: Throwable) {
                loge("CentauriCaTrust stage(downloads)", Exception(t))
            }

            val staged = File(context.cacheDir, STAGED_FILE_NAME).apply { writeBytes(pem) }
            androidx.core.content.FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                staged
            )
        }
    } catch (t: Throwable) {
        loge("CentauriCaTrust stage", Exception(t))
        null
    }

    /**
     * Ask the OS to install the CA, trying the routes in descending order of how few taps they cost:
     *
     *  1. `ACTION_VIEW` on the staged `.crt` with the CA mime type — hands the file straight to
     *     `com.android.certinstaller`, which raises its own naming/confirm sheet.
     *  2. The legacy [KeyChain] intent — still correct on pre-11 releases.
     *  3. Security settings — the user finishes at *Encryption & credentials → Install a certificate →
     *     CA certificate* and picks the copy staged in Downloads.
     *
     * Returns false only when EVERY route failed, which leaves the `:80` serving path untouched: a
     * missing trust anchor degrades the pillar, never the tunnel.
     */
    fun requestInstall(context: Context): Boolean {
        val staged = stage(context)

        // MEASURED on Android 14: BOTH app-initiated routes are refused with "…must be installed in
        // Settings" — the file route reaches com.android.certinstaller and is turned away there, so it
        // costs the user a dead-end dialog for nothing. From API 30 the honest move is to open Settings
        // directly; the CA is already staged in Downloads for the picker.
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.R) {
            if (staged != null) {
                val view = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(staged, CA_MIME)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                if (launch(context, view)) return true
            }
            installIntent(context)?.let { if (launch(context, it)) return true }
        }

        return launch(
            context,
            Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    }

    /** Start an activity, reporting whether anything actually handled it. */
    private fun launch(context: Context, intent: Intent): Boolean = try {
        context.startActivity(intent)
        true
    } catch (t: Throwable) {
        loge("CentauriCaTrust launch", Exception(t))
        false
    }
}
