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
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URL
import javax.inject.Inject
import javax.inject.Named
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Task #19 — the SOURCE-LIST auto-update PRODUCER. ModulesService-scoped, armed when DNSCrypt goes
 * RUNNING, mirrors [CentauriArtifactManager] exactly: `@ModulesServiceScope` + `@Inject` ctor, idempotent
 * `@Synchronized` start/stop, all work on [dispatcherIo], every stage fail-safe (a network fault, a bad
 * signature, a rollback attempt each degrade to "kept the current list" and never throw).
 *
 * **The gap this closes.** Our DNSCrypt engine is now PURE RUST — there is no Go `dnscrypt-proxy` binary,
 * so the `[sources]` self-refresh the Go binary used to run is GONE, and the on-device resolver/relay lists
 * (`public-resolvers.md`, `relays.md`, `odoh-servers.md`, `odoh-relays.md`) have been FROZEN at the install
 * snapshot. The consumer ([RotationPoolSource] parses the "auto-updating, minisig-verified" list) and the
 * verifier ([TortaCore.verifyArtifactSignature] → Rust `verify_minisign`) both already exist; only this
 * PRODUCER was missing. Grow a `.md` on disk and the rotation pool grows on its own.
 *
 * **The security boundary — VERIFY ORDER (load-bearing), same as Centauri.** For each list, OFF the caller
 * thread:
 *   1. GOVERNANCE GATE — [shouldAutoUpdate]; off ⇒ return, no fetch.
 *   2. THROTTLE — skip a list whose on-disk copy is younger than [REFRESH_INTERVAL_MS] (the dnscrypt-proxy
 *      `refresh_delay` default is 72 h; we match it so a RUNNING edge is not a fetch storm).
 *   3. fetch the `.md` + its detached `.minisig` (bounded reads, HTTPS, upstream fallback chain) — the CDN
 *      host is resolved THROUGH DNSCrypt and the TLS socket is opened directly to that IP (SNI = host), so
 *      the hostname NEVER leaks to the system resolver; a host that will not resolve via DNSCrypt is skipped
 *      (fail closed), never fetched over a plaintext-resolved connection.
 *   4. **VERIFY MINISIGN FIRST** — [TortaCore.verifyArtifactSignature] against the PINNED dnscrypt.info key
 *      ([PINNED_DNSCRYPT_PUBKEY_BASE64]). A bad/absent/swapped signature ⇒ REJECT, keep the current list.
 *      This is the ONLY trust anchor: an unsigned or tampered list would inject hostile resolvers.
 *   5. ANTI-ROLLBACK — reject a fetch whose minisign trusted-comment timestamp is OLDER than the last one
 *      we accepted for that list (a replay of a stale-but-genuine list). NOTE: slice-1 reads the timestamp
 *      from the (not-yet-independently-verified) trusted-comment line; verifying the minisign GLOBAL
 *      signature over that line — so the timestamp itself is cryptographically bound — is the slice-2
 *      SURPASS and needs a small Rust helper. The MAIN signature (step 4) already guarantees the `.md`
 *      CONTENT is genuine dnscrypt-signed, so the worst an unverified-timestamp rollback can serve is an
 *      OLDER GENUINE list, never a forged one.
 *   6. ATOMIC WRITE — temp-file + rename the verified `.md` AND its `.minisig` into the dnscrypt-proxy dir
 *      (a half-written list must never be read by the rotation pool). Record the accepted timestamp.
 *
 * No root, no `@Provides`. Default posture is ON (fresh resolvers are the app's core purpose and match the
 * dnscrypt-proxy default), gated by the kill-switch [TortaeKeys.SOURCE_LIST_AUTOUPDATE_ENABLED].
 */
@ModulesServiceScope
@ExperimentalCoroutinesApi
class SourceListUpdateManager @Inject constructor(
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
                    CoroutineName("SourceListUpdateManager") +
                    CoroutineExceptionHandler { _, t ->
                        loge("SourceListUpdateManager uncaught exception", t)
                    }
        )
    }

    /** True while a refresh sweep is in flight, so a repeated RUNNING edge does not stack sweeps. */
    @Volatile
    private var sweeping: Boolean = false

    /**
     * DNSCrypt reached RUNNING (or the engine started standalone). If the auto-update kill-switch is ON
     * (the default), sweep all source lists off the caller thread. Idempotent. Fetches run only AFTER the
     * engine is up, so name resolution for the upstream hosts goes through the live tunnel.
     */
    @Synchronized
    fun start() {
        try {
            if (!shouldAutoUpdate(defaultPreferences)) {
                return
            }
            if (sweeping) {
                return
            }
            sweeping = true
            coroutineScope.launch {
                try {
                    refreshAllLists()
                } finally {
                    sweeping = false
                }
            }
        } catch (e: Exception) {
            loge("SourceListUpdateManager start", e)
            sweeping = false
        }
    }

    /** DNSCrypt stopped (and not standalone): nothing to unwind — the on-disk lists stay as last written. */
    @Synchronized
    fun stop() {
        // No mutable install state to clear; the verified lists remain on disk for the next start.
    }

    /** DNSCrypt reached RUNNING: (re)check the source-list channel. */
    fun onDnsCryptStarted() = start()

    /**
     * DNSCrypt stopped. If the user runs the engine standalone, keep the channel armed (re-check on the
     * next edge); otherwise idle. Mirrors the other managers' standalone-aware stop edge.
     */
    fun onDnsCryptStopped() {
        if (defaultPreferences.getBoolean(TortaeKeys.DNS_ENGINE_STANDALONE, false)) {
            start()
        } else {
            stop()
        }
    }

    /**
     * Refresh every source list in turn. Each list is INDEPENDENT: one list's network fault or verify
     * failure never aborts the others — the sweep is best-effort, per-list fail-safe.
     *
     * **READINESS GATE (fail closed).** Every fetch resolves its upstream CDN host THROUGH DNSCrypt
     * ([resolveViaDnscrypt]); there is NO system-resolver fallback (the app is excluded from its own
     * tunnel, so a JVM-default resolve would leak the hostname in the clear). So before the sweep we probe
     * that the resolver actually answers ([awaitResolverReady] on the first mirror host): if it does not —
     * a boot race, or the engine is mid-bring-up — the whole sweep is SKIPPED (retried on the next
     * RUNNING/standalone edge), never downgraded to plaintext.
     */
    private suspend fun refreshAllLists() {
        val canary = try { URL(LISTS.first().mdUrls.first()).host } catch (_: Exception) { null }
        if (canary != null && !awaitResolverReady(canary)) {
            logw("SourceListUpdateManager — resolver not serving yet; skipping sweep (no plaintext fallback)")
            return
        }
        val dir = File(pathVars.get().appDataDir + DNSCRYPT_DIR)
        for (spec in LISTS) {
            try {
                refreshOne(spec, dir)
            } catch (e: Exception) {
                loge("SourceListUpdateManager — ${spec.fileName}: staying on the current list", e)
            }
        }
    }

    /**
     * Poll [resolveViaDnscrypt] on [canaryHost] until the DNSCrypt resolver answers, or the attempt budget
     * ([RESOLVER_READY_ATTEMPTS] × [RESOLVER_READY_BACKOFF_MS]) runs out. This is the anti-race half of the
     * fail-closed posture: the source-list sweep fires on the DNSCrypt-RUNNING edge, which can beat the Rust
     * MODE-2 pool's first `configure` by a beat — so a single cold probe would spuriously skip the boot
     * sweep. A short bounded settle wait lets the resolver come up. Returns `true` the instant it answers,
     * `false` if it never does (the caller then skips the sweep — NO plaintext fallback). Never throws.
     */
    private suspend fun awaitResolverReady(canaryHost: String): Boolean {
        for (attempt in 0 until RESOLVER_READY_ATTEMPTS) {
            if (resolveViaDnscrypt(canaryHost).isNotEmpty()) return true
            if (attempt < RESOLVER_READY_ATTEMPTS - 1) {
                kotlinx.coroutines.delay(RESOLVER_READY_BACKOFF_MS)
            }
        }
        return false
    }

    /**
     * The full per-list pipeline. THE ORDER is the point: throttle → fetch → VERIFY → anti-rollback →
     * atomic-write. Any failure short-circuits to "kept the current list".
     */
    private fun refreshOne(spec: ListSpec, dir: File) {
        val mdFile = File(dir, spec.fileName)
        val sigFile = File(dir, spec.fileName + MINISIG_SUFFIX)

        // Step 2 — THROTTLE. A list refreshed within the window is left alone (no fetch storm on every
        // RUNNING edge). A missing/empty local list is always fetched (age = infinite).
        if (mdFile.isFile && mdFile.length() > 0L) {
            val age = System.currentTimeMillis() - mdFile.lastModified()
            if (age in 0 until REFRESH_INTERVAL_MS) {
                return
            }
        }

        // Step 3 — FETCH (bounded, HTTPS, fallback chain). An unsigned list (no fetchable .minisig) is
        // rejected outright: we never write a list we cannot authenticate.
        val md = httpGetBounded(spec.mdUrls, MAX_MD_BYTES) ?: run {
            logw("SourceListUpdateManager — ${spec.fileName}: fetch failed on all mirrors, keeping current")
            return
        }
        val sigBytes = httpGetBounded(spec.sigUrls, MAX_MINISIG_BYTES) ?: run {
            logw("SourceListUpdateManager — ${spec.fileName}: no fetchable .minisig, rejecting (unsigned)")
            return
        }
        val sigText = String(sigBytes, Charsets.UTF_8)

        // Step 4 — VERIFY MINISIGN FIRST (provenance). The pinned dnscrypt.info public key is the only
        // trust anchor. A bad/absent/swapped signature ⇒ reject; the current on-disk list is untouched.
        val verified = TortaCore.verifyArtifactSignature(
            artifactBytes = md,
            minisigText = sigText,
            pinnedPubKeyBase64 = PINNED_DNSCRYPT_PUBKEY_BASE64,
        )
        if (!verified) {
            loge("SourceListUpdateManager — ${spec.fileName}: minisign verification FAILED; rejecting " +
                    "(provenance unproven — the list is NOT written)")
            return
        }

        // Step 5 — ANTI-ROLLBACK. Reject a fetch whose signed timestamp predates the last accepted one.
        val fetchedTs = parseTrustedTimestamp(sigText)
        val prevTs = defaultPreferences.getLong(tsKey(spec), 0L)
        if (fetchedTs != null && prevTs > 0L && fetchedTs < prevTs) {
            logw("SourceListUpdateManager — ${spec.fileName}: rollback rejected " +
                    "(fetched ts=$fetchedTs < accepted ts=$prevTs)")
            return
        }

        // Step 6 — ATOMIC WRITE both artifacts (list first, then its signature). A rotation pool read that
        // races the write sees either the whole old pair or the whole new pair, never a torn list.
        if (!atomicWrite(mdFile, md)) {
            loge("SourceListUpdateManager — ${spec.fileName}: atomic write of the list failed")
            return
        }
        if (!atomicWrite(sigFile, sigBytes)) {
            loge("SourceListUpdateManager — ${spec.fileName}: atomic write of the .minisig failed")
            return
        }
        if (fetchedTs != null) {
            defaultPreferences.edit().putLong(tsKey(spec), fetchedTs).apply()
        }
        logi("SourceListUpdateManager — ${spec.fileName}: refreshed + verified " +
                "(${md.size} B, ts=${fetchedTs ?: "n/a"})")
    }

    companion object {
        /** Relative path from [PathVars.appDataDir] to the dnscrypt-proxy working dir (trailing slash). */
        private const val DNSCRYPT_DIR = "/app_data/dnscrypt-proxy/"

        /** Suffix dnscrypt appends for a detached minisign signature (`public-resolvers.md.minisig`). */
        const val MINISIG_SUFFIX = ".minisig"

        /**
         * The PINNED dnscrypt.info minisign PUBLIC key (base64 of `Ed`(2) ‖ key_id(8) ‖ pk(32)). CONFIRMED
         * against the real on-device signatures: key_id `1fe8b442180f62e7`, pk
         * `79a561e70e…1853b7`, legacy `Ed` tag. The private key lives offline with the dnscrypt maintainer
         * and never ships; this pin is what makes a swapped-key attack fail at the on-device verify. The
         * SAME key signs all four lists (public-resolvers, relays, odoh-servers, odoh-relays).
         */
        const val PINNED_DNSCRYPT_PUBKEY_BASE64 =
            "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"

        /** Bounded reads — a hostile mirror must not be slurped whole. */
        const val MAX_MD_BYTES = 8L shl 20        // 8 MiB — public-resolvers.md is ~160 KiB today
        const val MAX_MINISIG_BYTES = 4L shl 10   // 4 KiB — a `.minisig` is a tiny text file

        /** Match the dnscrypt-proxy `refresh_delay` default (72 h) so a RUNNING edge is not a fetch storm. */
        const val REFRESH_INTERVAL_MS = 72L * 60L * 60L * 1000L

        private const val HTTP_CONNECT_TIMEOUT_MS = 15_000
        private const val HTTP_READ_TIMEOUT_MS = 30_000

        /** DNS QTYPEs for the private resolve (the codec is [TortaCore.buildQuery]'s, ground-truthed). */
        private const val DNS_TYPE_A = 1
        private const val DNS_TYPE_AAAA = 28

        /** The TLS port every mirror is reached on (we connect to the DNSCrypt-resolved IP, SNI = host). */
        private const val HTTPS_PORT = 443

        /**
         * Readiness settle budget for the fail-closed sweep gate. The sweep fires on the DNSCrypt-RUNNING
         * edge which can beat the Rust resolver's first `configure`; probe up to 5× with a 1.5 s backoff
         * (≈6 s worst case) before giving up and skipping the sweep. NEVER a plaintext fallback.
         */
        private const val RESOLVER_READY_ATTEMPTS = 5
        private const val RESOLVER_READY_BACKOFF_MS = 1_500L

        /**
         * One source list: its on-disk file name and the ordered upstream mirrors (primary + fallbacks),
         * ground-truthed from `dnscrypt-proxy-master`'s own `[sources]` (v3). The `.minisig` sits at
         * `<url>.minisig` on every mirror.
         */
        data class ListSpec(val fileName: String, val mdUrls: List<String>) {
            val sigUrls: List<String> get() = mdUrls.map { it + MINISIG_SUFFIX }
        }

        private fun v3(name: String): ListSpec = ListSpec(
            fileName = name,
            mdUrls = listOf(
                "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/$name",
                "https://download.dnscrypt.info/resolvers-list/v3/$name",
                "https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/$name",
            ),
        )

        /** All four auto-updating lists — the resolvers, the relays, and their ODoH twins. */
        val LISTS: List<ListSpec> = listOf(
            v3("public-resolvers.md"),
            v3("relays.md"),
            v3("odoh-servers.md"),
            v3("odoh-relays.md"),
        )

        /** Per-list SharedPreferences key holding the last accepted minisign timestamp (anti-rollback). */
        private fun tsKey(spec: ListSpec): String = "pref_source_list_ts_" + spec.fileName

        /**
         * THE GOVERNANCE GATE, extracted pure so it is unit-testable without an Android `Context`.
         *
         * **DEFAULT ON (slice-2 — the privacy leak is closed).** Source lists auto-update by default (fresh
         * resolvers are the app's core purpose and match the dnscrypt-proxy `[sources]` default). The
         * name-resolution privacy concern that held slice-1 at default-OFF is RESOLVED: the fetch no longer
         * touches the JVM's system resolver at all — it resolves each CDN host THROUGH DNSCrypt
         * ([resolveViaDnscrypt] → [TortaCore.buildQuery]/[TortaCore.resolve]) and opens the TLS socket
         * directly to that resolved IP with SNI = the real host ([httpsGetViaIp]), FAILING CLOSED (skipping
         * the sweep) whenever the resolver is not yet serving. So a fresh install refreshes privately out of
         * the box; only the explicit [TortaeKeys.SOURCE_LIST_AUTOUPDATE_ENABLED] kill-switch silences it.
         */
        fun shouldAutoUpdate(prefs: SharedPreferences): Boolean =
            prefs.getBoolean(TortaeKeys.SOURCE_LIST_AUTOUPDATE_ENABLED, true)

        /**
         * Parse the minisign trusted-comment UNIX timestamp — line 3 is
         * `trusted comment: timestamp:<unix>\tfile:<name>`. Returns the `<unix>` seconds or `null` if the
         * line/field is absent or unparseable. Pure; no I/O.
         */
        fun parseTrustedTimestamp(minisigText: String): Long? {
            val line = minisigText.lineSequence()
                .firstOrNull { it.startsWith("trusted comment:") } ?: return null
            val marker = "timestamp:"
            val at = line.indexOf(marker)
            if (at < 0) return null
            val rest = line.substring(at + marker.length)
            // The value runs to the next whitespace (a tab before `file:` in the canonical form).
            val end = rest.indexOfFirst { it == '\t' || it == ' ' }
            val token = if (end < 0) rest else rest.substring(0, end)
            return token.trim().toLongOrNull()
        }

        /**
         * Bounded HTTPS GET across an ordered mirror list — returns the first mirror's body (≤ [maxBytes]),
         * or `null` if every mirror fails. **PRIVATE by construction (slice-2):** the upstream host is
         * resolved THROUGH DNSCrypt ([resolveViaDnscrypt]) and the body is fetched over a TLS socket opened
         * DIRECTLY to that resolved IP with SNI = the real host ([httpsGetViaIp]) — the JVM's system
         * resolver is never consulted, so the CDN hostname never leaks in the clear. A host that does not
         * resolve via DNSCrypt is SKIPPED (fail closed), NEVER retried over plaintext. HTTP (non-TLS) URLs
         * and any body over the cap are refused. Never throws: a fault on one mirror falls through.
         */
        fun httpGetBounded(urls: List<String>, maxBytes: Long): ByteArray? {
            for (raw in urls) {
                try {
                    if (!raw.startsWith("https://")) continue   // TLS only — never fetch a list over plaintext
                    val u = URL(raw)
                    val host = u.host ?: continue
                    val path = u.file.ifEmpty { "/" }           // path + query; URL parsing does NO DNS
                    // RESOLVE via DNSCrypt only. Empty ⇒ the resolver did not answer for this host: skip
                    // the mirror (fail closed) — we do NOT fall back to the system resolver.
                    val addrs = resolveViaDnscrypt(host)
                    if (addrs.isEmpty()) {
                        logw("SourceListUpdateManager — $host: no DNSCrypt answer, skipping mirror " +
                                "(no plaintext fallback)")
                        continue
                    }
                    for (ip in addrs) {
                        val body = httpsGetViaIp(host, path, ip, maxBytes)
                        if (body != null) return body
                    }
                } catch (_: Exception) {
                    // Try the next mirror.
                }
            }
            return null
        }

        /**
         * Resolve [host] to its A + AAAA addresses THROUGH the DNSCrypt engine — never the system resolver.
         * The wire A/AAAA queries are built by the single-source-of-truth [TortaCore.buildQuery] (wrapping
         * Rust `dns::build_query`) and answered by [TortaCore.resolve] (block-check → cache → encrypted
         * transport → validate). The answer RDATA is parsed by [parseDnsAddresses] and each address is built
         * via [InetAddress.getByAddress] (NO reverse lookup ⇒ no leak). Returns A addresses first (then
         * AAAA); EMPTY means "the resolver is not serving / the host does not resolve" — the caller then
         * FAILS CLOSED. Never throws.
         */
        internal fun resolveViaDnscrypt(host: String): List<InetAddress> {
            val out = ArrayList<InetAddress>()
            for (qtype in intArrayOf(DNS_TYPE_A, DNS_TYPE_AAAA)) {
                try {
                    val query = TortaCore.buildQuery(host, qtype) ?: continue
                    val resp = TortaCore.resolve(query) ?: continue
                    out.addAll(parseDnsAddresses(resp, qtype))
                } catch (_: Exception) {
                    // Best-effort per QTYPE; a fault on A still lets AAAA try (and vice-versa).
                }
            }
            return out
        }

        /**
         * Parse the A (QTYPE 1, 4-byte) or AAAA (QTYPE 28, 16-byte) address RDATA out of a wire-format DNS
         * response [wire]. Walks the 12-byte header, skips the question section, then each answer RR
         * (honoring DNS name compression), collecting only records of [wantType] with the exact RDATA
         * length. A non-zero RCODE (NXDOMAIN/SERVFAIL/…) yields empty. Bad offsets short-circuit to what was
         * parsed so far — a truncated/hostile response can never over-read. Pure; no I/O; never throws.
         * Extracted `internal` so the codec is unit-provable on a plain JVM against a known response blob.
         */
        internal fun parseDnsAddresses(wire: ByteArray, wantType: Int): List<InetAddress> {
            if (wire.size < 12) return emptyList()
            fun u16(i: Int): Int = ((wire[i].toInt() and 0xFF) shl 8) or (wire[i + 1].toInt() and 0xFF)
            if ((wire[3].toInt() and 0x0F) != 0) return emptyList()   // RCODE != NOERROR ⇒ no addresses
            val qd = u16(4)
            val an = u16(6)
            var p = 12
            var q = 0
            while (q < qd) {
                p = skipDnsName(wire, p)
                if (p < 0 || p + 4 > wire.size) return emptyList()
                p += 4  // QTYPE + QCLASS
                q++
            }
            val out = ArrayList<InetAddress>()
            var a = 0
            while (a < an) {
                p = skipDnsName(wire, p)
                if (p < 0 || p + 10 > wire.size) return out
                val type = u16(p)
                val rdlen = u16(p + 8)
                p += 10
                if (p + rdlen > wire.size) return out
                val wantLen = if (wantType == DNS_TYPE_A) 4 else 16
                if (type == wantType && rdlen == wantLen) {
                    try {
                        out.add(InetAddress.getByAddress(wire.copyOfRange(p, p + rdlen)))
                    } catch (_: Exception) {
                    }
                }
                p += rdlen
                a++
            }
            return out
        }

        /**
         * Skip a DNS name starting at [start], honoring compression pointers (`0xC0` high bits) — a pointer
         * terminates the name in-place (2 bytes), a zero-length label ends it (1 byte). Returns the offset
         * just past the name, or -1 on a run-off. Pure.
         */
        private fun skipDnsName(wire: ByteArray, start: Int): Int {
            var p = start
            while (p < wire.size) {
                val len = wire[p].toInt() and 0xFF
                when {
                    len == 0 -> return p + 1
                    len and 0xC0 == 0xC0 -> return p + 2   // compression pointer: name ends here
                    else -> p += 1 + len
                }
            }
            return -1
        }

        /**
         * Fetch `https://<host><path>` over a TLS socket opened DIRECTLY to the DNSCrypt-resolved [ip] — the
         * privacy core. SNI is set to the REAL [host] (not the IP) so the CDN serves the right cert + vhost,
         * and the peer certificate is verified against [host] with the platform's default hostname verifier
         * (the IP is not in the cert, so this MUST verify the name, not the address). A hand-written minimal
         * HTTP/1.1 GET (identity encoding — no gzip; `Connection: close`; NO redirect following) is sent and
         * the body read back bounded to [maxBytes]. Only a `200` is accepted; any 3xx/4xx/5xx returns `null`
         * so the caller tries the next mirror/IP (a redirect to another host would need a fresh private
         * resolve, so we decline it here rather than risk a system-resolver hop). Never throws.
         */
        private fun httpsGetViaIp(host: String, path: String, ip: InetAddress, maxBytes: Long): ByteArray? {
            var socket: SSLSocket? = null
            return try {
                val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                socket = (factory.createSocket() as SSLSocket).apply {
                    connect(InetSocketAddress(ip, HTTPS_PORT), HTTP_CONNECT_TIMEOUT_MS)
                    soTimeout = HTTP_READ_TIMEOUT_MS
                    sslParameters = sslParameters.apply { serverNames = listOf(SNIHostName(host)) }
                }
                socket.startHandshake()
                if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, socket.session)) {
                    return null   // cert does not match the intended host — refuse (never trust the IP alone)
                }
                val request = "GET $path HTTP/1.1\r\n" +
                        "Host: $host\r\n" +
                        "User-Agent: YeahTorta-SourceList/1.0\r\n" +
                        "Accept: text/plain, */*\r\n" +
                        "Accept-Encoding: identity\r\n" +
                        "Connection: close\r\n\r\n"
                socket.outputStream.apply {
                    write(request.toByteArray(Charsets.US_ASCII))
                    flush()
                }
                readHttpResponseBody(socket.inputStream, maxBytes)
            } catch (_: Exception) {
                null
            } finally {
                try {
                    socket?.close()
                } catch (_: Exception) {
                }
            }
        }

        /**
         * Read a minimal HTTP/1.1 response: parse the status line (accept ONLY `200`), consume headers, then
         * read the body per `Transfer-Encoding: chunked` OR `Content-Length` OR to EOF (`Connection: close`)
         * — always bounded to [maxBytes] (`null` if exceeded, the anti-slurp guard). `null` on a non-200
         * status or a malformed head. Never throws to the caller's frame beyond the outer catch.
         */
        private fun readHttpResponseBody(input: java.io.InputStream, maxBytes: Long): ByteArray? {
            val stream = java.io.BufferedInputStream(input)
            val status = readHttpLine(stream) ?: return null
            // "HTTP/1.1 200 OK" → the second token is the status code.
            val code = status.split(' ').getOrNull(1)?.toIntOrNull() ?: return null
            if (code != 200) return null
            var contentLength = -1L
            var chunked = false
            while (true) {
                val line = readHttpLine(stream) ?: return null
                if (line.isEmpty()) break   // blank line ⇒ end of headers
                val colon = line.indexOf(':')
                if (colon <= 0) continue
                val name = line.substring(0, colon).trim().lowercase()
                val value = line.substring(colon + 1).trim()
                when (name) {
                    "content-length" -> contentLength = value.toLongOrNull() ?: -1L
                    "transfer-encoding" -> if (value.lowercase().contains("chunked")) chunked = true
                }
            }
            return when {
                chunked -> readChunkedBody(stream, maxBytes)
                contentLength >= 0 -> readFixedBody(stream, contentLength, maxBytes)
                else -> readBounded(stream, maxBytes)   // Connection: close, no length ⇒ read to EOF
            }
        }

        /** Read one CRLF-terminated header/status line as ASCII (without the CRLF), or `null` on EOF. */
        private fun readHttpLine(input: java.io.InputStream): String? {
            val buf = java.io.ByteArrayOutputStream(128)
            var sawAny = false
            while (true) {
                val b = input.read()
                if (b < 0) return if (sawAny) String(buf.toByteArray(), Charsets.US_ASCII) else null
                sawAny = true
                if (b == '\n'.code) {
                    val bytes = buf.toByteArray()
                    val len = if (bytes.isNotEmpty() && bytes[bytes.size - 1] == '\r'.code.toByte()) {
                        bytes.size - 1
                    } else {
                        bytes.size
                    }
                    return String(bytes, 0, len, Charsets.US_ASCII)
                }
                buf.write(b)
            }
        }

        /** Read a `Transfer-Encoding: chunked` body, bounded to [maxBytes] (`null` if exceeded). */
        private fun readChunkedBody(input: java.io.InputStream, maxBytes: Long): ByteArray? {
            val out = java.io.ByteArrayOutputStream()
            var total = 0L
            while (true) {
                val sizeLine = readHttpLine(input) ?: return null
                // A chunk-size line may carry `;ext` extensions — the size is the hex before the ';'.
                val hex = sizeLine.substringBefore(';').trim()
                val size = hex.toLongOrNull(16) ?: return null
                if (size == 0L) break   // last chunk; trailing headers (if any) are ignored
                total += size
                if (total > maxBytes) return null
                var remaining = size
                val buf = ByteArray(64 * 1024)
                while (remaining > 0) {
                    val toRead = minOf(remaining, buf.size.toLong()).toInt()
                    val n = input.read(buf, 0, toRead)
                    if (n < 0) return null
                    out.write(buf, 0, n)
                    remaining -= n
                }
                // Each chunk's data is followed by a bare CRLF — consume it.
                readHttpLine(input) ?: return null
            }
            return out.toByteArray()
        }

        /** Read exactly [length] body bytes (bounded to [maxBytes]); `null` on short read or over-cap. */
        private fun readFixedBody(input: java.io.InputStream, length: Long, maxBytes: Long): ByteArray? {
            if (length > maxBytes) return null
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(64 * 1024)
            var remaining = length
            while (remaining > 0) {
                val toRead = minOf(remaining, buf.size.toLong()).toInt()
                val n = input.read(buf, 0, toRead)
                if (n < 0) return null   // truncated body
                out.write(buf, 0, n)
                remaining -= n
            }
            return out.toByteArray()
        }

        /** Read at most [maxBytes] from [input] to EOF; return `null` if the stream exceeds the cap. */
        private fun readBounded(input: java.io.InputStream, maxBytes: Long): ByteArray? {
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                total += n
                if (total > maxBytes) return null
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }

        /**
         * ATOMIC file write: stage to a sibling `<file>.new` then `renameTo` the target. A same-directory
         * rename is atomic on the app-private filesystem, so a reader (the rotation pool) never observes a
         * torn list. Returns `true` on success; a failed rename cleans up the temp and returns `false`.
         */
        fun atomicWrite(target: File, bytes: ByteArray): Boolean {
            val tmp = File(target.parentFile, target.name + ".new")
            return try {
                target.parentFile?.mkdirs()
                tmp.outputStream().use { it.write(bytes); it.flush() }
                if (tmp.renameTo(target)) {
                    true
                } else {
                    // Some filesystems refuse rename-over-existing; replace explicitly then rename.
                    if (target.exists() && target.delete() && tmp.renameTo(target)) {
                        true
                    } else {
                        tmp.delete()
                        false
                    }
                }
            } catch (e: Exception) {
                loge("SourceListUpdateManager — atomicWrite ${target.name}", e)
                tmp.delete()
                false
            }
        }
    }
}
