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

import pillar.kuma_saimono.libumdnscrypt.utils.mmap.MmapTail
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * #133 — the per-pillar event log. Each pillar gets its OWN `query-<pillar>.log`, and they ALL write
 * through this single **pure-Kotlin** helper, so the pillars share one format + one location + one
 * read/debug path — the way `dnscrypt-proxy` populates `cache/query.log` (a timestamped, one-line-per-event
 * file the dashboards already tail). Generalized to every Tortä pillar.
 *
 * Pure-Kotlin by design (no native bridge): the write is a plain bounded file append, so adding a pillar's
 * log can never touch the Rust/UniFFI surface or the native `.so`. The existing
 * [pillar.kuma_saimono.libumdnscrypt.rust.TortaCore.logTailRecent] RAM⊗NAND fast-tier still READS any
 * `query-<pillar>.log` for the dashboards — one shared read path, a trivial write path.
 *
 * ## Where
 * Beside `DnsCrypt.log`, in the app-private logs dir: `<appDataDir>/logs/query-<pillar>.log`.
 *
 * ## The shared format (one line per event)
 * ```
 * [yyyy-MM-dd HH:mm:ss] <pillar> <event> key=value key=value …
 * ```
 * The bracketed timestamp is the dnscrypt `query.log` convention (one sortable column), so a unified debug
 * view can interleave EVERY `query-*.log` and correlate pillar events across the engine by time.
 *
 * ## Discipline
 * - **Control-plane, not the hot path.** Pillars log their *events* (a rotation swap, a heal, a cache fill,
 *   an attest, a CAKE state tick) — never per-resolved-query, never on the resolve() hot path.
 * - **No qname/PII.** Operational fields only (counts, families, modes, codes, byte totals), mirroring
 *   `resolverStats`'s "no qname ever" law (T20). #10.5 Beast connection-attribution is the deliberate,
 *   separately-gated exception — not the default.
 * - **Bounded + fail-open.** Each file is tail-rewritten at [MAX_LOG_BYTES]; any IO error is a silent no-op.
 *   A debug log can NEVER break a pillar.
 */
object PillarLog {

    /**
     * The pillars that own a `query-<pillar>.log`. The [tag] is the file infix AND the line's column.
     *
     * WIRED today (ready pillars): SOLVER + DNSMASQ (the engine tick), ROTATION (on swap), BLOCKLIST
     * (per DNSCrypt start), GITHUB_TRUST (#18 — crown rehydrate at boot pillar 7 + per investigate/cached
     * verdict serve). WARDEN is RESERVED but intentionally NOT wired yet (needs its full rebuild),
     * so emitting a log for it would be premature. Wiring it later is a one-liner.
     *
     * ## The log canon (D40)
     * Where a RUST pillar-log seam exists, IT is canonical and this Kotlin substrate does NOT write
     * that file — one file, one writer, one law. BEAST is the first canon pillar: `query-beast.log`
     * is written ONLY by the Rust `log_tier` seam (`Beast.bindLogDir` at engine build +
     * `Beast.logEvent` on [BeastMetricSinkImpl]'s latched cadence); its enum entry stays for
     * path/tail reads. CENTAURI is the second (D29): `query-centauri.log` is written ONLY by the Rust
     * `log_tier` seam, SELF-FED by the live loopback accept loop per serve (plus the exported
     * `recordServeLogged` control-plane twin) — and it lives BESIDE the content-addressed cache
     * (`app_data/centauri_cache/query-centauri.log`, the Object owns its log location; read the path
     * via `TortaCore.centauriQueryLogPath`), NOT under `<appDataDir>/logs/`. Pillars with no Rust twin
     * (SOLVER, DNSMASQ, ...) stay on this substrate.
     */
    enum class Pillar(val tag: String) {
        BEAST("beast"), // D40 canon: Rust-written (log_tier) — never write it from Kotlin
        SOLVER("solver"),
        ROTATION("rotation"),
        BLOCKLIST("blocklist"),
        CENTAURI("centauri"), // D40 canon: Rust-written, self-fed per serve (D29) — never write it from Kotlin
        DNSMASQ("dnsmasq"),
        WARDEN("warden"), // reserved — not wired yet (#108, not ready)
        GITHUB_TRUST("github-trust"), // #18 G6 — the crown pillar (no Rust log seam in github.rs ⇒ this substrate is canon per D40)

        /**
         * The Underground Layer's review channel. D40 canon: **Rust-written** — never write it from
         * Kotlin. `underground.rs` appends one line per judgement (DEDUCT / SEQUESTRATE / PROBATION /
         * PINNED / CONDEMNED / AMNESTY) as `<ts> <VERB> <host> <lane> -<penalty> licence=<points>`.
         *
         * ★ PATH — this pillar does NOT live under [pathFor]. MEASURED at `lib.rs:1892-1899`:
         * `resolver_rehydrate_cache(dir)` arms `resolver::arm_query_log(&dir)` and `underground::arm(&dir)`
         * with the SAME durable dir, so `query-underground.log` is written beside `underground-ledger.tsv`
         * AND beside `query-masksolver.log` — the resolver's durable dir, NOT `<appDataDir>/logs/`.
         *
         * That is the reassuring part: MASKSOLVER already reaches the UI from exactly this dir, so the
         * reader for UNDERGROUND must resolve its path the same way MASKSOLVER does — not via [pathFor],
         * and not by assuming the CENTAURI arrangement (which owns a different dir again and is the one
         * pillar whose log has never appeared on device).
         *
         * WHY IT EXISTS: the Underground Layer was the only pillar that could CONVICT a host while
         * narrating nothing, which is why ROOT CAUSE #26 (nx_burst reading the browser's speculative
         * AAAA/HTTPS negatives as DNS tunnelling) cost a whole session to find — the conviction was only
         * visible as its own aftermath. The `lane` column is the point: a browsing or music host filed
         * under `tunnel` is the #26 signature, obvious at a glance instead of reconstructed backwards.
         */
        UNDERGROUND("underground"),
    }

    /** Per-pillar log size cap (256 KiB) and the tail kept on overflow (128 KiB) — the anti-bloat rewrite. */
    private const val MAX_LOG_BYTES = 256L * 1024L
    private const val KEEP_BYTES = 128 * 1024

    /** Per-thread timestamp formatter (SimpleDateFormat is not thread-safe). dnscrypt's column convention. */
    private val TS: ThreadLocal<SimpleDateFormat> =
        object : ThreadLocal<SimpleDateFormat>() {
            override fun initialValue() = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        }

    /**
     * ThreadLocal.get() is typed nullable, but this one overrides initialValue() and therefore
     * cannot return null. Rather than assert that with `!!` -- which turns an impossible case into
     * a crash in the LOGGER, of all places -- the fallback constructs the identical formatter. A
     * log line is never worth an exception, and the two paths produce byte-identical output.
     */
    private fun timestampFormat(): SimpleDateFormat =
        TS.get() ?: SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

    private val WS = Regex("\\s+")

    /** The per-pillar log path beside `DnsCrypt.log`: `<appDataDir>/logs/query-<pillar>.log`. */
    fun pathFor(appDataDir: String, pillar: Pillar): String =
        "$appDataDir/logs/query-${pillar.tag}.log"

    /**
     * Append one shared-format event to [pillar]'s log. [event] is the verb (e.g. "switch", "heal", "fill",
     * "tick"); [fields] are operational `key to value` pairs — a null value is skipped, a value's whitespace
     * is collapsed to `_` so it never splits the columns. Bounded + crash-proof; never throws.
     */
    fun event(appDataDir: String, pillar: Pillar, event: String, vararg fields: Pair<String, Any?>) {
        try {
            val dir = File(appDataDir, "logs")
            if (!dir.exists()) dir.mkdirs()
            val file = File(dir, "query-${pillar.tag}.log")

            val sb = StringBuilder(64)
            sb.append('[').append(timestampFormat().format(Date())).append("] ")
            sb.append(pillar.tag).append(' ').append(event)
            for ((k, v) in fields) {
                if (v == null) continue
                sb.append(' ').append(k).append('=').append(WS.replace(v.toString(), "_"))
            }
            sb.append('\n')

            file.appendText(sb.toString())

            // Anti-bloat: past the cap, keep only the last KEEP_BYTES from a line boundary (never a torn head).
            // #20 — the kept tail is read through a tail-window mmap (O(KEEP_BYTES): the >128 KiB head is
            // never faulted in) with the original whole-file readBytes() as the fail-open fallback; both
            // produce the SAME suffix bytes, so the boundary scan + rewrite below are mechanism-blind.
            if (file.length() > MAX_LOG_BYTES) {
                val bytes = MmapTail.tailWindow(file, KEEP_BYTES)?.bytes ?: run {
                    val all = file.readBytes()
                    val cut = (all.size - KEEP_BYTES).coerceAtLeast(0)
                    all.copyOfRange(cut, all.size)
                }
                var start = 0
                while (start < bytes.size && bytes[start] != '\n'.code.toByte()) start++
                if (start < bytes.size) start++ // skip the newline so we keep whole lines
                file.writeBytes(bytes.copyOfRange(start.coerceAtMost(bytes.size), bytes.size))
            }
        } catch (_: Throwable) {
            // A debug log must never break a pillar — swallow everything.
        }
    }
}
