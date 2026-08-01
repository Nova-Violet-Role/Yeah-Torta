/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! ★ E-FIX r5 (R5-Q1) — the `cache/query.log` FEED for **Rust-answered datapath queries**.
//!
//! ## The witnessed regression this closes
//! The QUERY surface (the burger's `open-query-log` → `/cache/query.log`, and the DEBUG
//! [QueryLogTailer] shadow seam) is fed by the file the **Go** `dnscrypt-proxy` writes — and the Go
//! proxy can only log what reaches its loopback listener. Since the sovereign rewire, the production
//! pool is MODE 2 (the Rust DNSCrypt v2 transport answers intercepted foreign queries DIRECTLY), so a
//! foreign query answered by `torta_resolve` **never reaches the Go proxy and never lands in
//! query.log**: AVD round 5 witnessed the NXDOMAIN canary, wikipedia and the blocked example.org all
//! answered live (DNS-tab feed + dnsmasq stats climbing) while `query.log`'s 229 rows carried only
//! Go-visible traffic. Round 4 saw foreign rows only because those exercises happened while the Go
//! loopback path was serving. This module writes the missing rows: when the armed datapath
//! ([`super::resolve_datapath`]) ANSWERS a query the Go proxy will never see, it appends ONE row in
//! the exact Go `query.log` TSV shape, so the QUERY surface reports foreign traffic in BOTH modes.
//!
//! ## The row shape (byte-compatible with the Go writer — measured from a live device pull)
//! ```text
//! [2026-07-03 01:19:16]\t127.0.0.1\texample.com\tA\tPASS\t23ms\t-\t-\n
//! ```
//! `[local datetime]` TAB client TAB qname TAB qtype-text TAB status TAB `<n>ms` TAB server TAB relay.
//! The client renders the loopback literal (every row the Go proxy writes on this datapath carries
//! `127.0.0.1` — the tun forward arrives via loopback; per-app attribution lives in the DNS-tab feed,
//! never here). The server/relay columns render `-` — the pool returns the winning WIRE, not the
//! winning upstream id (the same honest-unknown as `query-masksolver.log`'s transport column), and the
//! Go writer itself renders `-` for its locally-answered rows.
//!
//! ## Privacy contract (LOUD — this file carries qnames)
//! Unlike every `query-<pillar>.log` (T20: counts + tokens, NEVER a qname), this feed writes the
//! QNAME — because it mirrors the **explicit query-logging surface the user (or a debug build) opted
//! into**: the arm ([`super::arm_query_feed`]) is driven ONLY by the effective `dnscrypt-proxy.toml`
//! `[query_log] file` value — the SAME enable the Go producer obeys (DEBUG-gated by
//! `ModulesStarterHelper.enableQueryLogForDebug`, or the user's own SLINT/settings query-log toggle).
//! No toml enable → never armed → release ships query logging OFF with ZERO feed writes — exactly the
//! Go posture. A BLANK arm DISARMS (the toggle can be flipped off between engine starts).
//!
//! ## Write discipline
//! The file is **owned by the Go proxy** (it rotates it by size). We therefore append with a plain
//! open-append-write-close per row — NEVER through [`crate::log_tier`], whose 256 KiB line-boundary
//! tail-REWRITE would truncate a file another process holds an open append handle on (fd-offset
//! chaos). One `O_APPEND` write per row (< 4 KiB) is atomic on the device filesystems; open-per-row
//! means a Go-side rotation rename can never strand our handle. FAIL-OPEN: any IO error is a silent
//! no-op — telemetry must never break the resolve path. The armed path is opt-in (debug/user), so the
//! per-row open cost rides only the mode that asked for it.

use std::path::Path;

use super::log::ResolveOutcome;

/// The client column literal — the datapath rows the Go proxy writes carry the loopback source (the
/// tun forward arrives via loopback), and this feed mirrors that shape. Per-app attribution is the
/// DNS-tab feed's job (ServiceVPN connection records), never query.log's.
pub(crate) const CLIENT_LOOPBACK: &str = "127.0.0.1";

/// Map a classified datapath outcome to the Go `query.log` status vocabulary, or `None` for outcomes
/// that must never produce a feed row. The tokens are the Go writer's own (`PASS`/`NXDOMAIN`/
/// `REJECT`/`CLOAK`), so every existing consumer (QueryLogTailer field\[4\], SolverDashboardCard's
/// counter, ResolverRuntime's RETURNCODE class split) parses our rows unchanged:
///
/// - `CacheHit`/`ServeStale`/`Solved` → `PASS` (an answered positive — the Go token for the same).
/// - `SolvedNegative` → `NXDOMAIN` (a validated upstream negative returned to the client).
/// - `LocalAnswer` → `CLOAK` (a user pin / `address=` literal / Centauri cloak — a name answered
///   with a configured address, the Go cloaking-plugin semantic).
/// - `Blocked`/`Guarded` → `REJECT` (the blocklist deny + the bogus-priv/never-forward privacy
///   guards — the Go blocked-names/block-undelegated semantic; RFC 6761 special-use is exactly Go's
///   `block_undelegated` REJECT class).
/// - `RebindReject`/`Rejected`/`Miss` → `None`: those datapath arms return NO answer (`None` wire),
///   so the C bridge falls through to the Go proxy — which then owns the query's row. Logging them
///   here would double-report the same query.
pub(crate) fn status_token(outcome: ResolveOutcome) -> Option<&'static str> {
    match outcome {
        ResolveOutcome::CacheHit | ResolveOutcome::ServeStale | ResolveOutcome::Solved => {
            Some("PASS")
        }
        ResolveOutcome::SolvedNegative => Some("NXDOMAIN"),
        ResolveOutcome::LocalAnswer => Some("CLOAK"),
        ResolveOutcome::Blocked(_) | ResolveOutcome::Guarded => Some("REJECT"),
        ResolveOutcome::RebindReject | ResolveOutcome::Rejected | ResolveOutcome::Miss => None,
    }
}

/// The FEED-ROW eligibility decision (pure — the unit-testable heart of the no-double-count law):
/// a LIVE-FORWARDED outcome (`Solved`/`SolvedNegative`) is SKIPPED when the pool holds the loopback
/// Do53 arm (MODE 1 — the Go fallback), because those answers traversed the Go proxy, which writes
/// its OWN query.log row (server-attributed); logging here too would double-count the query. Every
/// zero-egress outcome (cache hit / block / pin / guard) is Rust-local — the Go proxy never sees it
/// in ANY mode — so it always feeds. The two pool modes are never mixed (`buildSpecsJson` emits
/// EITHER the dnscrypt-stamp set OR the single loopback do53), so the pool-level flag is an exact
/// per-query discriminator, not a heuristic.
pub(crate) fn feed_status(
    outcome: ResolveOutcome,
    pool_has_loopback_proxy: bool,
) -> Option<&'static str> {
    let live_forward = matches!(
        outcome,
        ResolveOutcome::Solved | ResolveOutcome::SolvedNegative
    );
    if live_forward && pool_has_loopback_proxy {
        return None;
    }
    status_token(outcome)
}

/// The DNS QTYPE mnemonic for the row's qtype column — the same vocabulary the Go writer prints
/// (miekg `TypeToString`), with the identical `TYPE<n>` fallback for anything unmapped.
pub(crate) fn qtype_text(qtype: u16) -> String {
    let known = match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        257 => "CAA",
        _ => return format!("TYPE{qtype}"),
    };
    known.to_string()
}

/// Sanitize an attacker-controlled qname for the TSV row: any byte outside graphic ASCII, plus the
/// TSV structural bytes (TAB/CR/LF), renders `?` — a hostile label can never inject a column or a
/// forged row into query.log. An empty result renders `-` (never a torn empty field). The decoded
/// qname is already lowercased + trailing-dot-free (`dns::read_name`), so a normal name passes
/// through byte-identical.
pub(crate) fn sanitize_qname(qname: &str) -> String {
    let cleaned: String = qname
        .chars()
        .map(|c| if ('!'..='~').contains(&c) { c } else { '?' })
        .collect();
    if cleaned.is_empty() {
        "-".to_string()
    } else {
        cleaned
    }
}

/// Hinnant `civil_from_days` — pure epoch-seconds → (year, month, day, hour, minute, second) civil
/// split (proleptic Gregorian). The clock is INJECTED (the resolver-log invariant): callers pass
/// `epoch_secs + offset` for local time, so this stays deterministic + unit-testable to the byte.
pub(crate) fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (hh, mi, ss) = (
        (sod / 3600) as u32,
        ((sod % 3600) / 60) as u32,
        (sod % 60) as u32,
    );
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, hh, mi, ss)
}

/// The device's UTC offset (seconds east) at `epoch_secs` — so the feed's `[datetime]` matches the
/// LOCAL timestamps the Go writer puts on its neighbouring rows (interleaved rows must not skew
/// hours apart). Bionic/glibc `localtime_r` honours the device TZ (incl. DST at the queried
/// instant); a NULL result degrades to UTC. On non-unix hosts (the Windows test target) this is
/// UTC — the formatter itself is offset-injected + exact-byte tested, so the device-only branch
/// carries no test blind spot.
#[cfg(unix)]
pub(crate) fn local_utc_offset_secs(epoch_secs: i64) -> i64 {
    let t: libc::time_t = epoch_secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `localtime_r` reads `t` and writes only into the caller-owned `tm`; both are valid
    // for the duration of the call. A NULL return (invalid time_t) is handled below.
    let res = unsafe { libc::localtime_r(&t, &mut tm) };
    if res.is_null() {
        0
    } else {
        i64::from(tm.tm_gmtoff as i32)
    }
}

/// Non-unix fallback. On **Windows** (the desktop target) this returns the real device UTC offset
/// via Win32 `GetTimeZoneInformation` — DST-correct at the current instant (rows are stamped at write
/// time, so "now"'s offset is the right one), so the feed's `[datetime]` renders device-local
/// wall-clock like the Go writer's neighbouring rows instead of skewing hours into UTC. On any other
/// non-unix host it degrades to UTC (0). The device (Android) build is unix; see the unix twin.
#[cfg(not(unix))]
pub(crate) fn local_utc_offset_secs(_epoch_secs: i64) -> i64 {
    #[cfg(windows)]
    {
        // SYSTEMTIME — 8 WORDs. We read none of its fields, but the layout must match so the bias
        // fields inside TIME_ZONE_INFORMATION land at the right offsets.
        #[repr(C)]
        struct SystemTime {
            _data: [u16; 8],
        }
        // TIME_ZONE_INFORMATION (winbase.h). Win32 contract: UTC = localtime + Bias + active-bias,
        // ALL in MINUTES; the active bias (standard vs daylight) is chosen by the return code.
        #[repr(C)]
        struct TimeZoneInformation {
            bias: i32,
            _standard_name: [u16; 32],
            _standard_date: SystemTime,
            standard_bias: i32,
            _daylight_name: [u16; 32],
            _daylight_date: SystemTime,
            daylight_bias: i32,
        }
        // kernel32 — no external crate (matches pillar_log.rs's GetLocalTime discipline).
        extern "system" {
            fn GetTimeZoneInformation(info: *mut TimeZoneInformation) -> u32;
        }
        const TIME_ZONE_ID_INVALID: u32 = 0xFFFF_FFFF;
        const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
        // SAFETY: `GetTimeZoneInformation` writes only into the caller-owned `tz`, which is fully
        // owned here and valid for the call. An INVALID return degrades to UTC below.
        let mut tz: TimeZoneInformation = unsafe { std::mem::zeroed() };
        let id = unsafe { GetTimeZoneInformation(&mut tz) };
        if id == TIME_ZONE_ID_INVALID {
            return 0;
        }
        let active_bias = if id == TIME_ZONE_ID_DAYLIGHT {
            tz.daylight_bias
        } else {
            tz.standard_bias
        };
        // east-of-UTC seconds = -(Bias + active) minutes. CEST: -((-60) + (-60)) * 60 = +7200 (+2h).
        -(i64::from(tz.bias) + i64::from(active_bias)) * 60
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// ★ #83 — NAME THE SERVER OF A ZERO-EGRESS ANSWER, so a `0ms` row is never ambiguous.
///
/// THE DEFECT THIS CLOSES (measured on device, `cache/query.log`, same host 3 minutes apart):
/// ```text
/// [03:40:42] 127.0.0.1 mtalk.google.com A PASS 327ms dnscry.pt-bratislava-ipv4 -
/// [03:43:28] 127.0.0.1 mtalk.google.com A PASS   0ms -                         -
/// ```
/// The second row is a warm CACHE HIT — healthy, desirable, the resolver doing its job. But it renders
/// BYTE-IDENTICALLY to a forged local block: `0ms` + server `-`. THREE different outcomes collapsed onto
/// that shape (cache hit, Centauri/pin local answer, blocklist deny), so a user watching the log could
/// not tell a fast success from a silent conviction. Socio reported the Underground "biting my queries
/// offline by 0ms every single time" — some of those lines were the app WORKING, and the log gave him no
/// way to separate them. An engine that answers in 0ms is a triumph; one that BLOCKS in 0ms is a verdict.
/// A log that prints them the same is the defect.
///
/// The `status` column already separates REJECT from PASS — but only for the deny arms. This names the
/// SERVER for every zero-egress arm, so the row says WHO answered, not merely how fast:
///   - `CacheHit`      → `cache`        (warm hit inside TTL — the win)
///   - `ServeStale`    → `cache:stale`  (served past TTL while refreshing — a DIFFERENT win, and a
///                                       different diagnosis when a user reports staleness)
///   - `LocalAnswer`   → `local:cloak`  (user pin / `address=` literal / Centauri cloak)
///   - `Blocked(gate)` → the GATE's own label (`blocklist` / `warden` / `underground` /
///                                       `homograph`) — four gates, four names, never one
///   - `Guarded`       → `guard`        (bogus-priv / never-forward / RFC 6761 special-use)
/// Live-forward arms return `None` — their real upstream id belongs in the column and always wins.
///
/// PURE + total: every arm is named, so a new `ResolveOutcome` variant is a compile error here rather
/// than a silent regression back to `-`.
pub(crate) fn zero_egress_server(outcome: ResolveOutcome) -> Option<&'static str> {
    match outcome {
        ResolveOutcome::CacheHit => Some("cache"),
        ResolveOutcome::ServeStale => Some("cache:stale"),
        ResolveOutcome::LocalAnswer => Some("local:cloak"),
        // Was `Some("blocklist")` for ALL FOUR gates. Now each names itself, so the query log
        // can finally answer "which pillar denied this?". Proved injective for all gates in
        // D:/Lean/proofs/Proofs/DenyAttribution.lean.
        ResolveOutcome::Blocked(gate) => Some(gate.label()),
        ResolveOutcome::Guarded => Some("guard"),
        ResolveOutcome::Solved
        | ResolveOutcome::SolvedNegative
        | ResolveOutcome::RebindReject
        | ResolveOutcome::Rejected
        | ResolveOutcome::Miss => None,
    }
}

/// Format ONE Go-shape query.log row. PURE + deterministic (clock + offset INJECTED). `epoch_ms` is
/// the wall clock at the resolve seam; `offset_secs` shifts it to device-local civil time (the Go
/// writer's rendering); `latency_ms` is the measured wall time of THIS resolve.
///
/// ★ GENESIS A2/A3 (2026-07-05) — `server` is the winning DNSCrypt transport's id (e.g.
/// `"dnscrypt:quad9"`) for a live-forward, or `None` for a cache-hit/synth/cloak (the Go proxy renders
/// "-" there). `relay` is the 0x81 anonymized-relay name (None ⇒ "-", the no-relay direct path). The
/// server column is the ENCRYPTION proof + the ROTATION proof (it visibly rotates on cadence).
pub(crate) fn format_feed_line(
    epoch_ms: u64,
    offset_secs: i64,
    qname: &str,
    qtype: u16,
    status: &str,
    latency_ms: u64,
    server: Option<&str>,
    relay: Option<&str>,
) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix((epoch_ms / 1000) as i64 + offset_secs);
    let server_col = server.unwrap_or("-");
    let relay_col = relay.unwrap_or("-");
    format!(
        "[{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}]\t{CLIENT_LOOPBACK}\t{}\t{}\t{status}\t{latency_ms}ms\t{server_col}\t{relay_col}",
        sanitize_qname(qname),
        qtype_text(qtype),
    )
}

/// Append one row to the Go-owned query.log: open-append(-create)-write-close, ONE `write` of
/// `line + '\n'` (atomic under `O_APPEND` for our sub-4 KiB rows), FAIL-OPEN on any IO error.
/// Deliberately NOT [`crate::log_tier`] — see the module doc's write-discipline law (the bounded
/// tail-REWRITE must never truncate a file the Go proxy holds an open append handle on; rotation
/// and size-bounding of this file belong to the Go owner).
pub(crate) fn append_row(path: &Path, line: &str) {
    use std::io::Write;
    let mut buf = String::with_capacity(line.len() + 1);
    buf.push_str(line);
    buf.push('\n');
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
    {
        let _ = f.write_all(buf.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_tokens_match_the_go_vocabulary() {
        assert_eq!(status_token(ResolveOutcome::CacheHit), Some("PASS"));
        assert_eq!(status_token(ResolveOutcome::ServeStale), Some("PASS"));
        assert_eq!(status_token(ResolveOutcome::Solved), Some("PASS"));
        assert_eq!(
            status_token(ResolveOutcome::SolvedNegative),
            Some("NXDOMAIN")
        );
        assert_eq!(status_token(ResolveOutcome::LocalAnswer), Some("CLOAK"));
        assert_eq!(status_token(ResolveOutcome::Blocked(crate::resolver::log::DenyGate::Blocklist)), Some("REJECT"));
        assert_eq!(status_token(ResolveOutcome::Guarded), Some("REJECT"));
        // No-answer arms fall through to the Go proxy, which owns their rows.
        assert_eq!(status_token(ResolveOutcome::RebindReject), None);
        assert_eq!(status_token(ResolveOutcome::Rejected), None);
        assert_eq!(status_token(ResolveOutcome::Miss), None);
    }

    #[test]
    fn feed_status_skips_live_forwards_only_in_loopback_mode() {
        // MODE 1 (Go loopback pool): a live forward traversed the Go proxy → it logs its own row.
        assert_eq!(feed_status(ResolveOutcome::Solved, true), None);
        assert_eq!(feed_status(ResolveOutcome::SolvedNegative, true), None);
        // MODE 2 (direct Rust pool): the Go proxy never sees the query → we own the row.
        assert_eq!(feed_status(ResolveOutcome::Solved, false), Some("PASS"));
        assert_eq!(
            feed_status(ResolveOutcome::SolvedNegative, false),
            Some("NXDOMAIN")
        );
        // Zero-egress outcomes are Rust-local in EVERY mode — always fed.
        for mode in [true, false] {
            assert_eq!(feed_status(ResolveOutcome::CacheHit, mode), Some("PASS"));
            assert_eq!(
                feed_status(ResolveOutcome::Blocked(crate::resolver::log::DenyGate::Underground), mode),
                Some("REJECT")
            );
            assert_eq!(feed_status(ResolveOutcome::Guarded, mode), Some("REJECT"));
            assert_eq!(
                feed_status(ResolveOutcome::LocalAnswer, mode),
                Some("CLOAK")
            );
            assert_eq!(feed_status(ResolveOutcome::Miss, mode), None);
        }
    }

    #[test]
    fn qtype_text_covers_the_common_set_with_the_miekg_fallback() {
        assert_eq!(qtype_text(1), "A");
        assert_eq!(qtype_text(28), "AAAA");
        assert_eq!(qtype_text(12), "PTR");
        assert_eq!(qtype_text(65), "HTTPS");
        assert_eq!(qtype_text(16), "TXT");
        assert_eq!(qtype_text(999), "TYPE999");
        assert_eq!(qtype_text(0), "TYPE0");
    }

    #[test]
    fn civil_from_unix_spot_checks() {
        // The witnessed round-5 row instant: [2026-07-03 01:19:16] on a UTC device.
        assert_eq!(civil_from_unix(1_783_041_556), (2026, 7, 3, 1, 19, 16));
        // Epoch zero + a century boundary.
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_unix(946_684_799), (1999, 12, 31, 23, 59, 59));
        // A negative-offset shift crossing midnight backwards stays civil-correct.
        assert_eq!(
            civil_from_unix(1_783_041_556 - 7_200),
            (2026, 7, 2, 23, 19, 16)
        );
    }

    #[test]
    fn format_feed_line_is_byte_exact_go_shape() {
        // The exact TSV the Go writer produces (measured from a live device pull): [ts] TAB client
        // TAB qname TAB qtype TAB status TAB <n>ms TAB server TAB relay.
        let line = format_feed_line(
            1_783_041_556_000,
            0,
            "en.wikipedia.org",
            1,
            "PASS",
            23,
            Some("dnscrypt:quad9"),
            Some("dnscrypt-relay-fr"),
        );
        assert_eq!(
            line,
            "[2026-07-03 01:19:16]\t127.0.0.1\ten.wikipedia.org\tA\tPASS\t23ms\tdnscrypt:quad9\tdnscrypt-relay-fr"
        );
        // A positive UTC offset renders device-local civil time; None server/relay render "-" (cache-hit/synth).
        let local = format_feed_line(
            1_783_041_556_000,
            7_200,
            "example.org",
            28,
            "REJECT",
            0,
            None,
            None,
        );
        assert_eq!(
            local,
            "[2026-07-03 03:19:16]\t127.0.0.1\texample.org\tAAAA\tREJECT\t0ms\t-\t-"
        );
    }

    #[test]
    fn hostile_qnames_cannot_inject_rows_or_columns() {
        // TAB / LF / CR / control / non-ASCII bytes all render '?' — no forged column, no forged row.
        assert_eq!(sanitize_qname("evil\tname\nx"), "evil?name?x");
        assert_eq!(sanitize_qname("a\u{7f}b\u{0}c"), "a?b?c");
        assert_eq!(sanitize_qname("héllo.example"), "h?llo.example");
        assert_eq!(sanitize_qname(""), "-");
        assert_eq!(sanitize_qname("ok.example.com"), "ok.example.com");
    }

    /// ★ #83 — the three zero-egress shapes that used to be BYTE-IDENTICAL must now differ.
    ///
    /// Before this fix a cache hit, a Centauri/pin cloak and a blocklist deny all rendered
    /// `… 0ms  -  -`, so Socio could not tell a fast SUCCESS from a silent CONVICTION — which is why
    /// he read every 0ms row as the Underground biting him. The status column alone was not enough:
    /// it separates REJECT from PASS, but a cache hit and a stale serve are BOTH PASS, and both were
    /// `-`. Assert each row now NAMES its server, and that no two of them collide.
    #[test]
    fn a_cache_hit_a_cloak_and_a_block_are_no_longer_the_same_row() {
        let hit = format_feed_line(
            0,
            0,
            "mtalk.google.com",
            1,
            "PASS",
            0,
            zero_egress_server(ResolveOutcome::CacheHit),
            None,
        );
        let stale = format_feed_line(
            0,
            0,
            "mtalk.google.com",
            1,
            "PASS",
            0,
            zero_egress_server(ResolveOutcome::ServeStale),
            None,
        );
        let cloak = format_feed_line(
            0,
            0,
            "mtalk.google.com",
            1,
            "CLOAK",
            0,
            zero_egress_server(ResolveOutcome::LocalAnswer),
            None,
        );
        let block = format_feed_line(
            0,
            0,
            "mtalk.google.com",
            1,
            "REJECT",
            0,
            zero_egress_server(ResolveOutcome::Blocked(crate::resolver::log::DenyGate::Blocklist)),
            None,
        );
        assert!(hit.ends_with("\t0ms\tcache\t-"), "cache hit names itself: {hit}");
        assert!(
            stale.ends_with("\t0ms\tcache:stale\t-"),
            "a stale serve is a DIFFERENT win: {stale}"
        );
        assert!(
            cloak.ends_with("\t0ms\tlocal:cloak\t-"),
            "a pin/Centauri answer names itself: {cloak}"
        );
        assert!(
            block.ends_with("\t0ms\tblocklist\t-"),
            "a deny names the blocklist: {block}"
        );
        // The whole point: all four are distinct rows now.
        let rows = [&hit, &stale, &cloak, &block];
        for (i, a) in rows.iter().enumerate() {
            for b in rows.iter().skip(i + 1) {
                assert_ne!(a, b, "two zero-egress outcomes still render identically");
            }
        }
        // And a live forward keeps its real upstream id — the fix never overwrites a true server.
        assert_eq!(zero_egress_server(ResolveOutcome::Solved), None);
        assert_eq!(zero_egress_server(ResolveOutcome::SolvedNegative), None);
    }

    /// Four gates, four names. Before this the log rendered ALL FOUR as `"blocklist"`, so a denial
    /// could not be attributed to the pillar that issued it -- on device the UNDERGROUND teeth
    /// fired 1467 times under the blocklist's name.
    ///
    /// Proved for all gates in D:/Lean/proofs/Proofs/DenyAttribution.lean
    /// (`fixed_labelling_is_injective`); this test is the executable half, and it carries its own
    /// NEGATIVE CONTROL: it asserts the labels are pairwise DISTINCT, so collapsing any two back
    /// to a shared string fails it.
    #[test]
    fn every_deny_gate_reports_its_own_name_never_a_shared_one() {
        use crate::resolver::log::DenyGate;
        let gates = [
            DenyGate::Blocklist,
            DenyGate::Warden,
            DenyGate::Underground,
            DenyGate::Homograph,
        ];
        // Each gate's label survives the whole feed path, not just the enum.
        for g in gates {
            assert_eq!(
                zero_egress_server(ResolveOutcome::Blocked(g)),
                Some(g.label()),
                "the feed dropped the gate's identity for {g:?}"
            );
            assert!(!g.label().is_empty(), "a gate rendered as the empty string: {g:?}");
        }
        // PAIRWISE DISTINCT -- the property that actually makes attribution possible.
        for (i, a) in gates.iter().enumerate() {
            for (j, b) in gates.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert_ne!(
                    a.label(),
                    b.label(),
                    "{a:?} and {b:?} share a label -- a denial by one is indistinguishable from                      the other, which is exactly the defect that cost a debugging pass"
                );
            }
        }
        // And the UNDERGROUND teeth specifically no longer masquerade as the blocklist.
        assert_ne!(DenyGate::Underground.label(), DenyGate::Blocklist.label());
        assert_eq!(DenyGate::Underground.label(), "underground");
    }

    #[test]
    fn a_hostile_qname_still_cannot_inject_a_column() {
        let line = format_feed_line(0, 0, "x\ty\nz", 1, "PASS", 1, None, None);
        assert_eq!(
            line.matches('\t').count(),
            7,
            "always exactly 8 columns: {line}"
        );
        assert!(!line.contains('\n'), "a row is always one line");
    }

    #[test]
    fn append_row_roundtrips_plain_lines() {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "torta-efix5-feed-roundtrip-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        append_row(
            &p,
            "[2026-07-03 01:19:16]\t127.0.0.1\ta.example\tA\tPASS\t1ms\t-\t-",
        );
        append_row(
            &p,
            "[2026-07-03 01:19:17]\t127.0.0.1\tb.example\tA\tREJECT\t0ms\t-\t-",
        );
        let got = std::fs::read_to_string(&p).expect("feed file readable");
        let rows: Vec<&str> = got.lines().collect();
        assert_eq!(rows.len(), 2, "one appended line per row: {got:?}");
        assert!(rows[0].ends_with("\tPASS\t1ms\t-\t-"));
        assert!(rows[1].contains("\tb.example\t"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn local_offset_never_panics_and_is_bounded() {
        // The device branch reads the real TZ; the contract testable on EVERY host: total, and the
        // result is a sane UTC offset (|off| ≤ 18h — the RFC 3339 bound).
        let off = local_utc_offset_secs(1_783_041_556);
        assert!(off.abs() <= 18 * 3600, "sane UTC offset, got {off}");
    }
}
