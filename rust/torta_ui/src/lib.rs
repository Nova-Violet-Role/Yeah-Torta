/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

// The Tortä SLINT UI crate — the rust-native UI substrate, COMPLETE (OMEGA Stage-D · D3).
//
// `slint::include_modules!()` pulls in the Rust structs that slint-build generated from ui/*.slint
// (build.rs). `TortaShell` — THE DESIGN FINALE 4-tab Home (charter step 8) — is the root component
// the host constructs; its properties + callbacks are typed Rust. The host (the on-device
// `android_main` below, or the Kotlin bridge post-unification) constructs TortaShell, feeds the
// live pillar metrics from torta_core's typed Records, and the UI renders them — rust-native, no
// XML, no Compose. The D2 ||| AdvancedBurger (step 7) rides behind the shell's ||| door.

// The generated UI structs (from ui/main.slint). slint-build compiles the .slint → this macro binds
// them at the crate root: the 4-tab shell + the burger + the 12 pillar surfaces.
slint::include_modules!();

// ===========================================================================================
// THE QUERY-FEED SHAPE (OMEGA Stage-D · D3) — the pure helpers behind the shell's ④ QUERY tab.
//
// Host-visible on test builds too (cfg android-or-test) so the proof harness exercises the EXACT
// path-mapping + line-classification the on-device feed runs — never a parallel re-derivation.
// ===========================================================================================
#[cfg(any(target_os = "android", test))]
mod feed_shape {
    /// Map a QUERY-tab source id to its on-disk log path — the measured Kotlin conventions:
    /// dnscrypt-proxy's own logs live under `cache/` (the D2 `query_log`/`nx_log` toggle paths);
    /// pillar logs live as `logs/query-<tag>.log` (PillarLog.kt:26 "Beside DnsCrypt.log, in the
    /// app-private logs dir"); CENTAURI's log lives BESIDE its content-addressed cache
    /// (PillarLog.kt D40 canon: `app_data/centauri_cache/query-centauri.log`).
    pub(crate) fn query_log_path(data_dir: &str, source: &str) -> String {
        // The engine writes its logs under the app DATA dir (`applicationInfo.dataDir` =
        // `pathVars.appDataDir` = `{BASE}`), NOT the Slint UI's filesDir. `internal_data_path()`
        // hands us `{BASE}/files` (getFilesDir); every engine artifact lives one level up at
        // `{BASE}/…` (`cache/query.log`, `logs/query-<tag>.log`, the Centauri cache log — all set
        // from `pathVars.appDataDir`, PillarLog.kt:98 / PathVars.kt:48). Strip a trailing `/files`
        // so the reader resolves the REAL engine path instead of a phantom `{BASE}/files/…` that is
        // never written — the root cause of the ④ QUERY tab + ③ DNS RECENT-QUERIES reading empty
        // while the logs sat live on disk. Host tests pass a bare base (no `/files`) → the fallback
        // leaves it untouched. Also handle trailing slash to avoid double-slash in paths.
        let base = if let Some(stripped) = data_dir.strip_suffix("/files") {
            stripped.trim_end_matches('/')
        } else {
            data_dir.trim_end_matches('/')
        };
        match source {
            "dnscrypt" => format!("{base}/cache/query.log"),
            "nx" => format!("{base}/cache/nx.log"),
            "centauri" => format!("{base}/app_data/centauri_cache/query-centauri.log"),
            // #53 — MASKSOLVER is the D40 Rust-canon resolve feed (resolver/log.rs slice 6): the
            // RUNNING engine's MaskSolver writes it beside its durable records under
            // `app_data/runtime_tier/` (device-measured), NOT under `logs/`.
            "masksolver" => format!("{base}/app_data/runtime_tier/query-masksolver.log"),
            // #53 — INU's log is a SIBLING of its state blob (inu/object.rs
            // `nand.path().with_file_name(...)`): the Kotlin store opens `InuStore(filesDir)`
            // (RustPowerStateStore.kt:150) ⇒ `files/wire-cake-inu-spike/query-inu.log`
            // (device-measured live).
            "inu" => format!("{base}/files/wire-cake-inu-spike/query-inu.log"),
            other => format!("{base}/logs/query-{other}.log"),
        }
    }

    /// #3-EXT · Rows shown in the BEAST dashboard's RECENT TICKS feed (the pane renders a short
    /// pulse strip, not a log browser — the ④ QUERY tab owns the deep tail). `i32` — the exact
    /// `log_tail_recent` parameter type (the UniFFI-exported tail).
    pub(crate) const BEAST_TICKS_SHOWN: i32 = 8;

    /// #3-EXT · Parse ONE query-beast.log line into the pane's typed [`crate::BeastTickRow`].
    /// The writer's format (torta_core beast/log.rs:88) is space-separated `k=v` tokens after the
    /// `{now_ms} {kind}` head: `mode={} cwnd={a}/{b} rtt=..ms udp=..ms pace=../s pipe={} q={}/{}/{}
    /// valve={} shed={} aqm={} sparse={} relay={r}`. Tolerant by law: `mode=` + `cwnd=` are required
    /// (a line without them — a header, a torn write — is no tick and yields `None`); `shed=` and
    /// `relay=` default honestly (0 / "—") so a shorter historical line still renders its pulse.
    pub(crate) fn beast_tick_row_parse(line: &str) -> Option<crate::BeastTickRow> {
        let mut mode: Option<&str> = None;
        let mut cwnd: Option<i32> = None;
        let mut shed: i32 = 0;
        let mut relay: &str = "—";
        for tok in line.split_whitespace() {
            if let Some(v) = tok.strip_prefix("mode=") {
                mode = Some(v);
            } else if let Some(v) = tok.strip_prefix("cwnd=") {
                cwnd = v.split('/').next().and_then(|a| a.parse::<i32>().ok());
            } else if let Some(v) = tok.strip_prefix("shed=") {
                shed = v.parse::<i32>().unwrap_or(0);
            } else if let Some(v) = tok.strip_prefix("relay=") {
                relay = v;
            }
        }
        Some(crate::BeastTickRow {
            mode: mode?.into(),
            cwnd: cwnd?,
            shed,
            relay: relay.into(),
        })
    }

    /// Split + classify ONE log line into the typed `QueryRow` the feed renders. The shared line
    /// format is "[yyyy-MM-dd HH:mm:ss] <pillar> <event> k=v …" (PillarLog.kt:30 / log_tier); a
    /// line with no bracketed timestamp keeps its whole body. The verdict is a DISPLAY heuristic
    /// over event keywords (BLOCK/FAULT/STALE/CACHE/OK/EVENT) — never a verdict authority: the
    /// engines' own typed counters are the truth, this feed is the debug eye. Accents mirror the
    /// Monokuma verdict palette (risk/wound/caution) + the Masque cache violet + safe green.
    pub(crate) fn classify_query_line(line: &str) -> crate::QueryRow {
        let (time, body) = match (line.starts_with('['), line.find(']')) {
            (true, Some(end)) => (&line[..=end], line[end + 1..].trim_start()),
            _ => ("", line),
        };
        let lower = body.to_lowercase();
        let hit = |keys: &[&str]| keys.iter().any(|k| lower.contains(k));
        // #53 — a periodic stats tick (the ENGINE feed's `dnsmasq stats json={...}` lines) is a
        // COUNTER DUMP, not a verdict: its JSON carries keys like `"blocked":0` that the keyword
        // scan below would misread as a BLOCK row (device-witnessed misfire). Classify it EVENT
        // before any verdict keyword can fire.
        let (verdict, accent) = if lower.contains("stats json=") {
            ("EVENT", slint::Color::from_rgb_u8(0x8c, 0x8c, 0x8c)) // Monokuma.ash
        } else if hit(&["block", "deny", "reject", "sinkhole", "nxdomain"]) {
            ("BLOCK", slint::Color::from_rgb_u8(0xd8, 0x3a, 0x2c)) // Monokuma.risk — THE EYE
        } else if hit(&["fail", "error", "panic", "leak", "stall"]) {
            ("FAULT", slint::Color::from_rgb_u8(0xc0, 0x39, 0x2b)) // Monokuma.wound
        } else if hit(&["stale"]) {
            ("STALE", slint::Color::from_rgb_u8(0xf3, 0x9c, 0x12)) // Monokuma.caution
        } else if hit(&["cache", "hit"]) {
            ("CACHE", slint::Color::from_rgb_u8(0xa7, 0x8b, 0xfa)) // the Masque violet
        } else if hit(&[
            "serve", "answer", "resolved", "pass", "start", "swap", " ok",
        ]) {
            ("OK", slint::Color::from_rgb_u8(0x2e, 0xcc, 0x71)) // Monokuma.safe
        } else {
            ("EVENT", slint::Color::from_rgb_u8(0x8c, 0x8c, 0x8c)) // Monokuma.ash
        };
        crate::QueryRow {
            time: time.into(),
            line: body.into(),
            verdict: verdict.into(),
            accent,
        }
    }
}

// ===========================================================================================
// THE WARDEN FEED (SLINT substitution · 2-FEED-Warden) — the live Warden dashboard feed.
//
// Host-visible on test builds too (cfg android-or-test — the `feed_shape` precedent) so the host
// proof exercises the EXACT arm + field-for-field push the on-device rail runs, never a parallel
// re-derivation. `feed_from_live_warden` is the WardenObject twin of the `feed_from_live_centauri`
// template: it pulls a typed `WardenSnapshot` off a live `WardenObject` + the per-app matrix via
// `app_rows()` and lands every field onto the `WardenDashboard` inputs.
//
// THE SPIKE BOUNDARY (the D1 honesty, made explicit): the RUNNING firewall's Warden lives in
// libtorta_core.so — a SEPARATE torta_core instance from THIS .so (which statically links its own).
// So the rail arms a SPIKE-LOCAL `WardenObject` with a representative posture (real universal block
// rules + a real per-app matrix + a real verdict batch), then reads its snapshot. Every number the
// dashboard shows is a REAL read of a REALLY-armed-and-exercised engine — the Centauri precedent
// (capacity=1024 + the cloaked-host list are armed/config state, not fabricated traffic), never a
// faked tally. It is the honest non-zero baseline the dashboard renders until the single-.so
// unification feeds the running engine's Warden directly.
// ===========================================================================================
// ★ #22 slice 2 — the TCAT v2 catalog-freshness formatting seam, PURE + host-testable (the
// warden_feed cfg precedent: compiled for android + test, its android caller is the feed loop).
// Lives OUTSIDE the android-gated `engine_bridge` so the unit tests below prove it on host.
#[cfg(any(target_os = "android", test))]
pub(crate) mod centauri_feed_fmt {
    /// The i64 twin of `engine_bridge::json_i32` for values an i32 cannot carry past 2038 (the
    /// TCAT v2 freshness epoch `catalog_authored_at_secs`). Same tiny flat-object scanner.
    pub(crate) fn json_i64(json: &str, key: &str) -> Option<i64> {
        let pat = format!("\"{key}\":");
        let start = json.find(&pat)? + pat.len();
        let rest = &json[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(rest.len());
        rest.get(..end)?.parse::<i64>().ok()
    }

    /// Render the TCAT v2 catalog freshness epoch as the dashboard's age label. `0` = freshness
    /// UNKNOWN (a v1-era catalog / no catalog / author declined) ⇒ the em-dash — NEVER "56y ago"
    /// (the 1970 lie). A skewed clock (epoch ahead of now) reads "just now", never a negative age.
    /// Pure (caller passes `now`), unit-testable without a clock.
    pub(crate) fn freshness_label(now_secs: i64, epoch_secs: i64) -> String {
        if epoch_secs <= 0 {
            return "—".to_string();
        }
        let age = now_secs.saturating_sub(epoch_secs);
        if age < 90 {
            "just now".to_string()
        } else if age < 5_400 {
            format!("{}m ago", age / 60)
        } else if age < 129_600 {
            format!("{}h ago", age / 3_600)
        } else {
            format!("{}d ago", age / 86_400)
        }
    }
}

#[cfg(any(target_os = "android", test))]
pub(crate) mod warden_feed {
    // DEAD-CODE ALLOW REMOVED. The module-wide `#![allow(dead_code)]` that used to sit here was
    // covering TWO different situations with one blanket, which is precisely why it could never be
    // retired: it silenced both at once and told the reader nothing about either.
    //
    //   1. `arm_warden_spike` + its block-rule/verdict helpers + the sample-uid consts are RETIRED
    //      from the on-device path (SLINT substitution · 4-FIX round 5 finding 4 — no fabricated
    //      per-app matrix). Their ONLY remaining caller is the `warden_feed_proof` test. That is
    //      `#[cfg(test)]`, not an allow: `allow(dead_code)` says "this might be used and I do not
    //      want to hear about it", while `#[cfg(test)]` says "this is test support" and the
    //      compiler ENFORCES it. It also drops the items from the shipped `.so` entirely, so the
    //      retirement is real in the artifact and not just in a comment.
    //
    //   2. `record_to_row` / `flow_verdict_label` are the opposite case — they are LIVE on the
    //      shipped target, called from `live_flow_feed`'s `#[cfg(target_os = "android")]` arm, and
    //      dead only on a host build. So they carry that same cfg: an item gated exactly like its
    //      only caller cannot drift out of sync with it.
    //
    // Net effect: dead-code is now reported honestly on BOTH targets instead of suppressed on both,
    // and each item states which of the two reasons applies to it.
    use slint::{ModelRc, VecModel};
    use torta_core::{WardenAppMode, WardenNetClass, WardenObject};
    // #97 — these eight are consumed ONLY by the `#[cfg(test)]` spike builders in this module
    // (`conn` at :282, `arm_warden_spike` at :303). When those items were classified `#[cfg(test)]`
    // in 33189c78 the IMPORT was left unconditional, so the ship build carried an unused-import
    // warning that predates this commit and that an earlier coarser measurement of mine missed.
    //
    // Gated rather than silenced, for the same reason the items themselves were: `#[cfg(test)]` is
    // a classification the compiler ENFORCES — if one of these ever gains a real ship-side caller,
    // the build fails and says so, whereas an `#[allow(unused_imports)]` would hide that forever.
    #[cfg(test)]
    use torta_core::{
        WardenAppRow, WardenCidrRule, WardenConnFacts, WardenDomainRule, WardenIpStatus,
        WardenNetworkType, WardenUniversalRule, WardenUniversalToggles,
    };

    /// A normal app UID (matrix mode NONE) — the allow path + the TIER 2/4/5 deny probes ride it.
    #[cfg(test)]
    const NORMAL_UID: u32 = 10_101;
    /// An ISOLATE app UID (mode Isolate — only the DNS resolver + LAN are allowed) — a WAN conn for
    /// it denies at TIER 3 (the `deny_by_app` attribution).
    #[cfg(test)]
    const ISO_UID: u32 = 10_102;

    /// The universal BLOCK domain apexes the spike arms (real ad/tracker hosts — plain trie
    /// terminals, uid 0 = the universal tier). A conn carrying one as its `qname` denies at TIER 4
    /// (`deny_by_universal_rule`, mod.rs `stats_tally_allow_and_the_deny_tier_split`).
    #[cfg(test)]
    const BLOCK_DOMAINS: [&str; 12] = [
        "doubleclick.net",
        "googlesyndication.com",
        "google-analytics.com",
        "adservice.google.com",
        "scorecardresearch.com",
        "adnxs.com",
        "criteo.com",
        "taboola.com",
        "outbrain.com",
        "moatads.com",
        "amazon-adsystem.com",
        "quantserve.com",
    ];

    /// Pack an IPv4 dotted quad into the host-order u32 the CIDR rule-set stores.
    #[cfg(test)]
    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> u32 {
        (u32::from(a) << 24) | (u32::from(b) << 16) | (u32::from(c) << 8) | u32::from(d)
    }

    /// The universal BLOCK CIDR rules (uid 0). Two are /32 sinkholes a verdict probe hits (TIER 4
    /// `deny_by_universal_rule` via the IP table); two are wider nets for a realistic armed count.
    #[cfg(test)]
    fn block_cidrs() -> Vec<WardenCidrRule> {
        let mk = |net: u32, prefix: u8| WardenCidrRule {
            uid: 0,
            net,
            prefix,
            port: None,
            proto: None,
            status: WardenIpStatus::Block,
        };
        vec![
            mk(ipv4(198, 51, 100, 10), 32), // a probe hits this → TIER 4
            mk(ipv4(203, 0, 113, 5), 32),   // a probe hits this → TIER 4
            mk(ipv4(203, 0, 113, 0), 24),
            mk(ipv4(198, 18, 0, 0), 15),
        ]
    }

    /// One connection fact (the verdict-batch builder — every field the cascade reads).
    #[cfg(test)]
    fn conn(uid: u32, daddr: &str, dport: u16, qname: &str, dns_blocked: bool) -> WardenConnFacts {
        WardenConnFacts {
            uid,
            daddr: daddr.to_string(),
            dport,
            proto: 6, // TCP
            qname: Some(qname.to_string()),
            net: WardenNetworkType::Wifi,
            dns_blocked,
        }
    }

    /// Arm a SPIKE-LOCAL Warden with a representative posture so its snapshot reads REAL non-zero
    /// engine numbers (the Centauri armed-state precedent). Installs the universal block domain +
    /// CIDR rule-sets, the universal rules + the TIER-2 toggles (BlockHttp/BlockUdpNtp — a toggle
    /// fires only when BOTH its bit AND its matching rule are armed), a 5-row per-app matrix (varied
    /// modes/meteredness, one paused), then runs a verdict batch: an allow majority + a deny spread
    /// across every attribution tier (T2 toggle · T3 app-isolate · T4 universal rule · T5 dns-blocked).
    /// Each deny conn is shaped to match EXACTLY one tier (single-tier attribution, first-match-wins).
    /// Every resulting count is a REAL read of THIS armed+exercised engine — never a fabricated tally.
    #[cfg(test)]
    pub(crate) fn arm_warden_spike(w: &WardenObject) {
        // ---- The universal BLOCK domain rule-set (TIER 4, matched against a conn's qname) ----
        let domains: Vec<WardenDomainRule> = BLOCK_DOMAINS
            .iter()
            .map(|d| WardenDomainRule {
                domain: (*d).to_string(),
                uid: 0,
                wildcard: false,
            })
            .collect();
        w.install_domain_rules(domains);

        // ---- The universal BLOCK CIDR rule-set (TIER 4, matched against a conn's dest IP) ----
        w.install_cidr_rules(block_cidrs());

        // ---- The universal rules + the TIER-2 toggles (defense-in-depth) ----
        w.set_universal_rules(vec![
            WardenUniversalRule::BlockHttp,
            WardenUniversalRule::BlockUdpNtp,
            WardenUniversalRule::BlockUniversalDomain,
            WardenUniversalRule::BlockUniversalCidr,
        ]);
        w.set_universal_toggles(WardenUniversalToggles {
            block_http: true,
            block_udp_ntp: true,
            ..WardenUniversalToggles::default()
        });

        // ---- The per-app matrix (TIER 3) — 5 rows, varied modes/meteredness, one paused ----
        let rows = [
            (NORMAL_UID, WardenAppMode::None, WardenNetClass::Allow, 0u64),
            (ISO_UID, WardenAppMode::Isolate, WardenNetClass::Allow, 0),
            (10_103, WardenAppMode::Untracked, WardenNetClass::Metered, 0),
            (
                10_104,
                WardenAppMode::BypassUniversal,
                WardenNetClass::Allow,
                4_100_000_000_000, // a live temp-allow (paused)
            ),
            (10_105, WardenAppMode::None, WardenNetClass::Both, 0),
        ];
        for (uid, mode, meteredness, temp_allow_until) in rows {
            w.set_app_row(WardenAppRow {
                uid,
                mode,
                meteredness,
                temp_allow_until,
            });
        }

        // ---- The verdict batch — distinct conns (no cache collapse); each deny is single-tier. ----
        // 20 allows (normal app, unblocked dest + qname, port 443).
        for n in 0..20u32 {
            let _ = w.verdict(conn(
                NORMAL_UID,
                &format!("93.184.216.{}", 1 + n),
                443,
                &format!("site{n}.example.net"),
                false,
            ));
        }
        // TIER 4 (universal domain) — qname is an armed apex. Distinct daddr per conn so no cache
        // key (whatever its field set) collapses the four into one tally.
        for (i, d) in BLOCK_DOMAINS.iter().take(4).enumerate() {
            let _ = w.verdict(conn(
                NORMAL_UID,
                &format!("93.184.216.{}", 101 + i),
                443,
                d,
                false,
            ));
        }
        // TIER 4 (universal CIDR) — dest is an armed /32 sinkhole.
        for ip in ["198.51.100.10", "203.0.113.5"] {
            let _ = w.verdict(conn(NORMAL_UID, ip, 443, "cidrhit.example.net", false));
        }
        // TIER 5 (dns_blocked seam) — the resolver flagged it; qname is NOT armed (else T4 wins first).
        for n in 0..3u32 {
            let _ = w.verdict(conn(
                NORMAL_UID,
                &format!("93.184.216.{}", 200 + n),
                443,
                &format!("dnsblock{n}.example.org"),
                true,
            ));
        }
        // TIER 3 (per-app Isolate) — a WAN conn for the isolated app (only DNS + LAN are allowed).
        for n in 0..2u32 {
            let _ = w.verdict(conn(
                ISO_UID,
                &format!("93.184.216.{}", 210 + n),
                443,
                &format!("iso{n}.example.net"),
                false,
            ));
        }
        // TIER 2 (universal toggle) — a plain-HTTP (port 80) conn (block_http toggle + rule armed).
        let _ = w.verdict(conn(
            NORMAL_UID,
            "93.184.216.220",
            80,
            "http.example.net",
            false,
        ));
    }

    /// Push the live Warden state onto the dashboard — field-for-field, the WardenObject twin of
    /// [`super::android_spike::feed_from_live_centauri`]. Reads the typed `WardenSnapshot` + the
    /// per-app matrix off the live Object and lands every dashboard input; the blocklist-trust crown
    /// reads HONESTLY DISARMED (the spike arms no GitHub source — never a fabricated trust score).
    #[cfg(target_os = "android")]
    pub(crate) fn feed_from_live_warden(dash: &crate::WardenDashboard, w: &WardenObject) {
        let s = w.snapshot();
        dash.set_allow_count(s.allow as i32);
        dash.set_deny_count(s.deny as i32);
        dash.set_deny_by_toggle(s.deny_by_universal_toggle as i32);
        dash.set_deny_by_app(s.deny_by_app as i32);
        dash.set_deny_by_universal(s.deny_by_universal_rule as i32);
        dash.set_deny_by_dns(s.deny_by_blocklist as i32);
        dash.set_domain_rules(s.domain_rules as i32);
        dash.set_cidr_rules(s.cidr_rules as i32);
        dash.set_universal_rules(s.universal_rules as i32);
        dash.set_app_rows(s.app_rows as i32);
        dash.set_cache_entries(s.cache_entries as i32);
        dash.set_policy_loaded(s.policy_loaded);
        dash.set_fail_closed(s.fail_closed);

        // The per-app matrix — the REAL held rows (uid + mode + meteredness + temp-allow), replacing
        // the .slint sample defaults. The engine holds no package name (Kotlin's PackageManager does
        // that lookup in production); the spike labels each row by its uid — the identity the engine
        // actually keys on.
        let matrix: Vec<crate::AppRow> = w
            .app_rows()
            .into_iter()
            .map(|r| crate::AppRow {
                uid: r.uid as i32,
                name: format!("app {}", r.uid).into(),
                mode: app_mode_label(r.mode).into(),
                // A6 — the wire ORDINAL beside the label: `WardenAppMode` is `#[repr(i32)]` (0..5), the
                // SAME discriminant `setWardenAppMode` round-trips, so the row tap can hand the host the
                // current mode and let it compute the next in the cycle (the .slint never re-derives order).
                mode_ord: r.mode as i32,
                metered: net_class_label(r.meteredness).into(),
                paused: r.temp_allow_until != 0,
                // A6 — a HELD engine row: `app_rows()` IS the configured per-app policy set, so every row
                // here enforces (never a dimmed flow-derived default). Honest `true`.
                armed: true,
            })
            .collect();
        dash.set_app_matrix(ModelRc::new(VecModel::from(matrix)));

        // The blocklist-trust crown — HONEST DISARMED (no GitHub blocklist source armed). Pushed
        // explicitly (not left as the .slint default) so the surface reflects a real host decision.
        dash.set_trust_armed(false);
        dash.set_trust_source_name("no blocklist source armed".into());
        dash.set_trust_score(100);
        dash.set_trust_cdn_overlap(0);
        dash.set_lockdown_armed(false);
    }

    /// SLINT substitution · 4-FIX round 3 (2-FEED-Warden) — push the live Warden state onto the SHELL's
    /// in-shell `wdash-*` aliases (the warden-dash section), the twin of [`feed_from_live_warden`] that
    /// targets the standalone Window. Field-for-field the SAME typed `WardenSnapshot` + per-app matrix off
    /// the live Object; the pane derives its over-block hunt internally. Closes the witness finding that the
    /// WARDEN dashboard chip was a silent no-op — now it opens on a fed pane (honest cold read ⇒ honest zeros).
    #[cfg(target_os = "android")]
    pub(crate) fn feed_warden_shell(sh: &crate::TortaShell, w: &WardenObject) {
        let s = w.snapshot();
        sh.set_wdash_allow_count(s.allow as i32);
        sh.set_wdash_deny_count(s.deny as i32);
        sh.set_wdash_deny_by_toggle(s.deny_by_universal_toggle as i32);
        sh.set_wdash_deny_by_app(s.deny_by_app as i32);
        sh.set_wdash_deny_by_universal(s.deny_by_universal_rule as i32);
        sh.set_wdash_deny_by_dns(s.deny_by_blocklist as i32);
        sh.set_wdash_domain_rules(s.domain_rules as i32);
        sh.set_wdash_cidr_rules(s.cidr_rules as i32);
        sh.set_wdash_universal_rules(s.universal_rules as i32);
        sh.set_wdash_app_rows(s.app_rows as i32);
        sh.set_wdash_cache_entries(s.cache_entries as i32);
        sh.set_wdash_policy_loaded(s.policy_loaded);
        sh.set_wdash_fail_closed(s.fail_closed);

        let matrix: Vec<crate::AppRow> = w
            .app_rows()
            .into_iter()
            .map(|r| crate::AppRow {
                uid: r.uid as i32,
                name: format!("app {}", r.uid).into(),
                mode: app_mode_label(r.mode).into(),
                // A6 — the wire ORDINAL beside the label: `WardenAppMode` is `#[repr(i32)]` (0..5), the
                // SAME discriminant `setWardenAppMode` round-trips, so the row tap can hand the host the
                // current mode and let it compute the next in the cycle (the .slint never re-derives order).
                mode_ord: r.mode as i32,
                metered: net_class_label(r.meteredness).into(),
                paused: r.temp_allow_until != 0,
                // A6 — a HELD engine row: `app_rows()` IS the configured per-app policy set, so every row
                // here enforces (never a dimmed flow-derived default). Honest `true`.
                armed: true,
            })
            .collect();
        sh.set_wdash_app_matrix(ModelRc::new(VecModel::from(matrix)));

        // The blocklist-trust crown — HONEST DISARMED (no GitHub blocklist source armed), pushed
        // explicitly so the surface reflects a real host decision (never a fabricated trust score).
        sh.set_wdash_trust_armed(false);
        sh.set_wdash_trust_source_name("no blocklist source armed".into());
        sh.set_wdash_trust_score(100);
        sh.set_wdash_trust_cdn_overlap(0);
        sh.set_wdash_lockdown_armed(false);

        // SLINT substitution — THE LIVE WARDEN OVERLAY. The snapshot above is THIS .so's cold UNARMED
        // Warden (all zeros · empty matrix — the honest DORMANT baseline now the spike arming is
        // retired). The RUNNING firewall lives in libtorta_core.so; its real verdict aggregate + the
        // per-tier deny split + the armed rule-set / matrix / cache counts + the per-app matrix are
        // pulled by `refresh_warden_dash_live` (the SAME live read the 1s warden-dash Timer re-pumps,
        // so every tile CLIMBS with traffic instead of freezing at this startup zero). Android-only:
        // `engine_bridge` is the JNI seam; on host/test (the `warden_feed_proof` fixture) the honest
        // cold zeros + cold matrix stand.
        #[cfg(target_os = "android")]
        refresh_warden_dash_live(sh);
    }

    /// The LIVE warden-dashboard overlay — the real numbers off the RUNNING firewall (libtorta_core.so)
    /// via the bridge: ALL 13 `liveWardenStats` gauges (the verdict tallies + the per-tier deny split +
    /// the armed domain/cidr/universal rule counts + the per-app matrix count + the resolver-cache
    /// entries) PLUS the per-app matrix itself (`liveWardenMatrix` — the held rows unioned with the
    /// flow-observed app universe). Split from [`feed_warden_shell`] so the 1s warden-dash Timer can
    /// re-pull the live read each tick WITHOUT re-touching this .so's cold-zero snapshot — so every
    /// tile CLIMBS with live traffic instead of freezing at the startup zero (the split-brain the A6
    /// study mapped: the dashboard used to overlay only the 6 verdict scalars, ONCE, dropping the 5
    /// rule-set/cache counts + the real posture bits + the whole matrix the bridge already emits).
    ///
    /// The tallies + counts overlay ONLY while the datapath is ARMED (`configured`) — disarmed /
    /// unreachable ⇒ the honest cold zeros stand (never a fabricated reading). The per-app matrix rides
    /// UNGATED: a HELD row is real per-app policy whether or not the firewall is presently enforcing, so
    /// the actionable app universe shows even on a disarmed engine. Android-only: `engine_bridge` is the
    /// JNI seam. Never panics — a malformed field is simply skipped (fail-open, the underground-rows law).
    #[cfg(target_os = "android")]
    pub(crate) fn refresh_warden_dash_live(sh: &crate::TortaShell) {
        use crate::engine_bridge::{json_bool, json_i32};
        if let Some(j) = crate::engine_bridge::live_warden_stats() {
            let set = |key: &str, f: &dyn Fn(i32)| {
                if let Some(v) = json_i32(&j, key) {
                    f(v);
                }
            };
            // POSTURE + ARMED-POLICY COUNTS ride UNGATED — they are REAL state whether or not the
            // firewall is presently ENFORCING. A user who armed 5 domain rules but has not started the
            // tunnel should still see "5 domain rules · policy loaded" (the config is loaded, ready) —
            // gating them on `configured` would hide loaded policy behind a disarmed enforce bit. The
            // read is the real snapshot off the SAME instance the datapath queries — never the hardcoded
            // `policy_loaded=true` the narrow overlay used to force (that lit the over-block hunt's
            // `!policy-loaded` derive falsely on a configured-but-empty engine).
            sh.set_wdash_policy_loaded(json_bool(&j, "policy_loaded"));
            sh.set_wdash_fail_closed(json_bool(&j, "fail_closed"));
            // The LIVE enforce bit (`configured` = WardenDatapathGate.enforced()) — UNGATED: it IS the
            // arm state, so the crown pill reads the truth whether armed or disarmed (the witness found
            // this feed absent, so the pill was hardwired DISARMED regardless of the real datapath bit).
            sh.set_wdash_warden_armed(json_bool(&j, "configured"));
            set("domain_rules", &|v| sh.set_wdash_domain_rules(v));
            set("cidr_rules", &|v| sh.set_wdash_cidr_rules(v));
            set("universal_rules", &|v| sh.set_wdash_universal_rules(v));
            set("app_rows", &|v| sh.set_wdash_app_rows(v));
            set("cache_entries", &|v| sh.set_wdash_cache_entries(v));

            // The VERDICT TALLIES (allow + the per-tier deny split) are only meaningful while the
            // datapath is ACTIVELY judging packets — gate them on `configured` (the enforce bit), so a
            // disarmed firewall shows honest zeros, never a stale count dressed as a live reading.
            if json_bool(&j, "configured") {
                set("allow", &|v| sh.set_wdash_allow_count(v));
                set("deny", &|v| sh.set_wdash_deny_count(v));
                set("deny_by_universal_toggle", &|v| sh.set_wdash_deny_by_toggle(v));
                set("deny_by_app", &|v| sh.set_wdash_deny_by_app(v));
                set("deny_by_universal_rule", &|v| sh.set_wdash_deny_by_universal(v));
                set("deny_by_blocklist", &|v| sh.set_wdash_deny_by_dns(v));
            }
        }
        // The per-app matrix — the actionable app universe (held rows + flow-observed defaults) off the
        // SAME instance the datapath queries. `None`/`""` wire ⇒ empty ⇒ the pane's honest no-rows state
        // (never the retired synthetic apps). Mirrors the settings feed's matrix map.
        let matrix = crate::engine_bridge::live_warden_matrix()
            .as_deref()
            .map(parse_warden_dash_matrix)
            .unwrap_or_default();
        sh.set_wdash_app_matrix(ModelRc::new(VecModel::from(matrix)));

        // A6 seam close — the 9 TIER-2 chips off `wardenUniversalToggles` (the ENGINE's own bits the
        // cascade consults; the write callback round-trips `setWardenUniversalToggle`, and this 1s
        // re-pull is the read-back that moves a tapped chip — never a local echo). `None` wire ⇒ the
        // EMPTY model ⇒ the pane's honest silent/arm-to-read state stands. The lockdown over-block
        // banner derive rides the same real bit (it was hardwired false at shell feed).
        let toggles_wire = crate::engine_bridge::warden_universal_toggles();
        let toggles = build_warden_dash_toggles(toggles_wire.as_deref());
        sh.set_wdash_lockdown_armed(toggles.iter().any(|t| t.key == "lockdown" && t.armed));
        sh.set_wdash_universal_toggles(ModelRc::new(VecModel::from(toggles)));
    }

    /// Parse the `liveWardenMatrix` wire (line 1 `total=<n>`, then `uid\tapp\tmode\tmetered\ttemp_allow\tarmed`
    /// rows, `mode`/`metered` = the Kotlin enum ORDINALS) into DASHBOARD [`crate::AppRow`] rows — the
    /// twin of [`parse_warden_settings_matrix`], but it CARRIES the `mode_ord` (the tap-cycle discriminant)
    /// and the `armed` bit (`1` = a HELD engine row, `0` = a flow-observed default the .slint dims) that
    /// the settings parser drops. Host-safe (pure string parse). A malformed row is SKIPPED (fail-open —
    /// never a fabricated app row); an empty / `None` wire yields no rows (the pane's honest no-rows state).
    pub(crate) fn parse_warden_dash_matrix(wire: &str) -> Vec<crate::AppRow> {
        let mut rows = Vec::new();
        for line in wire.lines() {
            if line.is_empty() || line.starts_with("total=") {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 6 {
                continue; // malformed ⇒ skip (fail-open)
            }
            let uid = match f[0].trim().parse::<i32>() {
                Ok(u) => u,
                Err(_) => continue,
            };
            let name = if f[1].is_empty() {
                format!("uid {uid}")
            } else {
                f[1].to_string()
            };
            let mode_ord = f[2].trim().parse::<i32>().unwrap_or(3); // default NONE
            let metered_ord = f[3].trim().parse::<i32>().unwrap_or(3); // default ALLOW
            let paused = f[4].trim().parse::<u64>().map(|t| t != 0).unwrap_or(false);
            let armed = f[5].trim() == "1";
            rows.push(crate::AppRow {
                uid,
                name: name.into(),
                mode: app_mode_label_ord(mode_ord).into(),
                mode_ord,
                metered: net_class_label_ord(metered_ord).into(),
                paused,
                armed,
            });
        }
        rows
    }

    /// The `WardenAppMode` → dashboard label (the .slint tints "ISOLATE" red).
    fn app_mode_label(mode: WardenAppMode) -> &'static str {
        match mode {
            WardenAppMode::None => "NONE",
            WardenAppMode::Isolate => "ISOLATE",
            WardenAppMode::Untracked => "UNTRACKED",
            WardenAppMode::BypassUniversal => "BYPASS-U",
            WardenAppMode::BypassDnsFirewall => "BYPASS-DNS",
            WardenAppMode::Exclude => "EXCLUDE",
        }
    }

    /// The `WardenNetClass` (meteredness) → dashboard label.
    fn net_class_label(class: WardenNetClass) -> &'static str {
        match class {
            WardenNetClass::Both => "BOTH",
            WardenNetClass::Unmetered => "UNMETERED",
            WardenNetClass::Metered => "METERED",
            WardenNetClass::Allow => "ALLOW",
        }
    }

    // ===== 2-FEED-Warden (SETTINGS) — the in-shell Warden |||  settings feed (the ws-* aliases) =====
    //
    // The settings pane reflects + edits the CANONICAL live WardenObject (the SAME instance the datapath
    // consults, via WardenDatapathGate) — so its feed reads ONLY the cross-.so bridge (never this .so's cold
    // spike-local copy). The read is field-for-field the twin of the dashboard's overlay: posture + rule/matrix
    // counts off `liveWardenStats`, the 9 toggle bits off `wardenUniversalToggles`, the per-app matrix off
    // `liveWardenMatrix`. On a host/preview build (no bridge) the reads collapse to the honest cold defaults
    // (relaxed posture, all-off toggles, empty matrix) — never a fabricated rule or app row.

    /// The wire `mode` ORDINAL → the settings-matrix label — the exact inverse of the Kotlin `.ordinal`
    /// [`liveWardenMatrix`](../../engine_bridge) emits (the `#[repr(i32)]` values coincide with the Kotlin
    /// declaration order). Delegates to [`app_mode_label`] so the label strings stay single-sourced.
    fn app_mode_label_ord(ord: i32) -> &'static str {
        match ord {
            0 => app_mode_label(WardenAppMode::BypassUniversal),
            1 => app_mode_label(WardenAppMode::Exclude),
            2 => app_mode_label(WardenAppMode::Isolate),
            3 => app_mode_label(WardenAppMode::None),
            4 => app_mode_label(WardenAppMode::Untracked),
            5 => app_mode_label(WardenAppMode::BypassDnsFirewall),
            _ => app_mode_label(WardenAppMode::None),
        }
    }

    /// The wire `metered` ORDINAL → the settings-matrix label (the inverse of the Kotlin `.ordinal`).
    fn net_class_label_ord(ord: i32) -> &'static str {
        match ord {
            0 => net_class_label(WardenNetClass::Both),
            1 => net_class_label(WardenNetClass::Unmetered),
            2 => net_class_label(WardenNetClass::Metered),
            3 => net_class_label(WardenNetClass::Allow),
            _ => net_class_label(WardenNetClass::Allow),
        }
    }

    /// The 9 TIER-2 universal toggle rows — the stable `(key, label, hint)` copy (the canonical wire keys the
    /// `setWardenUniversalToggle` bridge round-trips). The host fills each row's `on` bit from the live engine
    /// wire; `key`/`label`/`hint` are UI copy the host re-pushes so a fresh model never renders blank.
    const WARDEN_TOGGLE_META: [(&str, &str, &str); 9] = [
        ("new_apps", "Block new apps", "RULE1B — deny apps not yet seen"),
        ("unknown", "Block unknown UIDs", "deny untracked-UID connections"),
        ("metered", "Block metered", "RULE1F — deny cellular / roaming"),
        ("lockdown", "Lockdown", "RULE11 — block everything except the allow-list"),
        ("device_lock", "Block on lock", "RULE3 — deny while the screen is off"),
        ("background", "Foreground only", "RULE4 — deny background data"),
        ("udp_ntp", "Block UDP-NTP", "RULE6 — deny port 123 / UDP"),
        ("http", "Block plain HTTP", "RULE10 — deny port 80"),
        ("dns_bypass", "No DNS bypass", "RULE7 — deny queries skipping the resolver"),
    ];

    /// Read one toggle bit out of the flat `new_apps=0|unknown=1|…` pipe wire (host-safe — no JNI dep, so it
    /// unit-tests on the host). Absent/unparsable ⇒ `false` (the honest off default). Every wire key is
    /// unique + `=`-terminated, so a bare `find` never cross-matches a sibling key.
    fn warden_toggle_bit(wire: &str, key: &str) -> bool {
        let pat = format!("{key}=");
        match wire.find(&pat) {
            Some(i) => wire[i + pat.len()..].starts_with('1'),
            None => false,
        }
    }

    /// Build the 9 universal-toggle rows for the settings pane — the `(key,label,hint)` copy + the live `on`
    /// bit parsed from the toggles wire (`None` wire ⇒ all-off cold default). `rule_armed` is `true`: the
    /// defense-in-depth universal rule ships armed with its toggle (the pane's "(rule off)" caution is a
    /// later-wave refinement once a per-rule arm state is bridged).
    pub(crate) fn build_warden_settings_toggles(wire: Option<&str>) -> Vec<crate::UniversalToggle> {
        WARDEN_TOGGLE_META
            .iter()
            .map(|(key, label, hint)| crate::UniversalToggle {
                key: (*key).into(),
                label: (*label).into(),
                hint: (*hint).into(),
                on: wire.map(|w| warden_toggle_bit(w, key)).unwrap_or(false),
                rule_armed: true,
            })
            .collect()
    }

    /// The DASHBOARD twin of [`build_warden_settings_toggles`] — the 9 TIER-2 chips as the warden-dash
    /// pane's `[ToggleRow]` (`key` + `label` + `armed`; the dash renders no hint copy). `None` wire ⇒ an
    /// EMPTY vec, NOT nine off-rows: the pane's `length == 0` derive is its honest "bridge is silent" /
    /// "arm to read" state, and nine fabricated off-chips would dress an unreadable engine as all-clear.
    pub(crate) fn build_warden_dash_toggles(wire: Option<&str>) -> Vec<crate::ToggleRow> {
        let Some(w) = wire else {
            return Vec::new();
        };
        WARDEN_TOGGLE_META
            .iter()
            .map(|(key, label, _hint)| crate::ToggleRow {
                key: (*key).into(),
                label: (*label).into(),
                armed: warden_toggle_bit(w, key),
            })
            .collect()
    }

    /// Parse the `liveWardenMatrix` wire (line 1 `total=<n>`, then `uid\tapp\tmode\tmetered\ttemp_allow\tarmed`
    /// rows) into the editable settings-matrix rows. Host-safe (pure string parse). A malformed row is SKIPPED
    /// (fail-open — never a fabricated app row); an empty/`None` wire yields no rows (the pane's honest no-rows
    /// state). `armed` is not surfaced here (every held row enforces; the settings matrix edits held rows).
    pub(crate) fn parse_warden_settings_matrix(wire: &str) -> Vec<crate::AppToggleRow> {
        let mut rows = Vec::new();
        for line in wire.lines() {
            if line.is_empty() || line.starts_with("total=") {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 6 {
                continue; // malformed ⇒ skip (fail-open)
            }
            let uid = match f[0].trim().parse::<i32>() {
                Ok(u) => u,
                Err(_) => continue,
            };
            let name = if f[1].is_empty() {
                format!("uid {uid}")
            } else {
                f[1].to_string()
            };
            let mode_ord = f[2].trim().parse::<i32>().unwrap_or(3); // default NONE
            let metered_ord = f[3].trim().parse::<i32>().unwrap_or(3); // default ALLOW
            let paused = f[4].trim().parse::<u64>().map(|t| t != 0).unwrap_or(false);
            rows.push(crate::AppToggleRow {
                uid,
                name: name.into(),
                mode: app_mode_label_ord(mode_ord).into(),
                metered: net_class_label_ord(metered_ord).into(),
                paused,
            });
        }
        rows
    }

    /// Parse the `liveWardenRules` wire (line 1 `total=<n>`, then `kind\ttext\tscope\twildcard\tstatus` rows —
    /// DOMAINS first, then CIDRS, matching the bridge's enumerate order + `removeWardenRule`'s flat index) into
    /// the settings-pane rule-editor rows. Host-safe (pure string parse). A malformed row is SKIPPED (fail-open
    /// — never a fabricated rule); an empty/`None` wire yields no rows (the pane's honest "none armed" state).
    pub(crate) fn parse_warden_settings_rules(wire: &str) -> Vec<crate::RuleEntry> {
        let mut rows = Vec::new();
        for line in wire.lines() {
            if line.is_empty() || line.starts_with("total=") {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 5 {
                continue; // malformed ⇒ skip (fail-open)
            }
            rows.push(crate::RuleEntry {
                kind: f[0].to_string().into(),
                text: f[1].to_string().into(),
                scope: f[2].to_string().into(),
                wildcard: f[3].trim() == "1",
                status: f[4].to_string().into(),
            });
        }
        rows
    }

    /// The live-engine read for the settings feed — cfg-split so the host build carries no JNI dep + no
    /// unused-mut warning. Returns `(fail_closed, policy_loaded, domain_rules, cidr_rules, toggles_wire,
    /// matrix_wire)`. On host/test (no bridge) the honest cold defaults stand.
    #[cfg(target_os = "android")]
    fn read_warden_settings_live() -> (bool, bool, i32, i32, Option<String>, Option<String>) {
        let mut fail_closed = false;
        let mut policy_loaded = false;
        let mut domain_rules = 0i32;
        let mut cidr_rules = 0i32;
        if let Some(j) = crate::engine_bridge::live_warden_stats() {
            use crate::engine_bridge::{json_bool, json_i32};
            fail_closed = json_bool(&j, "fail_closed");
            policy_loaded = json_bool(&j, "policy_loaded");
            domain_rules = json_i32(&j, "domain_rules").unwrap_or(0);
            cidr_rules = json_i32(&j, "cidr_rules").unwrap_or(0);
        }
        (
            fail_closed,
            policy_loaded,
            domain_rules,
            cidr_rules,
            crate::engine_bridge::warden_universal_toggles(),
            crate::engine_bridge::live_warden_matrix(),
        )
    }

    #[cfg(not(target_os = "android"))]
    fn read_warden_settings_live() -> (bool, bool, i32, i32, Option<String>, Option<String>) {
        (false, false, 0, 0, None, None) // host/preview: no bridge ⇒ honest cold defaults
    }

    /// The live-engine read for the settings RULE LIST — cfg-split like [`read_warden_settings_live`]. The
    /// serialized `liveWardenRules` wire (M2) off the canonical `WardenObject` enumerators, or `None` on
    /// host/preview (no bridge ⇒ the pane's honest "none armed" state stands).
    #[cfg(target_os = "android")]
    fn read_warden_settings_rules_wire() -> Option<String> {
        crate::engine_bridge::live_warden_rules()
    }

    #[cfg(not(target_os = "android"))]
    fn read_warden_settings_rules_wire() -> Option<String> {
        None
    }

    /// Push the CURRENT armed state of the canonical live WardenObject onto the shell's `ws-*` settings
    /// aliases (the warden-settings section) — posture + the 9 toggles + the per-app matrix + the enumerated
    /// BLOCK rule list + the summary scalars. Called on the SETTINGS chip tap + re-fed each second while the
    /// pane is shown (android_main). The rule list rides the M2 `liveWardenRules` enumerator (honest-empty on
    /// a cold engine). No trust list — the Warden layer has no trust concept by design law.
    pub(crate) fn feed_warden_settings_shell(sh: &crate::TortaShell) {
        let (fail_closed, policy_loaded, domain_rules, cidr_rules, toggles_wire, matrix_wire) =
            read_warden_settings_live();

        sh.set_ws_fail_closed(fail_closed);
        sh.set_ws_policy_loaded(policy_loaded);

        let toggles = build_warden_settings_toggles(toggles_wire.as_deref());
        let lockdown_on = toggles.iter().any(|t| t.key == "lockdown" && t.on);
        sh.set_ws_universal_toggles(ModelRc::new(VecModel::from(toggles)));
        sh.set_ws_lockdown_on(lockdown_on);

        let matrix = matrix_wire
            .as_deref()
            .map(parse_warden_settings_matrix)
            .unwrap_or_default();
        sh.set_ws_app_matrix(ModelRc::new(VecModel::from(matrix)));

        // Rules editor (M2): the live enumerated BLOCK rule list off the canonical WardenObject. Honest-empty
        // on a cold engine / unreachable bridge — the pane renders the "none armed" state. (No trust list:
        // the Warden layer has no trust concept by design law — that is the Underground pillar's surface.)
        let rules = read_warden_settings_rules_wire()
            .as_deref()
            .map(parse_warden_settings_rules)
            .unwrap_or_default();
        sh.set_ws_rules(ModelRc::new(VecModel::from(rules)));

        sh.set_ws_armed_rule_count(domain_rules + cidr_rules);
    }

    // ===== A5 slice-5 — the LIVE FLOWS docket feed (the ConnTracker ring → FlowRow rows) =====

    /// Rows the docket shows (the ring holds 512 — the panel renders the newest eyeful; the
    /// `flow-total` header carries the ring's honest RETAINED count so the cap never reads as it).
    const FLOWS_SHOWN: usize = 12;

    /// `WardenVerdict` → docket label. The DENY labels carry their seam (firewall cascade vs the
    /// datapath's external DNS-blocklist gate) so attribution reads off the row — and attribution
    /// INFORMS; the tint (`denied`) is driven by the verdict alone, never by cc/asn.
    #[cfg(not(target_os = "android"))]
    fn flow_verdict_label(v: torta_core::WardenVerdict) -> &'static str {
        match v {
            torta_core::WardenVerdict::Allow => "ALLOW",
            torta_core::WardenVerdict::DenyByFirewall => "DENY-FW",
            torta_core::WardenVerdict::DenyByBlocklist => "DENY-DNS",
        }
    }

    /// IANA protocol number → docket label; the unknown arm shows the honest number, never "?".
    fn proto_label(proto: u8) -> String {
        match proto {
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            1 => "ICMP".to_string(),
            58 => "ICMPv6".to_string(),
            n => format!("P{n}"),
        }
    }

    /// One in-process `FlowRecord` → docket row. `app` passes through as recorded — the tunnel
    /// choke point stamps "" (uid→label is the Kotlin PackageManager seam, which the BRIDGE rows
    /// carry resolved); the .slint falls back to `ip` on the empty. Bytes (`up`/`down`) are
    /// deliberately NOT rendered this wave — verdict-time records carry no byte truth yet (the
    /// per-flow byte-attribution road is banked, not faked).
    #[cfg(not(target_os = "android"))]
    fn record_to_row(r: &torta_core::FlowRecord) -> crate::FlowRow {
        crate::FlowRow {
            flag: r.flag.clone().into(),
            cc: r.cc.to_uppercase().into(),
            app: r.app.clone().into(),
            ip: r.ip.clone().into(),
            port: r.port as i32,
            proto: proto_label(r.proto).into(),
            asn: r.asn.clone().into(),
            domain: r.domain.clone().into(),
            verdict: flow_verdict_label(r.verdict).into(),
            denied: r.verdict != torta_core::WardenVerdict::Allow,
            carried: r.carried,
        }
    }

    /// Parse the cross-.so flows wire (TortaPillarBridge `liveWardenFlows`): line 1 `total=<n>`,
    /// then one row per line, 9 TAB-separated fields — `cc \t app \t ip \t port \t proto \t
    /// verdict \t asn \t carried \t domain`. TAB/newline because IPv6 owns `:` and AS names own
    /// `,`/space; the wire stays ASCII (`cc` not the flag glyph — the flag derives HERE via the
    /// engine's `flag_emoji`, the one source, so the JNI seam never carries supplementary-plane
    /// glyphs). `carried` is `1`/`0` (#20 ROW HONESTY — the datapath disposition rides beside the
    /// verdict, never inside it: the verdict cell stays the pure Kotlin enum name). `domain` is
    /// the A4 attribution ("" = unattributed) — LAST on the wire so every earlier column keeps
    /// its #20 position. A malformed row is SKIPPED (fail-open, the underground-rows law) — never
    /// a panic, never a fabricated field; an 8-field row from a stale peer .so drops to the
    /// honest empty docket (ship-together law).
    pub(crate) fn parse_flow_feed(raw: &str) -> (i32, Vec<crate::FlowRow>) {
        let mut total = 0i32;
        let mut rows: Vec<crate::FlowRow> = Vec::new();
        for (i, line) in raw.lines().enumerate() {
            if i == 0 {
                total = line
                    .strip_prefix("total=")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                continue;
            }
            if rows.len() >= FLOWS_SHOWN {
                break;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() != 9 {
                continue;
            }
            let Ok(port) = f[3].parse::<i32>() else { continue };
            let Ok(proto) = f[4].parse::<u8>() else { continue };
            // The wire verdict is the UniFFI Kotlin enum name; the unknown arm shows the honest
            // raw name and tints by the DENY prefix (a new verdict never renders as a false ALLOW).
            let (verdict, denied) = match f[5] {
                "ALLOW" => ("ALLOW".to_string(), false),
                "DENY_BY_FIREWALL" => ("DENY-FW".to_string(), true),
                "DENY_BY_BLOCKLIST" => ("DENY-DNS".to_string(), true),
                other => (other.to_string(), other.starts_with("DENY")),
            };
            // carried: strict `1` = carried; anything else (incl. garbage) reads uncarried — the
            // fail direction is DROPPED-when-unsure, never carried-when-unsure (#20).
            let carried = f[7] == "1";
            rows.push(crate::FlowRow {
                flag: torta_core::flag_emoji(f[0]).into(),
                cc: f[0].to_uppercase().into(),
                app: f[1].into(),
                ip: f[2].into(),
                port,
                proto: proto_label(proto).into(),
                asn: f[6].into(),
                domain: f[8].into(),
                verdict: verdict.into(),
                denied,
                carried,
            });
        }
        (total, rows)
    }

    /// ★ #47/#49 N8 — how many forwarder flows the FORWARDER dashboard lists at once. The Rust
    /// registry caps at 256 and the Kotlin wire at 12; this is the render cap. All three are
    /// deliberately separate numbers, and the panel shows `shown of total` so a cap never reads as
    /// "that is all the traffic there was".
    const FWD_FLOWS_SHOWN: usize = 12;

    /// Parse the cross-.so forwarder docket wire (`TortaPillarBridge.liveForwarderDocket`): line 1
    /// `total=<active_flows>`, then one row per line, 10 TAB-separated fields —
    /// `key \t proto_tcp \t tin \t paced \t cwnd \t bytes_up \t bytes_down \t rtt_ms \t age_ms \t stalls`.
    ///
    /// A malformed row is SKIPPED (fail-open — the same law as [`parse_flow_feed`]): never a panic,
    /// never a fabricated field. A row count that differs from a stale peer `.so` drops to the honest
    /// empty docket rather than mis-parsing (ship-together law).
    ///
    /// `rtt_ms` of `-1` is carried THROUGH as -1, not clamped to 0: the panel must be able to say
    /// "unmeasured" instead of claiming an instantaneous round trip (the #96 empty-state law).
    pub(crate) fn parse_forwarder_docket(raw: &str) -> (i32, Vec<crate::FwdFlowRow>) {
        let mut total = 0i32;
        let mut rows: Vec<crate::FwdFlowRow> = Vec::new();
        for (i, line) in raw.lines().enumerate() {
            if i == 0 {
                total = line
                    .strip_prefix("total=")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                continue;
            }
            if rows.len() >= FWD_FLOWS_SHOWN {
                break;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() != 10 {
                continue;
            }
            let (Ok(key), Ok(tin), Ok(cwnd)) = (
                f[0].parse::<i64>(),
                f[2].parse::<i32>(),
                f[4].parse::<i32>(),
            ) else {
                continue;
            };
            let (Ok(up), Ok(down)) = (f[5].parse::<i64>(), f[6].parse::<i64>()) else {
                continue;
            };
            // `stalls` is a u64 on the engine side, so it is parsed WIDE and clamped rather than
            // parsed as i32 — a counter that outgrew i32 must still render its flow, not silently
            // drop the row (the fail-open law: degrade the number, never the evidence).
            let (Ok(rtt), Ok(age), Ok(stalls)) = (
                f[7].parse::<i32>(),
                f[8].parse::<i64>(),
                f[9].parse::<i64>(),
            ) else {
                continue;
            };
            // ★ #51 — field 2 is the IANA protocol NUMBER, not a TCP flag. An unrecognised number
            // renders as itself (`ip 47`) rather than being folded into one of the three we know:
            // if the engine ever carries a fourth protocol, the panel must say so instead of
            // mislabelling it as the last one in the list.
            let proto = match f[1] {
                "6" => "TCP".to_string(),
                "17" => "UDP".to_string(),
                "1" => "ICMP".to_string(),
                other => format!("ip {other}"),
            };
            rows.push(crate::FwdFlowRow {
                // The folded CAKE key rendered as short hex — an IDENTITY the eye can follow across
                // ticks. Never an address: the wire carries no IP, port or hostname at all (T20).
                key: format!("{:012x}", key as u64 & 0xffff_ffff_ffff).into(),
                proto: proto.into(),
                tin: match tin {
                    0 => "CRITICAL",
                    1 => "HIGH",
                    _ => "BULK",
                }
                .into(),
                // Only BULK flows are paced; CRITICAL/HIGH run unshaped latency-first BY DESIGN, so
                // the row says "unshaped" rather than showing a window of zero.
                paced: f[3] == "1",
                cwnd,
                // Slint has no 64-bit numeric type: `float` is the house carrier for byte counts
                // (the ENGINE card's `fwd-bytes-up` already rides f32). Precision degrades past
                // 2^24 bytes, which is display-irrelevant at MB scale and never load-bearing.
                bytes_up: up as f32,
                bytes_down: down as f32,
                rtt_ms: rtt,
                age_ms: age as f32,
                stalls: stalls.clamp(0, i32::MAX as i64) as i32,
            });
        }
        (total, rows)
    }

    /// The FORWARDER docket source. ANDROID: only the bridge is honest (the shell's statically-linked
    /// `torta_core` owns a separate, permanently empty registry). HOST/TEST: no forwarder runs, so the
    /// honest reading is the empty docket — NOT a fabricated demo row.
    pub(crate) fn live_forwarder_docket_feed() -> (i32, Vec<crate::FwdFlowRow>) {
        #[cfg(target_os = "android")]
        {
            match crate::engine_bridge::live_forwarder_docket() {
                Some(raw) => parse_forwarder_docket(&raw),
                None => (0, Vec::new()),
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            (0, Vec::new())
        }
    }

    /// The docket source. ANDROID: the shell .so's in-process ring is a COLD rlib twin (the engine
    /// feeds ITS ring inside libtorta_core.so — the two-.so law), so the ONLY honest source is the
    /// TortaPillarBridge seam; bridge-silent = the honest empty docket, NEVER the cold twin's zeros
    /// dressed as a reading. HOST/TEST: the in-process ring IS the engine's ring (one .so) — read it.
    pub(crate) fn live_flow_feed() -> (i32, Vec<crate::FlowRow>) {
        #[cfg(target_os = "android")]
        {
            match crate::engine_bridge::live_warden_flows() {
                Some(raw) => parse_flow_feed(&raw),
                None => (0, Vec::new()),
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            let ring = torta_core::warden_flow_ring();
            let total = ring.count().try_into().unwrap_or(i32::MAX);
            let rows = ring
                .snapshot()
                .iter()
                .take(FLOWS_SHOWN)
                .map(record_to_row)
                .collect();
            (total, rows)
        }
    }

    /// Push the docket into the shell (startup + the 1s warden-dash Timer both land here).
    pub(crate) fn feed_live_flows(sh: &crate::TortaShell) {
        let (total, rows) = live_flow_feed();
        sh.set_wdash_flow_total(total);
        sh.set_wdash_live_flows(ModelRc::new(VecModel::from(rows)));
    }

    // ===== W-D (#79) — THE PER-APP INSPECTOR feed + block-ladder (the separate popup dashboard) =====
    //
    // The parsers are PURE string (host-testable — the proof harness runs them). The feed/handler fns
    // touch the cross-.so bridge (android-only). Selection state lives IN the dest MODEL (a select tap
    // flips the row's `selected` bit + re-feeds) — no shadow Rust set, so the SLINT model is the one truth.

    /// Parse the `liveWardenAppFlows` wire (line 1 `total=<n>`, then per row `uid\tapp\tflows\tallowed\t
    /// denied\tdistinct_ips\tcountries\tup\tdown\tlast_ts\tblock_wifi\tblock_mobile\tmode_ord`) into the app
    /// BROWSER rows. Host-safe; a malformed row is SKIPPED (fail-open — never a fabricated app), an empty /
    /// `None` wire yields no rows (the pane's honest DORMANT browser).
    pub(crate) fn parse_inspector_apps(wire: &str) -> Vec<crate::InspectorAppRow> {
        let mut rows = Vec::new();
        for line in wire.lines() {
            if line.is_empty() || line.starts_with("total=") {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 13 {
                continue; // malformed ⇒ skip (fail-open)
            }
            let uid = match f[0].trim().parse::<i32>() {
                Ok(u) => u,
                Err(_) => continue,
            };
            let name = if f[1].is_empty() {
                format!("uid {uid}")
            } else {
                f[1].to_string()
            };
            let gi = |i: usize| f[i].trim().parse::<i32>().unwrap_or(0);
            rows.push(crate::InspectorAppRow {
                uid,
                name: name.into(),
                flows: gi(2),
                allowed: gi(3),
                denied: gi(4),
                ips: gi(5),
                countries: gi(6),
                up: gi(7),
                down: gi(8),
                // f[9] = last_ts (ordering key, not rendered)
                block_wifi: f[10].trim() == "1",
                block_mobile: f[11].trim() == "1",
                mode_ord: gi(12),
            });
        }
        rows
    }

    /// Parse the `liveWardenAppDests(uid)` wire (line 1 `total=<n>`, then per row `ip\tcc\tasn\tdomain\t
    /// port\tproto\tdenied\tcarried\thits\tup\tdown\tlast_ts`) into ONE app's ENDPOINT rows. The GEO flag
    /// derives HERE via [`torta_core::flag_emoji`] (the one source — the JNI wire carries ASCII `cc`, never
    /// a supplementary-plane glyph). Every row starts UNSELECTED (the multi-select is a UI action). Host-safe;
    /// a malformed row is SKIPPED (fail-open).
    pub(crate) fn parse_inspector_dests(wire: &str) -> Vec<crate::InspectorDestRow> {
        let mut rows = Vec::new();
        for line in wire.lines() {
            if line.is_empty() || line.starts_with("total=") {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 12 {
                continue; // malformed ⇒ skip (fail-open)
            }
            let port = f[4].trim().parse::<i32>().unwrap_or(0);
            let proto = f[5].trim().parse::<u8>().unwrap_or(0);
            let hits = f[8].trim().parse::<i32>().unwrap_or(0);
            rows.push(crate::InspectorDestRow {
                ip: f[0].into(),
                flag: torta_core::flag_emoji(f[1]).into(),
                cc: f[1].to_uppercase().into(),
                asn: f[2].into(),
                domain: f[3].into(),
                port,
                proto: proto_label(proto).into(),
                denied: f[6].trim() == "1",
                carried: f[7].trim() == "1",
                hits,
                selected: false,
            });
        }
        rows
    }

    /// Build the ladder CIDR string for one endpoint at a granularity rung — mode `0` = the /32 (v4) or
    /// /128 (v6) HOST, `1` = the neighbourhood (/24 · /64), `2` = the source FAMILY (/16 · /48). A bare host
    /// (mode 0) rides as-is (the engine parses bare = /32 or /128). Pure — host-testable.
    pub(crate) fn ladder_cidr(ip: &str, mode: i32) -> String {
        let is_v6 = ip.contains(':');
        match (is_v6, mode) {
            (_, 0) => ip.to_string(),
            (false, 1) => format!("{ip}/24"),
            (false, _) => format!("{ip}/16"),
            (true, 1) => format!("{ip}/64"),
            (true, _) => format!("{ip}/48"),
        }
    }

    /// Refresh the inspector APP BROWSER (+ the focused app's live posture header + the armed GEO set) off
    /// the live bridge. Called every 1 s WHILE the overlay is open. The focused app's DEST list + its
    /// multi-selection are deliberately NOT re-pulled here — a per-tick clobber would drop the user's set.
    #[cfg(target_os = "android")]
    pub(crate) fn feed_inspector_browser(sh: &crate::TortaShell) {
        let apps = crate::engine_bridge::live_warden_app_flows()
            .as_deref()
            .map(parse_inspector_apps)
            .unwrap_or_default();
        let uid = sh.get_wdash_inspector_uid();
        if uid >= 0 {
            if let Some(a) = apps.iter().find(|a| a.uid == uid) {
                sh.set_wdash_inspector_app_name(a.name.clone());
                sh.set_wdash_inspector_block_wifi(a.block_wifi);
                sh.set_wdash_inspector_block_mobile(a.block_mobile);
            }
        }
        sh.set_wdash_inspector_apps(ModelRc::new(VecModel::from(apps)));
        let geo = crate::engine_bridge::warden_geo_blocks().unwrap_or_default();
        sh.set_wdash_inspector_geo_blocks(geo.to_uppercase().into());
    }

    /// Open the inspector overlay on ONE app (uid >= 0 → drill into its endpoints; uid < 0 → the browser).
    /// Pulls a FRESH endpoint snapshot (all unselected) + refreshes the browser/posture/geo.
    #[cfg(target_os = "android")]
    pub(crate) fn open_inspector(sh: &crate::TortaShell, uid: i32) {
        sh.set_wdash_inspector_uid(uid);
        sh.set_wdash_inspector_open(true);
        sh.set_wdash_inspector_selected_count(0);
        feed_inspector_browser(sh);
        // Pull the endpoint snapshot for ANY bucket — including the unattributed/system one (uid < 0).
        // Its dests ARE worth inspecting (rethink's "Unknown" bucket precedent), and the SLINT detail
        // view is now gated on `inspector-detail-open` (a pane-local flag), not the uid sign — so this
        // fold must serve both a real app AND the -1 aggregate. `app_destinations` folds by uid == -1
        // cleanly (the ring keys unresolved flows there); an empty pull just yields an empty list.
        let dests = crate::engine_bridge::live_warden_app_dests(uid)
            .as_deref()
            .map(parse_inspector_dests)
            .unwrap_or_default();
        sh.set_wdash_inspector_dests(ModelRc::new(VecModel::from(dests)));
        if uid < 0 {
            // The unattributed bucket has no per-app AppMatrixRow → no name from the browser fold, and
            // its WiFi/mobile posture is meaningless (the SLINT detail hides those toggles for uid < 0).
            sh.set_wdash_inspector_app_name("unattributed".into());
            sh.set_wdash_inspector_block_wifi(false);
            sh.set_wdash_inspector_block_mobile(false);
        }
    }

    /// Toggle ONE endpoint's multi-select bit (by ip) IN the dest model + recompute the selected count.
    /// The model is the one truth — no shadow set (the block-ladder reads `selected` straight back).
    #[cfg(target_os = "android")]
    pub(crate) fn inspector_toggle_select(sh: &crate::TortaShell, ip: &str) {
        use slint::Model;
        let model = sh.get_wdash_inspector_dests();
        let mut rows: Vec<crate::InspectorDestRow> = model.iter().collect();
        let mut count = 0;
        for r in rows.iter_mut() {
            if r.ip.as_str() == ip {
                r.selected = !r.selected;
            }
            if r.selected {
                count += 1;
            }
        }
        sh.set_wdash_inspector_selected_count(count);
        sh.set_wdash_inspector_dests(ModelRc::new(VecModel::from(rows)));
    }

    /// Ride the block-ladder over the SELECTED endpoint set at granularity `mode` (0 = each IP /32 · 1 =
    /// each /24 · 2 = each /16 · 3 = each endpoint's whole COUNTRY GEO family). The IP/CIDR rungs arm ONE
    /// additive per-app block each; the country rung UNIONS the selected ccs with the armed set + replaces.
    /// After arming, re-opens the app (fresh dests, selection cleared) so the posture header + geo line
    /// reflect the new blocks. A no-selection call is a no-op.
    #[cfg(target_os = "android")]
    pub(crate) fn inspector_block_selected(sh: &crate::TortaShell, uid: i32, mode: i32) {
        use slint::Model;
        let model = sh.get_wdash_inspector_dests();
        let selected: Vec<crate::InspectorDestRow> = model.iter().filter(|r| r.selected).collect();
        if selected.is_empty() {
            return;
        }
        if mode == 3 {
            // GEO family: union each selected endpoint's cc with the armed set, REPLACE.
            let mut codes: Vec<String> = crate::engine_bridge::warden_geo_blocks()
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .collect();
            for r in &selected {
                let cc = r.cc.as_str().trim().to_uppercase();
                if !cc.is_empty() && cc != "??" && !codes.contains(&cc) {
                    codes.push(cc);
                }
            }
            let _ = crate::engine_bridge::warden_set_geo_blocks(&codes.join(","));
        } else {
            // IP / CIDR-family rungs: one additive block per selected endpoint at the chosen granularity.
            // The unattributed/system bucket (uid < 0) can't hold a per-app IpRule (the verdict matches
            // uid EXACTLY) → arm the UNIVERSAL tier instead (uid 0 = `UID_UNIVERSAL`), which blocks the
            // endpoint for EVERY app and so actually bites the unattributed flow. A real app keeps its
            // per-app block.
            let rule_uid = if uid < 0 { 0 } else { uid };
            for r in &selected {
                let cidr = ladder_cidr(r.ip.as_str(), mode);
                if !cidr.is_empty() {
                    let _ = crate::engine_bridge::warden_block_ip(rule_uid, &cidr);
                }
            }
        }
        open_inspector(sh, uid);
    }
}

// ===========================================================================================
// THE UNDERGROUND FEED SHAPE (CP-U) — the pure row renderer behind the ENGINE tab's UNDERGROUND
// LAYER card. Host-visible on test builds too (the warden_feed cfg idiom) so the proof harness
// exercises the EXACT row-rendering the on-device feed runs — never a parallel re-derivation.
// ===========================================================================================
#[cfg(any(target_os = "android", test))]
pub(crate) mod underground_feed {
    /// Render the bridge's colon-joined worst-offender rows (`host:risk:source:hits:points:seq:verdict`
    /// joined by `;` — `TortaPillarBridge.liveUndergroundStats` reshapes the Rust snapshot's
    /// TAB-separated rows into the rttHints colon idiom before they ride the pipe record) into
    /// the card's one-line-per-host display text:
    /// `"host · risk/source · ×hits · points/20[ · TRUST|BLOCK|SEQ]"`. The manual Trust band
    /// (7th field) OVERRIDES the automatic tooth-mark: a condemned host reads `BLOCK` (which is
    /// why it sits sequestered), a vouched host reads `TRUST`, and a Neutral host falls back to
    /// the engine's own `SEQ`. Malformed rows (≠6/7 fields, empty host) are skipped fail-open —
    /// one bad row never blanks the court. A pre-Trust-bands 6-field row reads as Neutral. Empty
    /// input renders "".
    pub(crate) fn format_underground_top(raw: &str) -> String {
        raw.split(';')
            .filter_map(|row| {
                let f: Vec<&str> = row.split(':').collect();
                // 6 = pre-Trust-bands, 7 = D-era, 9 = the H pillar row (+score +ttl) — all render.
                if !(6..=9).contains(&f.len()) || f[0].is_empty() {
                    return None;
                }
                let badge = match f.get(6).copied().unwrap_or("neutral") {
                    "trusted" => " · TRUST",
                    "distrusted" => " · BLOCK",
                    _ if f[5] == "1" => " · SEQ",
                    _ => "",
                };
                Some(format!(
                    "{} · {}/{} · ×{} · {}/20{}",
                    f[0], f[1], f[2], f[3], f[4], badge
                ))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// One parsed docket row for the #15 pillar dashboard — the 9-field H row
    /// (`host:risk:source:hits:points:seq:verdict:score:ttl`) as owned typed parts. The feed
    /// maps these onto the generated `UgHostRow` slint struct; keeping the parse PURE keeps it
    /// host-testable (the `format_underground_top` precedent).
    pub(crate) struct DocketRow {
        pub host: String,
        pub risk: String,
        pub source: String,
        pub hits: i32,
        pub points: i32,
        pub seq: bool,
        pub verdict: String,
        pub score: i32,
        pub ttl_label: String,
    }

    /// The G quarantine countdown, human-shaped: `0` ⇒ "—" (no clock — active-destroy terminal,
    /// or a manual pin), else "3h12m" / "12m" / "45s".
    pub(crate) fn fmt_ttl(secs: i64) -> String {
        if secs <= 0 {
            return "—".into();
        }
        let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
        if h > 0 {
            format!("{h}h{m:02}m")
        } else if m > 0 {
            format!("{m}m")
        } else {
            format!("{s}s")
        }
    }

    /// Parse the bridge's colon-joined `top_score=` rows (the E score ordering, 9-field H shape)
    /// into typed docket rows. A shorter legacy row still parses (score/ttl default 0 ⇒ "—");
    /// malformed rows are skipped fail-open — one bad row never blanks the court.
    pub(crate) fn parse_underground_docket(raw: &str) -> Vec<DocketRow> {
        raw.split(';')
            .filter_map(|row| {
                let f: Vec<&str> = row.split(':').collect();
                if !(6..=9).contains(&f.len()) || f[0].is_empty() {
                    return None;
                }
                Some(DocketRow {
                    host: f[0].into(),
                    risk: f[1].into(),
                    source: f[2].into(),
                    hits: f[3].parse().unwrap_or(0),
                    points: f[4].parse().unwrap_or(0),
                    seq: f[5] == "1",
                    verdict: f.get(6).copied().unwrap_or("neutral").into(),
                    score: f.get(7).and_then(|s| s.parse().ok()).unwrap_or(0),
                    ttl_label: fmt_ttl(f.get(8).and_then(|s| s.parse().ok()).unwrap_or(0)),
                })
            })
            .collect()
    }

    /// Render the bridge's `liveUndergroundEvents` rows (`seq:host:verdict:delta:signal:ts`
    /// joined by `;`, newest LAST off the RAM ring) into the pillar's LIVE WIRE ticker text —
    /// newest FIRST, capped at 8 lines: `"#seq host · signal Δdelta → verdict"`. Malformed rows
    /// skip fail-open; empty input renders "".
    pub(crate) fn format_underground_wire(raw: &str) -> String {
        let mut lines: Vec<String> = raw
            .split(';')
            .filter_map(|row| {
                let f: Vec<&str> = row.split(':').collect();
                if f.len() != 6 || f[0].is_empty() || f[1].is_empty() {
                    return None;
                }
                Some(format!("#{} {} · {} Δ{} → {}", f[0], f[1], f[4], f[3], f[2]))
            })
            .collect();
        lines.reverse();
        lines.truncate(8);
        lines.join("\n")
    }

    /// Parse the operator's scoring.toml for the SETTINGS pane's quick state: the three
    /// `[detection]` kill switches (absent ⇒ ON, the engine's own default law) + the
    /// `[quarantine] ttl_secs` (absent ⇒ 86400). A crude line scan on purpose — the pane only
    /// mirrors; the ENGINE's serde parse is the authority (garbled ⇒ sitting law).
    pub(crate) fn parse_underground_law(toml: &str) -> (bool, bool, bool, i64) {
        let (mut dga, mut tunnel, mut beacon, mut ttl) = (true, true, true, 86_400_i64);
        let mut section = String::new();
        for line in toml.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                section = t.trim_matches(['[', ']']).to_string();
                continue;
            }
            let Some((k, v)) = t.split_once('=') else { continue };
            let (k, v) = (k.trim(), v.trim());
            match (section.as_str(), k) {
                ("detection", "dga") => dga = v != "false",
                ("detection", "tunnel") => tunnel = v != "false",
                ("detection", "beacon") => beacon = v != "false",
                ("quarantine", "ttl_secs") => ttl = v.parse().unwrap_or(86_400),
                _ => {}
            }
        }
        (dga, tunnel, beacon, ttl)
    }

    /// Patch ONE `[detection]` switch in the operator's toml text (the pane's quick toggles are
    /// sugar over the SAME law file the editor shows — never a fork). Rewrites the key in place
    /// if present, appends it to an existing `[detection]` section otherwise, or appends the
    /// whole section. Returns the new text.
    pub(crate) fn patch_underground_detection(toml: &str, name: &str, on: bool) -> String {
        let val = if on { "true" } else { "false" };
        let mut out: Vec<String> = Vec::new();
        let mut section = String::new();
        let mut patched = false;
        let mut det_end: Option<usize> = None;
        for line in toml.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                section = t.trim_matches(['[', ']']).to_string();
                out.push(line.to_string());
                if section == "detection" {
                    det_end = Some(out.len());
                }
                continue;
            }
            if section == "detection" {
                if let Some((k, _)) = t.split_once('=') {
                    if k.trim() == name {
                        out.push(format!("{name} = {val}"));
                        patched = true;
                        continue;
                    }
                }
                if !t.is_empty() {
                    det_end = Some(out.len() + 1);
                }
            }
            out.push(line.to_string());
        }
        if !patched {
            match det_end {
                Some(i) => out.insert(i, format!("{name} = {val}")),
                None => {
                    if out.last().map(|l| !l.trim().is_empty()).unwrap_or(false) {
                        out.push(String::new());
                    }
                    out.push("[detection]".into());
                    out.push(format!("{name} = {val}"));
                }
            }
        }
        let mut s = out.join("\n");
        s.push('\n');
        s
    }
}

// ===========================================================================================
// THE WIRE CAKE INU PREFS PARSER — the pure half of the Kotlin durability-triple read
// (`TortaPillarBridge.stagedInuConfig()`'s pipe record), kept OUTSIDE the android-gated spike so
// the host tests exercise the EXACT parser the on-device feeds consume (the
// `underground_feed::format_underground_top` precedent).
// ===========================================================================================
pub(crate) mod inu_feed {
    // DEAD-CODE ALLOW REMOVED — and it turned out to be REDUNDANT, which is the whole finding.
    //
    // The comment that sat here justified a module-wide `#![allow(dead_code)]` on the grounds that
    // these items are "compiled but uncalled on the host lib build". MEASURED with the allow
    // deleted: zero dead-code warnings from this module on the host build AND zero on the shipped
    // android target. Nothing here was ever dead. The suppression was defending against a problem
    // that did not exist, and because it was module-wide it would have gone on hiding any REAL
    // deadness that appeared later anywhere in this module.
    //
    // That is the characteristic failure of a blanket allow: it is written once against a
    // plausible-sounding worry, it is never re-tested, and from then on it silences a class of
    // finding rather than a specific known item. The only way to learn it was unnecessary was to
    // take it out and rebuild — which is exactly what "the only legal exit is to wire it" forces
    // you to do, and why removing these is worth the effort even when nothing changes.

    /// Parse the Kotlin durability-triple record (`bootreapply=<0/1>|alwayson=<0/1>|providerpref=<i>`,
    /// the `stagedInuConfig()` pipe shape) → (boot-reapply, always-on, provider-pref). A missing/garbled
    /// field holds its honest default (off / off / AUTO=0) — fail-open per field, never a panic.
    pub(crate) fn parse_inu_prefs(cfg: &str) -> (bool, bool, i32) {
        let (mut boot_reapply, mut always_on, mut provider_pref) = (false, false, 0i32);
        for part in cfg.split('|') {
            let mut kv = part.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("bootreapply"), Some(v)) => boot_reapply = v.trim() == "1",
                (Some("alwayson"), Some(v)) => always_on = v.trim() == "1",
                (Some("providerpref"), Some(v)) => provider_pref = v.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
        (boot_reapply, always_on, provider_pref)
    }

    /// Parse the GENERAL boot-autostart pair record (`on=<0/1>|delay=<secs>`, the
    /// `bootAutostartConfig()` pipe shape) → (keep-on-boot, delay-secs). A missing/garbled field
    /// holds its honest default (off / 0 s) — fail-open per field, never a panic. The delay clamps
    /// to the 0..=300 s band the stepper walks (the Kotlin writer clamps identically).
    pub(crate) fn parse_boot_autostart(cfg: &str) -> (bool, i32) {
        let (mut on, mut delay) = (false, 0i32);
        for part in cfg.split('|') {
            let mut kv = part.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("on"), Some(v)) => on = v.trim() == "1",
                (Some("delay"), Some(v)) => {
                    delay = v.trim().parse::<i32>().unwrap_or(0).clamp(0, 300)
                }
                _ => {}
            }
        }
        (on, delay)
    }
}

// ===========================================================================================
// THE ENGINE DRIVE BRIDGE (SLINT substitution · 2-DRIVE-CORE) — the Rust half of the HOME master
// switch. The pure-Rust SLINT rail CANNOT start the module runner (Kotlin's ModulesService owns it —
// the D09 law), so the shell's `engine-toggled` callback JNI-calls the Kotlin `TortaSlintBridge`
// (start/stop DNSCrypt), and a 1 s poll Timer JNI-reads the real `dnsCryptState` back onto the shell
// (flipping the crown to SHIELDED only when DNSCrypt is ACTUALLY running — the felt-truth law).
//
// THE CLASSLOADER IDIOM (measured, not doctrine): a rail-thread `FindClass` resolves against the
// SYSTEM classloader, which cannot see app classes. So every call attaches the current (rail) thread
// to the JVM (the `AndroidApp` glue published the VM + Activity jobject via `ndk_context` before
// `android_main`), reaches the Activity's OWN classloader (`Activity.getClassLoader()`), and
// `loadClass`es `TortaSlintBridge` there — the documented android JNI path to app classes. Every step
// is fail-open (`?`/`.ok()?` → `None`): a JNI hiccup never panics the render thread, it just skips a
// tick (the shell keeps drawing the last honest state).
// ===========================================================================================

/// The app-private data dir, published ONCE at launch so the argument-free row builders can reach the
/// durable tier.
///
/// WHY THIS EXISTS — the WIRE CAKE INU pillar row was a **hardcoded literal**: `status: "OFF — ADB
/// elevation idle"`, `live: false`, with a comment conceding "no live cross-.so counter bridge yet".
/// That row could therefore NEVER go live, whatever the engine or the user's own record said, which is
/// why every on-device run counted 8 pillars and not 9. The other pillars read a Kotlin static through
/// [`engine_bridge::read_pillar_string`]; INU has no such static, so the row had nothing to read.
///
/// It does not need one. INU's truth is DURABLE, not live-counted: `InuStore::rehydrate_exists()` is
/// the codebase's own documented answer to "has this record ever been written?" (inu/object.rs), and
/// both `InuStore` ctors are IO-free by the no-boot-IO-scan law, so a row builder can open the store on
/// any tick for free. All this cell carries is the path.
///
/// FAIL-OPEN, and the direction matters: an unset cell (or an absent record) yields OFF. The row can
/// only ever UNDER-claim elevation, never fabricate a privileged session that is not held — the same
/// law `pillar_rows` already states for its JNI reads, and the same direction `InuElevationStatus::
/// from_u8` chose for unknown ordinals. Proved for all inputs in
/// `D:/Lean/proofs/Proofs/InuPillarRow.lean` (`absent_record_is_never_live`,
/// `live_iff_elevated`, `row_never_overclaims`).
static INU_DATA_DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Publish the app-private data dir for the argument-free row builders. Idempotent; the first write
/// wins (`OnceLock`), so a re-launch cannot repoint the durable tier mid-session.
pub(crate) fn publish_inu_data_dir(dir: &str) {
    if !dir.is_empty() {
        let _ = INU_DATA_DIR.set(dir.to_string());
    }
}

/// The WIRE CAKE INU pillar row's HONEST posture, read off the durable record.
///
/// Returns `(status_text, live)`. `live` is true **only** for a genuinely held privileged session
/// (`InuElevationStatus::Elevated`) backed by a record that actually exists — never for the seeded
/// spike, never for an absent record, never for a mid-flight or failed elevation.
pub(crate) fn inu_row_posture() -> (String, bool) {
    use torta_core::inu::InuElevationStatus;
    let Some(dir) = INU_DATA_DIR.get() else {
        // No dir published yet (pre-launch push) — the honest OFF, identical to the old literal.
        return ("OFF — ADB elevation idle".to_string(), false);
    };
    let store = torta_core::inu::object::InuStore::new(dir.clone());
    // The SAME liveness instrument the dashboard rail uses (lib.rs:6559): a record that has genuinely
    // been written. `rehydrate_exists().is_none()` ⇒ never written ⇒ the spike would be rendering, and
    // a spike must never light a pillar crown.
    if store.rehydrate_exists().is_none() {
        return ("OFF — ADB elevation idle".to_string(), false);
    }
    let snap = store.snapshot();
    let held = snap.powers.iter().filter(|p| p.last_result).count();
    let total = snap.powers.len();
    match snap.elevation_status {
        InuElevationStatus::Elevated => (
            if total > 0 {
                format!("LIVE — elevated · {held}/{total} powers held")
            } else {
                "LIVE — privileged session held".to_string()
            },
            true,
        ),
        // In flight is NOT armed: the crown stays dark until the session is actually held.
        InuElevationStatus::Discovering => ("ARMING — locating the channel".to_string(), false),
        InuElevationStatus::Pairing => ("ARMING — SPAKE2 pairing".to_string(), false),
        InuElevationStatus::Connecting => ("ARMING — opening the shell".to_string(), false),
        InuElevationStatus::Failed => (
            "FAILED — re-run pairing (the reason is not retained)".to_string(),
            false,
        ),
        InuElevationStatus::Idle => (
            if snap.paired {
                format!("PAIRED — idle · {total} power(s) configured")
            } else {
                "OFF — ADB elevation idle".to_string()
            },
            false,
        ),
    }
}

#[cfg(target_os = "android")]
mod engine_bridge {
    use jni::objects::{JClass, JObject, JValue};
    use jni::JavaVM;

    /// The dotted binary name `ClassLoader.loadClass` expects (NOT the JNI slash form — that is only
    /// for `FindClass`, which we deliberately avoid here).
    const BRIDGE_CLASS: &str = "pillar.kuma_saimono.libumdnscrypt.slint.TortaSlintBridge";
    /// The 2-DRIVE-PILLARS twin bridge class — the per-pillar action statics (rotation & co). Resolved
    /// through the SAME Activity-classloader idiom, JNI-called by the pillar-dashboard callbacks.
    const PILLAR_CLASS: &str = "pillar.kuma_saimono.libumdnscrypt.slint.TortaPillarBridge";

    /// Attach the current (rail) thread + resolve an app-loaded class by its dotted binary name through the
    /// Activity's classloader, then run `f` with the env + the resolved class. `None` on ANY failure
    /// (fail-open — the caller keeps rendering).
    fn with_class<T>(
        class_name: &str,
        f: impl FnOnce(&mut jni::JNIEnv, &JClass) -> jni::errors::Result<T>,
    ) -> Option<T> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }.ok()?;
        let mut env = vm.attach_current_thread().ok()?;
        // The Activity jobject android-activity published (a global ref — valid off the main thread).
        let activity = unsafe { JObject::from_raw(ctx.context().cast()) };
        let loader = env
            .call_method(
                &activity,
                "getClassLoader",
                "()Ljava/lang/ClassLoader;",
                &[],
            )
            .ok()?
            .l()
            .ok()?;
        let name = env.new_string(class_name).ok()?;
        let class_obj = env
            .call_method(
                &loader,
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::Object(&name)],
            )
            .ok()?
            .l()
            .ok()?;
        // The returned Object IS a java.lang.Class — reinterpret as JClass (the checked cast the
        // static-method call below needs). Certain: `loadClass` returns a Class or throws (→ None).
        let class = unsafe { JClass::from_raw(class_obj.into_raw()) };
        f(&mut env, &class).ok()
    }

    /// The `TortaSlintBridge` (engine master-switch) specialization of [`with_class`].
    fn with_bridge_class<T>(
        f: impl FnOnce(&mut jni::JNIEnv, &JClass) -> jni::errors::Result<T>,
    ) -> Option<T> {
        with_class(BRIDGE_CLASS, f)
    }

    /// Drive DNSCrypt on/off — JNI-calls `TortaSlintBridge.setDnsCryptEnabled(Z)`.
    pub(crate) fn set_dnscrypt_enabled(enable: bool) {
        let _ = with_bridge_class(|env, class| {
            env.call_static_method(
                class,
                "setDnsCryptEnabled",
                "(Z)V",
                &[JValue::Bool(u8::from(enable))],
            )
            .map(|_| ())
        });
    }

    /// Read the live DNSCrypt state code — JNI-calls `TortaSlintBridge.dnsCryptStateCode()I`.
    /// 0 stopped · 1 starting · 2 running · 3 stopping · 5 fault. `None` on a JNI failure.
    pub(crate) fn dnscrypt_state_code() -> Option<i32> {
        with_bridge_class(|env, class| {
            env.call_static_method(class, "dnsCryptStateCode", "()I", &[])?
                .i()
        })
    }

    /// Read whether the DNSCrypt VPN tunnel is actually up — JNI-calls
    /// `TortaSlintBridge.engineTunnelUp()Z`. SLINT substitution · 4-FIX round 4: Tortä's Rust
    /// resolver rides IN the DNSCrypt `ServiceVPN` — there is NO separate dnscrypt-proxy process
    /// for the legacy `ModulesStateLoop` to watch, so `dnsCryptStateCode` stays STOPPED even while
    /// the tunnel shields DNS (witnessed on-device: `VPN CONNECTED` on `tun0` + the resolver ledger
    /// filling to queries=151 while the crown still read STOPPED). This reads the app's authoritative
    /// `VPN_SERVICE_ENABLED` flag (set true when the tunnel lifts, cleared on teardown) — the truthful
    /// "the shield is engaged" signal. `None` on a JNI failure → the caller keeps the last honest value.
    pub(crate) fn tunnel_up() -> Option<bool> {
        with_bridge_class(|env, class| {
            env.call_static_method(class, "engineTunnelUp", "()Z", &[])?
                .z()
        })
    }

    /// BUGS2 #64 · NOTIFY-BAR TRUTH FEED — read the device's honest interface speeds — JNI-calls
    /// `TortaSlintBridge.trafficSnapshot()[J` → `[dlBps, ulBps]` (Kotlin-side `TrafficStats`
    /// byte-counter deltas; `-1` = no honest number yet: first-call baseline / counter reset /
    /// UNSUPPORTED). The Kotlin side also throttled-pushes the SAME speeds onto the REAL Android
    /// foreground notification, so the shade and the in-app bar can never disagree. `None` on a
    /// JNI failure → the caller keeps the last honest value (the never-fabricate law the whole
    /// bridge shares).
    pub(crate) fn traffic_snapshot() -> Option<(i64, i64)> {
        with_bridge_class(|env, class| {
            let arr = env
                .call_static_method(class, "trafficSnapshot", "()[J", &[])?
                .l()?;
            let arr = jni::objects::JLongArray::from(arr);
            let mut buf = [0i64; 2];
            env.get_long_array_region(&arr, 0, &mut buf)?;
            Ok((buf[0], buf[1]))
        })
    }

    /// #59 D2 · THE DONATE TRUTH — direct-link route: JNI-calls
    /// `TortaSlintBridge.openDonate(Ljava/lang/String;)V`, which fires a REAL `ACTION_VIEW`
    /// intent so the Ko-Fi link opens in the user's DEFAULT browser. The `url` handed in is
    /// ALWAYS `torta_core::donate::donate_url()` (the four-sealed-clone majority vote — engine
    /// truth; the .slint surface string can never divert it). Fail-open like every bridge call:
    /// a JNI hiccup returns `None` here / logs Kotlin-side — never a panic, the shell keeps
    /// rendering.
    ///
    /// #60C: the donate TAP routes IN-APP through the text-mode lane and stays that way — the user
    /// directive forbids an AUTOMATIC external intent, and nothing here changes that.
    ///
    /// #60C-b WIRED: this is now reachable, from the ⧉ control beside the DONATE row
    /// (`carbon-donate-external()`). It used to carry `#[allow(dead_code)]` and describe itself as
    /// an escape hatch — but nothing could reach it, and an escape hatch nobody can open is not a
    /// hatch. The distinction that keeps the directive intact: leaving the app is the USER's
    /// explicit act here, never the app deciding to leave on its own. The text lane renders TEXT,
    /// and a Ko-Fi payment page cannot be completed in text, so the way out has to exist.
    pub(crate) fn open_donate_intent(url: &str) {
        let _ = with_bridge_class(|env, class| {
            let jurl = env.new_string(url)?;
            env.call_static_method(
                class,
                "openDonate",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&jurl)],
            )
            .map(|_| ())
        });
    }

    /// #60G THE ROLE LANE — read whether Tortä ACTUALLY holds the system
    /// default-browser role — JNI-calls `TortaSlintBridge.browserRoleHeld()Z`
    /// (a REAL `RoleManager.isRoleHeld(ROLE_BROWSER)` read, never a cached
    /// claim). `None` on a JNI failure → the caller keeps the last honest value.
    pub(crate) fn browser_role_held() -> Option<bool> {
        with_bridge_class(|env, class| {
            env.call_static_method(class, "browserRoleHeld", "()Z", &[])?
                .z()
        })
    }

    /// #60G THE ROLE LANE — fire the system default-browser request — JNI-calls
    /// `TortaSlintBridge.requestBrowserRole()I`. Returns OUR stable status code
    /// (1 SENT · 2 already-held · 3 role unavailable · 4 surface-gone · 5 error);
    /// `None` on a JNI failure → the caller treats it as error (5). The dialog is
    /// hosted by the live `TortaSlintActivity` (a role request needs an Activity);
    /// truth lands via [browser_role_held], never via the request's own claim.
    pub(crate) fn request_browser_role() -> Option<i32> {
        with_bridge_class(|env, class| {
            env.call_static_method(class, "requestBrowserRole", "()I", &[])?
                .i()
        })
    }

    // ---- #60C TEXT-MODE LANE — the carbon fetch bay (rust-pull, the house pattern) ----

    /// Fire a page fetch — JNI-calls `TortaSlintBridge.carbonFetch(Ljava/lang/String;)V`.
    /// The result parks Kotlin-side; [carbon_page_seq] advances when it lands.
    pub(crate) fn carbon_fetch(url: &str) {
        let _ = with_bridge_class(|env, class| {
            let jurl = env.new_string(url)?;
            env.call_static_method(
                class,
                "carbonFetch",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&jurl)],
            )
            .map(|_| ())
        });
    }

    /// The fetch-bay sequence counter — bumps once per landed fetch (0 = nothing
    /// ever landed). `None` on a JNI failure → the caller keeps the last honest seq.
    pub(crate) fn carbon_page_seq() -> Option<i64> {
        with_bridge_class(|env, class| {
            env.call_static_method(class, "carbonPageSeq", "()J", &[])?.j()
        })
    }

    /// The landed HTTP status (−1 = transport failure — rendered AS a failure).
    pub(crate) fn carbon_page_status() -> Option<i32> {
        with_bridge_class(|env, class| {
            env.call_static_method(class, "carbonPageStatus", "()I", &[])?
                .i()
        })
    }

    /// The landed page URL (what the fetch was actually for).
    pub(crate) fn carbon_page_url() -> Option<String> {
        with_bridge_class(|env, class| {
            let o = env
                .call_static_method(class, "carbonPageUrl", "()Ljava/lang/String;", &[])?
                .l()?;
            let jstr = jni::objects::JString::from(o);
            let s = env.get_string(&jstr)?.to_string_lossy().into_owned();
            Ok(s)
        })
    }

    /// The landed page body (capped 512 KiB Kotlin-side — a terminal page, not a heap flood).
    pub(crate) fn carbon_page_body() -> Option<String> {
        with_bridge_class(|env, class| {
            let o = env
                .call_static_method(class, "carbonPageBody", "()Ljava/lang/String;", &[])?
                .l()?;
            let jstr = jni::objects::JString::from(o);
            let s = env.get_string(&jstr)?.to_string_lossy().into_owned();
            Ok(s)
        })
    }

    // ---- 2-DRIVE-PILLARS: the per-pillar action statics on `TortaPillarBridge` (the rotation flagship) ----

    /// Fire ONE resolver rotation — JNI-calls `TortaPillarBridge.rotateResolversNow()I`. Returns OUR stable
    /// status code (1 SENT · 2 engine-off · 3 rotation-off · 5 error); `None` on a JNI failure → the caller
    /// treats it as error (5). This is the SLINT "Rotate Now" → real RotationManager.rotateNow() seam.
    pub(crate) fn rotate_resolvers_now() -> Option<i32> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "rotateResolversNow", "()I", &[])?
                .i()
        })
    }

    /// Write RESOLVER_ROTATION_ENABLED — JNI-calls `TortaPillarBridge.setRotationEnabled(Z)V`.
    pub(crate) fn set_rotation_enabled(enable: bool) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "setRotationEnabled",
                "(Z)V",
                &[JValue::Bool(u8::from(enable))],
            )
            .map(|_| ())
        });
    }

    /// Read RESOLVER_ROTATION_ENABLED — JNI-calls `TortaPillarBridge.rotationEnabled()Z`. `None` on failure.
    pub(crate) fn rotation_enabled() -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "rotationEnabled", "()Z", &[])?
                .z()
        })
    }

    /// Read RESOLVER_NATIVE_ENABLED — JNI-calls `TortaPillarBridge.solverEnabled()Z`. `None` on failure.
    pub(crate) fn solver_enabled() -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "solverEnabled", "()Z", &[])?
                .z()
        })
    }

    /// Read WARDEN_NATIVE_ENABLED — JNI-calls `TortaPillarBridge.wardenArmedPreference()Z`. `None` on failure.
    pub(crate) fn warden_armed_preference() -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "wardenArmedPreference", "()Z", &[])?
                .z()
        })
    }

    /// Feed the GENERAL section pillar toggle states from the host preferences (the Slint
    /// `general_section.slint` in-out properties rotation-on / solver-on / warden-on). Reads the live
    /// preference values through the JNI bridge so the shell shows HOST truth, not the spike-local
    /// defaults. Called once at shell construction and whenever the preferences may have changed
    /// (the FELT-TRUTH law: preview values never presented as live). `None` on any bridge failure leaves
    /// the shell at its seed defaults.
    pub(crate) fn feed_general_section_prefs(shell: &crate::TortaShell) {
        if let Some(rotation) = crate::engine_bridge::rotation_enabled() {
            shell.set_rotation_on(rotation);
        }
        if let Some(solver) = crate::engine_bridge::solver_enabled() {
            shell.set_solver_on(solver);
        }
        if let Some(warden) = crate::engine_bridge::warden_armed_preference() {
            shell.set_warden_on(warden);
        }
        // Mark the shell as having received live host preferences.
        //
        // FIXED — this used to set ONLY `home_host_live`, while the comment claimed it "hides the
        // PREVIEW banner". It could not. The GENERAL pane's banner is gated on its OWN flag,
        // `general_host_live` (`general_section.slint:396` `host-live`, forwarded at
        // `home_shell.slint:734` as `general-host-live`), and NOTHING in the crate ever called
        // `set_general_host_live`. The two names are one word apart and were never connected.
        //
        // The consequence was the exact INVERSE of a silent-zero panel, and it is worth naming
        // because it is easy to dismiss as cosmetic. The rows above are pushed from the REAL
        // SharedPreferences — MEASURED on the AVD, the toggles agreed with the live engine
        // (rotation ON, solver ON, Warden OFF, matching HOME's own pillar rows). So the pane was
        // showing CORRECT data underneath a banner that told the user "these rows show defaults,
        // not your live preferences". A false reassurance hides a problem; a false WARNING is
        // arguably worse here, because the honest reaction to it is to distrust a correct reading
        // and re-set a preference that was already applied.
        //
        // Both flags are set together now, from the same evidence: all three preference reads
        // returned `Some`, i.e. the JNI bridge genuinely answered.
        if crate::engine_bridge::rotation_enabled().is_some()
            && crate::engine_bridge::solver_enabled().is_some()
            && crate::engine_bridge::warden_armed_preference().is_some()
        {
            shell.set_home_host_live(true);
            shell.set_general_host_live(true);
        }
    }

    /// Write RESOLVER_ROTATION_CADENCE_MINUTES — JNI-calls `TortaPillarBridge.setRotationCadence(I)V`.
    pub(crate) fn set_rotation_cadence(minutes: i32) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "setRotationCadence", "(I)V", &[JValue::Int(minutes)])
                .map(|_| ())
        });
    }

    /// #22 s5A — read the SERVERS-PER-ROTATION count (`TortaPillarBridge.rotationMaxServers()I`,
    /// the pref `RotationManager.readMaxServers` consumes at every pick). `None` on a JNI failure.
    pub(crate) fn rotation_max_servers() -> Option<i32> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "rotationMaxServers", "()I", &[])?
                .i()
        })
    }

    /// #22 s5A — write the SERVERS-PER-ROTATION count (`TortaPillarBridge.setRotationMaxServers(I)V`;
    /// the Kotlin side clamps floor-only ≥1 — NO upper limit (Socio no-limits law); the host owns it, never this .so).
    pub(crate) fn set_rotation_max_servers(count: i32) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "setRotationMaxServers",
                "(I)V",
                &[JValue::Int(count)],
            )
            .map(|_| ())
        });
    }

    /// #22 s5A — read the RELAYS-PER-RESOLVER count (`TortaPillarBridge.rotationMaxRelays()I`;
    /// 0 is the legal "direct, no relays" posture). `None` on a JNI failure.
    pub(crate) fn rotation_max_relays() -> Option<i32> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "rotationMaxRelays", "()I", &[])?
                .i()
        })
    }

    /// #22 s5A — write the RELAYS-PER-RESOLVER count (`TortaPillarBridge.setRotationMaxRelays(I)V`;
    /// Kotlin clamps floor-only ≥0 — NO upper limit, the Socio 2026-07-19 no-limits law).
    pub(crate) fn set_rotation_max_relays(count: i32) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "setRotationMaxRelays",
                "(I)V",
                &[JValue::Int(count)],
            )
            .map(|_| ())
        });
    }

    /// #22 s5A-ext — read the tunnel-only KILL SWITCH pref
    /// (`TortaPillarBridge.tunnelOnlyKillSwitch()Z`, the app-wide swKillSwitch). None ⇒ JNI fault.
    pub(crate) fn tunnel_only_kill_switch() -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "tunnelOnlyKillSwitch", "()Z", &[])
                .and_then(|v| v.z())
        })
    }

    /// #22 s5A-ext — write the tunnel-only KILL SWITCH pref
    /// (`TortaPillarBridge.setTunnelOnlyKillSwitch(Z)V`; Socio: "allow Connection only inside The Tunnel").
    pub(crate) fn set_tunnel_only_kill_switch(on: bool) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "setTunnelOnlyKillSwitch",
                "(Z)V",
                &[JValue::Bool(u8::from(on))],
            )
            .map(|_| ())
        });
    }

    // ---- #49 THE BEAST SETTINGS: the Yeah TCP/UDP + Soft-cake/Mochi-Dango tune write+read seam ----

    /// Read the durable STAGED Beast config — JNI-calls `TortaPillarBridge.stagedBeastConfig()` (the
    /// BEAST_* prefs, the source of truth for what the pane shows as the user's picked-but-maybe-not-yet-
    /// applied selection). Flat pipe record `yeah=<i>|cake=<i>|preset=<i>|cycle=<i>|maxwin=<i>|free=<i>|
    /// compete=<i>` (milli units for the two thresholds); empty/`None` before the user ever staged a
    /// change (the feed then SEEDS the pane off the live engine snapshot so cold reads agree, dirty=false).
    pub(crate) fn staged_beast_config() -> Option<String> {
        read_pillar_string("stagedBeastConfig").filter(|s| !s.is_empty())
    }

    /// Persist the STAGED Beast config (durability — survives engine/app restart the #51 way) WITHOUT
    /// pushing to the live engine — JNI-calls `TortaPillarBridge.stageBeastConfig(IIIIIII)V`. Called on
    /// every pick/step so the pane's selection is durable; the live engine is only touched on Apply
    /// (`apply_beast_config`). thresholds are milli units.
    pub(crate) fn stage_beast_config(
        yeah: i32,
        cake: i32,
        preset: i32,
        cycle_ms: i32,
        max_window: i32,
        free_thresh_milli: i32,
        compete_thresh_milli: i32,
    ) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "stageBeastConfig",
                "(IIIIIII)V",
                &[
                    JValue::Int(yeah),
                    JValue::Int(cake),
                    JValue::Int(preset),
                    JValue::Int(cycle_ms),
                    JValue::Int(max_window),
                    JValue::Int(free_thresh_milli),
                    JValue::Int(compete_thresh_milli),
                ],
            )
            .map(|_| ())
        });
    }

    /// COMMIT the staged Beast config onto the LIVE overhauled engine (the Yeah TCP/UDP brain + the
    /// Soft-cake queue re-tune) AND re-persist it as the applied snapshot the restore-on-configure
    /// re-pushes — JNI-calls `TortaPillarBridge.applyBeastConfig(IIIIII)V` (Kotlin drives the three
    /// `uniffi.torta_core.beastSet*` edges). cycle-ms is carried for persistence though the overhauled
    /// scheduler has no live interval setter yet (staged-honest). thresholds are milli units.
    pub(crate) fn apply_beast_config(
        yeah: i32,
        cake: i32,
        cycle_ms: i32,
        max_window: i32,
        free_thresh_milli: i32,
        compete_thresh_milli: i32,
    ) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "applyBeastConfig",
                "(IIIIII)V",
                &[
                    JValue::Int(yeah),
                    JValue::Int(cake),
                    JValue::Int(cycle_ms),
                    JValue::Int(max_window),
                    JValue::Int(free_thresh_milli),
                    JValue::Int(compete_thresh_milli),
                ],
            )
            .map(|_| ())
        });
    }

    // ---- 2-FEED-Inu (SETTINGS · #50): the Wire Cake Inu elevation WRITE seams. Unlike Beast (torta_core
    // staged), the grant flow is KOTLIN-owned (the ElevationManager / per-power GrantEngine /
    // BootReapplyPolicy) — each intent JNI-calls its `TortaPillarBridge` static, which routes to the real
    // destination + persists the durable INU_* pref (the #51 durability law). Fail-open throughout: a
    // bridge-silent host-preview is a no-op, never a panic. ----

    /// Read the durable STAGED Inu settings prefs — JNI-calls `TortaPillarBridge.stagedInuConfig()` (the
    /// Kotlin-owned durability triple the pane shows: the boot-reapply / always-on / provider-pref that live
    /// OUTSIDE the typed InuState). Flat pipe record `bootreapply=<0/1>|alwayson=<0/1>|providerpref=<i>`;
    /// empty/`None` before Kotlin ever persisted one (the feed then holds the cold defaults).
    pub(crate) fn staged_inu_config() -> Option<String> {
        read_pillar_string("stagedInuConfig").filter(|s| !s.is_empty())
    }

    /// Read the GENERAL boot-autostart pair — `TortaPillarBridge.bootAutostartConfig()` (the SAME two
    /// prefs `BootCompleteManager` gates on at BOOT_COMPLETED: `swAutostartDNS` + `AUTO_START_DELAY`).
    /// Pipe record `on=<0/1>|delay=<secs>`; `None` on a JNI hiccup (the burger keeps its cold defaults).
    pub(crate) fn boot_autostart_config() -> Option<String> {
        read_pillar_string("bootAutostartConfig").filter(|s| !s.is_empty())
    }

    /// PERSIST the keep-on-boot gate — `TortaPillarBridge.setBootAutostart(Z)V` (`swAutostartDNS`, the
    /// exact key the boot receiver reads — the Socio "VPN dead after reboot" seam closer).
    pub(crate) fn set_boot_autostart(on: bool) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "setBootAutostart", "(Z)V", &[JValue::Bool(u8::from(on))])
                .map(|_| ())
        });
    }

    /// PERSIST the boot delay seconds — `TortaPillarBridge.setBootAutostartDelay(I)V`
    /// (`AUTO_START_DELAY`, stored Kotlin-side as the seconds STRING `parseAutostartDelayMs` expects).
    pub(crate) fn set_boot_autostart_delay(secs: i32) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "setBootAutostartDelay",
                "(I)V",
                &[JValue::Int(secs)],
            )
            .map(|_| ())
        });
    }

    /// Run the ADB pair + elevate flow — `TortaPillarBridge.inuPairNow()V` (Kotlin ElevationManager).
    pub(crate) fn inu_pair_now() {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "inuPairNow", "()V", &[])
                .map(|_| ())
        });
    }

    /// Clear the persisted pair (key/cert) + drop elevation — `TortaPillarBridge.inuUnpair()V`.
    pub(crate) fn inu_unpair() {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "inuUnpair", "()V", &[])
                .map(|_| ())
        });
    }

    /// Set/revert one power's protect intent — `TortaPillarBridge.inuPowerToggled(Ljava/lang/String;Z)V`
    /// (Kotlin GrantEngine PowerState.desired + persist to the InuState grant map).
    pub(crate) fn inu_power_toggled(id: &str, desired: bool) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            let jid = env.new_string(id)?;
            env.call_static_method(
                class,
                "inuPowerToggled",
                "(Ljava/lang/String;Z)V",
                &[JValue::Object(&jid), JValue::Bool(u8::from(desired))],
            )
            .map(|_| ())
        });
    }

    /// Arm/disarm the BootComplete re-establish branch — `TortaPillarBridge.inuBootReapply(Z)V` (persist the
    /// durable pref + arm the live BootReapplyPolicy — the Genesis #1 gap closer).
    pub(crate) fn inu_boot_reapply(on: bool) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "inuBootReapply", "(Z)V", &[JValue::Bool(u8::from(on))])
                .map(|_| ())
        });
    }

    /// Toggle the always-on foreground pairing notification — `TortaPillarBridge.inuAlwaysOn(Z)V`.
    pub(crate) fn inu_always_on(on: bool) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "inuAlwaysOn", "(Z)V", &[JValue::Bool(u8::from(on))])
                .map(|_| ())
        });
    }

    /// Set the elevation-path preference (0 Auto / 1 Shizuku / 2 Self-ADB) —
    /// `TortaPillarBridge.inuProviderPref(I)V`.
    pub(crate) fn inu_provider_pref(pref: i32) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "inuProviderPref", "(I)V", &[JValue::Int(pref)])
                .map(|_| ())
        });
    }

    /// Reveal/hide the raw Expert ADB knobs — `TortaPillarBridge.inuExpertToggled(Z)V` (persist
    /// WIRELESS_DEBUG_EXPERT + the InuState `expert_enabled` flag through the Kotlin store).
    pub(crate) fn inu_expert_toggled(on: bool) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "inuExpertToggled", "(Z)V", &[JValue::Bool(u8::from(on))])
                .map(|_| ())
        });
    }

    /// Run a raw manual ADB pair (Expert) — `TortaPillarBridge.inuManualPair(Ljava/lang/String;
    /// Ljava/lang/String;Ljava/lang/String;)V` (host, port, 6-digit code; Kotlin parses the port).
    pub(crate) fn inu_manual_pair(host: &str, port: &str, code: &str) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            let jhost = env.new_string(host)?;
            let jport = env.new_string(port)?;
            let jcode = env.new_string(code)?;
            env.call_static_method(
                class,
                "inuManualPair",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                &[
                    JValue::Object(&jhost),
                    JValue::Object(&jport),
                    JValue::Object(&jcode),
                ],
            )
            .map(|_| ())
        });
    }

    /// Read RESOLVER_ROTATION_CADENCE_MINUTES — JNI-calls `TortaPillarBridge.rotationCadence()I`.
    pub(crate) fn rotation_cadence() -> Option<i32> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "rotationCadence", "()I", &[])?
                .i()
        })
    }

    // ---- 2-FEED-MaskSolver (SETTINGS): the MaskSolver ||| SETTINGS WRITE drive. The in-shell
    // MaskSolverSettingsPane's 15 controls ride these to the ARMED engine (libtorta_core.so — the SAME
    // seam the live-stat READS cross, NOT this .so's cold copy). Each is a `TortaPillarBridge` @JvmStatic
    // that forwards to the matching `TortaCore.resolverSet*` UniFFI export (a live process-global the armed
    // resolver consults per query). The 7 booleans arm instantly on tap; the 5 cache/deadline steppers
    // commit on `reapply-config()` (the pane's staged-config law). Fail-open (no-op on any JNI failure —
    // a host/preview build has no bridge ⇒ inert; the engine keeps its last honest value). ----

    /// Helper — a MaskSolver Expert BOOLEAN toggle: JNI-call `TortaPillarBridge.<method>(Z)V`.
    fn call_resolver_bool(method: &str, on: bool) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, method, "(Z)V", &[JValue::Bool(u8::from(on))])
                .map(|_| ())
        });
    }
    /// Helper — a MaskSolver cache/deadline STEPPER: JNI-call `TortaPillarBridge.<method>(I)V`.
    fn call_resolver_int(method: &str, value: i32) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, method, "(I)V", &[JValue::Int(value)])
                .map(|_| ())
        });
    }

    /// P12 R6 SOLVE ladder — arm the verdict-gated resilient-resolution ladder (resolverSetSolveLadder).
    pub(crate) fn set_resolver_solve_ladder(on: bool) {
        call_resolver_bool("setResolverSolveLadder", on);
    }
    /// P12 R6 `--all-servers` — race every upstream concurrently vs the strict-order ladder.
    pub(crate) fn set_resolver_all_servers(on: bool) {
        call_resolver_bool("setResolverAllServers", on);
    }
    /// P12 `--stop-dns-rebind` — enforce (drop) public names resolving to a private IP.
    pub(crate) fn set_resolver_rebind_enforce(on: bool) {
        call_resolver_bool("setResolverRebindEnforce", on);
    }
    /// P12 R5 `--bogus-priv` — NXDOMAIN reverse (PTR) lookups of RFC1918/ULA/link-local IPs locally.
    pub(crate) fn set_resolver_bogus_priv(on: bool) {
        call_resolver_bool("setResolverBogusPriv", on);
    }
    /// P12 N3 `--proxy-dnssec` — pass the upstream AD bit through on a live forward (awareness).
    pub(crate) fn set_resolver_proxy_dnssec(on: bool) {
        call_resolver_bool("setResolverProxyDnssec", on);
    }
    /// P12 `--never-forward` — keep RFC 6761/8375 special-use + private PTR names LOCAL (never egress).
    pub(crate) fn set_resolver_never_forward(on: bool) {
        call_resolver_bool("setResolverNeverForward", on);
    }
    /// P12 N2 `--cache-rr` — cache SVCB/HTTPS answer records (speeds modern sites).
    pub(crate) fn set_resolver_cache_rr(on: bool) {
        call_resolver_bool("setResolverCacheRr", on);
    }
    /// `--cache-size` — the RAM-hot cache capacity (staged; commits on reapply, live-resizes the held cache).
    pub(crate) fn set_resolver_cache_cap(cap: i32) {
        call_resolver_int("setResolverCacheCap", cap);
    }
    /// The per-query deadline in ms (0 = engine default; staged, commits on reapply — bites the next query).
    pub(crate) fn set_resolver_query_timeout(ms: i32) {
        call_resolver_int("setResolverQueryTimeout", ms);
    }
    /// RFC 8767 serve-stale window in seconds (0 = OFF; staged, commits on reapply — bites the held cache).
    pub(crate) fn set_resolver_serve_stale(secs: i32) {
        call_resolver_int("setResolverServeStale", secs);
    }
    /// Positive-TTL floor `min-cache-ttl` in seconds (0 = no floor; staged, commits on reapply).
    pub(crate) fn set_resolver_ttl_floor(secs: i32) {
        call_resolver_int("setResolverTtlFloor", secs);
    }
    /// Positive-TTL ceiling `max-cache-ttl` in seconds (0 -> the 24h default; staged, commits on reapply).
    pub(crate) fn set_resolver_ttl_ceiling(secs: i32) {
        call_resolver_int("setResolverTtlCeiling", secs);
    }

    /// N7 · Write NETSTACK_FORWARDER_PREF — JNI-calls `TortaPillarBridge.setNetstackForwarder(Z)V`.
    /// The Kotlin side latches the pref once per `TunnelController.start()` (detachFd is a
    /// one-shot), so the flip lands on the NEXT tunnel start — never a mid-flight rebind.
    pub(crate) fn set_netstack_forwarder(enable: bool) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "setNetstackForwarder",
                "(Z)V",
                &[JValue::Bool(u8::from(enable))],
            )
            .map(|_| ())
        });
    }

    /// N7 · Read NETSTACK_FORWARDER_PREF — JNI-calls `TortaPillarBridge.netstackForwarderArmed()Z`.
    /// `None` on failure (host build, bridge unreachable) — callers fall to false, the ship default.
    pub(crate) fn netstack_forwarder_armed() -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "netstackForwarderArmed", "()Z", &[])?
                .z()
        })
    }

    // ---- 2-FEED-Centauri (SETTINGS): the Centauri ||| SETTINGS WRITE drive + the 2 control-plane reads ----
    //
    // The in-shell CentauriSettingsPane's controls ride these to the ARMED engine (libtorta_core.so, a
    // DIFFERENT .so than this one — the same seam the live-stat READS cross). Each is a `TortaPillarBridge`
    // static that read-mutate-writes the LIVE held Centauri Object / the flat resolver cloak fn / the durable
    // SeedPolicy pref (the manager reads it at the next arm). Fail-open (`None`/no-op on any JNI failure — the
    // host keeps the last honest value; a host/preview build has no bridge ⇒ inert).

    // (No `set_centauri_strict`: the CROWN is always-on LeakOnMiss — BlockMissing would freeze the growing
    //  encyclopedia — so the settings pane never surfaces a strict toggle. Removed end-to-end.)

    /// Arm/disarm the DNS-plane cloak — `TortaPillarBridge.setCentauriCloak(Z)V` (the flat
    /// `resolverSetCentauriCloak`, a live process-global atomic the armed resolver consults per-query).
    pub(crate) fn set_centauri_cloak(on: bool) {
        let _ = with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "setCentauriCloak",
                "(Z)V",
                &[JValue::Bool(u8::from(on))],
            )
            .map(|_| ())
        });
    }

    /// Cycle the durable SeedPolicy (CatalogOnly ⇄ WarmUpBatch) —
    /// `TortaPillarBridge.cycleCentauriSeedPolicy()I`. Returns the NEW policy code (0/1); `None` on failure.
    pub(crate) fn cycle_centauri_seed_policy() -> Option<i32> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "cycleCentauriSeedPolicy", "()I", &[])?
                .i()
        })
    }

    /// Run a TIER-B warm-up batch on the held Object — `TortaPillarBridge.centauriWarmUpNow()I`. Returns the
    /// count of assets FILLED (≥0), or `-1` on no-catalog/unreachable. `None` on a JNI failure.
    pub(crate) fn centauri_warm_up_now() -> Option<i32> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "centauriWarmUpNow", "()I", &[])?
                .i()
        })
    }

    // (No `centauri_install_catalog`: the signed catalog AUTO-ARMS on every engine start — install/device-arm
    //  runs unconditionally in CentauriMirrorManager.startMirrorObject — so it is never a user action.)

    /// ★ #65 · Is the device CA trusted by the OS — `TortaPillarBridge.centauriCaTrusted()Z`.
    ///
    /// This is the gate on the whole HTTPS serve leg: untrusted ⇒ every browser rejects our minted leaf
    /// and the asset is fetched from the real CDN instead of served locally. `None` on a JNI failure ⇒ the
    /// caller holds its last honest value rather than claiming trust it cannot see.
    pub(crate) fn centauri_ca_trusted() -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "centauriCaTrusted", "()Z", &[])?
                .z()
        })
    }

    /// ★ #65 · Has a CA been minted yet — `TortaPillarBridge.centauriCaMinted()Z`.
    pub(crate) fn centauri_ca_minted() -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "centauriCaMinted", "()Z", &[])?
                .z()
        })
    }

    /// ★ #65 · Ask the OS to install the CA — `TortaPillarBridge.centauriCaInstall()Z`.
    ///
    /// The OS presents its own confirmation sheet; this cannot grant trust on its own, which is the
    /// property that makes it safe to expose as a one-tap button.
    pub(crate) fn centauri_ca_install() -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "centauriCaInstall", "()Z", &[])?
                .z()
        })
    }

    /// ★ #22 · Hand every TLS-refused host back to Centauri — `TortaPillarBridge.centauriTlsRetrust()I`.
    ///
    /// The refusal ledger is deliberately permanent (a client that rejected our leaf must not be re-cloaked
    /// on the next boot and broken again), which left the user no way OUT of it: the dashboard could report
    /// `N untrusted` forever with a reinstall as the only escape. This is that escape. It must cross to the
    /// SERVICE engine, not the UI's statically-linked copy — the forwarder that records refusals lives
    /// there, so clearing the UI's RAM would move the tile without freeing a single host.
    ///
    /// Returns the number of hosts handed back; `None` on a bridge failure ⇒ the caller keeps its last
    /// honest value rather than showing a fabricated zero.
    pub(crate) fn centauri_tls_retrust() -> Option<i32> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "centauriTlsRetrust", "()I", &[])?
                .i()
        })
    }

    /// Read whether the DNS-plane cloak is armed — `TortaPillarBridge.centauriCloakArmed()Z`. `None` on
    /// failure ⇒ the caller holds its last honest value.
    pub(crate) fn centauri_cloak_armed() -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "centauriCloakArmed", "()Z", &[])?
                .z()
        })
    }

    /// Read the durable SeedPolicy code (0 CatalogOnly · 1 WarmUpBatch) —
    /// `TortaPillarBridge.centauriSeedPolicy()I`. `None` on failure ⇒ the caller holds its last honest value.
    pub(crate) fn centauri_seed_policy() -> Option<i32> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "centauriSeedPolicy", "()I", &[])?
                .i()
        })
    }

    // ---- 2-FEED-Warden (SETTINGS): the Warden ||| SETTINGS control WRITES ----
    //
    // The in-shell WardenSettingsPane's controls ride these to the CANONICAL live WardenObject (via the Kotlin
    // WardenDatapathGate — the SAME instance the datapath consults, in libtorta_core.so). Each is a
    // `TortaPillarBridge` static that read-mutate-writes the held engine. All return `Z` (landed?) — the pane's
    // next 1 s refresh re-reads HOST truth and snaps a failed control back. Fail-open (host/preview has no
    // bridge ⇒ inert `false`).

    /// ARM / DISARM the Warden datapath — `TortaPillarBridge.setWardenArmed(Z)Z`. This is the DASHBOARD
    /// crown control (the one true enforce seam the AVD found dead): the Kotlin side persists
    /// `WARDEN_NATIVE_ENABLED`, pushes it through `VpnUtils.setWardenNativeEnabled` ->
    /// `WardenDatapathGate.setEnforced`, and returns the LIVE `enforced()` bit read back (never a local
    /// echo). The pane re-feeds `warden-armed` from `liveWardenStats.configured` on the next 1 s tick, so a
    /// push that fails to land snaps the pill back. Fail-open (host/preview has no bridge => inert `false`).
    pub(crate) fn set_warden_armed(on: bool) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "setWardenArmed",
                "(Z)Z",
                &[JValue::Bool(u8::from(on))],
            )?
            .z()
        })
    }

    /// Arm/disarm the fail-CLOSED posture bit — `TortaPillarBridge.setWardenFailClosed(Z)Z`.
    pub(crate) fn set_warden_fail_closed(on: bool) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "setWardenFailClosed",
                "(Z)Z",
                &[JValue::Bool(u8::from(on))],
            )?
            .z()
        })
    }

    /// Flip one universal DENY toggle — `TortaPillarBridge.setWardenUniversalToggle(Ljava/lang/String;Z)Z`
    /// (read-mutate-write against the live 9 bits, so a chip tap never clobbers its siblings).
    pub(crate) fn set_warden_universal_toggle(key: &str, on: bool) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            let jkey = env.new_string(key)?;
            env.call_static_method(
                class,
                "setWardenUniversalToggle",
                "(Ljava/lang/String;Z)Z",
                &[JValue::Object(&jkey), JValue::Bool(u8::from(on))],
            )?
            .z()
        })
    }

    /// Cycle one app's firewall MODE — `TortaPillarBridge.cycleWardenAppMode(I)Z` (read-cycle-write; preserves
    /// meteredness + temp-allow).
    pub(crate) fn cycle_warden_app_mode(uid: i32) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "cycleWardenAppMode", "(I)Z", &[JValue::Int(uid)])?
                .z()
        })
    }

    /// Cycle one app's METEREDNESS block — `TortaPillarBridge.cycleWardenAppMetered(I)Z` (preserves mode +
    /// temp-allow).
    pub(crate) fn cycle_warden_app_metered(uid: i32) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "cycleWardenAppMetered", "(I)Z", &[JValue::Int(uid)])?
                .z()
        })
    }

    /// Toggle one app's PAUSE (temp-allow) — `TortaPillarBridge.toggleWardenAppPause(I)Z` (preserves mode +
    /// meteredness).
    pub(crate) fn toggle_warden_app_pause(uid: i32) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "toggleWardenAppPause", "(I)Z", &[JValue::Int(uid)])?
                .z()
        })
    }

    /// Arm one universal DENY DOMAIN rule — `TortaPillarBridge.addWardenDomainRule(Ljava/lang/String;Z)Z`
    /// (`wildcard` = the `*.domain` form; the engine RFC-1123 validates on insert). `Some(true)` iff armed.
    pub(crate) fn add_warden_domain_rule(text: &str, wildcard: bool) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            let jtext = env.new_string(text)?;
            env.call_static_method(
                class,
                "addWardenDomainRule",
                "(Ljava/lang/String;Z)Z",
                &[JValue::Object(&jtext), JValue::Bool(u8::from(wildcard))],
            )?
            .z()
        })
    }

    /// Arm one universal DENY CIDR rule — `TortaPillarBridge.addWardenCidrRule(Ljava/lang/String;)Z` (parses
    /// `a.b.c.d[/prefix]` Kotlin-side; a malformed string arms nothing). `Some(true)` iff armed.
    pub(crate) fn add_warden_cidr_rule(text: &str) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            let jtext = env.new_string(text)?;
            env.call_static_method(
                class,
                "addWardenCidrRule",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&jtext)],
            )?
            .z()
        })
    }

    /// Remove the armed rule at flat list index `idx` (M2) — `TortaPillarBridge.removeWardenRule(I)Z`. The
    /// bridge enumerates the live set (domains then CIDRs, the SAME order [`live_warden_rules`] emits), drops
    /// index `idx`, and re-installs the remainder (install REPLACES). `Some(true)` iff a rule was removed.
    pub(crate) fn remove_warden_rule(idx: i32) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "removeWardenRule", "(I)Z", &[JValue::Int(idx)])?
                .z()
        })
    }

    // ---- W-D (#79): the per-app INSPECTOR seam (block-ladder). The READERS fold the live engine
    // BY-SOURCE-APP / BY-ENDPOINT (connTracker + held matrix), the WRITERS ride the block-granularity
    // ladder (single IP /32 · CIDR family · whole country GEO) + the two per-app net-block axes. Every
    // one crosses to the CANONICAL WardenObject (WardenDatapathGate / connTracker) in libtorta_core.so,
    // never this .so's cold twin. Fail-open (host/preview has no bridge ⇒ inert None). ----

    /// Call a `TortaPillarBridge` static `(I)Ljava/lang/String;` (one int arg) and copy the result into an
    /// owned String — the int-arg sibling of [`read_pillar_string`]. `None` on any JNI failure (fail-open).
    fn read_pillar_string_i(method: &str, arg: i32) -> Option<String> {
        with_class(PILLAR_CLASS, |env, class| {
            let obj = env
                .call_static_method(class, method, "(I)Ljava/lang/String;", &[JValue::Int(arg)])?
                .l()?;
            let jstr = unsafe { jni::objects::JString::from_raw(obj.into_raw()) };
            let s = env.get_string(&jstr)?.to_string_lossy().into_owned();
            Ok(s)
        })
    }

    /// The LIVE per-app browser (W-D), serialized by `TortaPillarBridge.liveWardenAppFlows` — the
    /// `connTracker().appFlowSummary()` fold UNIONED with the held matrix (so each row carries ACTIVITY
    /// and BLOCK POSTURE): line 1 `total=<n>`, then per row TAB-separated `uid\tapp\tflows\tallowed\t
    /// denied\tdistinct_ips\tcountries\tup\tdown\tlast_ts\tblock_wifi\tblock_mobile\tmode_ord`. `None` when
    /// the bridge is unreachable OR no app has activity AND no held row exists — the caller then renders
    /// the honest DORMANT browser.
    pub(crate) fn live_warden_app_flows() -> Option<String> {
        read_pillar_string("liveWardenAppFlows").filter(|s| !s.is_empty())
    }

    /// ONE app's LIVE endpoint list (W-D), serialized by `TortaPillarBridge.liveWardenAppDests(uid)` —
    /// the `connTracker().appDestinations(uid)` fold: line 1 `total=<n>`, then per row TAB-separated
    /// `ip\tcc\tasn\tdomain\tport\tproto\tdenied\tcarried\thits\tup\tdown\tlast_ts` (`cc` ASCII — the flag
    /// derives HERE via `flag_emoji`, the one source, so no supplementary-plane glyph crosses JNI).
    /// `None` when the bridge is unreachable OR the app has no recorded endpoint.
    pub(crate) fn live_warden_app_dests(uid: i32) -> Option<String> {
        read_pillar_string_i("liveWardenAppDests", uid).filter(|s| !s.is_empty())
    }

    /// The LIVE armed country-block set (W-D GEO family, TIER 4), serialized by
    /// `TortaPillarBridge.wardenGeoBlocks` as a comma-joined lowercase `cc` list (`""` = none armed).
    /// `None` on any failure — the caller then keeps its last honest read.
    pub(crate) fn warden_geo_blocks() -> Option<String> {
        read_pillar_string("wardenGeoBlocks")
    }

    /// Arm ONE additive per-app BLOCK rule at a ladder granularity — `TortaPillarBridge.wardenBlockIp(I
    /// Ljava/lang/String;)Z`. `cidr` is `a.b.c.d[/prefix]` (bare = /32, or a `/24`·`/16` family sweep, or
    /// the v6 sibling). ADDITIVE (the engine `add_cidr_rule`, never install-replace). `Some(true)` iff armed.
    pub(crate) fn warden_block_ip(uid: i32, cidr: &str) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            let jcidr = env.new_string(cidr)?;
            env.call_static_method(
                class,
                "wardenBlockIp",
                "(ILjava/lang/String;)Z",
                &[JValue::Int(uid), JValue::Object(&jcidr)],
            )?
            .z()
        })
    }

    /// REPLACE the armed country-block set (W-D GEO family) — `TortaPillarBridge.wardenSetGeoBlocks(
    /// Ljava/lang/String;)I`. `csv` is a comma-joined `cc` list (empty CLEARS every country block).
    /// Returns the NEW armed count (>=0); `None` on any JNI failure.
    pub(crate) fn warden_set_geo_blocks(csv: &str) -> Option<i32> {
        with_class(PILLAR_CLASS, |env, class| {
            let jcsv = env.new_string(csv)?;
            env.call_static_method(
                class,
                "wardenSetGeoBlocks",
                "(Ljava/lang/String;)I",
                &[JValue::Object(&jcsv)],
            )?
            .i()
        })
    }

    /// Flip ONE app's WiFi-BLOCK axis — `TortaPillarBridge.wardenSetAppBlockWifi(IZ)Z` (composes the
    /// meteredness NetClass read-modify-write, preserving mode + the mobile axis + temp-allow).
    pub(crate) fn warden_set_app_block_wifi(uid: i32, on: bool) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "wardenSetAppBlockWifi",
                "(IZ)Z",
                &[JValue::Int(uid), JValue::Bool(u8::from(on))],
            )?
            .z()
        })
    }

    /// Flip ONE app's MOBILE-DATA-BLOCK axis — `TortaPillarBridge.wardenSetAppBlockMobile(IZ)Z` (the
    /// mobile sibling of [`warden_set_app_block_wifi`], preserving mode + the wifi axis + temp-allow).
    pub(crate) fn warden_set_app_block_mobile(uid: i32, on: bool) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(
                class,
                "wardenSetAppBlockMobile",
                "(IZ)Z",
                &[JValue::Int(uid), JValue::Bool(u8::from(on))],
            )?
            .z()
        })
    }

    /// Pin one host's Underground Trust band — `TortaPillarBridge.setUndergroundVerdict(Ljava/lang/String;I)Z`.
    /// `code`: 0 = Neutral (clear), 1 = Trusted (immune), 2 = Distrusted (condemned). The bridge crosses to
    /// the LIVE `libtorta_core.so` licence store (NOT this .so's cold copy) and persists atomically. `Some(true)`
    /// iff the pin landed; `None` on any JNI failure (fail-open — the control row keeps rendering).
    pub(crate) fn set_underground_verdict(host: &str, code: i32) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            let jhost = env.new_string(host)?;
            env.call_static_method(
                class,
                "setUndergroundVerdict",
                "(Ljava/lang/String;I)Z",
                &[JValue::Object(&jhost), JValue::Int(code)],
            )?
            .z()
        })
    }

    // ---- #15 UNDERGROUND H · the pillar-pane bridge quartet (all cross to the LIVE
    //      libtorta_core.so process-globals via TortaPillarBridge; all fail-open) ----

    /// The G-rung VerdictEvent ring — `TortaPillarBridge.liveUndergroundEvents()`:
    /// `seq:host:verdict:delta:signal:ts` rows `;`-joined, oldest first. `None`/"" fail-open.
    pub(crate) fn live_underground_events() -> Option<String> {
        read_pillar_string("liveUndergroundEvents").filter(|s| !s.is_empty())
    }

    /// The operator's scoring.toml text — `TortaPillarBridge.undergroundScoringToml()`.
    /// "" = no file (the compile-time defaults sit). `None` on JNI failure only.
    pub(crate) fn underground_scoring_toml() -> Option<String> {
        read_pillar_string("undergroundScoringToml")
    }

    /// Write the law — `TortaPillarBridge.setUndergroundScoringToml(Ljava/lang/String;)Z`
    /// (atomic tmp+rename Kotlin-side; blank DELETES the file so the defaults return). The Rust
    /// watcher hot-reloads ≤5 s. `Some(true)` iff the write landed.
    pub(crate) fn set_underground_scoring_toml(text: &str) -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            let jtext = env.new_string(text)?;
            env.call_static_method(
                class,
                "setUndergroundScoringToml",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&jtext)],
            )?
            .z()
        })
    }

    /// The amnesty — `TortaPillarBridge.resetUndergroundReputation()Z`: forgets every learned
    /// reputation row + the correction log (RAM + NAND); the licence ledger stands. `Some(true)`
    /// iff anything was forgotten.
    pub(crate) fn reset_underground_reputation() -> Option<bool> {
        with_class(PILLAR_CLASS, |env, class| {
            env.call_static_method(class, "resetUndergroundReputation", "()Z", &[])?
                .z()
        })
    }

    // ---- SLINT substitution · 4-FIX-1: the LIVE-ENGINE bridge readers (the .so-split fix) --------------
    //
    // `feed_home`/`feed_engine`/`pillar_rows` used to read THIS .so's OWN cold `torta_core` copy
    // (`MaskSolver::new()` / `warden_stats()` bound libtorta_ui.so's process-globals — always zero). These
    // JNI-read the RUNNING engine's stats JSON off `TortaPillarBridge`, which calls the SAME
    // `uniffi.torta_core` process-globals `libtorta_core.so` writes. `None`/empty on ANY JNI failure
    // (fail-open — the caller falls to the OFF state). The Java-String read mirrors the proven
    // `JClass::from_raw(obj.into_raw())` idiom already used above (no `FindClass`).

    /// Call a `TortaPillarBridge` static `()Ljava/lang/String;` and copy the result into a Rust `String`.
    /// `None` on any JNI failure (fail-open).
    fn read_pillar_string(method: &str) -> Option<String> {
        with_class(PILLAR_CLASS, |env, class| {
            let obj = env
                .call_static_method(class, method, "()Ljava/lang/String;", &[])?
                .l()?;
            // `call_static_method` returns a `java.lang.String` (or throws → the `?` bails). Reinterpret
            // as JString via the SAME from_raw idiom `with_class` uses for the resolved JClass.
            let jstr = unsafe { jni::objects::JString::from_raw(obj.into_raw()) };
            // Materialize into an owned String in its OWN statement so the JavaStr borrow of `jstr`
            // ends before the block's locals drop (E0597 — the `?`-in-tail-Ok kept it alive too long).
            let s = env.get_string(&jstr)?.to_string_lossy().into_owned();
            Ok(s)
        })
    }

    /// The RUNNING resolver's stats JSON (the ledger + the D10 Beast budget witness). `None` when the
    /// bridge is unreachable or returns empty (⇒ the caller holds the honest OFF state).
    pub(crate) fn live_resolver_stats() -> Option<String> {
        read_pillar_string("liveResolverStats").filter(|s| !s.is_empty())
    }

    /// The RUNNING Warden firewall's stats JSON (configured + the per-tier deny tally). `None` on failure.
    pub(crate) fn live_warden_stats() -> Option<String> {
        read_pillar_string("liveWardenStats").filter(|s| !s.is_empty())
    }

    /// The RUNNING Centauri Mirror status string — the LIVE `libtorta_core.so` content-addressed store
    /// (`"libraries=<N> bytes=<M> full=<bool>"`), NOT this .so's cold spike-local Centauri copy. `None` when
    /// the bridge is unreachable or returns empty (⇒ the caller holds the honest cold/OFF Centauri state).
    /// SLINT substitution · 4-FIX-2 — the Centauri live cross-.so reader the round-2 witness flagged missing.
    pub(crate) fn live_mirror_status() -> Option<String> {
        read_pillar_string("liveMirrorStatus").filter(|s| !s.is_empty())
    }

    /// The RUNNING Centauri Mirror's FULL snapshot as flat-JSON (`"key":<int>` pairs) — the whole
    /// CENTAURI dashboard's live cross-`.so` reader (the successor to [`live_mirror_status`], which
    /// carried only libraries/bytes/full). Read field-by-field with [`json_i32`] (collision-safe:
    /// `"bytes"` never matches inside `"served_bytes"`, which the naive `kv_i64` substring scan can
    /// not guarantee). `None` when the bridge is unreachable OR no Object is armed (base `.so`) ⇒ the
    /// caller holds the honest cold read. The gap the CENTAURI-dashboard cold-spike audit flagged:
    /// every tile except cache-libraries/bytes read this `.so`'s cold spike-local Object.
    pub(crate) fn live_centauri_stats() -> Option<String> {
        read_pillar_string("liveCentauriStats").filter(|s| !s.is_empty())
    }

    /// The RUNNING Centauri recent-serve ring, in the [`live_warden_flows`] docket shape: line 1
    /// `total=<N>`, then newest-first rows of 5 TAB-separated fields
    /// `host\tasset\toutcome\tsub\tbytes` (outcome/sub already the `.slint` ServeRow display tokens).
    /// `None` when the bridge is unreachable OR the ring is empty ⇒ the caller renders the honest
    /// empty constellation, never a fabricated serve.
    pub(crate) fn live_centauri_serves() -> Option<String> {
        read_pillar_string("liveCentauriServes").filter(|s| !s.is_empty())
    }

    /// The LIVE RotationManager's durable rotation cursor, serialized flat by
    /// `TortaPillarBridge.liveRotationState` as `"family=<f>|cadence_secs=<n>|index=<n>|
    /// next_flip_secs=<n>|warm=<bool>|hints=<id:ms;id:ms;…>"`. `None` when the bridge is unreachable OR
    /// the record is cold (never rotated) — the caller then keeps the honest DORMANT wheel, never the
    /// retired mullvad/cloudflare/quad9 spike seed. SLINT substitution · 4-FIX round 5 (Observation E —
    /// the rotation live bridge the witness flagged missing; the OTHER pillars bridged in round 1/3,
    /// rotation was left on the spike seed).
    pub(crate) fn live_rotation_state() -> Option<String> {
        read_pillar_string("liveRotationState").filter(|s| !s.is_empty())
    }

    /// The LIVE netstack forwarder's counters (N6c), serialized flat by
    /// `TortaPillarBridge.liveForwarderStats` as `"armed=<b>|live=<b>|flows_tcp=<n>|…|cwnd_last=<n>"`
    /// (the rotation-cursor pipe shape, read with [`rot_field_str`]/[`rot_field_i64`]/[`rot_field_bool`]).
    /// `None` when the bridge is unreachable OR the tunnel is not running — the caller then holds the
    /// honest DORMANT card (armed=false, every counter zero), never a stale/fabricated flow tally.
    pub(crate) fn live_forwarder_stats() -> Option<String> {
        read_pillar_string("liveForwarderStats").filter(|s| !s.is_empty())
    }

    /// The LIVE Underground Layer licence store (CP-U), serialized flat by
    /// `TortaPillarBridge.liveUndergroundStats` as `"armed=<b>|total=<n>|…|top=<rows>"` (the
    /// rotation-cursor pipe shape). The trailing `top` value carries the worst-offender rows
    /// colon-joined per row (`host:risk:source:hits:points:seq`, the rttHints idiom), rows joined
    /// by `;`. `None` when the bridge is unreachable OR the store is disarmed (engine not booted) —
    /// the caller then holds the honest DORMANT court, never a stale licence tally.
    pub(crate) fn live_underground_stats() -> Option<String> {
        read_pillar_string("liveUndergroundStats").filter(|s| !s.is_empty())
    }

    /// The LIVE Warden flows docket (A5 slice-5), serialized by `TortaPillarBridge.liveWardenFlows`
    /// from the ENGINE .so's `connTracker().snapshot()` (the ring the shell's own rlib twin cannot
    /// see — the two-.so law): line 1 `total=<n>`, then newest-first rows of 7 TAB-separated fields
    /// `cc\tapp\tip\tport\tproto\tverdict\tasn` (`app` = the PackageManager uid label, "" when
    /// unresolved). `None` when the bridge is unreachable OR the ring is empty — the caller then
    /// renders the honest empty docket, never a fabricated flow.
    pub(crate) fn live_warden_flows() -> Option<String> {
        read_pillar_string("liveWardenFlows").filter(|s| !s.is_empty())
    }

    /// ★ #47/#49 N8 — the LIVE netstack forwarder's PER-FLOW docket, serialized by
    /// `TortaPillarBridge.liveForwarderDocket` off the SERVICE .so's `forwarderFlowDocket()`. Same
    /// two-.so law as [`live_warden_flows`]: the shell's own statically-linked `torta_core` owns a
    /// SEPARATE, permanently empty flow registry, so the bridge is the only honest source.
    ///
    /// Line 1 `total=<active_flows>`, then one row per flow, 10 TAB-separated fields
    /// `key\tproto_tcp\ttin\tpaced\tcwnd\tup\tdown\trtt\tage\tstalls`. `None` when the bridge is
    /// unreachable or no tunnel is live — the caller renders the honest empty docket.
    pub(crate) fn live_forwarder_docket() -> Option<String> {
        read_pillar_string("liveForwarderDocket").filter(|s| !s.is_empty())
    }

    /// The LIVE Warden per-app matrix (TIER 3), serialized by `TortaPillarBridge.liveWardenMatrix` off the
    /// canonical `WardenDatapathGate.appRows()` (the SAME held rows the datapath enforces) UNIONED with the
    /// apps the live-flows ring has seen: line 1 `total=<n>`, then per row TAB-separated
    /// `uid\tapp\tmode_ord\tmetered_ord\ttemp_allow_until\tarmed`. `None` when the bridge is unreachable OR no
    /// rows exist — the caller then renders the honest no-rows state (never a fabricated app row).
    pub(crate) fn live_warden_matrix() -> Option<String> {
        read_pillar_string("liveWardenMatrix").filter(|s| !s.is_empty())
    }

    /// The LIVE Warden 9 universal DENY toggles (TIER 2), serialized by `TortaPillarBridge.wardenUniversalToggles`
    /// off the canonical `WardenDatapathGate.universalToggles()` (the ENGINE's own bits the cascade consults): a
    /// flat `new_apps=0|unknown=0|metered=0|lockdown=0|device_lock=0|background=0|udp_ntp=0|http=0|dns_bypass=0`
    /// pipe record. `None` on any failure — the caller then keeps the honest all-off default.
    pub(crate) fn warden_universal_toggles() -> Option<String> {
        read_pillar_string("wardenUniversalToggles").filter(|s| !s.is_empty())
    }

    /// The LIVE Warden armed BLOCK rule LIST (M2), serialized by `TortaPillarBridge.liveWardenRules` off the
    /// canonical enumerators (`WardenObject::domain_rules` + `cidr_rules`): line 1 `total=<n>`, then per row
    /// TAB-separated `kind\ttext\tscope\twildcard\tstatus`, DOMAINS FIRST then CIDRS (so the row index the
    /// pane renders matches [`remove_warden_rule`]). `None` when the bridge is unreachable OR no rule is armed
    /// — the caller then renders the honest "none armed" empty-state.
    pub(crate) fn live_warden_rules() -> Option<String> {
        read_pillar_string("liveWardenRules").filter(|s| !s.is_empty())
    }

    /// #16 THE BEAST — the LIVE process-global congestion engine's [`BeastSnapshot`], serialized flat by
    /// `TortaPillarBridge.liveBeastStats` off the ENGINE `.so`'s `beast_live_snapshot()` (the one Beast
    /// the DNS datapath feeds — NOT this UI `.so`'s throwaway cold copy). Shape:
    /// `"mode=<s>|slow_start=<b>|cwnd=<n>|base_rtt=<f>|udp_rtt=<f>|…|yeah_profile=<0..2>|sched_profile=<0..2>"`
    /// (the rotation-cursor pipe record). `None` when the bridge is unreachable OR the datapath is not live
    /// (Kotlin gates on `isDatapathLive`) — the caller then keeps the honest COLD baseline
    /// (`feed_engine`'s spike-local Beast, `engine-live=false`), never a stale window dressed as live.
    pub(crate) fn live_beast_stats() -> Option<String> {
        read_pillar_string("liveBeastStats").filter(|s| !s.is_empty())
    }

    /// Extract the string value of `key` from a flat `"key=value|key=value…"` record (the rotation-
    /// cursor bridge shape — NOT JSON, so the flat-JSON scanners above do not apply). The value runs to
    /// the next `|` or end-of-string (so the trailing `hints=id:ms;id:ms` blob is captured whole). Empty
    /// string when the key is absent.
    pub(crate) fn rot_field_str(rec: &str, key: &str) -> String {
        let pat = format!("{key}=");
        match rec.find(&pat) {
            Some(i) => {
                let rest = &rec[i + pat.len()..];
                let end = rest.find('|').unwrap_or(rest.len());
                rest[..end].to_string()
            }
            None => String::new(),
        }
    }

    /// The integer value of a flat rotation-record `key` (via [`rot_field_str`]). `None` if absent/unparsable.
    pub(crate) fn rot_field_i64(rec: &str, key: &str) -> Option<i64> {
        rot_field_str(rec, key).trim().parse::<i64>().ok()
    }

    /// The float value of a flat rotation-record `key` (via [`rot_field_str`]) — the RTT/pacing/valve
    /// fields the Beast snapshot carries. `None` if absent/unparsable.
    pub(crate) fn rot_field_f64(rec: &str, key: &str) -> Option<f64> {
        rot_field_str(rec, key).trim().parse::<f64>().ok()
    }

    /// Whether a flat rotation-record `key` is exactly `true`.
    pub(crate) fn rot_field_bool(rec: &str, key: &str) -> bool {
        rot_field_str(rec, key).trim() == "true"
    }

    /// Extract a `key=<int>` value from a flat space-separated `key=value` line (the `mirror_status` shape
    /// `"libraries=3 bytes=4096 full=false"` — NOT JSON, so the flat-JSON scanners above do not apply). `None`
    /// if the key is absent or its value is not an integer.
    pub(crate) fn kv_i64(line: &str, key: &str) -> Option<i64> {
        let pat = format!("{key}=");
        let start = line.find(&pat)? + pat.len();
        let rest = &line[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(rest.len());
        rest.get(..end)?.parse::<i64>().ok()
    }

    /// Extract a flat-JSON integer value for `key` (the resolver/warden stats are a flat object of
    /// `"key":<number>` pairs — no nesting, so a tiny scanner beats pulling in a JSON dep). `None` if the
    /// key is absent or its value is not an integer.
    pub(crate) fn json_i32(json: &str, key: &str) -> Option<i32> {
        let pat = format!("\"{key}\":");
        let start = json.find(&pat)? + pat.len();
        let rest = &json[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(rest.len());
        rest.get(..end)?.parse::<i32>().ok()
    }

    /// Extract a flat-JSON floating value for `key` (e.g. the pacing-qps witness, which serializes as a
    /// float). `None` if the key is absent or its value is unparsable.
    pub(crate) fn json_f32(json: &str, key: &str) -> Option<f32> {
        let pat = format!("\"{key}\":");
        let start = json.find(&pat)? + pat.len();
        let rest = &json[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && !matches!(c, '-' | '.' | 'e' | 'E' | '+'))
            .unwrap_or(rest.len());
        rest.get(..end)?.parse::<f32>().ok()
    }

    /// Whether a flat-JSON boolean `key` is `true`.
    pub(crate) fn json_bool(json: &str, key: &str) -> bool {
        let pat = format!("\"{key}\":");
        match json.find(&pat) {
            Some(i) => json[i + pat.len()..].trim_start().starts_with("true"),
            None => false,
        }
    }

    /// Extract a flat-JSON string value for `key` (`"key":"value"`). The values we read here — transport
    /// id LABELS and a file PATH — carry no escaped quote in practice, so a naive stop-at-first-`"` is
    /// exact; `\\` is un-escaped back to `\` (the ONE escape [`torta_core::json_escape_into`] emits that a
    /// value could actually contain). `None` if the key is absent. Never used for a numeric/`null` field.
    pub(crate) fn json_str(json: &str, key: &str) -> Option<String> {
        let pat = format!("\"{key}\":\"");
        let start = json.find(&pat)? + pat.len();
        let rest = &json[start..];
        let end = rest.find('"')?;
        Some(rest[..end].replace("\\\\", "\\"))
    }

    /// Slice a flat `"key":[ {..},{..} ]` array into its brace-delimited object substrings. The resolver
    /// stats' `upstreams` objects are FLAT (no nested braces), so a single-depth brace walk bounded by the
    /// array's first `]` is exact. Empty when the key is absent or the array is empty — the caller then
    /// leaves the honest cold read. Each returned substring is itself a flat JSON object the scanners above
    /// (`json_str`/`json_f32`/`json_i32`) read field-by-field.
    pub(crate) fn json_object_array(json: &str, key: &str) -> Vec<String> {
        let pat = format!("\"{key}\":[");
        let Some(head) = json.find(&pat) else {
            return Vec::new();
        };
        let body = &json[head + pat.len()..];
        let body = &body[..body.find(']').unwrap_or(body.len())];
        let mut objs = Vec::new();
        let mut depth = 0i32;
        let mut obj_start = None;
        for (i, c) in body.char_indices() {
            match c {
                '{' => {
                    if depth == 0 {
                        obj_start = Some(i);
                    }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        if let Some(s) = obj_start.take() {
                            objs.push(body[s..=i].to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        objs
    }
}

// ===========================================================================================
// #69 SLINT-ON-ANDROID SPIKE (OMEGA Stage-D · D1) — the on-device render rail.
//
// The OFFICIAL slint android bridge: `backend-android-activity-06` (Cargo.toml, android target) pulls
// i-slint-backend-android-activity with the `native-activity` glue (measured from the resolved slint
// 1.17.0 Cargo.toml:64-68), whose `ANativeActivity_onCreate` resolves THIS `android_main` symbol when
// the Kotlin `TortaSlintActivity` (a NativeActivity) loads `libtorta_ui.so`. NativeActivity owns the
// native surface; `slint::android::init` installs the platform + renderer onto it. The SurfaceView-
// EMBEDDED composition (a slint Window inside a Kotlin view tree) needs a custom `slint::platform::
// Platform` and is the Stage-D follow-up — the activity route IS the spike, as the Stage-B judgment
// blessed (find-SLINT.md G1).
//
// D3 (step 8, THE DESIGN FINALE): the on-device ENTRY is now the 4-TAB SLINT HOME
// (home_shell.slint `TortaShell`): ① HOME reads the typed `MaskSolverSnapshot` counters + the
// `CentauriSnapshot` CDN-local counter (real spike-local Records — cold ⇒ honest zeros); ② Tortä
// ENGINE renders the typed `BeastSnapshot` off a REAL cold Beast Object (the D1 Centauri
// precedent); ③ DNS mounts the SAME K5 `DnscryptSection` pane the burger embeds, both fed from ONE
// shared typed `DnscryptProxyConfig` (re-pushed on every window swap); ④ QUERY tails the per-pillar
// `query-*.log` files through `log_tail_recent`/`log_stale_secs` (the exact fns Kotlin reaches as
// `logTailRecent`/`logStaleSecs`).
//
// D2 (step 7): the ||| ADVANCED HAMBURGER (advanced_burger.slint) now rides BEHIND the shell's |||
// door (window-swap on the one event loop; close-advanced returns Home, the D2 quit is retired) —
// the K5 DNSCrypt section, the per-pillar private tabs with honest statuses, and the D1 CENTAURI
// dashboard rail (slice 8, fed from the REAL pillar uniffi::Object over a REAL app-private cache
// dir + the live `centauri_cdn_hosts()` surface — a cold Object ⇒ the honest zero baseline, never
// fabricated serves) riding behind the centauri tab.
// SPIKE HONESTY: this .so statically links its OWN torta_core instance — its state is NOT the engine
// process state held by libtorta_core.so (unifying them = the single-.so follow-up, Stage D proper).
// ===========================================================================================
#[cfg(target_os = "android")]
mod android_spike {
    use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// How many cloaked CDN hosts the watch-list panel shows (the dashboard's preview density).
    const CDN_HOSTS_SHOWN: usize = 8;
    /// How many recent-serve rows the constellation feed pulls from the Object's live ring.
    const RECENT_SERVES_SHOWN: u32 = 8;

    /// Split the pipe-delimited discovered-roster line (`centauri_discovery::discovered_line`, bounded at
    /// the engine side to `DISCOVERED_ROSTER_SHOWN`) into the Slint `[string]` list model the living-roster
    /// panel renders. Empty entries are dropped so an absent/trailing separator never yields a blank row.
    fn split_discovered_line(line: &str) -> slint::ModelRc<slint::SharedString> {
        let rows: Vec<slint::SharedString> = line
            .split('|')
            .filter(|s| !s.is_empty())
            .map(slint::SharedString::from)
            .collect();
        slint::ModelRc::new(slint::VecModel::from(rows))
    }
    /// The refresh-cadence clamp for the ± pills (hours) — a floor below the upstream default keeps
    /// the signed lists fresh without hammering; the ceiling keeps them from going stale for a month.
    const REFRESH_MIN_H: i32 = 24;
    const REFRESH_MAX_H: i32 = 720;
    /// How many classified lines the ④ QUERY feed tails per refresh (bounded — the whole file is
    /// already tail-rewritten at 256 KiB by the log_tier substrate; this is the view's window).
    const QUERY_ROWS_SHOWN: i32 = 40;
    /// 2-FEED-MaskSolver: how many query-masksolver.log resolve rows the in-shell MaskSolver pane's
    /// RECENT RESOLVES feed tails (bounded — the log is already tail-rewritten by the log_tier substrate).
    const MASK_RESOLVES_SHOWN: i32 = 20;
    /// 2-FEED-DNSCRYPT: how many cache/query.log rows the ③ DNS tab's LIVE dashboard preview tails
    /// (bounded — the full 40-row feed lives on ④ QUERY; this is the dashboard's at-a-glance window).
    const DNS_QUERIES_SHOWN: i32 = 12;
    /// How many recent `query-inu.log` events the Inu dashboard's RECENT EVENTS feed tails per refresh.
    const INU_EVENTS_SHOWN: u32 = 8;

    /// Feed the shell's ① HOME tab — the dnsmasq×rethink hybrid, from TYPED torta_core reads:
    /// the `MaskSolverSnapshot` resolver-ledger counters (a COLD handle binding the process-global
    /// atomics — object.rs `MaskSolver::new`, IO-free) + the `CentauriSnapshot` CDN-local counter
    /// off the ONE shared spike-local Centauri Object. Cold instance ⇒ honest zeros, never
    /// fabricated traffic (the D1 law). The ENGINE state lives with the Kotlin module runner this
    /// .so cannot read → `host-live=false` (the pane's PREVIEW banner says so) and the master
    /// switch stays honestly OFF until a real host pushes truth.
    /// SLINT substitution · 4-FIX-1 — overlay the HOME resolver ledger + the ENGINE-tab budget witnesses
    /// with the LIVE running-engine truth read over the JNI bridge (the .so-split fix). `feed_home` /
    /// `feed_engine` seed the honest COLD baseline from THIS .so's own `torta_core`; this OVERLAYS the
    /// real `libtorta_core.so` counters when the resolver is running, and sets the felt-truth flags
    /// (`home-host-live` / `engine-live`) so the "ENGINE OFF" preview banners hide ONLY when genuinely
    /// live. When stopped, both read FALSE — the honest OFF state ("start it on HOME"), never a cold copy
    /// dressed as live. `running_hint` is the crown's DNSCrypt-running read (so the banner never says OFF
    /// while the crown says RUNNING); at startup it is `false` and the resolver's own state decides.
    /// Called at startup + each 500 ms engine poll so the ledger streams while running.
    fn overlay_live_engine(shell: &crate::TortaShell, running_hint: bool) {
        use crate::engine_bridge::{json_bool, json_f32, json_i32};
        let stats = crate::engine_bridge::live_resolver_stats();
        // The resolver is active when its pool is configured OR it has already served ≥1 query.
        let resolver_active = stats
            .as_deref()
            .map(|j| json_bool(j, "configured") || json_i32(j, "queries").unwrap_or(0) > 0)
            .unwrap_or(false);
        let active = running_hint || resolver_active;
        shell.set_home_host_live(active);
        shell.set_engine_live(active);
        if !active {
            return;
        }
        let Some(j) = stats.as_deref() else {
            return; // running per the crown but the stats JSON was unreachable — keep the last honest values
        };
        // The HOME resolver ledger (the 5 tiles) — the LIVE running-engine counts.
        if let Some(v) = json_i32(j, "queries") {
            shell.set_queries(v);
        }
        if let Some(v) = json_i32(j, "answered") {
            shell.set_answered(v);
        }
        if let Some(v) = json_i32(j, "blocked") {
            shell.set_blocked(v);
        }
        if let Some(v) = json_i32(j, "cache_hits") {
            shell.set_cache_hits(v);
        }
        if let Some(v) = json_i32(j, "serve_stale_served") {
            shell.set_stale_served(v);
        }
        // The ENGINE tab's live movement — the D10 Beast budget witness (0 until the running engine pushes it).
        if let Some(v) = json_i32(j, "budget_cwnd_cap") {
            if v > 0 {
                shell.set_engine_cwnd(v);
            }
        }
        if let Some(v) = json_i32(j, "budget_inflight") {
            shell.set_engine_q_packets(v as f32);
        }
        if let Some(v) = json_f32(j, "budget_pacing_qps") {
            shell.set_engine_pacing_rate(v);
        }
        // #16 THE BEAST — overlay the FULL live congestion snapshot off the process-global live Beast
        // (the DNS datapath feeds it), superseding the partial D10 budget witnesses above with the
        // running engine's true window/RTT/mode/profile. A dormant/unreachable bridge ⇒ a no-op that
        // leaves `feed_engine`'s honest COLD baseline standing (never a stale window dressed as live).
        overlay_live_beast(shell);
        // 4-FIX-1b · The HOME "CDN local" tile (D1 Centauri served-locally) — overlay the LIVE armed
        // mirror value, the SAME `live_centauri_stats().served_locally` the D29 dashboard PRIVACY WITNESS
        // shows. `feed_home` seeds only the COLD spike-local snapshot, which reads 0 on-device (the real
        // serves land in the running libtorta_core.so, never this UI .so's Object) — without this overlay
        // the HOME tile stayed a cold 0 while the dashboard read the true served count. `live_centauri_stats`
        // is a distinct bridge read from the resolver `j` above (served-locally is a MIRROR stat, absent
        // from the resolver ledger JSON). Mirror unreachable ⇒ keep the honest last value, never a fake serve.
        if let Some(cj) = crate::engine_bridge::live_centauri_stats() {
            if let Some(v) = json_i32(&cj, "served_locally") {
                shell.set_served_local(v);
            }
            // 2-FEED-Centauri (SETTINGS) · the in-shell CentauriSettingsPane posture + scalar witnesses,
            // fed from the SAME armed `live_centauri_stats()` JSON (one instance, one truth — the pane's
            // decision-point warnings derive from these). No cache_mode/strict read: the CROWN is always-on
            // LeakOnMiss (no toggle). cloak-armed + seed-policy are control-plane reads off the manager.
            if let Some(v) = json_i32(&cj, "catalog_assets") {
                shell.set_cs_catalog_assets(v);
            }
            if let Some(v) = json_i32(&cj, "libraries") {
                shell.set_cs_libraries(v);
            }
            if let Some(v) = json_i32(&cj, "served_locally") {
                shell.set_cs_served_locally(v);
            }
            if let Some(v) = json_i32(&cj, "served_bytes") {
                shell.set_cs_served_bytes(v);
            }
            if let Some(v) = json_i32(&cj, "cdn_fetches") {
                shell.set_cs_cdn_fetches(v);
            }
        }
        if let Some(armed) = crate::engine_bridge::centauri_cloak_armed() {
            shell.set_cs_cloak_armed(armed);
        }
        if let Some(policy) = crate::engine_bridge::centauri_seed_policy() {
            shell.set_cs_seed_policy(policy);
        }
    }

    fn feed_home(shell: &crate::TortaShell, centauri: &torta_core::mirror::object::Centauri) {
        let solver = torta_core::MaskSolver::new();
        let snap = solver.snapshot();
        shell.set_queries(snap.queries as i32);
        shell.set_answered(snap.answered as i32);
        shell.set_blocked(snap.blocked as i32);
        shell.set_cache_hits(snap.cache_hits as i32);
        shell.set_stale_served(snap.serve_stale_served as i32);
        shell.set_served_local(centauri.snapshot().served_locally as i32);
        // The honest COLD baseline — `overlay_live_engine` (called after `feed_engine`, and each 500 ms
        // poll) flips these to the LIVE running-engine truth. Until the resolver is up, the OFF state is
        // the truth: the crown's 500 ms poll writes the real "STOPPED — flip the switch" / "RUNNING" line.
        shell.set_home_host_live(false);
        shell.set_engine_running(false);
        shell.set_engine_state_line(
            "DNSCrypt stopped — flip the switch on HOME to start the resolver; the ledger fills with live counts"
                .into(),
        );
        shell.set_pillar_chips(ModelRc::new(VecModel::from(pillar_rows())));
        // `engine-toggled` stays deliberately UN-wired in the spike .so: the module runner is the
        // Kotlin ModulesStateLoop's authority (D09) and this .so cannot start it. An un-wired
        // slint callback is a silent no-op, and the switch never fakes a flip — `engine-running`
        // only moves when the host pushes it (the felt-truth law).
    }

    /// Feed the shell's ② Tortä-ENGINE tab — the typed `BeastSnapshot` off a REAL but COLD
    /// spike-local Beast Object (the D1 Centauri precedent: real reads of a real Object, the
    /// honest zero baseline, never fabricated flows). Canonical × CoBALT is the shipped default
    /// brain/queue pair; the profile-gating booleans ride the SNAPSHOT's own enums (Chroma F6 —
    /// a Legacy profile's inert 0s render as the muted "—", never as live metrics).
    /// N6c · Feed the ENGINE tab's NETSTACK FORWARDER card from the LIVE `libtorta_core.so`
    /// ForwarderSnapshot over the pillar bridge (`TortaPillarBridge.liveForwarderStats` — the flat
    /// `key=value|…` rotation-cursor shape). A missing/empty record (bridge unreachable, tunnel cold)
    /// clears the card to the honest DORMANT birth state — armed=false + every counter zero — never
    /// a stale or fabricated flow tally (the Chroma F6 honesty law).
    fn feed_from_live_forwarder(shell: &crate::TortaShell) {
        use crate::engine_bridge::{live_forwarder_stats, rot_field_bool, rot_field_i64};
        let rec = live_forwarder_stats().unwrap_or_default();
        let count = |key: &str| rot_field_i64(&rec, key).unwrap_or(0).clamp(0, i32::MAX as i64) as i32;
        let bytes = |key: &str| rot_field_i64(&rec, key).unwrap_or(0).max(0) as f32;
        shell.set_fwd_armed(rot_field_bool(&rec, "armed"));
        shell.set_fwd_live(rot_field_bool(&rec, "live"));
        // N7: the ARM SWITCH shows HOST PREF truth (swNetstackForwarder), read on the same tick —
        // distinct from `armed` above (the RUNNING snapshot), so a queued flip renders honestly.
        shell.set_fwd_pref_armed(
            crate::engine_bridge::netstack_forwarder_armed().unwrap_or(false),
        );
        shell.set_fwd_flows_tcp(count("flows_tcp"));
        shell.set_fwd_flows_udp(count("flows_udp"));
        shell.set_fwd_flows_other(count("flows_other"));
        shell.set_fwd_active_flows(count("active_flows"));
        shell.set_fwd_tin_critical(count("tin_critical"));
        shell.set_fwd_tin_high(count("tin_high"));
        shell.set_fwd_tin_normal(count("tin_normal"));
        shell.set_fwd_dns_answered(count("dns_answered"));
        shell.set_fwd_paced_flows(count("paced_flows"));
        shell.set_fwd_bytes_up(bytes("bytes_up"));
        shell.set_fwd_bytes_down(bytes("bytes_down"));
        shell.set_fwd_rtt_samples(count("rtt_samples"));
        shell.set_fwd_stalls(count("stalls"));
        shell.set_fwd_warden_denied(count("warden_denied"));
        shell.set_fwd_cwnd_last(count("cwnd_last"));
        // ★ #66-A — the Centauri HTTPS seam. Absent keys read 0 through `count`, so an older .so (or a
        // base build with no `mirror` feature) renders an honest dormant row rather than a fabricated one.
        shell.set_fwd_centauri_sni_peeked(count("centauri_sni_peeked"));
        shell.set_fwd_centauri_spliced(count("centauri_spliced"));
        shell.set_fwd_centauri_splice_failed(count("centauri_splice_failed"));
        shell.set_fwd_centauri_tls_served(count("centauri_tls_served"));
        shell.set_fwd_centauri_tls_failed(count("centauri_tls_failed"));
        // ★ N-dial — the upstream dial's failure witnesses. Same `count()` discipline: absent from
        // the bridge string ⇒ 0, an honest dormant reading rather than a fabricated one.
        shell.set_fwd_dial_protect_failed(count("dial_protect_failed"));
        shell.set_fwd_dial_connect_failed(count("dial_connect_failed"));
        // ★ N-dial CLASSIFIED — same `count()` discipline: a key absent from the bridge string
        // reads 0, an honest dormant value rather than a fabricated one. The four are a proved
        // partition of the total above (Proofs/DialFailure.lean), so if they ever fail to sum to
        // it, that is a real bug in the datapath and not a modelling artefact.
        shell.set_fwd_dial_refused(count("dial_refused"));
        shell.set_fwd_dial_unreachable(count("dial_unreachable"));
        shell.set_fwd_dial_v6_suppressed(count("dial_v6_suppressed"));
        shell.set_fwd_dial_timed_out(count("dial_timed_out"));
        shell.set_fwd_dial_other(count("dial_other"));
        // ★ N-dial-UDP — the UDP dial's own two witnesses. It had none: five silent `None` exits in
        // `connect_udp_protected`, every one of them logged as a TCP failure. For a browser UDP is
        // HTTP/3, so this climbing while `dial_connect_failed` stays flat is QUIC dying behind a page
        // that still loads over TCP — intermittent slowness rather than a clean error.
        shell.set_fwd_udp_dial_protect_failed(count("udp_dial_protect_failed"));
        shell.set_fwd_udp_dial_connect_failed(count("udp_dial_connect_failed"));
        // The LIVE capability, read straight from the engine each tick — never a remembered UI flag, so
        // the banner can never claim a protection the datapath is not actually applying.
        //
        // ★ #65 — it must come over THE BRIDGE, exactly like every counter above. Calling
        // `torta_core::centauri_tls_armed()` here read the copy of `torta_core` linked STATICALLY into
        // `libtorta_ui.so` (the #74 duplication), which no one arms — the arming happens in the separate
        // `libtorta_core.so` that actually runs the tunnel. The banner therefore reported DISARMED while
        // the datapath was ARMED and serving. An absent key reads false, so an older .so still renders an
        // honest dormant row rather than a fabricated armed one.
        shell.set_fwd_centauri_tls_armed(rot_field_bool(&rec, "centauri_tls_armed"));

        // ★ #49 — the FORWARDER DASHBOARD reads the SAME record on the SAME tick. Feeding it from a
        // second bridge call would let the card and the dashboard disagree by one tick and invite
        // exactly the "two surfaces, two truths" confusion #66 had to adjudicate; one parse, two
        // views is the law. The dashboard's aggregate half is these same nineteen values.
        shell.set_fwddash_armed(rot_field_bool(&rec, "armed"));
        // The HOST PREF rides alongside the snapshot so the dashboard can tell "you never armed it"
        // apart from "you armed it and the tunnel is down" — two states whose remedies differ, and
        // which the snapshot alone renders identically. Same authority the ENGINE card's arm switch
        // reads, on the same tick.
        shell.set_fwddash_pref_armed(
            crate::engine_bridge::netstack_forwarder_armed().unwrap_or(false),
        );
        shell.set_fwddash_live(rot_field_bool(&rec, "live"));
        shell.set_fwddash_flows_tcp(count("flows_tcp"));
        shell.set_fwddash_flows_udp(count("flows_udp"));
        shell.set_fwddash_flows_other(count("flows_other"));
        // ★ #51 N9 — the ECHO lane rides the SAME parsed record as every other tile (one parse,
        // one truth), so the ping counters can never disagree with the lanes beside them.
        shell.set_fwddash_icmp_echo(count("icmp_echo"));
        shell.set_fwddash_icmp_replied(count("icmp_replied"));
        shell.set_fwddash_icmp_failed(count("icmp_failed"));
        shell.set_fwddash_active_flows(count("active_flows"));
        shell.set_fwddash_tin_critical(count("tin_critical"));
        shell.set_fwddash_tin_high(count("tin_high"));
        shell.set_fwddash_tin_normal(count("tin_normal"));
        shell.set_fwddash_dns_answered(count("dns_answered"));
        shell.set_fwddash_paced_flows(count("paced_flows"));
        shell.set_fwddash_bytes_up(bytes("bytes_up"));
        shell.set_fwddash_bytes_down(bytes("bytes_down"));
        shell.set_fwddash_rtt_samples(count("rtt_samples"));
        shell.set_fwddash_stalls(count("stalls"));
        shell.set_fwddash_warden_denied(count("warden_denied"));
        shell.set_fwddash_cwnd_last(count("cwnd_last"));
        shell.set_fwddash_dial_protect_failed(count("dial_protect_failed"));
        shell.set_fwddash_dial_connect_failed(count("dial_connect_failed"));
        // The CLASSIFIED faults reach the pillar dashboard too, so its banner names the errno class
        // instead of guessing an attribution from the total alone.
        shell.set_fwddash_dial_refused(count("dial_refused"));
        shell.set_fwddash_dial_unreachable(count("dial_unreachable"));
        shell.set_fwddash_dial_timed_out(count("dial_timed_out"));
        shell.set_fwddash_dial_other(count("dial_other"));

        // ★ #47/#48/#49 — the PER-FLOW DOCKET. Its own bridge crossing (a list cannot ride the flat
        // `key=value|…` record), parsed by the same fail-open discipline as the Warden docket.
        //
        // `docket_total` is the ENGINE's true active-flow count, deliberately taken from the SNAPSHOT
        // rather than from `rows.len()`: the two differ whenever a cap bites, and the panel is built
        // to say "showing N of M" instead of quietly presenting a truncated list as the whole truth.
        let (docket_total, docket_rows) = crate::warden_feed::live_forwarder_docket_feed();
        shell.set_fwddash_docket(slint::ModelRc::new(slint::VecModel::from(docket_rows)));
        // A bridge-silent read yields total 0 with no rows — the honest DORMANT docket. When the
        // bridge DID answer, its `total=` header wins; when it did not, fall back to the aggregate
        // record's own active_flows so the two halves of the panel cannot contradict each other.
        shell.set_fwddash_docket_total(if docket_total > 0 {
            docket_total
        } else {
            count("active_flows")
        });
    }

    /// CP-U · Feed the ENGINE tab's UNDERGROUND LAYER card from the LIVE `libtorta_core.so`
    /// UndergroundSnapshot over the pillar bridge (`TortaPillarBridge.liveUndergroundStats` — the
    /// flat `key=value|…` rotation-cursor shape). A missing/empty record (bridge unreachable,
    /// store disarmed) clears the card to the honest DORMANT birth state — armed=false + every
    /// counter zero — never a stale or fabricated licence tally (the Chroma F6 honesty law).
    fn feed_from_live_underground(shell: &crate::TortaShell) {
        use crate::engine_bridge::{
            live_underground_stats, rot_field_bool, rot_field_i64, rot_field_str,
        };
        use crate::underground_feed::{format_underground_top, parse_underground_docket};
        let rec = live_underground_stats().unwrap_or_default();
        let count = |key: &str| rot_field_i64(&rec, key).unwrap_or(0).clamp(0, i32::MAX as i64) as i32;
        shell.set_ug_armed(rot_field_bool(&rec, "armed"));
        shell.set_ug_total(count("total"));
        shell.set_ug_recorded(count("recorded"));
        shell.set_ug_recovered(count("recovered"));
        shell.set_ug_teeth(count("teeth"));
        shell.set_ug_sequestrated(count("sequestrated"));
        shell.set_ug_probation(count("probation"));
        shell.set_ug_content_lane(count("content_lane"));
        shell.set_ug_content_hot(count("content_hot"));
        shell.set_ug_trusted(count("trusted"));
        shell.set_ug_distrusted(count("distrusted"));
        shell.set_ug_r_analytics(count("r_analytics"));
        shell.set_ug_r_ads(count("r_ads"));
        shell.set_ug_r_tracker(count("r_tracker"));
        shell.set_ug_r_dnsleak(count("r_dnsleak"));
        shell.set_ug_r_ipleak(count("r_ipleak"));
        shell.set_ug_r_sonar(count("r_sonar"));
        shell.set_ug_r_mitm(count("r_mitm"));
        shell.set_ug_r_spoof(count("r_spoof"));
        shell.set_ug_r_malware(count("r_malware"));
        shell.set_ug_r_cdn(count("r_cdn"));
        shell.set_ug_s_blocklist(count("s_blocklist"));
        shell.set_ug_s_guard(count("s_guard"));
        shell.set_ug_s_rebind(count("s_rebind"));
        shell.set_ug_s_suffix(count("s_suffix"));
        shell.set_ug_s_centauri(count("s_centauri"));
        shell.set_ug_ledger_bytes(rot_field_i64(&rec, "ledger_bytes").unwrap_or(0).max(0) as f32);
        shell.set_ug_top(format_underground_top(&rot_field_str(&rec, "top")).into());
        // ---- #15 UNDERGROUND H · the pillar pane's own truths (the same pipe record) ----
        shell.set_ugd_mean_score(
            crate::engine_bridge::rot_field_f64(&rec, "mean").unwrap_or(0.0) as f32,
        );
        let docket: Vec<crate::UgHostRow> = parse_underground_docket(&rot_field_str(&rec, "top_score"))
            .into_iter()
            .map(|r| crate::UgHostRow {
                host: r.host.into(),
                risk: r.risk.into(),
                source: r.source.into(),
                hits: r.hits,
                points: r.points,
                seq: r.seq,
                verdict: r.verdict.into(),
                score: r.score,
                ttl_label: r.ttl_label.into(),
            })
            .collect();
        shell.set_ugd_docket(slint::ModelRc::new(slint::VecModel::from(docket)));
    }

    /// #81 — how many `query-underground.log` lines the review-channel panel shows. Enough to carry a
    /// full licence descent (20 points at the common penalties) plus the SEQUESTRATE that ends it, so
    /// the panel tells the whole story rather than its last frame; small enough to re-read every dash
    /// tick without cost.
    const UNDERGROUND_REVIEW_TAIL_LINES: i32 = 24;

    /// #15 UNDERGROUND H — the LIVE WIRE ticker feed (the G VerdictEvent RAM ring via
    /// `TortaPillarBridge.liveUndergroundEvents`). Cheap enough for the 500 ms dash cadence;
    /// fail-open ⇒ the wire simply stays quiet.
    fn feed_underground_wire(shell: &crate::TortaShell) {
        let raw = crate::engine_bridge::live_underground_events().unwrap_or_default();
        shell.set_ugd_live_wire(crate::underground_feed::format_underground_wire(&raw).into());

        // ★ #81 THE REVIEW CHANNEL — the DURABLE twin of the wire above.
        //
        // The live wire is a RAM ring: it dies with the process, so a verdict handed down before the
        // last restart is invisible. `query-underground.log` survives, and it is the record ROOT CAUSE
        // #26 needed and did not have — a healthy IPv4-only host drained to zero in the `tunnel` lane
        // with nothing anywhere saying so. Reading it here puts the whole descent on the pillar's own
        // dashboard, so the next such bug is one glance instead of one session.
        //
        // The path is ASKED for, never built: the file is a sibling of `underground-ledger.tsv` in the
        // dir bound by `underground::arm`, NOT under `<appDataDir>/logs/`. Fail-open by law — an
        // unarmed engine leaves the panel quiet rather than showing a fabricated row.
        let tail = torta_core::underground_log_path()
            .and_then(|p| torta_core::log_tail_recent(p, UNDERGROUND_REVIEW_TAIL_LINES))
            .unwrap_or_default();
        shell.set_ugd_review_log(tail.into());
    }

    /// #15 UNDERGROUND H — pull the operator's scoring.toml off NAND into the SETTINGS pane:
    /// the raw text + the parsed quick state (detection switches, quarantine TTL label).
    fn feed_underground_law(shell: &crate::TortaShell) {
        use crate::underground_feed::{fmt_ttl, parse_underground_law};
        let toml = crate::engine_bridge::underground_scoring_toml().unwrap_or_default();
        let (dga, tunnel, beacon, ttl) = parse_underground_law(&toml);
        shell.set_ugs_toml(toml.into());
        shell.set_ugs_dga_on(dga);
        shell.set_ugs_tunnel_on(tunnel);
        shell.set_ugs_beacon_on(beacon);
        shell.set_ugs_quarantine_label(fmt_ttl(ttl).into());
    }

    fn feed_engine(shell: &crate::TortaShell) {
        let beast = torta_core::Beast::new(
            torta_core::YeahProfile::Canonical,
            torta_core::TortaProfile::Baseline,
        );
        let s = beast.snapshot();
        // The CAKE tin caps the fountain renders (the beast.slint [4, 8, 16] canon).
        // The basin denominator, PROFILE-AWARE and taken from the single source of truth
        // (torta_core::fill_denominator, scheduler.rs). The hand-copied [4.0, 8.0, 16.0]
        // that stood here rendered every AQM-path tin as OVERFLOW-red: on that path the
        // ladder is not the governing bound (Proofs/TinCapacity.lean proves 128 != 28).
        let tin_caps: [f32; 3] = [
            torta_core::fill_denominator(s.sched_profile, 0) as f32,
            torta_core::fill_denominator(s.sched_profile, 1) as f32,
            torta_core::fill_denominator(s.sched_profile, 2) as f32,
        ];
        shell.set_engine_live(false); // spike-local — the RUNNING engine's Beast rides in libtorta_core.so
        shell.set_engine_mode(s.mode.into());
        shell.set_engine_slow_start(s.slow_start_active);
        shell.set_engine_fast_mode(s.fast_mode);
        shell.set_engine_cwnd(s.cwnd);
        shell.set_engine_window_max(s.window_max);
        shell.set_engine_base_rtt_ms(s.base_rtt_ms as f32);
        shell.set_engine_udp_rtt_ms(s.udp_base_rtt_ms as f32);
        shell.set_engine_floor_rtt_ms(s.rtt_base_floor_ms as f32);
        // #3-EXT (twin-RTT cure) — the typed-snapshot parity of the live overlay: the TRUE TCP
        // display lane + LineRate per-family telemetry + Mochi memory (cold ⇒ honest 0s, muted "—").
        shell.set_engine_tcp_rtt_ms(s.tcp_base_rtt_ms as f32);
        shell.set_engine_tcp_floor_ms(s.tcp_floor_ms as f32);
        shell.set_engine_udp_floor_ms(s.udp_floor_ms as f32);
        shell.set_engine_q_smooth(s.q_smooth as f32);
        shell.set_engine_zeta_streak(s.zeta_streak);
        shell.set_engine_shed_streak(s.shed_streak);
        shell.set_engine_valve_streak(s.valve_streak);
        shell.set_engine_soft_memory(s.soft_memory);
        shell.set_engine_adaptive_timeout_ms(s.adaptive_timeout_ms);
        shell.set_engine_pacing_rate(s.pacing_rate as f32);
        shell.set_engine_q_packets(s.q_packets as f32);
        shell.set_engine_reno_count(s.reno_count);
        shell.set_engine_pipeline_depth(s.pipeline_depth);
        shell.set_engine_q_critical(s.queue_critical);
        shell.set_engine_q_high(s.queue_high);
        shell.set_engine_q_normal(s.queue_normal);
        shell.set_engine_fill_critical((s.queue_critical as f32 / tin_caps[0]).clamp(0.0, 1.0));
        shell.set_engine_fill_high((s.queue_high as f32 / tin_caps[1]).clamp(0.0, 1.0));
        shell.set_engine_fill_normal((s.queue_normal as f32 / tin_caps[2]).clamp(0.0, 1.0));
        shell.set_engine_blue_critical(s.valve_critical as f32);
        shell.set_engine_blue_high(s.valve_high as f32);
        shell.set_engine_blue_normal(s.valve_normal as f32);
        let canonical = !matches!(s.yeah_profile, torta_core::YeahProfile::Legacy);
        // Any non-Legacy TortaProfile is a live Tortä AQM (Baseline = the former CoBALT;
        // SoftCake = the Rung-B surpassing law) — only Legacy renders the muted OFF state.
        let aqm_live = !matches!(s.sched_profile, torta_core::TortaProfile::Legacy);
        shell.set_engine_yeah_profile(
            match s.yeah_profile {
                torta_core::YeahProfile::Legacy => "LEGACY",
                torta_core::YeahProfile::Canonical => "CANONICAL",
                torta_core::YeahProfile::LineRate => "LINE-RATE",
            }
            .into(),
        );
        shell.set_engine_cake_profile(
            match s.sched_profile {
                torta_core::TortaProfile::Legacy => "LEGACY",
                torta_core::TortaProfile::Baseline => "BASELINE",
                torta_core::TortaProfile::SoftCake => "SOFT-CAKE",
            }
            .into(),
        );
        shell.set_engine_canonical_brain(canonical);
        shell.set_engine_cobalt_aqm(aqm_live);
    }

    /// #16 THE BEAST — OVERLAY the ENGINE tab's TORTA ENGINE card with the LIVE process-global
    /// congestion engine's snapshot, read over the `.so` bridge (`TortaPillarBridge.liveBeastStats` ->
    /// the ENGINE `.so`'s `beast_live_snapshot()`, the one Beast the DNS datapath feeds a measured RTT
    /// per live-forwarded resolve). [`feed_engine`] seeds the honest COLD spike-local Beast (this UI
    /// `.so`'s own throwaway copy, `engine-live=false`); THIS overlays the true window/RTT/mode/profile
    /// the running engine learned from the live DNS RTT stream. Bridge unreachable OR datapath not live
    /// (Kotlin gates on `isDatapathLive`) ⇒ the record is absent and the card keeps its cold baseline —
    /// never a stale window dressed as live (the Chroma F6 honesty law). The `engine-live` flag itself
    /// is set by [`overlay_live_engine`] off the resolver-active read; this only paints the metrics.
    /// Field-for-field the SAME mapping [`feed_engine`] applies to the cold snapshot, so the two paths
    /// render identically (no cold↔live drift), only the SOURCE of truth differs.
    fn overlay_live_beast(shell: &crate::TortaShell) {
        use crate::engine_bridge::{
            live_beast_stats, rot_field_bool, rot_field_f64, rot_field_i64, rot_field_str,
        };
        let Some(rec) = live_beast_stats() else {
            return; // dormant or unreachable — feed_engine's cold baseline stands
        };
        // The CAKE tin caps the fountain renders (the beast.slint [4, 8, 16] canon) — same as feed_engine.
        // The LIVE beast is Beast::new(LineRate, SoftCake) (torta_core beast/mod.rs:332),
        // so its basins scale against the global AQM cap, not the legacy ladder.
        let tin_caps: [f32; 3] = [
            torta_core::fill_denominator(torta_core::TortaProfile::SoftCake, 0) as f32,
            torta_core::fill_denominator(torta_core::TortaProfile::SoftCake, 1) as f32,
            torta_core::fill_denominator(torta_core::TortaProfile::SoftCake, 2) as f32,
        ];
        let int_of = |k: &str| {
            rot_field_i64(&rec, k)
                .unwrap_or(0)
                .clamp(i32::MIN as i64, i32::MAX as i64) as i32
        };
        let flt_of = |k: &str| rot_field_f64(&rec, k).unwrap_or(0.0) as f32;

        shell.set_engine_mode(rot_field_str(&rec, "mode").into());
        shell.set_engine_slow_start(rot_field_bool(&rec, "slow_start"));
        shell.set_engine_fast_mode(rot_field_bool(&rec, "fast_mode"));
        shell.set_engine_cwnd(int_of("cwnd"));
        shell.set_engine_window_max(int_of("window_max"));
        shell.set_engine_base_rtt_ms(flt_of("base_rtt"));
        shell.set_engine_udp_rtt_ms(flt_of("udp_rtt"));
        shell.set_engine_floor_rtt_ms(flt_of("floor_rtt"));
        // #3-EXT (twin-RTT cure) — the TRUE TCP display lane (forwarder dial EWMA + floor) + the
        // LineRate per-family telemetry + the Mochi memory pair, field-for-field off the live wire.
        shell.set_engine_tcp_rtt_ms(flt_of("tcp_rtt"));
        shell.set_engine_tcp_floor_ms(flt_of("tcp_floor"));
        shell.set_engine_udp_floor_ms(flt_of("udp_floor"));
        shell.set_engine_q_smooth(flt_of("q_smooth"));
        shell.set_engine_zeta_streak(int_of("zeta_streak"));
        shell.set_engine_shed_streak(int_of("shed_streak"));
        shell.set_engine_valve_streak(int_of("valve_streak"));
        shell.set_engine_soft_memory(int_of("soft_memory"));
        shell.set_engine_adaptive_timeout_ms(int_of("adaptive_timeout"));
        shell.set_engine_pacing_rate(flt_of("pacing"));
        shell.set_engine_q_packets(flt_of("q_packets"));
        shell.set_engine_reno_count(int_of("reno"));
        shell.set_engine_pipeline_depth(int_of("pipeline"));
        let qc = int_of("q_critical");
        let qh = int_of("q_high");
        let qn = int_of("q_normal");
        shell.set_engine_q_critical(qc);
        shell.set_engine_q_high(qh);
        shell.set_engine_q_normal(qn);
        shell.set_engine_fill_critical((qc as f32 / tin_caps[0]).clamp(0.0, 1.0));
        shell.set_engine_fill_high((qh as f32 / tin_caps[1]).clamp(0.0, 1.0));
        shell.set_engine_fill_normal((qn as f32 / tin_caps[2]).clamp(0.0, 1.0));
        shell.set_engine_blue_critical(flt_of("blue_critical"));
        shell.set_engine_blue_high(flt_of("blue_high"));
        shell.set_engine_blue_normal(flt_of("blue_normal"));
        // #16 THE BEAST (AQM retention) — the CAKE tins' session high-water: session-peak per-tin depth
        // + lifetime per-tin throughput ("N served"). Overlaid so a real query burst leaves an honest,
        // durable mark: the instantaneous `q_*` depth above reads 0 almost always (the 100ms AQM pump
        // drains each tin between the ~500ms polls), while these RETAIN what genuinely flowed. Never
        // fabricated — only real classified traffic moves them (0 before any query).
        shell.set_engine_peak_critical(int_of("peak_critical"));
        shell.set_engine_peak_high(int_of("peak_high"));
        shell.set_engine_peak_normal(int_of("peak_normal"));
        shell.set_engine_served_critical(int_of("thru_critical"));
        shell.set_engine_served_high(int_of("thru_high"));
        shell.set_engine_served_normal(int_of("thru_normal"));
        // The profile `.value` ints the bridge carried (0 = Legacy, 1 = Canonical/Baseline,
        // 2 = LineRate/SoftCake) map to the display labels + the Chroma F6 gating booleans (only a
        // Legacy profile renders the muted OFF state — its inert 0s never read as live metrics).
        let yeah_ord = rot_field_i64(&rec, "yeah_profile").unwrap_or(0);
        let sched_ord = rot_field_i64(&rec, "sched_profile").unwrap_or(0);
        shell.set_engine_yeah_profile(
            match yeah_ord {
                2 => "LINE-RATE",
                1 => "CANONICAL",
                _ => "LEGACY",
            }
            .into(),
        );
        shell.set_engine_cake_profile(
            match sched_ord {
                2 => "SOFT-CAKE",
                1 => "BASELINE",
                _ => "LEGACY",
            }
            .into(),
        );
        shell.set_engine_canonical_brain(yeah_ord != 0);
        shell.set_engine_cobalt_aqm(sched_ord != 0);
    }

    /// Feed the IN-SHELL BEAST pillar DASHBOARD (beast.slint `BeastPane`, mounted behind
    /// ||| → PILLARS → BEAST → DASHBOARD) — the typed `BeastSnapshot` pushed FIELD-FOR-FIELD onto the
    /// shell's `bdash-*` forwarding aliases. The Centauri/MaskSolver precedent applied to the flagship
    /// flow engine: REAL reads of a REAL `Beast` Object (cold spike-local ⇒ the honest DORMANT baseline
    /// — cwnd=1/16 SLOW-START, zero flows — never fabricated traffic, the D1 law + Chroma F16). Both
    /// profile ordinals ride the SNAPSHOT's own enums (0 Legacy · 1 Canonical/CoBALT · 2 LineRate). The
    /// `recent-ticks` sample rows are CLEARED (cold ⇒ query-beast.log absent ⇒ honestly empty), proving
    /// the live feed replaced the .slint preview literals. Re-called each tick while the pane is shown
    /// (android_main's refresh Timer) so the RUNNING engine's snapshot streams once the single-.so
    /// unification lands.
    fn feed_from_live_beast(shell: &crate::TortaShell, beast: &torta_core::Beast) {
        let s = beast.snapshot();
        shell.set_bdash_cwnd(s.cwnd);
        shell.set_bdash_window_max(s.window_max);
        shell.set_bdash_mode(s.mode.into());
        shell.set_bdash_slow_start_active(s.slow_start_active);
        shell.set_bdash_base_rtt_ms(s.base_rtt_ms as f32);
        shell.set_bdash_rtt_base_floor_ms(s.rtt_base_floor_ms as f32);
        shell.set_bdash_q_packets(s.q_packets as f32);
        shell.set_bdash_reno_count(s.reno_count);
        shell.set_bdash_fast_mode(s.fast_mode);
        shell.set_bdash_adaptive_timeout_ms(s.adaptive_timeout_ms);
        shell.set_bdash_pacing_rate(s.pacing_rate as f32);
        shell.set_bdash_yeah_profile(match s.yeah_profile {
            torta_core::YeahProfile::Legacy => 0,
            torta_core::YeahProfile::Canonical => 1,
            torta_core::YeahProfile::LineRate => 2,
        });
        shell.set_bdash_udp_base_rtt_ms(s.udp_base_rtt_ms as f32);
        // #3-EXT (twin-RTT cure) — the TRUE TCP display lane + LineRate per-family telemetry +
        // Mochi memory, typed field-for-field (cold ⇒ honest 0s, the pane mutes them to "—").
        shell.set_bdash_tcp_base_rtt_ms(s.tcp_base_rtt_ms as f32);
        shell.set_bdash_tcp_floor_ms(s.tcp_floor_ms as f32);
        // ★ #52 — the SHAPED PLANE (per-flow FlowShaper return leg): steady-state RTT under load and
        // the window the real forwarded flows converged on, as opposed to the handshake pair above.
        shell.set_bdash_shaped_rtt_ms(s.shaped_rtt_ms as f32);
        shell.set_bdash_shaped_cwnd_last(s.shaped_cwnd_last);
        shell.set_bdash_shaped_cwnd_mean(s.shaped_cwnd_mean as f32);
        shell.set_bdash_shaped_samples(s.shaped_samples as i32);
        shell.set_bdash_shaped_losses(s.shaped_losses as i32);
        shell.set_bdash_udp_floor_ms(s.udp_floor_ms as f32);
        shell.set_bdash_q_smooth(s.q_smooth as f32);
        shell.set_bdash_zeta_streak(s.zeta_streak);
        shell.set_bdash_shed_streak(s.shed_streak);
        shell.set_bdash_valve_streak(s.valve_streak);
        shell.set_bdash_soft_memory(s.soft_memory);
        shell.set_bdash_pipeline_depth(s.pipeline_depth);
        shell.set_bdash_queue_critical(s.queue_critical);
        shell.set_bdash_queue_high(s.queue_high);
        shell.set_bdash_queue_normal(s.queue_normal);
        shell.set_bdash_blue_prob(s.valve_prob as f32);
        shell.set_bdash_blue_critical(s.valve_critical as f32);
        shell.set_bdash_blue_high(s.valve_high as f32);
        shell.set_bdash_blue_normal(s.valve_normal as f32);
        shell.set_bdash_cobalt_dropped(s.shed_dropped);
        shell.set_bdash_aqm_dropped(s.aqm_dropped);
        shell.set_bdash_drr_sparse_served(s.drr_sparse_served);
        // ★ #22 slice 3 · Rung E — the global-overload witness (honest zero until the cap fires).
        shell.set_bdash_overload_sheds(s.overload_sheds);
        // TortaProfile is #[repr(i32)] (0 Legacy · 1 Baseline/CoBALT · 2 SoftCake) — the ordinal
        // rides straight onto the pane's `cake-profile` int (beast.slint decodes all three).
        shell.set_bdash_cake_profile(s.sched_profile as i32);
        // Cold ⇒ query-beast.log absent ⇒ the tick feed is honestly EMPTY (clears the .slint sample).
        shell.set_bdash_recent_ticks(ModelRc::new(VecModel::from(
            Vec::<crate::BeastTickRow>::new(),
        )));

        // SLINT substitution · 4-FIX-2 — THE LIVE BEAST MOVEMENT OVERLAY (the .so-split fix: the snapshot
        // above is THIS .so's cold spike-local Beast — cwnd=1/16 DORMANT, zero flows). The RUNNING engine's
        // Beast budget rides in libtorta_core.so; its live witnesses (`budget_cwnd_cap`/`budget_inflight`/
        // `budget_pacing_qps`) are carried on the SAME bridged resolver_stats JSON. Overlay the WINDOW +
        // backlog + pacing with the live numbers ONLY when the running engine has pushed a budget (> 0) — a
        // 0 budget means the engine is not shaping yet, so the honest cold DORMANT read stands. The per-tin
        // CAKE fountain + the CoBALT valves need a full typed Beast snapshot export (documented as remaining,
        // never fabricated). Unreachable / stopped ⇒ `None` ⇒ the cold read stands.
        if let Some(j) = crate::engine_bridge::live_resolver_stats() {
            use crate::engine_bridge::{json_f32, json_i32};
            if let Some(v) = json_i32(&j, "budget_cwnd_cap") {
                if v > 0 {
                    shell.set_bdash_cwnd(v);
                }
            }
            if let Some(v) = json_i32(&j, "budget_inflight") {
                if v > 0 {
                    shell.set_bdash_q_packets(v as f32);
                }
            }
            if let Some(v) = json_f32(&j, "budget_pacing_qps") {
                if v > 0.0 {
                    shell.set_bdash_pacing_rate(v);
                }
            }
        }
    }

    /// #3-EXT · THE LIVE BEAST DASHBOARD OVERLAY — the cure for the three-Beasts split the field
    /// bug witnessed (pillar DASHBOARD frozen on the cold spike-local Beast's CANONICAL·DORMANT
    /// while the ENGINE tab roared LIVE off `live_beast_stats()`). Mirrors [`overlay_live_beast`]'s
    /// idiom onto the `bdash-*` pane: `TortaPillarBridge.liveBeastStats` serializes the RUNNING
    /// `libtorta_core.so` Beast (`live_beast()` — the one the armed resolver seam feeds RTT + AQM,
    /// resolver/mod.rs:1280-1302) as the flat `k=v|…` record; every pane prop the .slint census
    /// names is overlaid from it. `None`/empty (tunnel stopped, bridge unreachable) ⇒ return — the
    /// cold DORMANT baseline from [`feed_from_live_beast`] stands, never a stale or fabricated read
    /// (the honesty law). The RECENT TICKS strip tails the REAL query-beast.log through the same
    /// RAM⊗NAND read path the ④ QUERY feed rides (`log_tail_recent`), newest first.
    fn overlay_live_beast_dashboard(shell: &crate::TortaShell, data_dir: &str) {
        use crate::engine_bridge::{
            live_beast_stats, rot_field_bool, rot_field_f64, rot_field_i64, rot_field_str,
        };
        let Some(rec) = live_beast_stats() else {
            return;
        };
        let int_of = |key: &str| rot_field_i64(&rec, key).unwrap_or(0);
        let flt_of = |key: &str| rot_field_f64(&rec, key).unwrap_or(0.0);
        // The brain + queue ordinals (0 Legacy · 1 Canonical/Baseline · 2 LineRate/SoftCake) ride
        // the pipe as ints; the pane decodes both (beast.slint:255-259) — LEGACY/CANONICAL/LINE-RATE
        // header + LEGACY-AQM/BASELINE/SOFT-CAKE crown, the exact live-profile truth Settings shows.
        shell.set_bdash_yeah_profile(int_of("yeah_profile") as i32);
        shell.set_bdash_cake_profile(int_of("sched_profile") as i32);
        shell.set_bdash_mode(rot_field_str(&rec, "mode").into());
        shell.set_bdash_slow_start_active(rot_field_bool(&rec, "slow_start"));
        shell.set_bdash_fast_mode(rot_field_bool(&rec, "fast_mode"));
        shell.set_bdash_cwnd(int_of("cwnd") as i32);
        shell.set_bdash_window_max(int_of("window_max") as i32);
        shell.set_bdash_base_rtt_ms(flt_of("base_rtt") as f32);
        shell.set_bdash_udp_base_rtt_ms(flt_of("udp_rtt") as f32);
        shell.set_bdash_rtt_base_floor_ms(flt_of("floor_rtt") as f32);
        // #3-EXT (twin-RTT cure) — the TRUE TCP display lane + LineRate per-family telemetry +
        // Mochi memory off the live wire (the exact keys the Kotlin pipe carries).
        shell.set_bdash_tcp_base_rtt_ms(flt_of("tcp_rtt") as f32);
        shell.set_bdash_tcp_floor_ms(flt_of("tcp_floor") as f32);
        // ★ #52 — the SHAPED PLANE off the live wire (the keys the Kotlin pipe carries). This is the
        // path that is REAL on device: torta_ui does not read its own statically-linked torta_core
        // there, it reads TortaPillarBridge (#49/#74) — so the snapshot feed above is the host lane
        // and THIS is what the phone renders.
        shell.set_bdash_shaped_rtt_ms(flt_of("shaped_rtt") as f32);
        shell.set_bdash_shaped_cwnd_last(int_of("shaped_cwnd") as i32);
        shell.set_bdash_shaped_cwnd_mean(flt_of("shaped_cwnd_mean") as f32);
        shell.set_bdash_shaped_samples(int_of("shaped_samples") as i32);
        shell.set_bdash_shaped_losses(int_of("shaped_losses") as i32);
        shell.set_bdash_udp_floor_ms(flt_of("udp_floor") as f32);
        shell.set_bdash_q_smooth(flt_of("q_smooth") as f32);
        shell.set_bdash_zeta_streak(int_of("zeta_streak") as i32);
        shell.set_bdash_shed_streak(int_of("shed_streak") as i32);
        shell.set_bdash_valve_streak(int_of("valve_streak") as i32);
        shell.set_bdash_soft_memory(int_of("soft_memory") as i32);
        shell.set_bdash_adaptive_timeout_ms(int_of("adaptive_timeout") as i32);
        shell.set_bdash_pacing_rate(flt_of("pacing") as f32);
        shell.set_bdash_q_packets(flt_of("q_packets") as f32);
        shell.set_bdash_reno_count(int_of("reno") as i32);
        shell.set_bdash_pipeline_depth(int_of("pipeline") as i32);
        shell.set_bdash_queue_critical(int_of("q_critical") as i32);
        shell.set_bdash_queue_high(int_of("q_high") as i32);
        shell.set_bdash_queue_normal(int_of("q_normal") as i32);
        shell.set_bdash_blue_prob(flt_of("blue_prob") as f32);
        shell.set_bdash_blue_critical(flt_of("blue_critical") as f32);
        shell.set_bdash_blue_high(flt_of("blue_high") as f32);
        shell.set_bdash_blue_normal(flt_of("blue_normal") as f32);
        shell.set_bdash_cobalt_dropped(int_of("shed") as i32);
        shell.set_bdash_aqm_dropped(int_of("aqm") as i32);
        shell.set_bdash_drr_sparse_served(int_of("sparse") as i32);
        // ★ #22 slice 3 · Rung E — the global-overload witness off the live wire (the exact
        // `overload_sheds` key the Kotlin pipe now carries; absent key ⇒ honest 0).
        shell.set_bdash_overload_sheds(int_of("overload_sheds") as i32);
        // RECENT TICKS — the REAL query-beast.log tail (the engine's own pulse log), through the
        // same `query_log_path` + `log_tail_recent` RAM⊗NAND lane as the ④ QUERY feed. Absent log
        // ⇒ empty rows (the cold clear stands) — honest, never the .slint sample preview.
        let path = crate::feed_shape::query_log_path(data_dir, "beast");
        let rows: Vec<crate::BeastTickRow> =
            torta_core::log_tail_recent(path, crate::feed_shape::BEAST_TICKS_SHOWN)
                .unwrap_or_default()
                .lines()
                .rev() // newest first — the pulse strip's reading order
                .filter_map(crate::feed_shape::beast_tick_row_parse)
                .collect();
        shell.set_bdash_recent_ticks(ModelRc::new(VecModel::from(rows)));
    }

    /// Wire the shell's ④ QUERY tab — the unified per-pillar log feed. One refresh closure tails
    /// the picked source through the SAME `log_tail_recent` / `log_stale_secs` RAM⊗NAND read path
    /// the dashboards use (the fns Kotlin reaches as `logTailRecent`/`logStaleSecs`), classifies
    /// each line through [`crate::feed_shape`] (typed `QueryRow`s, newest first), and lands the
    /// staleness truth (`-1` = absent → the pane's "not written yet" honesty, never "stale").
    /// Read the picked source's on-disk log and push its (present flag + staleness + classified
    /// rows) onto the ④ shell — the ONE place the QUERY feed is computed, shared by the interactive
    /// wiring ([`wire_query_feed`]) and the active-tab refresh timer (so a user who lands on the tab
    /// with the engine running sees live rows WITHOUT a manual REFRESH). Staleness `-1` = absent →
    /// the pane's "not written yet" honesty, never a fabricated "stale".
    fn refresh_query_rows(s: &crate::TortaShell, data_dir: &str, source: &str) {
        let path = crate::feed_shape::query_log_path(data_dir, source);
        let stale = torta_core::log_stale_secs(path.clone());
        s.set_query_log_present(stale >= 0);
        s.set_query_stale_secs(stale.min(i64::from(i32::MAX)) as i32);
        let rows: Vec<crate::QueryRow> = torta_core::log_tail_recent(path, QUERY_ROWS_SHOWN)
            .unwrap_or_default()
            .lines()
            .rev() // newest first — the feed's reading order
            .filter(|l| !l.trim().is_empty())
            .map(crate::feed_shape::classify_query_line)
            .collect();
        s.set_query_rows(ModelRc::new(VecModel::from(rows)));
    }

    fn wire_query_feed(shell: &crate::TortaShell, data_dir: String) {
        let refresh: Rc<dyn Fn(&str)> = {
            let shell_weak = shell.as_weak();
            Rc::new(move |source: &str| {
                if let Some(s) = shell_weak.upgrade() {
                    refresh_query_rows(&s, &data_dir, source);
                }
            })
        };
        {
            let r = refresh.clone();
            shell.on_query_source_picked(move |src| r(src.as_str()));
        }
        {
            let r = refresh.clone();
            let shell_weak = shell.as_weak();
            shell.on_query_refresh(move || {
                if let Some(s) = shell_weak.upgrade() {
                    r(s.get_query_source().as_str());
                }
            });
        }
        refresh("dnscrypt"); // the initial tail (the tab's default source)
    }

    /// ★ #97 — feed the ③ DNS tab's POST-QUANTUM WITNESS from the LIVE engine.
    ///
    /// Yeah Tortä's X-Wing (es-0x0003) transport has shaped every eligible exchange since the v2.1.17
    /// absorb, and no surface said so — the app's most distinctive security property was unverifiable
    /// from inside the app. `resolver::stats()` now carries the engine's own census across the seam
    /// (`pq_exchanges` / `classic_exchanges`, bumped at the single dispatch fork in
    /// `dnscrypt.rs::encrypted_exchange`), and this pushes it onto the fed `dc` mount.
    ///
    /// Reads `live_resolver_stats()` — libtorta_core.so's LIVE process-globals — NOT this .so's cold
    /// static copy, which would always report 0 (the #74 split-brain law). When the bridge is silent
    /// (host build, or the engine down) the `if let` leaves BOTH properties untouched rather than
    /// writing 0: a refresh tick must never zero-clobber a value it cannot measure (#80's law), and a
    /// stale-but-true count is honester than a fresh zero. The cold slint defaults (0/0) then stand,
    /// and `pq-measured` renders them as "—" rather than as "not protected".
    fn feed_pq_witness(sh: &crate::TortaShell) {
        if let Some(j) = crate::engine_bridge::live_resolver_stats() {
            use crate::engine_bridge::json_i32;
            if let Some(v) = json_i32(&j, "pq_exchanges") {
                sh.set_dc_pq_exchanges(v);
            }
            if let Some(v) = json_i32(&j, "classic_exchanges") {
                sh.set_dc_pq_classic(v);
            }
        }
    }

    /// Feed the ③ DNS tab's LIVE DASHBOARD (2-FEED-DNSCRYPT) — the running-status + server + query-feed
    /// twin of [`feed_from_live_centauri`], for the DNSCrypt namesake pillar. Unlike the other pillars
    /// whose engine state lives in a torta_core Object, DNSCrypt's RUNNING state is owned by Kotlin's
    /// ModulesService (the D09 law) → the STATE code is set by the shell's 500 ms JNI poll (NOT here);
    /// this fn pushes the two on-disk / typed halves the tail-refresh owns:
    ///   · the SERVER line — the K5 typed config (pinned `server_names`, else the auto-pick line) plus
    ///     the anonymized-relay-route note (`anonymized_dns.routes`), a REAL read of the shared Record;
    ///   · the QUERY FEED — the REAL on-disk `cache/query.log` tail (newest first, classified through the
    ///     SAME `feed_shape::classify_query_line` ④ QUERY uses), a bounded preview. Cold / no log ⇒ an
    ///     honest empty feed + a 0 count, NEVER a fabricated row (the felt-truth law).
    fn feed_from_live_dnscrypt(
        shell: &crate::TortaShell,
        cfg: &torta_core::DnscryptProxyConfig,
        data_dir: &str,
    ) {
        // SERVER — the K5 config truth (the same authority the config surface renders).
        let base = if cfg.server_names.is_empty() {
            "auto-pick from the signed source lists".to_string()
        } else {
            cfg.server_names.join(", ")
        };
        let routes = cfg.anonymized_dns.routes.len();
        let server = if routes > 0 {
            format!("{base}  ·  via {routes} anonymized relay route(s)")
        } else {
            base
        };
        shell.set_dc_live_server(server.into());

        // QUERY FEED — the REAL cache/query.log tail (newest first), bounded to the dashboard window.
        let path = crate::feed_shape::query_log_path(data_dir, "dnscrypt");
        let rows: Vec<crate::QueryRow> = torta_core::log_tail_recent(path, DNS_QUERIES_SHOWN)
            .unwrap_or_default()
            .lines()
            .rev()
            .filter(|l| !l.trim().is_empty())
            .map(crate::feed_shape::classify_query_line)
            .collect();
        shell.set_dc_live_query_count(rows.len() as i32);
        shell.set_dc_live_queries(ModelRc::new(VecModel::from(rows)));
    }

    /// Parse ONE `query-masksolver.log` line into the typed [`crate::MaskRow`] the pane's RECENT RESOLVES
    /// feed renders. The line format is the resolver's own (resolver/log.rs `format_query_line`):
    /// `<now_ms> <OUTCOME> <transport> <rtt> <qtype>` (e.g. `1751000000000 MISS - - 1`) — space-split,
    /// the leading epoch dropped (the feed shows outcome/qtype/transport/rtt, never the wall clock). A
    /// short/blank line is skipped (`None`). T20: outcome + type labels only, never a qname / client-IP.
    fn parse_mask_row(line: &str) -> Option<crate::MaskRow> {
        let mut it = line.split_whitespace();
        let _epoch = it.next()?;
        let outcome = it.next()?;
        let transport = it.next().unwrap_or("-");
        let rtt = it.next().unwrap_or("-");
        let qtype = it.next().unwrap_or("-");
        Some(crate::MaskRow {
            outcome: outcome.into(),
            qtype: qtype.into(),
            transport: transport.into(),
            rtt: rtt.into(),
        })
    }

    /// Feed the shell's in-shell MaskSolver pillar DASHBOARD (the ms-dash section, home_shell.slint
    /// `MaskSolverPane`) — the MaskSolver twin of [`feed_from_live_centauri`]. Pushes the live typed
    /// [`torta_core::MaskSolver::snapshot`] + [`solve_state`](torta_core::MaskSolver::solve_state) Records
    /// FIELD-FOR-FIELD onto the shell's `ms-*` forwarding aliases: the SOLVE/CACHE witnesses, the rebind
    /// guard, the SOLVE-cross resilience counters, the rotation cursor, the per-upstream RTT/loss health
    /// rows, and the query-masksolver.log resolve feed. Every number is a REAL read of the SAME live
    /// resolver atomics `resolver_stats()` renders (the single-source proof, no engine fork — object.rs
    /// F1). A COLD `MaskSolver` reads 0/0/0; the on-device host arms a spike-local loopback pool first
    /// (the Centauri precedent — a REAL Object, honest spike-local instance) so `transports`/`timeout`/
    /// `strategy` + the per-upstream health rows carry real STRUCTURAL numbers, never fabricated traffic.
    fn feed_from_live_masksolver(shell: &crate::TortaShell, solver: &torta_core::MaskSolver) {
        let snap = solver.snapshot();
        let solve = solver.solve_state();

        // ── the MaskSolverSnapshot fields (the resolver ledger + the CACHE/rebind witnesses) ──
        shell.set_ms_configured(snap.configured);
        shell.set_ms_transports(snap.transports as i32);
        shell.set_ms_cache_entries(snap.cache_entries as i32);
        shell.set_ms_cache_hit_rate(snap.cache_hit_rate as f32);
        shell.set_ms_solve_success_rate(snap.solve_success_rate as f32);
        shell.set_ms_queries(snap.queries as i32);
        shell.set_ms_blocked(snap.blocked as i32);
        shell.set_ms_cache_hits(snap.cache_hits as i32);
        shell.set_ms_answered(snap.answered as i32);
        shell.set_ms_rejected(snap.rejected as i32);
        shell.set_ms_transport_miss(snap.transport_miss as i32);
        shell.set_ms_panics(snap.panics as i32);
        shell.set_ms_rebind_observed(snap.rebind_observed as i32);
        shell.set_ms_rebind_rejected(snap.rebind_rejected as i32);
        shell.set_ms_serve_stale_served(snap.serve_stale_served as i32);
        shell.set_ms_neg_cache(snap.neg_cache as i32);
        shell.set_ms_local_record_hits(snap.local_record_hits as i32);
        shell.set_ms_never_forward_stops(snap.never_forward_stops as i32);
        shell.set_ms_dns64_synth(snap.dns64_synth as i32);

        // ── the MaskSolverSolveState fields (the SOLVE-cross resilience + the deadline + strategy) ──
        shell.set_ms_timeout_ms(solve.timeout_ms as i32);
        // The MaskSolverStrategy is a field-less UniFFI enum → its discriminant is the .slint ordinal
        // contract (0 StrictOrder · 1 AllServers · 2 Fastest — masksolver.slint:157, test-asserted at
        // solve_state_surfaces_the_typed_strategy_and_solve_counters).
        shell.set_ms_strategy(solve.strategy as i32);
        shell.set_ms_solve_retries(solve.solve_retries as i32);
        shell.set_ms_solve_soft_fails(solve.solve_soft_fails as i32);
        shell.set_ms_solve_hard_negatives(solve.solve_hard_negatives as i32);
        shell.set_ms_solve_ladder_exhausted(solve.solve_ladder_exhausted as i32);
        shell.set_ms_solve_upstream_promotions(solve.solve_upstream_promotions as i32);

        // ── the embedded rotation cursor (last-persisted durable diversity state) ──
        shell.set_ms_rotation_family(solve.rotation.last_family.into());
        shell.set_ms_rotation_cadence_secs(solve.rotation.cadence_secs as i32);
        shell.set_ms_rotation_index(solve.rotation.rotation_index as i32);
        shell.set_ms_rotation_hint_count(solve.rotation.hint_count as i32);

        // ── the per-upstream health rows — the REAL configured pool (R7 RTT/loss EWMA), replacing the
        //    .slint sample (quad9/cloudflare literals). `—` until the first reply; loss/samples typed. ──
        let rows: Vec<crate::MaskTransportRow> = solve
            .transports
            .iter()
            .map(|t| crate::MaskTransportRow {
                id: t.id.clone().into(),
                rtt: t
                    .rtt_ms_ewma
                    .map(|r| format!("{}ms", r.round() as i64))
                    .unwrap_or_else(|| "—".to_string())
                    .into(),
                loss: t.loss_ewma as f32,
                samples: t.samples as i32,
            })
            .collect();
        shell.set_ms_transport_rows(ModelRc::new(VecModel::from(rows)));

        // ── the recent-resolve feed — the live query-masksolver.log tail (newest first), replacing the
        //    .slint sample. Cold (no traffic through the spike .so) ⇒ honestly EMPTY, never a fake row. ──
        let resolves: Vec<crate::MaskRow> = solver
            .query_masksolver_log_path()
            .and_then(|p| torta_core::log_tail_recent(p, MASK_RESOLVES_SHOWN))
            .unwrap_or_default()
            .lines()
            .rev()
            .filter(|l| !l.trim().is_empty())
            .filter_map(parse_mask_row)
            .collect();
        shell.set_ms_recent_resolves(ModelRc::new(VecModel::from(resolves)));

        // SLINT substitution · 4-FIX-2 — THE LIVE MASKSOLVER LEDGER OVERLAY (the .so-split fix: the fields
        // above are THIS .so's cold spike-local resolver, always 0 traffic). The RUNNING engine writes the
        // SAME resolver process-globals `resolver_stats()` renders, bridged over JNI as flat JSON — overlay
        // the LEDGER counters (queries/answered/blocked/cache/solve-cross) with the live truth when the
        // resolver is active (configured OR ≥1 query served), plus the structural `configured` + upstream
        // COUNT, the per-upstream HEALTH DETAIL rows (the `upstreams` array), and the RECENT RESOLVES feed
        // (the bridged `mask_log` path) — all below. Only timeout/strategy stay THIS .so's cold read (the
        // K5 config surface fills them cold via `dnscrypt_config_get` further down). Unreachable / stopped
        // ⇒ the honest cold zeros stand (never a fabricated running count).
        if let Some(j) = crate::engine_bridge::live_resolver_stats() {
            use crate::engine_bridge::{json_bool, json_f32, json_i32};
            let active = json_bool(&j, "configured") || json_i32(&j, "queries").unwrap_or(0) > 0;
            if active {
                // Overlay the REAL structural aggregate from the live stats JSON: `configured` + the
                // `transports` COUNT (both ARE in the resolver stats JSON, resolver/mod.rs:1654). SLINT
                // substitution · 4-FIX round 5 — the DEAD-POOL FALSE-ALARM fix: the round-3 overlay
                // hard-set `configured=true` while THIS .so's cold `transports` stayed 0, so the pane
                // read "DEAD POOL — configured but ZERO upstreams" even while the running engine had a
                // live pool. Now the header shows the engine's REAL upstream COUNT, and DEAD POOL fires
                // ONLY when the engine genuinely reports 0 upstreams (honest). The per-upstream HEALTH
                // DETAIL rows now HAVE a live cross-.so reader — the `upstreams` array parsed below (the
                // deferred gap, closed); a cold/unconfigured engine sends an empty array → cold read stands.
                shell.set_ms_configured(json_bool(&j, "configured"));
                let set = |key: &str, f: &dyn Fn(i32)| {
                    if let Some(v) = json_i32(&j, key) {
                        f(v);
                    }
                };
                set("transports", &|v| shell.set_ms_transports(v));
                set("queries", &|v| shell.set_ms_queries(v));
                set("answered", &|v| shell.set_ms_answered(v));
                set("blocked", &|v| shell.set_ms_blocked(v));
                set("cache_hits", &|v| shell.set_ms_cache_hits(v));
                set("cache", &|v| shell.set_ms_cache_entries(v));
                set("rejected", &|v| shell.set_ms_rejected(v));
                set("transport_miss", &|v| shell.set_ms_transport_miss(v));
                set("panics", &|v| shell.set_ms_panics(v));
                set("rebind_observed", &|v| shell.set_ms_rebind_observed(v));
                set("rebind_rejected", &|v| shell.set_ms_rebind_rejected(v));
                set("serve_stale_served", &|v| {
                    shell.set_ms_serve_stale_served(v)
                });
                set("neg_cache", &|v| shell.set_ms_neg_cache(v));
                set("local_record_hits", &|v| shell.set_ms_local_record_hits(v));
                set("never_forward_stops", &|v| {
                    shell.set_ms_never_forward_stops(v)
                });
                set("dns64_synth", &|v| shell.set_ms_dns64_synth(v));
                set("solve_retries", &|v| shell.set_ms_solve_retries(v));
                set("solve_soft_fails", &|v| shell.set_ms_solve_soft_fails(v));
                set("solve_hard_negatives", &|v| {
                    shell.set_ms_solve_hard_negatives(v)
                });
                set("solve_ladder_exhausted", &|v| {
                    shell.set_ms_solve_ladder_exhausted(v)
                });
                set("solve_upstream_promotions", &|v| {
                    shell.set_ms_solve_upstream_promotions(v)
                });
                // The two display RATES the engine now emits on the SAME flat JSON (resolver/mod.rs
                // `stats()`, computed with object.rs's `rate()` — the single-source contract). Without
                // this overlay the header %s (GOT THROUGH, cache hit) stayed at THIS .so's cold-copy 0.0
                // while `answered`/`queries` above showed the live traffic — the .so-split telemetry gap.
                if let Some(v) = json_f32(&j, "solve_success_rate") {
                    shell.set_ms_solve_success_rate(v);
                }
                if let Some(v) = json_f32(&j, "cache_hit_rate") {
                    shell.set_ms_cache_hit_rate(v);
                }
                // ── UPSTREAM HEALTH — the per-upstream DETAIL rows, NOW cross-.so live. The engine's
                //    `stats()` carries an `upstreams` array (id + rtt_ms[null until first reply] + loss +
                //    samples); parse it into the pane's transport-rows so "N in pool" + the health list
                //    read the RUNNING pool, not THIS .so's cold-empty local resolver. Non-empty ⇒ overlay;
                //    empty (unconfigured) ⇒ leave the honest cold read (also empty). Retires the deferred
                //    gap noted above ("the per-upstream HEALTH DETAIL rows still have no live cross-.so
                //    reader"). T20: the stats array carries the id LABEL only, never a host/url.
                let ups = crate::engine_bridge::json_object_array(&j, "upstreams");
                if !ups.is_empty() {
                    let rows: Vec<crate::MaskTransportRow> = ups
                        .iter()
                        .map(|o| crate::MaskTransportRow {
                            id: crate::engine_bridge::json_str(o, "id")
                                .unwrap_or_default()
                                .into(),
                            rtt: crate::engine_bridge::json_f32(o, "rtt_ms")
                                .map(|r| format!("{}ms", r.round() as i64))
                                .unwrap_or_else(|| "—".to_string())
                                .into(),
                            loss: crate::engine_bridge::json_f32(o, "loss").unwrap_or(0.0),
                            samples: crate::engine_bridge::json_i32(o, "samples").unwrap_or(0),
                        })
                        .collect();
                    shell.set_ms_transport_rows(ModelRc::new(VecModel::from(rows)));
                }
                // ── RECENT RESOLVES — tail the RUNNING engine's armed `query-masksolver.log` (its path
                //    bridged over the SAME stats JSON as `mask_log`, since THIS .so's cold MaskSolver is
                //    unbound → its own `query_masksolver_log_path()` is None). T20-safe: the file's rows
                //    are `<epoch> <outcome> <transport> <rtt> <qtype>` — outcome/type tokens only, never a
                //    qname/IP. Non-empty ⇒ overlay the cold read; empty ⇒ leave it.
                if let Some(path) = crate::engine_bridge::json_str(&j, "mask_log") {
                    if !path.trim().is_empty() {
                        let resolves: Vec<crate::MaskRow> =
                            torta_core::log_tail_recent(path, MASK_RESOLVES_SHOWN)
                                .unwrap_or_default()
                                .lines()
                                .rev()
                                .filter(|l| !l.trim().is_empty())
                                .filter_map(parse_mask_row)
                                .collect();
                        if !resolves.is_empty() {
                            shell.set_ms_recent_resolves(ModelRc::new(VecModel::from(resolves)));
                        }
                    }
                }
            }
        }

        // SLINT substitution · 4-FIX round 6 (finding 1) — THE COLD-CONFIG PROOF OVERLAY. On the x86_64
        // emulator the resolver datapath cannot complete (class-c) → NO live traffic counter ever moves,
        // and THIS .so's spike-local resolver is unconfigured, so every field above reads 0 —
        // INDISTINGUISHABLE from an unfed default (the witness gap: unlike Centauri, which carries its
        // real `capacity` + cloaked-host watch-list even cold, MaskSolver surfaced NO non-zero snapshot
        // datum). Surface the REAL configured constants the resolver WILL apply — the per-query DEADLINE
        // (the K5 `timeout`, the exact ms `configure()` clamps to) and the rotation CADENCE (the
        // RESOLVER_ROTATION_CADENCE pref the wheel gates on) — read from the config/pref surfaces that
        // answer engine-COLD (`dnscrypt_config_get` + the TortaPillarBridge, the SAME reads `pillar_rows`
        // and `feed_from_live_rotation` already trust). CONFIG, never fabricated traffic: the deadline +
        // cadence are non-zero cold, proving the feed reaches the pane; the traffic counters stay the
        // honest engine-off zero. Both are `configured`-independent — they do NOT flip the DORMANT crown
        // nor the DEAD-POOL derive (`configured && transports == 0`) — so the honest posture is untouched.
        let cfg = torta_core::dnscrypt_config_get();
        if cfg.timeout > 0 {
            shell.set_ms_timeout_ms(cfg.timeout);
        }
        if let Some(mins) = crate::engine_bridge::rotation_cadence() {
            if mins > 0 {
                shell.set_ms_rotation_cadence_secs(mins.saturating_mul(60));
            }
        }
    }

    /// 2-FEED-MaskSolver SETTINGS — populate the in-shell `MaskSolverSettingsPane` (the `mss-*` aliases)
    /// from the RUNNING engine's control-plane posture, read over the SAME JNI stats bridge the dashboard
    /// overlay uses (`live_resolver_stats()` — libtorta_core.so's LIVE process-globals, NOT this .so's cold
    /// copy). Every toggle/knob shows the ENGINE's REAL state on entry + each 1s tick (never an optimistic
    /// UI echo). Unlike the dashboard, the control-plane posture is read UNCONDITIONALLY (not gated on
    /// `configured`/traffic): the Expert toggle + cache-shape globals are valid the moment the .so loads,
    /// so the pane populates even on a cold/idle engine (the counters just read the honest engine-off zero,
    /// and `configured`/`transports` drive the dead-pool guard). Cold host build (no bridge) ⇒ the cold
    /// slint defaults stand. T20-safe: shapes/bools/counts only — no qname/IP crosses.
    pub(crate) fn feed_masksolver_settings_shell(sh: &crate::TortaShell, tier_dir: &str) {
        if let Some(j) = crate::engine_bridge::live_resolver_stats() {
            use crate::engine_bridge::{json_bool, json_i32};

            // --- POOL POSTURE (the dead-pool guard's legibility source) ---
            sh.set_mss_configured(json_bool(&j, "configured"));
            let seti = |key: &str, f: &dyn Fn(i32)| {
                if let Some(v) = json_i32(&j, key) {
                    f(v);
                }
            };
            seti("transports", &|v| sh.set_mss_transports(v));

            // --- RESOLUTION STRATEGY (the two Object toggles + the derived active-strategy ordinal) ---
            let solve_ladder = json_bool(&j, "solve_ladder_on");
            let all_servers = json_bool(&j, "all_servers_on");
            sh.set_mss_solve_ladder_on(solve_ladder);
            sh.set_mss_all_servers_on(all_servers);
            // The active_strategy() precedence the engine itself applies (mod.rs/pool.rs): the SOLVE
            // resilient ladder (health-ordered ⇒ Fastest=2) wins over the --all-servers race (AllServers=1)
            // which wins over the sequential default (StrictOrder=0). Derived from the SAME two toggles the
            // engine reads, so the ordinal + the toggles can never disagree (round-robin is not a MaskSolver
            // pane strategy, so it is not surfaced here).
            let strategy = if solve_ladder {
                2
            } else if all_servers {
                1
            } else {
                0
            };
            sh.set_mss_strategy(strategy);

            // The per-query deadline: the LIVE override (query_timeout_ms) when armed, else the config-carried
            // `timeout` the resolver clamps to (the SAME cold-honest read the dashboard uses).
            let live_timeout = json_i32(&j, "query_timeout_ms").unwrap_or(0);
            if live_timeout > 0 {
                sh.set_mss_timeout_ms(live_timeout);
            } else {
                let cfg = torta_core::dnscrypt_config_get();
                if cfg.timeout > 0 {
                    sh.set_mss_timeout_ms(cfg.timeout);
                }
            }

            // --- CACHE (size · serve-stale · TTL — the durable Expert intents + the live fill witness) ---
            // ★ #80 — THE STEPPER'S INTENT MUST SURVIVE THE REFRESH TICK.
            // `set_resolver_cache_cap` is STAGED (see lib.rs:2084 — "commits on reapply"), so between a
            // step and a reapply the LIVE snapshot still reports the OLD cap — 0 on a fresh install.
            // Writing that 0 straight into the property made every `+` visibly snap back to `0b`: the
            // user stepped to 256, the next refresh tick overwrote it, and the panel never populated.
            // `timeout` three lines above already guards exactly this way (live-or-fallback, never
            // zero-clobber); `cache_cap` was the one stepper missing the guard. A 0 here means "the
            // resolver has not committed a cap yet", NOT "the user wants zero" — so keep what is
            // staged and let a real, non-zero engine value win.
            // ★ #91 — …AND WHEN THE ENGINE HAS NO LIVE VALUE, THE RECORD IS THE TRUTH.
            // #80 stopped the zero-clobber but left no fallback, so a not-yet-committed cap left the
            // Slint default showing (measured: panel 1024 while the record held 4096). Once #90 made
            // the steppers write through, that wrong at-rest base got PERSISTED — a step computed
            // from the default overwrote the durable value. Same live-or-record shape `timeout` uses
            // thirty lines above; this is the house pattern restored, not a new one.
            if let Some(v) = json_i32(&j, "cache_cap").filter(|v| *v > 0) {
                sh.set_mss_cache_cap(v);
            } else {
                let cfg = torta_core::dnscrypt_config_get();
                if cfg.cache_size > 0 {
                    sh.set_mss_cache_cap(cfg.cache_size);
                }
            }
            seti("cache", &|v| sh.set_mss_cache_entries(v));
            // ★ #92 — serve-stale now HAS a home in the authority, so it seeds like its four siblings.
            // Until this field existed it could only ever read the live value, which is why it was the
            // one stepper #91 could not repair.
            let stale_secs = match json_i32(&j, "serve_stale_secs").filter(|v| *v > 0) {
                Some(v) => v,
                None => torta_core::dnscrypt_config_get().serve_stale_secs.max(0),
            };
            sh.set_mss_serve_stale_secs(stale_secs);
            sh.set_mss_serve_stale_on(stale_secs > 0);
            seti("serve_stale_served", &|v| sh.set_mss_serve_stale_served(v));
            // ★ #91 — the TTL clamps were the worst case: a BARE `seti` wrote the live 0 straight into
            // the prop. Device-measured: record `cache_min_ttl = 2400`, panel "0s", two `+` taps ->
            // record `cache_min_ttl = 60`. The user's 2400 was destroyed by a step computed from 0.
            // A live 0 means "no clamp reported yet", NOT "the user wants none".
            if let Some(v) = json_i32(&j, "ttl_floor_secs").filter(|v| *v > 0) {
                sh.set_mss_ttl_floor_secs(v);
            } else {
                let cfg = torta_core::dnscrypt_config_get();
                if cfg.cache_min_ttl > 0 {
                    sh.set_mss_ttl_floor_secs(cfg.cache_min_ttl);
                }
            }
            if let Some(v) = json_i32(&j, "ttl_ceiling_secs").filter(|v| *v > 0) {
                sh.set_mss_ttl_ceiling_secs(v);
            } else {
                let cfg = torta_core::dnscrypt_config_get();
                if cfg.cache_max_ttl > 0 {
                    sh.set_mss_ttl_ceiling_secs(cfg.cache_max_ttl);
                }
            }

            // --- SECURITY GUARD (the P12 rebind protection toggle + its observed/rejected witnesses) ---
            sh.set_mss_rebind_protect_on(json_bool(&j, "rebind_enforce_on"));
            seti("rebind_observed", &|v| sh.set_mss_rebind_observed(v));
            seti("rebind_rejected", &|v| sh.set_mss_rebind_rejected(v));

            // --- EXPERT (the raw P12 knobs behind the reveal — each a live process-global toggle) ---
            sh.set_mss_bogus_priv_on(json_bool(&j, "bogus_priv_on"));
            sh.set_mss_proxy_dnssec_on(json_bool(&j, "proxy_dnssec_on"));
            sh.set_mss_never_forward_on(json_bool(&j, "never_forward_on"));
            sh.set_mss_cache_rr_on(json_bool(&j, "cache_rr_on"));
        }

        // --- ROTATION (the 12h-diversity cadence — Kotlin RotationManager owned; the SAME cold-honest read
        //     the dashboard + `feed_from_live_rotation` trust, so the cadence is non-zero even engine-cold). ---
        if let Some(mins) = crate::engine_bridge::rotation_cadence() {
            if mins > 0 {
                sh.set_mss_rotation_cadence_secs(mins.saturating_mul(60));
            }
        }
        // ★ #69 — the diversity family was DECLARED and rendered but NEVER fed. `masksolver_settings.slint`
        // :602 prints `ROTATION (<family> diversity)` with a `!= "" ? … : "cold"` fallback, and because no
        // Rust code ever set `mss_rotation_family` the header read "cold diversity" FOREVER — including
        // right after a real flip. The engine has carried the value the whole time
        // (`RotationSnapshot.last_family`, resolver/object.rs:228, persisted + parsed in rotation.rs:164/192).
        // Empty stays empty on purpose: "" is the genuine cold state and the .slint already renders it.
        // Read the family from the DURABLE RECORD by dir, not from a fresh `MaskSolver::new()` — an
        // unbound Object has `durable_dir = None` and `rotation_snapshot()` then returns
        // `cold_rotation_snapshot()` (object.rs:762-767), i.e. last_family "" no matter what is on disk.
        // That is exactly why this header read "cold diversity" on device while the record held
        // `family=dnscry`. `rehydrate_resolver_rotation` returns the same summary blob Kotlin parses at
        // RotationManager.kt:592 (`parseField(summary, "family")`) — one authority, one parse shape.
        // Empty stays empty: "" IS the honest cold state and the .slint already renders it as "cold".
        // ★ PREFER THE RUNNING MANAGER OVER THE LAST-PERSISTED RECORD. `live_rotation_state()`
        // (lib.rs:2597) is the house-sanctioned cross-.so read — its own doc names this very gap:
        // "the OTHER pillars bridged in round 1/3, ROTATION WAS LEFT ON THE SPIKE SEED". It returns
        // the LIVE RotationManager cursor, PIPE-separated ("family=<f>|cadence_secs=<n>|index=<n>|…"),
        // so it is fresher than the durable record, which only shows the last COMMITTED flip.
        // Different function, different delimiter: this one splits on '|', the durable summary below
        // splits on whitespace. Both are measured, neither is assumed.
        // The durable read stays as the fallback: `None` here means the bridge is unreachable or no
        // Object is armed (base .so), and the on-disk record is then the honest best answer — the
        // path already device-proven to render `dnscry`. Live first, proven second, cold last.
        let fam_live = crate::engine_bridge::live_rotation_state().and_then(|s| {
            s.split('|')
                .find_map(|tok| tok.strip_prefix("family=").map(|v| v.to_string()))
                .filter(|v| !v.is_empty())
        });
        let fam = fam_live.or_else(|| torta_core::rehydrate_resolver_rotation(tier_dir.to_string())
            // The summary is a SPACE-separated one-liner ("family=dnscry cadence=1800 index=1
            // hints=3"), NOT the raw CRLF record — device-verified: a line-oriented parse captured the
            // whole blob and rendered "dnscry cadence=1800 index=1 hints=3". Tokenize on whitespace,
            // exactly as Kotlin's parseField does (RotationManager.kt:592).
            .and_then(|summary| {
                summary
                    .split_whitespace()
                    .find_map(|tok| tok.strip_prefix("family=").map(|v| v.to_string()))
            }))
            .unwrap_or_default();
        sh.set_mss_rotation_family(fam.into());
    }

    /// 2-FEED-Rotation (SETTINGS): push the CURRENT rotation posture onto the shell's `rset-*` aliases. The
    /// wheel is HOST/Kotlin-owned (the NO-FORK consensus — this .so holds no live rotation cursor), so every
    /// field is read over the JNI bridge (the SAME seams the Rotation dashboard + `feed_from_live_rotation`
    /// trust): the durable rotation cursor (`live_rotation_state` — family + diversity index, `None` ⇒ the
    /// honest cold baseline) and the two `RESOLVER_ROTATION_*` prefs (cadence minutes + enabled). `pinned` is
    /// the INVERSE of enabled (pin ON == the wheel holds one family). `configured` (armed) is honest-derived:
    /// a durable cursor OR a live resolver pool proves it; a cold read is DORMANT (the controls stage for the
    /// next start). `expert-open` is self-managed by the pane (never overwritten here). Fail-open — a JNI
    /// hiccup leaves the honest cold baseline, never a fabricated wheel. Mirrors `feed_masksolver_settings_shell`.
    pub(crate) fn feed_rotation_settings_shell(sh: &crate::TortaShell) {
        use crate::engine_bridge::{json_bool, rot_field_i64, rot_field_str};

        // ── family + diversity index: the REAL durable cursor over JNI (cold/never-rotated ⇒ honest empty) ──
        let mut family = String::new();
        let mut index: i32 = 0;
        let mut have_record = false;
        if let Some(rec) = crate::engine_bridge::live_rotation_state() {
            have_record = true;
            family = rot_field_str(&rec, "family");
            if let Some(v) = rot_field_i64(&rec, "index") {
                index = v.clamp(0, i64::from(i32::MAX)) as i32;
            }
        }
        sh.set_rset_rotation_family(family.clone().into());
        sh.set_rset_rotation_index(index);

        // ── cadence: the PREF is authoritative (the selector writes RESOLVER_ROTATION_CADENCE_MINUTES) —
        //    minutes -> seconds; the pane decodes to plain words. Cold/unreadable ⇒ the 30-min default. ──
        let cadence_secs = crate::engine_bridge::rotation_cadence()
            .filter(|m| *m > 0)
            .map(|m| m.saturating_mul(60))
            .unwrap_or(1800);
        sh.set_rset_cadence_secs(cadence_secs);

        // ── pinned: pin ON == rotation DISABLED (the inverse of RESOLVER_ROTATION_ENABLED; default enabled) ──
        let pinned = !crate::engine_bridge::rotation_enabled().unwrap_or(true);
        sh.set_rset_pinned(pinned);

        // ── configured (armed): a durable cursor OR a live resolver pool proves it; else DORMANT (stage). ──
        let resolver_up = crate::engine_bridge::live_resolver_stats()
            .as_deref()
            .map(|j| json_bool(j, "configured"))
            .unwrap_or(false);
        sh.set_rset_configured(have_record || resolver_up);
        // expert-open: self-managed by the pane (the reveal is a local UI choice, not engine truth).
    }

    /// #49 — the host-pure BEAST preset table (0 DEFAULT · 1 FAST_PING · 2 OMEGA_BANDWIDTH ·
    /// 3 UPLOAD_DOWNLOAD) resolved per field (0 cycleMs · 1 maxWindow · 2 freeThreshMilli ·
    /// 3 competeThreshMilli). PURE RUST — NO Haskell muscle (the `libtorta_hs.so` `torta_hs_beast_preset`
    /// path is RETIRED); these are the canonical goal->tunables the overhauled Yeah TCP/UDP Beast
    /// documents. An out-of-range field -> -1 (the caller keeps its current value).
    fn beast_preset_host(preset: i32, field: i32) -> i32 {
        // rows: [cycleMs, maxWindow, freeThreshMilli, competeThreshMilli]
        let row: [i32; 4] = match preset {
            1 => [3000, 8, 1020, 1150],  // FAST_PING — latency-first (tight cycle, small window)
            2 => [5000, 32, 1100, 1500], // OMEGA_BANDWIDTH — throughput-first (large tolerant window)
            3 => [4000, 24, 1050, 1400], // UPLOAD_DOWNLOAD — big window, brisk cadence
            _ => [5000, 16, 1050, 1250], // DEFAULT — balanced, as-built (the recommended gaming beast)
        };
        match field {
            0..=3 => row[field as usize],
            _ => -1,
        }
    }

    /// #49 — the host-pure BEAST Expert safe-range clamp (field 0 cycleMs 1000..60000 · 1 maxWindow
    /// 2..64 · 2 freeThreshMilli 1000..2000 · 3 competeThreshMilli 1010..3000). PURE RUST (Haskell
    /// retired). An unknown field passes `raw` through unchanged.
    fn beast_clamp_host(field: i32, raw: i32) -> i32 {
        match field {
            0 => raw.clamp(1000, 60000),
            1 => raw.clamp(2, 64),
            2 => raw.clamp(1000, 2000),
            3 => raw.clamp(1010, 3000),
            _ => raw,
        }
    }

    /// #49 — persist the pane's CURRENT staged Beast selection (all 7 fields) to the durable BEAST_*
    /// prefs. Called on every pick/step so the selection survives restart the #51 way, WITHOUT touching
    /// the live engine (that is Apply's job).
    fn stage_beast_from_shell(sh: &crate::TortaShell) {
        crate::engine_bridge::stage_beast_config(
            sh.get_bset_yeah_profile(),
            sh.get_bset_cake_profile(),
            sh.get_bset_preset(),
            sh.get_bset_cycle_ms(),
            sh.get_bset_max_window(),
            sh.get_bset_free_thresh_milli(),
            sh.get_bset_compete_thresh_milli(),
        );
    }

    /// #49 THE BEAST SETTINGS feed — populate the `bset-*` aliases from (a) the LIVE overhauled
    /// process-global Beast snapshot (cwnd/mode/base_rtt + the true running Yeah/Soft-cake profiles) and
    /// (b) the durable STAGED selection (BEAST_* prefs). Cold/never-staged ⇒ SEED the staged fields off
    /// the live engine so the pane opens in agreement (profile-dirty false). `profile-dirty` is derived
    /// live (staged brain/queue/window vs what the engine actually runs) so it self-clears after Apply.
    pub(crate) fn feed_beast_settings_shell(sh: &crate::TortaShell) {
        use crate::engine_bridge::{
            live_beast_stats, rot_field_f64, rot_field_i64, rot_field_str, staged_beast_config,
        };

        // ── LIVE witnesses off the overhauled Beast (absent ⇒ the honest engine defaults so the pane
        //    still populates: LineRate brain (2) × SoftCake/CoBALT queue (1) — what `live_beast()` builds). ──
        let live = live_beast_stats();
        let (live_yeah, live_cake, live_cwnd, live_mode, live_base_rtt, live_maxwin) = match &live {
            Some(rec) => (
                rot_field_i64(rec, "yeah_profile").unwrap_or(2) as i32,
                // sched_profile 2 SoftCake -> pane cake 1 CoBALT; else 0 Legacy-AQM.
                if rot_field_i64(rec, "sched_profile").unwrap_or(2) >= 2 {
                    1
                } else {
                    0
                },
                rot_field_i64(rec, "cwnd").unwrap_or(0) as i32,
                rot_field_str(rec, "mode"),
                rot_field_f64(rec, "base_rtt").unwrap_or(0.0) as f32,
                rot_field_i64(rec, "window_max").unwrap_or(0) as i32,
            ),
            None => (2, 1, 0, String::new(), 0.0, 0),
        };

        // Live witnesses (read-only truth) — always painted.
        sh.set_bset_cwnd(live_cwnd);
        sh.set_bset_mode(live_mode.into());
        sh.set_bset_base_rtt_ms(live_base_rtt);

        // ── STAGED selection (the editable state) — durable BEAST_* prefs are the source of truth; cold
        //    (never staged) ⇒ seed from live + the DEFAULT preset tunables so the pane opens coherent. ──
        let staged = staged_beast_config();
        let (yeah, cake, preset, cycle_ms, max_window, free_m, compete_m) = match &staged {
            Some(rec) => (
                rot_field_i64(rec, "yeah").unwrap_or(live_yeah as i64) as i32,
                rot_field_i64(rec, "cake").unwrap_or(live_cake as i64) as i32,
                rot_field_i64(rec, "preset").unwrap_or(0) as i32,
                rot_field_i64(rec, "cycle").unwrap_or_else(|| beast_preset_host(0, 0) as i64) as i32,
                rot_field_i64(rec, "maxwin").unwrap_or_else(|| {
                    if live_maxwin > 0 {
                        live_maxwin as i64
                    } else {
                        beast_preset_host(0, 1) as i64
                    }
                }) as i32,
                rot_field_i64(rec, "free").unwrap_or_else(|| beast_preset_host(0, 2) as i64) as i32,
                rot_field_i64(rec, "compete").unwrap_or_else(|| beast_preset_host(0, 3) as i64)
                    as i32,
            ),
            None => (
                live_yeah,
                live_cake,
                0,
                beast_preset_host(0, 0),
                if live_maxwin > 0 {
                    live_maxwin
                } else {
                    beast_preset_host(0, 1)
                },
                beast_preset_host(0, 2),
                beast_preset_host(0, 3),
            ),
        };
        sh.set_bset_yeah_profile(yeah);
        sh.set_bset_cake_profile(cake);
        sh.set_bset_preset(preset);
        sh.set_bset_cycle_ms(cycle_ms);
        sh.set_bset_max_window(max_window);
        sh.set_bset_free_thresh_milli(free_m);
        sh.set_bset_compete_thresh_milli(compete_m);

        // profile-dirty: a staged change awaits Apply — the staged brain/queue/window differs from what
        // the LIVE engine actually runs (self-clearing: after Apply the next feed reads them equal). Only
        // meaningful when the datapath is live (a cold engine has nothing to diverge from).
        let dirty = live.is_some()
            && (yeah != live_yeah
                || cake != live_cake
                || (live_maxwin > 0 && max_window != live_maxwin));
        sh.set_bset_profile_dirty(dirty);
        // tunable-clamped + expert-open are self-managed by the handlers / pane (local UI state).
    }

    /// The per-pillar rows BOTH the shell's ① HOME health chips and the burger's private tabs render.
    /// SLINT substitution · 4-FIX-1: HONEST LIVE/OFF ONLY, read over the JNI bridge from the RUNNING
    /// engine (`libtorta_core.so` process-globals) — NOT THIS .so's cold spike-local copy. A running
    /// pillar shows LIVE + real numbers; a stopped one shows an honest OFF with a "start it on HOME"
    /// affordance. The "(spike-local instance)" + "live feed lands with the single-.so unification"
    /// placeholders are RETIRED (the Socio's truth law — no cold copy dressed as live). ONE row builder
    /// so the HOME chips + the burger tabs can never disagree.
    fn pillar_rows() -> Vec<crate::PillarTabRow> {
        use crate::engine_bridge::{json_bool, json_i32};
        // The LIVE engine reads (fail-open to OFF — a JNI hiccup never fabricates a running pillar).
        let rstats = crate::engine_bridge::live_resolver_stats();
        // ★ THE LIVE GATE — a row may claim LIVE only if the ENGINE IS RUNNING.
        //
        // MEASURED defect, and it cost two whole 111-URL runs: with the master switch OFF and HOME
        // showing "THE TUNNEL IS DOWN", these rows still read "LIVE — firewall armed",
        // "LIVE — offline-CDN serving" and "LIVE — resolver running". Every flag below was built
        // from a CONFIGURATION read, not a liveness read:
        //   * warden   `configured`                  -- rules exist, says nothing about running
        //   * resolver `configured || queries > 0`   -- `queries` is CUMULATIVE, so it stays true
        //                                               forever once the engine has ever answered
        //   * centauri `libraries > 0`               -- assets are CACHED, not being served
        // Two void measurement runs looked plausible precisely because of this, so the overclaim
        // was not cosmetic: it defeated the operator's own check.
        //
        // `tunnel_up()` is the single liveness authority (HOME's crown already owns it). Fail-open
        // to NOT-live: a JNI hiccup must never fabricate a running pillar, which is the same
        // direction the existing reads already fail.
        let engine_up = crate::engine_bridge::tunnel_up().unwrap_or(false);
        let resolver_live = engine_up
            && rstats
                .as_deref()
                .map(|j| json_bool(j, "configured") || json_i32(j, "queries").unwrap_or(0) > 0)
                .unwrap_or(false);
        // The WIRE CAKE INU posture off the DURABLE record (one read per row build; the ctor is IO-free
        // by the no-boot-IO-scan law, so this costs nothing on a refresh tick).
        let inu_posture = crate::inu_row_posture();
        let wstats = crate::engine_bridge::live_warden_stats();
        let warden_live = engine_up && wstats
            .as_deref()
            .map(|j| json_bool(j, "configured"))
            .unwrap_or(false);
        let warden_deny = wstats
            .as_deref()
            .and_then(|j| json_i32(j, "deny"))
            .unwrap_or(0);
        // SLINT substitution · 4-FIX-2: the CENTAURI live cross-.so read (the gap round 1 left OFF). The
        // running libtorta_core.so mirror store, bridged over JNI (`mirror_status()`); ≥1 cached library ⇒
        // the offline CDN is live-serving. Unreachable / cold ⇒ 0 ⇒ the honest OFF (never a fabricated tally).
        let cen_libraries = crate::engine_bridge::live_mirror_status()
            .and_then(|m| crate::engine_bridge::kv_i64(&m, "libraries"))
            .unwrap_or(0);
        let centauri_live = engine_up && cen_libraries > 0;
        // The shared OFF affordance for the engine-plane pillars (they ride the running DNSCrypt tunnel).
        let off = "OFF — start DNSCrypt on HOME";
        // The DNSCrypt pillar's dashboard is a CONFIG surface (the K5 typed authority) answered by THIS
        // .so directly — a REAL read, never an engine-running claim (HOME's crown owns "the tunnel is up").
        let dnscrypt_cfg = torta_core::dnscrypt_config_get();
        vec![
            crate::PillarTabRow {
                id: "warden".into(),
                name: "WARDEN".into(),
                blurb: "the per-app firewall courtroom".into(),
                status: if warden_live {
                    format!("LIVE — firewall armed · {warden_deny} denied").into()
                } else {
                    // The affordance MUST name the pane that can actually do it. This said "arm it
                    // in WARDEN settings", and WARDEN SETTINGS HAS NO ARM CONTROL: the
                    // `arm-warden(bool)` callback exists only in warden.slint (the DASHBOARD, whose
                    // ARMED/DISARMED chip is at :533). warden_settings.slint carries the posture,
                    // the nine universal blocks and the rules editor -- and no way to arm.
                    //
                    // Measured end-to-end on the AVD: armed Lockdown + Block UDP-NTP in WARDEN
                    // SETTINGS (persisted -- the on-disk bitfield read 0x0048 = 72 = 8 + 64,
                    // exactly the disjoint-bit sum Proofs/WardenToggleBits.lean models), started the
                    // engine, and this row still read "firewall disarmed (arm it in WARDEN
                    // settings)". The user has done precisely what it asks and it keeps asking.
                    //
                    // The datapath arm is a SEPARATE pref (WARDEN_NATIVE_ENABLED, default OFF since
                    // d36a30c0), mirrored into the engine at tunnel bring-up by ServiceVPN -- which
                    // logged `Warden datapath arm-on-tunnel: pref=false landed=true` while the nine
                    // toggles were set. Rules configured and datapath armed are two different
                    // things, and the old text conflated them.
                    "OFF — rules stay saved; arm the firewall on the WARDEN dashboard".into()
                },
                live: warden_live,
                accent: slint::Color::from_rgb_u8(0xd8, 0x3a, 0x2c),
            },
            crate::PillarTabRow {
                id: "centauri".into(),
                name: "CENTAURI".into(),
                blurb: "the offline-CDN constellation".into(),
                // 4-FIX-2: the LIVE mirror-store read over the JNI bridge (mirror_status()). ≥1 cached
                // library ⇒ LIVE with the real count; cold/unreachable ⇒ the honest OFF, never a cold
                // spike-local tally dressed as live (the Socio's truth law).
                status: if centauri_live {
                    format!("LIVE — offline-CDN serving · {cen_libraries} cached").into()
                } else {
                    "OFF — offline-CDN idle (serves once cached + running)".into()
                },
                live: centauri_live,
                accent: slint::Color::from_rgb_u8(0x28, 0xc8, 0xd8),
            },
            crate::PillarTabRow {
                id: "masksolver".into(),
                name: "MASKSOLVER".into(),
                blurb: "the resolver & warm cache".into(),
                status: if resolver_live {
                    "LIVE — resolver running".into()
                } else {
                    off.into()
                },
                live: resolver_live,
                accent: slint::Color::from_rgb_u8(0xa7, 0x8b, 0xfa),
            },
            crate::PillarTabRow {
                id: "beast".into(),
                name: "BEAST".into(),
                blurb: "Tortä × YeAH TCP/UDP flow engine".into(),
                status: if resolver_live {
                    "LIVE — shaping the running tunnel".into()
                } else {
                    off.into()
                },
                live: resolver_live,
                accent: slint::Color::from_rgb_u8(0xff, 0xb4, 0x54),
            },
            crate::PillarTabRow {
                id: "rotation".into(),
                name: "ROTATION".into(),
                blurb: "rotates your DNS servers".into(),
                status: if resolver_live {
                    "LIVE — rotating the resolver pool".into()
                } else {
                    off.into()
                },
                live: resolver_live,
                accent: slint::Color::from_rgb_u8(0x5e, 0x8b, 0xff),
            },
            crate::PillarTabRow {
                id: "inu".into(),
                name: "WIRE CAKE INU".into(),
                blurb: "no-root ADB self-elevation".into(),
                // WAS A HARDCODED LITERAL (`"OFF — ADB elevation idle"`, `live: false`) — the row could
                // never go live whatever the user's own record said, which is exactly why every
                // on-device run counted 8 pillars and not 9. Now read off the DURABLE record via
                // `inu_row_posture()`: `live` only for a genuinely held privileged session, never for
                // the seeded spike, an absent record, a mid-flight arm, or a failure. INU's truth is
                // durable, not live-counted, so no Kotlin static is needed.
                status: inu_posture.0.clone().into(),
                live: inu_posture.1,
                accent: slint::Color::from_rgb_u8(0x34, 0xb3, 0xa4),
            },
            crate::PillarTabRow {
                id: "dnscrypt".into(),
                name: "DNSCRYPT".into(),
                blurb: "the encrypted-DNS resolver config".into(),
                // A REAL read of the K5 typed authority backs the status (the config store answers
                // this .so — not a claim the tunnel is up; that is HOME's engine crown). The status
                // names the HONEST posture, the accent is the namesake candle-gold
                // (dnscrypt_section.slint Candle.candle #e7ad42).
                //
                // HONESTY OVERHAUL (Task #8): the old text read "0 server-name pin(s)" whenever the
                // pool ran source-driven auto-pick (server_names empty by default) — understated + it
                // read as broken. The pool was never empty: the LIVE ledger's `transports` count is
                // the rtt-ranked upstreams actually resolving. So when the engine is live we name the
                // real upstream count (± any explicit hand-pins); cold, we name the pins or the honest
                // auto-pick posture. The bare "0" is gone from every branch.
                status: {
                    let servers = dnscrypt_cfg.server_names.len();
                    // The relay tally is the total relay HOPS committed across every anon route
                    // (`Route{server_name, via}` — 10 relays/server in a full rotation). Sum of `via`,
                    // NOT route count, so the operator sees the real relay budget they hold.
                    let relays: usize = dnscrypt_cfg
                        .anonymized_dns
                        .routes
                        .iter()
                        .map(|r| r.via.len())
                        .sum();
                    let live_up = rstats
                        .as_deref()
                        .and_then(|j| json_i32(j, "transports"))
                        .unwrap_or(0);
                    if servers > 0 || relays > 0 {
                        // Committed pins (hand-pick OR a committed rotation) — name servers vs relays
                        // DISTINCTLY so the operator always knows how many of EACH they hold (Socio: the
                        // count must never collapse into one ambiguous "pins" number).
                        format!("K5 · {servers} servers · {relays} relays pinned")
                    } else if resolver_live && live_up > 0 {
                        // No committed pins ⇒ the Rotation pillar's source-driven auto-pick is serving;
                        // name the LIVE upstream count (the real pool), never a bare misleading "0".
                        format!("K5 live · {live_up} upstreams · rotation auto-pick")
                    } else {
                        "K5 config reachable · rotation auto-pick".to_string()
                    }
                }
                .into(),
                live: true,
                accent: slint::Color::from_rgb_u8(0xe7, 0xad, 0x42),
            },
            // #15 UNDERGROUND H — the 8th pillar row, seated DIRECTLY UNDER DNSCRYPT (the
            // standing directive): the DNSCrypt-native antivirus in his OWN space. A REAL
            // cross-.so read backs the status (the LIVE licence store over the pillar bridge);
            // cold/dormant ⇒ the honest OFF (the store arms on the resolver boot edge).
            {
                let ug = crate::engine_bridge::live_underground_stats().unwrap_or_default();
                let ug_armed = crate::engine_bridge::rot_field_bool(&ug, "armed");
                let ug_total = crate::engine_bridge::rot_field_i64(&ug, "total").unwrap_or(0);
                let ug_seq =
                    crate::engine_bridge::rot_field_i64(&ug, "sequestrated").unwrap_or(0);
                crate::PillarTabRow {
                    id: "underground".into(),
                    name: "UNDERGROUND LAYER".into(),
                    blurb: "the DNSCrypt-native antivirus".into(),
                    status: if ug_armed {
                        format!("LIVE · {ug_total} licences · {ug_seq} sequestrated")
                    } else {
                        "OFF — arms with the resolver boot".to_string()
                    }
                    .into(),
                    live: ug_armed,
                    accent: slint::Color::from_rgb_u8(0x2f, 0xe2, 0x6a),
                }
            },
            // ★ #49 — the NETSTACK FORWARDER row. NOT a ninth pillar: it is the ENGINE PLANE's
            // datapath, the packet mover every pillar above rides on, and it says so in its own
            // blurb. It earns a row on this rail because the rail is where dashboards are reached,
            // and #47's per-flow docket had no door until now.
            //
            // The status is a REAL cross-.so read of the running forwarder (the same bridge record
            // the ENGINE card parses). Three postures, because they demand three different
            // responses: DORMANT (switched off), ARMED-but-not-live (latches next tunnel start),
            // LIVE (with the flows it is actually carrying right now).
            {
                let fw = crate::engine_bridge::live_forwarder_stats().unwrap_or_default();
                let fw_armed = crate::engine_bridge::rot_field_bool(&fw, "armed");
                let fw_live = crate::engine_bridge::rot_field_bool(&fw, "live");
                let fw_active =
                    crate::engine_bridge::rot_field_i64(&fw, "active_flows").unwrap_or(0);
                let fw_paced =
                    crate::engine_bridge::rot_field_i64(&fw, "paced_flows").unwrap_or(0);
                // The HOST PREF, not the snapshot: with the tunnel down the snapshot reports
                // `armed=false` even when the operator HAS armed the switch, and telling them to go
                // arm it again would be false advice about their own device.
                let fw_pref = crate::engine_bridge::netstack_forwarder_armed().unwrap_or(false);
                crate::PillarTabRow {
                    id: "forwarder".into(),
                    name: "NETSTACK FORWARDER".into(),
                    blurb: "the CAKE-shaped datapath under every pillar".into(),
                    status: if fw_live {
                        format!("LIVE · {fw_active} active flow(s) · {fw_paced} shaped")
                    } else if fw_armed {
                        "ARMED — the accept loop starts with the next tunnel".to_string()
                    } else if fw_pref {
                        "ARMED — waiting on the engine; start it on HOME".to_string()
                    } else {
                        "OFF — arm the netstack forwarder on the ENGINE tab".to_string()
                    }
                    .into(),
                    live: fw_live,
                    // THE CARBON RING's cyan (theme_tokens.slint `carbon.accent` #8be9fd) — the
                    // engine-plane identity this dashboard wears, so the chip and the room match.
                    accent: slint::Color::from_rgb_u8(0x8b, 0xe9, 0xfd),
                }
            },
        ]
    }

    /// Push the honest pillar rows onto the burger's private tabs (the D2 surface — the shell's
    /// HOME chips take the SAME rows in [`feed_home`]).
    fn feed_pillar_tabs(burger: &crate::AdvancedBurger) {
        burger.set_pillar_tabs(ModelRc::new(VecModel::from(pillar_rows())));
    }

    /// Build the SLINT server-picker model from the signed `public-resolvers.md` — the DNSCrypt + DoH
    /// entries (the two server TYPES the pool draws from), each `pinned` iff its name is in the live
    /// config's `server_names`. Pure-Rust list scan per the ARC; a missing/unreadable file yields an
    /// empty model (the picker shows nothing rather than failing — the resolver's fail-open posture).
    fn build_server_rows(
        md_path: &str,
        cfg: &torta_core::DnscryptProxyConfig,
    ) -> ModelRc<crate::PickerRow> {
        let pinned: std::collections::HashSet<&str> =
            cfg.server_names.iter().map(String::as_str).collect();
        let rows: Vec<crate::PickerRow> =
            torta_core::resolver_list_picker_entries(md_path.to_string())
                .into_iter()
                // ★ LIVE-WIRED: the picker shows ONLY the servers matching the current config — the
                // enabled server TYPES (dnscrypt_servers / doh_servers) AND the armed REQUIREMENTS
                // (require_dnssec/nolog/nofilter satisfied by the stamp props). So DNSCrypt-only +
                // DNSSEC+no-log+no-filter armed ⇒ the list is exactly the pure-DNSCrypt DNSSEC set.
                .filter(|e| {
                    let type_ok = (e.proto == "dnscrypt" && cfg.dnscrypt_servers)
                        || (e.proto == "doh" && cfg.doh_servers)
                        || (e.proto == "odoh" && cfg.odoh_servers);
                    let req_ok = (!cfg.require_dnssec || e.dnssec)
                        && (!cfg.require_nolog || e.no_log)
                        && (!cfg.require_nofilter || e.no_filter);
                    // ADDRESS-FAMILY gate (Slice B): decode the stamp's family host-side (pure Rust,
                    // off the FFI) and keep the row iff an ENABLED family can reach it. Unknown
                    // (hostname-addressed — ODoH targets, hostname DoH) → (true,true), so it rides
                    // either toggle and is never family-hidden. Default cfg (ipv4=true, ipv6=false) ⇒
                    // V4 + Unknown show, V6-literal hides — byte-for-byte the upstream dnscrypt-proxy
                    // family posture, now MIRRORED into the picker the operator actually sees.
                    let (v4, v6) = torta_core::stamp_addr_family(&e.stamp);
                    let family_ok = (cfg.ipv4_servers && v4) || (cfg.ipv6_servers && v6);
                    type_ok && req_ok && family_ok
                })
                .map(|e| crate::PickerRow {
                    pinned: pinned.contains(e.name.as_str()),
                    hint: "".into(),
                    name: e.name.into(),
                    proto: e.proto.into(),
                    stamp: e.stamp.into(),
                })
                .collect();
        ModelRc::new(VecModel::from(rows))
    }

    /// Count how many resolvers each relay rides across ALL `anonymized_dns.routes` — the substrate
    /// of Socio's #22 s5B overload guard: "using same Relays with the same Resolver more times can
    /// lead to 404 error, because u overload them to request multiple resolver". A relay riding ≥2
    /// resolvers earns a visible "rides N resolvers" hint so the operator SPREADS instead of stacks.
    fn relay_ride_counts(
        cfg: &torta_core::DnscryptProxyConfig,
    ) -> std::collections::HashMap<String, usize> {
        let mut rides = std::collections::HashMap::new();
        for r in cfg.anonymized_dns.routes.iter() {
            for v in r.via.iter() {
                *rides.entry(v.clone()).or_insert(0) += 1;
            }
        }
        rides
    }

    /// Render one relay's overload hint from its ride count — "" below the 2-resolver threshold.
    fn overload_hint(rides: &std::collections::HashMap<String, usize>, name: &str) -> slint::SharedString {
        match rides.get(name).copied().unwrap_or(0) {
            n if n >= 2 => format!("rides {n} resolvers").into(),
            _ => "".into(),
        }
    }

    /// Build the SLINT relay-picker model from the signed `relays.md` — each 0x81 relay `pinned` iff
    /// it appears in ANY `anonymized_dns.routes` via-list (the whole-pool relay model the pin handler
    /// writes). Pure-Rust scan; empty on a read miss. The relay twin of [`build_server_rows`].
    /// #22 s5B: FILTER-AWARE like the server picker — the family gate (ipv4/ipv6 chips) narrows the
    /// list by the relay stamp's address family (relays carry no dnssec/no-log props, so family is
    /// the one criteria that applies to a hop); an armed relay always shows (never hide a live route
    /// from its owner). Each row carries the [`overload_hint`] ride-count note.
    fn build_relay_rows(
        md_path: &str,
        cfg: &torta_core::DnscryptProxyConfig,
    ) -> ModelRc<crate::PickerRow> {
        let pinned: std::collections::HashSet<String> = cfg
            .anonymized_dns
            .routes
            .iter()
            .flat_map(|r| r.via.iter().cloned())
            .collect();
        let rides = relay_ride_counts(cfg);
        let rows: Vec<crate::PickerRow> =
            torta_core::resolver_list_picker_entries(md_path.to_string())
                .into_iter()
                .filter(|e| {
                    let (v4, v6) = torta_core::stamp_addr_family(&e.stamp);
                    let family_ok = (cfg.ipv4_servers && v4) || (cfg.ipv6_servers && v6);
                    family_ok || pinned.contains(&e.name)
                })
                .map(|e| crate::PickerRow {
                    pinned: pinned.contains(&e.name),
                    hint: overload_hint(&rides, &e.name),
                    name: e.name.into(),
                    proto: e.proto.into(),
                    stamp: e.stamp.into(),
                })
                .collect();
        ModelRc::new(VecModel::from(rows))
    }

    /// #22 s5B (Socio): "user must be capable to choose manually from the list, which Relay based on
    /// his filters to ad-hoc to which Resolver!" — the PER-RESOLVER pairing model. Each relays.md row
    /// is `pinned` iff it rides THIS server's route (`routes[server].via`) — not any route, THE route
    /// — and carries the [`overload_hint`] when it also rides other resolvers. Same family gate as
    /// [`build_relay_rows`]; a relay armed on this route always shows.
    fn build_pairing_rows(
        md_path: &str,
        cfg: &torta_core::DnscryptProxyConfig,
        server: &str,
    ) -> ModelRc<crate::PickerRow> {
        let via: std::collections::HashSet<&str> = cfg
            .anonymized_dns
            .routes
            .iter()
            .find(|r| r.server_name == server)
            .map(|r| r.via.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let rides = relay_ride_counts(cfg);
        let rows: Vec<crate::PickerRow> =
            torta_core::resolver_list_picker_entries(md_path.to_string())
                .into_iter()
                .filter(|e| {
                    let (v4, v6) = torta_core::stamp_addr_family(&e.stamp);
                    let family_ok = (cfg.ipv4_servers && v4) || (cfg.ipv6_servers && v6);
                    family_ok || via.contains(e.name.as_str())
                })
                .map(|e| crate::PickerRow {
                    pinned: via.contains(e.name.as_str()),
                    hint: overload_hint(&rides, &e.name),
                    name: e.name.into(),
                    proto: e.proto.into(),
                    stamp: e.stamp.into(),
                })
                .collect();
        ModelRc::new(VecModel::from(rows))
    }

    /// Push the typed K5 authority onto ONE MOUNT of the DnscryptSection pane — field-for-field,
    /// the same set the Kotlin surface (`DnscryptSettingsFragment.reflectConfigToUi`) reflects.
    /// A macro (not a fn) since D3: the IDENTICAL alias set now lives on TWO generated component
    /// types — the D2 `AdvancedBurger` and the D3 `TortaShell` ③ DNS tab (one typed authority,
    /// two mounts; home_shell.slint keeps the names byte-equal so this body drives either).
    macro_rules! push_dnscrypt {
        ($ui:expr, $cfg:expr) => {{
            let burger = $ui;
            let cfg = $cfg;
            burger.set_require_dnssec(cfg.require_dnssec);
            burger.set_require_nolog(cfg.require_nolog);
            burger.set_require_nofilter(cfg.require_nofilter);
            // ★ #98 — the PQDNSCrypt gate reads back from the SAME held authority as its siblings, so
            // the toggle shows the config's real state on entry (and after a rehydrate), never an
            // optimistic UI default.
            burger.set_pqdnscrypt(cfg.pqdnscrypt);
            burger.set_dnscrypt_servers(cfg.dnscrypt_servers);
            burger.set_doh_servers(cfg.doh_servers);
            burger.set_odoh_servers(cfg.odoh_servers);
            burger.set_ipv4_servers(cfg.ipv4_servers);
            burger.set_ipv6_servers(cfg.ipv6_servers);
            burger.set_force_tcp(cfg.force_tcp);
            burger.set_http3(cfg.http3);
            burger.set_ignore_system_dns(cfg.ignore_system_dns);
            burger.set_proxy_enabled(cfg.proxy.is_some());
            burger.set_proxy_port(cfg.proxy.as_deref().and_then(port_of).unwrap_or(9050));
            burger.set_listen_port(
                cfg.listen_addresses
                    .first()
                    .map(String::as_str)
                    .and_then(port_of)
                    .unwrap_or(5354),
            );
            burger.set_bootstrap_resolvers(display_bootstrap(&cfg.bootstrap_resolvers).into());
            burger.set_dns64_on(!cfg.dns64.prefix.is_empty());
            burger.set_dns64_prefix(cfg.dns64.prefix.join(", ").into());
            burger.set_block_ipv6(cfg.block_ipv6);
            burger.set_block_unqualified(cfg.block_unqualified);
            burger.set_block_undelegated(cfg.block_undelegated);
            burger.set_query_log_on(cfg.query_log.file.is_some());
            burger.set_nx_log_on(cfg.nx_log.file.is_some());
            burger.set_cache_on(cfg.cache);
            burger.set_cache_size(cfg.cache_size);
            burger.set_timeout_ms(cfg.timeout);
            burger.set_server_names_count(cfg.server_names.len() as i32);
            burger.set_relay_routes(cfg.anonymized_dns.routes.len() as i32);
            // Total relay HOPS (Σ via across routes) — the operator's real relay budget, distinct from
            // the route COUNT above. Drives the servers-vs-relays split in `pool-summary`.
            burger.set_relay_hops(
                cfg.anonymized_dns
                    .routes
                    .iter()
                    .map(|r| r.via.len())
                    .sum::<usize>() as i32,
            );
            burger.set_sources_refresh_hours(
                cfg.sources
                    .get("public-resolvers")
                    .and_then(|s| s.refresh_delay)
                    .unwrap_or(72),
            );
            burger.set_relays_refresh_hours(
                cfg.sources
                    .get("relays")
                    .and_then(|s| s.refresh_delay)
                    .unwrap_or(72),
            );
        }};
    }

    /// Wire ONE MOUNT's edit intents onto the SHARED typed Record (mutate → the UI already
    /// local-echoed; linked fields re-pushed) + the two config actions. VALUE-only, datapath-safe:
    /// `apply-config` persists via `dnscrypt_config_set` + writes the compatibility TOML — the
    /// running engine re-reads it at the next module (re)start, exactly the Kotlin surface's
    /// contract (D09). A macro for the same two-mount reason as [`push_dnscrypt!`]: both the D2
    /// burger and the D3 shell ③ DNS tab wire onto the ONE `Rc<RefCell<DnscryptProxyConfig>>`
    /// (edits made on either mount land on the other via the window-swap re-push).
    macro_rules! wire_dnscrypt_edits {
        ($ui:expr, $cfg:expr, $toml_path:expr, $data_dir:expr) => {{
        let burger = &$ui;
        let cfg: Rc<RefCell<torta_core::DnscryptProxyConfig>> = $cfg;
        let toml_path: String = $toml_path;
        let data_dir: String = $data_dir;
        // The signed source lists (public-resolvers.md / relays.md) live BESIDE the toml, in the
        // dnscrypt-proxy dir — derive the picker's read dir from toml_path so it reads the SAME dir
        // the resolver + apply-config use (NOT data_dir, which is the {BASE}/files subdir).
        let cfg_dir: String = std::path::Path::new(&toml_path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        // W5 #12 (RAMxNAND Opt-2) — the app-private DurableTier root for the framed "dnscrypt-config"
        // record. The toml lives at {BASE}/app_data/dnscrypt-proxy/dnscrypt-proxy.toml, so its
        // grandparent is {BASE}/app_data and the durable dir is {BASE}/app_data/runtime_tier — the
        // SAME root the Kotlin RotationManager + RuntimeTierManager (RUNTIME_TIER_RELATIVE_DIR) read,
        // so an on-device toggle's persist and the boot rehydrate hit the identical record.
        let tier_dir: String = std::path::Path::new(&toml_path)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("runtime_tier").to_string_lossy().into_owned())
            .unwrap_or_default();
        let _ = &data_dir; // (kept for parity with the other edit closures; the picker uses cfg_dir)
        // #22 s5A-ext (Socio) — the TUNNEL-ONLY kill switch: an app-wide swKillSwitch PREF over JNI,
        // not a toml bit, so it rides beside the cfg closures here (both mounts get it via the macro).
        burger.set_tunnel_only(crate::engine_bridge::tunnel_only_kill_switch().unwrap_or(false));
        {
            let ui_weak = burger.as_weak();
            burger.on_tunnel_only_toggled(move |on| {
                crate::engine_bridge::set_tunnel_only_kill_switch(on);
                // Echo the host truth back (fail-open to the intent if the JNI read faults).
                let echo = crate::engine_bridge::tunnel_only_kill_switch().unwrap_or(on);
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_tunnel_only(echo);
                }
            });
        }
        {
            let c = cfg.clone();
            let path = toml_path.clone();
            let tdir = tier_dir.clone();
            burger.on_requirement_toggled(move |key, on| {
                {
                    let mut c = c.borrow_mut();
                    match key.as_str() {
                        "dnssec" => c.require_dnssec = on,
                        "nolog" => c.require_nolog = on,
                        "nofilter" => c.require_nofilter = on,
                        // ★ #98 — the PQDNSCrypt gate rides the requirement rail so it inherits the
                        // whole persistence tail below (held authority -> dnscrypt_config_set -> the
                        // materialized toml -> the durable record). `resolver/mod.rs:893` reads
                        // `dnscrypt_config::get().pqdnscrypt` on the next configure, so flipping this
                        // reaches the LIVE cert selector rather than only the picker.
                        "pqdnscrypt" => c.pqdnscrypt = on,
                        _ => {}
                    }
                }
                // ★ require→pool: persist to the held authority + the toml so
                // ResolverRuntime.deriveConfiguredUpstreams (which now reads the toml's require_* via
                // RotationPoolSource.policyFromConfig) applies the armed requirement to the LIVE pool on
                // the next configure — the SLINT toggle finally reaches the resolver, not just the picker.
                let snap = c.borrow().clone();
                torta_core::dnscrypt_config_set(snap);
                // W5 #12 — atomic Rust-side materialize of the compatibility toml from the just-set
                // authority (replaces the raw std::fs::write) + persist to the app-private W5
                // DurableTier so the edit survives a wiped loose toml. Both best-effort, off any datapath.
                let _ = torta_core::materialize_dnscrypt_toml(path.clone());
                let _ = torta_core::persist_dnscrypt_config(tdir.clone());
            });
        }
        {
            let c = cfg.clone();
            let b = burger.as_weak();
            let cdir = cfg_dir.clone();
            let path = toml_path.clone();
            let tdir = tier_dir.clone();
            burger.on_server_type_toggled(move |key, on| {
                {
                    let mut cfg = c.borrow_mut();
                    match key.as_str() {
                        "dnscrypt" => cfg.dnscrypt_servers = on,
                        "doh" => cfg.doh_servers = on,
                        "odoh" => cfg.odoh_servers = on,
                        "ipv4" => cfg.ipv4_servers = on,
                        "ipv6" => cfg.ipv6_servers = on,
                        _ => {}
                    }
                }
                // ★ type/family→pool: persist to the held authority + the toml (mirror
                // on_requirement_toggled) so the engine AND both rotation brains
                // (ResolverRuntime.deriveConfiguredUpstreams + RotationManager.rotationPolicy — which read
                // the toml's ipv4_servers/ipv6_servers/*_servers via RotationPoolSource.policyFromConfig)
                // honor the family/proto filter on the next configure. Previously this toggle updated only
                // the in-mem cfg + the picker preview, so the SLINT choice never reached the resolver.
                let snap = c.borrow().clone();
                torta_core::dnscrypt_config_set(snap);
                // W5 #12 — atomic materialize + DurableTier persist (retires the raw std::fs::write).
                let _ = torta_core::materialize_dnscrypt_toml(path.clone());
                let _ = torta_core::persist_dnscrypt_config(tdir.clone());
                // LIVE re-filter: a type/family toggle re-scans the source list against the UPDATED
                // predicate and re-pushes the rows at once — the picker the operator sees narrows the
                // instant a filter flips, no close/re-open. The SURPASS over a static one-shot list
                // (nautilus re-filters only on file reload); here the same 5-filter set gates the list
                // the moment it changes, mirroring exactly what the rotation auto-pick will honor.
                if let Some(b) = b.upgrade() {
                    let md = format!("{cdir}/public-resolvers.md");
                    b.set_server_entries(build_server_rows(&md, &c.borrow()));
                }
            });
        }
        // ── THE MANUAL PICKER (per the ARC: pure-Rust source-list scan → SLINT rows → pin → toml
        //    write). On open, fill the entries from `resolverListPickerEntries`, each row `pinned`
        //    relative to the live config; a row toggle edits `server_names` / `anonymized_dns.routes`,
        //    writes the toml (the apply-config path), and re-pushes so the pins + pool/route counts
        //    reflect at once. Re-reading the (~160 KB) list on a settings tap is ~1 ms — off any hot path. ──
        {
            let c = cfg.clone();
            let b = burger.as_weak();
            let cdir = cfg_dir.clone();
            burger.on_open_servers_picker(move || {
                if let Some(b) = b.upgrade() {
                    let md = format!("{cdir}/public-resolvers.md");
                    b.set_server_entries(build_server_rows(&md, &c.borrow()));
                }
            });
        }
        {
            let c = cfg.clone();
            let b = burger.as_weak();
            let cdir = cfg_dir.clone();
            burger.on_open_relays_picker(move || {
                if let Some(b) = b.upgrade() {
                    let md = format!("{cdir}/relays.md");
                    b.set_relay_entries(build_relay_rows(&md, &c.borrow()));
                }
            });
        }
        {
            let c = cfg.clone();
            let b = burger.as_weak();
            let path = toml_path.clone();
            let cdir = cfg_dir.clone();
            let tdir = tier_dir.clone();
            burger.on_pin_toggled(move |name, kind, pinned| {
                let name = name.to_string();
                {
                    let mut cfg = c.borrow_mut();
                    if kind.as_str() == "server" {
                        // Pin/unpin a server_name (a set — no duplicates). Empty ⇒ back to auto-pick.
                        cfg.server_names.retain(|n| n != &name);
                        if pinned {
                            cfg.server_names.push(name.clone());
                        }
                    } else {
                        // Relay: arm/disarm this relay across a route for EVERY configured server (the
                        // whole-pool model — every server routes via the pinned relay set). Seed one
                        // empty route per server_name if none exist yet, then drop routes left direct.
                        if cfg.anonymized_dns.routes.is_empty() && !cfg.server_names.is_empty() {
                            let servers = cfg.server_names.clone();
                            cfg.anonymized_dns.routes = servers
                                .into_iter()
                                .map(|s| torta_core::Route {
                                    server_name: s,
                                    via: Vec::new(),
                                })
                                .collect();
                        }
                        for r in cfg.anonymized_dns.routes.iter_mut() {
                            r.via.retain(|v| v != &name);
                            if pinned {
                                r.via.push(name.clone());
                            }
                        }
                        cfg.anonymized_dns.routes.retain(|r| !r.via.is_empty());
                    }
                }
                // Persist to the held authority + the toml (the same path apply-config writes).
                let snapshot = c.borrow().clone();
                torta_core::dnscrypt_config_set(snapshot);
                // W5 #12 — atomic materialize + DurableTier persist (retires the raw std::fs::write).
                let _ = torta_core::materialize_dnscrypt_toml(path.clone());
                let _ = torta_core::persist_dnscrypt_config(tdir.clone());
                // Re-push counts + re-mark BOTH picker models so the toggled row reflects immediately.
                if let Some(b) = b.upgrade() {
                    push_dnscrypt!(&b, &c.borrow());
                    let cfg = c.borrow();
                    b.set_server_entries(build_server_rows(
                        &format!("{cdir}/public-resolvers.md"),
                        &cfg,
                    ));
                    b.set_relay_entries(build_relay_rows(&format!("{cdir}/relays.md"), &cfg));
                }
            });
        }
        {
            // #22 s5B: a pinned server row's PAIR chip — fill the pairing panel's relay model for
            // THAT server (the slint side already set `pairing-server`; the host only feeds rows).
            let c = cfg.clone();
            let b = burger.as_weak();
            let cdir = cfg_dir.clone();
            burger.on_pair_server_selected(move |server| {
                if let Some(b) = b.upgrade() {
                    let md = format!("{cdir}/relays.md");
                    b.set_pairing_relay_entries(build_pairing_rows(&md, &c.borrow(), server.as_str()));
                }
            });
        }
        {
            // #22 s5B (Socio): "a separate way to choose which relay to combine with which Resolver
            // inside Dnscrypt" — the per-resolver route edit. Unlike on_pin_toggled's whole-pool
            // relay arm, this touches exactly ONE anonymized_dns route: toggle the relay on THIS
            // server's via-list, create the route on first arm, drop it when the last relay leaves
            // (a via-less route would force that server DIRECT — dnscrypt-proxy treats an empty
            // via as "no anonymization", the opposite of the user's intent). Same persist spine as
            // every other edit: dnscrypt_config_set → materialize → persist, then re-push all three
            // picker models so pin-marks + overload hints reflect immediately on BOTH mounts.
            let c = cfg.clone();
            let b = burger.as_weak();
            let path = toml_path.clone();
            let cdir = cfg_dir.clone();
            let tdir = tier_dir.clone();
            burger.on_route_relay_toggled(move |server, relay, on| {
                let server = server.to_string();
                let relay = relay.to_string();
                {
                    let mut cfg = c.borrow_mut();
                    match cfg
                        .anonymized_dns
                        .routes
                        .iter_mut()
                        .find(|r| r.server_name == server)
                    {
                        Some(r) => {
                            r.via.retain(|v| v != &relay);
                            if on {
                                r.via.push(relay.clone());
                            }
                        }
                        None if on => cfg.anonymized_dns.routes.push(torta_core::Route {
                            server_name: server.clone(),
                            via: vec![relay.clone()],
                        }),
                        None => {}
                    }
                    cfg.anonymized_dns.routes.retain(|r| !r.via.is_empty());
                }
                let snapshot = c.borrow().clone();
                torta_core::dnscrypt_config_set(snapshot);
                let _ = torta_core::materialize_dnscrypt_toml(path.clone());
                let _ = torta_core::persist_dnscrypt_config(tdir.clone());
                if let Some(b) = b.upgrade() {
                    push_dnscrypt!(&b, &c.borrow());
                    let cfg = c.borrow();
                    let md = format!("{cdir}/relays.md");
                    b.set_relay_entries(build_relay_rows(&md, &cfg));
                    b.set_pairing_relay_entries(build_pairing_rows(&md, &cfg, &server));
                }
            });
        }
        {
            let c = cfg.clone();
            let b = burger.as_weak();
            burger.on_transport_toggled(move |key, on| {
                let mut c = c.borrow_mut();
                match key.as_str() {
                    "force_tcp" => c.force_tcp = on,
                    "http3" => c.http3 = on,
                    "ignore_system_dns" => c.ignore_system_dns = on,
                    "block_unqualified" => c.block_unqualified = on,
                    "block_undelegated" => c.block_undelegated = on,
                    "cache" => c.cache = on,
                    "block_ipv6" => {
                        // Re-derive the listener so [::1] rides only when IPv6 answers are allowed
                        // (the Kotlin applyBlockIpv6 link, byte-identical intent).
                        c.block_ipv6 = on;
                        let port = c
                            .listen_addresses
                            .first()
                            .map(String::as_str)
                            .and_then(port_of)
                            .unwrap_or(5354);
                        set_listen(&mut c, port);
                    }
                    "query_log" => {
                        // The toml [query_log] file target MUST be the engine base path (the same
                        // `{BASE}/cache/query.log` the running resolver's default uses and the feeds
                        // read), NOT `{BASE}/files/cache/…` — route through `query_log_path` so the
                        // writer the Kotlin `armQueryFeedFromConfig` arms and the ③/④ readers agree.
                        c.query_log.file =
                            on.then(|| crate::feed_shape::query_log_path(&data_dir, "dnscrypt"));
                    }
                    "nx_log" => {
                        c.nx_log.file =
                            on.then(|| crate::feed_shape::query_log_path(&data_dir, "nx"));
                    }
                    "proxy" => {
                        if on {
                            if c.proxy.as_deref().unwrap_or("").is_empty() {
                                c.proxy = Some("socks5://127.0.0.1:9050".to_string());
                            }
                            // The legacy proxy↔force_tcp link: SOCKS needs TCP (re-echo the UI).
                            c.force_tcp = true;
                            if let Some(b) = b.upgrade() {
                                b.set_force_tcp(true);
                            }
                        } else {
                            c.proxy = None;
                        }
                    }
                    "dns64" => {
                        // Seed the well-known NAT64 prefix on arm; a user-typed prefix survives
                        // re-enable (the Kotlin applyDns64Enabled contract).
                        if on {
                            if c.dns64.prefix.is_empty() {
                                c.dns64.prefix = vec!["64:ff9b::/96".to_string()];
                                if let Some(b) = b.upgrade() {
                                    b.set_dns64_prefix("64:ff9b::/96".into());
                                }
                            }
                        } else {
                            c.dns64.prefix.clear();
                        }
                    }
                    _ => {}
                }
            });
        }
        {
            let c = cfg.clone();
            let b = burger.as_weak();
            burger.on_listen_port_edited(move |text| {
                if let Some(port) = parse_port(text.as_str()) {
                    let mut c = c.borrow_mut();
                    set_listen(&mut c, port);
                    if let Some(b) = b.upgrade() {
                        b.set_listen_port(port);
                    }
                }
            });
        }
        {
            let c = cfg.clone();
            let b = burger.as_weak();
            burger.on_proxy_port_edited(move |text| {
                if let Some(port) = parse_port(text.as_str()) {
                    c.borrow_mut().proxy = Some(format!("socks5://127.0.0.1:{port}"));
                    if let Some(b) = b.upgrade() {
                        b.set_proxy_port(port);
                    }
                }
            });
        }
        {
            let c = cfg.clone();
            let b = burger.as_weak();
            burger.on_bootstrap_edited(move |text| {
                let resolvers: Vec<String> = text
                    .as_str()
                    .split(',')
                    .filter_map(|t| t.trim().parse::<std::net::IpAddr>().ok())
                    .map(|ip| match ip {
                        std::net::IpAddr::V4(v4) => format!("{v4}:53"),
                        std::net::IpAddr::V6(v6) => format!("[{v6}]:53"),
                    })
                    .collect();
                if !resolvers.is_empty() {
                    let mut c = c.borrow_mut();
                    c.bootstrap_resolvers = resolvers;
                    if let Some(b) = b.upgrade() {
                        b.set_bootstrap_resolvers(display_bootstrap(&c.bootstrap_resolvers).into());
                    }
                }
            });
        }
        {
            let c = cfg.clone();
            burger.on_dns64_prefix_edited(move |text| {
                let prefixes: Vec<String> = text
                    .as_str()
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty() && t.contains("::"))
                    .map(str::to_string)
                    .collect();
                if !prefixes.is_empty() {
                    c.borrow_mut().dns64.prefix = prefixes;
                }
            });
        }
        {
            let c = cfg.clone();
            let b = burger.as_weak();
            burger.on_sources_refresh_stepped(move |delta| {
                let hours = step_refresh(&c, &["public-resolvers", "odoh-servers"], delta);
                if let (Some(b), Some(h)) = (b.upgrade(), hours) {
                    b.set_sources_refresh_hours(h);
                }
            });
        }
        {
            let c = cfg.clone();
            let b = burger.as_weak();
            burger.on_relays_refresh_stepped(move |delta| {
                let hours = step_refresh(&c, &["relays", "odoh-relays"], delta);
                if let (Some(b), Some(h)) = (b.upgrade(), hours) {
                    b.set_relays_refresh_hours(h);
                }
            });
        }
        {
            let c = cfg.clone();
            let b = burger.as_weak();
            let path = toml_path.clone();
            burger.on_reload_config(move || {
                *c.borrow_mut() = torta_core::dnscrypt_config_import_or_default(
                    std::fs::read_to_string(&path).unwrap_or_default(),
                );
                if let Some(b) = b.upgrade() {
                    push_dnscrypt!(&b, &c.borrow());
                }
            });
        }
        {
            let c = cfg;
            let tdir = tier_dir.clone();
            burger.on_apply_config(move || {
                let snapshot = c.borrow().clone();
                torta_core::dnscrypt_config_set(snapshot);
                // W5 #12 — atomic materialize (create_dir_all parent + tmp+fsync+rename, Rust-side) +
                // persist to the app-private W5 DurableTier; retires the raw std::fs::write +
                // hand-rolled create_dir_all — the framed durable record is the config's truth now.
                let _ = torta_core::materialize_dnscrypt_toml(toml_path.clone());
                let _ = torta_core::persist_dnscrypt_config(tdir.clone());
            });
        }
        }};
    }

    /// Extract the trailing `:port` of an address/URL as an int (the Kotlin extractPort twin).
    fn port_of(addr: &str) -> Option<i32> {
        addr.rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .map(i32::from)
    }

    /// Parse a user-typed port: numeric, unprivileged (>=1024) — the no-root floor the Kotlin
    /// validator enforces on this build.
    fn parse_port(text: &str) -> Option<i32> {
        text.trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p >= 1024)
            .map(i32::from)
    }

    /// Re-derive the loopback listener addresses (the Kotlin setListenAddresses twin).
    fn set_listen(cfg: &mut torta_core::DnscryptProxyConfig, port: i32) {
        cfg.listen_addresses = if cfg.block_ipv6 {
            vec![format!("127.0.0.1:{port}")]
        } else {
            vec![format!("127.0.0.1:{port}"), format!("[::1]:{port}")]
        };
    }

    /// Step every named source's refresh cadence by ±delta hours (clamped) and return the new value.
    fn step_refresh(
        cfg: &Rc<RefCell<torta_core::DnscryptProxyConfig>>,
        names: &[&str],
        delta: i32,
    ) -> Option<i32> {
        let mut c = cfg.borrow_mut();
        let mut result = None;
        for name in names {
            if let Some(src) = c.sources.get_mut(*name) {
                let next =
                    (src.refresh_delay.unwrap_or(72) + delta).clamp(REFRESH_MIN_H, REFRESH_MAX_H);
                src.refresh_delay = Some(next);
                result = Some(next);
            }
        }
        result
    }

    /// Render the bootstrap list for display (strip `:53` + brackets — the Kotlin displayBootstrap twin).
    fn display_bootstrap(resolvers: &[String]) -> String {
        resolvers
            .iter()
            .map(|r| {
                r.strip_suffix(":53")
                    .unwrap_or(r)
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Push the REAL Centauri pillar state into the dashboard: the typed `CentauriSnapshot` off the
    /// live `uniffi::Object` (object.rs:347) + the `centauri_cdn_hosts()` watch-list (lib.rs:1995) +
    /// the Object's recent-serve ring (cold ⇒ honestly EMPTY — the .slint sample preview rows are
    /// cleared, never shown as live serves). D3: takes the ONE shared spike-local Object (the same
    /// instance feeding the HOME CDN-local counter) — one instance, one truth, never two cold
    /// stores disagreeing.
    fn feed_from_live_centauri(
        // 2-FEED-Centauri: feeds the SHELL's in-shell centauri-dash pane. The `TortaShell` Centauri
        // aliases are byte-equal to the CentauriPane props (home_shell.slint), so the SAME `set_*`
        // field-map body drives the embedded pane (the two-mount law feed_from_live_masksolver
        // follows). `dash` kept as the param name so the body below stays byte-stable.
        dash: &crate::TortaShell,
        centauri: &torta_core::mirror::object::Centauri,
    ) {
        let snap = centauri.snapshot();

        dash.set_libraries(snap.libraries as i32);
        dash.set_cache_bytes(snap.bytes as i32);
        dash.set_cache_full(snap.full);
        dash.set_capacity(snap.capacity as i32);
        dash.set_serve_port(snap.serve_port);
        dash.set_serve_state(snap.serve_state.code());
        dash.set_catalog_assets(snap.catalog_assets as i32);
        // ★ #22 slice 2 — cold-seed the TCAT v2 freshness from THIS .so's own Object (0 ⇒ "—");
        // the live bridge JSON overlay below re-ages it from the engine .so's retained catalog.
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            dash.set_catalog_freshness(
                crate::centauri_feed_fmt::freshness_label(now, snap.catalog_authored_at_secs).into(),
            );
        }
        dash.set_catalog_installs_attempted(snap.catalog_installs_attempted as i32);
        dash.set_catalog_installs_verified(snap.catalog_installs_verified as i32);
        dash.set_resolve_queries(snap.resolve_queries as i32);
        dash.set_resolve_hits(snap.resolve_hits as i32);
        dash.set_rehydrates_attempted(snap.rehydrates_attempted as i32);
        dash.set_rehydrates_verified(snap.rehydrates_verified as i32);
        dash.set_served_locally(snap.served_locally as i32);
        dash.set_served_bytes(snap.served_bytes as i32);
        dash.set_cdn_fetches(snap.cdn_fetches as i32);
        dash.set_exact_serves(snap.exact_serves as i32);
        dash.set_fallback_serves(snap.fallback_serves as i32);
        // CP-Centauri-Discovery — the cold baseline (torta_ui's own Object is 0); the bridge JSON below
        // overlays the LIVE engine-.so discovery totals.
        dash.set_discovered_total(snap.discovered as i32);
        dash.set_discovered_observed(snap.discovered_observed as i32);
        // The living roster is resolver-side live state → torta_ui's own Object holds an empty line here;
        // the bridge JSON below overlays the real discovered hostnames.
        dash.set_discovered_hosts(split_discovered_line(&snap.discovered_hosts));

        // The cloaked CDN-host watch-list — the REAL engine surface, not the .slint sample literals.
        // The panel shows the first CDN_HOSTS_SHOWN, but `cdn_hosts_total` carries the TRUE watch-list
        // size so the "(N watched)" label is honest (was mis-reading the displayed 8 as the total when
        // the curated LocalCDN roster watches far more).
        let all_hosts = torta_core::centauri_cdn_hosts();
        dash.set_cdn_hosts_total(all_hosts.len() as i32);
        // ★ #16 — hosts un-cloaked because their client refused our leaf (device CA not installed yet).
        // Renders only when non-zero, so a healthy device shows the plain watched/discovered label.
        dash.set_tls_distrust(torta_core::centauri_tls_distrust_count() as i32);
        dash.set_absorb_count(torta_core::centauri_absorb_count() as i32);
        dash.set_promoted_cloak_count(torta_core::centauri_promoted_cloak_count() as i32);
        let hosts: Vec<SharedString> = all_hosts
            .iter()
            .take(CDN_HOSTS_SHOWN)
            .cloned()
            .map(SharedString::from)
            .collect();
        dash.set_cdn_hosts(ModelRc::new(VecModel::from(hosts)));

        // The recent-serve constellation feed — the live ring, typed row-for-row.
        let serves: Vec<crate::ServeRow> = centauri
            .recent_serves(RECENT_SERVES_SHOWN)
            .into_iter()
            .map(|r| crate::ServeRow {
                host: r.host.into(),
                asset: r.canonical_name.into(),
                outcome: match r.outcome {
                    torta_core::mirror::object::CentauriServeOutcome::ServedLocal => "LOCAL",
                    torta_core::mirror::object::CentauriServeOutcome::LeakedThenServed => "LEAK",
                    torta_core::mirror::object::CentauriServeOutcome::BlockedMissing => "BLOCK",
                    torta_core::mirror::object::CentauriServeOutcome::NotInCatalog => "MISS",
                    torta_core::mirror::object::CentauriServeOutcome::FetchFailed => "FAIL",
                }
                .into(),
                sub: match r.substitution {
                    torta_core::mirror::object::CentauriSubstitution::Exact => "exact",
                    torta_core::mirror::object::CentauriSubstitution::SafeNewer => "newer",
                    torta_core::mirror::object::CentauriSubstitution::RiskyOlder => "older",
                    torta_core::mirror::object::CentauriSubstitution::Incompatible => "incompat",
                    // A non-serve miss carries no verdict — empty token ⇒ the slint ServeRow renders a
                    // muted em-dash, never a phantom "exact" beside a MISS (matches the JNI-bridge contract).
                    torta_core::mirror::object::CentauriSubstitution::NotApplicable => "",
                }
                .into(),
                bytes: r.bytes as i32,
            })
            .collect();
        dash.set_recent_serves(ModelRc::new(VecModel::from(serves)));

        // SLINT substitution · CENTAURI FULL LIVE OVERLAY — the cold-spike-gap fix. Everything pushed
        // above is THIS .so's cold spike-local Object (never `start()`ed, never served — so it reads
        // Stopped / port 0 / every counter 0). Overlay the RUNNING libtorta_core.so armed Object read
        // over the JNI bridge (`liveCentauriStats` → the full snapshot as flat-JSON; the SAME Object the
        // loopback serves + the D29 observer counts) so EVERY tile shows the real engine: serve-state
        // header + `127.0.0.1:<port>`, THE CDN SAW, PRIVACY WITNESS (served-locally / cdn-fetches /
        // blocked-missing), SERVE QUALITY (exact / fallback), and the catalog / resolve / rehydrate
        // counters. Unreachable (base .so / mirror not running) ⇒ `None` ⇒ the honest cold read stands.
        // REAL stats only, never a fabricated tally. (Supersedes the 3-field `live_mirror_status` patch —
        // that flat reader remains for the HOME cache chip.)
        // ★ #65 — CA trust, re-read on every tick from the live OS store (not cached), so the prompt
        // clears the moment the user grants trust and returns if they revoke it. A JNI fault leaves the
        // last honest value standing rather than asserting a privacy guarantee we cannot verify.
        if let Some(v) = crate::engine_bridge::centauri_ca_minted() {
            dash.set_ca_minted(v);
        }
        if let Some(v) = crate::engine_bridge::centauri_ca_trusted() {
            dash.set_ca_trusted(v);
        }

        if let Some(j) = crate::engine_bridge::live_centauri_stats() {
            use crate::engine_bridge::json_i32 as ji;
            use crate::engine_bridge::json_str as js;
            if let Some(v) = ji(&j, "libraries") {
                dash.set_libraries(v);
            }
            if let Some(v) = ji(&j, "bytes") {
                dash.set_cache_bytes(v);
            }
            if let Some(v) = ji(&j, "full") {
                dash.set_cache_full(v != 0);
            }
            if let Some(v) = ji(&j, "capacity") {
                dash.set_capacity(v);
            }
            if let Some(v) = ji(&j, "serve_port") {
                dash.set_serve_port(v);
            }
            if let Some(v) = ji(&j, "serve_state") {
                dash.set_serve_state(v);
            }
            if let Some(v) = ji(&j, "catalog_assets") {
                dash.set_catalog_assets(v);
            }
            // ★ #22 slice 2 — the TCAT v2 catalog freshness: age-label the signing epoch (0 ⇒ "—",
            // the em-dash law; a v1-era catalog NEVER reads as ancient). Rendered here, not in slint
            // (slint has no clock; the feed tick re-ages it naturally).
            if let Some(epoch) = crate::centauri_feed_fmt::json_i64(&j, "catalog_authored_at_secs") {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                dash.set_catalog_freshness(
                    crate::centauri_feed_fmt::freshness_label(now, epoch).into(),
                );
            }
            if let Some(v) = ji(&j, "catalog_installs_attempted") {
                dash.set_catalog_installs_attempted(v);
            }
            if let Some(v) = ji(&j, "catalog_installs_verified") {
                dash.set_catalog_installs_verified(v);
            }
            if let Some(v) = ji(&j, "resolve_queries") {
                dash.set_resolve_queries(v);
            }
            if let Some(v) = ji(&j, "resolve_hits") {
                dash.set_resolve_hits(v);
            }
            if let Some(v) = ji(&j, "rehydrates_attempted") {
                dash.set_rehydrates_attempted(v);
            }
            if let Some(v) = ji(&j, "rehydrates_verified") {
                dash.set_rehydrates_verified(v);
            }
            if let Some(v) = ji(&j, "served_locally") {
                dash.set_served_locally(v);
            }
            if let Some(v) = ji(&j, "served_bytes") {
                dash.set_served_bytes(v);
            }
            if let Some(v) = ji(&j, "cdn_fetches") {
                dash.set_cdn_fetches(v);
            }
            if let Some(v) = ji(&j, "exact_serves") {
                dash.set_exact_serves(v);
            }
            if let Some(v) = ji(&j, "fallback_serves") {
                dash.set_fallback_serves(v);
            }
            // CP-Centauri-Discovery — overlay the LIVE living-watch-list totals (the engine .so's
            // discovery store, fed off the resolver walk; torta_ui's own cold Object never observed).
            if let Some(v) = ji(&j, "discovered") {
                dash.set_discovered_total(v);
            }
            if let Some(v) = ji(&j, "discovered_observed") {
                dash.set_discovered_observed(v);
            }
            // CP-Centauri-Absorb — same split-brain law as discovery above: the absorbed-asset index and
            // the promoted-cloak set live in the SERVICE's engine .so, armed by the tunnel. torta_ui's
            // statically-linked torta_core is a cold second instance whose absorb::arm() never ran, so a
            // direct centauri_absorb_count() reads its empty map. Take the live figures off the bridge.
            if let Some(v) = ji(&j, "absorbed") {
                dash.set_absorb_count(v);
            }
            if let Some(v) = ji(&j, "promoted_cloaks") {
                dash.set_promoted_cloak_count(v);
            }
            if let Some(v) = ji(&j, "tls_distrust") {
                dash.set_tls_distrust(v);
            }
            // ...and the living roster itself — the pipe-delimited top hosts, split into the list model.
            // Absent/empty ⇒ leave the cold (empty) list; never a fabricated host.
            if let Some(line) = js(&j, "discovered_hosts") {
                dash.set_discovered_hosts(split_discovered_line(&line));
            }
        }

        // The recent-serve constellation — overlay the LIVE ring (the .so-split twin of the cold
        // `recent_serves` above; the cold spike Object never served, so its ring is empty). `total=<N>`
        // header line, then newest-first TAB rows already carrying the ServeRow display tokens. Empty or
        // unreachable ⇒ the cold (honestly empty) feed stands — never a fabricated serve.
        if let Some(doc) = crate::engine_bridge::live_centauri_serves() {
            let live_serves: Vec<crate::ServeRow> = doc
                .lines()
                .skip(1) // line 1 is the `total=<N>` header
                .filter_map(|line| {
                    let mut f = line.split('\t');
                    let host = f.next()?;
                    let asset = f.next()?;
                    let outcome = f.next()?;
                    let sub = f.next()?;
                    let bytes = f.next().and_then(|b| b.parse::<i32>().ok()).unwrap_or(0);
                    Some(crate::ServeRow {
                        host: host.into(),
                        asset: asset.into(),
                        outcome: outcome.into(),
                        sub: sub.into(),
                        bytes,
                    })
                })
                .collect();
            if !live_serves.is_empty() {
                dash.set_recent_serves(ModelRc::new(VecModel::from(live_serves)));
            }
        }
    }

    /// Push the REAL Wire Cake Inu pillar state into the dashboard: the typed [`InuState`] Snapshot off the
    /// live `InuStore` (torta_core inu/object.rs:118) + the per-pillar `query-inu.log` tail (inu/object.rs:165),
    /// mapped FIELD-FOR-FIELD onto the `InuDashboard` inputs. The Inu twin of [`feed_from_live_centauri`].
    ///
    /// ★ TWO enum-contract reconciliations (GROUND_TRUTH — the Rust ordinals ≠ the .slint contract, so a naive
    /// `.code()` push would mis-render):
    ///  · elevation-status: the Rust `InuElevationStatus` (Idle0 · Discovering1 · Pairing2 · Connecting3 ·
    ///    Elevated4 · Failed5 — inu/mod.rs:81) is COLLAPSED onto the .slint 4-state contract
    ///    (0 RESTING · 1 FETCHING · 2 ELEVATED · 3 ERROR — inu.slint:135, derived `elevated: …== 2` at :161):
    ///    Elevated(4)→2, the Discovering/Pairing/Connecting cluster→1 FETCHING, Failed→3. A raw `.code()`
    ///    would read Elevated as 4 and the crown would show RESTING (it checks `== 2`).
    ///  · active-provider: the Rust `InuProvider` ordinals (None0 · Shizuku1 · SelfAdb2 · Stub3 — inu/mod.rs:136)
    ///    MATCH the .slint contract `0 NONE · 1 SHIZUKU · 2 SELF-ADB · 3 STUB` (inu.slint:136) 1:1 — a straight
    ///    `.code()`.
    ///
    /// `boot-reapply-armed` is NOT a snapshot field — it is the Kotlin-owned durability pref, and the live
    /// BootComplete re-establish branch it gates IS wired (`BootCompleteReceiver.maybeInuBootReapply` →
    /// `WireCakeInuService.bootReapply` → `WireCakeInuManager.reapplyOnBoot`, the P11 §3 consumer). So the
    /// feed reads it across the JNI seam ([`staged_inu_prefs`], the same `stagedInuConfig()` record the
    /// settings pane consumes) — a hardcoded `false` here would false-alarm the `drift-unguarded` caution
    /// lamp (inu.slint:175) forever on a box whose drift-prone powers ARE boot-guarded (#7 EUREKA, the
    /// next-flip-secs precedent). Host-preview / cold degrades to `false` (never an over-claim).
    /// `demo_posture` — TRUE when `store` is the SEEDED SPIKE rather than the user's own record.
    ///
    /// #97 — taken as a PARAMETER rather than set at one call site on purpose: the panel renders a
    /// fabricated `Elevated` / `paired 3d ago` / `3 of 3 held` posture when no record exists, and
    /// until now nothing told the pane that. Making it an argument means the compiler asks every
    /// present and future call site "is this real?", so the marking cannot be silently dropped the
    /// way it was silently absent.
    fn feed_from_live_inu(
        dash: &crate::InuDashboard,
        store: &torta_core::inu::object::InuStore,
        demo_posture: bool,
    ) {
        use torta_core::inu::{InuBootDurability, InuElevationStatus};
        let snap = store.snapshot();
        dash.set_demo_posture(demo_posture);

        // configured: the pillar carries a REAL posture (paired, or any power tracked, or elevation in flight).
        let configured = snap.paired
            || !snap.powers.is_empty()
            || snap.elevation_status != InuElevationStatus::Idle;
        dash.set_configured(configured);

        // elevation-status: collapse the 6-state Rust lifecycle → the 4-state .slint contract (see doc above).
        let elev = match snap.elevation_status {
            InuElevationStatus::Idle => 0,
            InuElevationStatus::Discovering
            | InuElevationStatus::Pairing
            | InuElevationStatus::Connecting => 1,
            InuElevationStatus::Elevated => 2,
            InuElevationStatus::Failed => 3,
        };
        dash.set_elevation_status(elev);

        // active-provider: the Rust ordinal maps 1:1 onto the .slint contract.
        dash.set_active_provider(snap.provider.code());

        dash.set_paired(snap.paired);
        dash.set_paired_label(SharedString::from(inu_paired_label(
            snap.paired,
            snap.granted_at,
        )));

        // powers-held / -total / drift — derived from the TYPED grant map (never inferred).
        let held = snap.powers.iter().filter(|p| p.last_result).count() as i32;
        let total = snap.powers.len() as i32;
        let drift_held = snap
            .powers
            .iter()
            .filter(|p| p.last_result && p.durability == InuBootDurability::DriftProne)
            .count() as i32;
        // status-detail — the in-out hint channel inu.slint:268 declares ("host pre-formatted extra
        // line (an error message / hint)") and NOTHING wrote to until now, so every Inu error stayed
        // mute on the pane. The engine deliberately does NOT store a failure reason
        // (InuElevationStatus::Failed, inu/mod.rs:92 — "the reason/detail is transient, not stored"),
        // so the ONLY honest hint is one DERIVED from state that IS stored:
        //   - Failed        -> say so, and do not invent a cause the engine never kept.
        //   - powers wanted but not held -> the actionable count, straight off the typed grant map.
        // Empty string = no hint, and inu.slint:519 hides the row entirely (`if != ""`), so silence
        // stays the honest resting state rather than a fabricated "OK".
        let wanted_unheld = snap
            .powers
            .iter()
            .filter(|p| p.desired && !p.last_result)
            .count() as i32;
        let detail = if snap.elevation_status == InuElevationStatus::Failed {
            "Elevation failed — the reason is not retained by the engine; re-run pairing to retry."
                .to_string()
        } else if wanted_unheld > 0 {
            format!("{wanted_unheld} of {total} requested powers are not currently held.")
        } else {
            String::new()
        };
        dash.set_status_detail(detail.into());

        dash.set_powers_held(held);
        dash.set_powers_total(total);
        dash.set_drift_prone_held(drift_held);
        // The Kotlin-owned boot-reapply pref, read live off the JNI seam (see doc above) — feeds the
        // "boot re-apply" cell (inu.slint:416) + un-latches the drift-unguarded lamp when armed.
        dash.set_boot_reapply_armed(staged_inu_prefs().0);

        // The per-power grant map → PowerRow, typed row-for-row: held/drift-prone come STRAIGHT off the
        // `InuPowerFlag` (the load-bearing signal); the friendly label + PowerTier are the UI display twin of
        // Kotlin `PowerCatalogue` (labels/tiers are inherently Kotlin display data — never an engine number).
        let prows: Vec<crate::PowerRow> = snap
            .powers
            .iter()
            .map(|p| {
                let (label, tier) = inu_power_meta(p.id);
                crate::PowerRow {
                    id: SharedString::from(p.id.key()),
                    label: SharedString::from(label),
                    tier: SharedString::from(tier),
                    held: p.last_result,
                    drift_prone: p.durability == InuBootDurability::DriftProne,
                }
            })
            .collect();
        dash.set_powers(ModelRc::new(VecModel::from(prows)));

        // The recent-events feed — the live `query-inu.log` tail, parsed row-for-row (cold ⇒ honestly EMPTY,
        // the .slint sample rows cleared, never shown as live events — the Centauri recent-serves precedent).
        let events: Vec<crate::InuLogRow> = parse_inu_log(&store.tail_log(INU_EVENTS_SHOWN));
        dash.set_recent_events(ModelRc::new(VecModel::from(events)));
    }

    /// SLINT substitution · 4-FIX round 3 (2-FEED-Inu) — push the live `InuState` onto the SHELL's in-shell
    /// `idash-*` aliases (the inu-dash section), the twin of [`feed_from_live_inu`] that targets the standalone
    /// Window. The SAME two enum reconciliations (elevation-status 6→4-state collapse; provider 1:1) + the
    /// SAME live `boot-reapply-armed` read off the JNI seam ([`staged_inu_prefs`] — see the twin's doc).
    /// Closes the witness finding that the WIRE CAKE INU dashboard chip was a silent no-op — now it opens
    /// on a fed pane showing the live spike posture.
    /// `demo_posture` — TRUE when `store` is the SEEDED SPIKE rather than the user's own record.
    /// A PARAMETER for the same reason as in the twin: the compiler then asks every call site
    /// "is this real?", so the marking cannot be silently omitted. This is the mount the user
    /// actually opens (the ADVANCED inu-dash section), so this is the one that matters most.
    fn feed_inu_shell(
        sh: &crate::TortaShell,
        store: &torta_core::inu::object::InuStore,
        demo_posture: bool,
    ) {
        use torta_core::inu::{InuBootDurability, InuElevationStatus};
        let snap = store.snapshot();
        sh.set_idash_demo_posture(demo_posture);

        let configured = snap.paired
            || !snap.powers.is_empty()
            || snap.elevation_status != InuElevationStatus::Idle;
        sh.set_idash_configured(configured);

        let elev = match snap.elevation_status {
            InuElevationStatus::Idle => 0,
            InuElevationStatus::Discovering
            | InuElevationStatus::Pairing
            | InuElevationStatus::Connecting => 1,
            InuElevationStatus::Elevated => 2,
            InuElevationStatus::Failed => 3,
        };
        sh.set_idash_elevation_status(elev);
        sh.set_idash_active_provider(snap.provider.code());
        sh.set_idash_paired(snap.paired);
        sh.set_idash_paired_label(SharedString::from(inu_paired_label(
            snap.paired,
            snap.granted_at,
        )));

        let held = snap.powers.iter().filter(|p| p.last_result).count() as i32;
        let total = snap.powers.len() as i32;
        let drift_held = snap
            .powers
            .iter()
            .filter(|p| p.last_result && p.durability == InuBootDurability::DriftProne)
            .count() as i32;
        // status-detail, SHELL-EMBED MOUNT — the two-mount law: `idash-status-detail` is the alias
        // home_shell.slint:1085 exposes into this embed, and it is a DIFFERENT setter from the
        // standalone pane's `set_status_detail`. Feeding only one mount leaves the other mute, which
        // is precisely what the declared-vs-set diff caught. Same derivation, same honest silence.
        let wanted_unheld = snap
            .powers
            .iter()
            .filter(|p| p.desired && !p.last_result)
            .count() as i32;
        let detail = if snap.elevation_status == InuElevationStatus::Failed {
            "Elevation failed — the reason is not retained by the engine; re-run pairing to retry."
                .to_string()
        } else if wanted_unheld > 0 {
            format!("{wanted_unheld} of {total} requested powers are not currently held.")
        } else {
            String::new()
        };
        sh.set_idash_status_detail(detail.into());

        sh.set_idash_powers_held(held);
        sh.set_idash_powers_total(total);
        sh.set_idash_drift_prone_held(drift_held);
        // Same live boot-reapply pref as the standalone dashboard (see [`feed_from_live_inu`]'s doc).
        sh.set_idash_boot_reapply_armed(staged_inu_prefs().0);

        let prows: Vec<crate::PowerRow> = snap
            .powers
            .iter()
            .map(|p| {
                let (label, tier) = inu_power_meta(p.id);
                crate::PowerRow {
                    id: SharedString::from(p.id.key()),
                    label: SharedString::from(label),
                    tier: SharedString::from(tier),
                    held: p.last_result,
                    drift_prone: p.durability == InuBootDurability::DriftProne,
                }
            })
            .collect();
        sh.set_idash_powers(ModelRc::new(VecModel::from(prows)));

        let events: Vec<crate::InuLogRow> = parse_inu_log(&store.tail_log(INU_EVENTS_SHOWN));
        sh.set_idash_recent_events(ModelRc::new(VecModel::from(events)));
    }

    /// 2-FEED-Inu (SETTINGS · #50): push the live Wire Cake Inu elevation posture + the Kotlin-owned durability
    /// prefs onto the shell's `iset-*` aliases (the InuSettingsPane the ||| INU settings chip lifts — the sixth
    /// + final per-pillar SETTINGS surface). The typed InuState half (paired / powers / expert / provider /
    /// elevation) is read off the SAME spike-local InuStore the dashboard reads (SPIKE HONESTY — the live
    /// running-engine store lands with the single-.so unification wave); the durability half (boot-reapply /
    /// always-on / provider-pref) lives OUTSIDE InuState (Kotlin prefs), so it is read across the JNI seam from
    /// `stagedInuConfig()`. Startup-only like `feed_inu_shell` — the seed is static, so a refresh Timer would
    /// clobber the handlers' optimistic echoes; the interactive echoes carry the live feedback this wave. The
    /// draft host/port/code input fields are DELIBERATELY left unfed (the user owns them). Fail-open throughout.
    ///
    /// `demo_posture` — TRUE when `store` is the SEEDED SPIKE rather than the user's own record, exactly as in
    /// `feed_from_live_inu` / `feed_inu_shell`. It is a PARAMETER, not a re-derivation, so all three surfaces
    /// answer from one decision. #97 marked the DASHBOARD; this pane was missed and kept rendering "PAIRED ·
    /// 3 power(s) held · paired 3d ago" — fabricated by `seed_inu_spike_posture` — with no marking at all,
    /// which is the more misleading of the two, since this is the surface that offers Unpair and Re-pair.
    fn feed_inu_settings_shell(
        sh: &crate::TortaShell,
        store: &torta_core::inu::object::InuStore,
        demo_posture: bool,
    ) {
        use torta_core::inu::{InuBootDurability, InuElevationStatus};
        let snap = store.snapshot();
        sh.set_iset_demo_posture(demo_posture);

        let configured = snap.paired
            || !snap.powers.is_empty()
            || snap.elevation_status != InuElevationStatus::Idle;
        sh.set_iset_configured(configured);
        sh.set_iset_paired(snap.paired);
        sh.set_iset_paired_label(SharedString::from(inu_paired_label(
            snap.paired,
            snap.granted_at,
        )));
        sh.set_iset_active_provider(snap.provider.code());

        let elev = match snap.elevation_status {
            InuElevationStatus::Idle => 0,
            InuElevationStatus::Discovering
            | InuElevationStatus::Pairing
            | InuElevationStatus::Connecting => 1,
            InuElevationStatus::Elevated => 2,
            InuElevationStatus::Failed => 3,
        };
        sh.set_iset_elevation_status(elev);
        sh.set_iset_expert_open(snap.expert_enabled);

        let held = snap.powers.iter().filter(|p| p.last_result).count() as i32;
        let desired = snap.powers.iter().filter(|p| p.desired).count() as i32;
        let drift_desired = snap
            .powers
            .iter()
            .filter(|p| p.desired && p.durability == InuBootDurability::DriftProne)
            .count() as i32;
        sh.set_iset_powers_held(held);
        sh.set_iset_desired_count(desired);
        sh.set_iset_drift_desired_count(drift_desired);

        let prows: Vec<crate::PowerToggleRow> = snap
            .powers
            .iter()
            .map(|p| {
                let (label, tier) = inu_power_meta(p.id);
                crate::PowerToggleRow {
                    id: SharedString::from(p.id.key()),
                    label: SharedString::from(label),
                    hint: SharedString::from(inu_power_hint(p.id)),
                    tier: SharedString::from(tier),
                    desired: p.desired,
                    held: p.last_result,
                    drift_prone: p.durability == InuBootDurability::DriftProne,
                }
            })
            .collect();
        sh.set_iset_powers(ModelRc::new(VecModel::from(prows)));

        // The durability triple lives OUTSIDE the typed InuState (Kotlin prefs) — read it across the JNI
        // seam via the shared [`staged_inu_prefs`] (the same read the two dashboard feeds now consume).
        let (boot_reapply, always_on, provider_pref) = staged_inu_prefs();
        sh.set_iset_boot_reapply_armed(boot_reapply);
        sh.set_iset_always_on(always_on);
        sh.set_iset_provider_pref(provider_pref);
    }

    /// The Kotlin-owned durability triple off the JNI seam (`stagedInuConfig()`), parsed by the
    /// host-tested [`crate::inu_feed::parse_inu_prefs`]. Cold / bridge-silent degrades to the honest
    /// defaults — the boot-reapply flag can only claim `true` off a REAL persisted pref (never an
    /// over-claim of reboot-safety).
    fn staged_inu_prefs() -> (bool, bool, i32) {
        crate::engine_bridge::staged_inu_config()
            .map(|cfg| crate::inu_feed::parse_inu_prefs(&cfg))
            .unwrap_or((false, false, 0))
    }

    /// Pre-format the collar's pair line ("paired 3d ago"; the .slint holds no clock, inu.slint:138). Cold /
    /// unpaired ⇒ "not paired yet". `granted_at` is epoch-ms (the InuState grant stamp); a `0`/future/unreadable
    /// stamp degrades to a plain "paired" (never a fabricated interval).
    fn inu_paired_label(paired: bool, granted_at: i64) -> String {
        if !paired {
            return "not paired yet".to_string();
        }
        if granted_at <= 0 {
            return "paired".to_string();
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let delta = now_ms - granted_at;
        if delta < 0 {
            return "paired".to_string();
        }
        let secs = delta / 1000;
        let (n, unit) = if secs < 60 {
            (secs, "s")
        } else if secs < 3600 {
            (secs / 60, "m")
        } else if secs < 86_400 {
            (secs / 3600, "h")
        } else {
            (secs / 86_400, "d")
        };
        format!("paired {n}{unit} ago")
    }

    /// The UI display twin of Kotlin `PowerCatalogue` (`PowerCatalogue.kt`) — the friendly power NAME + its
    /// PowerTier label ("basic"/"standard"/"deep") for one `InuPowerId`. Labels/tiers are inherently display
    /// data (feedback-simple-ux: plain words, never the raw key); the HELD / DRIFT signal is read off the typed
    /// `InuPowerFlag`, never this map. A closed 21-variant match (the [`torta_core::inu::InuPowerId`] set).
    fn inu_power_meta(id: torta_core::inu::InuPowerId) -> (&'static str, &'static str) {
        use torta_core::inu::InuPowerId as P;
        match id {
            P::AlwaysOnVpn => ("Always-on VPN", "deep"),
            P::Lockdown => ("Lockdown mode", "deep"),
            P::LockdownAllowlistEmpty => ("Strict lockdown (no allowlist)", "deep"),
            P::BatteryBackground => ("Background activity", "basic"),
            P::BatteryRunInBackground => ("Run in background", "basic"),
            P::BatteryWakeLock => ("Keep awake (wake lock)", "standard"),
            P::BatteryDozeWhitelist => ("Ignore battery optimizations", "standard"),
            P::BatteryStandbyBucket => ("Active standby bucket", "standard"),
            P::PostNotifications => ("Post notifications", "basic"),
            P::ReadLogs => ("Read device logs", "deep"),
            P::DataSaverBypass => ("Bypass Data Saver", "standard"),
            P::WriteSecureSettings => ("Tune secure settings", "deep"),
            // #63 S2 amplification — all Tier-3 Expert ("deep") pillar-mapped powers.
            P::PrivateDnsOff => ("Disable private DNS", "deep"),
            P::CaptivePortalOff => ("Silence captive-portal probe", "deep"),
            P::WifiScanThrottleOff => ("Unthrottle Wi-Fi scans", "deep"),
            P::UsageStats => ("Read app usage stats", "deep"),
            P::ScheduleExactAlarm => ("Schedule exact alarms", "deep"),
            P::SystemAlertWindow => ("Draw over other apps", "deep"),
            P::IgnoreSystemDns => ("Ignore system DNS", "deep"),
            P::NetworkRecommendationsOff => ("Disable network recommendations", "deep"),
            P::ActivateVpn => ("Silent VPN activation", "deep"),
        }
    }

    /// The one-line WHY for each power (the settings toggle's sub-caption — feedback-simple-ux: plain words on
    /// what granting it buys the user, never the raw ADB command). The display twin of Kotlin `PowerCatalogue`'s
    /// hint column; the same closed 21-variant [`torta_core::inu::InuPowerId`] set as [`inu_power_meta`].
    fn inu_power_hint(id: torta_core::inu::InuPowerId) -> &'static str {
        use torta_core::inu::InuPowerId as P;
        match id {
            P::AlwaysOnVpn => "Route every app through Tortä — no traffic escapes the tunnel",
            P::Lockdown => "Block all traffic whenever the VPN drops (no leak window)",
            P::LockdownAllowlistEmpty => "Strictest: no app may bypass the locked-down tunnel",
            P::BatteryBackground => "Let Tortä keep working when it is not on screen",
            P::BatteryRunInBackground => "Survive aggressive background-process killing",
            P::BatteryWakeLock => "Hold the CPU awake so the tunnel never stalls asleep",
            P::BatteryDozeWhitelist => "Exempt Tortä from Doze so pairing survives idle",
            P::BatteryStandbyBucket => "Keep Tortä in the active app-standby bucket",
            P::PostNotifications => "Show the pairing + protection status notification",
            P::ReadLogs => "Read device logs to self-diagnose a failed elevation",
            P::DataSaverBypass => "Keep the tunnel alive under Data Saver restrictions",
            P::WriteSecureSettings => "Set the always-on VPN binding without the user digging in Settings",
            P::PrivateDnsOff => "Stop the OS private-DNS resolver from leaking queries around the tunnel",
            P::CaptivePortalOff => "Silence the connectivity-check phone-home so no probe escapes",
            P::WifiScanThrottleOff => "Sense network changes fast so the tunnel re-establishes without a gap",
            P::UsageStats => "Let Warden see per-app usage to make sharper allow/deny calls",
            P::ScheduleExactAlarm => "Fire server rotations on the exact second even under Doze",
            P::SystemAlertWindow => "Float the always-on Tortä status bar over any screen",
            P::IgnoreSystemDns => "Purge any pinned system DoT resolver — zero DNS survives outside Tortä",
            P::NetworkRecommendationsOff => "Stop the OS steering connectivity around the Tortä netstack",
            P::ActivateVpn => "Re-arm the tunnel with no consent prompt — seamless always-on",
        }
    }

    /// Parse the `query-inu.log` tail (oldest→newest, '\n'-joined) into the typed `InuLogRow` feed. Each line
    /// is the greppable schema `<ts_ms> <EVENT> <provider> <detail…>` (inu/log.rs:60): the EVENT token becomes
    /// the lowercased `event` (the .slint colors "grant"/"pair"/… ), the provider+detail tail becomes the
    /// readable `detail`, and `ok` is `false` only for a `FAIL` event (the honest fault line). A malformed /
    /// empty line is skipped (never a torn row).
    fn parse_inu_log(tail: &str) -> Vec<crate::InuLogRow> {
        tail.lines()
            .filter_map(|line| {
                let mut it = line.split_whitespace();
                let _ts = it.next()?; // the injected wall-clock stamp (not shown)
                let event = it.next()?; // EVENT token (PAIR/ELEVATE/GRANT/REVERT/SWITCH/DRIFT_REAPPLY/FAIL)
                let detail: String = it.collect::<Vec<_>>().join(" "); // provider + detail tail
                Some(crate::InuLogRow {
                    event: SharedString::from(event.to_lowercase()),
                    detail: SharedString::from(detail),
                    ok: event != "FAIL",
                })
            })
            .collect()
    }

    /// Seed a REALISTIC healthy-ELEVATED posture into the spike-local `InuStore` through the REAL
    /// control-plane path — the SAME reason the on-device Centauri rail reads a spike-local Object:
    /// this `.so` statically links its OWN torta_core (SPIKE HONESTY, above) so the Kotlin driver's live
    /// `InuStore` state is NOT reachable here, and a fresh store is [`InuState::cold`] (all-zero). To WITNESS
    /// the feed pushing REAL typed values (not the .slint sample defaults, not 0/0/0), we drive a plausible
    /// posture through `persist` (the real RAM⊗NAND write-through) + `log_event` (the real `query-inu.log`
    /// seam), then read it straight back via `snapshot`/`tail_log` in [`feed_from_live_inu`]. The NUMBERS on
    /// screen therefore travel the LIVE typed pipeline (`persist`→`snapshot`→feed), exactly like Centauri's
    /// `capacity`/hosts — this is a spike FIXTURE, never a claim of a measured on-device elevation.
    ///
    /// The posture: paired 3 days ago over Self-ADB, a live ELEVATED session, 3 powers desired + held, all
    /// reboot-DURABLE (so `drift-prone-held` is 0 and the honest `boot-reapply-armed=false` raises no false
    /// DRIFT-UNGUARDED fault). A clean crown ⇒ ELEVATED.
    fn seed_inu_spike_posture(store: &torta_core::inu::object::InuStore) {
        use torta_core::inu::{
            InuBootDurability, InuElevationStatus, InuEvent, InuPowerFlag, InuPowerId, InuProvider,
            InuState,
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let three_days_ms: i64 = 3 * 24 * 60 * 60 * 1000;
        let held = |id: InuPowerId| InuPowerFlag {
            id,
            desired: true,
            last_verified: now_ms,
            last_result: true,
            durability: InuBootDurability::Durable,
        };
        let state = InuState {
            elevation_status: InuElevationStatus::Elevated,
            provider: InuProvider::SelfAdb,
            paired: true,
            granted_at: now_ms - three_days_ms,
            expert_enabled: false,
            powers: vec![
                held(InuPowerId::BatteryDozeWhitelist),
                held(InuPowerId::ReadLogs),
                held(InuPowerId::AlwaysOnVpn),
            ],
            // The #21 G7-RESIDUAL absorb flag — false = the doc'd honest posture above (all powers
            // DURABLE, so no boot-reapply arm is needed and no false DRIFT-UNGUARDED fault raises).
            boot_reapply: false,
            fully_protected: false, // RECOMPUTED by `persist` (`normalized`) — never trusted from the caller
        };
        // The REAL control-plane write (RAM hot tier ⊗ NAND durable mirror) — the same path Kotlin drives.
        store.persist(state);
        // The REAL per-pillar review-log seam → `query-inu.log`, read back by the RECENT EVENTS feed.
        store.log_event(
            InuEvent::Pair,
            InuProvider::SelfAdb,
            "loopback self-adb".to_string(),
            now_ms - three_days_ms,
        );
        store.log_event(
            InuEvent::Elevate,
            InuProvider::SelfAdb,
            "uid=2000".to_string(),
            now_ms,
        );
        store.log_event(
            InuEvent::Grant,
            InuProvider::SelfAdb,
            "always_on_vpn=held".to_string(),
            now_ms,
        );
    }

    /// How many classified rows the RECENT ROTATIONS feed tails from `query-rotation.log` per refresh.
    const ROTATION_ROWS_SHOWN: i32 = 24;

    /// Split ONE `query-rotation.log` line into the typed `RotationLogRow` the dashboard renders. The
    /// shared pillar-log format is `"[ts] rotation <event> family=<f> idx=<n> servers_list=<a,b> relays=<r,s>"`
    /// (PillarLog / log_tier): the SECOND bare token (after the `rotation` pillar tag) is the flip kind
    /// (switch / warm / cadence), and the k=v pairs carry the cursor. #22 s5C — `at` keeps the line's own
    /// `[ts]` timestamp (WHEN the flip happened) and `servers_list`/`relays` carry the actual resolver /
    /// relay NAMES that flip installed (comma-joined in the log, re-joined " · " for display). Tolerant —
    /// a missing key keeps the default, so pre-s5C log lines still render via the `family` fallback.
    /// Join a comma-separated NAME list for display, capped — the first `cap` names verbatim, the rest
    /// folded into "+N more". #22 s5C — an auto-picked rotation can honestly carry 60 relays; a 60-name
    /// wall in a dashboard row is the exact confusion this pass exists to kill. The LOG keeps the full
    /// truth; only the rendered string is capped.
    fn join_names_capped(csv: &str, cap: usize) -> String {
        let names: Vec<&str> = csv.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        if names.len() <= cap {
            names.join(" · ")
        } else {
            format!("{} +{} more", names[..cap].join(" · "), names.len() - cap)
        }
    }

    fn classify_rotation_line(line: &str) -> crate::RotationLogRow {
        let (at, body) = match (line.starts_with('['), line.find(']')) {
            (true, Some(end)) => (line[1..end].to_string(), line[end + 1..].trim_start()),
            _ => (String::new(), line),
        };
        let mut event = String::new();
        let mut family = String::new();
        let mut idx = 0i32;
        let mut servers = String::new();
        let mut relays = String::new();
        let mut bare_seen = 0u8; // [1] = the "rotation" pillar tag, [2] = the event kind
        for tok in body.split_whitespace() {
            match tok.split_once('=') {
                Some(("family", v)) => family = v.to_string(),
                Some(("idx", v)) | Some(("index", v)) => idx = v.parse().unwrap_or(0),
                Some(("servers_list", v)) => servers = join_names_capped(v, 4),
                Some(("relays", v)) => relays = join_names_capped(v, 3),
                Some(_) => {}
                None => {
                    bare_seen = bare_seen.saturating_add(1);
                    if bare_seen == 2 {
                        event = tok.to_string();
                    }
                }
            }
        }
        // A log line with no pillar-tag prefix keeps the first bare token as the event.
        if event.is_empty() {
            if let Some(first) = body.split_whitespace().find(|t| !t.contains('=')) {
                event = first.to_string();
            }
        }
        crate::RotationLogRow {
            event: event.into(),
            family: family.into(),
            idx,
            at: at.into(),
            servers: servers.into(),
            relays: relays.into(),
        }
    }

    /// Feed the IN-SHELL Rotation pillar DASHBOARD (THE ORBITAL WHEEL — rotation.slint `RotationPane`,
    /// mounted behind ||| → PILLARS → ROTATION → DASHBOARD) — the typed `RotationSnapshot` off the live
    /// `MaskSolver` control-plane read (object.rs:608 `rotation_snapshot()` over the bound durable dir)
    /// pushed FIELD-FOR-FIELD onto the shell's `rdash-*` forwarding aliases (the Beast/Centauri/MaskSolver
    /// in-shell precedent: the pane's props are byte-equal, the shell forwards them `<=>`, ONE host push
    /// drives the embedded pane). The six typed fields are the SAME the Kotlin surface reads; the warm-RTT
    /// leaderboard crosses as the typed `RttHint` list (fastest-first — the #1-badge sort); the operator-
    /// family RING is host-derived from the real cursor + hint labels (torta_core exposes NO pool-candidates
    /// surface — the ring is a host feed, rotation.slint:42); the RECENT-ROTATION feed tails the per-pillar
    /// `query-rotation.log` (the SAME `log_tail_recent` RAM⊗NAND read path the ④ QUERY tab uses). A cold /
    /// unbound read ⇒ honest zeros (DORMANT), never a fabricated wheel. `next_flip_secs` stays the durable
    /// read's value (0 — torta_core is clock-free, object.rs:221: the RUNNING host pushes the live countdown).
    /// Re-called each tick while the pane is shown (android_main's refresh Timer) so the RUNNING engine's
    /// snapshot streams once the single-.so unification lands. The D1 Centauri-feed template, mapped to the wheel.
    fn feed_from_live_rotation(
        shell: &crate::TortaShell,
        solver: &torta_core::MaskSolver,
        data_dir: &str,
    ) {
        let snap = solver.rotation_snapshot();

        // ── the SIX typed RotationSnapshot fields, field-for-field (object.rs:212) → the rdash-* aliases ──
        shell.set_rdash_rotation_family(snap.last_family.clone().into());
        shell.set_rdash_cadence_secs(snap.cadence_secs.clamp(0, i64::from(i32::MAX)) as i32);
        shell.set_rdash_rotation_index(snap.rotation_index.clamp(0, i64::from(i32::MAX)) as i32);
        shell.set_rdash_next_flip_secs(
            snap.next_flip_secs
                .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
        );
        shell.set_rdash_rehydrated_warm(snap.rehydrated_warm);

        // `configured` (the pillar is armed) is a Kotlin pref (DNS_ENGINE + ROTATION) this .so cannot
        // read — but a durable record PROVES it was armed (a flip persisted it). Honest derive: a warm
        // read (or a live cadence / family) is armed; a cold read is DORMANT. Never fakes an unarmed wheel.
        let configured =
            snap.rehydrated_warm || snap.cadence_secs > 0 || !snap.last_family.is_empty();
        shell.set_rdash_configured(configured);

        // ── the warm-RTT leaderboard — the typed RttHint list, fastest-first, rtt pre-formatted "<n>ms" ──
        let mut hints = snap.rtt_hints.clone();
        hints.sort_by_key(|h| h.rtt_ms);
        let hint_rows: Vec<crate::RotationHintRow> = hints
            .iter()
            .map(|h| crate::RotationHintRow {
                id: h.id.clone().into(),
                rtt: format!("{}ms", h.rtt_ms).into(),
                ms: h.rtt_ms.clamp(0, i64::from(i32::MAX)) as i32,
            })
            .collect();
        shell.set_rdash_rtt_hints(ModelRc::new(VecModel::from(hint_rows)));

        // ── the operator-family RING — host-derived (rotation.slint:42: host-supplied; torta_core has no
        //    candidates surface). The active family + each warm-hint's family-prefix (the coarse operator
        //    grouping of the transport label), deduped, order-stable, the active one lit by name-match. ──
        let mut families: Vec<crate::RotationFamilyRow> = Vec::new();
        let mut seen = std::collections::HashSet::<String>::new();
        if !snap.last_family.is_empty() && seen.insert(snap.last_family.clone()) {
            families.push(crate::RotationFamilyRow {
                name: snap.last_family.clone().into(),
            });
        }
        for h in &snap.rtt_hints {
            let fam = h.id.split('-').next().unwrap_or(h.id.as_str());
            if !fam.is_empty() && seen.insert(fam.to_string()) {
                families.push(crate::RotationFamilyRow { name: fam.into() });
            }
        }
        shell.set_rdash_families(ModelRc::new(VecModel::from(families)));

        // ── the RECENT-ROTATION feed — the tail of the per-pillar query-rotation.log (empty when the log
        //    is absent: the honest "not written yet", the SAME read path the ④ QUERY tab uses). ──
        let log_path = crate::feed_shape::query_log_path(data_dir, "rotation");
        let rot_rows: Vec<crate::RotationLogRow> =
            torta_core::log_tail_recent(log_path, ROTATION_ROWS_SHOWN)
                .unwrap_or_default()
                .lines()
                .rev() // newest first — the feed's reading order
                .filter(|l| !l.trim().is_empty())
                .map(classify_rotation_line)
                .collect();
        shell.set_rdash_recent_rotations(ModelRc::new(VecModel::from(rot_rows)));

        // ── 2-DRIVE-PILLARS: sync the ACTION controls to HOST truth (the real RESOLVER_ROTATION_* prefs +
        //    the live DNSCrypt state) so the toggle/chips/Rotate-Now button render felt-truth, never a local
        //    echo. JNI reads via the TortaPillarBridge / TortaSlintBridge (fail-open → the pref defaults on a
        //    non-android / standalone-witness build). Rides the SAME 1 s refresh this fn drives on-device. ──
        shell.set_rdash_rotation_enabled(crate::engine_bridge::rotation_enabled().unwrap_or(true));
        shell.set_rdash_cadence_minutes(crate::engine_bridge::rotation_cadence().unwrap_or(30));
        shell.set_rdash_engine_running(
            crate::engine_bridge::dnscrypt_state_code()
                .map(|c| c == 2)
                .unwrap_or(false),
        );

        // ── #22 s5A: PICK FILTER chips ← the ONE held dnscrypt-config authority (boot-synced to the
        //    shared Rc, re-set on every toggle — the SAME require_*/family keys rotationPolicy() reads
        //    from the materialized toml at every pick); POOL SHAPE ← the GEEK-clamped rotation prefs
        //    over JNI (fail-open to the LOCKED-SPEC defaults 10/10 on a non-android witness build). ──
        let dcfg = torta_core::dnscrypt_config_get();
        shell.set_rdash_crit_nolog(dcfg.require_nolog);
        shell.set_rdash_crit_dnssec(dcfg.require_dnssec);
        shell.set_rdash_crit_nofilter(dcfg.require_nofilter);
        shell.set_rdash_crit_ipv4(dcfg.ipv4_servers);
        shell.set_rdash_crit_ipv6(dcfg.ipv6_servers);
        shell.set_rdash_crit_proto_dnscrypt(dcfg.dnscrypt_servers);
        shell.set_rdash_crit_proto_doh(dcfg.doh_servers);
        shell.set_rdash_crit_proto_odoh(dcfg.odoh_servers);
        shell.set_rdash_crit_sysdns(dcfg.ignore_system_dns);
        shell.set_rdash_max_servers(crate::engine_bridge::rotation_max_servers().unwrap_or(10));
        shell.set_rdash_max_relays(crate::engine_bridge::rotation_max_relays().unwrap_or(10));

        // #22 s5C — the relay-chain baseline is honest-cold (no chain claimed) until the LIVE bridge
        // record below proves one; the durable snapshot deliberately carries no relay names.
        shell.set_rdash_chain_relays("".into());
        shell.set_rdash_chain_depth(0);

        // ── SLINT substitution · 4-FIX round 5 (finding 1 / Observation E): OVERLAY the REAL durable
        //    rotation cursor over the JNI bridge (`live_rotation_state()` → TortaPillarBridge
        //    .liveRotationState → TortaCore.maskSolverRotationSnapshot over the LIVE RotationManager's
        //    persisted record). The cold local read above is the HONEST DORMANT baseline (empty wheel —
        //    the retired spike seed is gone); when the running engine has actually rotated, its durable
        //    record feeds the REAL family / diversity index / cadence / warm-RTT wheel. `None` (bridge
        //    unreachable OR never rotated) ⇒ the DORMANT baseline stands — never a fabricated family. ──
        if let Some(rec) = crate::engine_bridge::live_rotation_state() {
            use crate::engine_bridge::{rot_field_bool, rot_field_i64, rot_field_str};
            let fam = rot_field_str(&rec, "family");
            shell.set_rdash_rotation_family(fam.clone().into());
            if let Some(v) = rot_field_i64(&rec, "cadence_secs") {
                shell.set_rdash_cadence_secs(v.clamp(0, i64::from(i32::MAX)) as i32);
            }
            if let Some(v) = rot_field_i64(&rec, "index") {
                shell.set_rdash_rotation_index(v.clamp(0, i64::from(i32::MAX)) as i32);
            }
            if let Some(v) = rot_field_i64(&rec, "next_flip_secs") {
                shell.set_rdash_next_flip_secs(
                    v.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
                );
            }
            shell.set_rdash_rehydrated_warm(rot_field_bool(&rec, "warm"));
            // A real durable record exists ⇒ the pillar is armed (the honest-derive twin of the cold read).
            shell.set_rdash_configured(true);

            // #22 s5C — the LIVE relay chain (bridge `chain_relays`: the DISTINCT relay names the last
            // committed rotation's routes actually ride; RotationManager.liveRelayChain over JNI). Depth
            // is COUNTED from the names — never a guessed number; "" ⇒ the cold baseline above stands.
            let chain = rot_field_str(&rec, "chain_relays");
            let depth =
                chain.split(',').map(str::trim).filter(|s| !s.is_empty()).count();
            if depth > 0 {
                // Capped for the crown card — the depth tile carries the honest full count.
                shell.set_rdash_chain_relays(join_names_capped(&chain, 3).into());
                shell.set_rdash_chain_depth(depth.min(i32::MAX as usize) as i32);
            }

            // The warm-RTT leaderboard + the operator-family RING — from the bridged "id:ms;id:ms" blob.
            let mut parsed: Vec<(String, i64)> = rot_field_str(&rec, "hints")
                .split(';')
                .filter(|s| !s.trim().is_empty())
                .filter_map(|pair| {
                    let (id, ms) = pair.rsplit_once(':')?;
                    Some((id.to_string(), ms.trim().parse::<i64>().ok()?))
                })
                .collect();
            parsed.sort_by_key(|(_, ms)| *ms); // fastest-first (the #1-badge sort)
            let hint_rows: Vec<crate::RotationHintRow> = parsed
                .iter()
                .map(|(id, ms)| crate::RotationHintRow {
                    id: id.clone().into(),
                    rtt: format!("{ms}ms").into(),
                    ms: (*ms).clamp(0, i64::from(i32::MAX)) as i32,
                })
                .collect();
            shell.set_rdash_rtt_hints(ModelRc::new(VecModel::from(hint_rows)));

            let mut families: Vec<crate::RotationFamilyRow> = Vec::new();
            let mut seen = std::collections::HashSet::<String>::new();
            if !fam.is_empty() && seen.insert(fam.clone()) {
                families.push(crate::RotationFamilyRow { name: fam.into() });
            }
            for (id, _) in &parsed {
                let f = id.split('-').next().unwrap_or(id).to_string();
                if !f.is_empty() && seen.insert(f.clone()) {
                    families.push(crate::RotationFamilyRow { name: f.into() });
                }
            }
            shell.set_rdash_families(ModelRc::new(VecModel::from(families)));
        }
    }

    /// The android-activity entry point (OMEGA Stage-D · D3, step 8 — THE DESIGN FINALE).
    /// `#[no_mangle]` so the android-activity glue inside this cdylib resolves it by symbol name —
    /// the documented slint-on-android pattern (the D1 #69 rail, unchanged). Defined LAST in the
    /// module so the two K5 mount macros above are lexically in scope.
    ///
    /// The on-device SLINT entry is now THE 4-TAB HOME (`TortaShell`):
    ///  · ① HOME + ② ENGINE + ④ QUERY are fed from typed torta_core reads (see [`feed_home`] /
    ///    [`feed_engine`] / [`wire_query_feed`] — real spike-local Records, honest zero baselines).
    ///  · ③ DNS and the burger's DNSCRYPT rail are TWO MOUNTS of the one DnscryptSection pane,
    ///    both wired onto ONE shared `Rc<RefCell<DnscryptProxyConfig>>` fed from the REAL on-disk
    ///    `dnscrypt-proxy.toml`; each window swap re-pushes the shared Record onto the mount being
    ///    shown, so edits made on either surface land on the other (one typed authority, two views).
    ///  · the D2 ||| burger rides behind the shell's ||| door; the D1 CENTAURI dashboard rail
    ///    rides behind the burger's centauri private tab — all window-swaps on the one event loop.
    ///    `close-advanced` now RETURNS HOME (the D2 quit-on-close is retired: the shell is the app).
    #[no_mangle]
    fn android_main(app: slint::android::AndroidApp) {
        // Read the app-private data dir BEFORE the backend consumes `app` — the Centauri Object
        // roots its content-addressed cache here (a REAL app dir, never a fabricated path).
        let data_dir = app
            .internal_data_path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| String::from("/data/local/tmp"));
        let cache_dir = format!("{data_dir}/centauri-slint-spike");

        slint::android::init(app).expect("slint android backend init (#69 spike)");

        // ★ THE ANDROID SINGLE-SURFACE LAW (SLINT substitution · 1A — MEASURED, not doctrine):
        // the android-activity backend hands EVERY component the ONE shared WindowAdapter
        // (i-slint-backend-android-activity-1.17.0 lib.rs:99 `create_window_adapter` returns
        // `self.window.clone()`), and each generated component `new()` EAGERLY resolves that
        // adapter and `WindowInner::set_component()`s ITSELF onto it (the slint-build generated
        // `window_adapter_ref` get_or_try_init). `show()`/`hide()` only toggle visibility — they
        // never re-take the component slot (i-slint-core-1.17.0 window.rs:1614 `show` renders
        // `try_component()`, the stored slot). So on-device the LAST-CONSTRUCTED component OWNS
        // the surface: the D2 burger + the D1 Centauri rail are constructed FIRST, and the
        // DESIGN-FINALE `TortaShell` is constructed LAST — the launcher opens the 4-TAB HOME
        // (witnessed: the pre-1A order rendered the Centauri dashboard at launch instead).
        // 1B closed the corollary: window-swap navigation is DEAD on-device (`hide()` hides the
        // one window — the whole app vanished), so ALL navigation is now in-shell state flips
        // inside home_shell.slint; see the Navigation block below.

        // ---- The D2 ||| burger (constructed FIRST — must NOT own the android surface). ----
        let burger = crate::AdvancedBurger::new().expect("AdvancedBurger constructs on-device");
        feed_pillar_tabs(&burger);

        // ONE spike-local Centauri Object serves BOTH the HOME "CDN local" counter and the D1
        // dashboard rail (one instance, one truth).
        let centauri = torta_core::mirror::object::Centauri::new(cache_dir);

        // ---- 2-FEED-Centauri: the Centauri pillar dashboard is now an IN-SHELL pane (the
        // centauri-dash section behind ||| → PILLARS → CENTAURI). No hidden CentauriDashboard Window is
        // constructed — the shell's byte-equal Centauri aliases are fed directly (after the shell is
        // built, below), the same embed pattern as MaskSolver's ms-dash. ----

        // ---- The Wire Cake Inu rail (the collar-medallion dashboard) — fed from the live typed `InuState`
        // off a spike-local `InuStore` rooted in the app-private dir (its OWN torta_core — SPIKE HONESTY,
        // above — so it seeds a realistic posture through the REAL persist/log path, then reads it straight
        // back; the numbers travel the live typed pipeline, never a .slint literal). Same committed position
        // as the Centauri rail: constructed BEFORE the shell so the shell still owns the launch surface. ----
        // ★ PREFER THE REAL KOTLIN-DRIVEN STORE OVER THE SPIKE. `inu/object.rs:29` states the
        // contract plainly — "KOTLIN IS THE AUTHORITATIVE DRIVER, Rust is the durable+cache" — and
        // that driver IS built: `WireCakeInuComponent.kt:100 provideInuStore()` ->
        // `RustPowerStateStore.kt:150 InuStore(app.filesDir.absolutePath)`. filesDir IS `data_dir`
        // here: line 56 above builds the spike log as `{base}/files/wire-cake-inu-spike/…`, so
        // `data_dir` == `{base}/files`. Opening at `data_dir` therefore lands on the SAME record
        // (`wire-cake-inu-state`) the app's own pairing/elevation flow writes.
        //
        // The predicate asks the ONE question that matters — "does a record exist?" — and asks it of the
        // durable tier directly (`rehydrate_exists()`, object.rs), never by comparing values. Two earlier
        // drafts got this wrong in instructive ways:
        //   · `granted_at > 0` — a record written by a boot-reapply or provider change carries real user
        //     state with `granted_at` still 0, so the seeded spike would have rendered OVER it.
        //   · `!= InuState::cold()` — closer, but `rotation.rs:140` documents the exact trap: a record
        //     that decoded to cold-ish values is a distinction `== cold()` structurally CANNOT make.
        // Both would fail in the same direction — showing invented elevation state as though it were the
        // user's. Only a genuinely never-written record falls back to the spike, so the rail demonstrates
        // the pipeline instead of rendering blank. Both ctors are IO-free (the no-boot-IO-scan law,
        // object.rs:21), so opening two stores costs nothing at boot.
        // Publish the durable tier so the argument-free `pillar_rows()` can read the REAL Inu record
        // instead of the hardcoded "OFF" literal it used to carry (the 9th-pillar gap). Must happen
        // BEFORE the shell's first `pillar_rows()` push, or the boot row renders the pre-launch OFF.
        crate::publish_inu_data_dir(&data_dir);
        let inu_real = torta_core::inu::object::InuStore::new(data_dir.clone());
        let inu_is_live = inu_real.rehydrate_exists().is_some();
        let inu_store = if inu_is_live {
            inu_real
        } else {
            let spike =
                torta_core::inu::object::InuStore::new(format!("{data_dir}/wire-cake-inu-spike"));
            seed_inu_spike_posture(&spike);
            spike
        };
        let inu = crate::InuDashboard::new().expect("InuDashboard constructs on-device");
        feed_from_live_inu(&inu, &inu_store, !inu_is_live);

        // ---- The Rotation orbital-wheel rail (the operator-family wheel) — the spike-local `MaskSolver`
        // bound to the app-private dir (its OWN torta_core — SPIKE HONESTY, above — so it seeds a realistic
        // posture through the REAL persist / `rotation_snapshot()` path, then reads it straight back; the
        // numbers travel the live typed pipeline, never a .slint literal). 2-FEED-Rotation: the Rotation
        // pillar dashboard is now an IN-SHELL pane (the rotation-dash section behind ||| → PILLARS →
        // ROTATION), fed onto the shell's byte-equal `rdash-*` aliases AFTER the shell is built (below) +
        // refreshed while shown — the same embed pattern as MaskSolver/Centauri/Beast. No standalone
        // RotationDashboard Window is constructed on the launch path (it would fight the single-surface law).
        // An owned copy of the data dir for BOTH the shell feed AND the opt-in witness feed below — the
        // shared K5 `wire_dnscrypt_edits!(burger, …, data_dir)` MOVES `data_dir`, so the witness (which
        // runs after it) reads this clone (E0382-safe, fully inside this task's own code).
        let rotation_data_dir = data_dir.clone();
        // SLINT substitution · 4-FIX round 5 (finding 1 / Observation E): the rotation SPIKE SEED is
        // RETIRED (no more persisted mullvad/cloudflare/quad9). An UNBOUND local `MaskSolver` gives the
        // HONEST DORMANT baseline (cold: no family · index 0 · empty wheel — object.rs proves an unbound
        // handle reads honest-cold); `feed_from_live_rotation` OVERLAYS the REAL durable cursor over the
        // `live_rotation_state()` JNI bridge when the running engine has actually rotated at least once.
        let rotation_solver = torta_core::MaskSolver::new();

        // ---- The Warden firewall dashboard (SLINT substitution · 2-FEED-Warden) — fed from the live
        // typed `WardenSnapshot` off a SPIKE-LOCAL `WardenObject` armed with a representative posture
        // (its OWN torta_core — SPIKE HONESTY, above — so it exercises the REAL install/verdict/snapshot
        // path, then reads it straight back; the numbers travel the live typed pipeline, never a .slint
        // literal). Same committed position as the Centauri/Inu/Rotation rails: constructed BEFORE the
        // shell so the shell still owns the launch surface (embedding it as an in-shell pane is the next
        // wave; the feed is ready + refreshed on the pillar-dashboard intent below). ----
        // SLINT substitution · 4-FIX round 5 (finding 4): the WARDEN SPIKE ARMING is RETIRED — no more
        // fabricated per-app matrix (synthetic apps/uids 10101-10105) or synthetic verdict batch. A
        // fresh UNARMED `WardenObject` reads the HONEST DORMANT baseline (disarmed · empty matrix · zero
        // verdicts); `feed_warden_shell` OVERLAYS the LIVE firewall's REAL aggregate (allow + per-tier
        // deny) over the round-1 `live_warden_stats()` bridge when the running engine has it armed.
        let warden = torta_core::WardenObject::new();
        let warden_dash =
            crate::WardenDashboard::new().expect("WardenDashboard constructs on-device");
        crate::warden_feed::feed_from_live_warden(&warden_dash, &warden);

        // ---- THE DESIGN FINALE SHELL: constructed LAST → owns the single android surface →
        // the 4-tab Home IS what the launcher opens (the 1A outcome). ----
        let shell = crate::TortaShell::new().expect("TortaShell constructs on-device");
        feed_home(&shell, &centauri);
        // 2-FEED-Centauri (SETTINGS) · the cloaked-CDN watch-list for the in-shell CentauriSettingsPane —
        // the REAL `centauri_cdn_hosts()` engine surface (the SAME roster the dashboard renders), NOT the
        // .slint sample literals. Fed ONCE (a static build-time roster; the posture/scalars stream on the
        // 500 ms overlay). The FULL list lands (uncapped) so the pane's "(N watched)" label is honest —
        // every watched host IS mapped/cloakable, so `mapped: true` across the roster.
        {
            let host_rows: Vec<crate::CdnHostRow> = torta_core::centauri_cdn_hosts()
                .into_iter()
                .map(|h| crate::CdnHostRow {
                    host: h.into(),
                    mapped: true,
                })
                .collect();
            shell.set_cs_cdn_hosts(ModelRc::new(VecModel::from(host_rows)));
        }
        // Feed the GENERAL section pillar toggles from host preferences (rotation / solver / warden)
        // so the Slint UI shows HOST truth, not spike defaults (closes the preferences persistence bug).
        // QUALIFIED: this lives in `engine_bridge` (1604-2960), not in `android_spike` like its
        // neighbours below. The unqualified call could never have compiled for Android -- and this
        // module is `#[cfg(target_os = "android")]`, so a host `cargo build` never elaborated it
        // and the break stayed invisible until an actual .so was built.
        crate::engine_bridge::feed_general_section_prefs(&shell);
        feed_engine(&shell);
        // N6c: land the honest initial forwarder card (DORMANT until the tunnel arms netstack);
        // the 1 s ENGINE-tab timer below keeps it streaming while the tab is shown.
        feed_from_live_forwarder(&shell);
        // CP-U: land the honest initial UNDERGROUND card the same way (DORMANT until the
        // resolver boot arms the licence store); it shares the forwarder's 1 s ENGINE-tab timer.
        feed_from_live_underground(&shell);
        // SLINT substitution · 4-FIX-1: overlay the LIVE running-engine ledger + budget the moment the
        // shell is built (the .so-split fix — replaces the cold spike-local reads feed_home/feed_engine
        // seed). The 500 ms poll below keeps it streaming; here it lands the honest initial state.
        overlay_live_engine(&shell, false);
        wire_query_feed(&shell, data_dir.clone());

        // ---- 2-FEED-Centauri: feed the in-shell Centauri pillar DASHBOARD (the centauri-dash section,
        // reached via ||| → PILLARS → CENTAURI dashboard chip). Push the shell's byte-equal Centauri
        // aliases from the live spike-local Object NOW (so the pane shows REAL engine numbers the moment
        // it lifts — capacity=1024 (MAX_ENTRIES), the 8 cloaked CDN hosts, honest cold zeros — never the
        // .slint sample defaults), then REFRESH every second WHILE it is shown. The refresh rides a slint
        // Timer (not the single open-pillar-dashboard host callback), so it never contends with the
        // sibling pillar embeds — the .slint chip already flipped the section; the host re-pushes truth. ----
        feed_from_live_centauri(&shell, &centauri);
        let centauri_refresh_timer = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            let cen = centauri.clone();
            centauri_refresh_timer.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open()
                            && sh.get_advanced_section().as_str() == "centauri-dash"
                        {
                            feed_from_live_centauri(&sh, &cen);
                        }
                    }
                },
            );
        }

        // ---- #60C-4 CARBON RENDERER SEAM: feed the carbon-dash pane's texture from
        // carbon_bridge::surface — every frame genuinely rendered through the assimilated
        // carbonyl gfx primitives (THE CARBON RING probe + orbiting glint), lifted into a
        // SharedPixelBuffer and pushed to the shell's `carbon-frame`. FELT-TRUTH:
        // `carbon-frame-live` flips true only AFTER the first real frame lands; the timer
        // renders ONLY while the pane is shown (the Centauri/MaskSolver template), so the
        // seam never contends with the sibling pillar embeds. ----
        // ---- #60C TEXT-MODE LANE v0 + #61D PRECEDENCE WIRE — the REAL browse pass:
        // carbon-navigate(url) FIRST takes a genuine LaneDecision off the REAL layer
        // stores for the REAL host (Warden firewall > Underground teeth > YeAH QoS —
        // the proven route law, one decision per navigation, absent entries allow).
        // A Denied lane NEVER reaches the Kotlin fetch bay: the socket genuinely
        // never opens, and the denial line names the layer that bit. A Routed lane
        // flips to "fetching …" at fire time and the page renders only when a fetch
        // GENUINELY lands (seam timer below polls the bay seq). ----
        {
            let shell_weak = shell.as_weak();
            let nav_probe =
                std::cell::RefCell::new(carbon_bridge::route::SocketProbe::new());
            shell.on_carbon_navigate(move |url| {
                if let Some(sh) = shell_weak.upgrade() {
                    let url = url.to_string();
                    // #61D: the judged name is the URL's host, judged by the SAME laws
                    // the resolver enforces (one law, two callers — never a copy).
                    let host = url
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .split(['/', '?', '#'])
                        .next()
                        .unwrap_or("")
                        .split(':')
                        .next()
                        .unwrap_or("")
                        .to_string();
                    let fw_deny = torta_core::navigate_gate_firewall(host.clone());
                    let rep_deny = torta_core::navigate_gate_reputation(host.clone());
                    // QoS class = the live YeAH phase at fire time (real read).
                    let qos: u8 = match torta_core::beast_live_snapshot().mode.as_str() {
                        "SLOW-START" => 0,
                        "YEAH" => 1,
                        "COMPETING" => 2,
                        _ => 3, // RECOVERY
                    };
                    let decision = nav_probe.borrow_mut().decide(fw_deny, rep_deny, qos);
                    match decision {
                        carbon_bridge::route::LaneDecision::Denied { reason } => {
                            // The deny is REAL: no fetch fires, no socket opens.
                            sh.set_carbon_page_status(
                                format!(
                                    "⛔ route DENIED ({reason:?}) — {host} never reached the socket layer"
                                )
                                .into(),
                            );
                        }
                        carbon_bridge::route::LaneDecision::Routed { qos_class } => {
                            #[cfg(target_os = "android")]
                            {
                                sh.set_carbon_page_status(
                                    format!(
                                        "fetching {url} … (routed QoS {qos_class}, through the tunnel)"
                                    )
                                    .into(),
                                );
                                crate::engine_bridge::carbon_fetch(&url);
                            }
                            #[cfg(not(target_os = "android"))]
                            sh.set_carbon_page_status(
                                format!(
                                    "routed (QoS {qos_class}) — but no fetch lane on desktop; the Kotlin bay is android-only ({url} not fetched)"
                                )
                                .into(),
                            );
                        }
                    }
                }
            });
        }
        let carbon_seam_timer = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            let mut surface = carbon_bridge::surface::CarbonSurface::new(192, 96);
            // ---- #60D ROUTING SEAM: the socket-layer probe rides the SAME pane-gated
            // tick. Every decision is fed off LIVE engine reads — Beast phase off the
            // process-global live snapshot, Underground reputation off the real store
            // (the probe host carries no fabricated entry: an absent score is reported
            // as exactly that). The probe opens NO real socket — it proves the seam. ----
            let mut route_probe = carbon_bridge::route::SocketProbe::new();
            // ---- #60E SANDBOX HARDENING: the fs jail arms ONCE (first shown tick)
            // at a REAL directory the process genuinely owns; the arm-time probe
            // takes real decisions (counters grow only then — the per-tick line
            // re-reports, it never re-probes). The permission map starts EMPTY:
            // 0 sites is the default-deny truth, no grant is ever fabricated. ----
            let mut sandbox_jail: Option<carbon_bridge::sandbox::FsJail> = None;
            let sandbox_perms = carbon_bridge::sandbox::PermissionMap::new();
            let mut tick: u32 = 0;
            // #60C: the fetch-bay watermark — pages land only when the Kotlin seq
            // genuinely advances past this (0 = nothing ever landed).
            #[cfg(target_os = "android")]
            let mut carbon_last_seq: i64 = 0;
            carbon_seam_timer.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(100),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open()
                            && sh.get_advanced_section().as_str() == "carbon-dash"
                        {
                            tick = tick.wrapping_add(6);
                            // ---- #60C TEXT-MODE LANE v0: poll the Kotlin fetch bay —
                            // the page lands only when the seq GENUINELY advances
                            // (felt-truth: no landed fetch, no page). ----
                            #[cfg(target_os = "android")]
                            if let Some(seq) = crate::engine_bridge::carbon_page_seq() {
                                if seq != carbon_last_seq {
                                    carbon_last_seq = seq;
                                    let status = crate::engine_bridge::carbon_page_status()
                                        .unwrap_or(-1);
                                    let url = crate::engine_bridge::carbon_page_url()
                                        .unwrap_or_default();
                                    let body = crate::engine_bridge::carbon_page_body()
                                        .unwrap_or_default();
                                    let doc =
                                        carbon_bridge::engine::parse_document(&body, &url);
                                    let title = if doc.title.is_empty() {
                                        "(untitled)".to_string()
                                    } else {
                                        doc.title.clone()
                                    };
                                    sh.set_carbon_page_status(
                                        format!(
                                            "HTTP {status} — {title} — {} lines · {} links (text-mode v0)",
                                            doc.lines.len(),
                                            doc.links.len()
                                        )
                                        .into(),
                                    );
                                    let rows: Vec<slint::SharedString> = doc
                                        .lines
                                        .iter()
                                        .map(|l| l.as_str().into())
                                        .collect();
                                    sh.set_carbon_page_lines(slint::ModelRc::new(
                                        slint::VecModel::from(rows),
                                    ));
                                }
                            }
                            surface.render_probe_frame(tick);
                            let mut buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(
                                surface.width(),
                                surface.height(),
                            );
                            buf.make_mut_bytes().copy_from_slice(surface.as_rgba());
                            sh.set_carbon_frame(slint::Image::from_rgba8(buf));
                            sh.set_carbon_frame_live(true);
                            // ---- #60B-3 LIVE ANALYTICS: every number read off the SAME
                            // CarbonSurface that just rendered — frames genuinely finished,
                            // pixels the finished frame genuinely wrote, the real RGBA8
                            // payload derived from the live dims (never sample defaults). ----
                            sh.set_carbon_frames(
                                surface.frames_rendered().min(i32::MAX as u64) as i32
                            );
                            sh.set_carbon_px(
                                surface.last_frame_px().min(i32::MAX as u64) as i32
                            );
                            sh.set_carbon_kib((surface.frame_bytes() / 1024) as i32);
                            // ---- #60D ROUTING SEAM: one probe decision per shown tick,
                            // every input read off the LIVE engine THIS tick. ----
                            let beast = torta_core::beast_live_snapshot();
                            let ug = torta_core::underground_snapshot(0);
                            let fw_denied = torta_core::resolver_warden_denied();
                            // QoS class = the live YeAH phase (typed read, display label kept
                            // for the pane line) — SLOW-START rides the caution class.
                            let qos: u8 = match beast.mode.as_str() {
                                "SLOW-START" => 0,
                                "YEAH" => 1,
                                "COMPETING" => 2,
                                _ => 3, // RECOVERY
                            };
                            // Honest layer inputs: the probe host carries NO entry in either
                            // store (no fabricated rule, no fabricated verdict) — an absent
                            // entry is an allow in BOTH layers, and a DORMANT (un-armed)
                            // Underground store can veto nothing. The counters report what
                            // the layers genuinely did elsewhere, never what we invented.
                            let fw_deny = false;
                            let rep_deny = false;
                            let line = match route_probe.decide(fw_deny, rep_deny, qos) {
                                carbon_bridge::route::LaneDecision::Routed { qos_class } => {
                                    format!(
                                        "60D live: probe routed on QoS class {} (beast {}) · warden denials {} · underground {} ({} hosts) · seam {}/{} routed/denied",
                                        qos_class,
                                        beast.mode,
                                        fw_denied,
                                        if ug.armed { "ARMED" } else { "DORMANT" },
                                        ug.total,
                                        route_probe.routed(),
                                        route_probe.denied(),
                                    )
                                }
                                carbon_bridge::route::LaneDecision::Denied { reason } => {
                                    format!(
                                        "60D live: probe DENIED ({:?}) · warden denials {} · underground {} · seam {}/{} routed/denied",
                                        reason,
                                        fw_denied,
                                        if ug.armed { "ARMED" } else { "DORMANT" },
                                        route_probe.routed(),
                                        route_probe.denied(),
                                    )
                                }
                            };
                            sh.set_carbon_route(line.into());
                // ---- #60E: arm-once jail + live counter re-report (no re-probe) ----
                let jail = sandbox_jail.get_or_insert_with(|| {
                    let root = std::env::temp_dir().join("torta_carbon_jail");
                    let mut j = carbon_bridge::sandbox::FsJail::new(&root.to_string_lossy());
                    // seam probe — two REAL decisions, taken exactly once at arm time:
                    let _ = j.admit("site/data.db"); // inside the root -> admitted
                    let _ = j.admit("../outside");   // escape attempt  -> refused
                    j
                });
                let sb_line = format!(
                    "60E live: fs-jail ARMED @ {} \u{00b7} {} admitted / {} refused \u{00b7} permission map: {} sites (default-deny) \u{00b7} topology: in-process renderer (.so), no separate process",
                    jail.root(), jail.allowed(), jail.refused(), sandbox_perms.sites(),
                );
                sh.set_carbon_sandbox(sb_line.into());
                        }
                    }
                },
            );
        }

        // ---- 2-FEED-MaskSolver: the in-shell MaskSolver pillar DASHBOARD (the ms-dash section, reached
        // via ||| → PILLARS → MASKSOLVER dashboard chip). A COLD MaskSolver reads 0/0/0, so we ARM a
        // spike-local loopback pool FIRST (the Centauri precedent — a REAL Object, honest spike-local
        // instance; the resolver is process-global so this arms THIS .so's resolver, which drives no real
        // traffic) → `transports`/`timeout`/`strategy` + the per-upstream health rows carry real
        // STRUCTURAL numbers, never fabricated traffic. Fed at startup + a 1s refresh Timer WHILE the pane
        // is shown (honoring "refreshed while the tab is shown", the Beast/Centauri template — the timer is
        // a no-op on a cold Object, ready for the live snapshot when the RUNNING resolver feeds it). The
        // refresh rides a slint Timer (not the single open-pillar-dashboard host callback), so it never
        // contends with the sibling pillar embeds. ----
        // SLINT substitution · 4-FIX round 5 (finding 2): the fabricated loopback pool
        // (do53:loopA / do53:loopB — the "2-upstream cold spike pool" the witness flagged) is RETIRED.
        // A COLD `MaskSolver` reads the HONEST DORMANT structural baseline (unconfigured · empty
        // upstream-health · zero ledger), never a fake 2-upstream pool; `feed_from_live_masksolver`
        // OVERLAYS the LIVE resolver ledger over the round-3 `live_resolver_stats()` bridge when the
        // running engine is active.
        let masksolver = torta_core::MaskSolver::new();
        // ★ #69 — this Object was bound to a SPIKE directory ("masksolver-slint-spike"), which holds no
        // records at all. `rotation_snapshot()` reads `self.durable_dir` (object.rs:762-767) and returns
        // `cold_rotation_snapshot()` — last_family "" — whenever that dir has no `resolver-rotation`
        // record. So `ms_rotation_family` (fed at :3643 off this very Object) rendered "cold" while the
        // REAL record held `family=dnscry` (verified on device with `od -c`: family=dnscry · cadence=1800
        // · index=8). The panel was never wrong; it was reading an empty directory.
        // Bind to the SAME app-private DurableTier root Kotlin's RotationManager writes through
        // `persistResolverRotation` — {BASE}/app_data/runtime_tier, derived from data_dir's parent
        // exactly as the MaskSolver steppers do (the #90 pattern).
        let tier_dir = std::path::Path::new(&data_dir)
            .parent()
            .map(|p| {
                p.join("app_data")
                    .join("runtime_tier")
                    .to_string_lossy()
                    .into_owned()
            })
            .unwrap_or_default();
        if tier_dir.is_empty() {
            // Fail-safe: never bind to "" (that would be a silent rebind to the process CWD). A cold
            // Object is the honest baseline — the same posture the comment above describes.
            masksolver.bind_durable(format!("{data_dir}/masksolver-slint-spike"));
        } else {
            masksolver.bind_durable(tier_dir);
        }
        feed_from_live_masksolver(&shell, &masksolver);
        let masksolver_refresh = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            let masksolver = masksolver.clone();
            masksolver_refresh.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open() && sh.get_advanced_section().as_str() == "ms-dash"
                        {
                            feed_from_live_masksolver(&sh, &masksolver);
                        }
                    }
                },
            );
        }

        // ---- 2-FEED-Beast: the in-shell BEAST pillar DASHBOARD (the beast-dash section, reached via
        // ||| → PILLARS → BEAST dashboard chip). A REAL cold spike-local `Beast` (Canonical × CoBALT —
        // the shipped default brain/queue) reads the honest DORMANT baseline: cwnd=1/16 SLOW-START,
        // window_max=16, caps 4/8/16, CANONICAL·COBALT, adaptive-timeout at the pre-sample default, zero
        // flows — REAL STRUCTURAL engine numbers (≠ the .slint sample cwnd:8/mode:YEAH/rtt:24ms), never
        // fabricated traffic (the RUNNING engine's Beast rides in libtorta_core.so — the single-.so
        // unification feeds live-changing numbers later). Fed at startup + a 1s refresh Timer while the
        // pane is shown (honoring "refreshed while the tab is shown"; the timer is a no-op on a cold
        // Object, ready for the live snapshot). ----
        let beast_obj = torta_core::Beast::new(
            torta_core::YeahProfile::Canonical,
            torta_core::TortaProfile::Baseline,
        );
        feed_from_live_beast(&shell, &beast_obj);
        // #3-EXT — the LIVE overlay rides ON TOP of the cold baseline at mount + every timer tick:
        // when the tunnel runs, the dashboard witnesses the SAME `live_beast()` the ENGINE tab
        // does (bridge reachable ⇒ overlay wins; stopped ⇒ no-op ⇒ the honest DORMANT cold stands).
        overlay_live_beast_dashboard(&shell, &data_dir);
        let beast_refresh = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            let beast_obj = beast_obj.clone();
            let data_dir_beast = data_dir.clone();
            beast_refresh.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open()
                            && sh.get_advanced_section().as_str() == "beast-dash"
                        {
                            feed_from_live_beast(&sh, &beast_obj);
                            overlay_live_beast_dashboard(&sh, &data_dir_beast);
                        }
                    }
                },
            );
        }

        // ---- N6c: refresh the ENGINE tab's NETSTACK FORWARDER card every second WHILE the tab is
        // shown (the dns-tab timer's gate — `active_tab == "engine"` — not the burger-section gate;
        // this card lives on a main tab). A cold bridge read clears to DORMANT, so a stopped tunnel
        // drains the card instead of freezing the last live tally. ----
        let forwarder_refresh = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            forwarder_refresh.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_active_tab().as_str() == "engine" {
                            feed_from_live_forwarder(&sh);
                            feed_from_live_underground(&sh);
                        } else if sh.get_advanced_section().as_str() == "underground-dash"
                            || sh.get_advanced_section().as_str() == "underground-settings"
                        {
                            // #15 UNDERGROUND H — the pillar's OWN room rides the same 1 s
                            // census cadence when ITS section is the one on screen.
                            //
                            // "underground-settings" was MISSING from this gate, and the SETTINGS
                            // pane binds `armed <=> root.ug-armed` (home_shell.slint:2418) — so with
                            // that section on screen nothing refreshed it and it held whatever it
                            // was at startup. Measured on the AVD with the engine RUNNING: the pane
                            // showed "UNDERGROUND DORMANT — the engine reads it on the resolver
                            // boot" while HOME simultaneously showed "UNDERGROUND LAYER · LIVE ·
                            // 1 licences". Two surfaces of one pillar contradicting each other, and
                            // the dormant one is the pane that edits the law.
                            //
                            // The gate, not the binding, was the bug: an honest banner wired to a
                            // property nobody refreshes becomes a lie the moment the truth moves.
                            feed_from_live_underground(&sh);
                        } else if sh.get_advanced_section().as_str() == "forwarder-dash" {
                            // ★ #49 — the FORWARDER dashboard rides the SAME 1 s cadence when ITS
                            // section is on screen. `feed_from_live_forwarder` refreshes the
                            // aggregate half AND re-enumerates the per-flow docket in one pass, so
                            // rows appear and retire within a second of the engine's own truth.
                            // Gated hard on the section: a docket enumeration is a second bridge
                            // crossing, and no other screen should pay for it.
                            feed_from_live_forwarder(&sh);
                        }
                    }
                },
            );
        }

        // ---- #15 UNDERGROUND H · THE LIVE WIRE — the VerdictEvent ticker refreshes at 500 ms
        // (the G Flow cadence) WHILE the underground-dash section is shown. A separate, faster
        // timer than the census tick on purpose: the ring read is one JNI string, cheap, and the
        // wire is the pane's heartbeat — verdicts should land sub-second. Gated hard on the
        // section so the rest of the app never pays for it. ----
        let underground_wire_refresh = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            underground_wire_refresh.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(500),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_section().as_str() == "underground-dash" {
                            feed_underground_wire(&sh);
                        }
                    }
                },
            );
        }

        // ---- 2-FEED-Rotation: feed the in-shell Rotation pillar DASHBOARD (THE ORBITAL WHEEL — the
        // rotation-dash section, reached via ||| → PILLARS → ROTATION dashboard chip). Push the shell's
        // byte-equal `rdash-*` aliases from the live spike-local `MaskSolver::rotation_snapshot()` NOW (so
        // the pane shows the REAL seeded wheel the moment it lifts — family=mullvad · idx 42 · cadence 1 hr ·
        // 3 warm-RTT hints · WARM-RESUME, read back through the real `rotation_snapshot()` datapath — never
        // the .slint sample defaults, never 0/0/0), then REFRESH every second WHILE it is shown. The refresh
        // rides a slint Timer gated on the advanced section (the Centauri/Beast precedent), so it never
        // contends with the sibling pillar embeds; a cold/unbound read is a no-op, ready for the live snapshot. ----
        feed_from_live_rotation(&shell, &rotation_solver, &rotation_data_dir);
        let rotation_refresh = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            let rsolver = rotation_solver.clone();
            let rdir = rotation_data_dir.clone();
            rotation_refresh.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open()
                            && sh.get_advanced_section().as_str() == "rotation-dash"
                        {
                            feed_from_live_rotation(&sh, &rsolver, &rdir);
                        }
                    }
                },
            );
        }

        // ---- #59 THE DONATE TRUTH — engine-truth re-assert (torta_core::donate). The NotifyBar
        // DONATE row displays `notify-donate-url`, but the .slint default is DISPLAY ONLY: the
        // engine (four sealed clones + const FNV-1a tripwires, majority-voted at runtime) overwrites
        // it at startup and re-asserts every second WHILE the notify panel is expanded (the Centauri
        // gate idiom — never a background burn), so a patched .slint diverts nothing. `open-donate`
        // routes to the D2 Ko-Fi panel: with carbon_bridge linked (60C-2) the tap now OPENS the |||
        // burger directly on the carbon-dash section (the #60B Carbon Browser bar + the #59 D1c
        // DONATE mirror row — engine truth on screen), still re-asserting the URL. Felt-truth law
        // holds: no external intent, a REAL pane; the in-pane carbonyl render of the Ko-Fi page
        // rides the 60E engine wave. ----
        shell.set_notify_donate_url(torta_core::donate::donate_url().into());
        {
            let shell_weak = shell.as_weak();
            shell.on_notify_open_donate(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    // Assert truth first (the sealed-clone majority read), THEN route: open the |||
                    // burger directly on the carbon-dash section — the D2 Ko-Fi panel surface. The
                    // D1c mirror row inside carbon-dash fires this same callback; re-entry lands on
                    // the section it is already showing — no loop, no external intent.
                    sh.set_notify_donate_url(torta_core::donate::donate_url().into());
                    sh.set_advanced_open(true);
                    sh.set_advanced_section("carbon-dash".into());
                    // #60C (user directive): the pane now BROWSES — drive the text-mode
                    // lane at the engine-truth URL so Ko-Fi genuinely renders IN-APP.
                    let durl = torta_core::donate::donate_url();
                    sh.set_carbon_url(durl.into());
                    sh.invoke_carbon_navigate(durl.into());
                }
            });
        }
        // ---- #59 D2 · the D1c mirror's escalation — `carbon-donate-direct()` fires ONLY from
        // carbon-dash (the pane is already on screen; re-entering it would be a silent no-op, and
        // Tortä never ships a dead control). Route: re-assert the sealed-clone URL first, THEN the
        // REAL `ACTION_VIEW` intent through `TortaSlintBridge.openDonate` — the user's default
        // browser, engine-truth URL, fail-open (a JNI hiccup logs Kotlin-side, shell keeps
        // rendering). Desktop builds have no intent seam: the honest fallback is the pane route
        // itself (never a fabricated "opened" signal). ----
        {
            let shell_weak = shell.as_weak();
            shell.on_carbon_donate_direct(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_notify_donate_url(torta_core::donate::donate_url().into());
                    // #60C re-route (user directive): the mirror row opens the Ko-Fi
                    // page IN-APP through the text-mode lane — never an external
                    // intent. The pane is already on screen; the fetch lands into it.
                    let durl = torta_core::donate::donate_url();
                    sh.set_advanced_open(true);
                    sh.set_advanced_section("carbon-dash".into());
                    sh.set_carbon_url(durl.into());
                    sh.invoke_carbon_navigate(durl.into());
                }
            });
        }
        // #60C-b THE ESCAPE HATCH — user-initiated only.
        //
        // The URL is re-read from `torta_core::donate::donate_url()` at the moment of the tap, NOT
        // taken from the shell property: the engine's four-sealed-clone majority vote is the only
        // authority for where a donation goes, and a .slint surface string must never be able to
        // divert money. Same law the in-app route already obeys, applied to the way out too.
        {
            let shell_weak = shell.as_weak();
            shell.on_carbon_donate_external(move || {
                let durl = torta_core::donate::donate_url();
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_notify_donate_url(durl.into());
                    sh.set_carbon_page_status(
                        format!("opening {durl} in your system browser (your explicit choice)")
                            .into(),
                    );
                }
                crate::engine_bridge::open_donate_intent(&durl);
            });
        }
        // ---- #60F THE SPECIALS · host wiring — the landed flag flips TRUE here
        // only because the engine is genuinely compiled into this build
        // (carbon_bridge::specials). The Install Extension lane runs a REAL
        // drop-in scan: *.user.js + manifest.json under the process-owned
        // drop-in dir are fed byte-for-byte through the parse/sniff laws. A
        // fresh bay per scan means counters reflect the CURRENT disk truth —
        // no stale claims; an empty folder reports itself honestly, never a
        // fabricated install. ----
        shell.set_carbon_extension_engine_landed(true);
        {
            let shell_weak = shell.as_weak();
            shell.on_carbon_install_extension_tapped(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    let dir = std::env::temp_dir().join("torta_carbon_specials");
                    let _ = std::fs::create_dir_all(&dir);
                    let mut bay = carbon_bridge::specials::SpecialsBay::new();
                    let mut scanned = 0u32;
                    if let Ok(rd) = std::fs::read_dir(&dir) {
                        for e in rd.flatten() {
                            let p = e.path();
                            let fname = p
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("")
                                .to_ascii_lowercase();
                            if fname.ends_with(".user.js") {
                                if let Ok(txt) = std::fs::read_to_string(&p) {
                                    scanned += 1;
                                    let _ = bay.install_userscript(&txt);
                                }
                            } else if fname == "manifest.json" || fname.ends_with(".manifest.json") {
                                if let Ok(txt) = std::fs::read_to_string(&p) {
                                    scanned += 1;
                                    let _ = bay.install_extension(&txt);
                                }
                            }
                        }
                    }
                    let line = if scanned == 0 {
                        format!(
                            "60F drop-in empty @ {} \u{00b7} drop *.user.js / manifest.json there and tap again",
                            dir.display()
                        )
                    } else {
                        let tail = if bay.rejected() > 0 {
                            format!(" (last reject: {})", bay.last_reject())
                        } else {
                            String::new()
                        };
                        format!(
                            "60F scan @ {}: {} candidate(s) \u{00b7} {} userscript(s) + {} extension(s) IN \u{00b7} {} rejected{}",
                            dir.display(),
                            scanned,
                            bay.userscripts(),
                            bay.extensions(),
                            bay.rejected(),
                            tail
                        )
                    };
                    sh.set_carbon_specials_status(line.into());
                }
            });
        }
        // ---- #60G THE ROLE LANE · host wiring — the system default-browser role.
        // Android: the tap JNI-fires the REAL RoleManager ROLE_BROWSER request
        // through the Kotlin layer (dialog hosted by the live SLINT Activity);
        // `carbon-role-granted` only ever carries a REAL `isRoleHeld` read — the
        // request's own claim never flips the flag. A 1 s re-read runs ONLY while
        // the carbon-settings pane is open, so returning from the system dialog
        // flips the pane to truth without a tap. Desktop builds have no
        // RoleManager: the honest fallback states the lane is Android-only. ----
        #[cfg(target_os = "android")]
        {
            let shell_weak = shell.as_weak();
            shell.on_carbon_set_default_browser_tapped(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    let sent = crate::engine_bridge::request_browser_role().unwrap_or(5);
                    let held = crate::engine_bridge::browser_role_held().unwrap_or(false);
                    sh.set_carbon_role_granted(held);
                    sh.set_carbon_role_status(match sent {
                        1 => "60G request SENT — pick Yeah Tortä in the system dialog; the pane re-reads the truth as you return".into(),
                        2 => "already held — RoleManager confirms Carbon owns ROLE_BROWSER".into(),
                        3 => "ROLE_BROWSER unavailable on this device (no RoleManager / role disabled)".into(),
                        4 => "SLINT surface gone — reopen the app surface and tap again".into(),
                        _ => "role request failed Kotlin-side — check logcat (fail-open, shell keeps rendering)".into(),
                    });
                }
            });
        }
        #[cfg(target_os = "android")]
        shell.set_carbon_role_granted(crate::engine_bridge::browser_role_held().unwrap_or(false));
        #[cfg(target_os = "android")]
        let carbon_role_poll = slint::Timer::default();
        #[cfg(target_os = "android")]
        {
            let shell_weak = shell.as_weak();
            carbon_role_poll.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open()
                            && sh.get_advanced_section().as_str() == "carbon-settings"
                        {
                            if let Some(held) = crate::engine_bridge::browser_role_held() {
                                if held != sh.get_carbon_role_granted() {
                                    sh.set_carbon_role_granted(held);
                                    sh.set_carbon_role_status(if held {
                                        "RoleManager confirms: Carbon now owns ROLE_BROWSER".into()
                                    } else {
                                        "role released — RoleManager reads un-held".into()
                                    });
                                }
                            }
                        }
                    }
                },
            );
        }
        #[cfg(not(target_os = "android"))]
        {
            let shell_weak = shell.as_weak();
            shell.on_carbon_set_default_browser_tapped(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_carbon_role_status(
                        "role lane is Android-only — desktop builds have no RoleManager; the flag stays un-fabricated".into(),
                    );
                }
            });
        }
        let donate_reassert = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            donate_reassert.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_notify_expanded() {
                            sh.set_notify_donate_url(torta_core::donate::donate_url().into());
                        }
                    }
                },
            );
        }

        // ---- 4-FIX round 3 · 2-FEED-Warden + 2-FEED-Inu: feed the in-shell WARDEN + WIRE-CAKE-INU pillar
        // DASHBOARDS (the warden-dash / inu-dash sections, reached via ||| → PILLARS → WARDEN / WIRE CAKE INU
        // dashboard chips — the two that were silent no-ops in the witness). Push the shell's byte-equal
        // `wdash-*` / `idash-*` aliases from the live spike-local `WardenObject` / `InuStore` NOW, so each pane
        // shows REAL engine numbers the moment it lifts — never the .slint sample defaults. The INU pane's
        // `InuState` seed is static (armed once), but its `boot-reapply-armed` cell now reads the LIVE Kotlin
        // pref through `staged_inu_prefs()` (the #7 EUREKA fill) — and the user can flip that pref in the INU
        // settings pane at any moment. A feed-once inu-dash would keep showing the launch-time value (the
        // AVD-measured stale "no" over a persisted `true`), so it gets the Centauri gate idiom below: re-fed
        // every second WHILE the inu-dash section is shown — never a background burn. The WARDEN dash likewise
        // RE-PULLS its live aggregate every second while shown (W-A — the warden-dash refresh Timer below,
        // beside the flows docket). The panes inherit Rectangle so they embed on the single android surface. ----
        crate::warden_feed::feed_warden_shell(&shell, &warden);
        feed_inu_shell(&shell, &inu_store, !inu_is_live);
        let inu_dash_refresh_timer = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            let store = inu_store.clone();
            // #97 - the 1s refresh must carry the demo marking too, or the banner would vanish
            // one second after the section opens - exactly when the user starts reading it.
            let store_is_demo = !inu_is_live;
            inu_dash_refresh_timer.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open() && sh.get_advanced_section().as_str() == "inu-dash"
                        {
                            feed_inu_shell(&sh, &store, store_is_demo);
                        }
                    }
                },
            );
        }

        // ---- A5 slice-5: the Warden LIVE FLOWS docket. Unlike the STATIC warden posture above, the
        // ConnTracker ring DOES change (the engine .so's `tunnel::warden::verdict` choke point feeds it
        // per judged flow), so this feed gets the refresh Timer the posture feed deliberately skipped:
        // fed once NOW (the honest empty docket until the bridge answers), then re-pushed every second
        // WHILE the warden-dash section is shown (the Centauri gate idiom — never a background burn).
        // The source is the TortaPillarBridge `liveWardenFlows` seam (engine .so ring); bridge-silent =
        // the honest empty docket, never the shell rlib twin's cold zeros dressed as a reading. ----
        crate::warden_feed::feed_live_flows(&shell);
        let warden_flows_refresh_timer = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            warden_flows_refresh_timer.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open()
                            && sh.get_advanced_section().as_str() == "warden-dash"
                        {
                            // W-A: the flows docket AND the dashboard aggregate (the verdict tallies
                            // + the per-tier deny split + the armed rule-set / matrix / cache counts
                            // + the per-app matrix) BOTH re-pull the live engine read each tick — so
                            // every warden-dash tile CLIMBS with traffic. Before W-A the aggregate was
                            // fed ONCE at startup (the A6 split-brain: it froze at the cold zero even
                            // as the datapath judged flows). Both gated on the pane being shown — the
                            // Centauri gate idiom, never a background burn.
                            crate::warden_feed::feed_live_flows(&sh);
                            crate::warden_feed::refresh_warden_dash_live(&sh);
                            // W-D: while the per-app INSPECTOR overlay is open, its app-browser + focused
                            // posture header + armed GEO set CLIMB each tick too (the dest list + its
                            // multi-selection are NOT re-pulled here — that would clobber the user's set).
                            if sh.get_wdash_inspector_open() {
                                crate::warden_feed::feed_inspector_browser(&sh);
                            }
                        }
                    }
                },
            );
        }

        // ---- 2-FEED-Warden (SETTINGS): the in-shell Warden SETTINGS pane — FED + WRITE-wired. Fed once NOW
        // (the honest cold defaults until the bridge answers), then re-pushed every second WHILE the
        // warden-settings section is shown (the warden-dash gate idiom — never a background burn); each push
        // re-reads the CANONICAL live WardenObject so a control that failed to land snaps back. The controls
        // DRIVE that same instance via the engine_bridge → TortaPillarBridge → WardenDatapathGate seam. The
        // rules-editor per-row LIST rides the M2 liveWardenRules enumerator (honest-empty on a cold engine);
        // Add-rule + Remove both WRITE the canonical set (the header's armed-rule count follows next tick). ----
        crate::warden_feed::feed_warden_settings_shell(&shell);
        let warden_settings_refresh_timer = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            warden_settings_refresh_timer.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open()
                            && sh.get_advanced_section().as_str() == "warden-settings"
                        {
                            crate::warden_feed::feed_warden_settings_shell(&sh);
                        }
                    }
                },
            );
        }
        // The DASHBOARD crown ARM chip → the datapath enforce bit (the seam the witness found dead —
        // the pill re-feeds from the live `configured` read next tick, so a failed push snaps back).
        shell.on_warden_arm(move |on| {
            let _ = crate::engine_bridge::set_warden_armed(on);
        });
        // The POSTURE toggle → the fail-closed bit (the Nerd knob).
        shell.on_warden_posture_changed(move |on| {
            let _ = crate::engine_bridge::set_warden_fail_closed(on);
        });
        // A universal chip tap → flip that one of the 9 TIER-2 toggles (read-mutate-write, siblings intact).
        shell.on_warden_universal_toggled(move |key, on| {
            let _ = crate::engine_bridge::set_warden_universal_toggle(key.as_str(), on);
        });
        // The matrix taps (uid-only) → the read-cycle-write bridge helpers (mode / meteredness / pause axes).
        shell.on_warden_app_mode_cycled(move |uid| {
            let _ = crate::engine_bridge::cycle_warden_app_mode(uid);
        });
        shell.on_warden_app_metered_cycled(move |uid| {
            let _ = crate::engine_bridge::cycle_warden_app_metered(uid);
        });
        shell.on_warden_app_pause_toggled(move |uid| {
            let _ = crate::engine_bridge::toggle_warden_app_pause(uid);
        });
        // Add-rule → arm ONE universal DENY rule (domain or CIDR by `kind`); the header count bumps next tick.
        shell.on_warden_add_rule(move |kind, text, wildcard| {
            let _ = if kind.as_str() == "cidr" {
                crate::engine_bridge::add_warden_cidr_rule(text.as_str())
            } else {
                crate::engine_bridge::add_warden_domain_rule(text.as_str(), wildcard)
            };
        });
        // Remove-rule → drop the rule at the flat list index the pane rendered (domains-then-CIDRs, the SAME
        // order the feed enumerates); the bridge re-installs the remainder. The list re-feeds next tick.
        shell.on_warden_remove_rule(move |idx| {
            let _ = crate::engine_bridge::remove_warden_rule(idx);
        });

        // ---- W-D (#79) — the PER-APP INSPECTOR overlay: BROWSE apps -> DRILL one app's whole endpoint list
        // (each with GEO flag) -> ride the BLOCK-LADDER (single IP /32 -> /24 -> /16 -> whole COUNTRY GEO
        // family). Each handler crosses to the CANONICAL WardenObject (WardenDatapathGate / connTracker) in
        // libtorta_core.so; the overlay's dest MODEL is the one selection truth (a select tap flips that row's
        // `selected` bit + re-feeds — no shadow Rust set). Fail-open (a JNI hiccup is a no-op). ----
        {
            let shell_weak = shell.as_weak();
            shell.on_warden_open_inspector(move |uid| {
                if let Some(sh) = shell_weak.upgrade() {
                    crate::warden_feed::open_inspector(&sh, uid);
                }
            });
        }
        {
            let shell_weak = shell.as_weak();
            shell.on_warden_close_inspector(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_wdash_inspector_open(false);
                }
            });
        }
        {
            // Per-app WiFi-block axis (optimistic set; the 1 s browser tick re-reads HOST truth + snaps back).
            let shell_weak = shell.as_weak();
            shell.on_warden_inspector_block_wifi(move |uid, on| {
                let _ = crate::engine_bridge::warden_set_app_block_wifi(uid, on);
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_wdash_inspector_block_wifi(on);
                    crate::warden_feed::feed_inspector_browser(&sh);
                }
            });
        }
        {
            // Per-app mobile-data-block axis (the sibling of the WiFi axis).
            let shell_weak = shell.as_weak();
            shell.on_warden_inspector_block_mobile(move |uid, on| {
                let _ = crate::engine_bridge::warden_set_app_block_mobile(uid, on);
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_wdash_inspector_block_mobile(on);
                    crate::warden_feed::feed_inspector_browser(&sh);
                }
            });
        }
        {
            // A dest tap → flip that endpoint's multi-select bit in the model + recompute the count.
            let shell_weak = shell.as_weak();
            shell.on_warden_inspector_select_dest(move |ip| {
                if let Some(sh) = shell_weak.upgrade() {
                    crate::warden_feed::inspector_toggle_select(&sh, ip.as_str());
                }
            });
        }
        {
            // The ladder rung → arm the selected set at granularity `mode` (0 /32 · 1 /24 · 2 /16 · 3 COUNTRY).
            let shell_weak = shell.as_weak();
            shell.on_warden_inspector_block_selected(move |uid, mode| {
                if let Some(sh) = shell_weak.upgrade() {
                    crate::warden_feed::inspector_block_selected(&sh, uid, mode);
                }
            });
        }
        // (No trust-arm callback: the Warden layer has no trust concept by design law — blocklist-source trust
        //  scoring is the Underground pillar's surface. The dead Trust-bands settings control was removed.)

        // ---- 2-FEED-MaskSolver SETTINGS: the in-shell MaskSolverSettingsPane's 15 controls WRITE the ARMED
        // engine (libtorta_core.so — the SAME cross-.so seam the live-stat READS use, never this .so's cold
        // copy) over the JNI bridge, and read the result back on the 1s tick. The 7 Expert toggles + serve-
        // stale arm the resolver's live process-globals INSTANTLY on tap; the 5 cache/deadline steppers
        // receive a -1|+1 DIRECTION, compute the new value host-side, and commit it LIVE (the resolver_set_*
        // exports are REAL live setters — an instant commit is honest, never a fabricated echo — so the feed
        // tick confirms rather than fights). reapply-config re-pushes the whole cache/deadline/policy set as
        // a force-apply. rotation-cadence rides the SAME set_rotation_cadence bridge the Rotation dashboard
        // already trusts (secs -> minutes). Fail-open throughout (a JNI hiccup is a no-op, never a panic). ----
        // ★ #69 fix #2 — the settings feed needs the DurableTier root to read the rotation family from
        // (its own `MaskSolver::new()` is unbound, which is why the header read "cold" while the record
        // held family=dnscry). A String threads cleanly into the `move` timer closure below; the Object
        // does not, so we pass the dir rather than the handle.
        let ms_settings_tier_dir: String = std::path::Path::new(&data_dir)
            .parent()
            .map(|p| {
                p.join("app_data")
                    .join("runtime_tier")
                    .to_string_lossy()
                    .into_owned()
            })
            .unwrap_or_default();
        feed_masksolver_settings_shell(&shell, &ms_settings_tier_dir);
        let masksolver_settings_refresh_timer = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            let tier_dir_for_timer = ms_settings_tier_dir.clone();
            masksolver_settings_refresh_timer.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open()
                            && sh.get_advanced_section().as_str() == "ms-settings"
                        {
                            feed_masksolver_settings_shell(&sh, &tier_dir_for_timer);
                        }
                    }
                },
            );
        }
        // The 7 Expert BOOLEAN toggles — the pane self-sets its own prop on tap (instant UI); each handler
        // arms the matching resolver process-global instantly, and the 1s feed confirms the engine truth.
        shell.on_masksolver_solve_ladder_toggled(|on| {
            crate::engine_bridge::set_resolver_solve_ladder(on);
        });
        shell.on_masksolver_all_servers_toggled(|on| {
            crate::engine_bridge::set_resolver_all_servers(on);
        });
        shell.on_masksolver_rebind_protect_toggled(|on| {
            crate::engine_bridge::set_resolver_rebind_enforce(on);
        });
        shell.on_masksolver_bogus_priv_toggled(|on| {
            crate::engine_bridge::set_resolver_bogus_priv(on);
        });
        shell.on_masksolver_proxy_dnssec_toggled(|on| {
            crate::engine_bridge::set_resolver_proxy_dnssec(on);
        });
        shell.on_masksolver_never_forward_toggled(|on| {
            crate::engine_bridge::set_resolver_never_forward(on);
        });
        shell.on_masksolver_cache_rr_toggled(|on| {
            crate::engine_bridge::set_resolver_cache_rr(on);
        });
        // Serve-stale toggle — turning it ON arms a REAL window (keep the staged secs, or default to 1800s /
        // 30 min when it was 0, so "on" is never inert-by-default); OFF commits 0. Keeps serve-stale-on
        // consistent with the engine truth (secs > 0), so the feed derive never flips the toggle back.
        {
            let shell_weak = shell.as_weak();
            shell.on_masksolver_serve_stale_toggled(move |on| {
                if let Some(sh) = shell_weak.upgrade() {
                    let secs = if on {
                        let cur = sh.get_mss_serve_stale_secs();
                        if cur > 0 { cur } else { 1800 }
                    } else {
                        0
                    };
                    sh.set_mss_serve_stale_secs(secs);
                    sh.set_mss_serve_stale_on(secs > 0);
                    crate::engine_bridge::set_resolver_serve_stale(secs);
                }
            });
        }
        // The 5 cache/deadline STEPPERS — dir is -1|+1; step + clamp host-side, set the prop, commit live.
        {
            let shell_weak = shell.as_weak();
            // ★ #90 — the DurableTier dir, derived exactly as the seven working persist sites derive
            // it (lib.rs:7574: toml_path -> parent -> parent -> "runtime_tier"). `toml_path` is
            // `{cfg_base}/app_data/dnscrypt-proxy/dnscrypt-proxy.toml`, so this resolves to
            // `{cfg_base}/app_data/runtime_tier` — the directory the device listing confirmed holds
            // the `dnscrypt-config` record. Cloned into the closure because the stepper outlives
            // this block.
            let tier_dir = std::path::Path::new(&data_dir)
                .parent()
                .map(|p| {
                    p.join("app_data")
                        .join("runtime_tier")
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or_default();
            shell.on_masksolver_cache_cap_stepped(move |dir| {
                if let Some(sh) = shell_weak.upgrade() {
                    let next = (sh.get_mss_cache_cap() + dir * 256).clamp(0, 65_536);
                    sh.set_mss_cache_cap(next);
                    crate::engine_bridge::set_resolver_cache_cap(next);
                    // ★ #90 — WRITE THROUGH TO THE DURABLE AUTHORITY, or the choice dies with the
                    // process. `set_resolver_cache_cap` only stages the LIVE engine; the durable
                    // record is `dnscrypt-config`, which ALREADY carries `cache_size` (measured on
                    // device: `cache_size = 4096` while the UI showed 512 — a three-way divergence
                    // between UI, engine and disk). So this EXTENDS the existing authority via its
                    // own get/set twin rather than adding a second store for state that already
                    // has one.
                    let mut cfg = torta_core::dnscrypt_config_get();
                    cfg.cache_size = next;
                    // `cache_cap` is derived as `cache && cache_size > 0`
                    // (dnscrypt_config.rs:1088), so stepping to 0 must disarm the flag too —
                    // otherwise the record would claim a cache of size zero.
                    cfg.cache = next > 0;
                    torta_core::dnscrypt_config_set(cfg);
                    // ★ #90 ROUND 2 — `dnscrypt_config_set` alone writes only the HELD (in-memory)
                    // authority: its own doc says Kotlin may "STAGE typed edits then COMMIT them in
                    // one apply". Round 1 stopped there and the device proved it — UI and engine
                    // moved to 512 while `dnscrypt-config` on disk stayed at 4096. The house
                    // pattern (seven existing sites, e.g. lib.rs:4595-4598) is a TRIPLE: set,
                    // materialize the TOML, then persist the DurableTier record. Only the third
                    // call reaches NAND.
                    // ★ #90 — THE CALL THAT ACTUALLY REACHES NAND. `dnscrypt_config_set` above
                    // writes only the HELD (in-memory) authority — its own doc says Kotlin may
                    // "STAGE typed edits then COMMIT them in one apply". Round 1 stopped there and
                    // the device proved it insufficient: UI and engine moved to 512 while
                    // `dnscrypt-config` on disk stayed at 4096. This is the third leg of the house
                    // triple (lib.rs:4595-4598).
                    let _ = torta_core::persist_dnscrypt_config(tier_dir.clone());
                }
            });
        }
        {
            let shell_weak = shell.as_weak();
            // ★ #90 REPLICATION — same tier dir derivation as the cache-cap stepper above.
            let tier_dir = std::path::Path::new(&data_dir)
                .parent()
                .map(|p| {
                    p.join("app_data")
                        .join("runtime_tier")
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or_default();
            shell.on_masksolver_timeout_stepped(move |dir| {
                if let Some(sh) = shell_weak.upgrade() {
                    let next = (sh.get_mss_timeout_ms() + dir * 250).clamp(0, 60_000);
                    sh.set_mss_timeout_ms(next);
                    crate::engine_bridge::set_resolver_query_timeout(next);
                    // ★ #90 — `timeout` is the SAME durable field #80 already read back as a
                    // fallback (lib.rs:3867, `dnscrypt_config_get().timeout`), so without this the
                    // stepper's choice was overwritten by the record on every reapply.
                    let mut cfg = torta_core::dnscrypt_config_get();
                    cfg.timeout = next;
                    torta_core::dnscrypt_config_set(cfg);
                    let _ = torta_core::persist_dnscrypt_config(tier_dir.clone());
                }
            });
        }
        {
            let shell_weak = shell.as_weak();
            // ★ #92 — the fifth stepper, finally persistable.
            let tier_dir = std::path::Path::new(&data_dir)
                .parent()
                .map(|p| {
                    p.join("app_data")
                        .join("runtime_tier")
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or_default();
            shell.on_masksolver_serve_stale_secs_stepped(move |dir| {
                if let Some(sh) = shell_weak.upgrade() {
                    let next = (sh.get_mss_serve_stale_secs() + dir * 300).clamp(0, 86_400);
                    sh.set_mss_serve_stale_secs(next);
                    sh.set_mss_serve_stale_on(next > 0);
                    crate::engine_bridge::set_resolver_serve_stale(next);
                    let mut cfg = torta_core::dnscrypt_config_get();
                    cfg.serve_stale_secs = next;
                    torta_core::dnscrypt_config_set(cfg);
                    let _ = torta_core::persist_dnscrypt_config(tier_dir.clone());
                }
            });
        }
        {
            let shell_weak = shell.as_weak();
            // ★ #90 REPLICATION — the TTL floor's durable field is `cache_min_ttl` (confirmed on
            // device: the record carries `cache_min_ttl = 2400`).
            let tier_dir = std::path::Path::new(&data_dir)
                .parent()
                .map(|p| {
                    p.join("app_data")
                        .join("runtime_tier")
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or_default();
            shell.on_masksolver_ttl_floor_stepped(move |dir| {
                if let Some(sh) = shell_weak.upgrade() {
                    let next = (sh.get_mss_ttl_floor_secs() + dir * 30).clamp(0, 86_400);
                    sh.set_mss_ttl_floor_secs(next);
                    crate::engine_bridge::set_resolver_ttl_floor(next);
                    let mut cfg = torta_core::dnscrypt_config_get();
                    cfg.cache_min_ttl = next;
                    torta_core::dnscrypt_config_set(cfg);
                    let _ = torta_core::persist_dnscrypt_config(tier_dir.clone());
                }
            });
        }
        {
            let shell_weak = shell.as_weak();
            // ★ #90 REPLICATION — the TTL ceiling's durable field is `cache_max_ttl` (confirmed on
            // device: the record carries `cache_max_ttl = 86400`).
            let tier_dir = std::path::Path::new(&data_dir)
                .parent()
                .map(|p| {
                    p.join("app_data")
                        .join("runtime_tier")
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or_default();
            shell.on_masksolver_ttl_ceiling_stepped(move |dir| {
                if let Some(sh) = shell_weak.upgrade() {
                    let next = (sh.get_mss_ttl_ceiling_secs() + dir * 3_600).clamp(0, 604_800);
                    sh.set_mss_ttl_ceiling_secs(next);
                    crate::engine_bridge::set_resolver_ttl_ceiling(next);
                    let mut cfg = torta_core::dnscrypt_config_get();
                    cfg.cache_max_ttl = next;
                    torta_core::dnscrypt_config_set(cfg);
                    let _ = torta_core::persist_dnscrypt_config(tier_dir.clone());
                }
            });
        }
        // Rotation cadence — host-owned (Kotlin RotationManager). Step in secs, commit in MINUTES over the
        // SAME bridge the Rotation dashboard uses (a P10 wheel gates on this pref; 0 = the manager default).
        {
            let shell_weak = shell.as_weak();
            shell.on_masksolver_rotation_cadence_stepped(move |dir| {
                if let Some(sh) = shell_weak.upgrade() {
                    let next = (sh.get_mss_rotation_cadence_secs() + dir * 3_600).clamp(0, 86_400);
                    sh.set_mss_rotation_cadence_secs(next);
                    crate::engine_bridge::set_rotation_cadence(next / 60);
                }
            });
        }
        // Re-apply — force-push the whole cache/deadline/policy set from the current staged props (every knob
        // already committed on its own edit; this is the pane's explicit "apply everything now" affordance).
        {
            let shell_weak = shell.as_weak();
            shell.on_masksolver_reapply_config(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    crate::engine_bridge::set_resolver_cache_cap(sh.get_mss_cache_cap());
                    crate::engine_bridge::set_resolver_query_timeout(sh.get_mss_timeout_ms());
                    let stale = if sh.get_mss_serve_stale_on() {
                        sh.get_mss_serve_stale_secs()
                    } else {
                        0
                    };
                    crate::engine_bridge::set_resolver_serve_stale(stale);
                    crate::engine_bridge::set_resolver_ttl_floor(sh.get_mss_ttl_floor_secs());
                    crate::engine_bridge::set_resolver_ttl_ceiling(sh.get_mss_ttl_ceiling_secs());
                }
            });
        }

        // ---- CP-U · THE UNDERGROUND TRUST BANDS (re-homed): the ENGINE tab's control row pins ONE host's
        // standing in the LIVE licence store — the trust concept the Warden layer intentionally sheds lives
        // HERE, on the pillar that actually scores hosts. The button JNI-writes through engine_bridge →
        // TortaPillarBridge.setUndergroundVerdict → the SAME libtorta_core.so process-globals the snapshot
        // reads (never this .so's cold copy), which persists the ledger atomically. `code`: 0 = Neutral
        // (clear the pin, hand the host back to the automatic engine), 1 = Trusted (immune — un-sequester +
        // pin the licence full), 2 = Distrusted (condemned — sequester + force NXDOMAIN at the teeth). The
        // RETURN bit lands on `ug_trust_status` (1 = landed, 2 = fail-open) for immediate on-pane feedback; a
        // landed pin clears the host input and SNAPS the tiles + WORST OFFENDERS court to truth at once (never
        // waiting for the 1 s tick). Fail-open — a JNI hiccup surfaces status 2, never a panic. ----
        {
            let shell_weak = shell.as_weak();
            shell.on_underground_set_verdict(move |host, code| {
                let landed = crate::engine_bridge::set_underground_verdict(host.as_str(), code)
                    .unwrap_or(false);
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_ug_trust_status(if landed { 1 } else { 2 });
                    if landed {
                        sh.set_ug_trust_input(slint::SharedString::from(""));
                        feed_from_live_underground(&sh);
                    }
                }
            });
        }

        // ---- #15 UNDERGROUND H · the SETTINGS pane intents — the tunable law's four wires.
        // SAVE writes the operator's scoring.toml atomically (Kotlin tmp+rename; blank DELETES —
        // the compile-time defaults return); the Rust mtime watcher hot-reloads ≤5 s. The quick
        // DETECTION toggles are sugar over the SAME text the editor shows (patched host-side,
        // then written through the same wire — never a fork of the law). RESET is the amnesty
        // (learned reputation + correction log forgotten; the licence ledger stands). All
        // fail-open: a JNI hiccup surfaces status 2, never a panic. ----
        feed_underground_law(&shell);
        {
            let shell_weak = shell.as_weak();
            shell.on_underground_save_toml(move |text| {
                let landed = crate::engine_bridge::set_underground_scoring_toml(text.as_str())
                    .unwrap_or(false);
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_ugs_save_status(if landed { 1 } else { 2 });
                    if landed {
                        feed_underground_law(&sh);
                    }
                }
            });
        }
        {
            let shell_weak = shell.as_weak();
            shell.on_underground_detection_toggled(move |name, on| {
                if let Some(sh) = shell_weak.upgrade() {
                    let patched = crate::underground_feed::patch_underground_detection(
                        sh.get_ugs_toml().as_str(),
                        name.as_str(),
                        on,
                    );
                    let landed = crate::engine_bridge::set_underground_scoring_toml(&patched)
                        .unwrap_or(false);
                    sh.set_ugs_save_status(if landed { 1 } else { 2 });
                    if landed {
                        feed_underground_law(&sh);
                    }
                }
            });
        }
        {
            let shell_weak = shell.as_weak();
            shell.on_underground_reset_reputation(move || {
                let forgot = crate::engine_bridge::reset_underground_reputation().unwrap_or(false);
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_ugs_reset_status(if forgot { 1 } else { 2 });
                }
            });
        }
        {
            let shell_weak = shell.as_weak();
            shell.on_underground_reload_law(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    feed_underground_law(&sh);
                    sh.set_ugs_save_status(0);
                    sh.set_ugs_reset_status(0);
                }
            });
        }

        // ---- 2-DRIVE-PILLARS: the Rotation dashboard ACTION controls DRIVE the real RotationManager path.
        // The pure-Rust rail cannot rotate the pool itself (Kotlin's ModulesService owns it — the D09 law), so
        // each control JNI-calls TortaPillarBridge (engine_bridge, above), which MIRRORS the canonical
        // RotationDashboardFragment: `rotate-now` → ACTION_ROTATE_RESOLVERS_NOW (→ ModulesStateLoop →
        // RotationManager.rotateNow(), the real one-shot pool swap the query.log SERVER column reflects);
        // `rotation-toggled`/`cadence-picked` write the SAME RESOLVER_ROTATION_* prefs the manager gates on.
        // The Rotate-Now RETURN code lands on `rdash-rotate-status` (honest on-pane feedback). Fail-open — a
        // JNI hiccup surfaces the error code, never a panic. ----
        {
            let shell_weak = shell.as_weak();
            shell.on_rdash_rotate_now(move || {
                // 5 = error (matches TortaPillarBridge's ROTATE_ERROR) when the JNI call fails outright.
                let code = crate::engine_bridge::rotate_resolvers_now().unwrap_or(5);
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_rdash_rotate_status(code);
                }
            });
        }
        shell.on_rdash_rotation_toggled(move |on| {
            crate::engine_bridge::set_rotation_enabled(on);
        });
        shell.on_rdash_cadence_picked(move |minutes| {
            crate::engine_bridge::set_rotation_cadence(minutes);
        });

        // ---- 2-FEED-Rotation (SETTINGS): the Rotation SETTINGS pane's 5 controls DRIVE the SAME Kotlin
        // rotation destinations the dashboard already trusts (the NO-FORK consensus — this .so owns no live
        // cursor). Initial feed + a 1s visibility-gated re-feed keep the `rset-*` aliases honest; each control
        // rides its own bridge: pin -> RESOLVER_ROTATION_ENABLED (INVERTED — pin ON == the wheel holds), the
        // preset chips send ABSOLUTE seconds (-> minutes), the Expert stepper sends a -1|+1 DIRECTION the HOST
        // clamps to [5 min, 7 days] then commits (with an optimistic echo the feed confirms), rotate-now fires
        // the one-shot ACTION (fire-and-forget — the settings pane has no rotate-status witness; the dashboard
        // owns that). Fail-open — a JNI hiccup is a no-op, never a panic. Expert reveal is self-managed by the
        // pane (a local UI choice, never fed). Mirrors the MaskSolver-settings handler block. ----
        feed_rotation_settings_shell(&shell);
        let rotation_settings_refresh_timer = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            rotation_settings_refresh_timer.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open()
                            && sh.get_advanced_section().as_str() == "rotation-settings"
                        {
                            feed_rotation_settings_shell(&sh);
                        }
                    }
                },
            );
        }
        // pin -> RESOLVER_ROTATION_ENABLED, INVERTED (pin ON pins one family == rotation DISABLED). The pane
        // self-sets its own `pinned` on tap; the 1s feed confirms the pref landed (a failed write snaps back).
        shell.on_rotation_settings_pin_toggled(|on| {
            crate::engine_bridge::set_rotation_enabled(!on);
        });
        // rotate-now -> the one-shot ACTION_ROTATE_RESOLVERS_NOW (fire-and-forget; the pane gates the button
        // on `configured`, so an inert tap on a cold engine is already prevented by the pane).
        shell.on_rotation_settings_rotate_now(|| {
            let _ = crate::engine_bridge::rotate_resolvers_now();
        });
        // set-cadence(secs) -> RESOLVER_ROTATION_CADENCE_MINUTES (the preset chips carry ABSOLUTE seconds;
        // seconds -> minutes for the pref the manager gates on). The pane self-lights the active preset; the
        // feed reads the pref back (secs) and re-derives the active chip + label.
        shell.on_rotation_settings_set_cadence(|secs| {
            crate::engine_bridge::set_rotation_cadence((secs / 60).max(1));
        });
        // cadence-stepped(dir) -> the SAME pref, stepped by the HOST-owned 300s grain (the pane sends only a
        // -1|+1 direction; the host computes + clamps to [5 min, 7 days] == [300, 604800] secs). Optimistic
        // echo onto `rset-cadence-secs` keeps the knob where the user put it; the 1s feed confirms the pref.
        {
            let shell_weak = shell.as_weak();
            shell.on_rotation_settings_cadence_stepped(move |dir| {
                if let Some(sh) = shell_weak.upgrade() {
                    let step: i32 = 300;
                    let cur = sh.get_rset_cadence_secs();
                    let next = (cur + dir.signum() * step).clamp(300, 604800);
                    sh.set_rset_cadence_secs(next);
                    crate::engine_bridge::set_rotation_cadence((next / 60).max(1));
                }
            });
        }

        // ---- #49 THE BEAST SETTINGS: the Yeah TCP/UDP brain + Soft-cake/Mochi-Dango queue + Expert tune,
        // staged-then-applied. Initial feed + a 1s visibility-gated re-feed keep the `bset-*` aliases honest
        // (live cwnd/mode/RTT witnesses + the durable staged selection). Picks/steps update the pane +
        // persist the BEAST_* prefs (durable, #51) but DON'T touch the live engine; Apply (reapply-profile)
        // commits the staged config onto the overhauled process-global Beast (re-seed the YeAH brain + CAKE
        // queue, then override the live tunables). profile-dirty is derived by the feed (staged vs live) so
        // it self-clears after Apply. Expert reveal + clamp flags are pane/handler-local. Fail-open. ----
        feed_beast_settings_shell(&shell);
        let beast_settings_refresh_timer = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            beast_settings_refresh_timer.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_advanced_open()
                            && sh.get_advanced_section().as_str() == "beast-settings"
                        {
                            feed_beast_settings_shell(&sh);
                        }
                    }
                },
            );
        }
        // yeah-profile-picked(id) -> stage the YeAH brain (0 Legacy / 1 Canonical / 2 LineRate). Optimistic
        // echo + profile-dirty; persist the full staged config. Bites the engine only on Apply.
        {
            let shell_weak = shell.as_weak();
            shell.on_beast_settings_yeah_profile_picked(move |id| {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_bset_yeah_profile(id);
                    sh.set_bset_profile_dirty(true);
                    stage_beast_from_shell(&sh);
                }
            });
        }
        // cake-profile-picked(id) -> stage the CAKE queue (0 Legacy-AQM / 1 Soft-cake == the SoftCake law).
        {
            let shell_weak = shell.as_weak();
            shell.on_beast_settings_cake_profile_picked(move |id| {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_bset_cake_profile(id);
                    sh.set_bset_profile_dirty(true);
                    stage_beast_from_shell(&sh);
                }
            });
        }
        // preset-picked(id) -> resolve the 4 tunables host-side (beast_preset_host) + stage them all. A
        // preset is canonical (not coerced), so clear the clamp flag; profile-dirty (a preset moves the window).
        {
            let shell_weak = shell.as_weak();
            shell.on_beast_settings_preset_picked(move |id| {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_bset_preset(id);
                    sh.set_bset_cycle_ms(beast_preset_host(id, 0));
                    sh.set_bset_max_window(beast_preset_host(id, 1));
                    sh.set_bset_free_thresh_milli(beast_preset_host(id, 2));
                    sh.set_bset_compete_thresh_milli(beast_preset_host(id, 3));
                    sh.set_bset_tunable_clamped(false);
                    sh.set_bset_profile_dirty(true);
                    stage_beast_from_shell(&sh);
                }
            });
        }
        // cycle-ms-stepped(dir) -> step the CoDel cycle by 500ms, clamp to [1000, 60000]; surface the clamp
        // when the raw value was coerced. (Persisted staged; the overhauled scheduler has no live interval
        // setter yet — honest, doesn't silently no-op.)
        {
            let shell_weak = shell.as_weak();
            shell.on_beast_settings_cycle_ms_stepped(move |dir| {
                if let Some(sh) = shell_weak.upgrade() {
                    let raw = sh.get_bset_cycle_ms() + dir.signum() * 500;
                    let v = beast_clamp_host(0, raw);
                    sh.set_bset_cycle_ms(v);
                    sh.set_bset_tunable_clamped(v != raw);
                    sh.set_bset_profile_dirty(true);
                    stage_beast_from_shell(&sh);
                }
            });
        }
        // max-window-stepped(dir) -> step the YeAH window ceiling by 1, clamp to [2, 64].
        {
            let shell_weak = shell.as_weak();
            shell.on_beast_settings_max_window_stepped(move |dir| {
                if let Some(sh) = shell_weak.upgrade() {
                    let raw = sh.get_bset_max_window() + dir.signum();
                    let v = beast_clamp_host(1, raw);
                    sh.set_bset_max_window(v);
                    sh.set_bset_tunable_clamped(v != raw);
                    sh.set_bset_profile_dirty(true);
                    stage_beast_from_shell(&sh);
                }
            });
        }
        // free-thresh-stepped(dir) -> step the free-airtime ratio by 10 milli, clamp to [1000, 2000].
        {
            let shell_weak = shell.as_weak();
            shell.on_beast_settings_free_thresh_stepped(move |dir| {
                if let Some(sh) = shell_weak.upgrade() {
                    let raw = sh.get_bset_free_thresh_milli() + dir.signum() * 10;
                    let v = beast_clamp_host(2, raw);
                    sh.set_bset_free_thresh_milli(v);
                    sh.set_bset_tunable_clamped(v != raw);
                    sh.set_bset_profile_dirty(true);
                    stage_beast_from_shell(&sh);
                }
            });
        }
        // compete-thresh-stepped(dir) -> step the compete ratio by 10 milli, clamp to [1010, 3000].
        {
            let shell_weak = shell.as_weak();
            shell.on_beast_settings_compete_thresh_stepped(move |dir| {
                if let Some(sh) = shell_weak.upgrade() {
                    let raw = sh.get_bset_compete_thresh_milli() + dir.signum() * 10;
                    let v = beast_clamp_host(3, raw);
                    sh.set_bset_compete_thresh_milli(v);
                    sh.set_bset_tunable_clamped(v != raw);
                    sh.set_bset_profile_dirty(true);
                    stage_beast_from_shell(&sh);
                }
            });
        }
        // expert-toggled(on) -> reveal the raw Expert knobs (pane-local UI state, no engine touch).
        {
            let shell_weak = shell.as_weak();
            shell.on_beast_settings_expert_toggled(move |on| {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_bset_expert_open(on);
                }
            });
        }
        // reapply-profile() -> COMMIT the staged config onto the LIVE overhauled Beast: re-seed the YeAH
        // brain + CAKE queue, then override the live tunables (Kotlin orders profile-then-tunables so the
        // re-seed doesn't clobber the window). Optimistic dirty=false; the 1s feed confirms off live truth.
        {
            let shell_weak = shell.as_weak();
            shell.on_beast_settings_reapply_profile(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    crate::engine_bridge::apply_beast_config(
                        sh.get_bset_yeah_profile(),
                        sh.get_bset_cake_profile(),
                        sh.get_bset_cycle_ms(),
                        sh.get_bset_max_window(),
                        sh.get_bset_free_thresh_milli(),
                        sh.get_bset_compete_thresh_milli(),
                    );
                    sh.set_bset_profile_dirty(false);
                }
            });
        }

        // ---- 2-FEED-Inu (SETTINGS · #50): the Wire Cake Inu SETTINGS surface — the SIXTH + FINAL per-pillar
        // SETTINGS pane (the #23 umbrella closer). Feed the live InuState posture + the Kotlin-owned durability
        // triple onto the `iset-*` aliases ONCE at startup (the static spike seed — feed_inu_settings_shell
        // explains why no refresh Timer would be honest here). Then wire the 8 write-callbacks: the grant flow
        // is KOTLIN-owned (the ElevationManager / per-power GrantEngine / BootReapplyPolicy), so each fires its
        // engine_bridge JNI seam with an OPTIMISTIC echo for immediate UI feedback; the durable prefs survive
        // restart the #51 way. close-settings returns to PILLARS in-shell (handled in home_shell.slint). ----
        feed_inu_settings_shell(&shell, &inu_store, !inu_is_live);

        // pair-now() -> run the ADB pair + elevate flow (Kotlin ElevationManager). Optimistic FETCHING so the
        // crown animates while the async handshake runs; the real ELEVATED/ERROR lands with the live store.
        {
            let shell_weak = shell.as_weak();
            shell.on_inu_settings_pair_now(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_iset_elevation_status(1);
                    crate::engine_bridge::inu_pair_now();
                }
            });
        }
        // unpair() -> clear the persisted pair (key/cert) + drop elevation. Optimistic RESTING + not-paired.
        {
            let shell_weak = shell.as_weak();
            shell.on_inu_settings_unpair(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_iset_paired(false);
                    sh.set_iset_paired_label(SharedString::from("not paired yet"));
                    sh.set_iset_elevation_status(0);
                    crate::engine_bridge::inu_unpair();
                }
            });
        }
        // power-toggled(id, on) -> set/revert one power's protect intent (Kotlin GrantEngine PowerState.desired).
        // desired-count optimistically follows so the "N wanted" fold reacts; `held` stays engine truth (it only
        // flips once the grant verifies, on the next live read — never faked here).
        {
            let shell_weak = shell.as_weak();
            shell.on_inu_settings_power_toggled(move |id, on| {
                if let Some(sh) = shell_weak.upgrade() {
                    let cur = sh.get_iset_desired_count();
                    sh.set_iset_desired_count((cur + if on { 1 } else { -1 }).max(0));
                    crate::engine_bridge::inu_power_toggled(id.as_str(), on);
                }
            });
        }
        // boot-reapply-toggled(on) -> persist the durable pref + arm the live BootReapplyPolicy (the Genesis #1
        // gap closer). Optimistic echo; the durable pref survives engine/app restart (the #51 durability law).
        {
            let shell_weak = shell.as_weak();
            shell.on_inu_settings_boot_reapply_toggled(move |on| {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_iset_boot_reapply_armed(on);
                    crate::engine_bridge::inu_boot_reapply(on);
                }
            });
        }
        // always-on-toggled(on) -> toggle the always-on foreground pairing notification (Shizuku-studied).
        {
            let shell_weak = shell.as_weak();
            shell.on_inu_settings_always_on_toggled(move |on| {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_iset_always_on(on);
                    crate::engine_bridge::inu_always_on(on);
                }
            });
        }
        // provider-pref-cycled() -> cycle the elevation-path preference (0 AUTO -> 1 SHIZUKU -> 2 SELF-ADB -> 0).
        {
            let shell_weak = shell.as_weak();
            shell.on_inu_settings_provider_pref_cycled(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    let next = (sh.get_iset_provider_pref() + 1).rem_euclid(3);
                    sh.set_iset_provider_pref(next);
                    crate::engine_bridge::inu_provider_pref(next);
                }
            });
        }
        // manual-pair(host, port, code) -> run a raw manual ADB pair (Expert). Optimistic FETCHING; Kotlin parses
        // the port + drives the ElevationManager. The draft fields stay as the user typed them (never fed back).
        {
            let shell_weak = shell.as_weak();
            shell.on_inu_settings_manual_pair(move |host, port, code| {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_iset_elevation_status(1);
                    crate::engine_bridge::inu_manual_pair(
                        host.as_str(),
                        port.as_str(),
                        code.as_str(),
                    );
                }
            });
        }
        // expert-toggled(on) -> reveal the raw ADB knobs + persist WIRELESS_DEBUG_EXPERT + the InuState
        // `expert_enabled` flag (the durability twin of MaskSolver Expert, #51).
        {
            let shell_weak = shell.as_weak();
            shell.on_inu_settings_expert_toggled(move |on| {
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_iset_expert_open(on);
                    crate::engine_bridge::inu_expert_toggled(on);
                }
            });
        }

        // ---- #63 · GENERAL BOOT-AUTOSTART (the Socio reboot cluster) — the general_section's
        // keep-on-boot pair, wired to the SAME two prefs `BootCompleteManager` gates on at
        // BOOT_COMPLETED (`swAutostartDNS` + `AUTO_START_DELAY`). Before this seam existed the
        // SLINT toggle flipped only the local prop (pref never persisted ⇒ VPN dead after reboot)
        // and the ±5 s stepper had NO Rust hookup at all (dead chip). Seed once at mount from the
        // durable truth; persist on every edit intent. Fail-open throughout (JNI hiccup ⇒ the
        // shell keeps the last honest value). ----
        {
            // SEED — the durable prefs are the one truth; the cold .slint defaults (off / 0 s)
            // only survive a bridge-silent read.
            if let Some(cfg) = crate::engine_bridge::boot_autostart_config() {
                let (on, delay) = crate::inu_feed::parse_boot_autostart(&cfg);
                shell.set_boot_autostart_on(on);
                shell.set_autostart_delay_secs(delay);
            }
        }
        // boot-toggled(v) -> persist `swAutostartDNS` (the .slint already flipped the prop; this
        // crossing makes it survive the reboot the toggle is FOR).
        shell.on_boot_toggled(move |on| {
            crate::engine_bridge::set_boot_autostart(on);
        });
        // autostart-delay-stepped(±5) -> step + clamp host-side (0..=300 s, the receiver's band),
        // set the prop, persist the seconds STRING `parseAutostartDelayMs` reads at boot.
        {
            let shell_weak = shell.as_weak();
            shell.on_autostart_delay_stepped(move |delta| {
                if let Some(sh) = shell_weak.upgrade() {
                    let next = (sh.get_autostart_delay_secs() + delta).clamp(0, 300);
                    sh.set_autostart_delay_secs(next);
                    crate::engine_bridge::set_boot_autostart_delay(next);
                }
            });
        }

        // ---- N7 · THE FORWARDER ARM SWITCH: the ENGINE tab's netstack toggle writes the SAME
        // `swNetstackForwarder` pref TunnelController.start() latches — so a flip applies on the
        // NEXT tunnel start (detachFd is a one-shot; no mid-flight rebind, and the .slint divergence
        // note names the queued state). The optimistic echo keeps the switch where the user put it;
        // the 1 s forwarder_refresh re-reads HOST truth right after (a failed JNI write snaps back). ----
        {
            let shell_weak = shell.as_weak();
            shell.on_forwarder_toggled(move |on| {
                crate::engine_bridge::set_netstack_forwarder(on);
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_fwd_pref_armed(on);
                }
            });
        }

        // ---- 2-FEED-Centauri (SETTINGS): the in-shell Centauri SETTINGS pane's controls DRIVE the ARMED
        // engine. Each wires to the engine_bridge → TortaPillarBridge static (fail-open). The cloak toggle
        // already flipped its own `cs-cloak-armed` alias in .slint (optimistic echo) before firing; the
        // 500ms `overlay_live_engine` re-reads the armed truth right after (a failed write snaps back). The
        // seed-policy cycle has no self-flip — the host sets `cs-seed-policy` from the returned NEW code;
        // warm-up is an action whose effect surfaces in the next overlay tick (libraries / served).
        // (No strict-toggled / install-catalog: the CROWN is always-on LeakOnMiss and the catalog auto-arms.)
        shell.on_centauri_cloak_toggled(move |on| {
            crate::engine_bridge::set_centauri_cloak(on);
        });
        {
            let shell_weak = shell.as_weak();
            shell.on_centauri_seed_policy_cycled(move || {
                if let Some(code) = crate::engine_bridge::cycle_centauri_seed_policy() {
                    if let Some(sh) = shell_weak.upgrade() {
                        sh.set_cs_seed_policy(code);
                    }
                }
            });
        }
        shell.on_centauri_warm_up_now(move || {
            let _ = crate::engine_bridge::centauri_warm_up_now();
        });

        // ★ #65 — hand the device CA to the OS installer. The OS raises its own confirmation sheet, so a
        // tap here REQUESTS trust and can never grant it. `ca-trusted` is not set optimistically: the next
        // dashboard tick re-reads the real store, so the banner only clears if trust actually landed.
        shell.on_install_ca(move || {
            let _ = crate::engine_bridge::centauri_ca_install();
        });

        // ★ #22 — hand every TLS-refused host back to the cloak. Like `install-ca` this is deliberately
        // fire-and-forget: the banner is driven by `tls-distrust`, which the next dashboard tick re-reads
        // from the SERVICE engine's real ledger. Setting the count to 0 optimistically here would clear
        // the banner even on a bridge failure — the tile must keep reporting what the engine actually
        // holds, so a re-trust that did not land stays visible instead of looking like it worked.
        shell.on_retrust_hosts(move || {
            let _ = crate::engine_bridge::centauri_tls_retrust();
        });

        // The K5 feed: REAL on-disk compatibility TOML -> the typed authority -> BOTH mounts.
        // ★ FIX (measured 2026-07-04): the DNSCrypt config lives at {BASE}/app_data/dnscrypt-proxy/,
        // but `data_dir` = internal_data_path() = getFilesDir() = {BASE}/files (the inu store lands at
        // files/wire-cake-inu-spike; files/app_data does NOT exist — the real toml is at BASE/app_data,
        // where the Kotlin installer extracts it via getAppDataDir()). So the config dir is the PARENT
        // of data_dir + /app_data/… — using data_dir directly aimed at the dead files/app_data path
        // (a latent apply-config-write bug + the manual picker's empty .md read).
        let cfg_base = std::path::Path::new(&data_dir)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| data_dir.clone());
        let toml_path = format!("{cfg_base}/app_data/dnscrypt-proxy/dnscrypt-proxy.toml");
        // W5 #12 (RAMxNAND Opt-2) — the config's DURABLE truth is the app-private DurableTier
        // "dnscrypt-config" record, NOT the loose toml. This .so links its OWN torta_core (statically),
        // a SEPARATE authority from the uniffi libtorta_core.so the Kotlin ResolverRuntime recovers into
        // — so the UI must run the SAME durable-record-wins recovery itself, or a toml wiped before this
        // init (then re-materialized engine-side after) would leave the ③ DNS toggles showing the stock
        // default while the engine honours the recovered config. Rehydrate THIS .so's authority from the
        // record FIRST (survives a toml wipe); fall back to the on-disk toml, then the upstream default.
        let tier_dir = std::path::Path::new(&toml_path)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("runtime_tier").to_string_lossy().into_owned())
            .unwrap_or_default();
        let cfg = Rc::new(RefCell::new(
            if !tier_dir.is_empty() && torta_core::rehydrate_dnscrypt_config(tier_dir.clone()) {
                torta_core::dnscrypt_config_get()
            } else {
                torta_core::dnscrypt_config_import_or_default(
                    std::fs::read_to_string(&toml_path).unwrap_or_default(),
                )
            },
        ));
        // #22 s5A — sync the GLOBAL held authority to the just-seeded Rc ONCE at boot: the import
        // branch above fills only the Rc, leaving `dnscrypt_config_get()` on the upstream default
        // until the first toggle called `dnscrypt_config_set` — so any get()-based feed (the Rotation
        // dashboard's PICK-FILTER chips below, the ③ DNS witness reads) could render defaults that
        // disagreed with the toml truth the pane shows. One boot set makes the two authorities equal
        // from the first frame (the rehydrate branch already left them equal — this is a no-op there).
        torta_core::dnscrypt_config_set(cfg.borrow().clone());
        push_dnscrypt!(&shell, &cfg.borrow());
        // 2-FEED-DNSCRYPT: seed the ③ DNS LIVE dashboard NOW — the server line + the cache/query.log
        // feed from the shared Record + on-disk log, and the RUNNING pill from an initial JNI state read.
        // The 500 ms poll below keeps the pill in lockstep; a 1 s tail-timer refreshes the feed while shown.
        let dns_dash_dir = data_dir.clone();
        // Cloned here, BEFORE `data_dir` is moved into the burger's `wire_dnscrypt_edits!` below —
        // the ④ QUERY tab's 1 s refresh timer (further down) owns this copy.
        let query_dash_dir = data_dir.clone();
        feed_from_live_dnscrypt(&shell, &cfg.borrow(), &dns_dash_dir);
        shell.set_dc_live_state(crate::engine_bridge::dnscrypt_state_code().unwrap_or(0));
        // ★ #97 — seed the POST-QUANTUM witness alongside the RUNNING pill; the 500 ms poll below keeps
        //   it in lockstep. Seeding here means an engine already up when the UI attaches shows its real
        //   PQ census on the FIRST frame rather than waiting a tick.
        feed_pq_witness(&shell);
        // #22 s5A — clones taken BEFORE the burger's wire_dnscrypt_edits! MOVES toml_path/data_dir;
        // the Rotation-dashboard PICK-FILTER wiring (below) owns these copies.
        let rdash_cfg = cfg.clone();
        let rdash_toml_path = toml_path.clone();
        let rdash_tier_dir = tier_dir.clone();
        wire_dnscrypt_edits!(shell, cfg.clone(), toml_path.clone(), data_dir.clone());
        push_dnscrypt!(&burger, &cfg.borrow());
        wire_dnscrypt_edits!(burger, cfg.clone(), toml_path, data_dir);

        // ---- #22 s5A: the Rotation dashboard PICK FILTER + POOL SHAPE drive (Socio: "the very same
        // filters of the DNSCrypt pillar" + "how many Relays per resolver? how many Resolver total per
        // rotation?"). The FILTER chips mutate the ONE shared `Rc<RefCell<DnscryptProxyConfig>>` the
        // two DNSCrypt mounts edit, then ride the EXACT burger closure contract: `dnscrypt_config_set`
        // (held authority) → `materialize_dnscrypt_toml` (the on-disk toml BOTH rotation brains read —
        // RotationManager.rotationPolicy + ResolverRuntime via RotationPoolSource.policyFromConfig) →
        // `persist_dnscrypt_config` (W5 durable). ONE filter set, never a second policy store. The
        // SHAPE steppers ride the JNI prefs bridge (Kotlin GEEK-clamps 1..20 / 0..10 and persists the
        // SAME MAX_SERVERS/MAX_RELAYS prefs readMaxServers/readMaxRelays consume). Each handler ends
        // with a host-truth read-back echo; the 1 s rotation feed keeps confirming after. ----
        {
            let c = rdash_cfg;
            let path = rdash_toml_path;
            let tdir = rdash_tier_dir;
            let shell_weak = shell.as_weak();
            shell.on_rdash_criteria_toggled(move |key, on| {
                {
                    let mut cfg = c.borrow_mut();
                    match key.as_str() {
                        "nolog" => cfg.require_nolog = on,
                        "dnssec" => cfg.require_dnssec = on,
                        "nofilter" => cfg.require_nofilter = on,
                        "ipv4" => cfg.ipv4_servers = on,
                        "ipv6" => cfg.ipv6_servers = on,
                        // s5A-ext (Socio): the PROTOCOL chips — the same server-type bits the
                        // DNSCrypt pillar's chips edit; dnscrypt/doh gate the random pick
                        // (RotationPolicy.allowDnsCrypt/allowDoh), odoh gates its derive lane.
                        "dnscrypt" => cfg.dnscrypt_servers = on,
                        "doh" => cfg.doh_servers = on,
                        "odoh" => cfg.odoh_servers = on,
                        // s5A-ext (Socio): the KILL SWITCH — the same ignore_system_dns bit the
                        // DNSCrypt pillar's transport kill switch edits (ISP/router intromission block).
                        "sysdns" => cfg.ignore_system_dns = on,
                        _ => return,
                    }
                }
                let snap = c.borrow().clone();
                torta_core::dnscrypt_config_set(snap.clone());
                let _ = torta_core::materialize_dnscrypt_toml(path.clone());
                let _ = torta_core::persist_dnscrypt_config(tdir.clone());
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_rdash_crit_nolog(snap.require_nolog);
                    sh.set_rdash_crit_dnssec(snap.require_dnssec);
                    sh.set_rdash_crit_nofilter(snap.require_nofilter);
                    sh.set_rdash_crit_ipv4(snap.ipv4_servers);
                    sh.set_rdash_crit_ipv6(snap.ipv6_servers);
                    sh.set_rdash_crit_proto_dnscrypt(snap.dnscrypt_servers);
                    sh.set_rdash_crit_proto_doh(snap.doh_servers);
                    sh.set_rdash_crit_proto_odoh(snap.odoh_servers);
                    sh.set_rdash_crit_sysdns(snap.ignore_system_dns);
                }
            });
        }
        {
            let shell_weak = shell.as_weak();
            shell.on_rdash_max_servers_stepped(move |dir| {
                let cur = crate::engine_bridge::rotation_max_servers().unwrap_or(10);
                crate::engine_bridge::set_rotation_max_servers(cur.saturating_add(dir));
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_rdash_max_servers(
                        crate::engine_bridge::rotation_max_servers().unwrap_or(cur),
                    );
                }
            });
        }
        {
            let shell_weak = shell.as_weak();
            shell.on_rdash_max_relays_stepped(move |dir| {
                let cur = crate::engine_bridge::rotation_max_relays().unwrap_or(10);
                crate::engine_bridge::set_rotation_max_relays(cur.saturating_add(dir));
                if let Some(sh) = shell_weak.upgrade() {
                    sh.set_rdash_max_relays(
                        crate::engine_bridge::rotation_max_relays().unwrap_or(cur),
                    );
                }
            });
        }

        // ---- Navigation (SLINT substitution · 1B): IN-SHELL — no window-swaps on-device. ----
        // The single-surface law (above) is stronger than "the last component owns the surface":
        // `hide()` on ANY component hides the ONE android window — WITNESSED (1B baseline,
        // 1b-baseline-2-burger-tap-real.png): the D2 swap handlers made the ||| door vanish the
        // WHOLE app (the previous app resurfaced). So home_shell.slint now hosts the ||| ADVANCED
        // surface as an in-shell full-screen overlay (`advanced-open`/`advanced-section` —
        // shell-local routing state): the per-pillar private tabs read the SAME `pillar-chips`
        // model HOME reads; GENERAL is a real embedded pane behind byte-equal forwarding aliases;
        // the rail's DNSCRYPT entry routes to the ③ DNS tab (the ONE host-fed K5 mount). The
        // host only REFRESHES fed state on the door events — it never shows/hides a window.
        {
            // The ||| door opened: re-push the shared K5 authority + fresh pillar rows onto the
            // shell's own mounts (live statuses re-probed at the moment the drawer lifts).
            let shell_weak = shell.as_weak();
            let c = cfg.clone();
            shell.on_open_advanced(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    push_dnscrypt!(&sh, &c.borrow());
                    sh.set_pillar_chips(ModelRc::new(VecModel::from(pillar_rows())));
                }
            });
        }
        {
            // ✕ close → the 4-tab Home (the .slint flipped `advanced-open` itself; re-push so
            // the ③ DNS tab renders the freshest shared-Record truth when it is next shown).
            let shell_weak = shell.as_weak();
            let c = cfg.clone();
            shell.on_close_advanced(move || {
                if let Some(sh) = shell_weak.upgrade() {
                    push_dnscrypt!(&sh, &c.borrow());
                }
            });
        }
        // `open-pillar` needs no host routing anymore — the HOME chip flips the shell's own
        // overlay to PILLARS in .slint (the id still reaches the host through the callback for
        // future per-pillar focus). The DASHBOARD chip is routed IN .slint: the open-dashboard
        // map flips `advanced-section` to the matching in-shell pane — ALL SIX pillar dashboards
        // now embed (ms-dash · centauri-dash · beast-dash · rotation-dash · warden-dash · inu-dash;
        // 4-FIX round 3 landed the last two, closing the silent-no-op witness finding). The
        // `open-pillar-dashboard` / `open-pillar-settings` HOST callbacks stay deliberately un-wired
        // (a silent no-op — the felt-truth law; the .slint owns the navigation, the host only feeds
        // the panes). `open-pillar-settings` still routes only DNSCRYPT to the ③ DNS tab; the other
        // per-pillar SETTINGS surfaces are a later wave, and nothing fakes a navigation that cannot render.

        // ---- 2-DRIVE-CORE: the HOME master switch DRIVES the real DNSCrypt engine. ----
        // The pure-Rust rail cannot start Kotlin's ModulesService (the D09 law), so:
        //   · `engine-toggled(on)` JNI-calls TortaSlintBridge.setDnsCryptEnabled (START/STOP), and
        //   · a 1 s poll Timer JNI-reads the REAL dnsCryptState back onto the shell — replacing the
        //     honest spike default (`host-live`=false / `engine-running`=false, set by feed_home)
        //     with the LIVE truth: the crown flips to SHIELDED only when DNSCrypt is ACTUALLY RUNNING.
        // Both directions are Rust→Kotlin static calls through the Activity classloader (engine_bridge,
        // above); fail-open — a JNI hiccup skips a tick, never a panic.
        shell.on_engine_toggled(move |on| {
            crate::engine_bridge::set_dnscrypt_enabled(on);
        });
        let engine_state_timer = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            // ★ PILLAR-CHIP LIVENESS (field cosmetic bug). The HOME "THE PILLARS" chips were pushed
            // at boot + on the ||| door only — so with the engine RUNNING (ledger live above them)
            // the engine-plane pillars kept reading "OFF — start DNSCrypt on HOME": a stale snapshot
            // contradicting the crown on the same screen. Re-probe on the crown's own tick: instantly
            // on a running-state EDGE (the witnessed case), and every 6th tick (3 s) for slower drift
            // (Warden arming, Centauri caching a library mid-run). The signature gate means an
            // unchanged probe pushes NOTHING — no per-tick model churn, no re-render when idle.
            let chip_tick = std::cell::Cell::new(0u32);
            let chip_last_running = std::cell::Cell::new(false);
            let chip_last_sig = std::cell::RefCell::new(String::new());
            engine_state_timer.start(
                slint::TimerMode::Repeated,
                // 500 ms (not 1 s like the dashboard refreshers): the master switch must reflect a
                // start/stop transition promptly — a coarse poll lags the felt-truth (and misses a
                // brief RUNNING flap entirely).
                std::time::Duration::from_millis(500),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if let Some(code) = crate::engine_bridge::dnscrypt_state_code() {
                            // SLINT substitution · 4-FIX round 4: the crown's running-truth is the REAL
                            // transport, not the phantom module state. Tortä's Rust resolver rides IN the
                            // DNSCrypt VpnService — there is NO dnscrypt-proxy process, so `code` never
                            // reaches RUNNING (2) even while the tunnel shields DNS (witnessed: VPN
                            // CONNECTED on tun0 + queries=151 while the crown read STOPPED). So the crown is
                            // RUNNING when the module state says RUNNING OR the tunnel is actually up — the
                            // truthful `VPN_SERVICE_ENABLED` read (cleared on teardown, so OFF is honest too).
                            let tunnel = crate::engine_bridge::tunnel_up().unwrap_or(false);
                            let running = code == 2 || tunnel;
                            sh.set_engine_running(running);
                            // 2-FEED-DNSCRYPT: the ③ DNS dashboard's RUNNING pill mirrors the crown — RUNNING
                            // when the tunnel is up even if the phantom module code lags at STOPPED (one
                            // truthful signal, two surfaces: HOME crown + the DNS pillar dashboard, lockstep).
                            sh.set_dc_live_state(if running && code != 2 { 2 } else { code });
                            // ★ #97 — the POST-QUANTUM witness rides the SAME 500 ms tick as the pill it
                            // sits beside, so the X-Wing census can never lag the RUNNING state it
                            // describes. Ungated by `running` on purpose: the counters are monotonic
                            // totals, so after a stop they keep reporting what the session actually
                            // negotiated instead of collapsing to a zero that never happened.
                            feed_pq_witness(&sh);
                            // SLINT substitution · 4-FIX-1: the state is a REAL Kotlin read — overlay the
                            // LIVE running-engine ledger + budget (the .so-split fix) instead of blindly
                            // flagging host-live. `running` is the crown's truth so the banner never says
                            // OFF while the crown says RUNNING; a stopped engine reads the honest OFF state.
                            overlay_live_engine(&sh, running);
                            // BUGS2 #64 · NOTIFY-BAR TRUTH FEED: the always-on bar's speeds are
                            // REAL TrafficStats deltas read through the bridge — the SAME well the
                            // Android foreground notification drinks from (Kotlin-side throttled
                            // push inside `trafficSnapshot`), so shade and bar can never disagree.
                            // `live` is honest: true only when a real ≥0 delta backs the numbers
                            // AND the crown runs; a JNI failure keeps the last shown truth
                            // (never fabricate — the felt-truth law).
                            fn fmt_bps(bps: i64) -> String {
                                const K: f64 = 1024.0;
                                let b = bps as f64;
                                if b < K {
                                    format!("{bps} B/s")
                                } else if b < K * K {
                                    format!("{:.1} KB/s", b / K)
                                } else {
                                    format!("{:.1} MB/s", b / (K * K))
                                }
                            }
                            sh.set_notify_engine_running(running);
                            if let Some((dl, ul)) = crate::engine_bridge::traffic_snapshot() {
                                if dl >= 0 && ul >= 0 {
                                    sh.set_notify_live(running);
                                    sh.set_notify_dl(fmt_bps(dl).into());
                                    sh.set_notify_ul(fmt_bps(ul).into());
                                } else {
                                    sh.set_notify_live(false);
                                }
                            }
                            sh.set_engine_state_line(
                                if running {
                                    "DNSCrypt RUNNING — queries ride the encrypted tunnel"
                                } else {
                                    match code {
                                        1 => "DNSCrypt starting…",
                                        3 => "DNSCrypt stopping…",
                                        5 => "DNSCrypt FAULT — check the query log",
                                        _ => {
                                            "DNSCrypt STOPPED — flip the switch to shield your DNS"
                                        }
                                    }
                                }
                                .into(),
                            );
                            // ★ PILLAR-CHIP LIVENESS: edge ⇒ probe NOW (the start/stop flip the user
                            // just watched); otherwise every 6th tick. The JNI probes inside
                            // `pillar_rows()` are the same fail-open statics the boot push used.
                            let tick = chip_tick.get().wrapping_add(1);
                            chip_tick.set(tick);
                            let edge = running != chip_last_running.get();
                            chip_last_running.set(running);
                            if edge || tick % 6 == 0 {
                                let rows = pillar_rows();
                                let sig: String = rows
                                    .iter()
                                    .map(|r| format!("{}|{}|{};", r.id, r.status, r.live))
                                    .collect();
                                if *chip_last_sig.borrow() != sig {
                                    *chip_last_sig.borrow_mut() = sig;
                                    sh.set_pillar_chips(ModelRc::new(VecModel::from(rows)));
                                }
                            }
                        }
                    }
                },
            );
        }

        // 2-FEED-DNSCRYPT: the ③ DNS LIVE dashboard's tail-refresh — re-reads the shared K5 Record's
        // server line + re-tails the REAL cache/query.log every 1 s WHILE the DNS tab is shown (the
        // other dashboards' "refresh Timer while the pane is shown" pattern; the 500 ms poll above owns
        // the RUNNING pill, this owns the server + query feed). Fail-open — the weak upgrade skips a tick.
        let dns_dash_timer = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            let c = cfg.clone();
            dns_dash_timer.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_active_tab().as_str() == "dns" {
                            feed_from_live_dnscrypt(&sh, &c.borrow(), &dns_dash_dir);
                        }
                    }
                },
            );
        }

        // The ④ QUERY tab's tail-refresh — the same 1 s "refresh WHILE the tab is shown" pattern the
        // ③ DNS dashboard uses, for the standalone query feed. `wire_query_feed` reads ONCE at wire
        // time (engine still down at boot ⇒ "no log on disk yet"); without this the pane stayed stale
        // until a manual REFRESH. Now the picked source re-tails every second while `active_tab ==
        // "query"`, so landing on the tab with the engine running shows live rows immediately. Cheap:
        // one `log_tail_recent` of the bounded window; skipped entirely on every other tab.
        let query_dash_timer = slint::Timer::default();
        {
            let shell_weak = shell.as_weak();
            query_dash_timer.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_millis(1000),
                move || {
                    if let Some(sh) = shell_weak.upgrade() {
                        if sh.get_active_tab().as_str() == "query" {
                            refresh_query_rows(&sh, &query_dash_dir, sh.get_query_source().as_str());
                        }
                    }
                },
            );
        }

        // ---- WITNESS (opt-in `--features warden_witness`, SLINT substitution · 2-FEED-Warden) —
        // construct the Warden dashboard LAST so it OWNS the single android surface (the proven
        // single-surface method, the 1A comment above), feed it, run it, then RETURN before the shell's
        // own run. Fully cfg'd OUT of the default `--features mirror` APK + every sibling build (zero
        // impact on the committed shell-is-app path and the other pillar witnesses). PROVES the live
        // `feed_from_live_warden` renders REAL engine numbers on-device — the exact pre-1A CENTAURI
        // proof (the standalone dashboard render that showed capacity=1024 + 8 hosts), applied to the
        // firewall's verdict tallies + armed rule-sets + per-app matrix. ----
        #[cfg(feature = "warden_witness")]
        {
            let wwarden = crate::WardenDashboard::new()
                .expect("WardenDashboard witness constructs on-device");
            crate::warden_feed::feed_from_live_warden(&wwarden, &warden);
            wwarden
                .run()
                .expect("slint android event loop (warden witness)");
            return;
        }

        // ---- WITNESS (opt-in `--features beast_witness`, SLINT substitution · 2-FEED-Beast) — open the
        // 4-tab SHELL DIRECTLY into the ||| → BEAST dashboard overlay (`advanced-open` + section
        // "beast-dash") so the EMBEDDED BeastPane renders at launch fed with the REAL cold `BeastSnapshot`:
        // cwnd 1/16 · SLOW-START · CANONICAL·COBALT · caps 4/8/16 · adaptive-timeout pre-sample default ·
        // DORMANT — NOT the .slint sample (cwnd:8 / mode:YEAH / rtt:24ms). Unlike the standalone-Window
        // witnesses, this proves the REAL in-shell substitution route AND that `feed_from_live_beast`
        // drives real engine numbers on-device. `return`s before the default run; fully cfg'd OUT of the
        // committed `--features mirror` APK + every sibling build. ----
        #[cfg(feature = "beast_witness")]
        {
            let beast_w = torta_core::Beast::new(
                torta_core::YeahProfile::Canonical,
                torta_core::TortaProfile::Baseline,
            );
            feed_from_live_beast(&shell, &beast_w);
            shell.set_advanced_open(true);
            shell.set_advanced_section("beast-dash".into());
            shell
                .run()
                .expect("slint android event loop (beast witness)");
            return;
        }

        // ---- WITNESS (opt-in `--features centauri_witness`, SLINT substitution · 2-FEED-Centauri) —
        // open the 4-tab SHELL DIRECTLY into the ||| → CENTAURI dashboard overlay (`advanced-open` +
        // section "centauri-dash") so the EMBEDDED CentauriPane renders at launch fed with the REAL cold
        // `CentauriSnapshot`: capacity=1024 (MAX_ENTRIES) · the 8 cloaked CDN hosts · DORMANT/STOPPED ·
        // the honest cold zeros — NOT the .slint sample (capacity:0 / 5 sample hosts / 3 sample serves).
        // Unlike the standalone-Window witnesses, this proves the REAL in-shell substitution route AND
        // that `feed_from_live_centauri` drives real engine numbers on-device. `return`s before the
        // default run; fully cfg'd OUT of the committed `--features mirror` APK + every sibling build. ----
        #[cfg(feature = "centauri_witness")]
        {
            feed_from_live_centauri(&shell, &centauri);
            shell.set_advanced_open(true);
            shell.set_advanced_section("centauri-dash".into());
            shell
                .run()
                .expect("slint android event loop (centauri witness)");
            return;
        }

        // ---- WITNESS (opt-in `--features masksolver_witness`, SLINT substitution · 2-FEED-MaskSolver) —
        // open the 4-tab shell DIRECTLY into the ||| → MASKSOLVER dashboard overlay (`advanced-open` +
        // section "ms-dash") so the EMBEDDED MaskSolverPane renders at launch fed with the REAL spike-local
        // `MaskSolver::snapshot()`/`solve_state()`: 2 UPSTREAM(S) (do53:loopA/loopB) · deadline 3000ms ·
        // STRICT-ORDER (ladder) · the 2 real upstream health rows · crown ARMED — NOT the .slint sample
        // (quad9/cloudflare + HIT/SOLVE/STALE). Like the Beast/Centauri witnesses, this proves the REAL
        // in-shell substitution route AND that `feed_from_live_masksolver` drives real engine numbers
        // on-device. `return`s before the default run; fully cfg'd OUT of the committed `--features mirror`
        // APK + every sibling build → zero impact on the shell-is-app path. ----
        #[cfg(feature = "masksolver_witness")]
        {
            feed_from_live_masksolver(&shell, &masksolver);
            shell.set_advanced_open(true);
            shell.set_advanced_section("ms-dash".into());
            shell
                .run()
                .expect("slint android event loop (masksolver witness)");
            return;
        }

        // ---- WITNESS (opt-in `--features rotation_witness`, SLINT substitution · 2-FEED-Rotation) — open
        // the 4-tab SHELL DIRECTLY into the ||| → ROTATION dashboard overlay (`advanced-open` + section
        // "rotation-dash") so the EMBEDDED RotationPane renders at launch fed with the REAL spike-local
        // `MaskSolver::rotation_snapshot()`: family=mullvad · idx 42 · cadence 1 hr · WARM-RESUME · the 3
        // warm-RTT hints (mullvad-doh 9ms / cloudflare-doh 14ms / quad9-doq 21ms) — NOT the .slint sample
        // (cold family / cadence 0 / cloudflare+quad9 hints), NOT 0/0/0. Like the Beast/Centauri/MaskSolver
        // witnesses, this proves the REAL in-shell substitution route AND that `feed_from_live_rotation`
        // drives real engine numbers on-device. `return`s before the default run; fully cfg'd OUT of the
        // committed `--features mirror` APK + every sibling build → zero impact on the shell-is-app path. ----
        #[cfg(feature = "rotation_witness")]
        {
            feed_from_live_rotation(&shell, &rotation_solver, &rotation_data_dir);
            shell.set_advanced_open(true);
            shell.set_advanced_section("rotation-dash".into());
            shell
                .run()
                .expect("slint android event loop (rotation witness)");
            return;
        }

        // ---- WITNESS (opt-in `--features inu_witness`, SLINT substitution · 2-FEED-Inu) — construct the
        // Wire Cake Inu dashboard LAST so it OWNS the single android surface (the 1A single-surface method)
        // + renders at launch with the live-fed REAL InuState numbers (crown ELEVATED · Self-ADB · held 3 /
        // of 3 · drift 0 · the query-inu.log pair/elevate/grant tail) — NOT the .slint sample defaults.
        // WITNESSED on the x86_64 AVD (torta_host). Fully cfg'd OUT of the default `--features mirror` APK +
        // every sibling build → zero impact on the committed shell-is-app path. ----
        #[cfg(feature = "inu_witness")]
        {
            let inu_witness =
                crate::InuDashboard::new().expect("InuDashboard witness constructs on-device");
            feed_from_live_inu(&inu_witness, &inu_store, !inu_is_live);
            // ---- refreshed WHILE the tab is shown (the Centauri/Beast "refresh every second while
            // shown" precedent, applied to the always-shown standalone witness window): a 1 s slint
            // Timer re-reads the live typed `InuState` off the SAME spike-local `InuStore` and re-pushes
            // it field-for-field through `feed_from_live_inu`. On the static seed it re-reads the same
            // ELEVATED posture (an honest no-op redraw); it is READY to stream a live-changing store the
            // moment the single-.so unification feeds the RUNNING engine's `InuStore`. The timer handle is
            // bound in-scope so it lives across the blocking `run()` (a dropped Timer stops firing). ----
            let inu_refresh = slint::Timer::default();
            {
                let inu_weak = inu_witness.as_weak();
                let store = inu_store.clone();
                // #97 — the refresh must carry the demo marking too. A 1s redraw that dropped it
                // would make the banner flicker away one second after launch, which is worse than
                // never showing it: the pane would look live precisely once the user started
                // reading it.
                let store_is_demo = !inu_is_live;
                inu_refresh.start(
                    slint::TimerMode::Repeated,
                    std::time::Duration::from_millis(1000),
                    move || {
                        if let Some(d) = inu_weak.upgrade() {
                            feed_from_live_inu(&d, &store, store_is_demo);
                        }
                    },
                );
            }
            inu_witness
                .run()
                .expect("slint android event loop (Inu witness)");
            return;
        }

        // ---- THE COMMITTED SHELL-IS-APP PATH — the 4-tab shell owns the single android surface (every
        // pillar witness above is cfg'd OUT of the default build; Inu is constructed + fed above like the
        // Centauri `dash`, ready for the in-shell InuPane embed wave). ----
        shell.run().expect("slint android event loop");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slint::{Model, ModelRc, VecModel};

    /// Proof-of-substrate (slices: the root substrate + slice 8 the Warden dashboard). This is the SOLE
    /// slint-constructing test BY DESIGN: winit's `EventLoop` is thread-affine and libtest runs every
    /// `#[test]` on its own thread, so a SECOND constructing test on another thread hits "EventLoop can't be
    /// recreated" (and `--test-threads=1` does not help — sequential is still a fresh thread per test). So
    /// the whole binary instantiates SLINT Window components on EXACTLY this one thread, constructing
    /// `TortaShell` (the D3 Design-Finale 4-tab Home), `WardenDashboard`, `WardenSettings`, AND — the
    /// Centauri overhaul — `CentauriDashboard` (slice 8) + `CentauriSettings` (slice 9) on it (multiple
    /// windows on one backend is the normal slint pattern).
    ///
    /// Proves: the toolchain bound ALL the .slint files (home_shell.slint `TortaShell` — the four tabs
    /// as embedded panes with the root's forwarding aliases — + warden.slint `WardenDashboard` +
    /// warden_settings.slint `WardenSettings` + centauri.slint `CentauriDashboard` +
    /// centauri_settings.slint `CentauriSettings` + the centauri_palette.slint `Centauri` global, all
    /// re-exported via main.slint); each accepts live typed Rust values (not a mock). The Warden OVER-BLOCK
    /// HUNT + FELT-TRUTH GUARD derivations fire (a `UniversalToggle` model bound); and the Centauri 🩸
    /// HIDDEN-FAULT HUNT (slice 8: the BLACKHOLE armed-but-empty + the STRICT-LEAK + fallback-dominant, with a
    /// `ServeRow` model bound) + the 🩸 DECISION-POINT GUARD (slice 9: arming strict/cloak against an empty
    /// catalog warns, with a `CdnHostRow` model bound) derivations fire. The pure torta_core engine-surface
    /// reachability (Warden + Centauri) lives in the backend-free tests below.
    #[test]
    fn slint_substrate_compiles_and_binds() {
        // #61D FOUND-LATENT: the 13-pillar shell's debug-build `TortaShell::new()` frame outgrew
        // the default libtest thread stack during the #60 .slint growth — STATUS_STACK_OVERFLOW
        // reproduced at HEAD 1ec5bcb4 WITHOUT the #61D delta (stash-attribution run, GROUND_TRUTH).
        // Same assertions, same truth — on an explicit 64 MiB thread; a panic inside resumes
        // unchanged (the original assert message survives). The on-device lane is unaffected
        // (release frame sizes; the Android UI thread).
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(run)
            .expect("big-stack test thread spawns")
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));
        fn run() {
        // --- home_shell.slint (OMEGA Stage-D · D3, step 8): THE DESIGN FINALE — the 4-tab Home binds.
        // ONE root Window carries the routing truth + the four embedded panes through forwarding
        // aliases (the D2 alias law — no pane behind an `if`). ---
        let shell = TortaShell::new().expect("TortaShell constructs");

        // (1) The tab routing truth is typed state the host reads + drives.
        assert_eq!(
            shell.get_active_tab().as_str(),
            "home",
            "the shell lands on ① HOME"
        );
        shell.set_active_tab("engine".into());
        assert_eq!(shell.get_active_tab().as_str(), "engine");
        shell.set_active_tab("dns".into());
        assert_eq!(shell.get_active_tab().as_str(), "dns");
        shell.set_active_tab("query".into());
        assert_eq!(shell.get_active_tab().as_str(), "query");
        shell.set_active_tab("home".into());

        // ★ #33 THE THEME-TOKEN SPINE — ThemeBook binds and the Demon-Slayer duality is
        // LOAD-BEARING: flipping `akuma` swaps the whole burger chrome set at runtime (the
        // ||| overlay + PillarTab + RailEntry all bind `ThemeBook.burger.*`), and the
        // per-section themes alias the REAL palette globals (never drifted copies).
        {
            let book = shell.global::<ThemeBook>();

            // The Hashira side is the landing chrome (akuma defaults false).
            assert!(!book.get_akuma(), "the burger lands hero-side");
            let hero = book.get_burger();
            assert_eq!(hero.name.as_str(), "HASHIRA");
            assert_eq!(
                hero.accent,
                slint::Color::from_rgb_u8(0x5e, 0x8b, 0xff),
                "hero chrome wears the pillar-blue accent"
            );

            // THE FLIP — one assignment restyles every bound consumer.
            book.set_akuma(true);
            let demon = book.get_burger();
            assert_eq!(demon.name.as_str(), "UPPER MOONS");
            assert_eq!(
                demon.accent,
                slint::Color::from_rgb_u8(0xc0, 0x26, 0xd3),
                "demon chrome wears the Upper-Moon magenta"
            );
            assert_ne!(hero.ground, demon.ground, "the ground itself flips demon-side");
            book.set_akuma(false);

            // The section entries alias the live palette globals (spot checks across the book):
            // Warden = Monokuma.risk, DNSCrypt = the Candle gold, Underground = the Matrix green.
            assert_eq!(book.get_warden().accent, slint::Color::from_rgb_u8(0xd8, 0x3a, 0x2c));
            assert_eq!(book.get_dnscrypt().accent, slint::Color::from_rgb_u8(0xe7, 0xad, 0x42));
            assert_eq!(book.get_underground().accent, slint::Color::from_rgb_u8(0x2f, 0xe2, 0x6a));
            // The typography energy rides the same struct (Beast = the kinetic 20px/900 value).
            assert_eq!(book.get_beast().value_weight, 900);
        }

        // ★ #22 slice 2 — the TCAT v2 freshness alias chain BINDS (shell → cendash → pane) and
        // lands on the honest em-dash (epoch unknown), never a 1970-derived age.
        assert_eq!(
            shell.get_catalog_freshness().as_str(),
            "—",
            "catalog freshness defaults to the em-dash (unknown), through the full alias chain"
        );
        shell.set_catalog_freshness("3m ago".into());
        assert_eq!(shell.get_catalog_freshness().as_str(), "3m ago");

        // (1B) THE ||| ADVANCED OVERLAY — the in-shell navigation truth (the single-surface law:
        // on-device window-swaps are dead, so the shell itself carries the ||| routing state).
        assert!(
            !shell.get_advanced_open(),
            "the shell lands with the ||| overlay closed"
        );
        assert_eq!(
            shell.get_advanced_section().as_str(),
            "pillars",
            "the ||| overlay lands on the PILLARS section"
        );
        shell.set_advanced_open(true);
        shell.set_advanced_section("general".into());
        assert_eq!(shell.get_advanced_section().as_str(), "general");
        // The GENERAL pane binds through the shell's byte-equal forwarding aliases and its
        // all-pillars-off guard derives through the shell mount.
        shell.set_rotation_on(false);
        shell.set_solver_on(false);
        shell.set_warden_on(false);
        assert!(
            shell.get_warn_all_pillars_off(),
            "every pillar OFF MUST surface through the shell's GENERAL mount"
        );
        shell.set_rotation_on(true);
        assert!(!shell.get_warn_all_pillars_off());
        assert_eq!(shell.get_preset_label().as_str(), "CUSTOM");
        shell.set_preset_active(1);
        assert_eq!(shell.get_preset_label().as_str(), "PRIVACY");
        // The overlay's per-pillar private chips route with their pillar id.
        let chip_routed = std::rc::Rc::new(std::cell::RefCell::new(String::new()));
        {
            let sink = chip_routed.clone();
            shell.on_open_pillar_dashboard(move |id| {
                *sink.borrow_mut() = format!("dash:{id}");
            });
        }
        shell.invoke_open_pillar_dashboard("warden".into());
        assert_eq!(
            chip_routed.borrow().as_str(),
            "dash:warden",
            "the overlay DASHBOARD chip intent carries its pillar id"
        );
        {
            let sink = chip_routed.clone();
            shell.on_open_pillar_settings(move |id| {
                *sink.borrow_mut() = format!("settings:{id}");
            });
        }
        shell.invoke_open_pillar_settings("beast".into());
        assert_eq!(chip_routed.borrow().as_str(), "settings:beast");
        shell.set_advanced_open(false);
        shell.set_advanced_section("pillars".into());

        // (2) ① HOME — the dnsmasq×rethink hybrid: the felt-truth crown + the resolver ledger.
        assert!(
            shell.get_home_note_preview(),
            "host-live defaults FALSE — HOME says PREVIEW until a host pushes real engine state"
        );
        assert!(
            shell.get_warn_engine_off(),
            "engine OFF MUST surface THE-TUNNEL-IS-DOWN (DNS rides the system resolver)"
        );
        assert!(
            shell.get_crown_line().as_str().contains("OPEN"),
            "the stopped crown reads OPEN: {}",
            shell.get_crown_line()
        );
        shell.set_engine_running(true);
        assert!(!shell.get_warn_engine_off());
        assert!(
            shell.get_crown_line().as_str().contains("SHIELDED"),
            "the running crown reads SHIELDED: {}",
            shell.get_crown_line()
        );
        assert!(
            shell.get_note_cold(),
            "running with zero queries notes the cold ledger (honest empty, not broken)"
        );
        shell.set_queries(1234);
        shell.set_answered(1200);
        shell.set_blocked(57);
        shell.set_cache_hits(801);
        shell.set_stale_served(3);
        shell.set_served_local(21);
        assert!(!shell.get_note_cold());
        assert_eq!(shell.get_blocked(), 57);
        assert_eq!(shell.get_served_local(), 21);

        // The pillar health chips: the typed PillarTabRow model binds and the chip intent routes.
        shell.set_pillar_chips(ModelRc::new(VecModel::from(vec![PillarTabRow {
            id: "centauri".into(),
            name: "CENTAURI".into(),
            blurb: "the offline-CDN constellation".into(),
            status: "libraries=0 bytes=0 full=false".into(),
            live: true,
            accent: slint::Color::from_rgb_u8(0x28, 0xc8, 0xd8),
        }])));
        assert_eq!(
            shell.get_pillar_chips().row_count(),
            1,
            "the PillarTabRow model binds through the shell's HOME chips"
        );
        let routed = std::rc::Rc::new(std::cell::RefCell::new(String::new()));
        {
            let sink = routed.clone();
            shell.on_open_pillar(move |id| {
                *sink.borrow_mut() = format!("pillar:{id}");
            });
        }
        shell.invoke_open_pillar("centauri".into());
        assert_eq!(
            routed.borrow().as_str(),
            "pillar:centauri",
            "the HOME chip intent routes with its pillar id"
        );

        // The master switch carries the intent WITHOUT local echo (the host owns the truth).
        let toggled = std::rc::Rc::new(std::cell::RefCell::new(None::<bool>));
        {
            let sink = toggled.clone();
            shell.on_engine_toggled(move |on| {
                *sink.borrow_mut() = Some(on);
            });
        }
        shell.invoke_engine_toggled(false);
        assert_eq!(
            *toggled.borrow(),
            Some(false),
            "the master-switch intent carries its typed bool"
        );
        assert!(
            shell.get_engine_running(),
            "no local echo — engine-running moves only when the host pushes it"
        );

        // (3) ② Tortä ENGINE — the Beast porthole: F6 profile-gated honesty + the spike preview.
        assert!(
            shell.get_engine_note_preview(),
            "engine-live defaults FALSE — the tab says SPIKE PREVIEW, never fakes the running engine"
        );
        shell.set_engine_mode("YEAH".into());
        assert_eq!(shell.get_engine_mode().as_str(), "YEAH");
        shell.set_engine_cwnd(42);
        shell.set_engine_window_max(96);
        assert_eq!(shell.get_engine_cwnd(), 42);
        shell.set_engine_fill_critical(0.75);
        assert!((shell.get_engine_fill_critical() - 0.75).abs() < 1e-6);
        shell.set_engine_canonical_brain(false);
        assert!(
            shell.get_engine_note_legacy_brain(),
            "a Legacy brain MUST note its dark canonical tiles (F6 — inert 0s never read live)"
        );
        shell.set_engine_canonical_brain(true);
        assert!(!shell.get_engine_note_legacy_brain());
        shell.set_engine_cobalt_aqm(false);
        assert!(
            shell.get_engine_note_legacy_aqm(),
            "a Legacy AQM MUST note its dark valve tiles"
        );
        shell.set_engine_cobalt_aqm(true);
        assert!(!shell.get_engine_note_legacy_aqm());

        // (4) ③ DNS — the SAME K5 pane the burger mounts: the shared alias set renders the typed
        // authority and the decision-point guard fires through the SHELL's forwarding (the full
        // guard matrix is exercised on the burger mount below — one pane component, two mounts).
        let shell_cfg = torta_core::dnscrypt_config_get();
        shell.set_require_nolog(shell_cfg.require_nolog);
        assert!(
            shell.get_require_nolog(),
            "the upstream default require_nolog=true renders through the shell's DNS-tab alias"
        );
        shell.set_dnscrypt_servers(false);
        shell.set_doh_servers(false);
        shell.set_odoh_servers(false);
        assert!(
            shell.get_warn_no_server_type(),
            "every server type OFF MUST surface POOL DARK through the shell mount too"
        );
        shell.set_doh_servers(true);
        shell.set_dnscrypt_servers(true);
        shell.set_odoh_servers(false);
        assert!(!shell.get_warn_no_server_type());

        // (5) ④ QUERY — the typed feed rows bind, the staleness honesty derives, the source routes.
        shell.set_query_rows(ModelRc::new(VecModel::from(vec![QueryRow {
            time: "[2026-07-02 12:00:00]".into(),
            line: "solver cache HIT qtype=A".into(),
            verdict: "CACHE".into(),
            accent: slint::Color::from_rgb_u8(0xa7, 0x8b, 0xfa),
        }])));
        assert_eq!(
            shell.get_query_rows().row_count(),
            1,
            "the QueryRow model binds through the generated struct"
        );
        shell.set_query_log_present(true);
        shell.set_query_stale_secs(9999);
        assert!(
            shell.get_query_stale_banner(),
            "a present-but-idle log MUST surface the STALE FEED banner"
        );
        shell.set_query_stale_secs(3);
        assert!(!shell.get_query_stale_banner());
        shell.set_query_log_present(false);
        shell.set_query_stale_secs(-1);
        assert!(
            !shell.get_query_stale_banner(),
            "an ABSENT log is `not written yet`, never `stale` (the -1 sentinel gates the banner)"
        );
        let picked = std::rc::Rc::new(std::cell::RefCell::new(String::new()));
        {
            let sink = picked.clone();
            shell.on_query_source_picked(move |src| {
                *sink.borrow_mut() = src.to_string();
            });
        }
        shell.invoke_query_source_picked("beast".into());
        assert_eq!(
            picked.borrow().as_str(),
            "beast",
            "the QUERY source intent carries its typed id"
        );

        // The torta_core dep resolves (the engine crate is reachable from the UI crate).
        let _cfg = torta_core::dnscrypt_config_get();

        // --- warden.slint (slice 8): the Warden dashboard binds + hunts over-block. ---
        let dash = WardenDashboard::new().expect("WardenDashboard constructs");

        // (1)(2) Host pushes a WardenSnapshot-shaped posture; the UI echoes it.
        dash.set_allow_count(0);
        dash.set_deny_count(57);
        dash.set_deny_by_toggle(0);
        dash.set_deny_by_app(40);
        dash.set_deny_by_universal(0);
        dash.set_deny_by_dns(17);
        dash.set_domain_rules(1280);
        dash.set_cidr_rules(64);
        dash.set_universal_rules(3);
        dash.set_app_rows(12);
        dash.set_cache_entries(512);
        dash.set_policy_loaded(false);
        dash.set_fail_closed(true);
        assert_eq!(dash.get_deny_count(), 57);
        assert_eq!(dash.get_app_rows(), 12);
        assert_eq!(dash.get_total_verdicts(), 57);

        // (3) The over-block hunt: the APEX stranding (fail-closed + no policy → all denied) surfaces, and
        // the zero-allow stranding surfaces — the dashboard makes the invisible wall visible.
        assert!(
            dash.get_overblock_fail_closed(),
            "fail-closed + no policy MUST surface (the silent total over-block)"
        );
        assert!(
            dash.get_overblock_all_denied(),
            "deny>0 with allow==0 MUST surface (the stranding firewall)"
        );
        assert!(dash.get_overblock_any());

        // The Trust crown over-block: an ARMED risky source over-blocks the web.
        dash.set_trust_source_name("hosts-evil-megalist".into());
        dash.set_trust_cdn_overlap(48);
        dash.set_trust_score(31);
        dash.set_trust_armed(true);
        assert_eq!(dash.get_trust_band().as_str(), "RISKY");
        assert!(
            dash.get_overblock_trust_risky(),
            "an armed RISKY blocklist MUST surface as a web-over-block"
        );

        // A SAFE armed source does NOT raise the web-over-block alarm.
        dash.set_trust_score(92);
        assert_eq!(dash.get_trust_band().as_str(), "SAFE");
        assert!(!dash.get_overblock_trust_risky());

        // --- warden_settings.slint (slice 9): the Warden |||  settings section binds + guards the decision
        // point. Constructed on THIS SAME thread (the EventLoop-thread-affine law above). ---
        let settings = WardenSettings::new().expect("WardenSettings constructs");

        // (1) A typed row model binds end-to-end — the exported `UniversalToggle` struct round-trips through
        // the generated binding (the host pushes the live WardenUniversalToggles state this way).
        let toggles = ModelRc::new(VecModel::from(vec![
            UniversalToggle {
                key: "lockdown".into(),
                label: "Lockdown".into(),
                hint: "RULE11 — block everything except the allow-list".into(),
                on: true,
                rule_armed: true,
            },
            UniversalToggle {
                key: "block-http".into(),
                label: "Block plain HTTP".into(),
                hint: "RULE10 — deny port 80".into(),
                on: false,
                rule_armed: true,
            },
        ]));
        settings.set_universal_toggles(toggles);
        assert_eq!(
            settings.get_universal_toggles().row_count(),
            2,
            "the UniversalToggle model binds through the generated struct"
        );

        // (2) The 🎷 FELT-TRUTH GUARD: a fail-closed posture with NO policy MUST warn at the decision point
        // (the silent total-deny, surfaced BEFORE it strands traffic — not after, like the dashboard).
        settings.set_fail_closed(true);
        settings.set_policy_loaded(false);
        assert!(settings.get_fail_closed());
        assert!(
            settings.get_warn_fail_closed_no_policy(),
            "fail-closed + no policy MUST warn at the settings decision point"
        );

        // (3) Flipping LOCKDOWN surfaces its cost at the arming tap. (There is deliberately NO trust/risky
        // guard here — the Warden layer has no trust concept by design law; that surface is a separate pillar.)
        settings.set_lockdown_on(true);
        assert!(settings.get_warn_lockdown());
        assert!(settings.get_warn_any());

        // (4) Relaxing the posture clears the warnings — the guard is honest, not a stuck red light.
        settings.set_lockdown_on(false);
        settings.set_policy_loaded(true);
        assert!(!settings.get_warn_lockdown());
        assert!(
            !settings.get_warn_fail_closed_no_policy(),
            "fail-closed alone (policy loaded) is not a no-policy stranding"
        );
        assert!(!settings.get_warn_any());

        // --- centauri.slint (Centauri slice 8): the offline-CDN CONSTELLATION dashboard binds + hunts the
        // hidden faults (the BLACKHOLE + the STRICT-LEAK). Constructed on THIS SAME thread (the EventLoop law). ---
        let cen = CentauriDashboard::new().expect("CentauriDashboard constructs");

        // (1) Host pushes a CentauriSnapshot-shaped CROWN posture; the UI echoes it + the ServeRow feed binds.
        cen.set_serve_state(2); // Serving
        cen.set_catalog_assets(50);
        cen.set_served_locally(128);
        cen.set_cdn_fetches(0);
        cen.set_exact_serves(120);
        cen.set_fallback_serves(8);
        cen.set_libraries(50);
        cen.set_cache_bytes(2_400_000);
        cen.set_capacity(1024);
        let feed = ModelRc::new(VecModel::from(vec![
            ServeRow {
                host: "cdnjs.cloudflare.com".into(),
                asset: "jquery/3.7.1/jquery.min.js".into(),
                outcome: "LOCAL".into(),
                sub: "exact".into(),
                bytes: 87533,
            },
            ServeRow {
                host: "use.fontawesome.com".into(),
                asset: "fontawesome/6.5.1/all.min.css".into(),
                outcome: "LEAK".into(),
                sub: "newer".into(),
                bytes: 70234,
            },
        ]));
        cen.set_recent_serves(feed);
        assert_eq!(
            cen.get_recent_serves().row_count(),
            2,
            "the ServeRow feed model binds through the generated struct"
        );
        assert_eq!(cen.get_served_locally(), 128);

        // (2) THE CROWN achieved — served from the device with the CDN touched zero times.
        assert!(
            cen.get_cdn_saw_zero(),
            "served-locally>0 + cdn-fetches==0 MUST surface as the crown (CDN saw 0)"
        );
        assert_eq!(cen.get_crown_headline().as_str(), "CDN SAW 0");
        assert!(
            !cen.get_blackhole_risk(),
            "a populated catalog is NOT a blackhole"
        );
        assert!(!cen.get_hidden_fault_any());
        // The CROWN is always-on LeakOnMiss — the identity label is baked, no strict mode exists.
        assert_eq!(cen.get_cache_mode_label().as_str(), "LEAK-ON-MISS (≤1/asset)");

        // (3) 🩸 THE BLACKHOLE — armed (serving) but the signed catalog is EMPTY → cloaked hosts 404-blackhole.
        cen.set_catalog_assets(0);
        assert!(
            cen.get_blackhole_risk(),
            "serving + empty catalog MUST surface the BLACKHOLE (the silent killer: stranded AND served nothing)"
        );
        assert_eq!(cen.get_crown_headline().as_str(), "BLACKHOLE");
        assert!(cen.get_hidden_fault_any());

        // (4) FALLBACK-DOMINANT — most serves were version-substituted, SRI-pinned consumers decline (F3).
        cen.set_catalog_assets(50); // cure the blackhole first
        cen.set_cdn_fetches(0);
        cen.set_exact_serves(1);
        cen.set_fallback_serves(5);
        assert!(
            cen.get_fallback_dominant(),
            "fallback majority MUST surface the SRI substitution risk (F3 honesty)"
        );

        // --- centauri_settings.slint (Centauri slice 9): the ||| settings guard the ARMING decision point. ---
        let cset = CentauriSettings::new().expect("CentauriSettings constructs");
        let watch = ModelRc::new(VecModel::from(vec![
            CdnHostRow {
                host: "cdnjs.cloudflare.com".into(),
                mapped: true,
            },
            CdnHostRow {
                host: "ajax.googleapis.com".into(),
                mapped: true,
            },
        ]));
        cset.set_cdn_hosts(watch);
        assert_eq!(
            cset.get_cdn_hosts().row_count(),
            2,
            "the CdnHostRow model binds through the generated struct"
        );

        // (1) 🩸 Arming the CLOAK with an EMPTY catalog MUST warn at the decision point (the blackhole, BEFORE).
        // (No strict path: the CROWN is always-on LeakOnMiss — the cloak is the only arming that can blackhole.)
        cset.set_cloak_armed(true);
        cset.set_catalog_assets(0);
        assert!(
            cset.get_warn_blackhole_arm(),
            "arming the cloak with no catalog MUST warn (the blackhole surfaced where it is chosen)"
        );
        assert!(cset.get_warn_any());

        // (2) The catalog arming (auto on every engine start) clears the blackhole — honest, not a stuck light.
        cset.set_catalog_assets(50);
        assert!(!cset.get_warn_blackhole_arm());
        assert!(!cset.get_warn_any());

        // (3) With a catalog present, the cloak's DNS-change caution is the remaining informational note.
        assert!(
            cset.get_warn_cloak_changes_dns(),
            "cloak armed + catalog present MUST surface the DNS-change caution"
        );
        // The seed-policy label decodes the 73MB scope call (CatalogOnly default vs the opt-in warm-up).
        cset.set_seed_policy(1);
        assert_eq!(
            cset.get_seed_policy_label().as_str(),
            "WARM-UP BATCH (self-fill on device)"
        );

        // (4) THE LENS (#25 inspector) — the served-bytes "never left your device" witness binds through the
        // forwarder to the pane (the "what it prevented" facet reads it live; the other facets reuse
        // catalog-assets / libraries / served-locally / cdn-hosts already asserted above).
        cset.set_served_locally(128);
        cset.set_served_bytes(524_288);
        cset.set_libraries(12);
        assert_eq!(
            cset.get_served_bytes(),
            524_288,
            "the LENS 'bytes never left your device' witness MUST bind through the forwarder to the pane"
        );

        // --- masksolver.slint (MaskSolver slice 8): the resolver dashboard binds + hunts the SILENT faults.
        // Constructed on THIS SAME thread (the EventLoop-thread-affine law above — Chroma F9). ---
        // Since 2-FEED-MaskSolver the driven prop + 🩸 hidden-fault surface lives on the embeddable
        // `MaskSolverPane` (the shell mounts it in-shell); `MaskSolverDashboard` is now a Window that
        // FORWARDS the pane's full API (a non-Window pane generates no standalone Rust code — measured),
        // so the proof drives the Window and the values reach the pane through the `<=>` aliases.
        let mask = MaskSolverDashboard::new().expect("MaskSolverDashboard constructs");

        // (1) Host pushes a HEALTHY MaskSolverSnapshot/SolveState-shaped posture; the UI echoes it + the
        // typed feed models bind end-to-end through the generated structs (MaskRow + MaskTransportRow).
        mask.set_configured(true);
        mask.set_transports(2);
        mask.set_cache_entries(512);
        mask.set_queries(1000);
        mask.set_answered(980);
        mask.set_cache_hits(600);
        mask.set_serve_stale_served(10);
        mask.set_rebind_observed(0);
        mask.set_rebind_rejected(0);
        mask.set_solve_ladder_exhausted(0);
        mask.set_panics(0);
        mask.set_solve_success_rate(0.98);
        mask.set_cache_hit_rate(0.6);
        mask.set_strategy(2);
        assert_eq!(mask.get_answered(), 980);
        assert_eq!(
            mask.get_strategy_label().as_str(),
            "FASTEST (health-ordered)"
        );

        let feed = ModelRc::new(VecModel::from(vec![
            MaskRow {
                outcome: "HIT".into(),
                qtype: "A".into(),
                transport: "-".into(),
                rtt: "-".into(),
            },
            MaskRow {
                outcome: "SOLVE".into(),
                qtype: "AAAA".into(),
                transport: "cloudflare-doh".into(),
                rtt: "12ms".into(),
            },
        ]));
        mask.set_recent_resolves(feed);
        assert_eq!(
            mask.get_recent_resolves().row_count(),
            2,
            "the MaskRow resolve-feed model binds through the generated struct"
        );
        let health = ModelRc::new(VecModel::from(vec![
            MaskTransportRow {
                id: "quad9-doh".into(),
                rtt: "18ms".into(),
                loss: 0.0,
                samples: 240,
            },
            MaskTransportRow {
                id: "cloudflare-doh".into(),
                rtt: "12ms".into(),
                loss: 0.02,
                samples: 512,
            },
        ]));
        mask.set_transport_rows(health);
        assert_eq!(
            mask.get_transport_rows().row_count(),
            2,
            "the MaskTransportRow health model binds through the generated struct"
        );

        // A healthy resolver: resolving, ZERO hidden fault, crown RESOLVING.
        assert!(mask.get_resolving());
        assert!(
            !mask.get_hidden_fault_any(),
            "a healthy resolver surfaces NO hidden fault"
        );
        assert_eq!(mask.get_crown_headline().as_str(), "RESOLVING");

        // (2) 🩸 THE SILENT MISS — traffic arrived but answered NOTHING (pool present ⇒ not a dead-pool).
        mask.set_answered(0);
        assert!(
            mask.get_silent_miss(),
            "queries>0 + answered==0 MUST surface the SILENT MISS (resolving into the void)"
        );
        assert!(!mask.get_dead_pool());
        assert_eq!(mask.get_crown_headline().as_str(), "SILENT MISS");
        assert!(mask.get_hidden_fault_any());

        // (3) 🩸 THE DEAD POOL — configured but ZERO upstreams; the ROOT CAUSE beats the silent-miss symptom.
        mask.set_transports(0);
        assert!(
            mask.get_dead_pool(),
            "configured + transports==0 MUST surface the DEAD POOL (armed, no upstream)"
        );
        assert_eq!(
            mask.get_crown_headline().as_str(),
            "DEAD POOL",
            "dead-pool (the cause) beats silent-miss (the symptom) in the crown chain"
        );

        // restore a healthy answering posture for the remaining hunts.
        mask.set_transports(2);
        mask.set_answered(980);
        assert!(mask.get_resolving());

        // (4) 🩸 THE REBIND LEAK — a public->private answer OBSERVED but not REJECTED (the guard is dormant).
        mask.set_rebind_observed(5);
        mask.set_rebind_rejected(2);
        assert!(
            mask.get_rebind_passthrough(),
            "rebind observed>rejected MUST surface the REBIND LEAK (a dormant P12 guard)"
        );
        assert_eq!(mask.get_crown_headline().as_str(), "REBIND LEAK");
        // arming the guard (every observed answer rejected) clears it — honest, not a stuck red light.
        mask.set_rebind_rejected(5);
        assert!(!mask.get_rebind_passthrough());

        // (5) 🩸 STALE-SERVING — more expired-cache serves than fresh hits (the fresh path degraded).
        mask.set_serve_stale_served(500);
        mask.set_cache_hits(100);
        assert!(
            mask.get_stale_dominant(),
            "serve_stale_served>cache_hits MUST surface STALE-SERVING (living on old answers)"
        );
        assert_eq!(mask.get_crown_headline().as_str(), "STALE-SERVING");
        mask.set_serve_stale_served(10);
        mask.set_cache_hits(600);
        assert!(!mask.get_stale_dominant());

        // (6) 🩸 LADDER STORM — the resilient ladder exhausts more often than it answers (upstreams failing).
        mask.set_solve_ladder_exhausted(1000);
        assert!(
            mask.get_ladder_storm(),
            "solve_ladder_exhausted>answered MUST surface the LADDER STORM"
        );
        assert_eq!(mask.get_crown_headline().as_str(), "LADDER STORM");
        mask.set_solve_ladder_exhausted(0);
        assert!(!mask.get_ladder_storm());

        // (7) 🩸 PANIC — the datapath firewall caught a bug (a breach, high in the chain).
        mask.set_panics(3);
        assert!(mask.get_panic_seen());
        assert_eq!(mask.get_crown_headline().as_str(), "PANIC");
        mask.set_panics(0);

        // (8) All faults cleared → back to healthy; the hunt is honest, not a stuck alarm.
        assert!(!mask.get_hidden_fault_any());
        assert_eq!(mask.get_crown_headline().as_str(), "RESOLVING");

        // (9) The dormant states: ARMED (configured, no traffic yet) vs DORMANT (unconfigured).
        mask.set_queries(0);
        mask.set_answered(0);
        assert!(!mask.get_resolving());
        assert_eq!(mask.get_crown_headline().as_str(), "ARMED");
        mask.set_configured(false);
        assert!(
            !mask.get_dead_pool(),
            "an unconfigured resolver is DORMANT, not a dead-pool"
        );
        assert_eq!(mask.get_crown_headline().as_str(), "DORMANT");

        // --- masksolver_settings.slint (MaskSolver slice 9): the ||| resolver controls bind + the 🎷 Violet
        // DECISION-POINT GUARD warns where a counterproductive choice is MADE (not after, like the dashboard).
        // Constructed on THIS SAME thread (the EventLoop-thread-affine law above — Chroma F9). ---
        let mset = MaskSolverSettings::new().expect("MaskSolverSettings constructs");

        // (1) A HEALTHY, configured posture: pool live, guard armed, sane cache + deadline → NO actionable warning.
        mset.set_configured(true);
        mset.set_transports(2);
        mset.set_solve_ladder_on(true);
        mset.set_all_servers_on(false);
        mset.set_strategy(2); // Fastest (the resolved active mode)
        mset.set_timeout_ms(2500);
        mset.set_cache_cap(4096);
        mset.set_cache_entries(512);
        mset.set_serve_stale_on(true);
        mset.set_serve_stale_secs(60);
        mset.set_rebind_protect_on(true);
        mset.set_rebind_observed(0);
        mset.set_rebind_rejected(0);
        assert_eq!(
            mset.get_strategy_label().as_str(),
            "FASTEST (health-ordered)",
            "the settings decode the host-pushed active-strategy ordinal (the engine's live truth)"
        );
        assert!(
            !mset.get_warn_any(),
            "a healthy configured posture raises NO actionable decision-point warning"
        );
        // The posture summary reads the live knobs back in plain words (the feedback-simple-ux felt-truth).
        assert!(
            mset.get_posture_line().as_str().contains("rebind ON"),
            "the plain-words posture line reflects the armed guard: {}",
            mset.get_posture_line()
        );

        // (2) 🎷 DEAD-POOL ARM — a retry/failover strategy armed against ZERO upstreams warns at the settings tap
        // (the settings-time twin of the dashboard's DEAD POOL, surfaced BEFORE the user relies on it).
        mset.set_transports(0);
        assert!(
            mset.get_warn_dead_pool_arm(),
            "arming the resilient ladder with zero upstreams MUST warn (settings-time dead pool)"
        );
        assert!(mset.get_warn_any());
        mset.set_transports(2);
        assert!(!mset.get_warn_dead_pool_arm());

        // (3) 🎷 REBIND GUARD OFF UNDER ATTACK — disabling the P12 guard while a rebind answer was already SEEN
        // warns (the felt-truth: you are turning off a guard that is catching a live attack).
        mset.set_rebind_protect_on(false);
        mset.set_rebind_observed(3);
        assert!(
            mset.get_warn_rebind_off(),
            "rebind-protect OFF while a public->private answer is observed MUST warn"
        );
        // re-arming it clears the warning — honest, not a stuck red light.
        mset.set_rebind_protect_on(true);
        assert!(!mset.get_warn_rebind_off());

        // (4) 🎷 SHORT DEADLINE vs the resilient ladder — a sub-200ms budget defeats the retry just armed.
        mset.set_timeout_ms(120);
        assert!(
            mset.get_warn_short_deadline(),
            "a sub-200ms deadline under the armed resilient ladder MUST warn"
        );
        mset.set_timeout_ms(2500);
        assert!(!mset.get_warn_short_deadline());

        // (5) 🎷 SERVE-STALE INERT — armed with a 0s window serves nothing stale (the toggle looks on, does nothing).
        mset.set_serve_stale_secs(0);
        assert!(
            mset.get_warn_stale_inert(),
            "serve-stale ON with a 0s window MUST warn (inert config)"
        );
        mset.set_serve_stale_secs(60);
        assert!(!mset.get_warn_stale_inert());

        // (6) 🎷 TINY CACHE — a cache this small barely caches (the cold-hit-rate felt-truth).
        mset.set_cache_cap(16);
        assert!(
            mset.get_warn_tiny_cache(),
            "a tiny cache cap MUST warn (near-zero hit-rate)"
        );
        mset.set_cache_cap(4096);
        assert!(!mset.get_warn_tiny_cache());

        // (7) All knobs sane again → every actionable warning clears; the guard is honest, not a stuck alarm.
        assert!(!mset.get_warn_any());
        // (8) The soft "unconfigured" note is informational (NOT an actionable warning — it does not raise warn-any).
        mset.set_configured(false);
        assert!(mset.get_note_unconfigured());
        assert!(
            !mset.get_warn_any(),
            "the unconfigured note is a soft stage-and-apply notice, not a misconfiguration alarm"
        );

        // --- beast.slint (the Beast surface overhaul, slice 8): THE CAKE-FOUNTAIN dashboard binds + hunts the
        // flow-faults (COLLAPSED / OVERFLOW / CONGESTED) + profile-gates the canonical/CoBALT cards (Chroma F6).
        // Constructed on THIS SAME thread (the EventLoop-thread-affine law above — Chroma F9). ---
        // 2-FEED-Beast: the properties + 🩸 flow-fault derivations live on the embeddable `BeastPane`; the
        // `BeastDashboard` Window FORWARDS them all (a non-Window pane exported from the root generates no
        // Rust code), so the test drives the pane's surface through the wrapper's byte-equal aliases.
        let beast = BeastDashboard::new().expect("BeastDashboard constructs");

        // (1) Host pushes a HEALTHY flowing BeastSnapshot-shaped posture (canonical YeAH + CoBALT AQM); the UI
        // echoes it + the BeastTickRow feed binds end-to-end through the generated struct.
        beast.set_yeah_profile(1); // Canonical
        beast.set_cake_profile(1); // CoBALT
        beast.set_cwnd(8);
        beast.set_window_max(16);
        beast.set_mode("YEAH".into());
        beast.set_base_rtt_ms(24.0);
        beast.set_pacing_rate(333.0);
        beast.set_pipeline_depth(3);
        beast.set_queue_critical(1);
        beast.set_queue_high(2);
        beast.set_queue_normal(4);
        beast.set_blue_prob(0.0);
        let ticks = ModelRc::new(VecModel::from(vec![
            BeastTickRow {
                mode: "YEAH".into(),
                cwnd: 8,
                shed: 0,
                relay: "cloudflare".into(),
            },
            BeastTickRow {
                mode: "COMPETING".into(),
                cwnd: 5,
                shed: 2,
                relay: "quad9".into(),
            },
        ]));
        beast.set_recent_ticks(ticks);
        assert_eq!(
            beast.get_recent_ticks().row_count(),
            2,
            "the BeastTickRow feed model binds through the generated struct"
        );
        assert_eq!(beast.get_cwnd(), 8);
        // A healthy flowing fountain: no flow-fault, the crown reads the live mode, both profiles live.
        assert!(
            !beast.get_hidden_fault_any(),
            "a healthy flowing Beast surfaces NO flow-fault"
        );
        assert_eq!(beast.get_crown_headline().as_str(), "YEAH");
        assert!(beast.get_canonical_live());
        assert!(beast.get_cobalt_live());
        assert_eq!(beast.get_yeah_profile_label().as_str(), "CANONICAL");
        assert_eq!(beast.get_cake_profile_label().as_str(), "BASELINE");

        // (2) 🩸 COLLAPSED WINDOW — the pump is stuck single-probe (cwnd==1) with a backlog piling.
        beast.set_cwnd(1);
        beast.set_pipeline_depth(5);
        assert!(
            beast.get_collapsed_window(),
            "cwnd==1 + backlog MUST surface the COLLAPSED WINDOW (DNS crawling single-probe)"
        );
        assert_eq!(beast.get_crown_headline().as_str(), "COLLAPSED");
        assert!(beast.get_hidden_fault_any());
        beast.set_cwnd(8); // restore

        // (3) 🩸 CONGESTED — a CoBALT BLUE valve is open (shedding SERVFAIL-fast; honest, never silent).
        beast.set_blue_prob(0.1);
        assert!(
            beast.get_congested(),
            "an open BLUE valve under CoBALT MUST surface CONGESTED (active shedding)"
        );
        assert_eq!(beast.get_crown_headline().as_str(), "CONGESTED");
        beast.set_blue_prob(0.0); // restore

        // (4) 🩸 BASIN OVERFLOW — a priority tin hit its cap ([4,8,16]) → the fountain spills.
        beast.set_queue_critical(4); // == cap_critical default
        assert!(
            beast.get_basin_overflow(),
            "a tin at its cap MUST surface BASIN OVERFLOW"
        );
        assert_eq!(
            beast.get_crown_headline().as_str(),
            "OVERFLOW",
            "overflow surfaces once collapse + congestion are clear"
        );
        beast.set_queue_critical(1); // restore

        // (5) 🩸 THE PROFILE-BLINDNESS HONESTY (Chroma F6) — under the LEGACY AQM an inert BLUE value does NOT
        // read as live congestion; under the LEGACY YeAH brain the canonical telemetry is gated off.
        beast.set_cake_profile(0); // Legacy AQM
        beast.set_blue_prob(0.1); // inert under Legacy
        assert!(
            !beast.get_cobalt_live(),
            "the Legacy AQM MUST gate the CoBALT valve cards off"
        );
        assert!(
            !beast.get_congested(),
            "a Legacy AQM's inert BLUE value MUST NOT read as live congestion (F6 honesty)"
        );
        beast.set_yeah_profile(0); // Legacy YeAH
        assert!(
            !beast.get_canonical_live(),
            "the Legacy YeAH brain MUST gate the canonical telemetry off"
        );
        assert_eq!(beast.get_yeah_profile_label().as_str(), "LEGACY");
        assert_eq!(beast.get_cake_profile_label().as_str(), "LEGACY-AQM");
        beast.set_yeah_profile(1); // restore
        beast.set_cake_profile(1);
        beast.set_blue_prob(0.0);

        // (6) 🩸 DORMANT (informational) — the engine has seen no RTT sample yet → the crown reads DORMANT.
        beast.set_base_rtt_ms(0.0);
        assert!(
            beast.get_dormant(),
            "base_rtt_ms<=0 MUST surface DORMANT (no sample yet)"
        );
        assert_eq!(beast.get_crown_headline().as_str(), "DORMANT");
        beast.set_base_rtt_ms(24.0); // restore

        // (7) 🩸 UDP/TCP RTT DIVERGENCE (informational) — judged on the TRUE per-family lanes
        // (#3-EXT twin-RTT cure): the netstack forwarder's TCP dial EWMA vs the UDP EWMA. The shared
        // estimator (base_rtt_ms) can NEVER fire it alone — that shared lane rendering as two
        // identical "per-family" tiles WAS the twin-RTT bug.
        beast.set_base_rtt_ms(10.0);
        beast.set_udp_base_rtt_ms(40.0);
        assert!(
            !beast.get_udp_tcp_divergence(),
            "the shared estimator alone MUST NOT surface divergence (the TCP lane is still cold)"
        );
        beast.set_tcp_base_rtt_ms(10.0);
        assert!(
            beast.get_udp_tcp_divergence(),
            "a >2x split between the TRUE TCP dial lane + the UDP base-RTT MUST surface the divergence"
        );

        // (8) All flow-faults cleared → back to a healthy fountain; the hunt is honest, not a stuck alarm.
        beast.set_base_rtt_ms(24.0);
        beast.set_udp_base_rtt_ms(0.0);
        beast.set_tcp_base_rtt_ms(0.0);
        assert!(!beast.get_hidden_fault_any());
        assert_eq!(beast.get_crown_headline().as_str(), "YEAH");

        // --- beast_settings.slint (the Beast surface overhaul, slice 9): the ||| Beast tune controls bind + the
        // 🎷 Violet DECISION-POINT GUARD warns/informs where a choice is MADE — the profile-blindness honesty
        // (Chroma F6) surfaced BEFORE the deep dashboard cards go dark. Constructed on THIS SAME thread (the
        // EventLoop-thread-affine law above — Chroma F9). ---
        let bset = BeastSettings::new().expect("BeastSettings constructs");

        // (1) A HEALTHY, smart posture: Canonical brain + CoBALT queue + a preset, the resolved tunables pushed.
        // The plain-words decoders read the host-pushed applied profile (BeastSnapshot.yeah_profile/.cake_profile).
        bset.set_yeah_profile(1); // Canonical
        bset.set_cake_profile(1); // CoBALT
        bset.set_preset(1); // FAST_PING
        bset.set_cycle_ms(2000);
        bset.set_max_window(16);
        bset.set_free_thresh_milli(1200);
        bset.set_compete_thresh_milli(1500);
        bset.set_cwnd(8);
        bset.set_mode("YEAH".into());
        bset.set_base_rtt_ms(24.0);
        assert_eq!(bset.get_yeah_profile_label().as_str(), "CANONICAL");
        assert_eq!(bset.get_cake_profile_label().as_str(), "SOFT-CAKE");
        assert_eq!(bset.get_preset_label().as_str(), "FAST PING");
        assert!(
            bset.get_posture_line().as_str().contains("CANONICAL brain"),
            "the plain-words posture line reflects the applied tune: {}",
            bset.get_posture_line()
        );
        // The smart posture raises NO actionable warning AND no profile-dark note (both deep views are live).
        assert!(
            !bset.get_warn_any(),
            "a Canonical+CoBALT posture raises NO actionable decision-point warning"
        );
        assert!(
            !bset.get_note_legacy_cake_dark(),
            "CoBALT does NOT dark the AQM cards"
        );
        assert!(
            !bset.get_note_legacy_yeah_dark(),
            "Canonical does NOT dark the YeAH telemetry"
        );
        assert!(!bset.get_note_any());

        // (2) 🎷 LEGACY QUEUE (F6 honesty) — picking the Legacy AQM informs the user its CoBALT valve cards will
        // read 0 at the moment of the choice (not left to puzzle over a dashboard of zeros). CoBALT clears it.
        bset.set_cake_profile(0); // Legacy AQM
        assert!(
            bset.get_note_legacy_cake_dark(),
            "the Legacy AQM MUST inform the CoBALT cards will be dark (F6, at the decision point)"
        );
        assert_eq!(bset.get_cake_profile_label().as_str(), "LEGACY-AQM");
        assert!(bset.get_note_any());
        bset.set_cake_profile(1);
        assert!(!bset.get_note_legacy_cake_dark());

        // (3) 🎷 LEGACY BRAIN (F6 honesty) — the Legacy YeAH brain informs the canonical telemetry cards will
        // stay 0. Canonical clears it; the label decodes.
        bset.set_yeah_profile(0); // Legacy
        assert!(
            bset.get_note_legacy_yeah_dark(),
            "the Legacy brain MUST inform the canonical telemetry will be dark (F6, at the decision point)"
        );
        assert_eq!(bset.get_yeah_profile_label().as_str(), "LEGACY");
        bset.set_yeah_profile(1);
        assert!(!bset.get_note_legacy_yeah_dark());

        // (4) 🎷 LINE-RATE CAUTION — the aggressive brain informs it can over-probe a lossy/mobile link.
        bset.set_yeah_profile(2); // LineRate
        assert!(
            bset.get_note_linerate_aggressive(),
            "the Line-rate brain MUST surface the over-probe caution"
        );
        assert_eq!(bset.get_yeah_profile_label().as_str(), "LINE-RATE");
        bset.set_yeah_profile(1); // restore Canonical

        // (5) 🎷 STAGED (dirty) — a pending profile/preset change informs the user Apply rebuilds the Beast
        // (reseeding cwnd + RTT). It is a soft note, NOT an actionable warning (warn-any stays clear).
        bset.set_profile_dirty(true);
        assert!(bset.get_note_profile_dirty());
        assert!(bset.get_note_any());
        assert!(
            !bset.get_warn_any(),
            "a staged (dirty) change is a soft note, not a misconfiguration warning"
        );
        bset.set_profile_dirty(false);
        assert!(!bset.get_note_profile_dirty());

        // (6) 🎷 CLAMPED (the ONE actionable warning) — an Expert value outside the safe range that beast_clamp
        // coerced MUST warn (your input did not stick) — never a silent coercion. Clearing it clears warn-any.
        bset.set_tunable_clamped(true);
        assert!(
            bset.get_warn_tunable_clamped(),
            "a coerced Expert value MUST warn (the non-silent clamp)"
        );
        assert!(bset.get_warn_any());
        bset.set_tunable_clamped(false);
        assert!(!bset.get_warn_tunable_clamped());

        // (7) All picks sane again → every actionable warning clears; the guard is honest, not a stuck alarm.
        assert!(!bset.get_warn_any());
        // (8) The preset label decodes each ordinal (the plain-language pick over the raw enum name).
        bset.set_preset(0);
        assert_eq!(bset.get_preset_label().as_str(), "DEFAULT");
        bset.set_preset(2);
        assert_eq!(bset.get_preset_label().as_str(), "OMEGA BANDWIDTH");
        bset.set_preset(3);
        assert_eq!(bset.get_preset_label().as_str(), "UPLOAD/DOWNLOAD");

        // --- rotation.slint (the Rotation pillar, slice 8): THE ORBITAL-WHEEL dashboard binds + hunts the
        // rotation faults (STALLED / DIAL FAULT) + surfaces the #98 warm-resume crown. Constructed on THIS
        // SAME thread (the EventLoop-thread-affine law above — Chroma F9). ---
        let rot = RotationDashboard::new().expect("RotationDashboard constructs");

        // (1) Host pushes a HEALTHY warm-resumed RotationSnapshot-shaped posture (the #98 crown: a rebooted
        // phone kept its schedule) + the ring / warm-RTT / query-rotation.log feeds bind end-to-end through
        // the generated structs (RotationFamilyRow + RotationHintRow + RotationLogRow).
        rot.set_configured(true);
        rot.set_rotation_family("cloudflare".into());
        rot.set_cadence_secs(1800); // 30 min — the live default cadence
        rot.set_rotation_index(7);
        rot.set_next_flip_secs(600); // the host-computed live countdown
        rot.set_rehydrated_warm(true);
        let ring = ModelRc::new(VecModel::from(vec![
            RotationFamilyRow {
                name: "cloudflare".into(),
            },
            RotationFamilyRow {
                name: "quad9".into(),
            },
            RotationFamilyRow {
                name: "google".into(),
            },
        ]));
        rot.set_families(ring);
        assert_eq!(
            rot.get_families().row_count(),
            3,
            "the RotationFamilyRow wheel-ring model binds through the generated struct"
        );
        let hints = ModelRc::new(VecModel::from(vec![
            RotationHintRow {
                id: "cloudflare-doh".into(),
                rtt: "12ms".into(),
                ms: 12,
            },
            RotationHintRow {
                id: "quad9-doh".into(),
                rtt: "18ms".into(),
                ms: 18,
            },
        ]));
        rot.set_rtt_hints(hints);
        assert_eq!(
            rot.get_rtt_hints().row_count(),
            2,
            "the RotationHintRow warm-RTT leaderboard model binds through the generated struct"
        );
        let rotlog = ModelRc::new(VecModel::from(vec![
            RotationLogRow {
                event: "switch".into(),
                family: "cloudflare".into(),
                idx: 7,
                at: "12:41:02".into(),
                servers: "cloudflare · quad9-doh".into(),
                relays: "anon-cs-berlin".into(),
            },
            RotationLogRow {
                event: "warm".into(),
                family: "quad9".into(),
                idx: 6,
                at: "12:11:40".into(),
                servers: "".into(),
                relays: "".into(),
            },
        ]));
        rot.set_recent_rotations(rotlog);
        assert_eq!(
            rot.get_recent_rotations().row_count(),
            2,
            "the RotationLogRow query-rotation.log feed model binds through the generated struct"
        );

        // A healthy turning wheel: rotating, warm-resumed, NO rotation fault, crown ROTATING.
        assert!(rot.get_rotating());
        assert!(
            rot.get_warm_resume(),
            "rehydrated_warm MUST surface the #98 warm-resume crown (resumed, not cold at family 0)"
        );
        assert!(!rot.get_cold_start());
        assert!(
            !rot.get_hidden_fault_any(),
            "a healthy turning wheel surfaces NO rotation fault"
        );
        assert_eq!(rot.get_crown_headline().as_str(), "ROTATING");
        // The cadence label decodes the host-pushed cadence seconds into plain words (the felt-truth).
        assert!(
            rot.get_cadence_label().as_str().contains("30")
                && rot.get_cadence_label().as_str().contains("min"),
            "the cadence label decodes 1800s -> 30 min: {}",
            rot.get_cadence_label()
        );

        // (2) 🩸 STALLED — the next flip is OVERDUE (next_flip_secs<0): the timer is starved, the wheel frozen.
        rot.set_next_flip_secs(-30);
        assert!(
            rot.get_stalled(),
            "next_flip_secs<0 MUST surface STALLED (the overdue/frozen wheel)"
        );
        assert_eq!(rot.get_crown_headline().as_str(), "STALLED");
        assert!(rot.get_hidden_fault_any());
        rot.set_next_flip_secs(600); // restore
        assert!(!rot.get_stalled());

        // (3) 🩸 DIAL FAULT — the countdown exceeds the whole cadence window (a miscomputed next-flip clock).
        rot.set_next_flip_secs(9999); // > cadence 1800
        assert!(
            rot.get_dial_anomaly(),
            "next_flip_secs>cadence_secs MUST surface the DIAL FAULT (the untrustworthy dial)"
        );
        assert_eq!(rot.get_crown_headline().as_str(), "DIAL FAULT");
        rot.set_next_flip_secs(600); // restore
        assert!(!rot.get_dial_anomaly());

        // (4) PINNED — cadence 0 = rotation disabled / a manual family pin (a chosen state, NOT a fault).
        rot.set_cadence_secs(0);
        assert!(rot.get_pinned());
        assert!(!rot.get_rotating());
        assert!(
            !rot.get_hidden_fault_any(),
            "a pinned wheel is a chosen state, not a fault"
        );
        assert_eq!(rot.get_crown_headline().as_str(), "PINNED");
        rot.set_cadence_secs(1800); // restore

        // (5) COLD START — no durable record resumed (rehydrated_warm==false): the anti-#98 posture, honest.
        rot.set_rehydrated_warm(false);
        assert!(
            rot.get_cold_start(),
            "configured + !rehydrated_warm MUST surface the cold-start posture"
        );
        assert!(!rot.get_warm_resume());
        rot.set_rehydrated_warm(true); // restore

        // (6) 🩸 COLD LEADERBOARD (honest empty) — the wheel is turning but the warm-RTT feed is inert. It is an
        // honesty state, not an actionable fault (the alert stack notes it; the crown stays ROTATING).
        let empty = ModelRc::new(VecModel::from(Vec::<RotationHintRow>::new()));
        rot.set_rtt_hints(empty);
        assert!(
            rot.get_cold_leaderboard(),
            "rotating + empty warm-RTT hints MUST surface the honest cold-leaderboard state"
        );
        assert!(!rot.get_hidden_fault_any());
        assert_eq!(rot.get_crown_headline().as_str(), "ROTATING");

        // (7) DORMANT — the rotation pillar is not armed → the crown reads DORMANT, no fault raised.
        rot.set_configured(false);
        assert!(!rot.get_rotating());
        assert!(
            !rot.get_stalled(),
            "an unconfigured pillar is DORMANT, not stalled"
        );
        assert!(!rot.get_hidden_fault_any());
        assert_eq!(rot.get_crown_headline().as_str(), "DORMANT");

        // --- rotation_settings.slint (the Rotation pillar, slice 9): THE ||| ROTATION SETTINGS surface binds +
        // the 🎷 decision-point guard warns WHERE a counterproductive choice is MADE (the settings-time twin of
        // the dashboard's fault hunt). Constructed on THIS SAME thread (the EventLoop-thread-affine law above —
        // Chroma F9). The three controls' callbacks are HOST/Kotlin-owned (the NO-FORK consensus). ---
        let rset = RotationSettings::new().expect("RotationSettings constructs");

        // (1) A HEALTHY, armed, rotating posture: family set, 30-min cadence, not pinned → NO actionable warning.
        rset.set_configured(true);
        rset.set_rotation_family("cloudflare".into());
        rset.set_rotation_index(7);
        rset.set_cadence_secs(1800); // 30 min — the live default
        rset.set_pinned(false);
        assert!(
            rset.get_rotating(),
            "armed + not pinned + a positive cadence MUST read as a turning wheel"
        );
        assert!(
            !rset.get_warn_any(),
            "a healthy rotating posture raises NO actionable decision-point warning"
        );
        // The cadence label + posture line read the live knobs back in plain words (the feedback-simple-ux felt-truth).
        assert!(
            rset.get_cadence_label().as_str().contains("30")
                && rset.get_cadence_label().as_str().contains("min"),
            "the settings decode 1800s -> 30 min: {}",
            rset.get_cadence_label()
        );
        assert!(
            rset.get_posture_line().as_str().contains("ROTATING")
                && rset.get_posture_line().as_str().contains("cloudflare"),
            "the plain-words posture line reflects the turning wheel + family: {}",
            rset.get_posture_line()
        );
        // Exactly the 30-min preset chip lights for the live cadence (the selector's one-of-N active state).
        assert!(rset.get_preset_default_active());
        assert!(!rset.get_preset_hour_active());

        // (2) 🎷 PIN-TO-NOTHING — pinning the "current family" while there is NO family yet (cold) warns at the
        // pin tap (the settings-time twin of a wheel that holds nothing).
        rset.set_pinned(true);
        rset.set_rotation_family("".into());
        assert!(
            rset.get_warn_pin_cold(),
            "pinning with no family yet MUST warn (pin-to-nothing)"
        );
        assert!(rset.get_warn_any());
        // pinned is a chosen state → the Rotate-Now-inert note fires, but it is informational, not warn-any-raising.
        assert!(rset.get_note_rotate_inert_pinned());
        assert_eq!(rset.get_cadence_label().as_str(), "pinned");
        // Landing a family clears the pin-cold danger; the pin itself stays a chosen (informational) state.
        rset.set_rotation_family("quad9".into());
        assert!(!rset.get_warn_pin_cold());
        assert!(
            !rset.get_warn_any(),
            "a pin onto a real family is a chosen state, not an actionable misconfiguration"
        );
        rset.set_pinned(false);

        // (3) 🎷 CADENCE CLAMPED — a sub-5-min cadence is below the host floor and will be silently coerced; warn
        // (the non-silent clamp — your value will not stick, never a mute coercion).
        rset.set_cadence_secs(120);
        assert!(
            rset.get_warn_cadence_clamped(),
            "a sub-5-min cadence MUST warn (the host will clamp it to the 5-min floor)"
        );
        assert!(rset.get_warn_any());
        rset.set_cadence_secs(1800);
        assert!(!rset.get_warn_cadence_clamped());

        // (4) All knobs sane again → every actionable warning clears; the guard is honest, not a stuck alarm.
        assert!(!rset.get_warn_any());
        // (5) DORMANT — the engine is not armed → the soft stage-and-apply note fires (NOT an actionable alarm).
        rset.set_configured(false);
        assert!(rset.get_note_dormant());
        assert!(!rset.get_rotating());
        assert!(
            !rset.get_warn_any(),
            "the dormant note is a soft stage-and-apply notice, not a misconfiguration alarm"
        );

        // --- inu.slint (the Wire Cake Inu pillar, slice 8): THE COLLAR-MEDALLION dashboard binds + hunts the
        // silent elevation faults (GHOST GRANT / PAIR LOST / NO PROVIDER / DRIFT UNGUARDED) + surfaces the
        // one-glance crown verdict. Constructed on THIS SAME thread (the EventLoop-thread-affine law above —
        // Chroma F9). Renders an `InuState` (the DurableTier RAM⊗NAND Record) the host pushes. ---
        let inu = InuDashboard::new().expect("InuDashboard constructs");

        // (1) Host pushes a HEALTHY ELEVATED posture (paired over loopback Self-ADB, 2 powers held, boot-safe)
        // + the per-power grant map (PowerRow) + the query-inu.log feed (InuLogRow) bind end-to-end.
        inu.set_configured(true);
        inu.set_elevation_status(2); // ELEVATED
        inu.set_active_provider(2); // SELF-ADB (our own no-root loopback path — no companion app)
        inu.set_paired(true);
        inu.set_paired_label("paired 3d ago".into());
        inu.set_powers_held(2);
        inu.set_powers_total(3);
        inu.set_drift_prone_held(0);
        inu.set_boot_reapply_armed(true);
        let prows = ModelRc::new(VecModel::from(vec![
            PowerRow {
                id: "battery-unrestricted".into(),
                label: "Ignore battery limits".into(),
                tier: "basic".into(),
                held: true,
                drift_prone: false,
            },
            PowerRow {
                id: "usage-stats".into(),
                label: "See app usage".into(),
                tier: "standard".into(),
                held: true,
                drift_prone: false,
            },
            PowerRow {
                id: "write-secure-settings".into(),
                label: "Tune secure settings".into(),
                tier: "deep".into(),
                held: false,
                drift_prone: true,
            },
        ]));
        inu.set_powers(prows);
        assert_eq!(
            inu.get_powers().row_count(),
            3,
            "the PowerRow grant-map model binds through the generated struct"
        );
        let ilog = ModelRc::new(VecModel::from(vec![
            InuLogRow {
                event: "pair".into(),
                detail: "paired over loopback self-ADB".into(),
                ok: true,
            },
            InuLogRow {
                event: "grant".into(),
                detail: "battery-unrestricted -> held".into(),
                ok: true,
            },
        ]));
        inu.set_recent_events(ilog);
        assert_eq!(
            inu.get_recent_events().row_count(),
            2,
            "the InuLogRow query-inu.log feed model binds through the generated struct"
        );

        // A healthy elevated hound: elevated, NO elevation fault, crown ELEVATED, plain-words path + mood decode.
        assert!(inu.get_elevated());
        assert!(
            !inu.get_hidden_fault_any(),
            "a paired, elevated, boot-safe hound surfaces NO elevation fault"
        );
        assert_eq!(inu.get_crown_headline().as_str(), "ELEVATED");
        assert_eq!(
            inu.get_provider_label().as_str(),
            "Self-ADB",
            "the active-provider enum decodes to plain words (feedback-simple-ux)"
        );
        assert_eq!(inu.get_status_label().as_str(), "elevated");
        assert!(
            inu.get_provider_how().as_str().contains("loopback"),
            "the felt-truth path line names the no-companion loopback reach: {}",
            inu.get_provider_how()
        );
        assert!(
            inu.get_crown_mood().as_str().contains("good dog"),
            "the playful mood line is friendly, never intimidating: {}",
            inu.get_crown_mood()
        );

        // (2) 🩸 GHOST GRANT — powers still marked held, but elevation dropped to RESTING: orphaned state,
        // nothing is actually enforced (the Chroma F10 silent killer). The crown flips to the breach verdict.
        inu.set_elevation_status(0); // RESTING while powers-held stays 2
        assert!(
            inu.get_ghost_grant(),
            "powers held but NOT elevated MUST surface GHOST GRANT (orphaned enforcement, F10)"
        );
        assert!(inu.get_hidden_fault_any());
        assert_eq!(inu.get_crown_headline().as_str(), "GHOST GRANT");
        inu.set_elevation_status(2); // restore ELEVATED
        assert!(!inu.get_ghost_grant());

        // (3) 🩸 PAIR LOST — paired, but the live provider dropped to none: the privileged channel died and
        // must flip honest (the Shizuku linkToDeath discipline — never lie that a dead session is alive).
        inu.set_active_provider(0);
        assert!(
            inu.get_pair_lost(),
            "paired + no active provider MUST surface PAIR LOST (the dead channel; linkToDeath honesty)"
        );
        assert_eq!(inu.get_crown_headline().as_str(), "PAIR LOST");
        assert!(inu.get_hidden_fault_any());
        inu.set_active_provider(2); // restore Self-ADB
        assert!(!inu.get_pair_lost());

        // (4) 🩸 NO PROVIDER — armed (fetching) but no provider active AND not paired (so it is NOT a pair-lost):
        // the ElevationManager is inert (its provider set empty until the two providers are wired — F17).
        inu.set_paired(false);
        inu.set_elevation_status(1); // FETCHING
        inu.set_active_provider(0);
        assert!(
            inu.get_no_provider(),
            "fetching + no provider MUST surface NO PROVIDER (the inert ElevationManager, F17)"
        );
        assert!(
            !inu.get_pair_lost(),
            "not paired -> it is a no-provider, not a pair-lost"
        );
        assert!(inu.get_hidden_fault_any());
        inu.set_paired(true); // restore
        inu.set_elevation_status(2);
        inu.set_active_provider(2);
        assert!(!inu.get_no_provider());

        // (5) 🩸 DRIFT UNGUARDED — a drift-prone power is held but boot-reapply is OFF: it silently vanishes on
        // the next reboot (the Shizuku always-availability gap — no live BootComplete branch yet).
        inu.set_drift_prone_held(1);
        inu.set_boot_reapply_armed(false);
        assert!(
            inu.get_drift_unguarded(),
            "drift-prone held + boot-reapply off MUST surface DRIFT UNGUARDED (vanishes on reboot)"
        );
        assert!(inu.get_hidden_fault_any());
        inu.set_boot_reapply_armed(true); // restore
        inu.set_drift_prone_held(0);
        assert!(!inu.get_drift_unguarded());

        // (6) DEMO STUB — the active provider is the honest isImplemented=false placeholder: informational, NOT
        // an actionable fault (excluded from hidden-fault-any); the crown reads DEMO STUB.
        inu.set_active_provider(3);
        assert!(inu.get_stub_active());
        assert!(
            inu.get_stub_inert(),
            "the demo stub surfaces the informational STUB note"
        );
        assert!(
            !inu.get_hidden_fault_any(),
            "the STUB note is informational, not an actionable elevation fault"
        );
        assert_eq!(inu.get_crown_headline().as_str(), "DEMO STUB");
        assert_eq!(inu.get_provider_label().as_str(), "demo stub");
        inu.set_active_provider(2); // restore

        // (7) OFF — the pillar is not armed AND nothing is held: the hound is asleep, no fault, crown OFF.
        inu.set_configured(false);
        inu.set_powers_held(0);
        inu.set_elevation_status(0);
        inu.set_drift_prone_held(0);
        assert!(
            !inu.get_hidden_fault_any(),
            "an unconfigured hound with nothing held surfaces NO fault (asleep, not broken)"
        );
        assert_eq!(inu.get_crown_headline().as_str(), "OFF");

        // --- inu_settings.slint (the Wire Cake Inu pillar, slice 9): THE ||| INU SETTINGS surface binds + the
        // 🎷 decision-point guard warns WHERE a counterproductive choice is MADE (the settings-time twin of the
        // dashboard's fault hunt). Constructed on THIS SAME thread (the EventLoop-thread-affine law above —
        // Chroma F9). The edit callbacks are HOST/Kotlin-owned (one-way flow to the live elevation engine). ---
        let iset = InuSettings::new().expect("InuSettings constructs");

        // (1) A HEALTHY, paired, boot-armed posture: 2 powers desired, none drift-at-risk → NO actionable warning.
        iset.set_configured(true);
        iset.set_paired(true);
        iset.set_paired_label("paired 3d ago".into());
        iset.set_active_provider(2);
        iset.set_elevation_status(2);
        iset.set_boot_reapply_armed(true);
        iset.set_provider_pref(0); // Auto
        iset.set_powers_held(2);
        iset.set_desired_count(2);
        iset.set_drift_desired_count(0);
        let ptr = ModelRc::new(VecModel::from(vec![
            PowerToggleRow {
                id: "battery-unrestricted".into(),
                label: "Ignore battery limits".into(),
                hint: "let the engine keep running in Doze".into(),
                tier: "basic".into(),
                desired: true,
                held: true,
                drift_prone: false,
            },
            PowerToggleRow {
                id: "write-secure-settings".into(),
                label: "Tune secure settings".into(),
                hint: "private-DNS + advanced knobs".into(),
                tier: "deep".into(),
                desired: false,
                held: false,
                drift_prone: true,
            },
        ]));
        iset.set_powers(ptr);
        assert_eq!(
            iset.get_powers().row_count(),
            2,
            "the PowerToggleRow model binds through the generated struct"
        );
        assert!(
            !iset.get_warn_any(),
            "a paired, boot-armed posture raises NO actionable decision-point warning"
        );
        assert!(
            iset.get_note_unpair_held(),
            "paired + powers held surfaces the informational unpair-orphans note"
        );
        assert!(
            iset.get_posture_line().as_str().contains("PAIRED"),
            "the plain-words posture line reflects the paired state: {}",
            iset.get_posture_line()
        );
        assert_eq!(
            iset.get_provider_pref_label().as_str(),
            "Auto (best available)"
        );

        // (2) 🎷 PROTECT WITHOUT PAIR — powers wanted protected while not paired: nothing takes effect. Warn at
        // the choice, not after silence.
        iset.set_paired(false);
        assert!(
            iset.get_warn_grant_no_pair(),
            "wanting powers protected while not paired MUST warn (it won't take effect)"
        );
        assert!(iset.get_warn_any());
        iset.set_paired(true); // restore
        assert!(!iset.get_warn_grant_no_pair());

        // (3) 🎷 WON'T SURVIVE REBOOT — a drift-prone power is wanted protected but boot re-apply is OFF: warn
        // where "Keep after reboot" is the fix.
        iset.set_drift_desired_count(1);
        iset.set_boot_reapply_armed(false);
        assert!(
            iset.get_warn_drift_no_boot(),
            "a drift-prone protected power with boot-reapply off MUST warn (vanishes on reboot)"
        );
        assert!(iset.get_warn_any());
        iset.set_boot_reapply_armed(true); // restore
        iset.set_drift_desired_count(0);
        assert!(!iset.get_warn_drift_no_boot());

        // (4) DEMO STUB (informational) — the active path is a placeholder; nothing truly elevates. Not a warn.
        iset.set_active_provider(3);
        assert!(iset.get_note_stub_active());
        assert!(
            !iset.get_warn_any(),
            "the stub note is informational, not an actionable warning"
        );
        assert_eq!(iset.get_active_provider_label().as_str(), "demo stub");
        iset.set_active_provider(2); // restore

        // (5) The elevation-path preference decodes to plain words (never a raw enum — feedback-simple-ux).
        iset.set_provider_pref(1);
        assert_eq!(iset.get_provider_pref_label().as_str(), "Shizuku");
        iset.set_provider_pref(2);
        assert_eq!(iset.get_provider_pref_label().as_str(), "Self-ADB");
        iset.set_provider_pref(0);

        // (6) DORMANT — the engine is not armed → the soft stage-and-apply note fires (NOT an actionable alarm).
        iset.set_configured(false);
        assert!(iset.get_note_dormant());
        assert!(
            !iset.get_warn_any(),
            "the dormant note is a soft stage-and-apply notice, not a misconfiguration alarm"
        );

        // --- advanced_burger.slint (OMEGA Stage-D · D2, step 7): THE ||| ADVANCED HAMBURGER — the SLINT
        // navigation surface binds. ONE Window carries the NavState routing pair, the per-pillar PRIVATE
        // TABS (typed PillarTabRow model + routed open intents), and the TWO EMBEDDED sections — the
        // overhauled DNSCRYPT section (K5) + the GENERAL section — reachable through the root's forwarding
        // aliases. Constructed on THIS SAME thread (the EventLoop-thread-affine law above). ---
        let burger = AdvancedBurger::new().expect("AdvancedBurger constructs");

        // (1) The NavState routing truth is typed state the host reads + drives.
        assert_eq!(
            burger.get_active_section().as_str(),
            "pillars",
            "the burger lands on the private tabs"
        );
        assert!(burger.get_drawer_open(), "the ||| rail starts open");
        burger.set_active_section("dnscrypt".into());
        assert_eq!(burger.get_active_section().as_str(), "dnscrypt");
        burger.set_active_section("general".into());
        assert_eq!(burger.get_active_section().as_str(), "general");
        burger.set_active_section("pillars".into());

        // (2) The per-pillar private tabs: a typed PillarTabRow model binds through the generated struct,
        // and the DASHBOARD/SETTINGS chips' intents round-trip as typed callbacks (the host routes them to
        // the pillar Windows until the Design-Finale G2 pane refactor embeds them).
        burger.set_pillar_tabs(ModelRc::new(VecModel::from(vec![
            PillarTabRow {
                id: "warden".into(),
                name: "WARDEN".into(),
                blurb: "the per-app firewall courtroom".into(),
                status: "allow 3 · deny 57".into(),
                live: true,
                accent: slint::Color::from_rgb_u8(0xd8, 0x3a, 0x2c),
            },
            PillarTabRow {
                id: "centauri".into(),
                name: "CENTAURI".into(),
                blurb: "the offline-CDN constellation".into(),
                status: "libraries=0 bytes=0 full=false".into(),
                live: true,
                accent: slint::Color::from_rgb_u8(0x28, 0xc8, 0xd8),
            },
        ])));
        assert_eq!(
            burger.get_pillar_tabs().row_count(),
            2,
            "the PillarTabRow model binds through the generated struct"
        );
        let opened = std::rc::Rc::new(std::cell::RefCell::new(String::new()));
        {
            let sink = opened.clone();
            burger.on_open_pillar_dashboard(move |id| {
                *sink.borrow_mut() = format!("dash:{id}");
            });
        }
        {
            let sink = opened.clone();
            burger.on_open_pillar_settings(move |id| {
                *sink.borrow_mut() = format!("settings:{id}");
            });
        }
        burger.invoke_open_pillar_dashboard("centauri".into());
        assert_eq!(
            opened.borrow().as_str(),
            "dash:centauri",
            "the dashboard intent routes with its pillar id"
        );
        burger.invoke_open_pillar_settings("warden".into());
        assert_eq!(
            opened.borrow().as_str(),
            "settings:warden",
            "the settings intent routes with its pillar id"
        );

        // (3) The EMBEDDED overhauled DNSCRYPT section (K5), fed from the REAL typed authority — the same
        // `dnscrypt_config_get()` Record the Kotlin surface owns; the upstream defaults render through the
        // root's forwarding aliases (never a mock shape).
        let cfg = torta_core::dnscrypt_config_get();
        burger.set_require_nolog(cfg.require_nolog);
        burger.set_require_nofilter(cfg.require_nofilter);
        burger.set_doh_servers(cfg.doh_servers);
        burger.set_dnscrypt_servers(cfg.dnscrypt_servers);
        burger.set_timeout_ms(cfg.timeout);
        burger.set_cache_on(cfg.cache);
        burger.set_cache_size(cfg.cache_size);
        burger.set_server_names_count(cfg.server_names.len() as i32);
        assert!(
            burger.get_require_nolog(),
            "the upstream default require_nolog=true renders through the alias"
        );
        assert!(
            burger.get_pool_summary().as_str().contains("auto-pick"),
            "an empty server_names decodes to the plain-words auto-pick line: {}",
            burger.get_pool_summary()
        );

        // (4) 🎷 The DNSCrypt decision-point guards fire where the pool-killing choice is made.
        burger.set_dnscrypt_servers(false);
        burger.set_doh_servers(false);
        burger.set_odoh_servers(false);
        assert!(
            burger.get_warn_no_server_type(),
            "every server type OFF MUST surface POOL DARK at the decision point"
        );
        assert!(burger.get_warn_any());
        burger.set_doh_servers(true);
        assert!(!burger.get_warn_no_server_type());
        burger.set_ipv4_servers(false);
        burger.set_ipv6_servers(false);
        assert!(
            burger.get_warn_no_ip_family(),
            "no IP family left MUST surface POOL DARK"
        );
        burger.set_ipv4_servers(true);
        assert!(!burger.get_warn_no_ip_family());
        burger.set_proxy_enabled(true);
        burger.set_force_tcp(false);
        assert!(
            burger.get_warn_proxy_no_tcp(),
            "SOCKS without force-TCP MUST warn (UDP exchanges silently fail)"
        );
        burger.set_force_tcp(true);
        assert!(!burger.get_warn_proxy_no_tcp());
        burger.set_proxy_enabled(false);
        burger.set_force_tcp(false);
        burger.set_dns64_on(true);
        burger.set_dns64_prefix("".into());
        assert!(
            burger.get_warn_dns64_no_prefix(),
            "DNS64 armed with no prefix MUST warn (dns64.prefix empty = inert)"
        );
        burger.set_dns64_prefix("64:ff9b::/96".into());
        assert!(!burger.get_warn_dns64_no_prefix());
        burger.set_dns64_on(false);
        burger.set_require_dnssec(true);
        assert!(
            burger.get_note_strict_filters(),
            "all three requirement filters together surface the pool-shrink note"
        );
        burger.set_require_dnssec(false);
        assert!(
            !burger.get_warn_any(),
            "the healthy posture raises no banner"
        );

        // (5) The EMBEDDED GENERAL section — the retired-general-settings home: the felt-truth preview
        // flag defaults FALSE (preview values never read as live), the guards fire, the preset decodes.
        assert!(
            !burger.get_general_host_live(),
            "host-live defaults FALSE — the pane says PREVIEW until a host pushes real pref state"
        );
        burger.set_rotation_on(false);
        burger.set_solver_on(false);
        burger.set_warden_on(false);
        assert!(
            burger.get_warn_all_pillars_off(),
            "every helper pillar OFF MUST surface the unguarded-tunnel warning"
        );
        burger.set_warden_on(true);
        assert!(!burger.get_warn_all_pillars_off());
        assert!(
            burger.get_note_boot_off(),
            "autostart OFF notes the won't-survive-reboot sibling"
        );
        burger.set_boot_autostart_on(true);
        assert!(!burger.get_note_boot_off());
        assert_eq!(burger.get_preset_label().as_str(), "CUSTOM");
        burger.set_preset_active(1);
        assert_eq!(
            burger.get_preset_label().as_str(),
            "PRIVACY",
            "the preset id decodes to plain words"
        );
        let general = std::rc::Rc::new(std::cell::RefCell::new(String::new()));
        {
            let sink = general.clone();
            burger.on_pillar_toggled(move |key, on| {
                *sink.borrow_mut() = format!("{key}={on}");
            });
        }
        burger.invoke_pillar_toggled("rebind".into(), false);
        assert_eq!(
            general.borrow().as_str(),
            "rebind=false",
            "the general pillar toggle intent carries its typed key+value"
        );
        } // fn run() — the big-stack body (see the #61D FOUND-LATENT note at the top)
    }

    /// The live torta_core warden surface is reachable from the UI crate AND carries the slice-1 REWORKED
    /// per-tier attribution shape (`deny_by_app` / `deny_by_blocklist`) — a real engine read, never faked.
    /// Backend-FREE (constructs NO slint Window), so it runs safely on its own libtest thread alongside the
    /// sole slint-constructing test above — the dashboard renders exactly this live shape.
    #[test]
    fn warden_engine_surface_reachable_from_ui_crate() {
        let stats = torta_core::warden_stats().expect("warden_stats resolves from the UI crate");
        assert!(
            stats.contains("deny_by_app"),
            "live per-tier (TIER 3) attribution shape: {stats}"
        );
        assert!(
            stats.contains("deny_by_blocklist"),
            "live per-tier (TIER 5) attribution shape: {stats}"
        );
    }

    /// The live torta_core CENTAURI offline-CDN surface is reachable from the UI crate (the `mirror` feature is
    /// enabled on the torta_core dep) — a REAL engine read, never faked (centauri-pillar). `mirror_status()`
    /// returns the content-addressed cache's well-defined zero baseline before start (`libraries=0 bytes=0
    /// full=false`); `centauri_cdn_hosts()` returns the static cloaked-CDN watch-list the dashboard renders +
    /// the DNS plane sinkholes to 127.0.0.1. Backend-FREE (constructs NO slint Window), so it runs safely on its
    /// own libtest thread alongside the sole slint-constructing test above — the dashboard renders this shape.
    #[test]
    fn centauri_engine_surface_reachable_from_ui_crate() {
        // The CROWN cache stats — REAL numbers (the empty zero baseline before any catalog/serve), never faked.
        let status = torta_core::mirror_status()
            .expect("mirror_status resolves from the UI crate (the mirror feature is enabled)");
        assert!(
            status.contains("libraries="),
            "live cache-stats shape (the dashboard's libraries/bytes tiles): {status}"
        );
        assert!(
            status.contains("bytes="),
            "live cache-stats shape: {status}"
        );

        // The cloaked CDN-host watch-list — the dashboard's "CLOAKED CDN HOSTS" panel + the DNS-plane sinkhole set.
        let hosts = torta_core::centauri_cdn_hosts();
        assert!(
            !hosts.is_empty(),
            "the cloaked CDN host set is non-empty (the DNS-plane watch-list the dashboard renders)"
        );
    }

    /// The live torta_core MASKSOLVER (Resolver&Cache) surface is reachable from the UI crate — a REAL engine
    /// read, never faked. `resolver_stats()` (lib.rs:1190) is the flat JSON twin of the typed
    /// `MaskSolverSnapshot` the dashboard renders (object.rs: "MaskSolver's snapshot is a SECOND renderer over
    /// the IDENTICAL atomics" — the single-source proof, no engine fork, Chroma F1/F2). Asserting it carries
    /// the SOLVE-cross (`answered` / `solve_ladder_exhausted`) + CACHE-cross (`cache_hits` / `serve_stale_served`)
    /// witnesses proves the 🩸 hidden-fault hunt (SILENT MISS / LADDER STORM / STALE-SERVING) reads a REAL shape.
    /// Backend-FREE (constructs NO slint Window), so it runs safely on its own libtest thread alongside the sole
    /// slint-constructing test above — the MaskSolver dashboard renders exactly this live shape.
    #[test]
    fn masksolver_engine_surface_reachable_from_ui_crate() {
        let stats = torta_core::resolver_stats()
            .expect("resolver_stats resolves from the UI crate (the snapshot twin)");
        // The SOLVE-cross witnesses (the FlareSolver cross) the crown + the SOLVE tiles + the hunt read.
        assert!(
            stats.contains("answered"),
            "live solve-success witness shape (the crown GOT-THROUGH + SILENT-MISS hunt): {stats}"
        );
        assert!(
            stats.contains("solve_ladder_exhausted"),
            "live SOLVE-cross resilience witness (the LADDER STORM hunt): {stats}"
        );
        // The CACHE-cross witnesses (the dnsmasq cross on RAM⊗NAND) the cache tiles + the STALE-SERVING hunt read.
        assert!(
            stats.contains("cache_hits"),
            "live cache-hit witness shape (the cache tiles): {stats}"
        );
        assert!(
            stats.contains("serve_stale_served"),
            "live serve-stale witness (the STALE-SERVING hunt): {stats}"
        );
        // The resolution-safety witnesses (the P12 rebind guard) the GUARD tiles + the REBIND LEAK hunt read.
        assert!(
            stats.contains("rebind_observed") && stats.contains("rebind_rejected"),
            "live rebind guard witnesses (the REBIND LEAK hunt): {stats}"
        );
    }

    /// The live torta_core K5 DNSCRYPT-CONFIG authority is reachable from the UI crate — a REAL typed
    /// read, never faked (OMEGA D2, the ||| Advanced DNSCrypt section's feed). `dnscrypt_config_get()`
    /// returns the triple-duty `DnscryptProxyConfig` Record whose upstream defaults the section renders,
    /// and the compatibility TOML round-trips through the ONE serde/toml brain
    /// (`dnscrypt_config_to_toml` → `dnscrypt_config_import_or_default` — the exact pair the on-device
    /// burger feed and the Kotlin surface use). Backend-FREE (constructs NO slint Window), so it runs
    /// safely on its own libtest thread alongside the sole slint-constructing test above.
    #[test]
    fn dnscrypt_config_engine_surface_reachable_from_ui_crate() {
        let cfg = torta_core::dnscrypt_config_get();
        // The upstream defaults the section's requirement/type cards render (B3 — never type-zeros).
        assert!(
            cfg.require_nolog,
            "upstream default require_nolog=true (the requirements card)"
        );
        assert!(
            cfg.require_nofilter,
            "upstream default require_nofilter=true"
        );
        assert!(
            cfg.dnscrypt_servers && cfg.doh_servers,
            "both core server types default ON (the server-types card)"
        );
        assert_eq!(
            cfg.timeout, 5000,
            "the upstream query-deadline default the cache row cites"
        );
        assert!(cfg.cache, "the answer cache defaults ON");
        assert!(
            !cfg.bootstrap_resolvers.is_empty(),
            "bootstrap resolvers default non-empty (the transport card)"
        );

        // The compatibility view round-trips through the ONE config brain — what the section applies is
        // exactly what a re-import reads back (no second codec anywhere).
        let toml = torta_core::dnscrypt_config_to_toml(cfg.clone())
            .expect("the typed authority serializes to the compatibility TOML");
        let back = torta_core::dnscrypt_config_import_or_default(toml);
        assert_eq!(back.require_nolog, cfg.require_nolog);
        assert_eq!(back.timeout, cfg.timeout);
        assert_eq!(back.cache_size, cfg.cache_size);
        assert_eq!(back.bootstrap_resolvers, cfg.bootstrap_resolvers);
    }

    /// The Design-Finale TYPED feeds are reachable from the UI crate (OMEGA D3 — the two additive
    /// torta_core `pub use` path aliases): ② ENGINE constructs a REAL `Beast` (Canonical × CoBALT,
    /// the shipped default pair) and reads its typed `BeastSnapshot` — a cold Object ⇒ the honest
    /// zero-flow baseline with the REAL construction-time profiles echoed back (the F6 gates the
    /// tab derives from); ① HOME reads a `MaskSolver` cold handle's typed `MaskSolverSnapshot`
    /// (the process-global atomics — zeros here, never fabricated traffic). Backend-FREE
    /// (constructs NO slint Window), so it runs safely on its own libtest thread.
    #[test]
    fn design_finale_typed_feeds_reachable_from_ui_crate() {
        // ② The ENGINE tab's read — the typed BeastSnapshot off a real cold Object.
        let beast = torta_core::Beast::new(
            torta_core::YeahProfile::Canonical,
            torta_core::TortaProfile::Baseline,
        );
        let s = beast.snapshot();
        assert!(
            matches!(s.yeah_profile, torta_core::YeahProfile::Canonical),
            "the construction-time YeAH brain echoes back through the snapshot (the F6 gate's truth)"
        );
        assert!(
            matches!(s.sched_profile, torta_core::TortaProfile::Baseline),
            "the construction-time Tortä queue echoes back through the snapshot"
        );
        assert!(
            s.cwnd >= 1,
            "a fresh window is live, not zeroed: {}",
            s.cwnd
        );
        assert_eq!(
            (s.queue_critical, s.queue_high, s.queue_normal),
            (0, 0, 0),
            "a cold Beast holds honestly EMPTY tins (the zero-flow baseline, never fabricated)"
        );

        // ① The HOME tab's read — the typed MaskSolverSnapshot off the cold global-binding handle.
        let solver = torta_core::MaskSolver::new();
        let snap = solver.snapshot();
        assert!(
            snap.queries >= 0 && snap.answered >= 0 && snap.blocked >= 0,
            "the resolver-ledger counters read as real non-negative counts"
        );
    }

    /// The ④ QUERY tab's log substrate is reachable from the UI crate AND the feed-shaping helpers
    /// are honest (OMEGA D3): `log_stale_secs` returns the `-1` absent sentinel (the tab's
    /// log-present gate — an absent log is "not written yet", never "stale"); an appended event
    /// round-trips through the ONE `log_tier` substrate (`log_append` → `log_tail_recent`, the
    /// same RAM⊗NAND pair Kotlin reaches); and [`feed_shape`] maps sources to the MEASURED Kotlin
    /// path conventions + classifies lines as a display heuristic over the shared
    /// "[ts] pillar event k=v" format. Backend-FREE (constructs NO slint Window).
    #[test]
    fn query_log_surface_and_feed_shape_reachable_from_ui_crate() {
        // The absent-log sentinel (the QUERY tab's log-present gate).
        assert_eq!(
            torta_core::log_stale_secs("definitely-absent-dir/query-nowhere.log".into()),
            -1,
            "an absent log reports the -1 sentinel, never a fake staleness"
        );

        // A real temp log round-trips through the ONE log substrate (append -> tail -> staleness).
        let dir = std::env::temp_dir().join("torta-ui-d3-query-tab-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("query-solver.log").to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&path);
        torta_core::log_append(
            path.clone(),
            "[2026-07-02 12:00:00] solver cache_fill entries=3".into(),
        );
        let tail = torta_core::log_tail_recent(path.clone(), 10).expect("the tail read resolves");
        assert!(
            tail.contains("cache_fill"),
            "the appended event tails back through log_tail_recent: {tail}"
        );
        assert!(
            torta_core::log_stale_secs(path) >= 0,
            "a present log reports a non-negative staleness"
        );

        // The path map mirrors the MEASURED Kotlin conventions (PillarLog.kt:26 + the D40 canon +
        // the D2 cache/query.log toggle paths).
        assert_eq!(
            feed_shape::query_log_path("/data", "dnscrypt"),
            "/data/cache/query.log"
        );
        assert_eq!(
            feed_shape::query_log_path("/data", "nx"),
            "/data/cache/nx.log"
        );
        assert_eq!(
            feed_shape::query_log_path("/data", "solver"),
            "/data/logs/query-solver.log"
        );
        assert_eq!(
            feed_shape::query_log_path("/data", "centauri"),
            "/data/app_data/centauri_cache/query-centauri.log"
        );
        // #53 — the two off-`logs/` pillar feeds, wired to their MEASURED on-device homes:
        // MaskSolver's D40 Rust-canon resolve log beside its durable records, and Inu's log
        // beside its state blob under the Kotlin store's filesDir.
        assert_eq!(
            feed_shape::query_log_path("/data", "masksolver"),
            "/data/app_data/runtime_tier/query-masksolver.log"
        );
        assert_eq!(
            feed_shape::query_log_path("/data", "inu"),
            "/data/files/wire-cake-inu-spike/query-inu.log"
        );
        // github-trust rides the default `logs/query-<tag>.log` arm (PillarLog.kt tag).
        assert_eq!(
            feed_shape::query_log_path("/data", "github-trust"),
            "/data/logs/query-github-trust.log"
        );

        // ★ THE `/files` STRIP — on-device `internal_data_path()` = getFilesDir = `{BASE}/files`, but
        // the engine writes every log under the DATA dir `{BASE}` (`pathVars.appDataDir`). The reader
        // MUST strip the trailing `/files` so it lands on the REAL engine file, not a phantom
        // `{BASE}/files/…` that is never written (the ④ QUERY / ③ DNS empty-feed root cause).
        assert_eq!(
            feed_shape::query_log_path("/data/data/app.torta.yeah/files", "dnscrypt"),
            "/data/data/app.torta.yeah/cache/query.log"
        );
        assert_eq!(
            feed_shape::query_log_path("/data/data/app.torta.yeah/files", "beast"),
            "/data/data/app.torta.yeah/logs/query-beast.log"
        );
        assert_eq!(
            feed_shape::query_log_path("/data/data/app.torta.yeah/files", "centauri"),
            "/data/data/app.torta.yeah/app_data/centauri_cache/query-centauri.log"
        );

        // The classifier: time column split + the display-verdict heuristic (never an authority).
        let row = feed_shape::classify_query_line("[2026-07-02 12:00:00] solver cache HIT qtype=A");
        assert_eq!(row.time.as_str(), "[2026-07-02 12:00:00]");
        assert_eq!(row.line.as_str(), "solver cache HIT qtype=A");
        assert_eq!(row.verdict.as_str(), "CACHE");
        let row = feed_shape::classify_query_line("[2026-07-02 12:00:01] warden deny app=1027");
        assert_eq!(row.verdict.as_str(), "BLOCK");
        let row = feed_shape::classify_query_line("beast tick cwnd=1 aqm=44 relay=cloudflare");
        assert_eq!(
            row.time.as_str(),
            "",
            "a line with no bracketed timestamp keeps an empty time column"
        );
        assert_eq!(
            row.verdict.as_str(),
            "EVENT",
            "an unmatched event line falls to the neutral EVENT verdict"
        );
        // #53 — the ENGINE stats tick: its JSON body carries `"blocked":0`/`"cache_hits":2`
        // counter keys that the verdict keywords would misread (device-witnessed BLOCK misfire).
        // A stats dump is an EVENT, always.
        let row = feed_shape::classify_query_line(
            "[2026-07-19 01:47:20] dnsmasq stats json={\"configured\":true,\"blocked\":0,\"cache_hits\":2}",
        );
        assert_eq!(
            row.verdict.as_str(),
            "EVENT",
            "a stats tick is a counter dump, never a BLOCK verdict"
        );
    }

    /// ★ #49 · The FORWARDER dashboard's per-flow docket parser, proven on the EXACT wire shape
    /// `TortaPillarBridge.liveForwarderDocket` emits. Every field carries a DISTINCT value so a
    /// crossed wire cannot pass by coincidence (the #47 discipline).
    #[test]
    fn forwarder_docket_parses_the_bridge_wire_field_for_field() {
        let raw = "total=3\n\
                   -1\t6\t0\t1\t42\t1000\t2000\t37\t5000\t9";
        let (total, rows) = super::warden_feed::parse_forwarder_docket(raw);
        assert_eq!(total, 3, "the header carries the ENGINE's true active-flow count");
        assert_eq!(rows.len(), 1, "one row on the wire, one row rendered");
        let r = &rows[0];
        // key -1 is the all-ones i64: folded to the low 48 bits it must render as 12 hex f's, NOT
        // as a negative number — the key is an identity, and identities are unsigned here.
        assert_eq!(r.key.as_str(), "ffffffffffff");
        assert_eq!(r.proto.as_str(), "TCP", "★ #51 — field 2 is the IANA number: 6 is TCP");
        assert_eq!(r.tin.as_str(), "CRITICAL", "tin 0 is the 53/853 latency lane");
        assert!(r.paced);
        assert_eq!(r.cwnd, 42);
        assert_eq!(r.bytes_up, 1000.0);
        assert_eq!(r.bytes_down, 2000.0);
        assert_eq!(r.rtt_ms, 37);
        assert_eq!(r.age_ms, 5000.0);
        assert_eq!(r.stalls, 9);
    }

    /// An UNMEASURED round trip must survive the wire as -1. Clamping it to 0 here would make the
    /// panel claim an instantaneous round trip on every newborn flow — the exact empty-state lie
    /// #96 was closed on.
    #[test]
    fn forwarder_docket_keeps_an_unmeasured_rtt_negative() {
        let (_, rows) =
            super::warden_feed::parse_forwarder_docket("total=1\n7\t17\t2\t0\t0\t0\t0\t-1\t12\t0");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rtt_ms, -1, "-1 means unmeasured and must reach the panel intact");
        assert_eq!(rows[0].proto.as_str(), "UDP");
        assert_eq!(rows[0].tin.as_str(), "BULK", "tin 2 is the paced bulk lane");
        assert!(!rows[0].paced, "an unpaced flow reports cwnd 0 without claiming a stall");
    }

    /// Fail-open: a malformed row is SKIPPED, never panicked on and never fabricated. A stale peer
    /// `.so` shipping a different column count must cost only its own rows.
    #[test]
    fn forwarder_docket_skips_malformed_rows_and_keeps_the_good_ones() {
        let raw = "total=9\n\
                   1\t6\t1\t0\t0\t0\t0\t-1\t0\t0\n\
                   2\t6\t1\t0\t0\n\
                   3\t6\tx\t0\t0\t0\t0\t0\t0\t0\n\
                   4\t17\t1\t0\t0\t0\t0\t-1\t0\t0";
        let (total, rows) = super::warden_feed::parse_forwarder_docket(raw);
        assert_eq!(total, 9, "the header survives bad rows beneath it");
        assert_eq!(rows.len(), 2, "the 5-field row and the non-numeric row drop; the rest stand");
        assert_eq!(rows[0].key.as_str(), "000000000001");
        assert_eq!(rows[1].key.as_str(), "000000000004");
    }

    /// ★ #51 N9 — a PING must reach the panel labelled as a ping.
    ///
    /// This is the whole reason the wire's protocol field stopped being a boolean. Under the old
    /// `proto_tcp` encoding an ICMP row could only render as "UDP" (the flag was false), so the
    /// docket would have shown every ping as something it is not. The unknown-protocol case is
    /// asserted alongside it: a number we do not have a name for must render as ITSELF, because
    /// silently folding it into the nearest known label is the same lie one size smaller.
    #[test]
    fn forwarder_docket_names_the_icmp_lane_and_never_guesses_an_unknown_one() {
        let raw = "total=2\n\
                   11\t1\t0\t0\t0\t64\t64\t3\t900\t0\n\
                   12\t47\t2\t0\t0\t0\t0\t-1\t10\t0";
        let (_, rows) = super::warden_feed::parse_forwarder_docket(raw);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].proto.as_str(), "ICMP", "IANA 1 is the echo lane");
        assert_eq!(
            rows[0].tin.as_str(),
            "CRITICAL",
            "a diagnostic probe rides the latency-first tin"
        );
        assert!(!rows[0].paced, "a single echo packet has no window to pace");
        assert_eq!(rows[0].rtt_ms, 3, "a REAL measured round trip reaches the panel");
        // GRE (47) has no lane and no label — it must name its own number rather than borrow one.
        assert_eq!(rows[1].proto.as_str(), "ip 47");
        assert_eq!(rows[1].rtt_ms, -1, "unmeasured stays unmeasured");
    }

    /// A header-only record is a REAL reading: "the forwarder is live and carrying nothing right
    /// now". It must parse to zero rows WITHOUT being mistaken for a parse failure.
    #[test]
    fn forwarder_docket_accepts_a_live_but_empty_docket() {
        let (total, rows) = super::warden_feed::parse_forwarder_docket("total=0");
        assert_eq!(total, 0);
        assert!(rows.is_empty());
    }

    /// #3-EXT · The BEAST dashboard's RECENT-TICKS parser — the EXACT fn the live overlay runs
    /// over the on-disk query-beast.log tail ([`feed_shape::beast_tick_row_parse`]), proven on the
    /// writer's real line shape (torta_core beast/log.rs:88), backend-free.
    #[test]
    fn beast_tick_parser_decodes_the_writer_line_and_rejects_headers() {
        // A REAL-shape tick line (every k=v token the writer emits, in its order).
        let line = "1752791000123 tick mode=COMPETING cwnd=11/16 rtt=368.2ms udp=368.0ms \
                    pace=30.0/s pipe=3 q=9/2/0 valve=0.0000 shed=0 aqm=44 sparse=2 relay=cloudflare";
        let row = feed_shape::beast_tick_row_parse(line).expect("a writer-shape line parses");
        assert_eq!(row.mode.as_str(), "COMPETING");
        assert_eq!(row.cwnd, 11, "cwnd takes the numerator of cwnd=a/b");
        assert_eq!(row.shed, 0);
        assert_eq!(row.relay.as_str(), "cloudflare");

        // Shed carries through; a shorter historical line (no relay) defaults honestly.
        let row = feed_shape::beast_tick_row_parse("9 t mode=SHEDDING cwnd=4/16 shed=7")
            .expect("mode+cwnd suffice");
        assert_eq!(row.mode.as_str(), "SHEDDING");
        assert_eq!(row.cwnd, 4);
        assert_eq!(row.shed, 7);
        assert_eq!(row.relay.as_str(), "—", "absent relay renders the em-dash placeholder");

        // Non-tick lines (headers, torn writes, garbage) yield None — never a fabricated row.
        assert!(feed_shape::beast_tick_row_parse("").is_none());
        assert!(feed_shape::beast_tick_row_parse("# query-beast.log v1").is_none());
        assert!(
            feed_shape::beast_tick_row_parse("1752791000123 tick cwnd=11/16").is_none(),
            "a line without mode= is no tick"
        );
        assert!(
            feed_shape::beast_tick_row_parse("1752791000123 tick mode=COMPETING cwnd=X/16")
                .is_none(),
            "an unparseable cwnd numerator is no tick"
        );
    }
}

// ===========================================================================================
// THE WARDEN FEED PROOF (SLINT substitution . 2-FEED-Warden) — backend-free GROUND_TRUTH.
//
// No slint construction (winit's EventLoop is thread-affine — the SOLE constructing test is the
// shared `slint_substrate_compiles_and_binds`), so the arm→snapshot numbers the on-device feed
// renders are proven HERE on the host, deterministically: the read-not-guess proof that
// `arm_warden_spike` produces a REAL, non-zero, correctly-attributed `WardenSnapshot` — the exact
// torta_core the on-device `feed_from_live_warden` then pushes field-for-field onto the dashboard.
// ===========================================================================================
#[cfg(test)]
mod warden_feed_proof {
    use super::warden_feed::arm_warden_spike;

    #[test]
    fn arm_warden_spike_yields_real_nonzero_snapshot() {
        let w = torta_core::WardenObject::new();
        // A cold Warden is the honest all-zero "off" baseline (NOT what the dashboard must show).
        let cold = w.snapshot();
        assert_eq!(cold.deny, 0, "a cold Warden has zero denies");
        assert_eq!(cold.domain_rules, 0, "a cold Warden has zero armed rules");

        arm_warden_spike(&w);
        let s = w.snapshot();

        // ---- Armed rule-sets + matrix (the Centauri capacity/hosts analog — armed/config state) ----
        assert_eq!(s.domain_rules, 12, "12 universal block domains armed");
        assert_eq!(s.cidr_rules, 4, "4 universal block CIDRs armed");
        assert_eq!(s.universal_rules, 4, "4 universal rules armed");
        assert_eq!(s.app_rows, 5, "5 per-app matrix rows armed");
        assert!(s.policy_loaded, "a constructed Warden reports armed");

        // ---- Verdict tallies (the exercised engine — the VERDICTS + DENY ATTRIBUTION cards) ----
        assert_eq!(s.allow, 20, "20 allows tallied");
        assert_eq!(s.deny, 12, "12 denies tallied");
        assert_eq!(
            s.deny_by_universal_rule, 6,
            "TIER 4: 4 domain + 2 cidr denies"
        );
        assert_eq!(s.deny_by_blocklist, 3, "TIER 5: 3 dns_blocked denies");
        assert_eq!(s.deny_by_app, 2, "TIER 3: 2 isolate-app denies");
        assert_eq!(
            s.deny_by_universal_toggle, 1,
            "TIER 2: 1 block-http toggle deny"
        );

        // The load-bearing invariant (mirrors mod.rs `stats_tally...` — exactly-one-tier attribution).
        assert_eq!(
            s.deny_by_universal_toggle
                + s.deny_by_app
                + s.deny_by_universal_rule
                + s.deny_by_blocklist,
            s.deny,
            "per-tier counts sum to deny (first-match-wins attribution)"
        );
        assert!(
            s.cache_entries > 0,
            "the exercised verdicts populated the decision cache"
        );

        // The OUTCOME bar the dashboard must clear — NOT 0/0/0.
        assert!(s.allow > 0 && s.deny > 0 && s.domain_rules > 0 && s.app_rows > 0);

        // The per-app matrix READ carries the REAL armed rows (the feed maps these to AppRow — the
        // 5 real rows replace the .slint sample defaults Browser/SocialApp/Updater).
        let rows = w.app_rows();
        assert_eq!(rows.len(), 5, "app_rows() returns the 5 armed rows");
        assert!(
            rows.iter()
                .any(|r| matches!(r.mode, torta_core::WardenAppMode::Isolate)),
            "the ISOLATE row is present (the red-tinted mode the dashboard renders)"
        );
        assert!(
            rows.iter().any(|r| r.temp_allow_until != 0),
            "the paused (temp-allow) row is present"
        );
    }

    /// 2-FEED-Warden (SETTINGS) — the EXACT pure parsers the on-device settings feed runs
    /// (`build_warden_settings_toggles` + `parse_warden_settings_matrix`, the warden_feed cfg idiom:
    /// host-visible on test builds, never a parallel re-derivation). Proves the two bridge wires the
    /// pane populates from decode field-for-field: the 9 toggle bits off the flat pipe record, the
    /// per-app matrix off the TAB rows (ordinal → label, temp-allow → paused), malformed rows skipped.
    #[test]
    fn warden_settings_feed_parsers_decode_the_live_wire() {
        use super::warden_feed::{
            build_warden_settings_toggles, parse_warden_settings_matrix, parse_warden_settings_rules,
        };

        // ---- The 9 universal toggles (the wardenUniversalToggles pipe wire) ----
        let wire = "new_apps=1|unknown=0|metered=0|lockdown=1|device_lock=0|\
                    background=0|udp_ntp=0|http=1|dns_bypass=0";
        let toggles = build_warden_settings_toggles(Some(wire));
        assert_eq!(toggles.len(), 9, "all 9 fixed toggle rows are pushed");
        let on: std::collections::HashMap<_, _> =
            toggles.iter().map(|t| (t.key.to_string(), t.on)).collect();
        assert_eq!(on["new_apps"], true, "new_apps bit reads on");
        assert_eq!(on["lockdown"], true, "lockdown bit reads on");
        assert_eq!(on["http"], true, "http bit reads on");
        assert_eq!(on["unknown"], false, "unknown bit reads off");
        assert_eq!(on["dns_bypass"], false, "dns_bypass bit reads off");
        // The label/hint copy is re-pushed (a fresh model never renders blank).
        assert!(
            toggles.iter().all(|t| !t.label.is_empty() && !t.hint.is_empty()),
            "every toggle row carries its label + hint copy"
        );
        // No wire (host/cold) ⇒ every bit is the honest off default.
        let cold = build_warden_settings_toggles(None);
        assert!(cold.iter().all(|t| !t.on), "a cold feed leaves all toggles off");

        // ---- The DASHBOARD twin (A6 seam close — the wdash chips feed) ----
        // The SAME wire decodes to the dash's [ToggleRow]; a `None` wire yields the EMPTY vec (the
        // pane's `length == 0` honest silent/arm-to-read derive), never nine fabricated off-chips.
        let dash = super::warden_feed::build_warden_dash_toggles(Some(wire));
        assert_eq!(dash.len(), 9, "all 9 chips ride the dash feed");
        let armed: std::collections::HashMap<_, _> =
            dash.iter().map(|t| (t.key.to_string(), t.armed)).collect();
        assert_eq!(armed["lockdown"], true, "lockdown chip reads BLOCKING");
        assert_eq!(armed["http"], true, "http chip reads BLOCKING");
        assert_eq!(armed["metered"], false, "metered chip reads off");
        assert!(
            dash.iter().all(|t| !t.label.is_empty()),
            "every chip carries its label copy"
        );
        assert!(
            super::warden_feed::build_warden_dash_toggles(None).is_empty(),
            "a silent bridge yields the EMPTY model — the pane keeps its honest unreadable state"
        );

        // ---- The per-app matrix (the liveWardenMatrix TAB wire) ----
        // row 1: uid 10112 Browser, mode ord 2 (ISOLATE), metered ord 3 (ALLOW), temp-allow 0 (not paused)
        // row 2: uid 10180 Social, mode ord 3 (NONE), metered ord 2 (METERED), temp-allow 123 (paused)
        // row 3: malformed (too few fields) ⇒ skipped (fail-open)
        let mwire = "total=3\n\
                     10112\tBrowser\t2\t3\t0\t1\n\
                     10180\tSocial\t3\t2\t123\t1\n\
                     9999\tbroken";
        let matrix = parse_warden_settings_matrix(mwire);
        assert_eq!(matrix.len(), 2, "the malformed 3rd row is skipped");
        assert_eq!(matrix[0].uid, 10112);
        assert_eq!(matrix[0].name.to_string(), "Browser");
        assert_eq!(matrix[0].mode.to_string(), "ISOLATE", "mode ord 2 → ISOLATE");
        assert_eq!(matrix[0].metered.to_string(), "ALLOW", "metered ord 3 → ALLOW");
        assert_eq!(matrix[0].paused, false, "temp-allow 0 → not paused");
        assert_eq!(matrix[1].uid, 10180);
        assert_eq!(matrix[1].mode.to_string(), "NONE", "mode ord 3 → NONE");
        assert_eq!(matrix[1].metered.to_string(), "METERED", "metered ord 2 → METERED");
        assert_eq!(matrix[1].paused, true, "temp-allow 123 → paused");
        // An empty wire yields no rows (the honest no-rows state).
        assert!(parse_warden_settings_matrix("").is_empty(), "empty wire → no rows");

        // ---- The BLOCK rule list (the liveWardenRules TAB wire — M2) ----
        // row 1: a wildcard universal DOMAIN rule; row 2: a per-app DOMAIN rule (no wildcard);
        // row 3: a universal CIDR rule (BLOCK); row 4: malformed (too few fields) ⇒ skipped (fail-open).
        // DOMAINS come first, then CIDRS — the exact order removeWardenRule's flat index rides.
        let rwire = "total=4\n\
                     domain\tmetrics.net\tuniversal\t1\tBLOCK\n\
                     domain\tads.example.com\tuid 10112\t0\tBLOCK\n\
                     cidr\t203.0.113.0/24\tuniversal\t0\tBLOCK\n\
                     cidr\tbroken";
        let rules = parse_warden_settings_rules(rwire);
        assert_eq!(rules.len(), 3, "the malformed 4th row is skipped");
        assert_eq!(rules[0].kind.to_string(), "domain", "domains enumerate first");
        assert_eq!(rules[0].text.to_string(), "metrics.net");
        assert_eq!(rules[0].scope.to_string(), "universal");
        assert_eq!(rules[0].wildcard, true, "wildcard flag '1' decodes true");
        assert_eq!(rules[0].status.to_string(), "BLOCK");
        assert_eq!(rules[1].scope.to_string(), "uid 10112", "the per-app scope round-trips");
        assert_eq!(rules[1].wildcard, false, "wildcard flag '0' decodes false");
        assert_eq!(rules[2].kind.to_string(), "cidr", "CIDRs enumerate after the domains");
        assert_eq!(rules[2].text.to_string(), "203.0.113.0/24");
        // An empty wire yields no rows (the honest "none armed" state).
        assert!(parse_warden_settings_rules("").is_empty(), "empty rule wire → no rows");
    }

    /// W-A · THE DASHBOARD MATRIX PARSER — `parse_warden_dash_matrix`, the live warden-dash overlay's
    /// per-app decoder (the twin of `parse_warden_settings_matrix`, but it CARRIES the `mode_ord`
    /// tap-cycle discriminant + the `armed` bit the settings parser drops). Proves the `liveWardenMatrix`
    /// UNION wire decodes field-for-field: a HELD row (`armed=1`) keeps its ordinal → label AND the raw
    /// discriminant, a flow-observed default (`armed=0`) reads UNARMED (the .slint dims it), temp-allow →
    /// paused, and a malformed row is skipped (fail-open — never a fabricated app row).
    #[test]
    fn warden_dash_matrix_parser_carries_mode_ord_and_armed() {
        use super::warden_feed::parse_warden_dash_matrix;
        // row 1: uid 10112 Browser, mode ord 2 (ISOLATE), metered ord 3 (ALLOW), temp-allow 0, armed 1 (HELD)
        // row 2: uid 10180 Social,  mode ord 3 (NONE),    metered ord 3 (ALLOW), temp-allow 0, armed 0 (flow default)
        // row 3: uid 10222 Updater, mode ord 4 (UNTRACKED), metered ord 2 (METERED), temp-allow 999, armed 1
        // row 4: malformed (too few fields) ⇒ skipped (fail-open)
        let wire = "total=4\n\
                    10112\tBrowser\t2\t3\t0\t1\n\
                    10180\tSocial\t3\t3\t0\t0\n\
                    10222\tUpdater\t4\t2\t999\t1\n\
                    9999\tbroken";
        let rows = parse_warden_dash_matrix(wire);
        assert_eq!(rows.len(), 3, "the malformed 4th row is skipped (fail-open)");

        // A HELD row: ordinal → label AND the raw discriminant both survive; armed lit.
        assert_eq!(rows[0].uid, 10112);
        assert_eq!(rows[0].name.to_string(), "Browser");
        assert_eq!(rows[0].mode.to_string(), "ISOLATE", "mode ord 2 → ISOLATE label");
        assert_eq!(rows[0].mode_ord, 2, "the tap-cycle discriminant round-trips beside the label");
        assert_eq!(rows[0].metered.to_string(), "ALLOW", "metered ord 3 → ALLOW");
        assert_eq!(rows[0].paused, false, "temp-allow 0 → not paused");
        assert_eq!(rows[0].armed, true, "armed=1 → a HELD engine row");

        // A flow-observed default: armed=0 (the .slint dims it — it enforces nothing yet).
        assert_eq!(rows[1].uid, 10180);
        assert_eq!(rows[1].mode.to_string(), "NONE", "mode ord 3 → NONE");
        assert_eq!(rows[1].mode_ord, 3);
        assert_eq!(rows[1].armed, false, "armed=0 → a flow-observed default, unarmed");

        // A paused HELD row: temp-allow != 0 → paused.
        assert_eq!(rows[2].mode.to_string(), "UNTRACKED", "mode ord 4 → UNTRACKED");
        assert_eq!(rows[2].metered.to_string(), "METERED", "metered ord 2 → METERED");
        assert_eq!(rows[2].paused, true, "temp-allow 999 → paused");
        assert_eq!(rows[2].armed, true);

        // An empty wire yields no rows (the honest no-rows state).
        assert!(parse_warden_dash_matrix("").is_empty(), "empty wire → no rows");
    }

    /// CP-U · THE UNDERGROUND ROW RENDERER — the EXACT `format_underground_top` the on-device
    /// feed runs (the warden_feed cfg idiom: host-visible on test builds, never a parallel
    /// re-derivation). Proves the happy path: two well-formed 7-field bridge rows
    /// (`host:risk:source:hits:points:seq:verdict` joined by `;`) render one display line each,
    /// the automatically-sequestrated Neutral row wears the SEQ badge, the live row does not.
    #[test]
    fn underground_top_renders_rows() {
        let raw = "ads.tracker.example:ads:blocklist:7:0:1:neutral;metrics.example:analytics:suffix:3:14:0:neutral";
        let out = crate::underground_feed::format_underground_top(raw);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "two rows render two lines");
        assert_eq!(lines[0], "ads.tracker.example · ads/blocklist · ×7 · 0/20 · SEQ");
        assert_eq!(lines[1], "metrics.example · analytics/suffix · ×3 · 14/20");
    }

    /// CP-U · THE RE-HOMED TRUST BANDS BADGE — the 7th field (the manual verdict slug) drives the
    /// row badge: a `trusted` host reads TRUST, a `distrusted` host reads BLOCK and that manual
    /// condemnation OVERRIDES the automatic SEQ mark (BLOCK is why it sits sequestered — never
    /// both), a `neutral` sequestered host still reads SEQ, and a pre-Trust-bands 6-field legacy
    /// row renders as Neutral (backward-compatible, no badge when not sequestered).
    #[test]
    fn underground_top_trust_bands_render_and_override_seq() {
        let raw = "friend.example:tracker:suffix:2:20:0:trusted;\
                   evil.example:tracker:suffix:5:0:1:distrusted;\
                   auto.example:ads:blocklist:9:0:1:neutral;\
                   legacy.example:analytics:suffix:4:11:0";
        let out = crate::underground_feed::format_underground_top(raw);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "friend.example · tracker/suffix · ×2 · 20/20 · TRUST");
        assert_eq!(
            lines[1], "evil.example · tracker/suffix · ×5 · 0/20 · BLOCK",
            "manual BLOCK overrides the automatic SEQ mark"
        );
        assert_eq!(lines[2], "auto.example · ads/blocklist · ×9 · 0/20 · SEQ");
        assert_eq!(
            lines[3], "legacy.example · analytics/suffix · ×4 · 11/20",
            "a 6-field legacy row renders as Neutral (no badge)"
        );
    }

    /// CP-U · THE FAIL-OPEN ROW GATE — a malformed row (wrong field count, empty host) is
    /// SKIPPED, never rendered and never allowed to blank the whole court; the well-formed
    /// neighbours still render. Empty input renders the empty string (the card's `ug-top != ""`
    /// visibility gate then hides the offenders block entirely).
    #[test]
    fn underground_top_skips_malformed_rows_fail_open() {
        // 5 fields (truncated), empty host, and a healthy row — only the healthy row survives.
        let raw = "short.example:ads:blocklist:7:0;:spoof:rebind:1:8:0;ok.example:spoof:rebind:1:8:0";
        let out = crate::underground_feed::format_underground_top(raw);
        assert_eq!(out, "ok.example · spoof/rebind · ×1 · 8/20");
        assert_eq!(
            crate::underground_feed::format_underground_top(""),
            "",
            "empty bridge value renders empty (the DORMANT court)"
        );
    }

    /// #15 UNDERGROUND H · THE 9-FIELD PILLAR ROW — the H engine row
    /// (`host:risk:source:hits:points:seq:verdict:score:ttl`) renders through the SAME ENGINE-tab
    /// renderer (backward-forward compatible: the two new columns ride silently there), and the
    /// pillar's OWN `parse_underground_docket` lifts them typed: score, the human TTL label
    /// ("1h01m" shape / "—" for no clock), the seq bool, the verdict slug. A legacy 7-field row
    /// still parses (score 0, no clock); malformed rows skip fail-open.
    #[test]
    fn underground_docket_parses_the_nine_field_row() {
        let raw = "mal.example:dga:guard:4:0:1:neutral:12:3661;\
                   ok.example:analytics:suffix:3:14:0:neutral:1:0;\
                   legacy.example:ads:blocklist:7:0:1:distrusted;\
                   bad.row:only:three";
        let rows = crate::underground_feed::parse_underground_docket(raw);
        assert_eq!(rows.len(), 3, "the malformed row is skipped fail-open");
        assert_eq!(rows[0].host, "mal.example");
        assert_eq!(rows[0].risk, "dga", "a coined detector lane rides as the badge slug");
        assert_eq!(rows[0].source, "guard");
        assert_eq!(rows[0].hits, 4);
        assert_eq!(rows[0].points, 0);
        assert_eq!(rows[0].score, 12);
        assert!(rows[0].seq);
        assert_eq!(rows[0].ttl_label, "1h01m", "3661 s wears the h+m clock face");
        assert_eq!(rows[1].ttl_label, "—", "ttl 0 = no quarantine clock");
        assert_eq!(rows[2].score, 0, "a legacy 7-field row parses with score 0");
        assert_eq!(rows[2].verdict, "distrusted");
        // The ENGINE-tab renderer accepts the SAME 9-field rows (the summary card never blanks).
        let out = crate::underground_feed::format_underground_top(raw);
        assert!(out.starts_with("mal.example · dga/guard · ×4 · 0/20 · SEQ"));
        // The clock face: minutes-only + seconds-only shapes.
        assert_eq!(crate::underground_feed::fmt_ttl(120), "2m");
        assert_eq!(crate::underground_feed::fmt_ttl(45), "45s");
    }

    /// #15 UNDERGROUND H · THE LIVE WIRE RENDERER — the G VerdictEvent ring rows
    /// (`seq:host:verdict:delta:signal:ts`, oldest first off the bridge) render newest-FIRST,
    /// capped at 8 lines; malformed rows skip fail-open; empty input renders "" (the quiet wire).
    #[test]
    fn underground_wire_renders_newest_first_capped() {
        let raw: String = (1..=10)
            .map(|i| format!("{i}:host{i}.example:distrusted:-10:sonar:1700000{i}"))
            .collect::<Vec<_>>()
            .join(";");
        let out = crate::underground_feed::format_underground_wire(&raw);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 8, "the ticker caps at 8 lines");
        assert_eq!(
            lines[0], "#10 host10.example · sonar Δ-10 → distrusted",
            "newest event rides the top line"
        );
        assert_eq!(lines[7], "#3 host3.example · sonar Δ-10 → distrusted");
        assert_eq!(crate::underground_feed::format_underground_wire(""), "");
        assert_eq!(
            crate::underground_feed::format_underground_wire("garbled;1:2"),
            "",
            "malformed rows skip fail-open"
        );
    }

    /// #15 UNDERGROUND H · THE LAW PARSER + THE DETECTION PATCH — `parse_underground_law` mirrors
    /// the engine's own defaults (absent ⇒ every faculty ON, TTL 86400) and reads the explicit
    /// switches; `patch_underground_detection` rewrites a key in place, appends into an existing
    /// `[detection]` section, or creates the section on virgin text — and the patched text
    /// round-trips through the parser (the pane's toggles are sugar over the SAME law, never a
    /// fork).
    #[test]
    fn underground_law_parses_and_patches() {
        use crate::underground_feed::{parse_underground_law, patch_underground_detection};
        assert_eq!(
            parse_underground_law(""),
            (true, true, true, 86_400),
            "absent law = the engine's compile-time defaults"
        );
        let toml = "[penalty]\nads = 2\n\n[quarantine]\nttl_secs = 3600\n\n[detection]\ndga = false\ntunnel = true\n";
        assert_eq!(
            parse_underground_law(toml),
            (false, true, true, 3600),
            "explicit switches + TTL read back; absent beacon stays ON"
        );
        // Patch in place — dga flips back true, everything else byte-survives.
        let patched = patch_underground_detection(toml, "dga", true);
        assert_eq!(parse_underground_law(&patched), (true, true, true, 3600));
        assert!(patched.contains("ads = 2"), "the rest of the law byte-survives");
        // Append into the existing section — beacon lands under [detection].
        let patched = patch_underground_detection(toml, "beacon", false);
        assert_eq!(parse_underground_law(&patched), (false, true, false, 3600));
        // Virgin text — the section is created whole.
        let patched = patch_underground_detection("", "tunnel", false);
        assert_eq!(parse_underground_law(&patched), (true, false, true, 86_400));
        assert!(patched.contains("[detection]\ntunnel = false"));
    }

    /// #7 EUREKA · THE INU DURABILITY-TRIPLE PARSER (host path) — the EXACT
    /// `inu_feed::parse_inu_prefs` the on-device dashboard/idash/iset feeds consume for the
    /// live `boot-reapply-armed` fill (`stagedInuConfig()`'s pipe record). Proves the armed
    /// pref reads back `true` (un-latching the drift-unguarded lamp, inu.slint:175), a cold /
    /// garbled record degrades to the honest defaults per field, and unknown keys are ignored
    /// fail-open.
    #[test]
    fn inu_prefs_parse_live_and_fail_open() {
        use crate::inu_feed::parse_inu_prefs;
        // The armed record — every field live.
        assert_eq!(
            parse_inu_prefs("bootreapply=1|alwayson=1|providerpref=2"),
            (true, true, 2),
            "an armed boot-reapply pref MUST read back true (the #7 EUREKA fill)"
        );
        // Cold record / empty string — the honest defaults (off / off / AUTO).
        assert_eq!(parse_inu_prefs(""), (false, false, 0));
        assert_eq!(
            parse_inu_prefs("bootreapply=0|alwayson=0|providerpref=0"),
            (false, false, 0)
        );
        // Per-field fail-open: a garbled providerpref holds AUTO, the good fields still land.
        assert_eq!(
            parse_inu_prefs("bootreapply=1|alwayson=0|providerpref=banana"),
            (true, false, 0),
            "one garbled field never drops its healthy neighbours"
        );
        // Unknown keys ignored; whitespace-tolerant values.
        assert_eq!(
            parse_inu_prefs("mystery=7|bootreapply= 1 |alwayson=1"),
            (true, true, 0)
        );
    }

    /// A5 slice-5 · THE DOCKET FEED (host path) — the EXACT `live_flow_feed` the startup feed +
    /// the 1s warden-dash Timer run: real flows into the GLOBAL `warden_flow_ring` (the slice-4
    /// choke-point ring; cleared first — the global-ring serial law), out as newest-first FlowRow
    /// rows with the engine-derived flag/cc/asn (the tracker OVERWRITES wire values — the anchors
    /// 8.8.8.8→us/GOOGLE, 193.0.10.1→nl/RIPE-NCC-AS) and verdict-driven tint. No slint
    /// construction (the winit thread-affinity law above) — the rows are asserted as data.
    #[test]
    fn live_flows_ring_feeds_newest_first_docket_rows() {
        let ring = torta_core::warden_flow_ring();
        ring.clear();
        let base = torta_core::FlowRecord {
            uid: -1,
            app: "chrome".to_string(),
            ip: "8.8.8.8".to_string(),
            cc: String::new(),
            flag: String::new(),
            asn: String::new(),
            domain: "dns.google".to_string(),
            port: 443,
            proto: 6,
            verdict: torta_core::WardenVerdict::Allow,
            carried: true,
            up: 0,
            down: 0,
            ts_ms: 1,
        };
        ring.record(base.clone());
        ring.record(torta_core::FlowRecord {
            app: String::new(), // unresolved uid — the row falls back to ip in the .slint
            ip: "193.0.10.1".to_string(),
            port: 853,
            proto: 17,
            verdict: torta_core::WardenVerdict::DenyByFirewall,
            carried: false, // a deny is never carried
            ts_ms: 2,
            ..base.clone()
        });
        ring.record(torta_core::FlowRecord {
            // #20 — the sync-loop shape: allowed by the Warden, dropped by the datapath.
            port: 5228,
            verdict: torta_core::WardenVerdict::Allow,
            carried: false,
            ts_ms: 3,
            ..base
        });

        let (total, rows) = super::warden_feed::live_flow_feed();
        assert_eq!(total, 3, "the retained count reaches the flow-total header");
        assert_eq!(rows.len(), 3, "all retained flows render");

        // Row 0 is the NEWEST (the ring's snapshot order — the docket renders top-down): the
        // allowed-but-uncarried flow (#20) — verdict stays the honest ALLOW grain (no red tint),
        // carried=false rides beside it so the .slint renders DROPPED amber.
        assert_eq!(rows[0].port, 5228);
        assert_eq!(rows[0].verdict.as_str(), "ALLOW");
        assert!(!rows[0].denied, "allowed-but-uncarried is NOT a deny — no red tint");
        assert!(!rows[0].carried, "the drop disposition reaches the row");

        assert_eq!(rows[1].ip.as_str(), "193.0.10.1");
        assert_eq!(rows[1].flag.as_str(), "🇳🇱", "engine-derived flag (never a UI guess)");
        assert_eq!(rows[1].cc.as_str(), "NL");
        assert_eq!(
            rows[1].asn.as_str(),
            "RIPE-NCC-AS Reseaux IP Europeens Network Coordination Centre RIPE NCC",
            "the engine's full AS name rides the row (the .slint elides visually, never the data)"
        );
        assert_eq!(rows[1].port, 853);
        assert_eq!(rows[1].proto.as_str(), "UDP");
        assert_eq!(rows[1].verdict.as_str(), "DENY-FW");
        assert!(rows[1].denied, "a firewall deny tints red");
        assert!(!rows[1].carried);
        assert_eq!(rows[1].app.as_str(), "", "an unresolved app rides through empty — no guess");

        assert_eq!(rows[2].ip.as_str(), "8.8.8.8");
        assert_eq!(rows[2].app.as_str(), "chrome", "a caller-stamped app label passes through");
        assert_eq!(
            rows[2].domain.as_str(),
            "dns.google",
            "the A4 domain is CALLER truth — record() never overwrites it (no ip-derivable ground truth)"
        );
        assert_eq!(rows[2].flag.as_str(), "🇺🇸");
        assert_eq!(rows[2].cc.as_str(), "US");
        assert_eq!(rows[2].asn.as_str(), "GOOGLE");
        assert_eq!(rows[2].proto.as_str(), "TCP");
        assert_eq!(rows[2].verdict.as_str(), "ALLOW");
        assert!(!rows[2].denied, "an allow never tints red");
        assert!(rows[2].carried, "the forwarder's allow is an honest carried ALLOW");

        ring.clear(); // leave the global ring cold for the sibling tests (the serial law)
    }

    /// A5 slice-5 · THE BRIDGE WIRE PARSER (android path) — the EXACT `parse_flow_feed` the
    /// on-device docket runs over `TortaPillarBridge.liveWardenFlows`: the `total=` header lands,
    /// well-formed rows render (flag derived from the ASCII `cc` via the engine's `flag_emoji`),
    /// an UNKNOWN verdict shows its honest raw name and tints by its DENY prefix, and a malformed
    /// row (wrong field count / non-numeric port) is SKIPPED fail-open — never a panic, never a
    /// blanked docket (the underground-rows law).
    #[test]
    fn live_flows_bridge_wire_parses_and_skips_malformed() {
        let raw = concat!(
            "total=42\n",
            "us\tchrome\t8.8.8.8\t443\t6\tALLOW\tGOOGLE\t1\tdns.google\n",
            "nl\t\t193.0.10.1\t853\t17\tDENY_BY_FIREWALL\tRIPE-NCC-AS\t0\t\n",
            "us\tsync-drop\t8.8.4.4\t443\t6\tALLOW\tGOOGLE\t0\t\n",
            "us\tshort-row\t1.2.3.4\t80\t6\n",
            "us\tstale-8col\t2.2.2.2\t443\t6\tALLOW\tGOOGLE\t1\n",
            "us\tbad-port\t1.2.3.4\tno\t6\tALLOW\tGOOGLE\t1\t\n",
            "\tfuture\t9.9.9.9\t8080\t132\tDENY_BY_NEW_TIER\tQUAD9\tx\t\n",
        );
        let (total, rows) = super::warden_feed::parse_flow_feed(raw);
        assert_eq!(total, 42, "the total= header lands");
        assert_eq!(rows.len(), 4, "three malformed rows skipped, four render");

        assert_eq!(rows[0].app.as_str(), "chrome", "the PackageManager label rides the wire");
        assert_eq!(rows[0].flag.as_str(), "🇺🇸", "flag derives from the ASCII cc wire field");
        assert_eq!(rows[0].verdict.as_str(), "ALLOW");
        assert!(!rows[0].denied);
        assert!(rows[0].carried, "the forwarder's carried ALLOW rides the 8th wire column");
        assert_eq!(rows[0].domain.as_str(), "dns.google", "the A4 attribution rides the 9th column");

        assert_eq!(rows[1].app.as_str(), "", "unresolved uid ships empty — the row shows ip");
        assert_eq!(rows[1].domain.as_str(), "", "an unattributed flow ships an EMPTY domain — no guess");
        assert_eq!(rows[1].ip.as_str(), "193.0.10.1");
        assert_eq!(rows[1].proto.as_str(), "UDP");
        assert_eq!(rows[1].verdict.as_str(), "DENY-FW");
        assert!(rows[1].denied);
        assert!(!rows[1].carried);

        // #20 — the sync-loop shape on the wire: allowed grain, uncarried disposition. The verdict
        // cell stays the pure enum name; carried=0 rides beside it (the .slint renders DROPPED).
        assert_eq!(rows[2].verdict.as_str(), "ALLOW");
        assert!(!rows[2].denied, "allowed-but-uncarried is NOT a deny");
        assert!(!rows[2].carried, "carried=0 reaches the row untangled from the verdict");

        // The unknown arm: honest raw name, DENY-prefix tint, numeric proto label — no false ALLOW.
        // A garbage carried cell (`x`) reads UNCARRIED — the fail direction is DROPPED-when-unsure.
        assert_eq!(rows[3].verdict.as_str(), "DENY_BY_NEW_TIER");
        assert!(rows[3].denied, "an unknown DENY* verdict still tints red");
        assert_eq!(rows[3].proto.as_str(), "P132");
        assert_eq!(rows[3].flag.as_str(), "🌐", "an EMPTY cc (geoip miss) wears the honest globe");
        assert!(!rows[3].carried, "a non-`1` carried cell never reads carried");

        assert_eq!(
            super::warden_feed::parse_flow_feed("total=0").1.len(),
            0,
            "a header-only wire is the honest empty docket"
        );
    }

    /// W-D (#79) · THE INSPECTOR APP-BROWSER PARSER (host path) — the EXACT `parse_inspector_apps` the
    /// overlay runs over `TortaPillarBridge.liveWardenAppFlows`: the `total=` header is skipped, a
    /// well-formed 13-field row lands with its activity + block posture, an app with an EMPTY name falls
    /// back to `uid N` (never a fabricated label), the WiFi/mobile block bits read only from `1`, and a
    /// short (malformed) row is SKIPPED fail-open — never a panic, never a blanked browser.
    #[test]
    fn inspector_apps_wire_parses_posture_and_skips_malformed() {
        let raw = concat!(
            "total=7\n",
            "10123\tchrome\t42\t40\t2\t9\t4\t1000\t500\t1710000000\t1\t0\t3\n",
            "10456\t\t3\t3\t0\t2\t1\t10\t5\t1710000001\t0\t1\t0\n",
            "10789\tshort-row\t1\t1\t0\n",
        );
        let rows = super::warden_feed::parse_inspector_apps(raw);
        assert_eq!(rows.len(), 2, "the header + the short row are both skipped");

        assert_eq!(rows[0].uid, 10123);
        assert_eq!(rows[0].name.as_str(), "chrome", "the resolved label rides the wire");
        assert_eq!(rows[0].flows, 42);
        assert_eq!(rows[0].allowed, 40);
        assert_eq!(rows[0].denied, 2);
        assert_eq!(rows[0].ips, 9, "the distinct-endpoint count reaches the browser row");
        assert_eq!(rows[0].countries, 4);
        assert!(rows[0].block_wifi, "the WiFi-block posture bit rides the 11th column");
        assert!(!rows[0].block_mobile, "0 never reads as a mobile block");
        assert_eq!(rows[0].mode_ord, 3);

        assert_eq!(
            rows[1].name.as_str(),
            "uid 10456",
            "an unresolved app falls back to its uid — never a fabricated name"
        );
        assert!(!rows[1].block_wifi);
        assert!(rows[1].block_mobile, "the mobile-block posture bit rides the 12th column");

        assert!(
            super::warden_feed::parse_inspector_apps("total=0").is_empty(),
            "a header-only wire is the honest DORMANT browser"
        );
    }

    /// W-D (#79) · THE INSPECTOR ENDPOINT PARSER (host path) — the EXACT `parse_inspector_dests` the
    /// drilled-app view runs over `TortaPillarBridge.liveWardenAppDests(uid)`: the flag GLYPH derives HERE
    /// from the ASCII `cc` (the one `flag_emoji` source — an empty cc wears the honest globe), the cc is
    /// upper-cased, the proto number becomes its label, `denied`/`carried` read only from `1`, every row
    /// starts UNSELECTED, and a short (malformed) row is SKIPPED fail-open.
    #[test]
    fn inspector_dests_wire_parses_flag_and_skips_malformed() {
        let raw = concat!(
            "total=9\n",
            "8.8.8.8\tus\tGOOGLE\tdns.google\t443\t6\t0\t1\t12\t900\t400\t1710000000\n",
            "2001:4860:4860::8888\t\tGOOGLE\t\t53\t17\t1\t0\t3\t60\t30\t1710000001\n",
            "1.2.3.4\tde\tDTAG\t80\t6\n",
        );
        let rows = super::warden_feed::parse_inspector_dests(raw);
        assert_eq!(rows.len(), 2, "the header + the short row are both skipped");

        assert_eq!(rows[0].ip.as_str(), "8.8.8.8");
        assert_eq!(rows[0].flag.as_str(), "🇺🇸", "flag derives torta_ui-side from the ASCII cc");
        assert_eq!(rows[0].cc.as_str(), "US", "the cc is upper-cased for display");
        assert_eq!(rows[0].asn.as_str(), "GOOGLE");
        assert_eq!(rows[0].domain.as_str(), "dns.google");
        assert_eq!(rows[0].port, 443);
        assert_eq!(rows[0].proto.as_str(), "TCP");
        assert!(!rows[0].denied, "0 never reads as a deny");
        assert!(rows[0].carried, "the carried disposition rides the 8th column");
        assert_eq!(rows[0].hits, 12);
        assert!(!rows[0].selected, "every endpoint starts UNSELECTED — the multi-select is a UI action");

        assert_eq!(rows[1].ip.as_str(), "2001:4860:4860::8888");
        assert_eq!(rows[1].flag.as_str(), "🌐", "an EMPTY cc (geoip miss) wears the honest globe");
        assert_eq!(rows[1].proto.as_str(), "UDP");
        assert!(rows[1].denied, "the deny bit rides the 7th column");
        assert!(!rows[1].carried, "a deny is never carried");

        assert!(
            super::warden_feed::parse_inspector_dests("total=0").is_empty(),
            "a header-only wire is the honest empty endpoint list"
        );
    }

    /// W-D (#79) · THE BLOCK-LADDER CIDR builder — `ladder_cidr` climbs the granularity rungs: mode 0 is
    /// the bare HOST (the engine parses bare = /32 or /128), mode 1 the neighbourhood (/24 · /64), mode 2
    /// the source FAMILY (/16 · /48). The v4 and v6 rungs differ by address space — a v6 endpoint never
    /// wears a v4 prefix.
    #[test]
    fn ladder_cidr_climbs_v4_and_v6_rungs() {
        assert_eq!(super::warden_feed::ladder_cidr("8.8.8.8", 0), "8.8.8.8", "mode 0 = bare host");
        assert_eq!(super::warden_feed::ladder_cidr("8.8.8.8", 1), "8.8.8.8/24", "mode 1 = /24 neighbourhood");
        assert_eq!(super::warden_feed::ladder_cidr("8.8.8.8", 2), "8.8.8.8/16", "mode 2 = /16 source family");
        assert_eq!(
            super::warden_feed::ladder_cidr("2001:4860:4860::8888", 0),
            "2001:4860:4860::8888",
            "a v6 host rides bare too"
        );
        assert_eq!(
            super::warden_feed::ladder_cidr("2001:4860:4860::8888", 1),
            "2001:4860:4860::8888/64",
            "the v6 neighbourhood is /64, never /24"
        );
        assert_eq!(
            super::warden_feed::ladder_cidr("2001:4860:4860::8888", 2),
            "2001:4860:4860::8888/48",
            "the v6 source family is /48, never /16"
        );
    }

    /// ★ #22 slice 2 — the TCAT v2 freshness label: 0 = the em-dash (NEVER "56y ago" — the 1970
    /// lie), a skewed-ahead clock reads "just now" (never negative), and the m/h/d rungs land on
    /// their honest units. Pure — `now` is a parameter, no wall clock in the assert.
    #[test]
    fn freshness_label_renders_honest_ages() {
        use super::centauri_feed_fmt::freshness_label;
        let now = 1_784_000_000_i64;
        assert_eq!(freshness_label(now, 0), "—", "epoch 0 = freshness UNKNOWN, the em-dash");
        assert_eq!(freshness_label(now, -5), "—", "a negative epoch is unknown too");
        assert_eq!(freshness_label(now, now), "just now", "zero age");
        assert_eq!(freshness_label(now, now + 120), "just now", "clock skew NEVER reads negative");
        assert_eq!(freshness_label(now, now - 89), "just now", "under 90s is 'just now'");
        assert_eq!(freshness_label(now, now - 300), "5m ago", "minutes rung");
        assert_eq!(freshness_label(now, now - 7_200), "2h ago", "hours rung");
        assert_eq!(freshness_label(now, now - 259_200), "3d ago", "days rung");
        // The parse twin: the bridge JSON field rides json_i64, not the i32 scanner (2038-proof).
        assert_eq!(
            super::centauri_feed_fmt::json_i64("{\"catalog_authored_at_secs\":1784000000}", "catalog_authored_at_secs"),
            Some(1_784_000_000),
            "json_i64 reads the epoch the Kotlin bridge emits"
        );
    }
}
