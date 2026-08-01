/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! A5 — THE LIVE CONNECTION TRACKER: sovereignty made VISIBLE.
//!
//! The bounded per-flow log behind the "🇺🇸 chrome · 443 · TCP · ALLOW · 1.2 MB↓" panel: every judged
//! connection lands here as a [`FlowRecord`] (app, ip, country flag, verdict, byte counts), Kotlin
//! pulls [`ConnTracker::snapshot`] and folds ([`ConnTracker::country_summary`] /
//! [`ConnTracker::asn_summary`]) for the "where your data goes" view.
//!
//! ## GENESIS (studied, then originated — no source byte ships)
//! Studied from RethinkDNS (`rethink-app-main`, Apache-2.0, credited in NOTICE):
//! - `CountryConfig.kt:141-147` — the `flagEmojiFor` regional-indicator algorithm ([`flag_emoji`]).
//! - `ConnectionTracker.kt:38-56` — the per-flow field inventory (`appName`, `uid`, `ipAddress`,
//!   `port`, `protocol`, `isBlocked`, `flag:49`, `downloadBytes`, `uploadBytes`, `timeStamp`).
//! - `StatsSummaryDao.kt` — the aggregate shapes: countries = GROUP BY flag / allowed-only / LIMIT 7
//!   (`getMostContactedCountries`), ASN = GROUP BY asName / `asName != ''` / LIMIT 7
//!   (`getMostConnectedASN`).
//! IDEAS only; the Room-DB persistence is NOT reproduced — this tracker is a hard-capped RAM ring
//! (a chatty device can never balloon memory; history is a UI nicety, not a ledger).
//!
//! ## Scope (A5 slices 1–4: trio + feed — the ring is ARMED)
//! The tracker + flag derivation are LIVE (slice-1); the `cc` producer is LIVE (slice-2 —
//! [`super::geoip`], the embedded RIR range tables); the `asn` producer is LIVE (slice-3 —
//! [`super::asn`], the embedded BGP range tables): [`ConnTracker::record`] derives `cc` and `asn`
//! from the flow's `ip` and `flag` from that `cc`, overwriting ALL THREE wire values — a caller
//! can never desynchronize country, network, or flag from the destination. Slice-4 arms the FEED:
//! the [`global`] ring is filled by [`feed`] from the `tunnel::warden::verdict` bridge — the one
//! choke point BOTH datapaths (tunnel loop + netstack forwarder) cross — and pulled by Kotlin via
//! [`conn_tracker`] / read in-crate by the SLINT host via [`global`].

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use super::object::WardenVerdict;

/// Hard cap on retained flows — the ring evicts oldest-first past this. 512 × ~100 B ≈ 50 KB worst
/// case: enough scrollback for the live panel, bounded against a chatty device.
pub const FLOW_CAP: usize = 512;

/// The globe fallback (`U+1F310`) for an unknown/absent country — `CountryConfig.kt:142` verbatim
/// semantics (`"🌐"` is the UTF-16 surrogate pair for the same scalar).
const GLOBE: &str = "\u{1F310}";

/// An ISO-3166 alpha-2 country code → its flag emoji (two regional-indicator scalars), or 🌐 for
/// anything that is not exactly two ASCII letters. The `CountryConfig.kt:141-147` algorithm: each
/// letter maps to `0x1F1E6 + (letter - 'A')`. TIGHTENED over the original: the Kotlin accepts ANY
/// two chars (a digit would yield a non-flag scalar); this port gates on ASCII-alphabetic so the
/// output is a real flag or the globe, never tofu-adjacent garbage.
pub fn flag_emoji(cc: &str) -> String {
    let b = cc.as_bytes();
    if b.len() != 2 || !b[0].is_ascii_alphabetic() || !b[1].is_ascii_alphabetic() {
        return GLOBE.to_owned();
    }
    const BASE: u32 = 0x1F1E6 - 'A' as u32;
    let first = char::from_u32(BASE + b[0].to_ascii_uppercase() as u32);
    let second = char::from_u32(BASE + b[1].to_ascii_uppercase() as u32);
    match (first, second) {
        (Some(f), Some(s)) => {
            let mut out = String::with_capacity(8);
            out.push(f);
            out.push(s);
            out
        }
        // Unreachable for A-Z (0x1F1E6..=0x1F1FF are valid scalars) — but the fallback stays a
        // globe, never a panic, on a render-only path.
        _ => GLOBE.to_owned(),
    }
}

/// ONE judged flow — the UniFFI-bridged log line the live panel renders
/// (`ConnectionTracker.kt:38-56` field inventory, RAM-ring scoped). Byte counts and the timestamp
/// are caller-stamped (the datapath owns the clock and the counters); `flag` is ENGINE-stamped from
/// `cc` on [`ConnTracker::record`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct FlowRecord {
    /// The owning app's UID; `-1` = unresolved (no N-warden hook installed, or the OS could not
    /// attribute the flow — the same sentinel the verdict path carries).
    pub uid: i32,
    /// The app's display name (`appName`) — resolved Kotlin-side (PackageManager lives there).
    pub app: String,
    /// The destination IP as a string (the FFI convention — [`super::object::WardenConnFacts`]).
    pub ip: String,
    /// ISO-3166 alpha-2 country code, lowercase; `""` = unknown (renders 🌐). ENGINE-derived from
    /// `ip` on record ([`super::geoip::country_code`]) — the wire value is overwritten.
    pub cc: String,
    /// The flag emoji for `cc` — ALWAYS engine-derived ([`flag_emoji`]); the wire value is
    /// overwritten on record so flag and country can never disagree.
    pub flag: String,
    /// The AS name (`IpInfo.kt:27` `asName`); `""` = unknown. ENGINE-derived from `ip` on record
    /// ([`super::asn::as_name`]) — the wire value is overwritten.
    pub asn: String,
    /// The domain the app resolved to reach `ip` (A4 attribution; `""` = unattributed). CALLER
    /// truth from the verdict seam — the qname the caller knew, or the attribution map's
    /// best-effort label ([`super::attribution`]) — NOT engine-overwritten on record: unlike
    /// `cc`/`asn` there is no ip-derivable ground truth to re-derive it from.
    pub domain: String,
    /// Destination port.
    pub port: u16,
    /// IP protocol number (6 = TCP, 17 = UDP).
    pub proto: u8,
    /// The Warden's verdict for this flow ([`WardenVerdict`] — coarse allow/deny grain).
    pub verdict: WardenVerdict,
    /// Did the datapath CARRY this flow (#20 ROW HONESTY)? `true` = the judging datapath forwards
    /// it (the netstack forwarder's allow path); `false` = judged but dropped — the sync loop's
    /// Stage-2-min non-DNS gate drops every flow it rules on, and a DENY is never carried. Two
    /// truths, two fields: `verdict` is the Warden's judgment, `carried` is the tunnel's
    /// disposition — the panel renders an allowed-but-uncarried flow as DROPPED, never as a false
    /// ALLOW.
    pub carried: bool,
    /// Bytes uploaded on this flow so far (`uploadBytes`).
    pub up: i64,
    /// Bytes downloaded on this flow so far (`downloadBytes`).
    pub down: i64,
    /// Wall-clock ms since epoch (`timeStamp`), caller-stamped.
    pub ts_ms: i64,
}

/// One row of the "where your data goes" COUNTRY fold — allowed flows grouped by country
/// (`StatsSummaryDao.kt` `getMostContactedCountries`: GROUP BY flag · allowed-only · LIMIT 7), plus
/// the byte sums the panel renders beside the count.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CountrySummary {
    /// The group's country code (`""` = the unknown/🌐 bucket — kept, per the Dao, which does not
    /// filter unknown flags out).
    pub cc: String,
    /// The group's flag emoji ([`flag_emoji`] of `cc`).
    pub flag: String,
    /// Allowed flows in the group.
    pub count: i64,
    /// Sum of uploaded bytes across the group.
    pub up: i64,
    /// Sum of downloaded bytes across the group.
    pub down: i64,
}

/// One row of the ASN fold — allowed flows grouped by AS name (`StatsSummaryDao.kt`
/// `getMostConnectedASN`: GROUP BY asName · `asName != ''` · allowed-only · LIMIT 7).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AsnSummary {
    /// The AS name (never `""` — unknown-ASN flows are excluded, per the Dao).
    pub asn: String,
    /// Allowed flows in the group.
    pub count: i64,
    /// Sum of uploaded bytes across the group.
    pub up: i64,
    /// Sum of downloaded bytes across the group.
    pub down: i64,
}

/// One row of the PER-APP fold (W-D TIER-3 INSPECTOR, #79) — every flow the ring has seen grouped by
/// `uid`, so the inspector can list the apps the firewall has judged and, per app, how much it talks and
/// where. Distinct from the country/ASN folds (which slice the ring by DESTINATION); this slices it by
/// SOURCE APP. Includes DENIED flows (the inspector shows the whole picture, not the allowed-only "where
/// your data goes" view). `app` is the first non-empty display name the ring holds for the uid (Kotlin
/// resolves uid → name on the flows it feeds; `""` until it does).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AppFlowSummary {
    /// The owning app's UID (`-1` = unresolved — its own bucket; the inspector labels it, cannot per-app
    /// rule it).
    pub uid: i32,
    /// The app's display name — the first non-empty `app` the ring holds for this uid (`""` = unresolved
    /// this render; the inspector falls back to `uid N`).
    pub app: String,
    /// Total flows the ring holds for this uid (allowed + denied).
    pub flows: i64,
    /// Of those, the flows the Warden ALLOWED.
    pub allowed: i64,
    /// Of those, the flows the Warden DENIED (any non-`Allow` verdict).
    pub denied: i64,
    /// Distinct destination IPs this app has contacted (the inspector's "N endpoints" count).
    pub distinct_ips: i64,
    /// Distinct destination COUNTRIES (distinct `cc`, the 🌐 unknown bucket counts as one).
    pub countries: i64,
    /// Sum of uploaded bytes across the app's flows.
    pub up: i64,
    /// Sum of downloaded bytes across the app's flows.
    pub down: i64,
    /// The newest `ts_ms` the ring holds for this uid (the inspector sorts "most recently active" first).
    pub last_ts: i64,
}

/// One DESTINATION row of the per-app inspector (W-D, #79) — the flows for ONE app grouped by destination
/// IP, so the inspector renders the WHOLE list of endpoints an app contacts, each with its GEO flag + ASN
/// + the domain it resolved to reach it. This is the row the block-granularity ladder acts on: block this
/// single IP (/32) → its CIDR family (/24) → its whole country (the `cc`) → a similar source (its `asn`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DestRecord {
    /// The destination IP as a string.
    pub ip: String,
    /// ISO-3166 alpha-2 country code, lowercase (`""` = unknown/🌐). Engine-derived (already on the flow).
    pub cc: String,
    /// The flag emoji for `cc` ([`flag_emoji`]).
    pub flag: String,
    /// The AS name (`""` = unknown). Engine-derived (already on the flow) — the "similar source" hint.
    pub asn: String,
    /// The most-recent non-empty domain the app resolved to reach this IP (A4 attribution; `""` = none).
    pub domain: String,
    /// The most-recently-seen destination port.
    pub port: u16,
    /// The most-recently-seen IP protocol number (6 = TCP, 17 = UDP).
    pub proto: u8,
    /// Did ANY flow to this IP get DENIED? (the inspector tints a denied endpoint red).
    pub denied: bool,
    /// Did the datapath CARRY the most-recent flow to this IP (#20 ROW HONESTY)?
    pub carried: bool,
    /// Flows to this IP (the endpoint's hit count).
    pub hits: i64,
    /// Sum of uploaded bytes to this IP.
    pub up: i64,
    /// Sum of downloaded bytes from this IP.
    pub down: i64,
    /// The newest `ts_ms` of a flow to this IP.
    pub last_ts: i64,
}

/// Rows the summary folds return — the `LIMIT 7` of the Dao's country/ASN aggregate queries.
const SUMMARY_LIMIT: usize = 7;

/// Cap on rows the per-app inspector folds return (W-D, #79) — a chatty device can hold [`FLOW_CAP`]
/// flows across many apps + endpoints; the inspector is a scrollable list, but a hard cap keeps the FFI
/// payload bounded (the ring itself is already bounded, so this only bites a pathological many-app fold).
const INSPECTOR_LIMIT: usize = 128;

/// THE CONNECTION TRACKER — the stateful per-flow RAM ring (the [`super::object::WardenObject`] /
/// `BeastMetricSink` Object pattern: Kotlin constructs one, holds the `Arc`, pushes records from the
/// datapath, pulls snapshots/folds from the UI). Interior state is one `Mutex<VecDeque>`; lock-poison
/// RECOVERY (`unwrap_or_else(into_inner)`, the crate-wide idiom) is strictly safe here — the guarded
/// state is an always-valid ring of plain data.
#[derive(uniffi::Object)]
pub struct ConnTracker {
    flows: Mutex<VecDeque<FlowRecord>>,
}

impl ConnTracker {
    /// Ring mechanics only (evict past [`FLOW_CAP`], append) — NO derivation. [`Self::record`] is
    /// the only production caller; tests push hand-authored records through this seam so the fold
    /// tests exercise folding, not the GeoIP table.
    fn push(&self, rec: FlowRecord) {
        let mut flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        if flows.len() >= FLOW_CAP {
            flows.pop_front();
        }
        flows.push_back(rec);
    }
}

#[uniffi::export]
impl ConnTracker {
    /// A cold, empty tracker. UniFFI Object ctors MUST return `Arc<Self>`.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            flows: Mutex::new(VecDeque::with_capacity(64)),
        })
    }

    /// Push ONE judged flow. `cc`, `asn`, and `flag` are OVERWRITTEN with engine derivations —
    /// [`super::geoip::country_code`] and [`super::asn::as_name`] of the flow's `ip`
    /// (unparseable/unknown → `""` → 🌐 / skipped by the ASN fold), then [`flag_emoji`] of that
    /// `cc` — never wire input. Past [`FLOW_CAP`] the oldest record is evicted (bounded RAM; the
    /// ring is a live panel, not a ledger).
    pub fn record(&self, rec: FlowRecord) {
        let mut rec = rec;
        let dest = rec.ip.parse::<std::net::IpAddr>().ok();
        rec.cc = dest.and_then(super::geoip::country_code).unwrap_or_default();
        rec.asn = dest.and_then(super::asn::as_name).unwrap_or_default();
        rec.flag = flag_emoji(&rec.cc);
        self.push(rec);
    }

    /// The retained flows, NEWEST FIRST (the live panel renders top-down). A copy — the lock is held
    /// only for the clone, never across the FFI render.
    pub fn snapshot(&self) -> Vec<FlowRecord> {
        let flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        flows.iter().rev().cloned().collect()
    }

    /// Retained flow count (`0..=`[`FLOW_CAP`]).
    pub fn count(&self) -> i64 {
        let flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        flows.len() as i64
    }

    /// Drop every retained flow (the panel's "clear log").
    pub fn clear(&self) {
        let mut flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        flows.clear();
    }

    /// The COUNTRY fold — ALLOWED flows grouped by `cc`, count DESC (ties: `cc` ASC, deterministic),
    /// top [`SUMMARY_LIMIT`]. Unknown-country flows (`cc == ""`) stay as the 🌐 bucket, per the Dao.
    pub fn country_summary(&self) -> Vec<CountrySummary> {
        let flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        let mut groups: HashMap<String, (i64, i64, i64)> = HashMap::new();
        for f in flows.iter() {
            if !matches!(f.verdict, WardenVerdict::Allow) {
                continue;
            }
            let g = groups.entry(f.cc.to_ascii_lowercase()).or_insert((0, 0, 0));
            g.0 += 1;
            g.1 += f.up;
            g.2 += f.down;
        }
        drop(flows);
        let mut out: Vec<CountrySummary> = groups
            .into_iter()
            .map(|(cc, (count, up, down))| CountrySummary {
                flag: flag_emoji(&cc),
                cc,
                count,
                up,
                down,
            })
            .collect();
        out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.cc.cmp(&b.cc)));
        out.truncate(SUMMARY_LIMIT);
        out
    }

    /// The ASN fold — ALLOWED flows with a KNOWN AS name (`asn != ""`, per the Dao) grouped by it,
    /// count DESC (ties: `asn` ASC), top [`SUMMARY_LIMIT`].
    pub fn asn_summary(&self) -> Vec<AsnSummary> {
        let flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        let mut groups: HashMap<String, (i64, i64, i64)> = HashMap::new();
        for f in flows.iter() {
            if !matches!(f.verdict, WardenVerdict::Allow) || f.asn.is_empty() {
                continue;
            }
            let g = groups.entry(f.asn.clone()).or_insert((0, 0, 0));
            g.0 += 1;
            g.1 += f.up;
            g.2 += f.down;
        }
        drop(flows);
        let mut out: Vec<AsnSummary> = groups
            .into_iter()
            .map(|(asn, (count, up, down))| AsnSummary {
                asn,
                count,
                up,
                down,
            })
            .collect();
        out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.asn.cmp(&b.asn)));
        out.truncate(SUMMARY_LIMIT);
        out
    }

    /// THE PER-APP FOLD (W-D TIER-3 INSPECTOR, #79) — every retained flow grouped by `uid` into an
    /// [`AppFlowSummary`], so the inspector lists the apps the firewall has judged. Counts allowed +
    /// denied (the whole picture), distinct destination IPs + countries, byte sums, and the newest
    /// timestamp. Sorted most-recently-active FIRST (ties: flow count DESC, then uid ASC — deterministic).
    /// Iterating the ring OLDEST→newest means later (newer) records win the "most recent name / ts"
    /// fields naturally. Capped at [`INSPECTOR_LIMIT`].
    pub fn app_flow_summary(&self) -> Vec<AppFlowSummary> {
        let flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        // Per-uid accumulator: (app, flows, allowed, denied, distinct-ip set, distinct-cc set, up, down,
        // last_ts). The sets dedupe endpoints/countries without a second pass.
        use std::collections::HashSet;
        struct Acc {
            app: String,
            flows: i64,
            allowed: i64,
            denied: i64,
            ips: HashSet<String>,
            ccs: HashSet<String>,
            up: i64,
            down: i64,
            last_ts: i64,
        }
        let mut groups: HashMap<i32, Acc> = HashMap::new();
        for f in flows.iter() {
            let g = groups.entry(f.uid).or_insert_with(|| Acc {
                app: String::new(),
                flows: 0,
                allowed: 0,
                denied: 0,
                ips: HashSet::new(),
                ccs: HashSet::new(),
                up: 0,
                down: 0,
                last_ts: 0,
            });
            g.flows += 1;
            if matches!(f.verdict, WardenVerdict::Allow) {
                g.allowed += 1;
            } else {
                g.denied += 1;
            }
            g.ips.insert(f.ip.clone());
            g.ccs.insert(f.cc.clone());
            g.up += f.up;
            g.down += f.down;
            // Iterating oldest→newest: the last non-empty name seen (the newest) wins.
            if !f.app.is_empty() {
                g.app = f.app.clone();
            }
            if f.ts_ms > g.last_ts {
                g.last_ts = f.ts_ms;
            }
        }
        drop(flows);
        let mut out: Vec<AppFlowSummary> = groups
            .into_iter()
            .map(|(uid, a)| AppFlowSummary {
                uid,
                app: a.app,
                flows: a.flows,
                allowed: a.allowed,
                denied: a.denied,
                distinct_ips: a.ips.len() as i64,
                countries: a.ccs.len() as i64,
                up: a.up,
                down: a.down,
                last_ts: a.last_ts,
            })
            .collect();
        out.sort_by(|a, b| {
            b.last_ts
                .cmp(&a.last_ts)
                .then_with(|| b.flows.cmp(&a.flows))
                .then_with(|| a.uid.cmp(&b.uid))
        });
        out.truncate(INSPECTOR_LIMIT);
        out
    }

    /// THE PER-APP DESTINATION FOLD (W-D, #79) — the flows for ONE `uid` grouped by destination IP into
    /// a [`DestRecord`], so the inspector renders the WHOLE list of endpoints that app contacts (each with
    /// its GEO flag + ASN + resolved domain). Includes denied endpoints (`denied` = ANY flow to the IP was
    /// denied). Sorted hits DESC (ties: newest last_ts, then ip ASC). Later (newer) records win the
    /// most-recent domain/port/proto/carried fields. Capped at [`INSPECTOR_LIMIT`].
    pub fn app_destinations(&self, uid: i32) -> Vec<DestRecord> {
        let flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        // Per-IP accumulator, keyed on the destination IP string.
        struct Acc {
            cc: String,
            flag: String,
            asn: String,
            domain: String,
            port: u16,
            proto: u8,
            denied: bool,
            carried: bool,
            hits: i64,
            up: i64,
            down: i64,
            last_ts: i64,
        }
        let mut groups: HashMap<String, Acc> = HashMap::new();
        for f in flows.iter().filter(|f| f.uid == uid) {
            let g = groups.entry(f.ip.clone()).or_insert_with(|| Acc {
                cc: f.cc.clone(),
                flag: f.flag.clone(),
                asn: f.asn.clone(),
                domain: String::new(),
                port: f.port,
                proto: f.proto,
                denied: false,
                carried: f.carried,
                hits: 0,
                up: 0,
                down: 0,
                last_ts: 0,
            });
            g.hits += 1;
            g.up += f.up;
            g.down += f.down;
            if !matches!(f.verdict, WardenVerdict::Allow) {
                g.denied = true;
            }
            // Newest wins the most-recent fields (oldest→newest iteration).
            g.port = f.port;
            g.proto = f.proto;
            g.carried = f.carried;
            if !f.domain.is_empty() {
                g.domain = f.domain.clone();
            }
            if f.ts_ms > g.last_ts {
                g.last_ts = f.ts_ms;
            }
        }
        drop(flows);
        let mut out: Vec<DestRecord> = groups
            .into_iter()
            .map(|(ip, a)| DestRecord {
                ip,
                cc: a.cc,
                flag: a.flag,
                asn: a.asn,
                domain: a.domain,
                port: a.port,
                proto: a.proto,
                denied: a.denied,
                carried: a.carried,
                hits: a.hits,
                up: a.up,
                down: a.down,
                last_ts: a.last_ts,
            })
            .collect();
        out.sort_by(|a, b| {
            b.hits
                .cmp(&a.hits)
                .then_with(|| b.last_ts.cmp(&a.last_ts))
                .then_with(|| a.ip.cmp(&b.ip))
        });
        out.truncate(INSPECTOR_LIMIT);
        out
    }
}

// ===================================================================================================
// THE GLOBAL RING — the process-wide tracker instance (A5 slice-4, the datapath feed).
// ===================================================================================================

/// The ONE process-wide ring. Feed and render must observe the SAME instance: the datapath fills it
/// ([`feed`]), Kotlin pulls it ([`conn_tracker`]), the SLINT host reads it in-crate ([`global`]).
static GLOBAL: OnceLock<Arc<ConnTracker>> = OnceLock::new();

/// The process-wide tracker — lazily built on first touch, then one `Arc` clone per call.
pub fn global() -> Arc<ConnTracker> {
    GLOBAL.get_or_init(ConnTracker::new).clone()
}

/// The UniFFI accessor for the GLOBAL ring — the panel host calls THIS, not [`ConnTracker::new`]
/// (a fresh constructor is a private, forever-empty ring; the flows live in the instance the
/// datapath feeds).
#[uniffi::export]
pub fn conn_tracker() -> Arc<ConnTracker> {
    global()
}

/// The DATAPATH FEED — one judged flow into the global ring (A5 slice-4). Called from the
/// `tunnel::warden::verdict` bridge, the single choke point BOTH datapaths cross (the tunnel
/// loop's non-DNS gate and the netstack forwarder's per-flow `warden_allows`), so arming the feed
/// there covers every judgment without touching either loop.
///
/// Field honesty: `uid` is the verdict-path value (`-1` = unresolved); `app` stays `""`
/// (PackageManager is Kotlin's — the panel resolves uid → name at render); `up`/`down` are 0 (the
/// judge-time feed predates the bytes; per-flow byte attribution is banked); `ts_ms` is stamped
/// HERE (the feed IS the datapath's clock edge); `cc`/`asn`/`flag` are engine-derived inside
/// [`ConnTracker::record`]; `domain` is the verdict seam's effective qname (A4 — caller-known or
/// attributed, `None` ⇒ `""`). On the tunnel loop this fires per-PACKET (Stage-2-min holds no session
/// table); on the forwarder per-FLOW — session-collapse is future polish, [`FLOW_CAP`] bounds it.
pub(crate) fn feed(
    uid: i32,
    ip: std::net::IpAddr,
    port: u16,
    proto: u8,
    verdict: WardenVerdict,
    carried: bool,
    domain: Option<&str>,
) {
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    global().record(FlowRecord {
        uid,
        app: String::new(),
        ip: ip.to_string(),
        cc: String::new(),
        flag: String::new(),
        asn: String::new(),
        domain: domain.unwrap_or_default().to_owned(),
        port,
        proto,
        verdict,
        carried,
        up: 0,
        down: 0,
        ts_ms,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal allowed flow for `cc` — the fold tests vary only what they assert on.
    fn flow(cc: &str, verdict: WardenVerdict) -> FlowRecord {
        FlowRecord {
            uid: 10_001,
            app: "chrome".into(),
            ip: "93.184.216.34".into(),
            cc: cc.into(),
            flag: String::new(),
            asn: String::new(),
            domain: String::new(),
            port: 443,
            proto: 6,
            verdict,
            carried: verdict == WardenVerdict::Allow,
            up: 100,
            down: 1_000,
            ts_ms: 1_700_000_000_000,
        }
    }

    /// A5 GUARD -- `INSPECTOR_LIMIT` (= 128, tracker.rs:226) caps `app_flow_summary`, the per-app
    /// list the Warden inspector renders. The A5 inventory found it had a NUMBER and no test naming
    /// it: an uncapped fold over a busy device hands the UI an unbounded vector every refresh.
    ///
    /// Two arms, because length alone cannot see the failure that matters. The fold sorts
    /// most-recently-active FIRST and THEN truncates, so the cap must keep the NEWEST apps. A
    /// truncation applied before the sort -- or a sort in the wrong direction -- would hand the
    /// inspector the 128 STALEST apps at exactly the right length.
    #[test]
    fn inspector_limit_is_128_and_keeps_the_newest_apps() {
        let t = ConnTracker::new();
        let n = (INSPECTOR_LIMIT * 2) as u32;
        for i in 0..n {
            let mut f = flow("US", WardenVerdict::Allow);
            f.uid = 10_000 + i as i32;
            f.app = format!("app{i:04}");
            // Strictly increasing timestamps: higher i == more recent.
            f.ts_ms = 1_700_000_000_000 + i as i64;
            t.record(f);
        }

        let out = t.app_flow_summary();
        assert_eq!(
            out.len(),
            INSPECTOR_LIMIT,
            "the inspector list must saturate AT the cap, never above"
        );
        assert_eq!(
            out.first().map(|s| s.app.as_str()),
            Some(format!("app{:04}", n - 1).as_str()),
            "sorted most-recently-active FIRST -- the newest app leads"
        );
        let oldest_kept = format!("app{:04}", n - INSPECTOR_LIMIT as u32);
        assert_eq!(
            out.last().map(|s| s.app.as_str()),
            Some(oldest_kept.as_str()),
            "the cap keeps the NEWEST apps -- it must not hand back the stalest ones"
        );
    }

    #[test]
    fn flag_emoji_maps_iso_codes_and_falls_back_to_globe() {
        // The A5 compile-confirm triple (GENESIS-pillar-warden.md:253): US → 🇺🇸, de → 🇩🇪 (case-
        // insensitive), and every non-2-ASCII-letter input → 🌐.
        assert_eq!(flag_emoji("US"), "\u{1F1FA}\u{1F1F8}"); // 🇺🇸
        assert_eq!(flag_emoji("de"), "\u{1F1E9}\u{1F1EA}"); // 🇩🇪
        assert_eq!(flag_emoji("Jp"), "\u{1F1EF}\u{1F1F5}"); // 🇯🇵 mixed case
        for bad in ["", "u", "usa", "1a", "a1", "??", "🇺🇸"] {
            assert_eq!(flag_emoji(bad), "\u{1F310}", "{bad:?} must yield the globe");
        }
    }

    #[test]
    fn record_derives_cc_flag_and_asn_from_ip_never_the_wire() {
        let t = ConnTracker::new();
        // Wire LIES three times — German cc, German flag, AND a fake AS name on a flow to 8.8.8.8
        // (the stable US/GOOGLE anchor). All three must come out engine-derived.
        let mut r = flow("de", WardenVerdict::Allow);
        r.ip = "8.8.8.8".into();
        r.flag = "\u{1F1E9}\u{1F1EA}".into();
        r.asn = "EVILNET".into();
        t.record(r);
        // Unparseable destination → unknown, never a guess (and never a panic).
        let mut u = flow("de", WardenVerdict::Allow);
        u.ip = "not-an-ip".into();
        u.asn = "EVILNET".into();
        t.record(u);
        let snap = t.snapshot(); // newest first: [unparseable, 8.8.8.8]
        assert_eq!(snap.len(), 2);
        assert_eq!((snap[1].cc.as_str(), snap[1].flag.as_str()), ("us", "\u{1F1FA}\u{1F1F8}"));
        assert_eq!(snap[1].asn, "GOOGLE");
        assert_eq!((snap[0].cc.as_str(), snap[0].flag.as_str()), ("", "\u{1F310}"));
        assert_eq!(snap[0].asn, "", "unparseable ip yields the honest blank, not a stale lie");
    }

    #[test]
    fn record_folds_live_derived_countries_and_networks() {
        // Slices 2+3 armed, end to end: real anchors in, BOTH "where your data goes" folds out.
        let t = ConnTracker::new();
        for ip in ["8.8.8.8", "8.8.4.4", "193.0.10.1"] {
            let mut r = flow("", WardenVerdict::Allow);
            r.ip = ip.into();
            t.record(r);
        }
        let s = t.country_summary();
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].cc.as_str(), s[0].count), ("us", 2));
        assert_eq!((s[1].cc.as_str(), s[1].count), ("nl", 1));
        assert_eq!(s[0].flag, "\u{1F1FA}\u{1F1F8}");
        let a = t.asn_summary();
        assert_eq!(a.len(), 2);
        assert_eq!((a[0].asn.as_str(), a[0].count), ("GOOGLE", 2));
        assert!(
            a[1].asn.starts_with("RIPE-NCC-AS") && a[1].count == 1,
            "the RIPE anchor announces as AS3333 RIPE-NCC-AS…, got {:?}",
            a[1].asn
        );
    }

    #[test]
    fn ring_evicts_oldest_past_the_cap() {
        let t = ConnTracker::new();
        for i in 0..(FLOW_CAP + 10) {
            let mut r = flow("us", WardenVerdict::Allow);
            r.ts_ms = i as i64;
            t.record(r);
        }
        assert_eq!(t.count(), FLOW_CAP as i64, "hard cap holds");
        let snap = t.snapshot();
        // newest-first: head is the LAST record, tail is the oldest SURVIVOR (the first 10 evicted).
        assert_eq!(snap[0].ts_ms, (FLOW_CAP + 9) as i64);
        assert_eq!(snap[snap.len() - 1].ts_ms, 10);
    }

    #[test]
    fn snapshot_is_newest_first_and_clear_empties() {
        let t = ConnTracker::new();
        for ts in [1i64, 2, 3] {
            let mut r = flow("us", WardenVerdict::Allow);
            r.ts_ms = ts;
            t.record(r);
        }
        let snap = t.snapshot();
        assert_eq!(
            snap.iter().map(|f| f.ts_ms).collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
        t.clear();
        assert_eq!(t.count(), 0);
        assert!(t.snapshot().is_empty());
    }

    #[test]
    fn country_summary_folds_allowed_flows_only_sorted_and_capped() {
        // Hand-authored `cc` via the `push` seam (fold logic under test, not GeoIP derivation).
        let t = ConnTracker::new();
        // 3× US allowed, 2× DE allowed (one lowercase — case folds), 1× US DENIED (excluded),
        // 1× unknown (globe bucket kept).
        for _ in 0..3 {
            t.push(flow("US", WardenVerdict::Allow));
        }
        t.push(flow("DE", WardenVerdict::Allow));
        t.push(flow("de", WardenVerdict::Allow));
        t.push(flow("US", WardenVerdict::DenyByFirewall));
        t.push(flow("", WardenVerdict::Allow));
        let s = t.country_summary();
        assert_eq!(s.len(), 3);
        assert_eq!((s[0].cc.as_str(), s[0].count), ("us", 3));
        assert_eq!((s[1].cc.as_str(), s[1].count), ("de", 2));
        assert_eq!((s[2].cc.as_str(), s[2].count), ("", 1), "unknown bucket kept");
        assert_eq!(s[0].flag, "\u{1F1FA}\u{1F1F8}");
        assert_eq!(s[2].flag, "\u{1F310}");
        // byte sums fold per group: 3 allowed US flows × (100 up, 1000 down).
        assert_eq!((s[0].up, s[0].down), (300, 3_000));
        // deterministic ties + the LIMIT-7 cap: 9 distinct single-flow countries → 7 rows survive
        // after the 3 above, ordered by count DESC then cc ASC.
        let t2 = ConnTracker::new();
        for cc in ["ir", "hu", "gr", "fr", "ee", "dk", "cz", "bg", "at"] {
            t2.push(flow(cc, WardenVerdict::Allow));
        }
        let s2 = t2.country_summary();
        assert_eq!(s2.len(), SUMMARY_LIMIT);
        assert_eq!(
            s2.iter().map(|r| r.cc.as_str()).collect::<Vec<_>>(),
            vec!["at", "bg", "cz", "dk", "ee", "fr", "gr"],
            "equal counts tie-break cc ASC — a stable panel, never a shuffle"
        );
    }

    #[test]
    fn global_ring_is_one_instance_shared_with_the_ffi_accessor() {
        let a = global();
        let b = conn_tracker();
        assert!(
            Arc::ptr_eq(&a, &b),
            "feed, FFI pull, and SLINT read must observe ONE ring"
        );
    }

    #[test]
    fn feed_stamps_the_clock_and_derives_attribution() {
        let _w = crate::lock_warden_global(); // ring feeders serialize on the crate gate (lib.rs)
        let g = global();
        g.clear();
        feed(
            1000,
            "8.8.8.8".parse().unwrap(),
            443,
            6,
            WardenVerdict::Allow,
            true,
            Some("dns.google"),
        );
        let snap = g.snapshot();
        assert_eq!(snap.len(), 1);
        let f = &snap[0];
        assert_eq!((f.uid, f.port, f.proto), (1000, 443, 6));
        assert_eq!((f.cc.as_str(), f.asn.as_str()), ("us", "GOOGLE"));
        assert_eq!(f.app, "", "uid→name is Kotlin's — the engine never guesses");
        assert_eq!(f.domain, "dns.google", "the A4 domain rides the fed row verbatim");
        assert_eq!((f.up, f.down), (0, 0), "judge-time feed predates the bytes");
        assert!(
            f.ts_ms > 1_700_000_000_000,
            "feed stamps a real wall clock, got {}",
            f.ts_ms
        );
        g.clear(); // leave no residue in the process-global
    }

    #[test]
    fn asn_summary_skips_unknown_asn_and_denied_flows() {
        let t = ConnTracker::new();
        let mut a = flow("us", WardenVerdict::Allow);
        a.asn = "CLOUDFLARENET".into();
        t.push(a.clone());
        t.push(a.clone());
        let mut b = flow("us", WardenVerdict::DenyByFirewall);
        b.asn = "CLOUDFLARENET".into();
        t.push(b); // denied — excluded
        t.push(flow("us", WardenVerdict::Allow)); // asn "" — excluded (Dao: asName != '')
        let s = t.asn_summary();
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].asn.as_str(), s[0].count), ("CLOUDFLARENET", 2));
        assert_eq!((s[0].up, s[0].down), (200, 2_000));
    }

    /// A flow authored for the PER-APP folds — full control of uid/ip/app/verdict/ts (hand-pushed via
    /// [`ConnTracker::push`], so the fold logic is under test, not the GeoIP derivation).
    fn app_flow(uid: i32, ip: &str, app: &str, cc: &str, verdict: WardenVerdict, ts: i64) -> FlowRecord {
        let mut r = flow(cc, verdict);
        r.uid = uid;
        r.ip = ip.into();
        r.app = app.into();
        r.flag = flag_emoji(cc);
        r.ts_ms = ts;
        r
    }

    #[test]
    fn app_flow_summary_groups_by_uid_counts_verdicts_and_distincts() {
        // W-D #79: two apps. uid 10001 (chrome) — 2 IPs (one hit twice), 1 denied, 2 countries.
        // uid 10002 (maps) — 1 IP, all allowed, newest ts (sorts FIRST).
        let t = ConnTracker::new();
        t.push(app_flow(10_001, "8.8.8.8", "chrome", "us", WardenVerdict::Allow, 100));
        t.push(app_flow(10_001, "8.8.8.8", "chrome", "us", WardenVerdict::Allow, 200));
        t.push(app_flow(10_001, "1.1.1.1", "chrome", "au", WardenVerdict::DenyByFirewall, 300));
        t.push(app_flow(10_002, "9.9.9.9", "maps", "us", WardenVerdict::Allow, 900));
        let s = t.app_flow_summary();
        assert_eq!(s.len(), 2);
        // most-recently-active first: maps (ts 900) before chrome (ts 300).
        assert_eq!((s[0].uid, s[0].app.as_str()), (10_002, "maps"));
        assert_eq!((s[0].flows, s[0].allowed, s[0].denied), (1, 1, 0));
        assert_eq!((s[0].distinct_ips, s[0].countries), (1, 1));
        let c = &s[1];
        assert_eq!((c.uid, c.app.as_str()), (10_001, "chrome"));
        assert_eq!((c.flows, c.allowed, c.denied), (3, 2, 1));
        assert_eq!((c.distinct_ips, c.countries), (2, 2), "2 distinct IPs, 2 distinct countries");
        assert_eq!(c.last_ts, 300, "the newest flow's ts wins");
        // byte sums fold across the app's flows (3 × 100 up, 3 × 1000 down).
        assert_eq!((c.up, c.down), (300, 3_000));
    }

    #[test]
    fn app_destinations_folds_one_apps_endpoints_by_ip() {
        // W-D #79: chrome (uid 10001) talks to 8.8.8.8 twice (one denied → endpoint tinted denied) and
        // 1.1.1.1 once; a DIFFERENT app's flow to 8.8.8.8 must NOT leak in. Newest domain/port win.
        let t = ConnTracker::new();
        let mut a1 = app_flow(10_001, "8.8.8.8", "chrome", "us", WardenVerdict::Allow, 100);
        a1.domain = "old.example".into();
        a1.port = 80;
        t.push(a1);
        let mut a2 = app_flow(10_001, "8.8.8.8", "chrome", "us", WardenVerdict::DenyByFirewall, 200);
        a2.domain = "dns.google".into();
        a2.port = 443;
        t.push(a2);
        t.push(app_flow(10_001, "1.1.1.1", "chrome", "au", WardenVerdict::Allow, 150));
        t.push(app_flow(10_002, "8.8.8.8", "maps", "us", WardenVerdict::Allow, 300)); // other app
        let d = t.app_destinations(10_001);
        assert_eq!(d.len(), 2, "only chrome's two distinct endpoints — maps excluded");
        // hits DESC: 8.8.8.8 (2 hits) before 1.1.1.1 (1 hit).
        assert_eq!((d[0].ip.as_str(), d[0].hits), ("8.8.8.8", 2));
        assert!(d[0].denied, "one flow to 8.8.8.8 was denied → endpoint reads denied");
        assert_eq!(d[0].domain, "dns.google", "newest non-empty domain wins");
        assert_eq!(d[0].port, 443, "newest port wins");
        assert_eq!((d[0].up, d[0].down), (200, 2_000), "byte sums fold across the two hits");
        assert_eq!((d[1].ip.as_str(), d[1].hits, d[1].denied), ("1.1.1.1", 1, false));
        // an app with no flows folds to nothing (never a panic).
        assert!(t.app_destinations(99_999).is_empty());
    }
}
