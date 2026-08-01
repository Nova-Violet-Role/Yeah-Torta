/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **CP-Centauri-Discovery** — the LIVING watch-list. Centauri ships a large STATIC curated corpus
//! ([`crate::mirror::localcdn`], 65 hosts / 1950 maps) of cloakable CDN hosts. This layer makes the
//! watch-list GROW WITH THE USER: every resolved host is observed on the datapath, and a
//! content-delivery-SHAPED host PAST the static corpus is recorded as DISCOVERED, hit-counted, and
//! persisted to `<dir>/centauri-discovered.tsv` — so the encyclopedia is a living thing across boots,
//! never a frozen seed. This is the Centauri twin of the Underground Layer's "grows with you" faculty
//! ([`crate::underground`]), and the engine-core answer to the sibling nautilus host-only discovery.
//!
//! ## Pure observation — never an answer
//! Discovery WATCHES + remembers; it NEVER changes a DNS answer. The resolver decides block/forward;
//! this only classifies the qname and tallies it. A discovered host is a candidate the operator can
//! later map/serve offline — surfacing it is the whole point, not enforcement. So the feed is
//! independent of the Centauri cloak toggle (the encyclopedia sees even when the cloak is disarmed).
//!
//! ## Classification (conservative, marker-gated)
//! A host is content-delivery-SHAPED iff it bears a distinctive CDN INFRASTRUCTURE token as a
//! dot-label ([`INFRA_TOKENS`]: `cloudfront`/`akamai…`/`fastly`/`jsdelivr`/…) OR its LEADING dot-label
//! is a curated content subdomain word ([`CDN_LABELS`]: `cdn`/`static`/`assets`/…). Hosts already in
//! the static corpus are NOT discoveries (they are already watched); reverse-DNS (`*.arpa`), the local
//! suffixes, and IP-literals are skipped. The markers are studied public facts, re-expressed as our
//! own Rust tables — no source is copied.
//!
//! ## Durability
//! A TSV v1 store (`centauri-discovered.tsv`) in the SAME durable dir the resolver cache + Underground
//! ledger use, armed by the same boot edge ([`crate::resolver_rehydrate_cache`] → [`arm`]). Writes are
//! change-gated (FNV-1a XOR-fold signature, order-independent) + atomic (tmp + rename). A hostile flood
//! of unique names is bounded by [`MAX_DISCOVERED`] (the first N unique hosts win; `observed_total`
//! still counts every observation). Every path is FAIL-OPEN: a poisoned lock, missing dir, or corrupt
//! row degrades to "nothing discovered yet", never a panic and never a changed answer.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

/// TSV wire version (bump only on an incompatible column change; [`parse_body`] is fail-open per row).
const STORE_VERSION: &str = "v1";
/// The durable store file name, beside `underground-ledger.tsv` in the resolver's durable dir.
const STORE_FILE_NAME: &str = "centauri-discovered.tsv";
/// The hard ceiling on distinct discovered hosts — a flood of unique cdn-shaped names cannot grow the
/// store unbounded. Once reached, new hosts are counted (`observed_total`) but not stored.
const MAX_DISCOVERED: usize = 4096;

/// ★ #65 — how many times a discovered host must RECUR before it earns a cloak row ([`promotable`]).
/// Classification already proved the host is CDN-shaped; this proves it is part of how the user
/// actually browses. At 1 a single page-load could author a permanent catalog row; 3 means the host
/// came back across separate loads or app launches.
const MIN_PROMOTION_HITS: u64 = 3;

/// ★ #65 — the hard ceiling on PROMOTED hosts. Every promotion becomes a device-signed catalog row,
/// so this bounds catalog-authoring work no matter how many unique cdn-shaped names appear. Well under
/// [`MAX_DISCOVERED`]: the ledger may remember thousands of candidates, but only the hosts the user
/// demonstrably depends on are carried into the served catalog.
const MAX_PROMOTED: usize = 256;

/// WHICH classifier lane witnessed the host — provenance, the store's column 5. `Infra` (a known CDN
/// infrastructure token) is a stronger signal than `Label` (a cdn-ish leading subdomain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    /// Matched a distinctive CDN infrastructure token ([`INFRA_TOKENS`]) as a dot-label.
    Infra,
    /// The LEADING dot-label was a curated content-delivery word ([`CDN_LABELS`]).
    Label,
}

impl Marker {
    fn slug(self) -> &'static str {
        match self {
            Marker::Infra => "infra",
            Marker::Label => "label",
        }
    }
    fn from_slug(s: &str) -> Option<Marker> {
        match s {
            "infra" => Some(Marker::Infra),
            "label" => Some(Marker::Label),
            _ => None,
        }
    }
}

/// Distinctive CDN infrastructure tokens — a host bearing one of these inside a dot-label is almost
/// certainly content-delivery edge infrastructure. Matched as a per-label substring so the family
/// variants collapse (`akamai` catches `akamaized`/`akamaiedge`/`akamaihd`). Studied public facts.
/// ★ #87 — service labels that are NEVER content delivery, whichever operator hosts them.
///
/// Checked as WHOLE LABELS before [`INFRA_TOKENS`], so an operator token (`cloudflare`, `gstatic`, …)
/// can never promote a telemetry/analytics/challenge/NAT-traversal endpoint onto the cloak roster.
/// Every entry is a service Centauri can never hold a signed catalog asset for: they serve dynamic,
/// per-request, or non-HTTP payloads by definition, so cloaking one can only ever break a page.
///
/// Derived from what the device actually promoted (see the veto site in [`classify`]) plus the
/// obvious siblings of each. Kept deliberately SHORT and whole-label — a broad or substring list would
/// start vetoing real CDNs, which is the failure mode in the other direction.
const NEVER_DELIVERY_LABELS: &[&str] = &[
    "stun",       // WebRTC NAT traversal — not even HTTP
    "turn",       // the STUN sibling (relay)
    "nel",        // Network Error Logging beacons
    "challenges", // Turnstile / bot challenges — dynamic per request
    "insights",   // analytics beacons
    "analytics",
    "telemetry",
    "beacon",
    "metrics",
    "collect", // the common analytics collector label
    // Operator-fused analytics brands: the service word is WELDED INTO the label, so the whole-label
    // rule above cannot see it (`static.cloudflareinsights.com` -> label `cloudflareinsights`, which
    // equals neither `insights` nor `cloudflare`). Measured on device — both this and its apex were
    // promoted. Listed explicitly rather than relaxing the rule to substring matching, which would
    // start vetoing real CDNs (`cdn.stunning-assets.net` must survive `stun`).
    "cloudflareinsights",
];

const INFRA_TOKENS: &[&str] = &[
    "akamai",
    "edgekey",
    "edgesuite",
    "llnwd",
    "cloudfront",
    "fastly",
    "cloudflare",
    "cdnjs",
    "jsdelivr",
    "unpkg",
    "gstatic",
    "bunnycdn",
    "stackpath",
    "keycdn",
    "azureedge",
    "cachefly",
    "cdn77",
    "cdnetworks",
    "netdna",
    "wpengine",
    "wp-cdn",
    "fbcdn",
    "twimg",
];

/// Curated content-delivery LEADING-label words — the first dot-label that signals a CDN subdomain.
const CDN_LABELS: &[&str] = &[
    "cdn", "cdns", "static", "assets", "asset", "media", "img", "images", "content", "cache", "edge",
    "js", "css", "fonts", "ajax", "static1", "static2",
];

struct Entry {
    host: String,
    hits: u64,
    first_seen: u64,
    last_seen: u64,
    marker: Marker,
}

#[derive(Default)]
struct Store {
    by_host: HashMap<String, Entry>,
    /// Total cdn-shaped observations EVER (survives the cap + any pruning; persisted in `#meta`). The
    /// "the encyclopedia has watched N times" volume, distinct from the distinct-host count.
    observed_total: u64,
}

static STORE: OnceLock<RwLock<Store>> = OnceLock::new();
/// Fast gate: false until [`arm`] binds a durable dir (a cold build never takes the store lock).
static ARMED: AtomicBool = AtomicBool::new(false);
static STORE_DIR: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();
/// Signature of the store at the last persisted write (change gate — identical store ⇒ no IO).
static LAST_PERSIST_SIG: AtomicU64 = AtomicU64::new(0);

fn store() -> &'static RwLock<Store> {
    STORE.get_or_init(|| RwLock::new(Store::default()))
}

fn store_dir_cell() -> &'static RwLock<Option<PathBuf>> {
    STORE_DIR.get_or_init(|| RwLock::new(None))
}

/// Wall-clock unix seconds; 0 on a clock before the epoch (fail-safe, never a panic).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Canonical store key: lower-cased, trailing root-dot stripped, surrounding space trimmed.
fn normalize(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

// ── Classification ────────────────────────────────────────────────────────────────────────────────

/// Is `host` an IPv4/IPv6 literal (never a discoverable CDN NAME)?
fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Classify a NORMALIZED host as content-delivery-shaped. `None` ⇒ not a CDN shape. The marker is the
/// provenance lane. Conservative: requires ≥2 dot-labels, skips reverse-DNS + the local/onion suffixes
/// + IP-literals, and matches only the curated marker tables.
fn classify(host: &str) -> Option<Marker> {
    if host.is_empty() || is_ip_literal(host) {
        return None;
    }
    // Reverse-DNS + non-routable/local suffixes are never public CDNs.
    if host.ends_with(".arpa")
        || host.ends_with(".local")
        || host.ends_with(".onion")
        || host.ends_with(".localhost")
    {
        return None;
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    // ★ #87 — VETO FIRST: a NON-DELIVERY SERVICE LABEL beats any operator token.
    //
    // MEASURED ON DEVICE 2026-07-26, `centauri-discovered.tsv` — six of seven promoted hosts:
    //   a.nel.cloudflare.com  challenges.cloudflare.com  cloudflareinsights.com
    //   static.cloudflareinsights.com  stun.cloudflare.com          -> all classified `infra`
    // They matched because [`INFRA_TOKENS`] carries `"cloudflare"`, and an OPERATOR NAME IS NOT A
    // CONTENT-DELIVERY SIGNAL. Cloudflare runs a CDN *and* Turnstile challenges, NEL telemetry,
    // Insights analytics, and STUN. `akamai`/`fastly`/`cloudfront` mostly appear in edge hostnames, but
    // `cloudflare` sits in the apex `cloudflare.com`, so the token swallows the company's whole service
    // surface. `stun.cloudflare.com` is not even HTTP.
    //
    // Cloaking these is what broke monochrome.tf's Hot & New (#78): Centauri claimed
    // `challenges.cloudflare.com`, could not serve a dynamic challenge, and the page died.
    // #78's `serve_miss_should_uncloak` RECOVERS from that — and stays, because no list is ever
    // complete — but recovery still costs one broken load per host per install. This declines the
    // mistake instead of repairing it.
    //
    // Matched as a WHOLE LABEL, never a substring: `cdn.stunning-assets.net` must keep its cloak, so
    // `stun` may not match inside `stunning`. Whole-label equality is the difference between a veto and
    // a new false negative.
    for label in &labels {
        if NEVER_DELIVERY_LABELS.contains(label) {
            return None;
        }
    }
    // STRONG signal first: any label carries a distinctive infra token.
    for label in &labels {
        for tok in INFRA_TOKENS {
            if label.contains(tok) {
                return Some(Marker::Infra);
            }
        }
    }
    // STRONG signal, REGISTRABLE-DOMAIN lane: the second-level label itself carries `cdn`. Measured
    // need — the app CDNs are named at the DOMAIN, not the subdomain, so the lead-label lane above is
    // structurally blind to them:
    //   · `scontent.cdninstagram.com`  lead `scontent`     ⇒ missed
    //   · `p16-sign-va.tiktokcdn.com`  lead `p16-sign-va`  ⇒ missed
    //   · `v16-webapp.tiktokcdn-us.com`                    ⇒ missed
    // Every one is read-side asset delivery, and `INFRA_TOKENS` only ever caught them one vendor at a
    // time (`fbcdn`, `twimg` are literally that pattern, enumerated by hand). Reading the SLD instead
    // generalizes the same fact. Deliberately the SLD alone and not a whole-host `contains`, so a
    // `cdn` appearing in some deeper label cannot promote a host on its own.
    if labels.len() >= 2 {
        let sld = labels[labels.len() - 2];
        if sld.contains("cdn") {
            return Some(Marker::Infra);
        }
    }
    // MEDIUM signal: the LEADING label is a curated content word, possibly carrying a region/shard
    // suffix (`images-na`, `img-01`, `assets-eu`). Real CDN subdomains are routinely sharded that way,
    // and an exact-match-only test measurably missed them: browsing amazon.com emitted
    // `images-na.ssl-images-amazon.com` and the encyclopedia recorded NO row for it. Matching the lead
    // label's leading ALPHABETIC run admits every shard of a word we already trust while staying
    // conservative — a plain `mail.`/`login.`/`m.` lead still fails, and a stem is only ever accepted
    // if the WHOLE word is in the curated table. Kept as a strict SUPERSET of the previous law (the
    // `starts_with("cdn")` arm is retained verbatim) so no host that classified before stops doing so.
    // The leading label only — a mid-host `static` is still not a delivery signal.
    let lead = labels[0];
    let stem = &lead[..lead
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(lead.len())];
    if CDN_LABELS.contains(&lead) || CDN_LABELS.contains(&stem) || lead.starts_with("cdn") {
        return Some(Marker::Label);
    }
    None
}

// ── Feed ──────────────────────────────────────────────────────────────────────────────────────────

/// Observe one resolved host on the datapath. NO-OP until [`arm`]. `already_static` = the host is
/// already in the static LocalCDN corpus (a WATCHED host, never a discovery). A non-cdn-shaped host is
/// ignored. Fail-open: a poisoned lock drops the observation, never a panic. Persists change-gated.
pub(crate) fn observe(host: &str, already_static: bool) {
    if !armed() || already_static {
        return;
    }
    let norm = normalize(host);
    let Some(marker) = classify(&norm) else {
        return;
    };
    let now = now_secs();
    // Did THIS observation carry the host over the promotion line? Captured inside the guard, acted on
    // after it drops — `promotable()` takes the same lock and would deadlock if called while held.
    let mut crossed = false;
    {
        let Ok(mut g) = store().write() else {
            return;
        };
        g.observed_total = g.observed_total.saturating_add(1);
        // `contains_key` first (its borrow ends immediately) so the cap check + insert in the else
        // branch are borrow-clean — a `get_mut`-scrutinee whose borrow spans the else trips NLL.
        if g.by_host.contains_key(&norm) {
            if let Some(e) = g.by_host.get_mut(&norm) {
                e.hits = e.hits.saturating_add(1);
                e.last_seen = now;
                // Exactly ON the line, so the republish happens once per host, not on every later hit.
                crossed = e.hits == MIN_PROMOTION_HITS;
            }
        } else if g.by_host.len() < MAX_DISCOVERED {
            g.by_host.insert(
                norm.clone(),
                Entry {
                    host: norm,
                    hits: 1,
                    first_seen: now,
                    last_seen: now,
                    marker,
                },
            );
        }
        // Capped (else path falls through): the observation still counts, but no new row is stored.
    }
    persist();

    // ★ #65 · LIVE promotion. Without this the promoted set only ever reached the DNS plane when the
    // catalog armed (`mirror/object.rs`), so a host that earned promotion in the MIDDLE of a browsing
    // session kept resolving to the real CDN for the rest of that session — the request never reached
    // Centauri, and the asset could never be absorbed. Measured: `cdn.cookielaw.org` (11 hits) and
    // `edge.aditude.io` (6 hits) sat far above the threshold in the discovery ledger while the cloak
    // stayed frozen, and neither was ever absorbed. Publishing on the crossing closes that window.
    //
    // The FULL promotable set is republished, not just the new host: `publish_promoted_cloak` REPLACES
    // the set, so sending one host would drop everything already cloaked.
    #[cfg(feature = "mirror")]
    if crossed {
        let promoted = promotable();
        if !promoted.is_empty() {
            crate::mirror::localcdn::publish_promoted_cloak(promoted);
        }
    }
    #[cfg(not(feature = "mirror"))]
    let _ = crossed;
}

// ── Snapshot readers (the dashboard fold) ───────────────────────────────────────────────────────────

pub(crate) fn armed() -> bool {
    ARMED.load(Ordering::Acquire)
}

/// Distinct discovered hosts (the dashboard's "M discovered" count).
pub(crate) fn count() -> u64 {
    store()
        .read()
        .map(|g| g.by_host.len() as u64)
        .unwrap_or(0)
}

/// Cumulative cdn-shaped observations ever (the "grows with you" volume).
pub(crate) fn observed_total() -> u64 {
    store().read().map(|g| g.observed_total).unwrap_or(0)
}

/// The top-N discovered hosts by hit count (for a future roster surface). Ties break by host name so
/// the order is deterministic + host-testable.
pub(crate) fn top(n: usize) -> Vec<(String, u64)> {
    let Ok(g) = store().read() else {
        return Vec::new();
    };
    let mut rows: Vec<(String, u64)> = g.by_host.values().map(|e| (e.host.clone(), e.hits)).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(n);
    rows
}

/// ★ #65 PROMOTION — the discovered hosts that have EARNED a cloak row in the living catalog.
///
/// Discovery alone only ever remembered NAMES: it observed, classified and persisted, but nothing
/// crossed from the candidate ledger into the served catalog, so a CDN met while browsing was
/// recorded and then still fetched from the real CDN forever. This is the crossing.
///
/// The law, and why each half of it is here:
///
/// * **`MIN_PROMOTION_HITS`** — a host must RECUR before it earns a row. Classification already
///   proved the host is CDN-shaped; the hit count proves it is actually part of how this user
///   browses, rather than a single beacon or a one-off redirect. Promoting on first sight would let
///   one page-load author a permanent catalog row.
/// * **`MAX_PROMOTED`** — a hard ceiling, because every promoted host becomes a SIGNED catalog row.
///   A flood of unique cdn-shaped names must not be able to grow catalog-authoring work without
///   bound. Beyond the cap the highest-hit hosts win (the ones the user actually depends on).
/// * **hits-desc then host-asc** — the same deterministic order as [`top`], so the promoted set is
///   reproducible and host-testable rather than HashMap-walk-dependent.
///
/// PROMOTION DOES NOT FETCH ANYTHING. The row it earns carries `content_hash = 0` — "the redirect is
/// armed, but nothing is cached until a real request self-fills it" (`mirror/object.rs:879`). So the
/// FIRST request for a promoted host self-fills through the ≤1 fetch-once crown and every request
/// after it is served from this device with ZERO egress. That is the whole doctrine: meet the CDN
/// once while online, absorb it, and never let it see the user again.
///
/// The caller is responsible for excluding hosts already in the static corpus — this returns the
/// discovered set on its own, and the corpus union happens at the single roster choke point.
pub(crate) fn promotable() -> Vec<String> {
    let Ok(g) = store().read() else {
        return Vec::new();
    };
    let mut rows: Vec<(&str, u64)> = g
        .by_host
        .values()
        .filter(|e| e.hits >= MIN_PROMOTION_HITS)
        .map(|e| (e.host.as_str(), e.hits))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    rows.truncate(MAX_PROMOTED);
    rows.into_iter().map(|(h, _)| h.to_string()).collect()
}

/// How many discovered hosts currently satisfy the promotion law (the dashboard's "absorbed" tally).
pub(crate) fn promotable_count() -> u64 {
    promotable().len() as u64
}

/// The living roster as a single pipe-delimited line of the top-`n` hostnames (hits-desc, host-asc). The
/// dashboard splits this back into a list to render the "grown from your traffic" surface. Hostnames are
/// `[a-z0-9.-]` by construction (classify() rejects everything else) so the `|` separator can never collide
/// with a host and the line is JSON-string-safe as-is. Empty when nothing has been observed yet.
pub(crate) fn discovered_line(n: usize) -> String {
    top(n).into_iter().map(|(h, _)| h).collect::<Vec<_>>().join("|")
}

// ── Durability ──────────────────────────────────────────────────────────────────────────────────────

fn store_path() -> Option<PathBuf> {
    store_dir_cell()
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|d| d.join(STORE_FILE_NAME)))
}

/// FNV-1a over each row's identity-bearing fields, XOR-folded per row so a HashMap walk order cannot
/// change the signature. The change gate for [`persist`].
fn store_signature(s: &Store) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut folded: u64 = s.observed_total.wrapping_mul(11);
    for e in s.by_host.values() {
        let mut h = FNV_OFFSET;
        let mut eat = |bytes: &[u8]| {
            for b in bytes {
                h ^= u64::from(*b);
                h = h.wrapping_mul(FNV_PRIME);
            }
        };
        eat(e.host.as_bytes());
        eat(&e.hits.to_le_bytes());
        eat(&e.first_seen.to_le_bytes());
        eat(&e.last_seen.to_le_bytes());
        eat(e.marker.slug().as_bytes());
        folded ^= h;
    }
    folded
}

/// Serialize the store to the TSV v1 wire: version header, `#meta` totals, one host-sorted row per
/// entry (host · hits · first_seen · last_seen · marker-slug).
fn serialize_store(s: &Store) -> String {
    let mut out = String::with_capacity(48 + s.by_host.len() * 48);
    out.push_str("#centauri-discovered ");
    out.push_str(STORE_VERSION);
    out.push('\n');
    out.push_str(&format!("#meta observed_total={}\n", s.observed_total));
    let mut rows: Vec<&Entry> = s.by_host.values().collect();
    rows.sort_by(|a, b| a.host.cmp(&b.host));
    for e in rows {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            e.host,
            e.hits,
            e.first_seen,
            e.last_seen,
            e.marker.slug(),
        ));
    }
    out
}

/// Parse a store body back into entries + total. FAIL-OPEN per row: a corrupt/short/unknown row is
/// SKIPPED, never an error — a half-good store rehydrates its good half.
fn parse_body(body: &str) -> (Vec<Entry>, u64) {
    let mut entries = Vec::new();
    let mut observed = 0u64;
    for line in body.lines() {
        if let Some(meta) = line.strip_prefix("#meta ") {
            for tok in meta.split_whitespace() {
                if let Some(v) = tok.strip_prefix("observed_total=") {
                    observed = v.parse().unwrap_or(0);
                }
            }
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 5 {
            continue;
        }
        let Some(marker) = Marker::from_slug(f[4]) else {
            continue;
        };
        let host = normalize(f[0]);
        if host.is_empty() {
            continue;
        }
        entries.push(Entry {
            host,
            hits: f[1].parse().unwrap_or(1),
            first_seen: f[2].parse().unwrap_or(0),
            last_seen: f[3].parse().unwrap_or(0),
            marker,
        });
    }
    (entries, observed)
}

/// Load the store from the armed dir (merge-by-key; existing RAM rows win — boot calls this on an
/// empty store). Missing file = clean cold start. Honors the [`MAX_DISCOVERED`] cap on rehydrate.
fn load_store() {
    let Some(path) = store_path() else {
        return;
    };
    let Ok(body) = std::fs::read_to_string(&path) else {
        return;
    };
    let (entries, observed) = parse_body(&body);
    let Ok(mut g) = store().write() else {
        return;
    };
    if g.observed_total < observed {
        g.observed_total = observed;
    }
    for e in entries {
        if g.by_host.len() >= MAX_DISCOVERED {
            break;
        }
        g.by_host.entry(e.host.clone()).or_insert(e);
    }
    // Seed the change gate so a load that changed nothing does not force an immediate rewrite.
    LAST_PERSIST_SIG.store(store_signature(&g), Ordering::Relaxed);
}

/// Persist the store atomically iff its signature changed (change-gated tmp + rename).
fn persist() {
    let Some(path) = store_path() else {
        return;
    };
    let (sig, body) = {
        let Ok(guard) = store().read() else {
            return;
        };
        let sig = store_signature(&guard);
        if sig == LAST_PERSIST_SIG.load(Ordering::Relaxed) {
            return;
        }
        (sig, serialize_store(&guard))
    };
    let tmp = path.with_extension("tsv.tmp");
    if std::fs::write(&tmp, body).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
        LAST_PERSIST_SIG.store(sig, Ordering::Relaxed);
    }
}

/// Arm the discovery layer: bind the durable `dir`, rehydrate ONCE, open the feed. Rides the SAME boot
/// edge as the resolver cache rehydrate ([`crate::resolver_rehydrate_cache`]). Idempotent: a re-arm
/// re-binds the dir but the merge-by-key load never duplicates rows.
pub(crate) fn arm(dir: &str) {
    let trimmed = dir.trim();
    if trimmed.is_empty() {
        return;
    }
    {
        let Ok(mut guard) = store_dir_cell().write() else {
            return;
        };
        *guard = Some(PathBuf::from(trimmed));
    }
    load_store();
    // ★ #20 — the TLS-refusal ledger rides the SAME boot edge. It is written by the forwarder in the
    // VPN service process and read by the DNS plane on every query, so without this rehydrate a host
    // that refused our leaf is cloaked again on the next start and that app breaks a second time.
    #[cfg(feature = "mirror")]
    crate::mirror::localcdn::arm_tls_distrust_store(std::path::Path::new(trimmed));
    ARMED.store(true, Ordering::Release);
    // The promoted-cloak set lives in RAM only, and `observe` republishes it solely on the instant a
    // host's count EQUALS `MIN_PROMOTION_HITS`. A host that earned promotion in an EARLIER process is
    // reloaded above already past that edge, so it would never cross again and its cloak would stay
    // unpublished for the life of the install — the ledger remembers, the DNS plane forgets. Republish
    // the full promotable roster here, on the same boot edge that rehydrates it.
    #[cfg(feature = "mirror")]
    {
        let promoted = promotable();
        if !promoted.is_empty() {
            crate::mirror::localcdn::publish_promoted_cloak(promoted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The store is process-global (OnceLock static); serialize the tests that mutate it so they do not
    // race each other's counts (the underground-test precedent).
    static SCRUB: Mutex<()> = Mutex::new(());

    fn scrub() -> std::sync::MutexGuard<'static, ()> {
        let g = SCRUB.lock().unwrap_or_else(|e| e.into_inner());
        // Reset the shared store + gates to a clean slate for each test.
        if let Ok(mut s) = store().write() {
            s.by_host.clear();
            s.observed_total = 0;
        }
        ARMED.store(false, Ordering::Release);
        LAST_PERSIST_SIG.store(0, Ordering::Relaxed);
        if let Ok(mut d) = store_dir_cell().write() {
            *d = None;
        }
        g
    }

    /// A5 GUARD -- `MAX_DISCOVERED` (= 4096, centauri_discovery.rs:50) bounds the discovery
    /// ledger. The A5 inventory found it had a NUMBER and no test naming it, and this ledger is
    /// fed by OBSERVED TRAFFIC -- its size is chosen by whatever the device talks to, not by us.
    ///
    /// Three arms. The cap sits in the `else` of a `contains_key` test, which is the whole point:
    /// a FULL ledger must still count hits for hosts it ALREADY knows, or promotion freezes the
    /// moment the ledger fills and a host that legitimately crosses MIN_PROMOTION_HITS afterwards
    /// is never promoted. A length-only assertion stays green through that bug.
    #[test]
    fn max_discovered_bounds_new_hosts_but_never_freezes_the_known_ones() {
        let _g = scrub();
        // `observe` is gated on `armed()` and on `classify()` returning a marker, BOTH before the
        // cap is consulted. Without arming, the first version of this test filled nothing and
        // asserted 0 == 4096 -- the gate dominated the bound, exactly as `is_cdn_host` dominates
        // MAX_CACHED_LEAVES. `*.cloudfront.net` is a shape classify() admits (see :724).
        ARMED.store(true, Ordering::Release);

        for i in 0..MAX_DISCOVERED {
            observe(&format!("h{i:06}.cloudfront.net"), false);
        }
        assert_eq!(
            count() as usize,
            MAX_DISCOVERED,
            "the ledger must saturate AT the cap"
        );

        // (a) a NEW host past the ceiling is refused -- the ledger does not grow.
        observe("brand-new-probe.cloudfront.net", false);
        assert_eq!(
            count() as usize,
            MAX_DISCOVERED,
            "a NEW host past MAX_DISCOVERED must not grow the ledger"
        );
        let present = store()
            .read()
            .map(|g| g.by_host.contains_key("brand-new-probe.cloudfront.net"))
            .unwrap_or(true);
        assert!(!present, "the refused host must not be in the ledger at all");

        // (b) a host the ledger ALREADY holds still accrues hits when full.
        let hits_of = |h: &str| {
            store()
                .read()
                .ok()
                .and_then(|g| g.by_host.get(h).map(|e| e.hits))
                .expect("seeded host present")
        };
        let before = hits_of("h000000.cloudfront.net");
        observe("h000000.cloudfront.net", false);
        assert_eq!(
            hits_of("h000000.cloudfront.net"),
            before + 1,
            "a FULL ledger must keep counting hits for hosts it already knows"
        );

        // Leave the gate as scrub() found it -- ARMED is process-global.
        ARMED.store(false, Ordering::Release);
    }


    #[test]
    fn a_non_delivery_service_is_never_promoted_however_cdn_its_operator_looks() {
        // ★ #87 — every one of these was MEASURED on the device roster as `infra`, purely because
        // INFRA_TOKENS carries the operator name `cloudflare`. None is content delivery.
        for host in [
            "stun.cloudflare.com",             // not even HTTP
            "a.nel.cloudflare.com",            // error-logging beacons
            "challenges.cloudflare.com",       // Turnstile — the host that broke Hot & New (#78)
            "static.cloudflareinsights.com",   // analytics, operator-fused label
            "cloudflareinsights.com",          // its apex
        ] {
            assert_eq!(classify(host), None, "{host} must never be promoted to the cloak roster");
        }

        // THE OTHER DIRECTION — the veto must not cost us a single real CDN. `stun` may not match
        // inside `stunning`, and the operator tokens must still win everywhere they legitimately do.
        // `Label`, not `Infra` — it carries no operator token, only the cdn-ish leading label. The
        // POINT is that it is not None: `stun` must not match inside `stunning`, so the veto is
        // whole-label. (Asserted Infra first; the suite corrected me — the marker is Label.)
        assert_eq!(classify("cdn.stunning-assets.net"), Some(Marker::Label));
        assert_eq!(classify("cdnjs.cloudflare.com"), Some(Marker::Infra));
        assert_eq!(classify("cdn.jsdelivr.net"), Some(Marker::Infra));
        assert_eq!(classify("fonts.gstatic.com"), Some(Marker::Infra));
    }

    #[test]
    fn classify_catches_infra_and_leading_label_but_not_plain_hosts() {
        assert_eq!(classify("d123abc.cloudfront.net"), Some(Marker::Infra));
        assert_eq!(classify("e4.a.akamaiedge.net"), Some(Marker::Infra));
        assert_eq!(classify("cdn.jsdelivr.net"), Some(Marker::Infra)); // infra wins over the lead label
        assert_eq!(classify("static.example.com"), Some(Marker::Label));
        assert_eq!(classify("cdn1.example.org"), Some(Marker::Label));
        assert_eq!(classify("assets.shop.co"), Some(Marker::Label));
        // A sharded/region-suffixed lead label is still a delivery signal. Measured on the AVD:
        // browsing amazon.com emits `images-na.ssl-images-amazon.com`, which the exact-match-only
        // law skipped entirely, so the host never earned a discovery row and could never promote.
        assert_eq!(
            classify("images-na.ssl-images-amazon.com"),
            Some(Marker::Label)
        );
        assert_eq!(classify("img-01.example.com"), Some(Marker::Label));
        assert_eq!(classify("assets-eu.shop.co"), Some(Marker::Label));
        // …but the stem must be a WHOLE curated word, and the lead label only. A short/ordinary lead
        // is not a CDN shape no matter what follows it.
        assert_eq!(classify("m.media-amazon.com"), None);
        assert_eq!(classify("mail.example.com"), None);
        assert_eq!(classify("login.example.com"), None);
        assert_eq!(classify("api.static.example.com"), None);
        // Not CDN-shaped:
        assert_eq!(classify("www.example.com"), None);
        assert_eq!(classify("mail.google.com"), None);
        assert_eq!(classify("1.2.3.4"), None); // IP literal
        assert_eq!(classify("4.3.2.1.in-addr.arpa"), None); // reverse-DNS
        assert_eq!(classify("localhost"), None); // single label
        assert_eq!(classify(""), None);
    }

    /// ★ #65 — a host must RECUR to earn a cloak row. One sighting is a candidate, not an absorption.
    #[test]
    fn promotion_requires_the_recurrence_threshold() {
        let _s = scrub();
        ARMED.store(true, Ordering::Release);

        // Seen once — recorded as a candidate, but NOT promotable.
        observe("cdn.oneshot.example", false);
        assert_eq!(count(), 1, "the candidate IS remembered");
        assert!(
            promotable().is_empty(),
            "one sighting must never author a permanent catalog row"
        );

        // Seen again up to the threshold — now it has earned the row.
        for _ in 1..MIN_PROMOTION_HITS {
            observe("cdn.oneshot.example", false);
        }
        assert_eq!(
            promotable(),
            vec!["cdn.oneshot.example".to_string()],
            "a recurring CDN crosses into the served catalog"
        );
        assert_eq!(promotable_count(), 1);
    }

    /// ★ #65 APP LANE — the phone-app CDNs are named at the REGISTRABLE DOMAIN, so the lead-label lane
    /// cannot see them. These are the hosts Instagram/TikTok actually fetch their media from.
    #[test]
    fn registrable_domain_cdn_is_classified() {
        for host in [
            "scontent.cdninstagram.com",
            "scontent-lhr8-1.cdninstagram.com",
            "p16-sign-va.tiktokcdn.com",
            "v16-webapp.tiktokcdn-us.com",
        ] {
            assert_eq!(
                classify(host),
                Some(Marker::Infra),
                "{host} is app-side asset delivery and must be discoverable"
            );
        }
        // The guard rails. Note `cdn-status.example.com` is NOT one of them: the pre-existing
        // `lead.starts_with("cdn")` law already classifies it `Label`, and this lane does not change
        // that either way — measured, not assumed.
        assert_eq!(classify("cdn-status.example.com"), Some(Marker::Label));
        assert_eq!(classify("api.wikimedia.org"), None);
        assert_eq!(classify("mail.google.com"), None);
    }

    /// ★ #65 — a host promoted in an EARLIER process must still cloak after a restart. `observe` fires
    /// the publish only on the `== MIN_PROMOTION_HITS` edge, so without a republish on the rehydrate
    /// edge the reloaded host sails past that edge forever and the DNS plane never learns about it.
    #[cfg(feature = "mirror")]
    #[test]
    fn rehydrated_promotion_republishes_the_cloak() {
        let _s = scrub();
        let dir = std::env::temp_dir().join(format!("torta-rehydrate-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let dir_s = dir.to_string_lossy().to_string();

        // Process #1: earn promotion and persist the ledger.
        arm(&dir_s);
        for _ in 0..MIN_PROMOTION_HITS {
            observe("cdn.restart.example", false);
        }
        persist();
        assert_eq!(promotable_count(), 1, "the host earned its row before the restart");

        // Process #2: wipe RAM exactly as a fresh process would, leaving ONLY the on-disk ledger.
        crate::mirror::localcdn::publish_promoted_cloak(Vec::new());
        if let Ok(mut s) = store().write() {
            s.by_host.clear();
            s.observed_total = 0;
        }
        ARMED.store(false, Ordering::Release);
        LAST_PERSIST_SIG.store(0, Ordering::Relaxed);
        assert_eq!(
            crate::mirror::localcdn::promoted_cloak_count(),
            0,
            "the cold process starts with an empty cloak set"
        );

        arm(&dir_s);
        assert_eq!(
            crate::mirror::localcdn::promoted_cloak_count(),
            1,
            "the rehydrate edge must republish what the ledger already remembers"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ★ #65 — the promoted set is ordered hits-desc then host-asc, so an arm is reproducible.
    #[test]
    fn promotion_is_deterministic_and_bounded() {
        let _s = scrub();
        ARMED.store(true, Ordering::Release);

        // `rare` never reaches the threshold; `busy` outranks `calm` on hits.
        for _ in 0..(MIN_PROMOTION_HITS + 4) {
            observe("cdn.busy.example", false);
        }
        for _ in 0..MIN_PROMOTION_HITS {
            observe("cdn.calm.example", false);
        }
        observe("cdn.rare.example", false);

        assert_eq!(
            promotable(),
            vec!["cdn.busy.example".to_string(), "cdn.calm.example".to_string()],
            "hits-desc, and the sub-threshold host is excluded"
        );
        assert!(
            promotable().len() <= MAX_PROMOTED,
            "the promoted set is bounded by the signing ceiling"
        );
    }

    #[test]
    fn observe_is_noop_until_armed() {
        let _s = scrub();
        observe("cdn.jsdelivr.net", false);
        assert_eq!(count(), 0, "no feed before arm");
        assert_eq!(observed_total(), 0);
    }

    #[test]
    fn observe_grows_dedupes_and_skips_static_and_non_cdn() {
        let _s = scrub();
        ARMED.store(true, Ordering::Release); // arm without a dir (RAM-only; persist no-ops)
        observe("cdn.jsdelivr.net", false);
        observe("cdn.jsdelivr.net", false); // dedupe → same host, hits++
        observe("static.example.com", false); // new discovery
        observe("www.example.com", false); // not cdn-shaped → ignored
        observe("d1.cloudfront.net", true); // already static (watched) → NOT a discovery
        assert_eq!(count(), 2, "two distinct discovered hosts");
        assert_eq!(observed_total(), 3, "three cdn-shaped observations (static+non-cdn excluded)");
        let top = top(2);
        assert_eq!(top[0].0, "cdn.jsdelivr.net");
        assert_eq!(top[0].1, 2, "the deduped host carries 2 hits");
    }

    #[test]
    fn discovered_line_is_pipe_delimited_hits_desc_and_bounded() {
        let _s = scrub();
        ARMED.store(true, Ordering::Release);
        observe("cdn.jsdelivr.net", false);
        observe("cdn.jsdelivr.net", false); // 2 hits → ranks first
        observe("static.example.com", false); // 1 hit
        observe("assets.shop.co", false); // 1 hit → ties break by host name (assets < static)
        // Full roster: hits-desc, then host-asc on ties. No collision risk: the `|` never appears in a host.
        assert_eq!(discovered_line(9), "cdn.jsdelivr.net|assets.shop.co|static.example.com");
        // Bounded by n — the header count still rides the uncapped `count()`, but the line is windowed.
        assert_eq!(discovered_line(1), "cdn.jsdelivr.net");
        // Empty store → empty line (never a stray separator).
        if let Ok(mut s) = store().write() {
            s.by_host.clear();
        }
        assert_eq!(discovered_line(9), "");
    }

    #[test]
    fn round_trips_through_the_tsv() {
        let _s = scrub();
        ARMED.store(true, Ordering::Release);
        observe("cdn.jsdelivr.net", false);
        observe("static.example.com", false);
        observe("static.example.com", false);
        let body = {
            let g = store().read().unwrap();
            serialize_store(&g)
        };
        let (entries, observed) = parse_body(&body);
        assert_eq!(entries.len(), 2);
        assert_eq!(observed, 3);
        // The rehydrated rows carry the hits + marker back.
        let jsd = entries.iter().find(|e| e.host == "cdn.jsdelivr.net").unwrap();
        assert_eq!(jsd.hits, 1);
        assert_eq!(jsd.marker, Marker::Infra);
        let stx = entries.iter().find(|e| e.host == "static.example.com").unwrap();
        assert_eq!(stx.hits, 2);
        assert_eq!(stx.marker, Marker::Label);
    }

    #[test]
    fn legacy_short_row_is_skipped_not_fatal() {
        let (entries, observed) = parse_body(
            "#centauri-discovered v1\n#meta observed_total=9\nbad\trow\ncdn.ok.net\t1\t0\t0\tinfra\n",
        );
        assert_eq!(entries.len(), 1, "the good row survives; the short row is skipped");
        assert_eq!(entries[0].host, "cdn.ok.net");
        assert_eq!(observed, 9);
    }

    #[test]
    fn cap_bounds_distinct_hosts_but_still_counts_observations() {
        let _s = scrub();
        ARMED.store(true, Ordering::Release);
        // Force the store to the cap, then observe one more distinct host.
        {
            let mut g = store().write().unwrap();
            for i in 0..MAX_DISCOVERED {
                g.by_host.insert(
                    format!("cdn{i}.example.net"),
                    Entry { host: format!("cdn{i}.example.net"), hits: 1, first_seen: 0, last_seen: 0, marker: Marker::Label },
                );
            }
        }
        assert_eq!(count() as usize, MAX_DISCOVERED);
        observe("cdn-overflow.example.net", false);
        assert_eq!(count() as usize, MAX_DISCOVERED, "capped: no new row stored");
        assert_eq!(observed_total(), 1, "but the observation still counted");
    }
}
