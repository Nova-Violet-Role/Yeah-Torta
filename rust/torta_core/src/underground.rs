/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **The Underground Layer** — the licence-based host reputation store that GROWS on the box's own
//! navigation and BITES back with sequestration teeth.
//!
//! Every name the resolver actually answers or denies is fed here ONCE per resolve
//! ([`feed`], called from the `resolve_datapath` seam) and classified into a risk lane. A hostile
//! host does not get banned on first sight: it holds a LICENCE of [`LICENCE_START`] points and
//! loses points per accident on a GRADUATED scale (an active destroyer bleeds 10, a mere ad
//! presence bleeds 1). Idle good behavior HEALS the licence back (+1 per [`RECOVERY_IDLE_SECS`]
//! of silence) — except the active-destroy tier (Malware/Spoof/Mitm), which NEVER heals (the
//! mitigation ceiling). A licence drained to 0 is SEQUESTRATED — terminal — and from that moment
//! the resolver's step-1b teeth ([`teeth_gate`]) answer the name NXDOMAIN locally, ZERO egress.
//!
//! ## The content-lane law (the uBlock lesson)
//! A Centauri-witnessed CDN/content host ([`Source::Centauri`]) is INVESTIGATED — its licence
//! meters content-heat — but NEVER sequestrated: blocking a shared CDN domain breaks the web, so
//! the content lane keeps the DOMAIN reachable while the mirror layer handles the payloads.
//! Rehydrating an old ledger DEFANGS any wrongly-sequestrated content-lane row.
//!
//! ## Classification LISTENS, never re-derives
//! The resolver already computes the real verdicts (blocklist/warden deny, never-forward guard,
//! rebind reject); the feed receives the compressed [`NavEvent`] and only sub-classifies:
//! a Blocked/Answered name against the curated recon-suffix lists, a Guarded name by qtype
//! (PTR ⇒ IpLeak, else Sonar), a RebindReject straight to Spoof. Benign answered traffic records
//! NOTHING (post-filter, not a mirror of your history).
//!
//! ## Durability
//! A TSV v1 ledger (`underground-ledger.tsv`) in the SAME durable dir the resolver cache uses,
//! armed by the same boot edge (`resolver_rehydrate_cache` → [`arm`]). Writes are change-gated
//! (FNV-1a XOR-fold signature) + atomic (tmp + rename), and SELF-TICKING: settle + persist ride
//! the feed itself at ≥[`PERSIST_MIN_GAP_SECS`] gaps — no GUI tick dependency. Every path is
//! FAIL-OPEN: a poisoned lock, missing dir, or corrupt row degrades to "no reputation yet",
//! never a panic and never a false block.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

/// Every host starts with this many licence points (the presumption of innocence).
const LICENCE_START: i32 = 20;
/// At or below this many points the host is ON PROBATION: every further penalty DOUBLES.
const PROBATION_AT: i32 = 6;
/// Seconds of full silence (no accident, no heal) before a licence point regrows.
const RECOVERY_IDLE_SECS: u64 = 30;
/// Points regained per recovery settle once idle.
const RECOVERY_STEP: i32 = 1;
/// Default quarantine TTL (24h) — how long an EARNED sequestration serves before the retest
/// rung re-licences a non-active-destroy Neutral host (G rung; `[quarantine] ttl_secs`).
const QUARANTINE_TTL_SECS: u64 = 86_400;
/// Minimum seconds between self-ticking settle/persist passes on the feed path (keeps the
/// per-query cost O(1) — the O(n) settle + signature walk runs at most once per gap).
const PERSIST_MIN_GAP_SECS: u64 = 5;
/// Ledger wire-format version tag (first header line).
const LEDGER_VERSION: &str = "v1";
/// Ledger file name inside the armed durable dir.
const LEDGER_FILE_NAME: &str = "underground-ledger.tsv";

/// ★ #79 — the DETECTION EPOCH: which generation of detection logic authored the verdicts on disk.
///
/// BUMP THIS whenever a detection change invalidates verdicts a previous build handed down. On load, a
/// ledger stamped with a lower epoch has every AUTOMATIC sequestration vacated (see the amnesty block in
/// [`parse_body`]) — the engine cannot leave a user permanently cut off from a host that a since-deleted
/// bug convicted. A ledger with no `epoch=` token reads 0, so pre-amnesty ledgers amnesty exactly once.
///
/// - **1** — the ROOT CAUSE #26 generation: `nx_burst` no longer reads the browser's speculative
///   AAAA/SVCB/HTTPS negatives as DNS-tunnel exfiltration, so every `tunnel`-lane conviction older than
///   this epoch is unsafe to trust.
const DETECTION_EPOCH: u32 = 1;

/// The risk lane a recorded host sits in. Lanes are DECLARED even where no Tortä witness feeds
/// them yet (DnsLeak/Mitm/Malware wait for the geo rung) — the vocabulary is the contract.
/// `pub` + `uniffi::Enum` since the E rung: [`ThreatScore`] carries the lane across the seam.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Risk {
    /// Usage-measurement beacon (page/app analytics).
    Analytics,
    /// Ad delivery / ad auction infrastructure.
    Ads,
    /// Cross-site/app tracking or telemetry exfiltration.
    Tracker,
    /// A resolve that would leak DNS metadata to a foreign resolver (geo rung).
    DnsLeak,
    /// A reverse lookup that would leak private address space upstream (the guard's PTR stop).
    IpLeak,
    /// LAN-topology probing via special-use zones (`.local`/`.lan`/`.internal`/`.home.arpa`).
    Sonar,
    /// Cross-border/anchor-contradicting movement of an already-known host (geo rung).
    Mitm,
    /// A public name answered with reserved address space — the classic rebind/poison move.
    Spoof,
    /// A beacon that escalated to active-hostile behavior (geo rung).
    Malware,
    /// Centauri-witnessed CDN/content host — the content lane (metered, never sequestrated).
    Cdn,
    /// A novel malware-shape class coined by the Detection suite (F rung) — the escape hatch
    /// that lets new detectors name lanes (`dga`/`tunnel`/`beacon`/…) WITHOUT shifting the
    /// 10-lane `per_risk` index the snapshot vocabulary froze. Rides the wire as its raw slug;
    /// detector slugs never collide with the ten built-ins by construction.
    Custom { slug: String },
}

impl Risk {
    /// Stable lower-case wire slug (ledger column 2). A `Custom` lane rides as its raw slug —
    /// [`Risk::from_slug`]'s catch-all brings it back whole (the F round-trip law).
    fn slug(&self) -> String {
        match self {
            Risk::Analytics => "analytics".into(),
            Risk::Ads => "ads".into(),
            Risk::Tracker => "tracker".into(),
            Risk::DnsLeak => "dns-leak".into(),
            Risk::IpLeak => "ip-leak".into(),
            Risk::Sonar => "sonar".into(),
            Risk::Mitm => "mitm".into(),
            Risk::Spoof => "spoof".into(),
            Risk::Malware => "malware".into(),
            Risk::Cdn => "cdn".into(),
            Risk::Custom { slug } => slug.clone(),
        }
    }

    fn from_slug(s: &str) -> Option<Risk> {
        Some(match s {
            "analytics" => Risk::Analytics,
            "ads" => Risk::Ads,
            "tracker" => Risk::Tracker,
            "dns-leak" => Risk::DnsLeak,
            "ip-leak" => Risk::IpLeak,
            "sonar" => Risk::Sonar,
            "mitm" => Risk::Mitm,
            "spoof" => Risk::Spoof,
            "malware" => Risk::Malware,
            "cdn" => Risk::Cdn,
            // The F escape hatch: any other non-empty slug is a detector-coined lane, kept
            // whole (fail-open — a future detector's rows survive a downgrade round-trip).
            "" | "-" => return None,
            other => Risk::Custom { slug: other.to_string() },
        })
    }

    /// Graduated licence penalty — active hostility bleeds fast, mere presence bleeds slow.
    fn base_penalty(&self) -> i32 {
        match self {
            // ACTIVE-destroy: attacks the box's integrity. A detector-coined Custom lane
            // (dga/tunnel/beacon) is a malware SHAPE — it bleeds at the top tier.
            Risk::Malware | Risk::Spoof | Risk::Mitm | Risk::Custom { .. } => 10,
            // ACTIVE-exfil: ships private facts upstream.
            Risk::IpLeak | Risk::DnsLeak => 8,
            // PASSIVE-leak: maps what it should not see.
            Risk::Sonar => 5,
            // RECON: measures the user.
            Risk::Tracker | Risk::Analytics => 3,
            // PRESENCE: exists loudly.
            Risk::Ads | Risk::Cdn => 1,
        }
    }

    /// The mitigation ceiling — the tier that NEVER heals its licence back.
    fn is_active_destroy(&self) -> bool {
        matches!(self, Risk::Malware | Risk::Spoof | Risk::Mitm | Risk::Custom { .. })
    }

    fn lane_index(&self) -> usize {
        match self {
            Risk::Analytics => 0,
            Risk::Ads => 1,
            Risk::Tracker => 2,
            Risk::DnsLeak => 3,
            Risk::IpLeak => 4,
            Risk::Sonar => 5,
            Risk::Mitm => 6,
            Risk::Spoof => 7,
            // A Custom lane counts in the malware column — the vec stays 10 wide forever.
            Risk::Malware | Risk::Custom { .. } => 8,
            Risk::Cdn => 9,
        }
    }
}

/// WHICH Tortä pillar witnessed the accident (provenance, ledger column 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// The resolver's deny verdict (user blocklist or Warden universal ruleset — both are
    /// domain-deny verdicts at the same datapath step; attribution is deliberately merged).
    Blocklist,
    /// The never-forward / bogus-priv privacy guard (the zero-egress NXDOMAIN stops).
    Guard,
    /// The rebind enforcement (a validated answer carrying reserved space for a public name).
    Rebind,
    /// The Underground's own curated recon-suffix lists over ANSWERED traffic (meters recon even
    /// when every enforcement toggle is off).
    Suffix,
    /// The Centauri CDN witness — the content lane (never sequestrates).
    Centauri,
}

impl Source {
    fn slug(self) -> &'static str {
        match self {
            Source::Blocklist => "blocklist",
            Source::Guard => "guard",
            Source::Rebind => "rebind",
            Source::Suffix => "suffix",
            Source::Centauri => "centauri",
        }
    }

    fn from_slug(s: &str) -> Option<Source> {
        Some(match s {
            "blocklist" => Source::Blocklist,
            "guard" => Source::Guard,
            "rebind" => Source::Rebind,
            "suffix" => Source::Suffix,
            "centauri" => Source::Centauri,
            _ => return None,
        })
    }

    fn lane_index(self) -> usize {
        match self {
            Source::Blocklist => 0,
            Source::Guard => 1,
            Source::Rebind => 2,
            Source::Suffix => 3,
            Source::Centauri => 4,
        }
    }
}

/// The user's MANUAL trust pin over a host — the re-homed Trust bands (lifted out of Warden,
/// where a firewall has no reputation concept, into the Underground where reputation LIVES).
/// The automatic licence engine governs a `Neutral` host. A `Trusted` host is IMMUNE: the teeth
/// never bite it, its licence is pinned full, and it can never sequestrate — a vouched
/// false-positive the user needs. A `Distrusted` host is CONDEMNED: the teeth always bite (force
/// NXDOMAIN) and it is pinned sequestrated — killed the instant the user says so, not when the
/// licence would have drained on its own. Column 11 of the TSV; an OLD 10-column ledger reads
/// back `Neutral` (backward-compatible rehydrate). This is the "GROWS with the user" faculty:
/// the user teaches the store which hosts to always-allow and always-block, and it persists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Verdict {
    /// Automatic — the licence engine alone decides (the default for every witnessed host).
    #[default]
    Neutral,
    /// Manual ALLOW — immune to the teeth + pinned to a full licence (a vouched host).
    Trusted,
    /// Manual BLOCK — force NXDOMAIN + pinned sequestrated (a condemned host).
    Distrusted,
}

impl Verdict {
    /// Stable lower-case wire slug (ledger column 11 + the top-row's 7th field).
    fn slug(self) -> &'static str {
        match self {
            Verdict::Neutral => "neutral",
            Verdict::Trusted => "trusted",
            Verdict::Distrusted => "distrusted",
        }
    }

    /// FAIL-SAFE decode: an unknown/missing slug reads back `Neutral` (a corrupt pin degrades to
    /// "let the automatic engine decide", never to a spurious block).
    fn from_slug(s: &str) -> Verdict {
        match s {
            "trusted" => Verdict::Trusted,
            "distrusted" => Verdict::Distrusted,
            _ => Verdict::Neutral,
        }
    }

    /// The bridge/UI numeric contract: 0=Neutral (clear the pin), 1=Trusted, 2=Distrusted.
    /// Any other code fails safe to `Neutral`.
    fn from_code(code: u8) -> Verdict {
        match code {
            1 => Verdict::Trusted,
            2 => Verdict::Distrusted,
            _ => Verdict::Neutral,
        }
    }
}

/// The compressed resolver verdict the feed listens to — the resolver maps its own private
/// `ResolveOutcome` to this at the datapath seam so the Underground never imports resolver
/// internals (and the resolver never imports licence law).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NavEvent {
    /// The name was DENIED (blocklist / Warden universal / Underground teeth).
    Blocked,
    /// The privacy guard answered locally (private PTR or special-use zone) — zero egress.
    Guarded,
    /// A validated answer was DROPPED for carrying reserved space under a public name.
    RebindReject,
    /// The name resolved (live forward, cache hit, or local synth) — passive metering lane.
    Answered,
}

/// One host's reputation row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    host: String,
    risk: Risk,
    source: Source,
    hits: u64,
    points: i32,
    first_seen: u64,
    last_seen: u64,
    last_heal: u64,
    /// ISO-3166 alpha-2, uppercase — UNSET until the geo rung lands (ledger column 9 stays `-`).
    country: Option<[u8; 2]>,
    sequestrated: bool,
    /// The user's manual trust pin (ledger column 11; `Neutral` for an automatic host).
    verdict: Verdict,
    /// When the AUTOMATIC sequestration closed (unix-secs; ledger column 12; 0 = not
    /// quarantined). The G-rung TTL clock: a sequestered non-active-destroy Neutral host is
    /// RETESTED once `now ≥ seq_at + ttl` — permadeath is reserved for the active-destroy
    /// class and the user's own Distrust pin.
    seq_at: u64,
}

/// The whole reputation store (behind the process-global lock).
#[derive(Debug, Default)]
struct Store {
    by_host: HashMap<String, Entry>,
    /// Total accidents ever recorded (survives entry pruning; persisted in #meta).
    recorded_total: u64,
    /// Total licence points ever healed back (persisted in #meta).
    recovered_total: u64,
    /// Total live NXDOMAINs the sequestration teeth served (persisted in #meta).
    teeth_total: u64,
}

static STORE: OnceLock<RwLock<Store>> = OnceLock::new();
/// Fast gate: false until [`arm`] binds a durable dir (the fleet-cold default — a cold build
/// never takes the store lock on the datapath).
static ARMED: AtomicBool = AtomicBool::new(false);
static LEDGER_DIR: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();
/// Signature of the store at the last persisted write (change gate — identical store ⇒ no IO).
static LAST_PERSIST_SIG: AtomicU64 = AtomicU64::new(0);
/// Unix-seconds of the last self-ticking settle/persist pass (the ≥5s gap gate).
static LAST_TICK_SECS: AtomicU64 = AtomicU64::new(0);

fn store() -> &'static RwLock<Store> {
    STORE.get_or_init(|| RwLock::new(Store::default()))
}

fn ledger_dir_cell() -> &'static RwLock<Option<PathBuf>> {
    LEDGER_DIR.get_or_init(|| RwLock::new(None))
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

// ── Classification ──────────────────────────────────────────────────────────────────────────────

/// Curated ad-delivery suffixes (pure-purpose domains — never dual-use application APIs).
const ADS: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "adservice.google.com",
    "adnxs.com",
];

/// Curated analytics/measurement suffixes.
const ANALYTICS: &[&str] = &[
    "google-analytics.com",
    "scorecardresearch.com",
    "app-measurement.com",
];

/// Curated telemetry/attribution suffixes (mobile SDK exfil lanes included).
const TELEMETRY: &[&str] = &[
    "events.data.microsoft.com",
    "telemetry.microsoft.com",
    "datadoghq.com",
    "crashlytics.com",
    "appsflyer.com",
    "adjust.com",
    "branch.io",
];

/// True iff `host` IS `suffix` or ends with `.suffix` (case handled by [`normalize`] upstream).
fn suffix_hit(host: &str, suffixes: &[&str]) -> bool {
    suffixes
        .iter()
        .any(|s| host == *s || host.ends_with(&format!(".{s}")))
}

/// Map one resolved-row event to its risk lane + witnessing pillar. `None` = benign — recorded
/// NOWHERE (the post-filter law: the store is a threat ledger, never a browsing mirror).
fn classify(host: &str, qtype: u16, event: NavEvent) -> Option<(Risk, Source)> {
    match event {
        NavEvent::Blocked => Some((
            if suffix_hit(host, ADS) {
                Risk::Ads
            } else if suffix_hit(host, ANALYTICS) {
                Risk::Analytics
            } else {
                // The deny lists are overwhelmingly ad/tracker lists — Tracker is the honest
                // fallback lane for an unattributed deny.
                Risk::Tracker
            },
            Source::Blocklist,
        )),
        // The guard fires on exactly two shapes: a private-PTR stop (qtype 12 ⇒ the reverse
        // lookup would have leaked private address space) or a special-use zone (LAN sonar).
        NavEvent::Guarded => Some((
            if qtype == 12 { Risk::IpLeak } else { Risk::Sonar },
            Source::Guard,
        )),
        NavEvent::RebindReject => Some((Risk::Spoof, Source::Rebind)),
        NavEvent::Answered => {
            if suffix_hit(host, ADS) {
                Some((Risk::Ads, Source::Suffix))
            } else if suffix_hit(host, ANALYTICS) {
                Some((Risk::Analytics, Source::Suffix))
            } else if suffix_hit(host, TELEMETRY) {
                Some((Risk::Tracker, Source::Suffix))
            } else {
                #[cfg(feature = "mirror")]
                if crate::mirror::localcdn::is_cdn_host(host) {
                    return Some((Risk::Cdn, Source::Centauri));
                }
                None
            }
        }
    }
}

// ── The runtime scoring brain (E rung) ──────────────────────────────────────────────────────────
// Surpasses the compile-time penalty law: the licence economy's numbers (LICENCE_START /
// PROBATION_AT / the per-risk penalty table) become RUNTIME state — loaded from an operator-
// editable `scoring.toml` beside the ledger, overridable PER HOST by the [`ReputationStore`],
// and fused per event into a [`ThreatScore`] the record path consumes. The compile-time
// constants above remain as the GROUND-TRUTH defaults, so a box with no toml and no reputation
// rows behaves byte-identically to the pre-E engine. OFFLINE by law (underground.rs:6-8): the
// reputation context is a local map only — nothing is ever asked of a cloud.

/// One fused evidence mark inside a [`ThreatScore`] — WHICH faculty saw something. `Suffix`/
/// `GeoMitm`/`GeoRebind`/`Reputation` fire from the E fusion below; `Dga`/`Tunnel`/`Beacon`
/// wait for the F detection suite; `Correction` is the G learning-loop's mark. Declared now —
/// the vocabulary is the contract (the Risk-lane precedent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Signal {
    /// A curated recon-suffix class matched (ADS/ANALYTICS/TELEMETRY).
    Suffix,
    /// Cross-border/anchor-contradicting movement (geo rung witness).
    GeoMitm,
    /// A validated answer carried reserved space under a public name.
    GeoRebind,
    /// Fixed-cadence C2-style beaconing (F detector).
    Beacon,
    /// DNS-tunneling exfil shape (F detector).
    Tunnel,
    /// Algorithmically-generated label shape (F detector).
    Dga,
    /// The local reputation map shifted this host's weight.
    Reputation,
    /// A user Trust/Distrust flip taught the engine (G learning loop).
    Correction,
    /// Punycode/confusable label forging a high-value brand skeleton (F detector, 61F).
    Homoglyph,
    /// Host inside its newly-seen probation window (61F) — a MODIFIER witness that never
    /// testifies alone (the fusion admits it only beside a shape signal). Appended at the
    /// enum tail: existing wire indices never shift.
    Newborn,
}

/// The fused runtime verdict for ONE event on ONE host — what [`record_scored_at`] consumes in
/// place of the old bare `Risk`. `weight` is the licence penalty this event carries (the
/// runtime-config lane penalty plus the host's reputation baseline shift, floored at 0);
/// `confidence` is a 0..1 honesty scalar (more independent signals ⇒ higher).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ThreatScore {
    /// The risk lane the event lands in.
    pub risk: Risk,
    /// The licence penalty to apply (runtime table + reputation shift, ≥ 0).
    pub weight: i32,
    /// 0..1 — how many independent faculties agree.
    pub confidence: f32,
    /// Every faculty that saw something, in witness order.
    pub signals: Vec<Signal>,
}

/// The operator-tunable scoring law — `scoring.toml` beside the ledger. Every field defaults to
/// the compile-time constant it replaces, so a missing/partial/garbled file is HARMLESS
/// (serde `default` per table + per field; a parse failure keeps the previous law).
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct ScoringCfg {
    licence: LicenceCfg,
    penalty: PenaltyCfg,
    quarantine: QuarantineCfg,
    detection: DetectionCfg,
}

/// `[detection]` — the H-rung per-faculty kill switches (settings-pane toggles ride the SAME
/// scoring.toml hot-reload watcher; all default ON, and a garbled file keeps the sitting law).
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(default)]
struct DetectionCfg {
    dga: bool,
    tunnel: bool,
    beacon: bool,
    homoglyph: bool,
    newborn: bool,
}

impl Default for DetectionCfg {
    fn default() -> Self {
        DetectionCfg { dga: true, tunnel: true, beacon: true, homoglyph: true, newborn: true }
    }
}

/// The runtime detection-toggle read (`[detection]` in scoring.toml; defaults = all ON).
fn detection_cfg() -> DetectionCfg {
    scoring_cell().read().map(|g| g.detection.clone()).unwrap_or_default()
}

/// `[quarantine]` — the G-rung TTL circuit-breaker on earned sequestration.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(default)]
struct QuarantineCfg {
    /// Seconds a sequestered non-active-destroy host serves before the retest rung re-licences
    /// it (default 24h). The active-destroy class ignores this — earned-terminal stays law.
    ttl_secs: u64,
}

impl Default for QuarantineCfg {
    fn default() -> Self {
        QuarantineCfg { ttl_secs: QUARANTINE_TTL_SECS }
    }
}

/// The runtime quarantine TTL (scoring.toml `[quarantine] ttl_secs`, else the 24h constant).
fn quarantine_ttl_secs() -> u64 {
    scoring_cell()
        .read()
        .map(|g| g.quarantine.ttl_secs)
        .unwrap_or(QUARANTINE_TTL_SECS)
}

/// `[licence]` — the economy's thresholds.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(default)]
struct LicenceCfg {
    /// Every host starts with this many points (default [`LICENCE_START`]).
    start: i32,
    /// At or below this, penalties DOUBLE (default [`PROBATION_AT`]).
    probation_at: i32,
}

impl Default for LicenceCfg {
    fn default() -> Self {
        LicenceCfg { start: LICENCE_START, probation_at: PROBATION_AT }
    }
}

/// `[penalty]` — the per-lane licence bleed (defaults = [`Risk::base_penalty`], the graduated
/// 10/8/5/3/1 ladder).
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(default)]
struct PenaltyCfg {
    analytics: i32,
    ads: i32,
    tracker: i32,
    dns_leak: i32,
    ip_leak: i32,
    sonar: i32,
    mitm: i32,
    spoof: i32,
    malware: i32,
    cdn: i32,
}

impl Default for PenaltyCfg {
    fn default() -> Self {
        PenaltyCfg {
            analytics: Risk::Analytics.base_penalty(),
            ads: Risk::Ads.base_penalty(),
            tracker: Risk::Tracker.base_penalty(),
            dns_leak: Risk::DnsLeak.base_penalty(),
            ip_leak: Risk::IpLeak.base_penalty(),
            sonar: Risk::Sonar.base_penalty(),
            mitm: Risk::Mitm.base_penalty(),
            spoof: Risk::Spoof.base_penalty(),
            malware: Risk::Malware.base_penalty(),
            cdn: Risk::Cdn.base_penalty(),
        }
    }
}

/// One host's local reputation row — the RAM hot tier of the [`ReputationStore`]. `baseline`
/// shifts every future penalty for the host (negative = the user/corrections taught leniency);
/// `licence_start`/`probation_at` override the global thresholds when set (`None` = law).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Rep {
    baseline: i32,
    confidence: f32,
    licence_start: Option<i32>,
    probation_at: Option<i32>,
    /// True once a USER correction shaped this row (G rung) — the fusion then witnesses
    /// [`Signal::Correction`] instead of the anonymous [`Signal::Reputation`].
    corrected: bool,
}

/// Reputation mirror file name inside the armed durable dir (NAND tier of the RAM⊗NAND pair).
const REPUTATION_FILE_NAME: &str = "underground-reputation.tsv";
/// Scoring-law file name inside the armed durable dir (operator-editable, hot-reloaded).
const SCORING_FILE_NAME: &str = "scoring.toml";

static SCORING: OnceLock<RwLock<ScoringCfg>> = OnceLock::new();
/// mtime (unix secs) of the last-loaded scoring.toml — the hot-reload change gate.
static SCORING_MTIME: AtomicU64 = AtomicU64::new(0);
static REPUTATION: OnceLock<RwLock<HashMap<String, Rep>>> = OnceLock::new();
/// True when the RAM reputation tier has rows the NAND mirror has not seen.
static REPUTATION_DIRTY: AtomicBool = AtomicBool::new(false);

fn scoring_cell() -> &'static RwLock<ScoringCfg> {
    SCORING.get_or_init(|| RwLock::new(ScoringCfg::default()))
}

fn reputation_cell() -> &'static RwLock<HashMap<String, Rep>> {
    REPUTATION.get_or_init(|| RwLock::new(HashMap::new()))
}

fn scoring_path() -> Option<PathBuf> {
    ledger_dir_cell()
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|d| d.join(SCORING_FILE_NAME)))
}

fn reputation_path() -> Option<PathBuf> {
    ledger_dir_cell()
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|d| d.join(REPUTATION_FILE_NAME)))
}

/// (Re)load `scoring.toml` when its mtime moved (or `force`). A missing file re-arms the
/// compile-time defaults; a garbled file KEEPS the previous law (fail-open, never a panic) —
/// an operator's half-saved edit cannot zero the economy.
pub(crate) fn maybe_reload_scoring(force: bool) {
    let Some(path) = scoring_path() else {
        return;
    };
    let mtime = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if !force && mtime == SCORING_MTIME.load(Ordering::Relaxed) {
        return;
    }
    SCORING_MTIME.store(mtime, Ordering::Relaxed);
    let next = match std::fs::read_to_string(&path) {
        Ok(body) => match toml::from_str::<ScoringCfg>(&body) {
            Ok(cfg) => cfg,
            Err(_) => return, // garbled edit ⇒ keep the sitting law
        },
        Err(_) => ScoringCfg::default(), // no file ⇒ the compile-time defaults
    };
    if let Ok(mut guard) = scoring_cell().write() {
        *guard = next;
    }
}

/// The RUNTIME licence penalty for a lane (the [`Risk::base_penalty`] surpass point).
fn penalty_for(risk: &Risk) -> i32 {
    let Ok(guard) = scoring_cell().read() else {
        return risk.base_penalty();
    };
    let p = &guard.penalty;
    (match risk {
        Risk::Analytics => p.analytics,
        Risk::Ads => p.ads,
        Risk::Tracker => p.tracker,
        Risk::DnsLeak => p.dns_leak,
        Risk::IpLeak => p.ip_leak,
        Risk::Sonar => p.sonar,
        Risk::Mitm => p.mitm,
        Risk::Spoof => p.spoof,
        Risk::Malware => p.malware,
        Risk::Cdn => p.cdn,
        // A detector-coined lane has no scoring.toml row (yet) — the malware-tier constant
        // holds (10, the active-destroy tier a C2/exfil shape earns).
        Risk::Custom { .. } => risk.base_penalty(),
    })
    .max(0)
}

/// Does the box's OWN locally-grown evidence corroborate that this host is bad?
///
/// `true` when a reputation row exists with a POSITIVE baseline — the Underground has independently
/// seen this host behave badly (or a user correction taught it so). A negative baseline means the
/// box learned LENIENCY for the host, which is corroboration of the opposite and must not count.
///
/// This is the read behind blocklist SOURCE reputation: a list earns reputation on THIS box by the
/// share of its domains the Underground already judges bad on its own evidence. Nothing is asked of
/// a cloud, and a box with no history corroborates NOTHING rather than guessing — an honest zero.
pub(crate) fn corroborates_bad(host: &str) -> bool {
    let key = normalize(host);
    if key.is_empty() {
        return false;
    }
    reputation_cell()
        .read()
        .ok()
        .and_then(|rep| rep.get(&key).map(|r| r.baseline > 0))
        .unwrap_or(false)
}

/// Unconditionally empty the in-RAM reputation map. TEST-ONLY.
///
/// [`reputation_reset`] is NOT usable for this: it returns `false` and does NOTHING when the
/// Underground is disarmed (`:1218`), which is correct for the user-facing "forget what you
/// learned" action — a disarmed engine has nothing running to forget — but means a test calling it
/// on a disarmed engine silently keeps every row another test left behind. That is precisely how
/// the empty-store assertion failed with `left: 1, right: 0` while looking like a race.
#[cfg(test)]
pub(crate) fn reputation_clear_for_test() {
    if let Ok(mut g) = reputation_cell().write() {
        g.clear();
    }
}

/// How many hosts the local reputation store currently knows.
///
/// A source's corroboration share is meaningless when this is 0 — the box has learned nothing yet,
/// so EVERY source would score 0 and the panel would imply every list is worthless. Callers use
/// this to report "not yet judged" instead of a misleading zero.
pub(crate) fn reputation_rows() -> usize {
    reputation_cell().read().map(|r| r.len()).unwrap_or(0)
}

/// The host's licence ceiling: reputation override, else the runtime law, else the constant.
fn licence_start_for(host: &str) -> i32 {
    if let Ok(rep) = reputation_cell().read() {
        if let Some(r) = rep.get(host) {
            if let Some(v) = r.licence_start {
                return v.max(1);
            }
        }
    }
    scoring_cell()
        .read()
        .map(|g| g.licence.start.max(1))
        .unwrap_or(LICENCE_START)
}

/// The host's probation floor: reputation override, else the runtime law, else the constant.
fn probation_at_for(host: &str) -> i32 {
    if let Ok(rep) = reputation_cell().read() {
        if let Some(r) = rep.get(host) {
            if let Some(v) = r.probation_at {
                return v.max(0);
            }
        }
    }
    scoring_cell()
        .read()
        .map(|g| g.licence.probation_at.max(0))
        .unwrap_or(PROBATION_AT)
}

/// Upsert one host's reputation row in RAM with ABSOLUTE values and mark the NAND mirror dirty
/// (persisted on the same self-ticking pass as the ledger).
///
/// TEST-ONLY, and it must stay that way — this is a design constraint, not a convenience.
/// Production teaches reputation through [`reputation_learn`], which is ADDITIVE and clamps the
/// baseline to ±10 precisely so that "no amount of tapping escapes the licence economy". An
/// absolute setter reachable from the UI would defeat that: one call could pin any host to any
/// score. So this is deliberately NOT given an FFI front door.
///
/// The other conceivable caller — NAND restore — legitimately bypasses it too: `load_reputation`
/// rebuilds whole `Rep` rows including `licence_start` / `probation_at` / `corrected`, which this
/// cannot express, and takes the write lock ONCE for the entire file instead of per row.
///
/// `#[cfg(test)]` rather than `#[allow(dead_code)]`: measured crate-wide, every caller
/// (underground.rs:2701/2707/2755/2756/2814) is inside `mod tests` (line 2182). Gating states that
/// truth and ships no dead code, where the bare warning claimed a production caller was missing.
#[cfg(test)]
pub(crate) fn reputation_set(host: &str, baseline: i32, confidence: f32) {
    let key = normalize(host);
    if key.is_empty() {
        return;
    }
    if let Ok(mut guard) = reputation_cell().write() {
        let row = guard.entry(key).or_insert(Rep {
            baseline: 0,
            confidence: 0.0,
            licence_start: None,
            probation_at: None,
            corrected: false,
        });
        row.baseline = baseline;
        row.confidence = confidence.clamp(0.0, 1.0);
        REPUTATION_DIRTY.store(true, Ordering::Release);
    }
}

/// ADDITIVE reputation teaching (G rung) — a user correction SHIFTS the baseline (clamped to
/// ±10 so no amount of tapping escapes the licence economy) and raises confidence: the row is
/// now literally user-taught. Dirty-bit + the same NAND mirror as [`reputation_set`].
fn reputation_learn(host: &str, baseline_delta: i32, confidence_bump: f32) {
    let key = normalize(host);
    if key.is_empty() {
        return;
    }
    if let Ok(mut guard) = reputation_cell().write() {
        let row = guard.entry(key).or_insert(Rep {
            baseline: 0,
            confidence: 0.0,
            licence_start: None,
            probation_at: None,
            corrected: false,
        });
        row.baseline = (row.baseline + baseline_delta).clamp(-10, 10);
        row.confidence = (row.confidence + confidence_bump).clamp(0.0, 1.0);
        row.corrected = true;
        REPUTATION_DIRTY.store(true, Ordering::Release);
    }
}

/// Serialize the RAM reputation tier: `#underground-reputation v1` header, then one
/// `host<TAB>baseline<TAB>confidence<TAB>licence_start-or-dash<TAB>probation_at-or-dash` row per
/// host, host-sorted (stable diffs, the ledger idiom).
fn serialize_reputation(map: &HashMap<String, Rep>) -> String {
    let mut out = String::with_capacity(32 + map.len() * 48);
    out.push_str("#underground-reputation v1\n");
    let mut hosts: Vec<&String> = map.keys().collect();
    hosts.sort();
    for h in hosts {
        let r = &map[h];
        let ls = r.licence_start.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
        let pa = r.probation_at.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
        let co = if r.corrected { "c" } else { "-" };
        out.push_str(&format!("{h}\t{}\t{:.3}\t{ls}\t{pa}\t{co}\n", r.baseline, r.confidence));
    }
    out
}

/// Persist the reputation RAM tier to its NAND mirror — atomic tmp+rename beside the ledger
/// (the [`persist_ledger`] idiom), gated on the dirty bit so an unchanged map costs zero IO.
pub(crate) fn persist_reputation() {
    if !REPUTATION_DIRTY.swap(false, Ordering::AcqRel) {
        return;
    }
    let Some(path) = reputation_path() else {
        return;
    };
    let body = {
        let Ok(guard) = reputation_cell().read() else {
            return;
        };
        serialize_reputation(&guard)
    };
    let tmp = path.with_extension("tsv.tmp");
    if std::fs::write(&tmp, body.as_bytes()).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Rehydrate the reputation RAM tier from its NAND mirror. Malformed rows are skipped
/// fail-open (the [`parse_body`] law) — one bad row never blanks the map.
fn load_reputation() {
    let Some(path) = reputation_path() else {
        return;
    };
    let Ok(body) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(mut guard) = reputation_cell().write() else {
        return;
    };
    guard.clear();
    for line in body.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        // 5 columns = an E-era file (corrected reads back false); 6 = with the G flag.
        if !(5..=6).contains(&f.len()) || f[0].is_empty() {
            continue;
        }
        let Ok(baseline) = f[1].parse::<i32>() else {
            continue;
        };
        let Ok(confidence) = f[2].parse::<f32>() else {
            continue;
        };
        let opt = |s: &str| if s == "-" { None } else { s.parse::<i32>().ok() };
        guard.insert(
            f[0].to_string(),
            Rep {
                baseline,
                confidence: confidence.clamp(0.0, 1.0),
                licence_start: opt(f[3]),
                probation_at: opt(f[4]),
                corrected: f.get(5) == Some(&"c"),
            },
        );
    }
}

/// Fuse one resolved-row event into a [`ThreatScore`] — the E brain's front door, grown F
/// eyes. `None` = benign AND shape-clean (the [`classify`] post-filter law holds: benign is
/// recorded NOWHERE — but since the F rung, a host whose SHAPE runs hot (DGA label /
/// tunnel burst / beacon cadence / NX-burst) earns a [`Risk::Custom`] lane even when every
/// suffix list is blind to it — that is the whole point of the Detection suite). Fusion:
/// the lane's runtime penalty is the base weight; the local reputation baseline shifts it
/// (floored at 0 — reputation can pardon, never invert into a reward); each independent
/// faculty that saw something appends its [`Signal`] and raises `confidence`. Detectors only
/// RAISE score — the teeth path is untouched (`answer_len`/`rcode` ride in from the one
/// `resolve_datapath` CP-U seam; hosts the resolver never answered feed the rings nothing).
pub(crate) fn score_host(
    host: &str,
    qtype: u16,
    event: NavEvent,
    answer_len: u32,
    rcode: u8,
) -> Option<ThreatScore> {
    let key = normalize(host);
    let classified = classify(&key, qtype, event);
    let mut signals: Vec<Signal> = Vec::with_capacity(4);
    if matches!(classified, Some((_, Source::Suffix)))
        || suffix_hit(&key, ADS)
        || suffix_hit(&key, ANALYTICS)
        || suffix_hit(&key, TELEMETRY)
    {
        signals.push(Signal::Suffix);
    }
    if event == NavEvent::RebindReject {
        signals.push(Signal::GeoRebind);
    }
    // ── The F detectors — three independent faculties, each RAM-only + offline. H rung: each
    //    rides its own `[detection]` kill switch (settings-pane toggles, hot-reloaded). ──
    let now = now_secs();
    let det = detection_cfg();
    // 61F: the first-seen registry FEEDS on every scored row (the tunnel-ring RAM-only
    // per-host precedent — benign still reaches the ledger NOWHERE); the mark itself only
    // testifies beside a shape witness, below.
    let newborn = det.newborn && crate::detection::newborn::newborn_at(&key, now);
    // ★ #88 — an operator-minted distribution ID is an ADDRESSING SCHEME, not evidence. The scorer
    // only ever sees the leading label, so `d17vo8z6jop21h.cloudfront.net` reads as pure DGA shape.
    // Suppress the randomness faculty for those hosts; every other detector below stays live against
    // them, so abuse staged behind a CDN is still scored.
    if det.dga
        && !crate::detection::dga::label_is_distribution_id(&key)
        && crate::detection::dga::dga_score(key.split('.').next().unwrap_or(""))
            >= crate::detection::dga::DGA_THRESHOLD
    {
        signals.push(Signal::Dga);
    }
    if det.tunnel
        && (crate::detection::tunnel::tunnel_signal_at(&key, qtype, answer_len, now).is_some()
            || crate::detection::beacon::nx_burst(&key, qtype, rcode, now))
    {
        signals.push(Signal::Tunnel);
    }
    if det.beacon && crate::detection::beacon::beacon_signal_at(&key, now).is_some() {
        signals.push(Signal::Beacon);
    }
    // 61F: a label that RENDERS as a brand it is not — any label of the name can carry the
    // forgery (the registrable label usually does; `www.xn--pple-43d.com` must still fire).
    if det.homoglyph
        && key
            .split('.')
            .any(|l| crate::detection::homoglyph::homoglyph_hit(l).is_some())
    {
        signals.push(Signal::Homoglyph);
    }
    // 61F probation: newborn NEVER testifies alone — fresh domain + hot shape is the
    // phish/C2 pairing; "newly seen" beside a curated-list hit (or beside nothing) is
    // first-install noise, not evidence.
    if newborn
        && signals.iter().any(|s| {
            matches!(s, Signal::Dga | Signal::Tunnel | Signal::Beacon | Signal::Homoglyph)
        })
    {
        signals.push(Signal::Newborn);
    }
    // The lane: classified wins; else the FIRST-fired detector coins a Custom lane; else
    // (benign + shape-clean) nothing was witnessed at all.
    let risk = match classified {
        Some((risk, _)) => risk,
        None => {
            let slug = if signals.contains(&Signal::Homoglyph) {
                "homoglyph"
            } else if signals.contains(&Signal::Dga) {
                "dga"
            } else if signals.contains(&Signal::Tunnel) {
                "tunnel"
            } else if signals.contains(&Signal::Beacon) {
                "beacon"
            } else {
                return None;
            };
            Risk::Custom { slug: slug.to_string() }
        }
    };
    let mut weight = penalty_for(&risk);
    let mut rep_conf = 0.0_f32;
    if let Ok(rep) = reputation_cell().read() {
        if let Some(r) = rep.get(&key) {
            if r.baseline != 0 {
                weight = (weight + r.baseline).max(0);
                rep_conf = r.confidence;
                // G rung: a user-taught row testifies AS the user's correction.
                signals.push(if r.corrected { Signal::Correction } else { Signal::Reputation });
            }
        }
    }
    // Honesty scalar: one witness = 0.4; each further independent faculty +0.15; a confident
    // reputation row adds up to +0.3 of its own confidence. Deterministic, test-asserted.
    let confidence = (0.4 + 0.15 * signals.len().saturating_sub(1) as f32 + 0.3 * rep_conf)
        .clamp(0.0, 1.0);
    Some(ThreatScore { risk, weight, confidence, signals })
}

/// The CURRENT fused score of an already-witnessed host — the `underground_score` read export.
/// `None` = the store never saw it (benign is recorded nowhere) or the store is disarmed.
pub(crate) fn score_of(host: &str) -> Option<ThreatScore> {
    if !armed() {
        return None;
    }
    let key = normalize(host);
    let (risk, source) = {
        let guard = store().read().ok()?;
        let e = guard.by_host.get(&key)?;
        (e.risk.clone(), e.source)
    };
    let mut signals: Vec<Signal> = Vec::with_capacity(2);
    if source == Source::Suffix {
        signals.push(Signal::Suffix);
    }
    let mut weight = penalty_for(&risk);
    let mut rep_conf = 0.0_f32;
    if let Ok(rep) = reputation_cell().read() {
        if let Some(r) = rep.get(&key) {
            if r.baseline != 0 {
                weight = (weight + r.baseline).max(0);
                rep_conf = r.confidence;
                // G rung: a user-taught row testifies AS the user's correction.
                signals.push(if r.corrected { Signal::Correction } else { Signal::Reputation });
            }
        }
    }
    let confidence = (0.4 + 0.15 * signals.len().saturating_sub(1) as f32 + 0.3 * rep_conf)
        .clamp(0.0, 1.0);
    Some(ThreatScore { risk, weight, confidence, signals })
}

// ── The G rung: correction log + live verdict event ring ────────────────────────────────────────

impl Signal {
    /// Stable wire slug for the event stream (the [`Risk::slug`] idiom).
    fn slug(&self) -> &'static str {
        match self {
            Signal::Suffix => "suffix",
            Signal::GeoMitm => "geo-mitm",
            Signal::GeoRebind => "geo-rebind",
            Signal::Beacon => "beacon",
            Signal::Tunnel => "tunnel",
            Signal::Dga => "dga",
            Signal::Homoglyph => "homoglyph",
            Signal::Newborn => "newborn",
            Signal::Reputation => "reputation",
            Signal::Correction => "correction",
        }
    }
}

/// One user correction — the literal "GROWS with the user" record: the pin flip that taught
/// the engine. RAM ring (cap [`CORRECTIONS_CAP`]) + NAND audit log beside the ledger.
#[derive(Debug, Clone, PartialEq)]
struct Correction {
    host: String,
    from: Verdict,
    to: Verdict,
    ts: u64,
}

const CORRECTIONS_FILE_NAME: &str = "underground-corrections.tsv";
/// Newest CORRECTIONS_CAP corrections are kept (RAM and NAND alike) — an audit trail, not a
/// hoard.
const CORRECTIONS_CAP: usize = 256;

static CORRECTIONS: OnceLock<RwLock<VecDeque<Correction>>> = OnceLock::new();

fn corrections_cell() -> &'static RwLock<VecDeque<Correction>> {
    CORRECTIONS.get_or_init(|| RwLock::new(VecDeque::new()))
}

fn corrections_path() -> Option<PathBuf> {
    ledger_dir_cell()
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|d| d.join(CORRECTIONS_FILE_NAME)))
}

/// Append one correction to the RAM ring + rewrite the NAND log (atomic tmp+rename, the
/// [`persist_reputation`] idiom — corrections arrive at user-tap cadence, IO is negligible).
fn log_correction(c: Correction) {
    if let Ok(mut guard) = corrections_cell().write() {
        guard.push_back(c);
        while guard.len() > CORRECTIONS_CAP {
            guard.pop_front();
        }
        let Some(path) = corrections_path() else {
            return;
        };
        let mut body = String::with_capacity(32 + guard.len() * 48);
        body.push_str("#underground-corrections v1\n");
        for c in guard.iter() {
            body.push_str(&format!("{}\t{}\t{}\t{}\n", c.host, c.from.slug(), c.to.slug(), c.ts));
        }
        let tmp = path.with_extension("tsv.tmp");
        if std::fs::write(&tmp, body.as_bytes()).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// Rehydrate the correction ring from its NAND log (fail-open per row, the [`parse_body`] law).
fn load_corrections() {
    let Some(path) = corrections_path() else {
        return;
    };
    let Ok(body) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(mut guard) = corrections_cell().write() else {
        return;
    };
    guard.clear();
    for line in body.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 4 || f[0].is_empty() {
            continue;
        }
        guard.push_back(Correction {
            host: f[0].to_string(),
            from: Verdict::from_slug(f[1]),
            to: Verdict::from_slug(f[2]),
            ts: f[3].parse().unwrap_or(0),
        });
        while guard.len() > CORRECTIONS_CAP {
            guard.pop_front();
        }
    }
}

/// One live verdict-stream event — what the H-rung dashboard subscribes to. `seq` is the
/// monotonic dedup key (a same-second burst stays ordered and distinguishable).
#[derive(Debug, Clone, uniffi::Record)]
pub struct VerdictEvent {
    pub seq: u64,
    pub host: String,
    /// The host's verdict slug at emit time (`trusted`/`distrusted`/`neutral`).
    pub verdict: String,
    /// Licence delta this event applied (negative = bleed, positive = restore, 0 = pin only).
    pub score_delta: i32,
    /// The primary witnessing signal's slug (or the risk lane's slug for a pure lane hit).
    pub signal: String,
    pub ts: u64,
}

/// RAM ring cap — the WARDEN_ENFORCE tally idiom, but carrying rows: 64 newest events.
const EVENT_RING_CAP: usize = 64;

static EVENTS: OnceLock<RwLock<VecDeque<VerdictEvent>>> = OnceLock::new();
/// Monotonic event sequence (lock-free; the AtomicUsize-head idiom from the Warden tally).
static EVENT_SEQ: AtomicU64 = AtomicU64::new(0);

fn events_cell() -> &'static RwLock<VecDeque<VerdictEvent>> {
    EVENTS.get_or_init(|| RwLock::new(VecDeque::new()))
}

/// Push one event onto the RAM ring (oldest drops at cap). RAM-ONLY by design — the stream is
/// live telemetry, not a record; the ledger/corrections/reputation mirrors are the record.
fn push_event(host: &str, verdict: &Verdict, score_delta: i32, signal: &str, ts: u64) {
    let seq = EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut guard) = events_cell().write() {
        guard.push_back(VerdictEvent {
            seq,
            host: host.to_string(),
            verdict: verdict.slug().to_string(),
            score_delta,
            signal: signal.to_string(),
            ts,
        });
        while guard.len() > EVENT_RING_CAP {
            guard.pop_front();
        }
    }
}

/// The live event stream read — newest-last snapshot of the RAM ring (≤[`EVENT_RING_CAP`]
/// rows). The Kotlin Flow polls this and forwards only seq-fresh rows; unarmed ⇒ empty.
pub(crate) fn events_snapshot() -> Vec<VerdictEvent> {
    if !armed() {
        return Vec::new();
    }
    events_cell().read().map(|g| g.iter().cloned().collect()).unwrap_or_default()
}

/// H rung — the settings-pane RESET button: forget every learned reputation row AND the
/// correction audit log, RAM + NAND alike (the engine returns to the compile-time law; the
/// LEDGER — hits/licences/verdicts — is untouched). True iff anything was actually forgotten.
pub(crate) fn reputation_reset() -> bool {
    if !armed() {
        return false;
    }
    let mut any = false;
    if let Ok(mut g) = reputation_cell().write() {
        any |= !g.is_empty();
        g.clear();
    }
    // Dirty-bit forced: the persist writes the EMPTY map over the NAND mirror.
    REPUTATION_DIRTY.store(true, Ordering::Release);
    persist_reputation();
    if let Ok(mut c) = corrections_cell().write() {
        any |= !c.is_empty();
        c.clear();
    }
    if let Some(path) = corrections_path() {
        let tmp = path.with_extension("tsv.tmp");
        if std::fs::write(&tmp, b"#underground-corrections v1\n").is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
    any
}

// ── Licence mechanics ───────────────────────────────────────────────────────────────────────────

/// Apply one accident's penalty to an entry: probation DOUBLES the graduated base, the floor is
/// 0, and a drained licence sequestrates — UNLESS the content-lane law protects it (Centauri) or
/// the user has manually pinned a verdict (the Trust bands OVERRIDE the automatic licence).
fn deduct(e: &mut Entry, weight: i32, now: u64) {
    match e.verdict {
        // Vouched — immune to the bleed: the accident is still witnessed (hits/recorded count),
        // but the licence stays pinned full and the host never sequestrates.
        Verdict::Trusted => {
            e.points = licence_start_for(&e.host);
            e.sequestrated = false;
            append_underground_log(&UndergroundJudgement {
                ts: now,
                verb: UndergroundVerb::Pinned,
                host: e.host.clone(),
                lane: e.risk.slug(),
                penalty: 0,
                points: e.points,
            });
            return;
        }
        // Condemned — already sequestrated at 0; the pin holds regardless of provenance.
        Verdict::Distrusted => {
            e.points = 0;
            e.sequestrated = true;
            append_underground_log(&UndergroundJudgement {
                ts: now,
                verb: UndergroundVerb::Condemned,
                host: e.host.clone(),
                lane: e.risk.slug(),
                penalty: weight.max(0),
                points: 0,
            });
            return;
        }
        Verdict::Neutral => {}
    }
    // E rung: the penalty arrives PRE-FUSED (runtime lane table + reputation shift) — the
    // probation doubling and the sequestration law stay exactly where they were.
    let mut penalty = weight;
    if e.points <= probation_at_for(&e.host) {
        penalty *= 2;
    }
    e.points = (e.points - penalty).max(0);
    // The review channel narrates the judgement BEFORE the sequestration branch, so the log carries the
    // whole descent (every DEDUCT with its lane and remaining licence) and not merely the final verdict
    // — that descent is exactly what #26 needed and did not have.
    let verb = if e.points == 0 {
        UndergroundVerb::Sequestrate
    } else if e.points <= probation_at_for(&e.host) {
        UndergroundVerb::Probation
    } else {
        UndergroundVerb::Deduct
    };
    append_underground_log(&UndergroundJudgement {
        ts: now,
        verb,
        host: e.host.clone(),
        lane: e.risk.slug(),
        penalty,
        points: e.points,
    });
    if e.points == 0 && e.source != Source::Centauri {
        // G rung: an AUTOMATIC sequestration stamps the quarantine clock (only on the
        // close edge — a re-accident against an already-quarantined host never re-arms it).
        if !e.sequestrated {
            e.seq_at = now;
        }
        e.sequestrated = true;
    }
}

/// #84-A — is this charge a DUPLICATE PROBE of one the court already heard this second?
///
/// ★ MEASURED ON DEVICE (2026-07-26, Socio's monochrome.tf playback test). The #81 review channel
/// caught the Underground charging ONE navigation THREE times:
/// ```text
/// 1785038502 DEDUCT fonts.googleapis.com cdn -1 licence=19
/// 1785038502 DEDUCT fonts.googleapis.com cdn -1 licence=18
/// 1785038502 DEDUCT fonts.googleapis.com cdn -1 licence=17
/// ```
/// Same host, same SECOND, three deductions. That is the browser's `A` + `AAAA` + `HTTPS` triple —
/// every modern browser fires all three for a single navigation. Charging per-qtype means a wholly
/// innocent CDN bleeds 3 licences per page view: 20 ÷ 3 ⇒ SEQUESTRATED in ~7 views, after which the
/// teeth gate answers it forever as a forged NXDOMAIN (`0ms`, transport `-`). That is precisely the
/// "biting my queries offline by 0ms every single time" Socio reported, and the durable ledger is
/// why it survived reinstalls (hence #79's epoch amnesty).
///
/// #77 already taught `nx_burst` this lesson via a qtype discriminator, but the ORDINARY deduct
/// path never learned it. THE LAW: **one navigation is one event.** The qtype must never multiply a
/// penalty. The accident is still WITNESSED (hits/recorded_total keep counting, so the census and
/// the detection heuristics see the full traffic) — only the LICENCE stops being charged twice for
/// one crime.
///
/// Pure and total: `first_witness` (the row was created by this very call) can never be a duplicate,
/// and a strictly-later second is always a fresh charge.
pub(crate) fn is_duplicate_probe(first_witness: bool, prior_seen: u64, now: u64) -> bool {
    !first_witness && prior_seen == now
}

/// #84-B — is `source` a host the OFFLINE CDN is serving, and therefore not chargeable?
///
/// ★ MEASURED ALONGSIDE THE ABOVE. `cache/query.log` showed `cdn.jsdelivr.net A/AAAA CLOAK 0ms -`
/// and `fonts.googleapis.com A/AAAA CLOAK 0ms -` — Centauri SUCCEEDING, serving both from the signed
/// offline catalog — while `query-underground.log` deducted their licences on the `cdn` lane in the
/// same instant. Two pillars fighting over one host.
///
/// A cloaked host is answered locally and never reaches the network, so nothing it "did" can be
/// evidence against it: the offline-CDN win was being read as suspicious traffic. [`deduct`] already
/// refuses to SEQUESTRATE a [`Source::Centauri`] row (see the `e.source != Source::Centauri` guard on
/// the sequestration branch), and the #79 amnesty already yields to Centauri wholesale — so bleeding
/// the licence toward a zero that can never bite does nothing but make the dashboard LIE, reporting
/// `0 licences` for a host that is in perfect standing. Same shape as [`Verdict::Trusted`]: witness
/// the accident, pin the licence.
pub(crate) fn cloak_is_immune(source: Source) -> bool {
    matches!(source, Source::Centauri)
}

/// Record one accident against `host` at `now` with the OLD bare-risk shape — a thin front over
/// [`record_scored_at`] that builds the minimal single-witness [`ThreatScore`] (runtime lane
/// penalty, no extra signals).
///
/// Its doc used to say "Kept so every pre-E witness seam and test reads unchanged". Measured: no
/// pre-E witness seam survives — every production path now records through `record_scored_at` with
/// a FUSED score, which is the point of the E brain (the lane penalty is only the base weight; the
/// local reputation baseline and the independent F-rung signals shift it). The only callers left
/// are the ledger/licence tests, which want a minimal single-witness accident.
///
/// `#[cfg(test)]` states that; the bare warning implied a production caller was missing when the
/// production shape had simply moved on.
#[cfg(test)]
fn record_at(host: &str, risk: Risk, source: Source, now: u64) {
    let score = ThreatScore {
        weight: penalty_for(&risk),
        risk,
        confidence: 0.4,
        signals: Vec::new(),
    };
    record_scored_at(host, &score, source, now);
}

/// Record one FUSED accident against `host` at `now` — the E brain's consume seam. A new host
/// enters with its per-host licence ceiling minus the first weighted penalty; a repeat bumps
/// hits + deducts (original risk/source provenance is KEPT — the first witness owns the row;
/// only the licence bleeds).
fn record_scored_at(host: &str, score: &ThreatScore, source: Source, now: u64) {
    let key = normalize(host);
    if key.is_empty() {
        return;
    }
    let start = licence_start_for(&key);
    let Ok(mut guard) = store().write() else {
        return; // poisoned ⇒ fail-open: skip the accident, never panic the datapath
    };
    guard.recorded_total += 1;
    let entry = guard.by_host.entry(key.clone()).or_insert_with(|| Entry {
        host: key,
        risk: score.risk.clone(),
        source,
        hits: 0,
        points: start,
        first_seen: now,
        last_seen: now,
        last_heal: now,
        country: None,
        sequestrated: false,
        verdict: Verdict::Neutral,
        seq_at: 0,
    });
    // #84 — read the row's PRIOR state before we stamp it, so the charge gate can see whether the
    // court already heard this host this second (the A/AAAA/HTTPS triple) and whether Centauri owns
    // it. `hits == 0` is the unambiguous "this call created the row" tell.
    let first_witness = entry.hits == 0;
    let prior_seen = entry.last_seen;
    entry.hits += 1;
    entry.last_seen = now;
    let before = entry.points;
    // The accident is ALWAYS witnessed above (hits + recorded_total), so the census, the detection
    // heuristics and the event ring all still see the full traffic. Only the LICENCE charge is gated.
    let duplicate = is_duplicate_probe(first_witness, prior_seen, now);
    let immune = cloak_is_immune(entry.source);
    if duplicate || immune {
        // Pin the licence and narrate the mercy — the review channel must show its work here too, or
        // #84 becomes invisible the moment it regresses. `Pinned` is the existing "witnessed, not
        // charged" verb (see the `Verdict::Trusted` arm of `deduct`), which is exactly this case.
        append_underground_log(&UndergroundJudgement {
            ts: now,
            verb: UndergroundVerb::Pinned,
            host: entry.host.clone(),
            lane: entry.risk.slug(),
            penalty: 0,
            points: entry.points,
        });
    } else {
        deduct(entry, score.weight, now);
    }
    // G rung: every applied accident lands on the live event ring (delta = the real bleed
    // after probation doubling; the primary witness names itself, a bare lane hit names the
    // lane).
    let delta = entry.points - before;
    let signal =
        score.signals.first().map(|s| s.slug().to_string()).unwrap_or_else(|| entry.risk.slug());
    let (host_ev, verdict_ev) = (entry.host.clone(), entry.verdict);
    drop(guard);
    push_event(&host_ev, &verdict_ev, delta, &signal, now);
}

/// Manually pin `host`'s trust verdict — the re-homed Trust bands surface. `code`: 0=Neutral
/// (clear the pin; the automatic licence resumes from the CURRENT points), 1=Trusted (immune —
/// un-sequester + pin the licence full), 2=Distrusted (condemned — sequester + drain to 0).
/// Find-or-create the entry so a NEVER-seen host can be pre-trusted or pre-blocked (a manual
/// row carries user-curated provenance: the Suffix lane, the Underground's own curation). The
/// verdict persists immediately (the pin is durable — it is the whole point of "grows with the
/// user"). FAIL-OPEN false: unarmed / empty host / poisoned lock, never a panic.
pub(crate) fn set_verdict(host: &str, code: u8) -> bool {
    if !armed() {
        return false;
    }
    let key = normalize(host);
    if key.is_empty() {
        return false;
    }
    let verdict = Verdict::from_code(code);
    let now = now_secs();
    let start = licence_start_for(&key);
    let from = {
        let Ok(mut guard) = store().write() else {
            return false;
        };
        let entry = guard.by_host.entry(key.clone()).or_insert_with(|| Entry {
            host: key,
            // A pre-emptive pin with no automatic witness yet: the honest fallback lane (Tracker,
            // as the resolver's own unattributed-deny fallback) + user-curation provenance.
            risk: Risk::Tracker,
            source: Source::Suffix,
            hits: 0,
            points: start,
            first_seen: now,
            last_seen: now,
            last_heal: now,
            country: None,
            sequestrated: false,
            verdict: Verdict::Neutral,
            seq_at: 0,
        });
        let from = entry.verdict;
        entry.verdict = verdict;
        entry.last_seen = now;
        match verdict {
            Verdict::Trusted => {
                entry.sequestrated = false;
                entry.points = start;
            }
            Verdict::Distrusted => {
                entry.sequestrated = true;
                entry.points = 0;
            }
            // Neutral clears the pin but leaves the licence/seq where they stand — the automatic
            // engine picks the host back up from its real current standing.
            Verdict::Neutral => {}
        }
        from
    };
    // G rung — the learning loop: a REAL flip (from ≠ to) is a correction. It lands in the
    // NAND audit log, TEACHES the reputation row (Trust = leniency, Distrust = severity,
    // Neutral = a hand-back that only firms confidence), and streams live. A same-pin re-tap
    // teaches nothing.
    if from != verdict {
        let key = normalize(host);
        log_correction(Correction { host: key.clone(), from, to: verdict, ts: now });
        let (delta, bump) = match verdict {
            Verdict::Trusted => (-3, 0.25),
            Verdict::Distrusted => (3, 0.25),
            Verdict::Neutral => (0, 0.10),
        };
        reputation_learn(&key, delta, bump);
        persist_reputation();
        push_event(&key, &verdict, 0, "correction", now);
    }
    persist_ledger();
    true
}

/// Heal every entry that earned it at `now`: not sequestrated (terminal), not active-destroy
/// (the mitigation ceiling), and FULLY idle — ≥[`RECOVERY_IDLE_SECS`] since BOTH the last
/// accident and the last heal (so healing paces itself, one step per idle window).
fn settle_recovery_at(now: u64) {
    let Ok(mut guard) = store().write() else {
        return;
    };
    let mut healed_points: u64 = 0;
    let ttl = quarantine_ttl_secs();
    for e in guard.by_host.values_mut() {
        let start = licence_start_for(&e.host);
        // G rung — the quarantine RETEST: an EARNED sequestration is no longer permadeath.
        // A non-active-destroy Neutral host whose TTL expired AND whose recent window ran
        // clean (no accident in the last quarter of the TTL — an actively-hammering C2
        // keeps its own clock hot and never walks) is re-licenced in full and handed back
        // to the automatic economy. Malware/Spoof/Mitm/Custom stay EARNED-terminal; a
        // Distrusted pin is the user's own law and only the user lifts it.
        if e.sequestrated
            && !e.risk.is_active_destroy()
            && e.verdict == Verdict::Neutral
            && e.seq_at > 0
            && now >= e.seq_at.saturating_add(ttl)
            && now.saturating_sub(e.last_seen) >= ttl / 4
        {
            e.sequestrated = false;
            e.seq_at = 0;
            let restored = (start - e.points).max(0);
            e.points = start;
            e.last_heal = now;
            healed_points += restored as u64;
            push_event(&e.host, &e.verdict, restored, "retest", now);
            continue;
        }
        if e.sequestrated || e.risk.is_active_destroy() || e.points >= start {
            continue;
        }
        let idle_since = e.last_seen.max(e.last_heal);
        if now.saturating_sub(idle_since) >= RECOVERY_IDLE_SECS {
            e.points = (e.points + RECOVERY_STEP).min(start);
            e.last_heal = now;
            healed_points += RECOVERY_STEP as u64;
        }
    }
    guard.recovered_total += healed_points;
}

// ── The datapath surface ────────────────────────────────────────────────────────────────────────

/// Fast armed check for the datapath seams (Acquire pairs with [`arm`]'s Release).
pub(crate) fn armed() -> bool {
    ARMED.load(Ordering::Acquire)
}

/// THE TEETH — consulted by `resolve_inner` step 1b. True iff `host` is sequestrated: the caller
/// synthesizes NXDOMAIN (zero egress) and this store counts the bite. FAIL-OPEN false: unarmed,
/// unknown, content-lane, or poisoned-lock hosts all pass — the teeth can only close on a
/// licence PROVABLY drained to 0.
pub(crate) fn teeth_gate(host: &str) -> bool {
    if !armed() {
        return false;
    }
    let key = normalize(host);
    let Ok(mut guard) = store().write() else {
        return false;
    };
    // The manual Trust bands OVERRIDE the automatic licence at the datapath: a vouched host never
    // bites (even if some stale state left it sequestrated), a condemned host always bites (even
    // at a full licence — the user's kill is immediate). A Neutral host falls to the licence.
    match guard.by_host.get(&key).map(|e| (e.verdict, e.sequestrated)) {
        Some((Verdict::Trusted, _)) => false,
        Some((Verdict::Distrusted, _)) => {
            guard.teeth_total += 1;
            true
        }
        Some((Verdict::Neutral, true)) => {
            guard.teeth_total += 1;
            true
        }
        _ => false,
    }
}

/// THE FEED — one call per resolved row from the `resolve_datapath` seam. Classifies, records,
/// and self-ticks settle + persist (≥[`PERSIST_MIN_GAP_SECS`] gaps keep the O(n) walks off the
/// per-query budget). Unarmed ⇒ complete no-op (the fleet-cold fast path). Since the F rung
/// the seam also carries `answer_len` (answer wire bytes, 0 = no answer) + `rcode` (DNS
/// header RCODE) — the tunnel ring + NX-burst faculties eat the answer SHAPE, never its
/// content (no packet payload is retained anywhere in the Underground).
pub(crate) fn feed(qname: &str, qtype: u16, event: NavEvent, answer_len: u32, rcode: u8) {
    if !armed() {
        return;
    }
    let now = now_secs();
    let host = normalize(qname);
    // ★ NO-SELF-ECHO LAW (companion to the no-self-witness law at `resolver/mod.rs:1431`). A
    // `Blocked` row for a host that is ALREADY sequestrated is this engine hearing its OWN teeth
    // (`resolver/mod.rs:1548`) — not a fresh navigation accident. Recording it bumps `last_seen`,
    // and the quarantine retest (`:1373`) demands a QUIET recent window (`now - last_seen >=
    // ttl/4`) before it re-licences. A browser that keeps retrying a blocked host would therefore
    // keep the clock permanently hot and the retest could NEVER fire — turning an EARNED,
    // time-limited quarantine into permadeath, which is exactly what the G rung forbids. The user
    // still sees the block; the ledger simply refuses to treat its own denial as new evidence.
    if matches!(event, NavEvent::Blocked) {
        if let Ok(guard) = store().read() {
            if guard
                .by_host
                .get(&host)
                .is_some_and(|e| e.sequestrated && e.verdict == Verdict::Neutral)
            {
                return;
            }
        }
    }
    // E rung: the fused ThreatScore (runtime lane table + reputation + signal witnesses) is
    // what the record path consumes — provenance still rides classify's Source lane. F rung:
    // a detector-coined Custom lane has no classify row — the Suffix lane (the Underground's
    // OWN curation/faculties) is its honest provenance.
    if let Some(score) = score_host(&host, qtype, event, answer_len, rcode) {
        let source = classify(&host, qtype, event)
            .map(|(_, s)| s)
            .unwrap_or(Source::Suffix);
        record_scored_at(&host, &score, source, now);
    }
    // Self-ticking maintenance: at most one settle+persist pass per gap, riding the traffic
    // itself (no GUI tick dependency; an idle box simply has nothing new to persist).
    let last = LAST_TICK_SECS.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= PERSIST_MIN_GAP_SECS
        && LAST_TICK_SECS
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        maybe_reload_scoring(false);
        settle_recovery_at(now);
        persist_ledger();
        persist_reputation();
    }
}

// ── Durable ledger (TSV v1) ─────────────────────────────────────────────────────────────────────

// ── The per-pillar review channel (`query-underground.log`, the #133 convention) ─────────────────
//
// ★ WHY THIS EXISTS — earned the hard way. ROOT CAUSE #26 (nx_burst convicting healthy IPv4-only hosts
// on the browser's routine AAAA/HTTPS probes) took an entire session to find, because the Underground
// Layer was the ONLY pillar with no review channel: Centauri writes `query-centauri.log`, MaskSolver
// writes `query-masksolver.log`, the blocklist writes `query-blocklist.log` — but the layer that
// SEQUESTRATES hosts wrote nothing. The condemnation was only visible as its own aftermath (a REJECT
// row with `0ms` and no transport in `cache/query.log`) and had to be reconstructed backwards from the
// ledger. ONE line at the moment of judgement would have named wildriftfire.cc, its lane, and its
// collapsing licence in seconds. A layer that can convict must show its work.

/// The per-pillar log filename — a sibling of `underground-ledger.tsv` in the armed durable dir.
pub const QUERY_UNDERGROUND_LOG_NAME: &str = "query-underground.log";

/// The human-legible judgement verb — the greppable first token after the timestamp.
///   - `DEDUCT`      — an accident cost the host licence points; it is still serving.
///   - `SEQUESTRATE` — the licence reached 0: from here the teeth gate answers for this host.
///   - `PROBATION`   — the host fell to/below the probation floor (penalties now DOUBLE).
///   - `PINNED`      — a `Trusted` host took an accident and was held at full licence (immune).
///   - `CONDEMNED`   — a `Distrusted` host: pinned at 0, sequestrated by verdict, not by bleed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UndergroundVerb {
    Deduct,
    Sequestrate,
    Probation,
    Pinned,
    Condemned,
    /// ★ #79 — a heuristic conviction VACATED because the logic that made it was proven wrong.
    Amnesty,
}

impl UndergroundVerb {
    fn token(self) -> &'static str {
        match self {
            UndergroundVerb::Deduct => "DEDUCT",
            UndergroundVerb::Sequestrate => "SEQUESTRATE",
            UndergroundVerb::Probation => "PROBATION",
            UndergroundVerb::Pinned => "PINNED",
            UndergroundVerb::Condemned => "CONDEMNED",
            UndergroundVerb::Amnesty => "AMNESTY",
        }
    }
}

/// One judgement event — the structured twin of a `query-underground.log` line. The clock is INJECTED
/// (`ts`), never read here, so [`format_underground_line`] stays pure and deterministic (#133).
#[derive(Clone, Debug)]
pub struct UndergroundJudgement {
    /// Unix seconds, injected by the caller.
    pub ts: u64,
    /// What the layer did.
    pub verb: UndergroundVerb,
    /// The host judged.
    pub host: String,
    /// The lane that testified (`tunnel` / `ads` / `cdn` / …) — WHY it was judged. This is the single
    /// field that would have exposed #26 on sight: a browsing host filed under `tunnel`.
    pub lane: String,
    /// Points removed by this event (0 for a pin).
    pub penalty: i32,
    /// Licence remaining AFTER the event.
    pub points: i32,
}

/// Format ONE `query-underground.log` line. PURE — no clock, no lock, no IO. Schema (single-space,
/// greppable, no PII beyond a hostname the device already resolved):
///
/// ```text
/// <ts> <VERB> <host> <lane> -<penalty> licence=<points>
/// ```
pub fn format_underground_line(j: &UndergroundJudgement) -> String {
    let host = if j.host.trim().is_empty() { "-" } else { j.host.trim() };
    let lane = if j.lane.trim().is_empty() { "-" } else { j.lane.trim() };
    format!(
        "{} {} {} {} -{} licence={}\n",
        j.ts,
        j.verb.token(),
        host,
        lane,
        j.penalty.max(0),
        j.points.max(0)
    )
}

/// The armed `query-underground.log` path; `None` until [`arm`] binds a dir (same cell as the ledger,
/// so the log and the ledger can never disagree about where "durable" is).
fn underground_log_path() -> Option<PathBuf> {
    ledger_dir_cell()
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|d| d.join(QUERY_UNDERGROUND_LOG_NAME)))
}

/// The armed `query-underground.log` path as a String, for the UniFFI seam
/// ([`crate::underground_log_path`]). `None` until [`arm`] binds a dir — which is the honest answer,
/// because before arming there is no file and a guessed path would send the reader somewhere empty.
pub(crate) fn log_path_string() -> Option<String> {
    underground_log_path().map(|p| p.to_string_lossy().into_owned())
}

/// Append one judgement to the per-pillar log. FAIL-OPEN and best-effort by law: an unarmed dir, a
/// poisoned lock, or a full disk must NEVER change a DNS verdict — the layer keeps judging, it just
/// stops narrating. Bounded by the same T20 discipline as its siblings (device-local, never exported).
fn append_underground_log(j: &UndergroundJudgement) {
    let Some(path) = underground_log_path() else {
        return;
    };
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(format_underground_line(j).as_bytes());
    }
}

/// The armed ledger file path; `None` until [`arm`] binds a dir.
fn ledger_path() -> Option<PathBuf> {
    ledger_dir_cell()
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|d| d.join(LEDGER_FILE_NAME)))
}

/// FNV-1a over every row's identity-bearing fields, XOR-folded per row so iteration order (a
/// HashMap walk) cannot change the signature. The change gate for [`persist_ledger`].
fn store_signature(s: &Store) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut folded: u64 = s
        .recorded_total
        .wrapping_mul(3)
        .wrapping_add(s.recovered_total.wrapping_mul(5))
        .wrapping_add(s.teeth_total.wrapping_mul(7));
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
        eat(&e.points.to_le_bytes());
        eat(&e.last_seen.to_le_bytes());
        eat(&e.last_heal.to_le_bytes());
        eat(&[u8::from(e.sequestrated)]);
        eat(e.verdict.slug().as_bytes());
        eat(&e.seq_at.to_le_bytes());
        folded ^= h;
    }
    folded
}

/// Serialize the whole store to the TSV v1 wire: version header, #meta totals, one
/// host-sorted row per entry (host · risk · source · hits · points · first_seen · last_seen ·
/// last_heal · country-or-dash · seq-1/0 · verdict-slug). The verdict is column 11 — an OLD
/// reader that split-checks `== 10` skips it, but [`parse_body`] accepts 10 OR 11 columns so a
/// same-version rehydrate round-trips the pin (forward-compatible within v1).
fn serialize_store(s: &Store) -> String {
    let mut out = String::with_capacity(64 + s.by_host.len() * 96);
    out.push_str("#underground-ledger ");
    out.push_str(LEDGER_VERSION);
    out.push('\n');
    out.push_str(&format!(
        "#meta recorded_total={} recovered_total={} teeth_total={} epoch={}\n",
        s.recorded_total, s.recovered_total, s.teeth_total, DETECTION_EPOCH
    ));
    let mut rows: Vec<&Entry> = s.by_host.values().collect();
    rows.sort_by(|a, b| a.host.cmp(&b.host));
    for e in rows {
        let cc = e
            .country
            .map(|c| String::from_utf8_lossy(&c).into_owned())
            .unwrap_or_else(|| "-".to_owned());
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            e.host,
            e.risk.slug(),
            e.source.slug(),
            e.hits,
            e.points,
            e.first_seen,
            e.last_seen,
            e.last_heal,
            cc,
            u8::from(e.sequestrated),
            e.verdict.slug(),
            e.seq_at,
        ));
    }
    out
}

/// Parse a ledger body back into entries + totals. FAIL-OPEN per row: a corrupt/short/unknown
/// row is SKIPPED, never an error — a half-good ledger rehydrates its good half.
fn parse_body(body: &str) -> (Vec<Entry>, u64, u64, u64) {
    let mut entries = Vec::new();
    let (mut recorded, mut recovered, mut teeth) = (0u64, 0u64, 0u64);
    // The epoch the ledger on disk was written under. A ledger predating the field reads 0, which is
    // BELOW [`DETECTION_EPOCH`] — so every pre-amnesty ledger is amnestied exactly once, which is the
    // intent: those are the ledgers written by the build that convicted wrongly.
    let mut stored_epoch: u32 = 0;
    for line in body.lines() {
        if let Some(meta) = line.strip_prefix("#meta ") {
            for tok in meta.split_whitespace() {
                if let Some(v) = tok.strip_prefix("recorded_total=") {
                    recorded = v.parse().unwrap_or(0);
                } else if let Some(v) = tok.strip_prefix("recovered_total=") {
                    recovered = v.parse().unwrap_or(0);
                } else if let Some(v) = tok.strip_prefix("teeth_total=") {
                    teeth = v.parse().unwrap_or(0);
                } else if let Some(v) = tok.strip_prefix("epoch=") {
                    stored_epoch = v.parse().unwrap_or(0);
                }
            }
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        // 10 columns = a pre-Trust-bands ledger (verdict reads back Neutral); 11 = with the
        // pin; 12 = with the G-rung quarantine clock (column 12, `seq_at`).
        if !(10..=12).contains(&f.len()) {
            continue;
        }
        let (Some(risk), Some(source)) = (Risk::from_slug(f[1]), Source::from_slug(f[2])) else {
            continue;
        };
        let host = normalize(f[0]);
        if host.is_empty() {
            continue;
        }
        let country = match f[8].as_bytes() {
            [a, b] if f[8] != "-" => Some([a.to_ascii_uppercase(), b.to_ascii_uppercase()]),
            _ => None,
        };
        // Column 11 (the manual Trust pin) is absent in a 10-column legacy row ⇒ Neutral.
        let verdict = f.get(10).map(|s| Verdict::from_slug(s)).unwrap_or_default();
        let sequestrated = f[9] == "1";
        // Column 12 (the quarantine clock) is absent in a pre-G row: a sequestered legacy
        // row starts its TTL AT THIS LOAD (the upgrade boot arms the circuit-breaker; a
        // pre-G permadeath can finally retest) — everything else reads back 0.
        let seq_at = match f.get(11) {
            Some(v) => v.parse().unwrap_or(0),
            None if sequestrated => now_secs(),
            None => 0,
        };
        entries.push(Entry {
            host,
            risk,
            source,
            hits: f[3].parse().unwrap_or(0),
            points: f[4].parse().unwrap_or(LICENCE_START),
            first_seen: f[5].parse().unwrap_or(0),
            last_seen: f[6].parse().unwrap_or(0),
            last_heal: f[7].parse().unwrap_or(0),
            country,
            sequestrated,
            verdict,
            seq_at,
        });
    }
    // ── ★ EPOCH AMNESTY (#79) ────────────────────────────────────────────────────────────────────
    //
    // A heuristic that has been PROVEN WRONG has no standing to keep the convictions it handed down.
    //
    // ROOT CAUSE #26 stopped `nx_burst` from reading the browser's routine AAAA/HTTPS negatives as DNS
    // tunnelling — but a fix cannot reach backwards. The ledger is durable and rehydrated at boot, and
    // an `install -r` UPDATE preserves app-private storage, so every host the buggy build sequestrated
    // stays at points=0 and is answered by the teeth gate FOREVER: a forged NXDOMAIN, `0ms`, transport
    // `-`, on every single query. Socio measured exactly that on monochrome.tf — safe hosts stopped
    // being newly blocked, yet the already-condemned kept biting mid-stream.
    //
    // So the ledger carries the epoch it was written under. When detection logic changes in a way that
    // invalidates past verdicts, [`DETECTION_EPOCH`] is bumped and every AUTOMATIC sequestration is
    // vacated on load. `Verdict::Distrusted` is deliberately EXEMPT: that is a human/blocklist
    // condemnation, not a guess, and nothing here has proven it wrong.
    if stored_epoch < DETECTION_EPOCH {
        for e in entries.iter_mut() {
            if e.verdict == Verdict::Distrusted {
                continue;
            }
            // Centauri-sourced rows are LEFT ALONE: the content lane already has its own recovery path
            // (the rehydrate defang, which both frees the row AND de-escalates its active-destroy risk
            // tag). Clearing `sequestrated` here would satisfy the amnesty's goal while silently robbing
            // that defang of the flag it keys on — the row would come back free but still tagged `mitm`.
            // Two recovery paths for one row is one too many; this one yields to the older, proven one.
            if e.source == Source::Centauri {
                continue;
            }
            if e.sequestrated || e.points <= 0 {
                e.points = licence_start_for(&e.host);
                e.sequestrated = false;
                e.seq_at = 0;
                // The amnesty narrates itself — an unexplained mass-restore would be indistinguishable
                // from state corruption to whoever reads this log next.
                append_underground_log(&UndergroundJudgement {
                    ts: e.last_seen,
                    verb: UndergroundVerb::Amnesty,
                    host: e.host.clone(),
                    lane: e.risk.slug(),
                    penalty: 0,
                    points: e.points,
                });
            }
        }
    }
    (entries, recorded, recovered, teeth)
}

/// The content-lane defang (rehydrate law): an OLD ledger written before the content-lane law
/// may carry a sequestrated Centauri row — heal it back to a metered, reachable content host.
fn content_lane_defang(e: &mut Entry) {
    if e.source == Source::Centauri && e.sequestrated {
        e.sequestrated = false;
        e.points = e.points.max(1);
        // A geo-escalated content row de-escalates with its defang — the content lane never
        // carries an active-destroy tag (it could never have earned one under the law).
        if e.risk.is_active_destroy() {
            e.risk = Risk::Cdn;
        }
    }
}

/// Load the ledger from the armed dir into the store (merge-by-key; existing RAM rows win —
/// boot order calls this on an empty store). Missing file = clean cold start.
fn load_ledger() {
    let Some(path) = ledger_path() else {
        return;
    };
    let Ok(body) = std::fs::read_to_string(&path) else {
        return;
    };
    let (entries, recorded, recovered, teeth) = parse_body(&body);
    let Ok(mut guard) = store().write() else {
        return;
    };
    for mut e in entries {
        content_lane_defang(&mut e);
        guard.by_host.entry(e.host.clone()).or_insert(e);
    }
    guard.recorded_total = guard.recorded_total.max(recorded);
    guard.recovered_total = guard.recovered_total.max(recovered);
    guard.teeth_total = guard.teeth_total.max(teeth);
    // Baseline the change gate to the just-loaded state so an untouched boot never rewrites.
    LAST_PERSIST_SIG.store(store_signature(&guard), Ordering::Relaxed);
}

/// Change-gated atomic persist: identical signature ⇒ zero IO; otherwise write tmp + rename
/// (a torn write can never destroy the previous good ledger). Fail-open on any IO error.
fn persist_ledger() {
    let Some(path) = ledger_path() else {
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

/// Arm the Underground: bind the durable `dir`, rehydrate the ledger ONCE, open the feed + the
/// teeth. Rides the SAME boot edge as the resolver cache rehydrate (`resolver_rehydrate_cache`).
/// Idempotent: a re-arm re-binds the dir but the merge-by-key load never duplicates rows.
pub(crate) fn arm(dir: &str) {
    let trimmed = dir.trim();
    if trimmed.is_empty() {
        return;
    }
    {
        let Ok(mut guard) = ledger_dir_cell().write() else {
            return;
        };
        *guard = Some(PathBuf::from(trimmed));
    }
    maybe_reload_scoring(true);
    load_reputation();
    load_corrections();
    load_ledger();
    ARMED.store(true, Ordering::Release);
}

// ── Snapshot (the panel ARC) ────────────────────────────────────────────────────────────────────

/// The Underground panel snapshot — every counter the UI renders, one crossing.
#[derive(Debug, Clone, uniffi::Record)]
pub struct UndergroundSnapshot {
    /// False until the boot edge arms the store — the UI renders DORMANT (honesty law).
    pub armed: bool,
    /// Hosts currently in the store.
    pub total: u32,
    /// Accidents ever recorded (all-time, survives restarts via #meta).
    pub recorded_total: u64,
    /// Licence points ever healed back (all-time).
    pub recovered_total: u64,
    /// Live NXDOMAINs the sequestration teeth have served (all-time).
    pub teeth_total: u64,
    /// Hosts whose licence drained to 0 — terminally sequestrated.
    pub sequestrated: u32,
    /// Hosts at or below the probation threshold (and not sequestrated).
    pub on_probation: u32,
    /// Content-lane hosts (Centauri-witnessed — metered, never sequestrated).
    pub content_lane: u32,
    /// Content-lane hosts currently below full licence (the "hot" content).
    pub content_hot: u32,
    /// Hosts the user manually TRUSTED (the re-homed Trust bands — immune to the teeth).
    pub trusted_total: u32,
    /// Hosts the user manually DISTRUSTED (condemned — the teeth always bite).
    pub distrusted_total: u32,
    /// Per-risk lane counts, index order: analytics, ads, tracker, dns-leak, ip-leak, sonar,
    /// mitm, spoof, malware, cdn.
    pub per_risk: Vec<u32>,
    /// Per-source lane counts, index order: blocklist, guard, rebind, suffix, centauri.
    pub per_source: Vec<u32>,
    /// Ledger file size on disk (0 until first persist).
    pub ledger_bytes: u64,
    /// Worst offenders, one formatted row each: `host<TAB>risk-slug<TAB>source-slug<TAB>hits
    /// <TAB>points<TAB>seq-1/0<TAB>verdict-slug` — sorted by hits desc.
    pub top: Vec<String>,
    /// Mean live threat score across the store (E rung): per host, the runtime lane penalty
    /// plus its reputation baseline shift — 0.0 on an empty store.
    pub mean_score: f32,
    /// Worst offenders SCORE-ordered (same 7-field row shape as `top`; the E brain's ranking —
    /// a heavy lane with few hits outranks a light lane with many).
    pub top_by_score: Vec<String>,
}

/// Build the panel snapshot (top `top_n` offenders by hits). Settles recovery FIRST so an idle
/// panel still shows licences healing. Fail-open: a poisoned lock renders the DORMANT shape.
pub(crate) fn snapshot(top_n: u32) -> UndergroundSnapshot {
    let armed = armed();
    if armed {
        settle_recovery_at(now_secs());
    }
    let dormant = UndergroundSnapshot {
        armed,
        total: 0,
        recorded_total: 0,
        recovered_total: 0,
        teeth_total: 0,
        sequestrated: 0,
        on_probation: 0,
        content_lane: 0,
        content_hot: 0,
        trusted_total: 0,
        distrusted_total: 0,
        per_risk: vec![0; 10],
        per_source: vec![0; 5],
        ledger_bytes: 0,
        top: Vec::new(),
        mean_score: 0.0,
        top_by_score: Vec::new(),
    };
    // Honesty law (Chroma F6): a disarmed store renders the DORMANT shape — zeros, never a
    // stale RAM residue.
    if !armed {
        return dormant;
    }
    let Ok(guard) = store().read() else {
        return dormant;
    };
    let mut snap = dormant;
    snap.total = guard.by_host.len() as u32;
    snap.recorded_total = guard.recorded_total;
    snap.recovered_total = guard.recovered_total;
    snap.teeth_total = guard.teeth_total;
    for e in guard.by_host.values() {
        snap.per_risk[e.risk.lane_index()] += 1;
        snap.per_source[e.source.lane_index()] += 1;
        if e.sequestrated {
            snap.sequestrated += 1;
        } else if e.points <= probation_at_for(&e.host) {
            snap.on_probation += 1;
        }
        if e.source == Source::Centauri {
            snap.content_lane += 1;
            // #84-B rebased this metric onto ACCIDENT PRESSURE instead of a drained licence. The
            // cloak now PINS a Centauri host's licence (it is served from the offline catalog and
            // never reaches the network, so it cannot earn a bleed), which would have left
            // `e.points < start` permanently false and this panel tile permanently 0 — a dead
            // metric. "Hot content" was always meant to name the content the app is leaning on,
            // and `hits` measures exactly that, honestly, for a host that is not being charged.
            if e.hits > 0 {
                snap.content_hot += 1;
            }
        }
        match e.verdict {
            Verdict::Trusted => snap.trusted_total += 1,
            Verdict::Distrusted => snap.distrusted_total += 1,
            Verdict::Neutral => {}
        }
    }
    /// One offender row — the 9-field TSV shape BOTH orderings share (renderer reuse). H rung
    /// appends the live score (col 8) + the quarantine-TTL seconds remaining (col 9; 0 = no
    /// clock running — the pillar dashboard's countdown column).
    fn format_row(e: &Entry, score: i32, now: u64) -> String {
        let ttl_remain = if e.sequestrated
            && !e.risk.is_active_destroy()
            && e.verdict == Verdict::Neutral
            && e.seq_at > 0
        {
            e.seq_at.saturating_add(quarantine_ttl_secs()).saturating_sub(now)
        } else {
            0
        };
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            e.host,
            e.risk.slug(),
            e.source.slug(),
            e.hits,
            e.points,
            u8::from(e.sequestrated),
            e.verdict.slug(),
            score,
            ttl_remain
        )
    }
    /// The E brain's live per-host score: runtime lane penalty + reputation baseline shift.
    fn live_score(e: &Entry) -> i32 {
        let mut w = penalty_for(&e.risk);
        if let Ok(rep) = reputation_cell().read() {
            if let Some(r) = rep.get(&e.host) {
                w = (w + r.baseline).max(0);
            }
        }
        w
    }
    let row_now = now_secs();
    let mut rows: Vec<&Entry> = guard.by_host.values().collect();
    rows.sort_by(|a, b| b.hits.cmp(&a.hits).then(a.host.cmp(&b.host)));
    // Score every row ONCE (hits order preserved) — both orderings format from the same pairs.
    let mut score_sum: i64 = 0;
    let mut scored: Vec<(i32, &Entry)> = rows
        .iter()
        .map(|e| {
            let s = live_score(e);
            score_sum += i64::from(s);
            (s, *e)
        })
        .collect();
    snap.top =
        scored.iter().take(top_n as usize).map(|(s, e)| format_row(e, *s, row_now)).collect();
    // E rung: the score-ordered ranking — a heavy lane with few hits outranks a light lane
    // with many — plus the store-wide mean of the same live score.
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.hits.cmp(&a.1.hits)).then(a.1.host.cmp(&b.1.host)));
    snap.top_by_score =
        scored.iter().take(top_n as usize).map(|(s, e)| format_row(e, *s, row_now)).collect();
    snap.mean_score = if rows.is_empty() {
        0.0
    } else {
        score_sum as f32 / rows.len() as f32
    };
    drop(guard);
    snap.ledger_bytes = ledger_path()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .unwrap_or(0);
    snap
}

// ── Tests ───────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the global-store tests against each other, self-enforcing the discipline the
    /// external `--test-threads=1` flag only *asked* for — a stray parallel `cargo test` otherwise
    /// races the shared `store()` between one test's scrub() and its asserts (e.g. the `recorded`
    /// total). Poison-tolerant so one panicking test can't cascade-fail the rest.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Every test starts from a scrubbed store + disarmed gates, holding [`SERIAL`] **and the
    /// crate-level detection-stores lock** for its body — the F-rung scrub below wipes the beacon
    /// RHYTHMS + tunnel RINGS the detection unit tests accumulate in parallel, so both families
    /// must serialize on ONE lock (the measured beacon-cadence 1046/1 flake; the charter at
    /// lib.rs `lock_detection_global`). Acquisition order is FIXED (detection first, then SERIAL)
    /// and the detection-side tests take only the detection lock — no deadlock cycle exists.
    /// Bind the return (`let _serial = scrub();`); the `must_use` makes a bare `scrub();` — which
    /// would drop the guards inline and silently un-serialize the test — a compile warning.
    #[must_use = "hold the guards for the whole test body: `let _serial = scrub();`"]
    fn scrub() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        let detection = crate::lock_detection_global();
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut guard = store().write().unwrap_or_else(|e| e.into_inner());
        *guard = Store::default();
        drop(guard);
        ARMED.store(false, Ordering::Release);
        let mut d = ledger_dir_cell().write().unwrap_or_else(|e| e.into_inner());
        *d = None;
        drop(d);
        LAST_PERSIST_SIG.store(0, Ordering::Relaxed);
        LAST_TICK_SECS.store(0, Ordering::Relaxed);
        // E rung state: the runtime law back to compile-time defaults, the reputation RAM
        // tier empty — one test's toml/baseline must never leak into the next.
        if let Ok(mut cfg) = scoring_cell().write() {
            *cfg = ScoringCfg::default();
        }
        SCORING_MTIME.store(0, Ordering::Relaxed);
        if let Ok(mut rep) = reputation_cell().write() {
            rep.clear();
        }
        REPUTATION_DIRTY.store(false, Ordering::Release);
        // F rung: forget every detector ring — one test's tunnel burst or beacon cadence
        // must never leak into the next.
        crate::detection::tunnel::scrub_rings();
        crate::detection::beacon::scrub_rhythms();
        crate::detection::newborn::scrub_registry();
        // G rung: blank the correction ring + the live event stream too (seq restarts so
        // every test's ring reads from 0).
        if let Ok(mut c) = corrections_cell().write() {
            c.clear();
        }
        if let Ok(mut ev) = events_cell().write() {
            ev.clear();
        }
        EVENT_SEQ.store(0, Ordering::Relaxed);
        (detection, serial)
    }

    fn points_of(host: &str) -> Option<i32> {
        store().read().unwrap().by_host.get(host).map(|e| e.points)
    }

    #[test]
    fn classify_ladder_covers_every_event() {
        let _serial = scrub();
        // Blocked → suffix sub-class, else Tracker; always the Blocklist lane.
        assert_eq!(
            classify("ads.doubleclick.net", 1, NavEvent::Blocked),
            Some((Risk::Ads, Source::Blocklist))
        );
        assert_eq!(
            classify("www.google-analytics.com", 1, NavEvent::Blocked),
            Some((Risk::Analytics, Source::Blocklist))
        );
        assert_eq!(
            classify("evil-unknown.example", 1, NavEvent::Blocked),
            Some((Risk::Tracker, Source::Blocklist))
        );
        // Guarded → PTR = IpLeak, anything else = Sonar.
        assert_eq!(
            classify("1.0.168.192.in-addr.arpa", 12, NavEvent::Guarded),
            Some((Risk::IpLeak, Source::Guard))
        );
        assert_eq!(
            classify("printer.local", 1, NavEvent::Guarded),
            Some((Risk::Sonar, Source::Guard))
        );
        // RebindReject → Spoof.
        assert_eq!(
            classify("rebinder.example", 1, NavEvent::RebindReject),
            Some((Risk::Spoof, Source::Rebind))
        );
        // Answered → recon suffixes meter even with enforcement off; benign records NOTHING.
        assert_eq!(
            classify("sdk.appsflyer.com", 1, NavEvent::Answered),
            Some((Risk::Tracker, Source::Suffix))
        );
        assert_eq!(classify("en.wikipedia.org", 1, NavEvent::Answered), None);
    }

    #[test]
    fn record_grows_dedupes_and_normalizes() {
        let _serial = scrub();
        record_at("Ads.DoubleClick.NET.", Risk::Ads, Source::Suffix, 100);
        record_at("ads.doubleclick.net", Risk::Ads, Source::Suffix, 101);
        let guard = store().read().unwrap();
        assert_eq!(guard.by_host.len(), 1);
        let e = guard.by_host.get("ads.doubleclick.net").unwrap();
        assert_eq!(e.hits, 2);
        assert_eq!(e.points, LICENCE_START - 2); // two PRESENCE-tier accidents
        assert_eq!(guard.recorded_total, 2);
    }

    #[test]
    fn probation_doubles_and_drain_sequestrates() {
        let _serial = scrub();
        // Tracker bleeds 3/accident: 20→17→14→11→8→5(probation)→max(5-6,0)... escalation ×2 below.
        // #84: each accident is stamped its OWN second. Five separate offences happen at five
        // separate times; five charges inside ONE second are one navigation's qtype fan-out and are
        // now (correctly) charged once — see `is_duplicate_probe`.
        for i in 0..5 {
            record_at("track.example", Risk::Tracker, Source::Blocklist, 100 + i);
        }
        assert_eq!(points_of("track.example"), Some(5)); // 20 - 5*3
        record_at("track.example", Risk::Tracker, Source::Blocklist, 105);
        assert_eq!(points_of("track.example"), Some(0)); // probation ⇒ 3×2=6 ⇒ floor 0
        let guard = store().read().unwrap();
        assert!(guard.by_host.get("track.example").unwrap().sequestrated);
    }

    #[test]
    fn content_lane_never_sequestrates() {
        let _serial = scrub();
        // Hammer a Centauri content host 40 times across 40 DISTINCT seconds — so no charge is
        // excused as a duplicate probe and the ONLY thing standing between it and a drained licence
        // is #84-B's cloak immunity.
        //
        // ★ THIS ASSERTION WAS STRENGTHENED BY #84. It used to demand `points == 0` — i.e. it
        // ENCODED the bug: it agreed the licence should bleed to nothing and only insisted the host
        // stay reachable. The device disagreed. `cdn.jsdelivr.net` and `fonts.googleapis.com` were
        // being served BY CENTAURI (`CLOAK 0ms` in query.log) while the court deducted their
        // licences in the same second, so the Underground dashboard reported `0 licences` for two
        // hosts in perfect standing. A number the user reads must not lie. Now: witnessed, pinned.
        for i in 0..40 {
            record_at("cdn.example", Risk::Cdn, Source::Centauri, 100 + i);
        }
        let guard = store().read().unwrap();
        let e = guard.by_host.get("cdn.example").unwrap();
        assert_eq!(e.hits, 40, "every accident is still WITNESSED — immunity is not blindness");
        assert_eq!(e.points, licence_start_for("cdn.example"), "#84-B: the cloak pins the licence");
        assert!(!e.sequestrated);
    }

    /// ★ #84 — ONE NAVIGATION IS ONE EVENT. Replays the exact device evidence from Socio's
    /// monochrome.tf playback test: a browser firing `A` + `AAAA` + `HTTPS` for a single name inside
    /// one second must cost ONE licence, not three.
    ///
    /// The measured regression this locks out (`query-underground.log`, ts 1785038502):
    /// ```text
    /// DEDUCT fonts.googleapis.com cdn -1 licence=19
    /// DEDUCT fonts.googleapis.com cdn -1 licence=18
    /// DEDUCT fonts.googleapis.com cdn -1 licence=17
    /// ```
    /// At 3 licences per page view a clean CDN sequestrates in ~7 views and is then answered by our
    /// own teeth as a forged NXDOMAIN forever — the `0ms` bite Socio reported.
    #[test]
    fn one_navigation_costs_one_licence_not_three() {
        let _serial = scrub();
        // A NON-Centauri lane, so cloak immunity cannot be what passes this test — the dedupe must
        // carry it alone. Tracker bleeds 3/accident.
        let start = licence_start_for("probe.example");
        for _ in 0..3 {
            record_at("probe.example", Risk::Tracker, Source::Blocklist, 500);
        }
        assert_eq!(
            points_of("probe.example"),
            Some(start - 3),
            "the A/AAAA/HTTPS triple is ONE navigation ⇒ exactly one 3-point charge"
        );
        {
            let guard = store().read().unwrap();
            assert_eq!(guard.by_host.get("probe.example").unwrap().hits, 3, "all 3 still witnessed");
        }
        // A genuinely NEW second is a genuinely new accident — the gate must not become a mute.
        record_at("probe.example", Risk::Tracker, Source::Blocklist, 501);
        assert_eq!(points_of("probe.example"), Some(start - 6), "a later second charges again");
    }

    /// #84 — the two pure gates, exhaustively. Total functions, so a new [`Source`] variant that
    /// should be immune is a deliberate decision rather than a silent omission.
    #[test]
    fn the_charge_gates_are_exact() {
        // A row created by this very call can never be a duplicate, whatever the clock says.
        assert!(!is_duplicate_probe(true, 100, 100));
        // Same second, pre-existing row ⇒ the qtype fan-out.
        assert!(is_duplicate_probe(false, 100, 100));
        // Any later second ⇒ a fresh accident.
        assert!(!is_duplicate_probe(false, 100, 101));
        // Only the offline CDN is immune; every other provenance still pays.
        assert!(cloak_is_immune(Source::Centauri));
        for s in [Source::Blocklist, Source::Guard, Source::Rebind, Source::Suffix] {
            assert!(!cloak_is_immune(s), "{:?} must still be chargeable", s.slug());
        }
    }

    /// ★ NO-SELF-ECHO LAW. A sequestrated host answered NXDOMAIN by our OWN teeth must not have
    /// that block recorded as a fresh accident. If it were, `last_seen` would be bumped on every
    /// retry, and the quarantine retest (which demands `now - last_seen >= ttl/4`) could never
    /// fire — an EARNED, time-limited quarantine would silently become permadeath.
    #[test]
    fn a_sequestrated_hosts_own_block_never_re_bumps_its_clock() {
        let _serial = scrub();
        // Drain a Neutral, non-active-destroy host to sequestration.
        for i in 0..7 {
            record_at("drained.example", Risk::Tracker, Source::Blocklist, 100 + i);
        }
        let before = {
            let guard = store().read().unwrap();
            let e = guard.by_host.get("drained.example").unwrap();
            assert!(e.sequestrated, "precondition: the host must be sequestrated");
            assert_eq!(e.verdict, Verdict::Neutral);
            e.last_seen
        };
        // Arm and replay the teeth's own NXDOMAIN (rcode 3) exactly as `resolve_datapath` would.
        ARMED.store(true, Ordering::Release);
        feed("drained.example", 1, NavEvent::Blocked, 0, 3);
        ARMED.store(false, Ordering::Release);
        let after = store().read().unwrap().by_host.get("drained.example").unwrap().last_seen;
        assert_eq!(
            after, before,
            "the engine recorded its OWN block as a new accident — the retest clock is now hot \
             forever and the quarantine has become permadeath"
        );
    }

    #[test]
    fn recovery_heals_idle_but_never_active_destroy_or_sequestrated() {
        let _serial = scrub();
        record_at("track.example", Risk::Tracker, Source::Blocklist, 100); // 17 pts
        record_at("spoof.example", Risk::Spoof, Source::Rebind, 100); // 10 pts, active-destroy
        for i in 0..7 {
            record_at("drained.example", Risk::Tracker, Source::Blocklist, 100 + i);
        }
        assert!(store().read().unwrap().by_host.get("drained.example").unwrap().sequestrated);
        // Not yet idle long enough — nothing moves.
        settle_recovery_at(100 + RECOVERY_IDLE_SECS - 1);
        assert_eq!(points_of("track.example"), Some(17));
        // Fully idle — the tracker heals one step; the spoofer (mitigation ceiling) and the
        // sequestrated host (terminal) stay exactly where they were.
        settle_recovery_at(100 + RECOVERY_IDLE_SECS);
        assert_eq!(points_of("track.example"), Some(18));
        assert_eq!(points_of("spoof.example"), Some(10));
        assert_eq!(points_of("drained.example"), Some(0));
        assert_eq!(store().read().unwrap().recovered_total, 1);
        // Healing paces itself: the same instant cannot heal twice.
        settle_recovery_at(100 + RECOVERY_IDLE_SECS + 1);
        assert_eq!(points_of("track.example"), Some(18));
    }

    #[test]
    fn teeth_bite_only_sequestrated_and_count_bites() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        assert!(!teeth_gate("unknown.example")); // unknown ⇒ pass (fail-open)
        record_at("track.example", Risk::Tracker, Source::Blocklist, 100);
        assert!(!teeth_gate("track.example")); // licenced ⇒ pass
        for i in 0..6 {
            record_at("track.example", Risk::Tracker, Source::Blocklist, 100 + i);
        }
        assert!(teeth_gate("track.example")); // drained ⇒ NXDOMAIN
        assert!(teeth_gate("Track.Example.")); // normalization holds at the gate
        assert_eq!(store().read().unwrap().teeth_total, 2);
        ARMED.store(false, Ordering::Release);
        assert!(!teeth_gate("track.example")); // disarmed ⇒ teeth open (fleet-cold fast path)
    }

    #[test]
    fn feed_is_noop_until_armed() {
        let _serial = scrub();
        feed("ads.doubleclick.net", 1, NavEvent::Answered, 0, 0);
        assert_eq!(store().read().unwrap().by_host.len(), 0);
        ARMED.store(true, Ordering::Release);
        feed("ads.doubleclick.net", 1, NavEvent::Answered, 0, 0);
        assert_eq!(store().read().unwrap().by_host.len(), 1);
    }

    #[test]
    fn ledger_round_trips_and_change_gate_holds() {
        let _serial = scrub();
        let dir = std::env::temp_dir().join(format!("torta-underground-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        {
            let mut d = ledger_dir_cell().write().unwrap();
            *d = Some(dir.clone());
        }
        record_at("track.example", Risk::Tracker, Source::Blocklist, 100);
        for i in 0..7 {
            record_at("dead.example", Risk::Tracker, Source::Blocklist, 100 + i);
        }
        persist_ledger();
        let path = dir.join(LEDGER_FILE_NAME);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("#underground-ledger v1\n"));
        // Round-trip: parse the serialized wire back — identical rows + totals.
        let (entries, recorded, _, _) = parse_body(&body);
        assert_eq!(entries.len(), 2);
        assert_eq!(recorded, 8);
        let dead = entries.iter().find(|e| e.host == "dead.example").unwrap();
        assert!(dead.sequestrated);
        // Change gate: an unchanged store never rewrites (mtime-free proof via the gate itself).
        let sig_before = LAST_PERSIST_SIG.load(Ordering::Relaxed);
        persist_ledger();
        assert_eq!(LAST_PERSIST_SIG.load(Ordering::Relaxed), sig_before);
        // A corrupt row is skipped, the good half survives (fail-open rehydrate).
        let half_bad = format!("{body}garbage-row-without-tabs\n");
        let (salvaged, _, _, _) = parse_body(&half_bad);
        assert_eq!(salvaged.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rehydrate_defangs_wrongly_sequestrated_content_lane() {
        let _serial = scrub();
        let dir =
            std::env::temp_dir().join(format!("torta-underground-df-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let old = "#underground-ledger v1\n#meta recorded_total=9 recovered_total=0 teeth_total=0\n\
                   cdn.example\tmitm\tcentauri\t9\t0\t100\t200\t100\t-\t1\n";
        std::fs::write(dir.join(LEDGER_FILE_NAME), old).unwrap();
        arm(dir.to_str().unwrap());
        let guard = store().read().unwrap();
        let e = guard.by_host.get("cdn.example").unwrap();
        assert!(!e.sequestrated);
        assert!(e.points >= 1);
        assert_eq!(e.risk, Risk::Cdn); // the active-destroy tag de-escalates with the defang
        drop(guard);
        assert!(armed());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn snapshot_populates_every_panel_lane() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        // Recorded at REAL now: snapshot() self-settles, and an epoch-old timestamp would let
        // the idle-heal cap the licences back mid-test (content_hot would empty).
        let now = now_secs();
        record_at("ads.doubleclick.net", Risk::Ads, Source::Suffix, now);
        record_at("printer.local", Risk::Sonar, Source::Guard, now);
        record_at("cdn.example", Risk::Cdn, Source::Centauri, now);
        for i in 0..7 {
            record_at("track.example", Risk::Tracker, Source::Blocklist, now + i);
        }
        let snap = snapshot(2);
        assert!(snap.armed);
        assert_eq!(snap.total, 4);
        assert_eq!(snap.recorded_total, 10);
        assert_eq!(snap.sequestrated, 1);
        assert_eq!(snap.content_lane, 1);
        assert_eq!(snap.content_hot, 1);
        assert_eq!(snap.per_risk[Risk::Ads.lane_index()], 1);
        assert_eq!(snap.per_risk[Risk::Tracker.lane_index()], 1);
        assert_eq!(snap.per_risk[Risk::Sonar.lane_index()], 1);
        assert_eq!(snap.per_risk[Risk::Cdn.lane_index()], 1);
        assert_eq!(snap.per_source[Source::Blocklist.lane_index()], 1);
        assert_eq!(snap.per_source[Source::Centauri.lane_index()], 1);
        assert_eq!(snap.top.len(), 2);
        // Worst offender first (7 hits), row format machine-splittable on TAB.
        let worst: Vec<&str> = snap.top[0].split('\t').collect();
        assert_eq!(worst[0], "track.example");
        assert_eq!(worst[3], "7");
        assert_eq!(worst[5], "1"); // sequestrated flag
        // Disarmed ⇒ the DORMANT shape, zeros everywhere (honesty law).
        ARMED.store(false, Ordering::Release);
        let cold = snapshot(5);
        assert!(!cold.armed);
        assert_eq!(cold.total, 0);
    }

    // ── The re-homed Trust bands (manual Verdict pins) ───────────────────────────────────────────

    #[test]
    fn manual_trust_immunizes_against_teeth_and_bleed() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        record_at("vouched.example", Risk::Tracker, Source::Suffix, 100);
        assert!(set_verdict("vouched.example", 1)); // Trusted
        // Hammer with the harshest accidents: a vouched host must NOT bleed and NEVER sequestrate.
        for i in 0..12 {
            record_at("vouched.example", Risk::Malware, Source::Blocklist, 100 + i);
        }
        let g = store().read().unwrap();
        let e = g.by_host.get("vouched.example").unwrap();
        assert_eq!(e.points, LICENCE_START);
        assert!(!e.sequestrated);
        assert_eq!(e.verdict, Verdict::Trusted);
        drop(g);
        assert!(!teeth_gate("vouched.example")); // immune ⇒ the teeth stay open
    }

    #[test]
    fn manual_distrust_condemns_even_a_never_seen_host() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        // A host the automatic engine never witnessed — pre-emptively blocked (find-or-create).
        assert!(set_verdict("evil.example", 2)); // Distrusted
        let g = store().read().unwrap();
        let e = g.by_host.get("evil.example").unwrap();
        assert!(e.sequestrated);
        assert_eq!(e.points, 0);
        assert_eq!(e.verdict, Verdict::Distrusted);
        drop(g);
        assert!(teeth_gate("evil.example")); // condemned ⇒ NXDOMAIN
        assert!(teeth_gate("Evil.Example.")); // normalization holds at the gate
        assert_eq!(store().read().unwrap().teeth_total, 2);
    }

    #[test]
    fn neutral_clears_the_pin_and_resumes_the_automatic_engine() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        assert!(set_verdict("host.example", 1)); // Trusted ⇒ full, immune
        assert!(!teeth_gate("host.example"));
        assert!(set_verdict("host.example", 0)); // Neutral ⇒ clear the pin
        {
            let g = store().read().unwrap();
            let e = g.by_host.get("host.example").unwrap();
            assert_eq!(e.verdict, Verdict::Neutral);
            assert_eq!(e.points, LICENCE_START); // the trust pin left it full; clearing keeps it
            assert!(!e.sequestrated);
        }
        // Automatic law resumes: accidents now bleed the licence normally, down to the teeth.
        for i in 0..25 {
            record_at("host.example", Risk::Tracker, Source::Blocklist, 100 + i);
        }
        assert!(teeth_gate("host.example")); // drained under the automatic engine ⇒ bite
    }

    #[test]
    fn verdict_round_trips_through_the_ledger_column_eleven() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        let dir =
            std::env::temp_dir().join(format!("torta-underground-vd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        {
            let mut d = ledger_dir_cell().write().unwrap();
            *d = Some(dir.clone());
        }
        set_verdict("allow.example", 1); // Trusted (persists internally)
        set_verdict("block.example", 2); // Distrusted
        let body = std::fs::read_to_string(dir.join(LEDGER_FILE_NAME)).unwrap();
        // The 11th column carries the pin slug (a 10-column legacy reader would just ignore
        // it); column 12 is the G-rung quarantine clock — 0 for a pin (no TTL on user law).
        assert!(body
            .lines()
            .any(|l| l.starts_with("allow.example") && l.ends_with("\ttrusted\t0")));
        assert!(body
            .lines()
            .any(|l| l.starts_with("block.example") && l.ends_with("\tdistrusted\t0")));
        // Parse the wire back — the pins survive the round-trip.
        let (entries, _, _, _) = parse_body(&body);
        let allow = entries.iter().find(|e| e.host == "allow.example").unwrap();
        let block = entries.iter().find(|e| e.host == "block.example").unwrap();
        assert_eq!(allow.verdict, Verdict::Trusted);
        assert_eq!(block.verdict, Verdict::Distrusted);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_ten_column_row_reads_back_neutral() {
        let _serial = scrub();
        // A pre-Trust-bands row (exactly 10 columns) MUST rehydrate as Neutral, never a spurious pin.
        let old = "#underground-ledger v1\n#meta recorded_total=1 recovered_total=0 teeth_total=0\n\
                   old.example\ttracker\tblocklist\t3\t8\t100\t200\t100\t-\t0\n";
        let (entries, _, _, _) = parse_body(old);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].verdict, Verdict::Neutral);
        assert_eq!(entries[0].points, 8);
    }

    #[test]
    fn snapshot_counts_trust_bands_and_top_row_carries_the_verdict() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        let now = now_secs();
        record_at("noisy.example", Risk::Tracker, Source::Blocklist, now);
        set_verdict("noisy.example", 2); // Distrusted (has a hit ⇒ tops the offender list)
        set_verdict("friend.example", 1); // Trusted
        let snap = snapshot(5);
        assert_eq!(snap.distrusted_total, 1);
        assert_eq!(snap.trusted_total, 1);
        let row: Vec<&str> = snap
            .top
            .iter()
            .find(|r| r.starts_with("noisy.example"))
            .unwrap()
            .split('\t')
            .collect();
        assert_eq!(row.len(), 9); // H rung: + score (col 8) + ttl-remaining (col 9)
        assert_eq!(row[6], "distrusted"); // the 7th field is the manual verdict slug
        assert_eq!(row[8], "0", "a manual pin runs no quarantine clock");
    }

    // ── E rung: the runtime scoring brain ───────────────────────────────────────────────────

    #[test]
    fn score_host_fuses_multi_signal_weights() {
        let _serial = scrub();
        // One witness (suffix class on an Answered ads host): lane weight, base confidence.
        let s = score_host("ads.doubleclick.net", 1, NavEvent::Answered, 0, 0).unwrap();
        assert_eq!(s.risk, Risk::Ads);
        assert_eq!(s.weight, Risk::Ads.base_penalty());
        assert_eq!(s.signals, vec![Signal::Suffix]);
        assert!((s.confidence - 0.4).abs() < 1e-6);
        // A reputation baseline SHIFTS the weight and joins the witness list.
        reputation_set("ads.doubleclick.net", 4, 1.0);
        let s2 = score_host("ads.doubleclick.net", 1, NavEvent::Answered, 0, 0).unwrap();
        assert_eq!(s2.weight, Risk::Ads.base_penalty() + 4);
        assert_eq!(s2.signals, vec![Signal::Suffix, Signal::Reputation]);
        assert!(s2.confidence > s.confidence);
        // Reputation can pardon but never invert into a reward (floor 0).
        reputation_set("ads.doubleclick.net", -99, 0.5);
        assert_eq!(score_host("ads.doubleclick.net", 1, NavEvent::Answered, 0, 0).unwrap().weight, 0);
        // A rebind rejection carries the GeoRebind witness on the Spoof lane.
        let s3 = score_host("rebind.example", 1, NavEvent::RebindReject, 0, 0).unwrap();
        assert_eq!(s3.risk, Risk::Spoof);
        assert_eq!(s3.signals, vec![Signal::GeoRebind]);
        // Benign stays unrecorded — the post-filter law survives the brain.
        assert!(score_host("plain.example", 1, NavEvent::Answered, 0, 0).is_none());
    }

    #[test]
    fn scoring_toml_hot_reload_overrides_the_penalty_law() {
        let _serial = scrub();
        let dir = std::env::temp_dir().join(format!("torta-underground-sc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        arm(dir.to_str().unwrap());
        // No toml on disk ⇒ the compile-time defaults hold (byte-identical launch law).
        assert_eq!(penalty_for(&Risk::Ads), Risk::Ads.base_penalty());
        assert_eq!(licence_start_for("any.example"), LICENCE_START);
        // Operator writes a hotter law: ads bleed 7, licences start at 12, probation at 4.
        std::fs::write(
            dir.join(SCORING_FILE_NAME),
            "[licence]\nstart = 12\nprobation_at = 4\n\n[penalty]\nads = 7\n",
        )
        .unwrap();
        maybe_reload_scoring(true);
        assert_eq!(penalty_for(&Risk::Ads), 7);
        assert_eq!(penalty_for(&Risk::Malware), Risk::Malware.base_penalty()); // partial file: rest default
        assert_eq!(licence_start_for("any.example"), 12);
        assert_eq!(probation_at_for("any.example"), 4);
        // The record path CONSUMES the hot law: a fresh ads accident bleeds 12 - 7 = 5.
        record_at("ads.doubleclick.net", Risk::Ads, Source::Suffix, now_secs());
        assert_eq!(points_of("ads.doubleclick.net"), Some(5));
        // A garbled edit keeps the sitting law (fail-open, never a zeroed economy).
        std::fs::write(dir.join(SCORING_FILE_NAME), "[penalty\nads = ").unwrap();
        maybe_reload_scoring(true);
        assert_eq!(penalty_for(&Risk::Ads), 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reputation_ram_nand_round_trip() {
        let _serial = scrub();
        let dir = std::env::temp_dir().join(format!("torta-underground-rp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        arm(dir.to_str().unwrap());
        reputation_set("shady.example", 5, 0.8);
        reputation_set("pardoned.example", -3, 0.25);
        persist_reputation();
        let on_disk = std::fs::read_to_string(dir.join(REPUTATION_FILE_NAME)).unwrap();
        assert!(on_disk.starts_with("#underground-reputation v1\n"));
        assert!(on_disk.contains("shady.example\t5\t0.800\t-\t-"));
        // Blank the RAM tier, rehydrate from NAND — the rows come back whole.
        reputation_cell().write().unwrap().clear();
        load_reputation();
        let rep = reputation_cell().read().unwrap();
        assert_eq!(rep.get("shady.example").unwrap().baseline, 5);
        assert!((rep.get("shady.example").unwrap().confidence - 0.8).abs() < 1e-3);
        assert_eq!(rep.get("pardoned.example").unwrap().baseline, -3);
        drop(rep);
        // The dirty gate: an unchanged map persists ZERO further IO (idempotence witness).
        let mtime_before = std::fs::metadata(dir.join(REPUTATION_FILE_NAME)).unwrap().modified().unwrap();
        persist_reputation();
        assert_eq!(
            std::fs::metadata(dir.join(REPUTATION_FILE_NAME)).unwrap().modified().unwrap(),
            mtime_before
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn escalation_curve_neutral_to_sequestrated_under_weighted_scores() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        let now = now_secs();
        // Sonar bleeds 5: 20→15→10→5(≤6 ⇒ next DOUBLES)→0 sequestrated. Four accidents, the
        // last one landing the doubled 10 — the probation curve under the runtime brain.
        for i in 0..3 {
            record_at("probe.lan", Risk::Sonar, Source::Guard, now + i);
        }
        assert_eq!(points_of("probe.lan"), Some(5));
        assert!(!store().read().unwrap().by_host.get("probe.lan").unwrap().sequestrated);
        record_at("probe.lan", Risk::Sonar, Source::Guard, now);
        assert_eq!(points_of("probe.lan"), Some(0));
        assert!(store().read().unwrap().by_host.get("probe.lan").unwrap().sequestrated);
    }

    #[test]
    fn snapshot_score_order_outranks_hits_order_and_means_honestly() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        let now = now_secs();
        // Light lane, MANY hits vs heavy lane, ONE hit: hits-order and score-order disagree.
        for i in 0..5 {
            record_at("ads.doubleclick.net", Risk::Ads, Source::Suffix, now + i);
        }
        record_at("rebind.example", Risk::Spoof, Source::Rebind, now);
        let snap = snapshot(5);
        assert!(snap.top[0].starts_with("ads.doubleclick.net")); // hits ordering: 5 beats 1
        assert!(snap.top_by_score[0].starts_with("rebind.example")); // score ordering: 10 beats 1
        assert_eq!(snap.top_by_score.len(), 2);
        // Mean = (ads 1 + spoof 10) / 2 hosts.
        let expect = (Risk::Ads.base_penalty() + Risk::Spoof.base_penalty()) as f32 / 2.0;
        assert!((snap.mean_score - expect).abs() < 1e-6);
        // A reputation shift moves BOTH the ranking input and the mean.
        reputation_set("ads.doubleclick.net", 20, 1.0);
        let snap2 = snapshot(5);
        assert!(snap2.top_by_score[0].starts_with("ads.doubleclick.net")); // 21 outranks 10
        assert!(snap2.mean_score > snap.mean_score);
    }

    // ── F rung: the Detection suite riding the fusion wire ──────────────────────────────────

    #[test]
    fn dga_qname_earns_a_custom_lane_no_suffix_list_needed() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        // No suffix list knows this host — only its SHAPE convicts it.
        let s = score_host("xkqzwtplvmnrbds.tld", 1, NavEvent::Answered, 0, 0).unwrap();
        assert_eq!(s.risk, Risk::Custom { slug: "dga".into() });
        assert_eq!(s.weight, 10); // malware-tier constant — no scoring.toml row for a coined lane
        assert!(s.signals.contains(&Signal::Dga));
        // Through the full feed wire: the accident lands, the licence bleeds the top tier.
        feed("xkqzwtplvmnrbds.tld", 1, NavEvent::Answered, 64, 0);
        assert_eq!(points_of("xkqzwtplvmnrbds.tld"), Some(LICENCE_START - 10));
        let g = store().read().unwrap();
        let e = g.by_host.get("xkqzwtplvmnrbds.tld").unwrap();
        assert_eq!(e.source, Source::Suffix); // the Underground's OWN faculty is the provenance
        assert_eq!(e.risk.lane_index(), 8); // counts in the malware column — the vec stays 10
    }

    #[test]
    fn homoglyph_forgery_earns_its_lane_and_newborn_rides_beside_it() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        // Cyrillic-а "аpple" — no list knows it; the rendered-shape faculty convicts it,
        // and the first-sight probation mark joins BESIDE the shape witness (61F).
        let s = score_host("xn--pple-43d.example", 1, NavEvent::Answered, 0, 0).unwrap();
        assert_eq!(s.risk, Risk::Custom { slug: "homoglyph".into() });
        assert_eq!(s.weight, 10); // a forged brand is a malware SHAPE — top tier
        assert!(s.signals.contains(&Signal::Homoglyph));
        assert!(s.signals.contains(&Signal::Newborn));
        // The brand itself: shape-clean, benign, recorded nowhere.
        assert!(score_host("apple.example", 1, NavEvent::Answered, 0, 0).is_none());
    }

    #[test]
    fn newborn_never_testifies_alone_or_beside_curated_lists() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        // A fresh benign host: probation alone is NOT evidence — recorded nowhere.
        assert!(score_host("brand-new.example", 1, NavEvent::Answered, 0, 0).is_none());
        // A fresh curated-suffix host: the lane stands, the newborn mark stays OFF the
        // witness list (the first-install-noise law).
        let s = score_host("ads.doubleclick.net", 1, NavEvent::Answered, 0, 0).unwrap();
        assert!(!s.signals.contains(&Signal::Newborn));
    }

    #[test]
    fn tunnel_burst_through_score_host_coins_the_tunnel_lane() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        // Four oversized TXT answers: quiet (wall-clock calls land inside one 60s window).
        for _ in 0..4 {
            assert!(score_host("exfil2.example", 16, NavEvent::Answered, 400, 0).is_none());
        }
        // The fifth crosses TUNNEL_BURST — the shape is called + coined.
        let s = score_host("exfil2.example", 16, NavEvent::Answered, 400, 0).unwrap();
        assert_eq!(s.risk, Risk::Custom { slug: "tunnel".into() });
        assert!(s.signals.contains(&Signal::Tunnel));
    }

    #[test]
    fn nx_burst_files_under_the_tunnel_signal() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        // Seven NXDOMAINs: quiet. The eighth makes the host a tunnel candidate.
        for _ in 0..7 {
            assert!(score_host("probe9.example", 1, NavEvent::Answered, 30, 3).is_none());
        }
        let s = score_host("probe9.example", 1, NavEvent::Answered, 30, 3).unwrap();
        assert_eq!(s.risk, Risk::Custom { slug: "tunnel".into() });
        assert!(s.signals.contains(&Signal::Tunnel));
    }

    #[test]
    fn fp_control_high_qps_benign_host_stays_unrecorded() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        // A browser hammering a benign CDN name: rapid arrivals, ordinary A answers — no
        // suffix hit, no DGA shape, no TXT, no NX. NOTHING may be witnessed (the recipe's
        // false-positive gate).
        for _ in 0..30 {
            assert!(score_host("www.google.com", 1, NavEvent::Answered, 120, 0).is_none());
            feed("www.google.com", 1, NavEvent::Answered, 120, 0);
        }
        assert_eq!(points_of("www.google.com"), None);
    }

    #[test]
    fn custom_slug_round_trips_through_the_ledger() {
        let _serial = scrub();
        let dir = std::env::temp_dir().join(format!("torta-underground-cu-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        arm(dir.to_str().unwrap());
        // A detector-coined accident lands durably…
        feed("xkqzwtplvmnrbds.tld", 1, NavEvent::Answered, 64, 0);
        persist_ledger();
        let on_disk = std::fs::read_to_string(dir.join(LEDGER_FILE_NAME)).unwrap();
        assert!(on_disk.contains("xkqzwtplvmnrbds.tld\tdga\t"), "raw slug missing: {on_disk}");
        // …RAM blanked, NAND rehydrates: the coined lane comes back WHOLE (the from_slug
        // catch-all — no round-trip downgrade, no dropped row).
        {
            let mut g = store().write().unwrap();
            g.by_host.clear();
        }
        load_ledger();
        let g = store().read().unwrap();
        let e = g.by_host.get("xkqzwtplvmnrbds.tld").unwrap();
        assert_eq!(e.risk, Risk::Custom { slug: "dga".into() });
        assert_eq!(e.points, LICENCE_START - 10);
        drop(g);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── G rung: quarantine TTL + the learning loop + the live event stream ──────────────────

    fn drain_to_sequestration(host: &str) {
        // The E escalation curve verbatim: Sonar bleeds 5 — 20→15→10→5(≤6 ⇒ DOUBLES)→0.
        // Four accidents sequestrate, on a NON-active-destroy lane (the TTL-eligible class).
        // #84: each accident gets its OWN second. Four offences in one second would now (correctly)
        // be read as one navigation's A/AAAA/HTTPS fan-out and charged once — see
        // `is_duplicate_probe`. A real drain happens over time, so the helper must model time.
        // The four accidents END at real `now` (not start there), so the sequestration stamp
        // `seq_at` lands on the present and the TTL countdown reads a full, un-underflowed window.
        let now = now_secs();
        for i in (0..4).rev() {
            record_at(host, Risk::Sonar, Source::Guard, now - i);
        }
        let g = store().read().unwrap();
        assert!(g.by_host.get(host).unwrap().sequestrated, "drain failed for {host}");
    }

    #[test]
    fn quarantine_ttl_expiry_retests_and_restores_the_licence() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        drain_to_sequestration("ads.doubleclick.net");
        let now = now_secs();
        {
            let mut g = store().write().unwrap();
            let e = g.by_host.get_mut("ads.doubleclick.net").unwrap();
            assert!(e.seq_at > 0, "the close edge must stamp the quarantine clock");
            // Warp: the TTL served in full AND the recent window ran clean.
            e.seq_at = now - QUARANTINE_TTL_SECS - 10;
            e.last_seen = now - QUARANTINE_TTL_SECS / 4 - 10;
        }
        settle_recovery_at(now);
        let g = store().read().unwrap();
        let e = g.by_host.get("ads.doubleclick.net").unwrap();
        assert!(!e.sequestrated, "an expired clean quarantine must walk");
        assert_eq!(e.points, LICENCE_START);
        assert_eq!(e.seq_at, 0);
        drop(g);
        // …and the restore streamed live.
        let ev = events_snapshot();
        assert!(ev.iter().any(|e| e.signal == "retest" && e.score_delta == LICENCE_START));
    }

    #[test]
    fn active_destroy_and_hot_hosts_stay_terminal_across_ttl() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        drain_to_sequestration("ads.doubleclick.net");
        let now = now_secs();
        {
            let mut g = store().write().unwrap();
            let e = g.by_host.get_mut("ads.doubleclick.net").unwrap();
            // Surgery: the same expired clock, but the lane is active-destroy.
            e.risk = Risk::Malware;
            e.seq_at = now - QUARANTINE_TTL_SECS - 10;
            e.last_seen = now - QUARANTINE_TTL_SECS;
        }
        settle_recovery_at(now);
        {
            let g = store().read().unwrap();
            let e = g.by_host.get("ads.doubleclick.net").unwrap();
            assert!(e.sequestrated, "Malware NEVER walks on TTL — earned-terminal is law");
            assert_eq!(e.points, 0);
        }
        // A non-active-destroy host still HAMMERING (fresh last_seen) doesn't walk either.
        {
            let mut g = store().write().unwrap();
            let e = g.by_host.get_mut("ads.doubleclick.net").unwrap();
            e.risk = Risk::Ads;
            e.last_seen = now; // the C2 keeps its own clock hot
        }
        settle_recovery_at(now);
        let g = store().read().unwrap();
        assert!(g.by_host.get("ads.doubleclick.net").unwrap().sequestrated);
    }

    #[test]
    fn a_correction_teaches_the_reputation_and_logs_to_nand() {
        let _serial = scrub();
        let dir = std::env::temp_dir().join(format!("torta-underground-gc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        arm(dir.to_str().unwrap());
        // Neutral → Distrusted: a REAL flip. The log records it, the row learns severity.
        assert!(set_verdict("shady.example", 2));
        let log = std::fs::read_to_string(dir.join(CORRECTIONS_FILE_NAME)).unwrap();
        assert!(log.contains("shady.example\tneutral\tdistrusted\t"), "log row missing: {log}");
        {
            let rep = reputation_cell().read().unwrap();
            let r = rep.get("shady.example").unwrap();
            assert_eq!(r.baseline, 3, "Distrust teaches +3 severity");
            assert!(r.corrected);
            assert!((r.confidence - 0.25).abs() < 1e-6);
        }
        // …and the taught row testifies AS the correction in the fusion.
        let s = score_of("shady.example").unwrap();
        assert!(s.signals.contains(&Signal::Correction));
        assert!(!s.signals.contains(&Signal::Reputation));
        // A same-pin re-tap teaches NOTHING (no new log row, no double-shift).
        assert!(set_verdict("shady.example", 2));
        assert_eq!(corrections_cell().read().unwrap().len(), 1);
        // Distrusted → Trusted flips back the other way: -3 from +3 = 0? No — the pardon
        // shifts ANOTHER -3: 3-3 = 0 baseline, confidence firms further.
        assert!(set_verdict("shady.example", 1));
        {
            let rep = reputation_cell().read().unwrap();
            let r = rep.get("shady.example").unwrap();
            assert_eq!(r.baseline, 0);
            assert!((r.confidence - 0.5).abs() < 1e-6);
        }
        // NAND round-trip: blank the RAM ring, rehydrate from the log — both rows return.
        corrections_cell().write().unwrap().clear();
        load_corrections();
        let ring = corrections_cell().read().unwrap();
        assert_eq!(ring.len(), 2);
        assert_eq!(ring[0].from, Verdict::Neutral);
        assert_eq!(ring[0].to, Verdict::Distrusted);
        assert_eq!(ring[1].from, Verdict::Distrusted);
        assert_eq!(ring[1].to, Verdict::Trusted);
        drop(ring);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn event_ring_drops_oldest_at_cap() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        for _ in 0..70 {
            feed("ads.doubleclick.net", 1, NavEvent::Answered, 0, 0);
        }
        let ev = events_snapshot();
        assert_eq!(ev.len(), EVENT_RING_CAP, "the ring holds exactly the newest 64");
        assert_eq!(ev[0].seq, 6, "the first six accidents fell off the back");
        assert_eq!(ev[63].seq, 69);
        assert!(ev.iter().all(|e| e.host == "ads.doubleclick.net" && e.signal == "suffix"));
        // The bleed is honest: the first surviving rows still carry negative deltas; the
        // floor-0 tail carries 0 (a drained licence bleeds no further).
        assert_eq!(ev[63].score_delta, 0);
    }

    #[test]
    fn ttl_clock_and_corrections_survive_reboot_via_nand() {
        let _serial = scrub();
        let dir = std::env::temp_dir().join(format!("torta-underground-gr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        arm(dir.to_str().unwrap());
        drain_to_sequestration("ads.doubleclick.net");
        assert!(set_verdict("shady.example", 2));
        let seq_at_before = {
            let g = store().read().unwrap();
            g.by_host.get("ads.doubleclick.net").unwrap().seq_at
        };
        assert!(seq_at_before > 0);
        persist_ledger();
        // REBOOT: blank every RAM tier, re-arm from the same NAND dir (release the serial
        // guard first — scrub's mutex is not reentrant).
        drop(_serial);
        let _serial = scrub();
        arm(dir.to_str().unwrap());
        let g = store().read().unwrap();
        let e = g.by_host.get("ads.doubleclick.net").unwrap();
        assert!(e.sequestrated);
        assert_eq!(e.seq_at, seq_at_before, "column 12 must round-trip the quarantine clock");
        drop(g);
        assert_eq!(corrections_cell().read().unwrap().len(), 1);
        let rep = reputation_cell().read().unwrap();
        assert!(rep.get("shady.example").unwrap().corrected, "the c flag survives the mirror");
        drop(rep);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── H rung: detection kill switches + the 9-field pillar row + the reputation RESET ──────

    #[test]
    fn detection_toggle_disables_the_dga_faculty() {
        let _serial = scrub();
        let dir = std::env::temp_dir().join(format!("torta-underground-hd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        arm(dir.to_str().unwrap());
        // Default law: the F soup coins the DGA lane.
        let s = score_host("xkqzwtplvmnrbds.tld", 1, NavEvent::Answered, 0, 0).unwrap();
        assert!(s.signals.contains(&Signal::Dga));
        // The settings pane flips the switch — the SAME hot-reload wire the penalties ride.
        std::fs::write(dir.join(SCORING_FILE_NAME), "[detection]\ndga = false\n").unwrap();
        maybe_reload_scoring(true);
        assert!(
            score_host("xkqzwtplvmnrbds.tld", 1, NavEvent::Answered, 0, 0).is_none(),
            "with DGA off and no suffix listing, the soup host must score nothing"
        );
        // Partial file: the untouched faculties stay ON (tunnel oversize still fires).
        for _ in 0..4 {
            let _ = score_host("exfil9.example", 16, NavEvent::Answered, 400, 0);
        }
        let t = score_host("exfil9.example", 16, NavEvent::Answered, 400, 0).unwrap();
        assert!(t.signals.contains(&Signal::Tunnel));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_rows_carry_score_and_ttl_countdown_columns() {
        let _serial = scrub();
        ARMED.store(true, Ordering::Release);
        drain_to_sequestration("probe.lan");
        let snap = snapshot(5);
        let f: Vec<&str> = snap.top[0].split('\t').collect();
        assert_eq!(f.len(), 9, "the pillar row is 9 fields: {:?}", f);
        assert_eq!(f[0], "probe.lan");
        assert_eq!(f[7], "5", "col 8 = the live score (Sonar lane penalty)");
        let ttl: u64 = f[8].parse().unwrap();
        assert!(
            ttl > 0 && ttl <= QUARANTINE_TTL_SECS,
            "a fresh automatic quarantine counts down from the full TTL, got {ttl}"
        );
        // The score ordering carries the SAME 9-field shape.
        assert_eq!(snap.top_by_score[0].split('\t').count(), 9);
    }

    #[test]
    fn reputation_reset_forgets_the_learned_law_but_not_the_ledger() {
        let _serial = scrub();
        let dir = std::env::temp_dir().join(format!("torta-underground-hr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        arm(dir.to_str().unwrap());
        record_at("probe.lan", Risk::Sonar, Source::Guard, now_secs());
        assert!(set_verdict("shady.example", 2)); // teaches +3 / logs a correction
        assert!(reputation_reset(), "there was something to forget");
        assert!(reputation_cell().read().unwrap().is_empty());
        assert!(corrections_cell().read().unwrap().is_empty());
        // NAND agrees: the reputation mirror holds no shady row, the log is header-only.
        let rep_disk = std::fs::read_to_string(dir.join(REPUTATION_FILE_NAME)).unwrap();
        assert!(!rep_disk.contains("shady.example"));
        let log_disk = std::fs::read_to_string(dir.join(CORRECTIONS_FILE_NAME)).unwrap();
        assert_eq!(log_disk.trim(), "#underground-corrections v1");
        // The ledger is UNTOUCHED — the licence economy survives the amnesty.
        assert_eq!(points_of("probe.lan"), Some(LICENCE_START - Risk::Sonar.base_penalty()));
        // …and a second reset finds nothing to forget.
        assert!(!reputation_reset());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod review_channel_tests {
    use super::*;

    /// ★ The line that would have exposed ROOT CAUSE #26 on sight.
    ///
    /// The layer's whole failure mode in that hunt was that it convicted SILENTLY: a healthy IPv4-only
    /// host was filed under the `tunnel` lane and drained to zero, and nothing anywhere said so. This
    /// asserts the review channel names all four things an investigator needs — the VERB, the HOST, the
    /// LANE that testified, and the licence remaining — so a browsing host filed as `tunnel` is visible
    /// in one grep instead of one session.
    #[test]
    fn the_review_channel_names_the_lane_that_convicted_the_host() {
        let line = format_underground_line(&UndergroundJudgement {
            ts: 1_785_028_019,
            verb: UndergroundVerb::Sequestrate,
            host: "wildriftfire.cc".into(),
            lane: "tunnel".into(),
            penalty: 8,
            points: 0,
        });
        assert_eq!(line, "1785028019 SEQUESTRATE wildriftfire.cc tunnel -8 licence=0\n");
        // The descent must be legible too, not just the final verdict.
        let mid = format_underground_line(&UndergroundJudgement {
            ts: 1_785_028_017,
            verb: UndergroundVerb::Deduct,
            host: "wildriftfire.cc".into(),
            lane: "tunnel".into(),
            penalty: 4,
            points: 12,
        });
        assert!(mid.starts_with("1785028017 DEDUCT wildriftfire.cc tunnel -4 licence=12"));
        // An empty host/lane must never render a torn line with a missing column.
        let bare = format_underground_line(&UndergroundJudgement {
            ts: 1,
            verb: UndergroundVerb::Pinned,
            host: String::new(),
            lane: String::new(),
            penalty: 0,
            points: 20,
        });
        assert_eq!(bare, "1 PINNED - - -0 licence=20\n");
    }
}

#[cfg(test)]
mod amnesty_tests {
    use super::*;

    /// ★ #79 — a ledger written by the pre-#26 build must not keep its wrongful convictions.
    ///
    /// Replays Socio's monochrome.tf report: a host sequestrated in the `tunnel` lane with its licence
    /// drained to 0, persisted, and carried across an `install -r` UPDATE. Before the amnesty that host
    /// was answered by the teeth gate forever (forged NXDOMAIN, 0ms, transport `-`) no matter how many
    /// times the detection bug was fixed, because a fix cannot reach backwards into stored verdicts.
    #[test]
    fn the_epoch_amnesty_frees_a_host_the_old_build_wrongly_sequestrated() {
        // An OLD ledger: no `epoch=` token at all ⇒ reads 0 ⇒ below DETECTION_EPOCH.
        let old = "#underground-ledger v1\n\
                   #meta recorded_total=10 recovered_total=5 teeth_total=10\n\
                   monochrome.tf\ttunnel\tsuffix\t4\t0\t100\t200\t100\t-\t1\n";
        let (entries, _, _, _) = parse_body(old);
        let e = entries
            .iter()
            .find(|e| e.host == "monochrome.tf")
            .expect("the row must survive parsing");
        assert!(!e.sequestrated, "the amnesty must vacate the sequestration");
        assert!(e.points > 0, "the licence must be restored, not left at 0");
        assert_eq!(e.seq_at, 0, "the quarantine clock must be cleared too");

        // A CURRENT-epoch ledger is left EXACTLY alone — the amnesty is a one-time correction for
        // superseded logic, never a standing pardon that makes sequestration meaningless.
        let current = format!(
            "#underground-ledger v1\n\
             #meta recorded_total=10 recovered_total=5 teeth_total=10 epoch={}\n\
             evil.example\ttunnel\tsuffix\t4\t0\t100\t200\t100\t-\t1\n",
            DETECTION_EPOCH
        );
        let (kept, _, _, _) = parse_body(&current);
        let k = kept.iter().find(|e| e.host == "evil.example").expect("row");
        assert!(k.sequestrated, "a current-epoch conviction MUST stand");
        assert_eq!(k.points, 0, "and its licence must stay spent");
    }
}
