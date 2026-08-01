/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! R4 Warden — Slice 5: **the Trust Crown** (`GithubTrustEngine`).
//!
//! This is the PRODUCER half of the blocklist trust model. Its sibling [`crate::blocklist::trust`] (P8 Wave B1,
//! 658 LOC, sealed) is the CONSUMER: it SCORES sources from pre-supplied scalars
//! (`SourceMeta::reputation`) but nothing in it ever FETCHES or MEASURES a candidate list. The crown
//! fills that gap — it DISCOVERS candidate sources (unauthenticated GitHub search, Fork #5: ship NO API
//! key), MEASURES each one's **collateral damage** against the shipped LocalCDN host table
//! ([`crate::mirror::FULL_MAPS`] — the Centauri over-block corpus), produces a 0..=100
//! integer-deterministic **safety score**, projects it to a [`SafetyBand`] (Safe/Caution/Risky), and is
//! the value the arming layer feeds into `trust.rs`'s `SourceMeta::reputation`. The user arms a
//! *trust-scored* list, never a blind one.
//!
//! ## The four-way Genesis cross (study → overhaul → combine → bind; ZERO derived bytes)
//!   - **rethink-app-main** `RethinkBlocklistManager`/`FileTag` (Apache-2.0) — the blocklist *descriptor*
//!     with group/curation and the `isSelected` arming model. We add a per-source NUMERIC score
//!     Rethink never had, and the Safe/Caution/Risky bands (a UI projection Rethink also lacks).
//!   - **dnsmasq-2.93** `pattern.c` (GPL-2.0, IDEA only) — the RFC-1123 validator + the per-label
//!     dot-is-a-barrier match shape. Reimplemented original-Rust ([`validate_host`]); the validator is
//!     the load-bearing integrity gate against a poisoned/over-broad list (a `*.com` never enters).
//!   - **`crate::blocklist::trust`** (EXISTS) — the consumer this crown feeds via `reputation`.
//!   - **`crate::mirror::FULL_MAPS`** (EXISTS, Centauri/LocalCDN) — the over-block corpus the
//!     `cdn_overlap` signal measures against (the Carnage collision the corpora never had).
//!
//! ## The semantic inversion (what makes this ORIGINAL, not copied)
//! RethinkDNS has CURATION but no numeric score; dnsmasq has an ipset SINK but no trust concept at all.
//! The crown measures **how much a candidate list would collateral-damage known-good CDN fronts** (the
//! same hosts Centauri serves locally) and makes THAT the dominant signal — louder than entry-count,
//! signature, or freshness. A list that blocks `cdnjs.cloudflare.com` is provably harmful to the
//! datapath, no matter how reputable its origin.
//!
//! ## Two separate axes — do NOT conflate
//!   - **This crown's safety score** = COLLATERAL DAMAGE (would arming this over-block the web?). Even an
//!     unsigned list can be perfectly *safe to arm* if it touches no CDN. The crown does NOT apply
//!     `trust.rs`'s signed/unsigned band ceiling — that is the consumer's job.
//!   - **`trust.rs`'s trust score** = TRUSTWORTHINESS (provenance/corroboration + the signature band
//!     `UNSIGNED_CEILING`). The crown's safety score FEEDS its `reputation` input; `trust.rs` then
//!     applies the signature ceiling. The two compose — they never duplicate.
//!
//! ## Verification scope (GROUND_TRUTH, honest)
//! The PURE core — parse → RFC-1123 validate → measure `cdn_overlap` → integer-deterministic score →
//! band → DurableTier cache round-trip — is fully exercised by the host-cargo fixtures below
//! (`clean → Safe`, `googleapis-seeded → Risky`). The live network leg [`GithubTrustEngine::
//! fetch_and_investigate`] reuses the SAME `hyper`/`hyper-rustls`/`rustls` client stack as
//! [`crate::mirror::fetch`] (ZERO new dep) but is **network-gated** — it is compiled + type-checked, NOT
//! exercised by the offline fixtures. `fetch_once` itself is content-address-PINNED (the Centauri
//! catalog knows the hash in advance); live blocklist discovery has no pre-known hash, so this sibling
//! drops the content-address gate — the `cdn_overlap` + RFC-1123 validator + safety score ARE the
//! integrity gates for discovered content.
//!
//! ## RAM⊗NAND substrate
//! The RAM cache is a `Mutex<HashMap<url_key, SourceSafety>>`; it is written through to
//! [`crate::runtime_tier::DurableTier`] (the #133 query.log precedent) on every investigate/arm and
//! rehydrated once at construction. ZERO `std::fs` is on any verdict hot path — this is a control-plane
//! pillar (the user arms lists), never the per-query datapath.
//!
//! Credits (NOTICE): celcro/RethinkDNS (Apache-2.0, the descriptor/curation model) · dnsmasq-2.93 ©
//! Simon Kelley (GPL-2.0, the validator SHAPE only — zero bytes). Gated behind `mirror` so the base
//! cargo-ndk `.so` (no feature) stays BYTE-IDENTICAL.

#![cfg(feature = "mirror")]

use std::collections::{HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, OnceLock};

use crate::mirror::cache::MAX_ASSET_BYTES;
use crate::mirror::FULL_MAPS;
use crate::runtime_tier::DurableTier;

// ---- Scoring constants (integer / fixed-point, deterministic — no float in the score) -------------

/// A perfect, no-collateral list starts here.
const SCORE_FULL: i32 = 100;
/// The DOMINANT signal: `cdn_overlap_ratio` (as permille) scaled by this. At weight 80 a list that
/// over-blocks ~62% of its entries already drops out of `Safe`; ~90% lands deep in `Risky`. This is the
/// Carnage collision — collateral damage outweighs every other signal.
const CDN_WEIGHT: i32 = 80;
/// Below this entry count a list is suspiciously thin (narrow coverage / possible padding shell).
const LOW_ENTRIES_FLOOR: u32 = 50;
const LOW_ENTRIES_PENALTY: i32 = 8;
/// A list whose last-seen age exceeds this (days) begins a gentle staleness decay…
const STALE_AFTER_DAYS: u32 = 90;
/// …reaching its full penalty after this many further days.
const STALE_SPAN_DAYS: u32 = 365;
const STALE_MAX_PENALTY: i32 = 8;
/// A RethinkDNS curated-seed list (Fork #4) is editorially vetted — a small positive nudge.
const CURATED_BONUS: i32 = 6;
/// A signature-verified list is provably maintained — a small positive nudge (NOT the security-band
/// ceiling; that lives in `trust.rs`).
const SIGNED_BONUS: i32 = 4;

/// `score >= SAFE_FLOOR` ⇒ [`SafetyBand::Safe`].
const SAFE_FLOOR: u8 = 80;
/// `score >= CAUTION_FLOOR` (and `< SAFE_FLOOR`) ⇒ [`SafetyBand::Caution`]; below ⇒ [`SafetyBand::Risky`].
const CAUTION_FLOOR: u8 = 50;

// ---- Bounds (battery-frugal; the crown is a control-plane pillar, never the hot path) -------------

/// A single candidate list is parsed up to this many entries (a bounded-read guard against a hostile
/// multi-million-line blob exhausting per-control-plane memory).
const MAX_ENTRIES: usize = 200_000;
/// The `hits` vec on a [`SourceSafety`] is a bounded SAMPLE for the dashboard — `cdn_overlap` (the
/// COUNT) stays exact regardless, this only caps the displayed/persisted detail.
const MAX_SAMPLE_HITS: usize = 32;
/// At most this many distinct sources are held in the cache / persisted (the armed-set is small).
const MAX_CACHE_SOURCES: usize = 256;

/// The durable record name under the engine's app-private dir (sanitized by `DurableTier::with_dir`).
const DURABLE_NAME: &str = "github-trust-crown";
/// The crown's own payload framing inside the DurableTier blob (forward-compatible).
const CODEC_MAGIC: &[u8; 4] = b"GTC1";

// ===================================================================================================
// UniFFI typed surface (full-power: Enum + Records + Error + Object — NEVER a flat string)
// ===================================================================================================

/// The safety band a source falls in — a UI projection of the numeric [`SourceSafety::trust_score`].
/// RethinkDNS has no equivalent; we derive it. `Safe` ⇒ arm freely; `Caution` ⇒ review; `Risky` ⇒ a
/// consent gate (the arming layer refuses to arm a `Risky` source without an explicit override).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SafetyBand {
    /// 80..=100 — negligible collateral, safe to arm.
    Safe,
    /// 50..=79 — some collateral or thin/stale coverage; review before arming.
    Caution,
    /// 0..=49 — heavy CDN collateral; arming would over-block the web. Consent-gated.
    Risky,
}

/// The category of one scoring signal, so the dashboard can render WHY a source scored as it did (a
/// transparent decomposition, never a black box). Negative kinds dock points; positive kinds add.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ReasonKind {
    /// NEGATIVE — entries collide with known-good CDN hosts (the dominant signal).
    CdnOverlap,
    /// NEGATIVE — suspiciously few entries (thin coverage / possible shell).
    LowEntries,
    /// NEGATIVE — the list is old (recency decay).
    StaleFetch,
    /// NEGATIVE/INFO — entries the RFC-1123 validator rejected (poisoned / over-broad rules).
    Malformed,
    /// POSITIVE — healthy entry count with zero CDN collateral.
    GoodCoverage,
    /// POSITIVE — a RethinkDNS curated-seed list (editorially vetted, Fork #4).
    CuratedSeed,
    /// POSITIVE — a signature-verified (maintained) source.
    SignedSource,
}

/// One element of a source's score decomposition: the signal kind, its point contribution, and a
/// human-readable detail for the dashboard's expanded card.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TrustReason {
    pub kind: ReasonKind,
    /// The signed point delta this signal contributed to the final score (negative = docked).
    pub delta: i16,
    pub detail: String,
}

/// One collateral collision — a blocklist `entry` that would block the CDN host `cdn_host` (which
/// serves `library` locally via Centauri). The transparency detail behind [`SourceSafety::cdn_overlap`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct BlocklistHit {
    /// The blocklist entry that causes collateral.
    pub entry: String,
    /// The known-good CDN host it would block.
    pub cdn_host: String,
    /// The LocalCDN library that host serves (extra context from the [`crate::mirror::FULL_MAPS`] map).
    pub library: String,
}

/// The non-bytes signals the caller supplies about a candidate list (full-power typed input — not a row
/// of flat args). `signed`/`curated` are Fork-driven facts about the source; `age_days` drives recency
/// decay (0 = unknown/fresh ⇒ neutral); `fetched_at_ms` is stored for the dashboard's freshness label.
#[derive(Debug, Clone, Copy, uniffi::Record)]
pub struct SourceHints {
    /// Is the list minisign-signed? (A maintained-source nudge — NOT the `trust.rs` security ceiling.)
    pub signed: bool,
    /// Is this a RethinkDNS curated-seed list (Fork #4)?
    pub curated: bool,
    /// Age of the list in days (0 = unknown/fresh ⇒ neutral recency).
    pub age_days: u32,
    /// Wall-clock fetch time in epoch-ms (display only; never enters the score).
    pub fetched_at_ms: u64,
}

/// The full scored descriptor for ONE candidate source — the crown's output and the dashboard's row.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SourceSafety {
    /// Stable opaque id (FNV-1a/32 of the URL), the join key to the blocklist `Matcher.sources` bitset.
    pub source_id: u32,
    pub name: String,
    pub url: String,
    /// The 0..=100 SAFETY score (collateral-dominant). This is the value fed to `trust.rs`'s
    /// `SourceMeta::reputation` at the arming layer.
    pub trust_score: u8,
    pub band: SafetyBand,
    /// Total entries the parser admitted (post-validation `valid` + the malformed are tracked separately).
    pub entry_count: u32,
    /// Entries that passed the RFC-1123 validator (the ones that would actually enter the rule-set).
    pub valid_entry_count: u32,
    /// Entries the validator REJECTED (over-broad `*.com` / malformed) — a poisoned-list signal.
    pub malformed_count: u32,
    /// Distinct valid entries that collide with a known CDN host (the COUNT is exact).
    pub cdn_overlap: u32,
    /// `cdn_overlap / valid_entry_count` for display ONLY — the score uses integer permille math.
    pub cdn_overlap_ratio: f32,
    /// A bounded SAMPLE (`MAX_SAMPLE_HITS`) of the colliding entries for the dashboard's detail card.
    pub hits: Vec<BlocklistHit>,
    /// The transparent score decomposition.
    pub reasons: Vec<TrustReason>,
    pub signed: bool,
    pub curated: bool,
    /// The arming flag (RethinkDNS `isSelected`, reimagined over a trust-scored descriptor).
    pub armed: bool,
    pub fetched_at_ms: u64,
}

/// WHY a crown network operation failed — the typed, UniFFI-bridged failure surface. Only the live legs
/// are fallible; the pure `investigate_bytes` is infallible (it fail-closes a panic to a `Risky`
/// verdict, never an error). `#[non_exhaustive]` so a future mode (e.g. a parse-quota) is additive.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum GithubTrustError {
    /// A transport-layer failure: non-`https`/unparseable URL, connect/TLS error, non-2xx (other than
    /// rate-limit), oversized body, or a mid-stream read error. Fail-closed: no bytes leave on this path.
    #[error("network: {reason}")]
    Network { reason: String },

    /// The unauthenticated GitHub endpoint rate-limited us (HTTP 403/429). Fork #5 ships NO API key, so
    /// the budget is the public 60/hr + 10/min — the cache absorbs repeats; the UI shows the retry hint.
    #[error("rate-limited (retry in ~{reset_seconds}s)")]
    RateLimited { reset_seconds: u32 },

    /// A panic inside a live leg — the engine's `catch_unwind` firewall caught a bug and reports it
    /// typed, never aborting across the FFI boundary.
    #[error("panic: {reason}")]
    Panic { reason: String },
}

// ===================================================================================================
// The CDN over-block corpus (built once from FULL_MAPS)
// ===================================================================================================

/// The deduped `(cdn_host, library)` table, built ONCE from [`crate::mirror::FULL_MAPS`]. The crown
/// scans this linearly (~43 hosts) — a control-plane cost, never per-packet. First library per host
/// wins (a host serves one canonical library family in the seed map).
fn cdn_corpus() -> &'static [(&'static str, &'static str)] {
    static CORPUS: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let mut seen: HashSet<&'static str> = HashSet::new();
        let mut out: Vec<(&'static str, &'static str)> = Vec::new();
        for m in FULL_MAPS {
            if seen.insert(m.host) {
                out.push((m.host, m.library));
            }
        }
        out
    })
}

/// Does `entry` (a validated, lowercased blocklist host) collide with any known CDN host? An entry
/// collides when it EQUALS a CDN host OR is a parent domain of one (`example.com` blocks
/// `cdn.example.com`) — the dot-is-a-barrier over-block test (a blocklist trie blocks every subdomain
/// beneath a listed apex). Returns the first colliding `(cdn_host, library)`. Allocation-free.
fn collides(entry: &str) -> Option<(&'static str, &'static str)> {
    let eb = entry.as_bytes();
    for &(host, library) in cdn_corpus() {
        if host == entry {
            return Some((host, library));
        }
        // `host` ends with `.<entry>` ⇒ `entry` is a parent of the CDN host (collateral).
        let hb = host.as_bytes();
        if hb.len() > eb.len() + 1 && hb.ends_with(eb) && hb[hb.len() - eb.len() - 1] == b'.' {
            return Some((host, library));
        }
    }
    None
}

// ===================================================================================================
// Pure parsing + validation (the dnsmasq pattern.c IDEA, reimplemented clean-room)
// ===================================================================================================

/// Strip a leading sinkhole IP (`0.0.0.0`/`127.0.0.1`/`::`/`::1`/`255.255.255.255`) from a hosts-format
/// line and return the host token, or the bare token for a domain-only list. `None` when the line has
/// no usable host token.
fn extract_host(line: &str) -> Option<&str> {
    let mut it = line.split_whitespace();
    let first = it.next()?;
    let is_sinkhole_ip = matches!(
        first,
        "0.0.0.0" | "127.0.0.1" | "::" | "::1" | "255.255.255.255" | "0.0.0.0:0"
    );
    let host = if is_sinkhole_ip { it.next()? } else { first };
    // Drop a trailing root dot ("example.com." → "example.com").
    Some(host.strip_suffix('.').unwrap_or(host))
}

/// RFC-1123-lite validation — the load-bearing INTEGRITY GATE (the dnsmasq `is_valid_dns_name` IDEA,
/// reimplemented). A rule from a candidate source must pass this BEFORE it counts. Rejects defend
/// against a poisoned/over-broad list: total 1..=253, **≥2 labels** (no bare TLD `com`), each label
/// 1..=63, alphanumeric + hyphen only, no leading/trailing hyphen, and the final label NON-numeric
/// (reject a raw IP masquerading as a host). A `*.com`-style wildcard never reaches the rule-set.
fn validate_host(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() < 2 {
        return false; // a bare single label (e.g. "com") would over-block an entire TLD
    }
    for label in &labels {
        let lb = label.as_bytes();
        if lb.is_empty() || lb.len() > 63 {
            return false;
        }
        if lb[0] == b'-' || lb[lb.len() - 1] == b'-' {
            return false;
        }
        for &c in lb {
            if !(c.is_ascii_alphanumeric() || c == b'-') {
                return false; // rejects '*', '_', '/', whitespace — no glob/over-broad rule enters
            }
        }
    }
    // The final label must not be all-numeric (defends against an IPv4 literal scored as a "domain").
    let last = labels[labels.len() - 1];
    if last.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    true
}

/// Parse a candidate list's raw bytes into the set of valid, lowercased, deduped hosts + the count of
/// entries the validator REJECTED. Handles hosts-format (`0.0.0.0 host`), domain-only, `#`/`!` comment
/// lines, and inline `#` comments. Bounded at [`MAX_ENTRIES`].
fn parse_entries(raw: &[u8]) -> (Vec<String>, u32) {
    let text = String::from_utf8_lossy(raw);
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut malformed: u32 = 0;
    for raw_line in text.lines() {
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue; // blank / full-line comment (hosts `#` + adblock `!`)
        }
        // Strip an inline `#` comment (hosts-format trailing notes).
        if let Some(idx) = line.find('#') {
            line = line[..idx].trim();
        }
        if line.is_empty() {
            continue;
        }
        match extract_host(line) {
            Some(host_tok) => {
                let host = host_tok.to_ascii_lowercase();
                if validate_host(&host) {
                    if seen.insert(host.clone()) {
                        out.push(host);
                    }
                } else {
                    malformed = malformed.saturating_add(1);
                }
            }
            None => malformed = malformed.saturating_add(1),
        }
        if out.len() >= MAX_ENTRIES {
            break;
        }
    }
    (out, malformed)
}

// ===================================================================================================
// Pure scoring (integer-deterministic — the crown's verifiable heart)
// ===================================================================================================

/// `overlap / total` expressed as integer permille (0..=1000), so the score is float-free + deterministic.
fn overlap_permille(overlap: u32, total: u32) -> u32 {
    if total == 0 {
        return 0;
    }
    ((overlap as u64 * 1000) / total as u64).min(1000) as u32
}

/// The gentle recency penalty (0..=`STALE_MAX_PENALTY`) for a list `age_days` old. Fresh/unknown ⇒ 0;
/// linear from `STALE_AFTER_DAYS` to its full penalty over `STALE_SPAN_DAYS`. Integer, monotone.
fn stale_penalty(age_days: u32) -> i32 {
    if age_days <= STALE_AFTER_DAYS {
        return 0;
    }
    let over = (age_days - STALE_AFTER_DAYS).min(STALE_SPAN_DAYS);
    (over as i32 * STALE_MAX_PENALTY) / STALE_SPAN_DAYS as i32
}

/// The complete deterministic score + its decomposition. `valid` = entries that passed validation;
/// `overlap` = distinct valid entries colliding with a CDN host. Collateral dominates; coverage,
/// staleness, curation and signature are bounded modifiers. Returns `(score 0..=100, reasons)`.
fn compute_score(
    valid: u32,
    overlap: u32,
    malformed: u32,
    hints: &SourceHints,
) -> (u8, Vec<TrustReason>) {
    let mut reasons: Vec<TrustReason> = Vec::new();
    let mut score: i32 = SCORE_FULL;

    // CDN collateral — the dominant signal.
    let permille = overlap_permille(overlap, valid);
    let cdn_pen = (permille as i32 * CDN_WEIGHT) / 1000;
    if cdn_pen > 0 {
        score -= cdn_pen;
        reasons.push(TrustReason {
            kind: ReasonKind::CdnOverlap,
            delta: -(cdn_pen.min(i16::MAX as i32) as i16),
            detail: format!(
                "{overlap}/{valid} entries collide with known CDN hosts ({}.{}% over-block)",
                permille / 10,
                permille % 10
            ),
        });
    } else {
        reasons.push(TrustReason {
            kind: ReasonKind::GoodCoverage,
            delta: 0,
            detail: format!("zero CDN collateral across {valid} entries"),
        });
    }

    // Thin coverage.
    if valid < LOW_ENTRIES_FLOOR {
        score -= LOW_ENTRIES_PENALTY;
        reasons.push(TrustReason {
            kind: ReasonKind::LowEntries,
            delta: -(LOW_ENTRIES_PENALTY as i16),
            detail: format!("only {valid} valid entries (< {LOW_ENTRIES_FLOOR})"),
        });
    }

    // Staleness.
    let stale = stale_penalty(hints.age_days);
    if stale > 0 {
        score -= stale;
        reasons.push(TrustReason {
            kind: ReasonKind::StaleFetch,
            delta: -(stale as i16),
            detail: format!("list is {} days old", hints.age_days),
        });
    }

    // Malformed-rule note (informational; does not move the score on its own — the validator already
    // EXCLUDED them — but it surfaces a poisoned-list signal to the dashboard).
    if malformed > 0 {
        reasons.push(TrustReason {
            kind: ReasonKind::Malformed,
            delta: 0,
            detail: format!("{malformed} entries rejected by the RFC-1123 validator"),
        });
    }

    // Curated seed.
    if hints.curated {
        score += CURATED_BONUS;
        reasons.push(TrustReason {
            kind: ReasonKind::CuratedSeed,
            delta: CURATED_BONUS as i16,
            detail: "RethinkDNS curated-seed list".to_string(),
        });
    }

    // Signature (maintained source).
    if hints.signed {
        score += SIGNED_BONUS;
        reasons.push(TrustReason {
            kind: ReasonKind::SignedSource,
            delta: SIGNED_BONUS as i16,
            detail: "minisign-verified source".to_string(),
        });
    }

    (score.clamp(0, SCORE_FULL) as u8, reasons)
}

/// Project a 0..=100 score to its [`SafetyBand`].
fn band_for(score: u8) -> SafetyBand {
    if score >= SAFE_FLOOR {
        SafetyBand::Safe
    } else if score >= CAUTION_FLOOR {
        SafetyBand::Caution
    } else {
        SafetyBand::Risky
    }
}

/// FNV-1a/32 of a URL — the stable opaque `source_id` (joins the blocklist `Matcher.sources` bitset).
/// `pub(crate)` since #61B: the Underground lane catalogs (`crate::catalogs`) derive their lane
/// `source_id`s from stable URNs through this SAME hash — one scheme, no collision management.
pub(crate) fn fnv1a32(s: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in s.as_bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// FNV-1a/64 of a URL — the RAM cache key.
fn fnv1a64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// The PURE investigate core: parse → validate → measure `cdn_overlap` → score → band → assemble. No
/// network, no I/O, fully deterministic. This is what the fixtures exercise.
fn investigate_core(name: &str, url: &str, raw: &[u8], hints: &SourceHints) -> SourceSafety {
    let (entries, malformed) = parse_entries(raw);
    let valid = entries.len() as u32;

    let mut hits: Vec<BlocklistHit> = Vec::new();
    let mut overlap: u32 = 0;
    for e in &entries {
        if let Some((cdn_host, library)) = collides(e) {
            overlap += 1;
            if hits.len() < MAX_SAMPLE_HITS {
                hits.push(BlocklistHit {
                    entry: e.clone(),
                    cdn_host: cdn_host.to_string(),
                    library: library.to_string(),
                });
            }
        }
    }

    let (score, reasons) = compute_score(valid, overlap, malformed, hints);
    let ratio = if valid == 0 {
        0.0_f32
    } else {
        overlap as f32 / valid as f32
    };

    SourceSafety {
        source_id: fnv1a32(url),
        name: name.to_string(),
        url: url.to_string(),
        trust_score: score,
        band: band_for(score),
        entry_count: valid.saturating_add(malformed),
        valid_entry_count: valid,
        malformed_count: malformed,
        cdn_overlap: overlap,
        cdn_overlap_ratio: ratio,
        hits,
        reasons,
        signed: hints.signed,
        curated: hints.curated,
        armed: false,
        fetched_at_ms: hints.fetched_at_ms,
    }
}

/// A fail-closed verdict for the panic path: an un-analyzable source is treated as `Risky` (never armed
/// silently). Safety fail-closes to caution, never to "safe".
fn fail_safe_safety(name: &str, url: &str, hints: &SourceHints) -> SourceSafety {
    SourceSafety {
        source_id: fnv1a32(url),
        name: name.to_string(),
        url: url.to_string(),
        trust_score: 0,
        band: SafetyBand::Risky,
        entry_count: 0,
        valid_entry_count: 0,
        malformed_count: 0,
        cdn_overlap: 0,
        cdn_overlap_ratio: 0.0,
        hits: Vec::new(),
        reasons: vec![TrustReason {
            kind: ReasonKind::Malformed,
            delta: 0,
            detail: "analysis panicked — treated as Risky (fail-closed)".to_string(),
        }],
        signed: hints.signed,
        curated: hints.curated,
        armed: false,
        fetched_at_ms: hints.fetched_at_ms,
    }
}

// ===================================================================================================
// DurableTier cache codec (the crown's own framing inside the DurableTier blob)
// ===================================================================================================

fn put_str(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let len = b.len().min(u16::MAX as usize) as u16;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&b[..len as usize]);
}

fn get_str(buf: &[u8], pos: &mut usize) -> Option<String> {
    let len = get_u16(buf, pos)? as usize;
    let end = pos.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&buf[*pos..end]).into_owned();
    *pos = end;
    Some(s)
}

fn get_u8(buf: &[u8], pos: &mut usize) -> Option<u8> {
    let v = *buf.get(*pos)?;
    *pos += 1;
    Some(v)
}

fn get_u16(buf: &[u8], pos: &mut usize) -> Option<u16> {
    let end = pos.checked_add(2)?;
    let slice = buf.get(*pos..end)?;
    let v = u16::from_le_bytes([slice[0], slice[1]]);
    *pos = end;
    Some(v)
}

fn get_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let slice = buf.get(*pos..end)?;
    let v = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
    *pos = end;
    Some(v)
}

fn get_u64(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    let slice = buf.get(*pos..end)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(slice);
    *pos = end;
    Some(u64::from_le_bytes(a))
}

fn band_to_u8(b: SafetyBand) -> u8 {
    match b {
        SafetyBand::Safe => 0,
        SafetyBand::Caution => 1,
        SafetyBand::Risky => 2,
    }
}

fn band_from_u8(v: u8) -> SafetyBand {
    match v {
        0 => SafetyBand::Safe,
        1 => SafetyBand::Caution,
        _ => SafetyBand::Risky,
    }
}

fn kind_to_u8(k: ReasonKind) -> u8 {
    match k {
        ReasonKind::CdnOverlap => 0,
        ReasonKind::LowEntries => 1,
        ReasonKind::StaleFetch => 2,
        ReasonKind::Malformed => 3,
        ReasonKind::GoodCoverage => 4,
        ReasonKind::CuratedSeed => 5,
        ReasonKind::SignedSource => 6,
    }
}

fn kind_from_u8(v: u8) -> ReasonKind {
    match v {
        0 => ReasonKind::CdnOverlap,
        1 => ReasonKind::LowEntries,
        2 => ReasonKind::StaleFetch,
        3 => ReasonKind::Malformed,
        4 => ReasonKind::GoodCoverage,
        5 => ReasonKind::CuratedSeed,
        _ => ReasonKind::SignedSource,
    }
}

/// Serialize the cache (bounded to [`MAX_CACHE_SOURCES`]) into the crown's framed blob.
fn encode_cache(sources: &[SourceSafety]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(CODEC_MAGIC);
    let n = sources.len().min(MAX_CACHE_SOURCES) as u32;
    buf.extend_from_slice(&n.to_le_bytes());
    for s in sources.iter().take(MAX_CACHE_SOURCES) {
        buf.extend_from_slice(&s.source_id.to_le_bytes());
        put_str(&mut buf, &s.name);
        put_str(&mut buf, &s.url);
        buf.push(s.trust_score);
        buf.push(band_to_u8(s.band));
        buf.extend_from_slice(&s.entry_count.to_le_bytes());
        buf.extend_from_slice(&s.valid_entry_count.to_le_bytes());
        buf.extend_from_slice(&s.malformed_count.to_le_bytes());
        buf.extend_from_slice(&s.cdn_overlap.to_le_bytes());
        buf.extend_from_slice(&s.cdn_overlap_ratio.to_le_bytes());
        buf.push(s.signed as u8);
        buf.push(s.curated as u8);
        buf.push(s.armed as u8);
        buf.extend_from_slice(&s.fetched_at_ms.to_le_bytes());

        let hn = s.hits.len().min(MAX_SAMPLE_HITS) as u16;
        buf.extend_from_slice(&hn.to_le_bytes());
        for h in s.hits.iter().take(MAX_SAMPLE_HITS) {
            put_str(&mut buf, &h.entry);
            put_str(&mut buf, &h.cdn_host);
            put_str(&mut buf, &h.library);
        }

        let rn = s.reasons.len().min(u16::MAX as usize) as u16;
        buf.extend_from_slice(&rn.to_le_bytes());
        for r in s.reasons.iter().take(rn as usize) {
            buf.push(kind_to_u8(r.kind));
            buf.extend_from_slice(&r.delta.to_le_bytes());
            put_str(&mut buf, &r.detail);
        }
    }
    buf
}

/// Decode the crown's framed blob. Fail-safe: a truncated / wrong-magic record yields an empty cache
/// (a cold start), never a torn read or a panic.
fn decode_cache(buf: &[u8]) -> Vec<SourceSafety> {
    if buf.len() < 8 || &buf[0..4] != CODEC_MAGIC {
        return Vec::new();
    }
    let mut pos = 4usize;
    let n = match get_u32(buf, &mut pos) {
        Some(n) => (n as usize).min(MAX_CACHE_SOURCES),
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let rec = (|| -> Option<SourceSafety> {
            let source_id = get_u32(buf, &mut pos)?;
            let name = get_str(buf, &mut pos)?;
            let url = get_str(buf, &mut pos)?;
            let trust_score = get_u8(buf, &mut pos)?;
            let band = band_from_u8(get_u8(buf, &mut pos)?);
            let entry_count = get_u32(buf, &mut pos)?;
            let valid_entry_count = get_u32(buf, &mut pos)?;
            let malformed_count = get_u32(buf, &mut pos)?;
            let cdn_overlap = get_u32(buf, &mut pos)?;
            let ratio = f32::from_le_bytes([
                get_u8(buf, &mut pos)?,
                get_u8(buf, &mut pos)?,
                get_u8(buf, &mut pos)?,
                get_u8(buf, &mut pos)?,
            ]);
            let signed = get_u8(buf, &mut pos)? != 0;
            let curated = get_u8(buf, &mut pos)? != 0;
            let armed = get_u8(buf, &mut pos)? != 0;
            let fetched_at_ms = get_u64(buf, &mut pos)?;

            let hn = get_u16(buf, &mut pos)? as usize;
            if hn > MAX_SAMPLE_HITS {
                return None;
            }
            let mut hits = Vec::with_capacity(hn);
            for _ in 0..hn {
                let entry = get_str(buf, &mut pos)?;
                let cdn_host = get_str(buf, &mut pos)?;
                let library = get_str(buf, &mut pos)?;
                hits.push(BlocklistHit {
                    entry,
                    cdn_host,
                    library,
                });
            }

            let rn = get_u16(buf, &mut pos)? as usize;
            let mut reasons = Vec::with_capacity(rn.min(64));
            for _ in 0..rn {
                let kind = kind_from_u8(get_u8(buf, &mut pos)?);
                let delta = get_u16(buf, &mut pos)? as i16;
                let detail = get_str(buf, &mut pos)?;
                reasons.push(TrustReason {
                    kind,
                    delta,
                    detail,
                });
            }

            Some(SourceSafety {
                source_id,
                name,
                url,
                trust_score,
                band,
                entry_count,
                valid_entry_count,
                malformed_count,
                cdn_overlap,
                cdn_overlap_ratio: ratio,
                hits,
                reasons,
                signed,
                curated,
                armed,
                fetched_at_ms,
            })
        })();
        match rec {
            Some(r) => out.push(r),
            None => break, // truncated tail — keep what parsed cleanly (fail-safe)
        }
    }
    out
}

// ===================================================================================================
// THE GITHUB TRUST ENGINE (UniFFI Object — the crown's stateful handle)
// ===================================================================================================

/// THE TRUST CROWN — the stateful blocklist-trust PRODUCER. Kotlin constructs it ONCE at boot (passing
/// the app-private durable dir), holds the `Arc`, then: builds the unauthenticated search URL via
/// [`search_query_url`], investigates each discovered list's bytes via [`investigate_bytes`] (or the
/// live [`fetch_and_investigate`]), arms a source via [`arm`], and reads the armed/scored set via
/// [`cached`] for the SLINT dashboard. Interior state is `Mutex<HashMap>` (RAM hot tier) + a
/// [`DurableTier`] (NAND mirror). Each method is panic-firewalled — a bug degrades to a safe default,
/// never aborts the app.
#[derive(uniffi::Object)]
pub struct GithubTrustEngine {
    /// RAM hot tier: `fnv1a64(url) → SourceSafety`.
    cache: Mutex<HashMap<u64, SourceSafety>>,
    /// NAND mirror (#133 query.log precedent): the whole cache is written through here on change and
    /// rehydrated once at construction.
    durable: DurableTier,
}

#[uniffi::export]
impl GithubTrustEngine {
    /// Construct the crown rooted at the app-private `durable_dir`, rehydrating the cached/armed set
    /// from the NAND mirror. UniFFI Object ctors MUST return `Arc<Self>`. A cold/absent record
    /// rehydrates to an empty cache (never a panic across the FFI boundary).
    #[uniffi::constructor]
    pub fn new(durable_dir: String) -> Arc<Self> {
        let durable = DurableTier::with_dir(std::path::PathBuf::from(&durable_dir), DURABLE_NAME);
        let cache = catch_unwind(AssertUnwindSafe(|| {
            let mut map: HashMap<u64, SourceSafety> = HashMap::new();
            if let Some(bytes) = durable.rehydrate() {
                for s in decode_cache(&bytes) {
                    map.insert(fnv1a64(&s.url), s);
                }
            }
            map
        }))
        .unwrap_or_default();
        Arc::new(Self {
            cache: Mutex::new(cache),
            durable,
        })
    }

    /// Build the UNAUTHENTICATED GitHub repository-search URL for `query` (Fork #5 — ship NO API key;
    /// the public 60/hr + 10/min budget). The CALLER performs the search + extracts the candidate
    /// raw-list URLs (it has the JSON surface), then feeds each through [`investigate_bytes`]. Pure +
    /// deterministic; embeds no token. The `+blocklist` qualifier biases toward blocklist repos and
    /// `sort=stars` surfaces the well-known seeds first.
    pub fn search_query_url(&self, query: String) -> String {
        let mut q = String::with_capacity(query.len() + 16);
        for c in query.chars() {
            match c {
                ' ' => q.push('+'),
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => q.push(c),
                _ => {
                    let mut b = [0u8; 4];
                    for byte in c.encode_utf8(&mut b).bytes() {
                        q.push('%');
                        q.push_str(&format!("{byte:02X}"));
                    }
                }
            }
        }
        format!("https://api.github.com/search/repositories?q={q}+blocklist&sort=stars&order=desc")
    }

    /// Investigate a candidate list's already-fetched bytes: parse → RFC-1123 validate → measure
    /// `cdn_overlap` against the LocalCDN corpus → integer-deterministic score → band. Caches the result
    /// (RAM + NAND write-through) and returns the full [`SourceSafety`]. Infallible: a panic fail-closes
    /// to a `Risky` verdict (an un-analyzable source is never silently safe). This is the wired entry
    /// the live-discovery caller uses per candidate.
    pub fn investigate_bytes(
        &self,
        name: String,
        url: String,
        raw_list: Vec<u8>,
        hints: SourceHints,
    ) -> SourceSafety {
        let safety = catch_unwind(AssertUnwindSafe(|| {
            investigate_core(&name, &url, &raw_list, &hints)
        }))
        .unwrap_or_else(|_| fail_safe_safety(&name, &url, &hints));
        self.store(safety.clone());
        safety
    }

    /// LIVE LEG (network-gated): fetch `url`'s raw list bytes over ring-pinned HTTPS — reusing the SAME
    /// `hyper`/`hyper-rustls`/`rustls` client stack as [`crate::mirror::fetch`] (ZERO new dep) — then
    /// delegate to [`investigate_bytes`]. Unlike `fetch_once` this drops the content-address pin (live
    /// discovery has no pre-known hash; the `cdn_overlap` + validator + safety score ARE the integrity
    /// gates). NOT exercised by the offline fixtures; compiled + type-checked here. `Err` on transport
    /// failure / rate-limit / panic. h2-only + https-only (the encrypted-only invariant), 8 MiB capped.
    pub fn fetch_and_investigate(
        &self,
        name: String,
        url: String,
        hints: SourceHints,
    ) -> Result<SourceSafety, GithubTrustError> {
        let bytes = catch_unwind(AssertUnwindSafe(|| http_get_capped(&url))).map_err(|_| {
            GithubTrustError::Panic {
                reason: "fetch_and_investigate: panic firewalled".to_string(),
            }
        })??;
        Ok(self.investigate_bytes(name, url, bytes, hints))
    }

    /// The full cached/armed set (the SLINT dashboard's rows), most-recently-investigated order is not
    /// guaranteed (HashMap). A clone — the caller never holds the lock.
    pub fn cached(&self) -> Vec<SourceSafety> {
        match self.cache.lock() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// The cached descriptor for one `url`, if investigated.
    pub fn cached_for(&self, url: String) -> Option<SourceSafety> {
        match self.cache.lock() {
            Ok(g) => g.get(&fnv1a64(&url)).cloned(),
            Err(_) => None,
        }
    }

    /// Toggle the arming flag on a cached source (RethinkDNS `isSelected`, over a trust-scored
    /// descriptor). Returns `true` if the source was found. The arming layer is where the source's
    /// `trust_score` is fed into `trust.rs`'s `SourceMeta::reputation`; a `Risky` band is the caller's
    /// consent gate (the crown records intent, never auto-arms a Risky source on the user's behalf).
    pub fn arm(&self, url: String, armed: bool) -> bool {
        let found = match self.cache.lock() {
            Ok(mut g) => {
                if let Some(s) = g.get_mut(&fnv1a64(&url)) {
                    s.armed = armed;
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        };
        if found {
            self.persist();
        }
        found
    }

    /// Clear the entire cache (RAM + NAND).
    pub fn clear(&self) {
        if let Ok(mut g) = self.cache.lock() {
            g.clear();
        }
        self.durable.clear();
    }

    /// The count of cached sources (the dashboard's "N sources scored" glance).
    pub fn cached_count(&self) -> u32 {
        match self.cache.lock() {
            Ok(g) => g.len() as u32,
            Err(_) => 0,
        }
    }
}

impl GithubTrustEngine {
    /// Insert/replace a scored source in the RAM cache and write the whole cache through to NAND.
    fn store(&self, safety: SourceSafety) {
        if let Ok(mut g) = self.cache.lock() {
            // Bound the cache: if at capacity and this is a new url, drop the persist of overflow but
            // keep RAM correct (control-plane; the armed set is small in practice).
            g.insert(fnv1a64(&safety.url), safety);
        }
        self.persist();
    }

    /// Encode the RAM cache and write it through to the DurableTier (gentle, atomic, non-failing).
    fn persist(&self) {
        let snapshot: Vec<SourceSafety> = match self.cache.lock() {
            Ok(g) => g.values().take(MAX_CACHE_SOURCES).cloned().collect(),
            Err(_) => return,
        };
        let bytes = encode_cache(&snapshot);
        let _ = self.durable.write_through(&bytes);
    }
}

/// The live raw-list GET, reusing [`crate::mirror::fetch`]'s `hyper`/`hyper-rustls`/`rustls` client
/// construction verbatim, minus the content-address pin (live discovery has no pre-known hash).
/// https-only + h2-only (the encrypted-only invariant), 8 MiB capped streaming read. Returns the raw
/// bytes on a 2xx; `RateLimited` on 403/429; `Network` on any other failure. Network-gated.
fn http_get_capped(url: &str) -> Result<Vec<u8>, GithubTrustError> {
    use http::{Method, Request, Uri};
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_rustls::HttpsConnector;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let uri: Uri = url.parse().map_err(|_| GithubTrustError::Network {
        reason: "unparseable URL".to_string(),
    })?;
    if uri.scheme_str() != Some("https") {
        return Err(GithubTrustError::Network {
            reason: "non-https URL refused (encrypted-only)".to_string(),
        });
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| GithubTrustError::Network {
            reason: "runtime build failed".to_string(),
        })?;

    rt.block_on(async move {
        // Ring-pinned shared trust, EXACTLY as the mirror::fetch / DoH path. ALPN is the builder's:
        // `with_tls_config` hard-asserts an ALPN-empty config (hyper-rustls builder.rs:61) and
        // `enable_http2()` stamps the identical `h2` itself (builder.rs:260-261).
        let owned_tls = crate::tls_shared::client_tls_config();
        let https = HttpsConnector::<HttpConnector>::builder()
            .with_tls_config(owned_tls)
            .https_only()
            .enable_http2()
            .build();
        let client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build(https);

        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            // GitHub's unauthenticated API requires a User-Agent or it 403s.
            .header("user-agent", "torta-warden-trust-crown")
            .body(Empty::<Bytes>::new())
            .map_err(|_| GithubTrustError::Network {
                reason: "request build failed".to_string(),
            })?;

        let resp = client
            .request(req)
            .await
            .map_err(|_| GithubTrustError::Network {
                reason: "connect/send failed".to_string(),
            })?;
        let status = resp.status().as_u16();
        if status == 403 || status == 429 {
            return Err(GithubTrustError::RateLimited { reset_seconds: 60 });
        }
        if !resp.status().is_success() {
            return Err(GithubTrustError::Network {
                reason: format!("HTTP {status}"),
            });
        }

        let mut body = resp.into_body();
        let mut buf: Vec<u8> = Vec::with_capacity(512);
        use http_body_util::BodyExt;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| GithubTrustError::Network {
                reason: "body read error".to_string(),
            })?;
            if let Some(chunk) = frame.data_ref() {
                if buf.len() + chunk.len() > MAX_ASSET_BYTES {
                    return Err(GithubTrustError::Network {
                        reason: "list exceeds 8 MiB cap".to_string(),
                    });
                }
                buf.extend_from_slice(chunk);
            }
        }
        Ok(buf)
    })
}

// ===================================================================================================
// Host-cargo fixtures (the crown's verifiable heart — clean → Safe, googleapis-seeded → Risky)
// ===================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_hints() -> SourceHints {
        SourceHints {
            signed: false,
            curated: false,
            age_days: 0,
            fetched_at_ms: 0,
        }
    }

    /// A clean list of pure ad/tracker domains — NONE of which appear in the LocalCDN corpus.
    const CLEAN_LIST: &[u8] = b"\
# StevenBlack-style hosts header
0.0.0.0 ads.doubleclick.net
0.0.0.0 telemetry.evil.io
0.0.0.0 track.spyware.example
0.0.0.0 beacon.adserver.net
127.0.0.1 metrics.creepy.org
pixel.tracker.example
";

    /// A list seeded with REAL CDN hosts from `FULL_MAPS` — arming it would collateral-damage the web.
    const GOOGLEAPIS_LIST: &[u8] = b"\
# a poisoned list that nukes legitimate CDNs
0.0.0.0 ajax.googleapis.com
0.0.0.0 cdn.jsdelivr.net
0.0.0.0 cdnjs.cloudflare.com
0.0.0.0 maxcdn.bootstrapcdn.com
0.0.0.0 stackpath.bootstrapcdn.com
0.0.0.0 ads.tracker.example
";

    #[test]
    fn fixture_clean_list_scores_safe() {
        let e = GithubTrustEngine::new(temp_dir("clean"));
        let s = e.investigate_bytes(
            "clean ads".into(),
            "https://example.com/clean.txt".into(),
            CLEAN_LIST.to_vec(),
            fresh_hints(),
        );
        assert_eq!(s.cdn_overlap, 0, "a clean list collides with no CDN host");
        assert_eq!(
            s.band,
            SafetyBand::Safe,
            "clean → Safe (got score {})",
            s.trust_score
        );
        assert!(s.trust_score >= SAFE_FLOOR);
        assert_eq!(s.valid_entry_count, 6);
        assert_eq!(s.malformed_count, 0);
    }

    #[test]
    fn fixture_googleapis_seeded_scores_risky() {
        let e = GithubTrustEngine::new(temp_dir("risky"));
        let s = e.investigate_bytes(
            "poisoned".into(),
            "https://example.com/poison.txt".into(),
            GOOGLEAPIS_LIST.to_vec(),
            fresh_hints(),
        );
        assert_eq!(s.cdn_overlap, 5, "five of six entries hit a known CDN host");
        assert_eq!(
            s.band,
            SafetyBand::Risky,
            "CDN-nuking → Risky (got score {})",
            s.trust_score
        );
        assert!(s.trust_score < CAUTION_FLOOR);
        // The transparency detail must name the CDN collateral.
        assert!(s.hits.iter().any(|h| h.cdn_host == "ajax.googleapis.com"));
        assert!(s.reasons.iter().any(|r| r.kind == ReasonKind::CdnOverlap));
    }

    #[test]
    fn clean_strictly_outscores_poisoned() {
        let e = GithubTrustEngine::new(temp_dir("cmp"));
        let clean = e.investigate_bytes(
            "c".into(),
            "https://x/c".into(),
            CLEAN_LIST.to_vec(),
            fresh_hints(),
        );
        let poison = e.investigate_bytes(
            "p".into(),
            "https://x/p".into(),
            GOOGLEAPIS_LIST.to_vec(),
            fresh_hints(),
        );
        assert!(
            clean.trust_score > poison.trust_score,
            "the clean list ({}) must outscore the CDN-nuking list ({})",
            clean.trust_score,
            poison.trust_score
        );
    }

    #[test]
    fn score_is_deterministic() {
        let e = GithubTrustEngine::new(temp_dir("det"));
        let a = e.investigate_bytes(
            "n".into(),
            "https://x/d".into(),
            GOOGLEAPIS_LIST.to_vec(),
            fresh_hints(),
        );
        let b = e.investigate_bytes(
            "n".into(),
            "https://x/d".into(),
            GOOGLEAPIS_LIST.to_vec(),
            fresh_hints(),
        );
        assert_eq!(
            a.trust_score, b.trust_score,
            "the score is integer-deterministic"
        );
        assert_eq!(a.cdn_overlap, b.cdn_overlap);
        assert_eq!(a.source_id, b.source_id, "same URL → same opaque source_id");
    }

    #[test]
    fn collides_matches_apex_parent_of_cdn_host() {
        // A blocklist entry at the apex of a CDN host blocks the CDN host (the over-block test).
        assert!(
            collides("googleapis.com").is_some(),
            "apex over-blocks ajax.googleapis.com"
        );
        assert!(
            collides("cdn.jsdelivr.net").is_some(),
            "exact CDN host collides"
        );
        assert!(
            collides("doubleclick.net").is_none(),
            "a non-CDN ad domain does not collide"
        );
        // A near-miss suffix that is NOT a dot-boundary parent must NOT false-collide.
        assert!(
            collides("oogleapis.com").is_none(),
            "partial-label suffix is not a parent"
        );
    }

    #[test]
    fn validator_rejects_overbroad_and_malformed() {
        assert!(
            !validate_host("com"),
            "a bare TLD is rejected (would over-block)"
        );
        assert!(!validate_host("*.com"), "a glob is rejected");
        assert!(
            !validate_host("-bad.example.com"),
            "leading hyphen rejected"
        );
        assert!(
            !validate_host("bad-.example.com"),
            "trailing hyphen rejected"
        );
        assert!(
            !validate_host("192.168.0.1"),
            "a raw IPv4 is rejected (numeric final label)"
        );
        assert!(
            !validate_host("under_score.example.com"),
            "underscore rejected"
        );
        assert!(validate_host("ads.example.com"), "a normal host passes");
        assert!(validate_host("a.co"), "a minimal two-label host passes");
    }

    #[test]
    fn parser_counts_malformed_and_dedups() {
        // Two valid (one duped) + one over-broad bare TLD + one glob.
        let raw = b"0.0.0.0 ads.example.com\n0.0.0.0 ads.example.com\ncom\n*.evil.net\n";
        let (entries, malformed) = parse_entries(raw);
        assert_eq!(entries.len(), 1, "the duplicate is deduped");
        assert_eq!(malformed, 2, "the bare TLD and the glob are rejected");
    }

    #[test]
    fn curated_and_signed_nudge_the_score_up() {
        let plain = compute_score(100, 0, 0, &fresh_hints()).0;
        let boosted = compute_score(
            100,
            0,
            0,
            &SourceHints {
                signed: true,
                curated: true,
                age_days: 0,
                fetched_at_ms: 0,
            },
        )
        .0;
        assert!(
            boosted >= plain,
            "curated+signed never lowers a clean score"
        );
    }

    #[test]
    fn stale_list_scores_no_higher_than_fresh() {
        let fresh = compute_score(100, 0, 0, &fresh_hints()).0;
        let old = compute_score(
            100,
            0,
            0,
            &SourceHints {
                signed: false,
                curated: false,
                age_days: 800,
                fetched_at_ms: 0,
            },
        )
        .0;
        assert!(
            old <= fresh,
            "an old list is trusted no more than a fresh one"
        );
    }

    #[test]
    fn band_edges_are_exact() {
        assert_eq!(band_for(100), SafetyBand::Safe);
        assert_eq!(band_for(SAFE_FLOOR), SafetyBand::Safe);
        assert_eq!(band_for(SAFE_FLOOR - 1), SafetyBand::Caution);
        assert_eq!(band_for(CAUTION_FLOOR), SafetyBand::Caution);
        assert_eq!(band_for(CAUTION_FLOOR - 1), SafetyBand::Risky);
        assert_eq!(band_for(0), SafetyBand::Risky);
    }

    #[test]
    fn cache_round_trips_through_durable_tier() {
        let dir = temp_dir("rt");
        {
            let e = GithubTrustEngine::new(dir.clone());
            let mut s = e.investigate_bytes(
                "poison".into(),
                "https://x/poison".into(),
                GOOGLEAPIS_LIST.to_vec(),
                fresh_hints(),
            );
            assert!(
                e.arm("https://x/poison".into(), true),
                "arming a cached source succeeds"
            );
            s.armed = true;
            assert_eq!(e.cached_count(), 1);
        }
        // A FRESH engine over the SAME dir rehydrates the armed, scored source from NAND.
        let reborn = GithubTrustEngine::new(dir);
        assert_eq!(reborn.cached_count(), 1, "the cache survives a reboot");
        let got = reborn
            .cached_for("https://x/poison".into())
            .expect("rehydrated");
        assert_eq!(got.band, SafetyBand::Risky);
        assert_eq!(got.cdn_overlap, 5);
        assert!(got.armed, "the armed flag survived the round-trip");
    }

    #[test]
    fn decode_of_garbage_is_empty_not_panic() {
        assert!(decode_cache(b"").is_empty());
        assert!(decode_cache(b"NOPE").is_empty());
        assert!(
            decode_cache(b"GTC1\xff\xff\xff\xff").is_empty(),
            "absurd count → fail-safe empty"
        );
    }

    #[test]
    fn arming_unknown_source_returns_false() {
        let e = GithubTrustEngine::new(temp_dir("arm0"));
        assert!(!e.arm("https://never/seen".into(), true));
    }

    #[test]
    fn search_query_url_is_unauthenticated_and_encoded() {
        let e = GithubTrustEngine::new(temp_dir("url"));
        let u = e.search_query_url("ad block list".into());
        assert!(u.starts_with("https://api.github.com/search/repositories?q="));
        assert!(u.contains("ad+block+list"), "spaces become +");
        assert!(
            !u.to_lowercase().contains("token"),
            "Fork #5 — ship NO API key"
        );
        assert!(!u.contains("access_token"));
    }

    /// A per-test scratch dir under the cargo target tmp (host-only, no network).
    fn temp_dir(tag: &str) -> String {
        let mut d = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or(0);
        d.push(format!("torta-trust-crown-{tag}-{nanos}"));
        let _ = std::fs::create_dir_all(&d);
        d.to_string_lossy().into_owned()
    }
}
