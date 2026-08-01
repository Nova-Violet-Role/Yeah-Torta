/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! #61B — **SIGNED LANE CATALOGS**: the Underground Layer's Centauri supply line.
//!
//! The Underground Layer is Socio's invention — born on nautilus-rs
//! (`nautilus-bin/src/underground.rs`), re-made inside Yeah Tortä as the full **DNS ANTIVIRUS
//! ENGINE** (antivirus + antimalware + anti-MITM / Arpa / Sonar / telegraphy / analytics).
//! Warden and Centauri are its BOUND organs. This module IS the Centauri half of that binding:
//! the four antivirus lanes (**ads / trackers-analytics / malware / phishing**) arrive ONLY as
//! minisign-signed `.tcat` catalogs, verified by the IDENTICAL
//! [`crate::mirror::Catalog::parse_verified`] gate the Centauri mirror itself trusts
//! (verify-sig-FIRST, fail-closed: a `Catalog` VALUE is proof the signature checked out), then
//! land in the SAME [`crate::blocklist::Matcher`] the resolver block-checks
//! (`resolver/mod.rs` step-1 → `blocklist::query_action` → NXDOMAIN synthesis) through the
//! provenance-preserving [`crate::blocklist::install_with_source`] — its first live caller — so
//! every blocked name remembers WHICH lane armed it, and the Warden half keeps taking genuine
//! `LaneDecision`s downstream (firewall outranks reputation, always).
//!
//! ## FELT-TRUTH LAWS (the Underground's non-negotiables, applied to supply)
//! - **verify-sig-FIRST, fail-closed** — a tampered/forged/absent signature installs NOTHING
//!   and counts NOTHING; the `GLOBAL` matcher is left untouched.
//! - **honest emptiness** — an absent on-disk pair is an EMPTY lane ([`LaneIngestFail::AbsentPair`]),
//!   never an error dressed up as data and never a fabricated count.
//! - **counters grow only on genuinely taken ingests** — [`lane_counts`] reports what verified
//!   catalogs REALLY installed; [`ingest_lane_catalog`] is the counters' ONLY writer.
//! - **offline-capable** — [`load_lanes_from_dir`] rehydrates from on-disk signed pairs
//!   (`<base>.tcat` + `<base>.tcat.sig`, the [`crate::read_signed_pair`] layout Centauri already
//!   persists), so the engine arms with ZERO network.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::blocklist::{self, trust};
use crate::github::fnv1a32;
use crate::mirror;

/// Uniform trust tier for signed Underground lane catalogs (a config judgment, not telemetry):
/// high enough to count as corroborating provenance, below a user's manual pin.
const LANE_TRUST: u8 = 80;

/// The four Underground antivirus lanes. Index order (everywhere a per-lane vector appears):
/// ads = 0, trackers-analytics = 1, malware = 2, phishing = 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UndergroundLane {
    Ads,
    TrackersAnalytics,
    Malware,
    Phishing,
}

impl UndergroundLane {
    pub const ALL: [UndergroundLane; 4] = [
        UndergroundLane::Ads,
        UndergroundLane::TrackersAnalytics,
        UndergroundLane::Malware,
        UndergroundLane::Phishing,
    ];

    /// Human slug — the registry label AND the FFI selector.
    pub fn slug(self) -> &'static str {
        match self {
            UndergroundLane::Ads => "ads",
            UndergroundLane::TrackersAnalytics => "trackers-analytics",
            UndergroundLane::Malware => "malware",
            UndergroundLane::Phishing => "phishing",
        }
    }

    pub fn from_slug(s: &str) -> Option<UndergroundLane> {
        Self::ALL.into_iter().find(|l| l.slug() == s)
    }

    /// On-disk catalog file name; the signed pair is `<this>` + `<this>.sig`
    /// (the [`crate::read_signed_pair`] naming law, `SIGNED_SIG_SUFFIX = ".sig"`).
    pub fn catalog_base(self) -> &'static str {
        match self {
            UndergroundLane::Ads => "underground_ads.tcat",
            UndergroundLane::TrackersAnalytics => "underground_trackers_analytics.tcat",
            UndergroundLane::Malware => "underground_malware.tcat",
            UndergroundLane::Phishing => "underground_phishing.tcat",
        }
    }

    /// Stable URN hashed into the opaque `source_id` — the SAME `fnv1a32` scheme the GitHub
    /// Trust Crown uses for list URLs (one scheme, no collision management).
    fn urn(self) -> &'static str {
        match self {
            UndergroundLane::Ads => "torta:underground:lane:ads",
            UndergroundLane::TrackersAnalytics => "torta:underground:lane:trackers-analytics",
            UndergroundLane::Malware => "torta:underground:lane:malware",
            UndergroundLane::Phishing => "torta:underground:lane:phishing",
        }
    }

    /// The lane's stable opaque `source_id` (joins the blocklist `Matcher.sources` bitset).
    pub fn source_id(self) -> u32 {
        fnv1a32(self.urn())
    }

    fn index(self) -> usize {
        match self {
            UndergroundLane::Ads => 0,
            UndergroundLane::TrackersAnalytics => 1,
            UndergroundLane::Malware => 2,
            UndergroundLane::Phishing => 3,
        }
    }
}

/// One GENUINELY TAKEN lane ingest — constructed only after the signature verified AND the set
/// installed (there is no other constructor path; FELT-TRUTH by type).
#[derive(Clone, Copy, Debug)]
pub struct LaneIngest {
    pub lane: UndergroundLane,
    /// Domains THIS lane's verified catalog carries (the lane matcher's own post-normalize count).
    pub domains: usize,
    /// Fingerprint of the WHOLE installed set after this ingest (the SET oracle, not per-lane).
    pub fingerprint: u64,
}

/// Why a lane did NOT ingest — the fail-closed taxonomy (mirrors `CentauriRehydrateFail`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneIngestFail {
    /// No `<base>` + `<base>.sig` pair on disk — an HONESTLY EMPTY lane (cold start), not an attack.
    AbsentPair,
    /// The minisign gate refused (tampered/forged/wrong key) — NOTHING was installed.
    BadSignature,
    /// Signature verified but the body would not parse (a producer bug, never an attack — the
    /// body is already authenticated).
    Malformed,
}

/// Per-lane domain counts, index order = [`UndergroundLane::index`]. Written ONLY by
/// [`ingest_lane_catalog`] on genuine success — the FELT-TRUTH counter law.
static LANE_DOMAINS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Verify-sig-FIRST ingest of ONE lane catalog into the live matcher.
///
/// Order of operations (each step gated on the previous):
/// 1. [`mirror::Catalog::parse_verified`] — the minisign gate over the RAW `.tcat` bytes; any
///    refusal returns fail-closed with the `GLOBAL` matcher untouched.
/// 2. Register the lane's [`trust::SourceMeta`] (slug label, [`LANE_TRUST`], `signed = true`) so
///    the mask bit stays explainable.
/// 3. Build the lane's set through the public [`blocklist::Matcher`] API (normalize + prune +
///    fingerprint parity with the text path), then install through the provenance-preserving
///    [`blocklist::install_with_source`] (`merge = true` stacks onto the user's lists).
/// 4. Record the lane counter — the genuinely taken ingest is its ONLY writer.
pub fn ingest_lane_catalog(
    lane: UndergroundLane,
    tcat: &[u8],
    sig: &[u8],
    pubkey: &[u8],
    merge: bool,
    now_days: u32,
) -> Result<LaneIngest, LaneIngestFail> {
    let cat = mirror::Catalog::parse_verified(tcat, sig, pubkey).map_err(|e| match e {
        mirror::CatalogError::BadSignature => LaneIngestFail::BadSignature,
        // A retired-algorithm catalog is REJECTED exactly as hard as a malformed one; only the
        // reported reason collapses here, because widening `LaneIngestFail` would cascade into the
        // Kotlin bindings for a diagnostic. The finer reason stays observable through
        // `mirror::catalog::legacy_algo_rejections()`.
        mirror::CatalogError::LegacyHashAlgo | mirror::CatalogError::Malformed => {
            LaneIngestFail::Malformed
        }
    })?;

    // Identity BEFORE set: bind the lane's mask bit to an explainable, signed SourceMeta.
    //
    // The ingest moment IS the source's last-seen day, so it is recorded here rather than left at
    // the "unknown" default that made every lane read as maximally stale to `recency_pct`. It is
    // MEASURED, not invented: `now_days` is injected by the caller exactly like every other
    // trust-scoring surface in this crate (`domain_provenance`, `list_trust_of`), so a test can
    // drive the clock and the engine never reaches for a wall clock of its own.
    //
    // `first_seen` is PRESERVED across re-ingests: a lane re-downloaded next week is the same
    // source first seen last week, and overwriting it would make every source look brand new at
    // every refresh -- which is the reading that quietly destroys recency as a signal.
    let first_seen = blocklist::source_first_seen(lane.source_id()).unwrap_or(now_days);
    blocklist::register_source_meta(
        trust::SourceMeta::new(lane.source_id(), LANE_TRUST, lane.slug())
            .with_signed(true)
            .with_seen(first_seen, now_days),
    );

    let mut m = blocklist::Matcher::new();
    for e in cat.entries() {
        m.insert(&e.host);
    }
    m.finalize();
    let domains = m.count();
    let (_total, fingerprint) = blocklist::install_with_source(m, lane.source_id(), merge);

    LANE_DOMAINS[lane.index()].store(domains as u64, Ordering::Relaxed);
    Ok(LaneIngest {
        lane,
        domains,
        fingerprint,
    })
}

/// OFFLINE rehydrate: arm every lane whose signed pair exists on disk (`merge = true` — lanes
/// stack onto each other and onto the user's lists). Absent pair ⇒ [`LaneIngestFail::AbsentPair`]
/// (an honestly empty lane); a refused signature stays refused — NOTHING silently degrades.
pub fn load_lanes_from_dir(
    dir: &std::path::Path,
    pubkey: &[u8],
    now_days: u32,
) -> Vec<(UndergroundLane, Result<LaneIngest, LaneIngestFail>)> {
    UndergroundLane::ALL
        .into_iter()
        .map(
            |lane| match crate::read_signed_pair(dir, lane.catalog_base()) {
                None => (lane, Err(LaneIngestFail::AbsentPair)),
                Some((tcat, sig)) => (
                    lane,
                    ingest_lane_catalog(lane, &tcat, &sig, pubkey, true, now_days),
                ),
            },
        )
        .collect()
}

/// Truthful per-lane domain counts, index order ads / trackers-analytics / malware / phishing.
/// Reads the counters [`ingest_lane_catalog`] alone writes — never derived, never fabricated.
pub fn lane_counts() -> [u64; 4] {
    [
        LANE_DOMAINS[0].load(Ordering::Relaxed),
        LANE_DOMAINS[1].load(Ordering::Relaxed),
        LANE_DOMAINS[2].load(Ordering::Relaxed),
        LANE_DOMAINS[3].load(Ordering::Relaxed),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::GLOBAL_TEST_LOCK;
    use crate::mirror::{encode_catalog, CatalogEntry};
    use ed25519_dalek::{Signer, SigningKey};

    /// A fixed ingest day. The clock is INJECTED, so these tests never depend on the wall clock and
    /// a recency assertion cannot drift into failing overnight.
    const TEST_DAY: u32 = 20_000;

    // ---- minisign blob helpers (mirror/catalog.rs test vectors EXACTLY — the legacy `Ed` shape) ----

    const TEST_KEY_ID: [u8; 8] = [0x61, 0xB5, 0x1A, 0x4E, 0x5D, 0x6C, 0x7B, 0x8A];

    fn make_pubkey_blob(pk: &[u8; 32], key_id: &[u8; 8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(42);
        v.extend_from_slice(b"Ed");
        v.extend_from_slice(key_id);
        v.extend_from_slice(pk);
        v
    }

    fn sign_legacy(sk: &SigningKey, key_id: &[u8; 8], bytes: &[u8]) -> Vec<u8> {
        let sig = sk.sign(bytes);
        let mut v = Vec::with_capacity(74);
        v.extend_from_slice(b"Ed");
        v.extend_from_slice(key_id);
        v.extend_from_slice(&sig.to_bytes());
        v
    }

    fn signed(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Deterministic TEST key — NEVER a production key (that one is offline, Centauri-side).
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        (
            sign_legacy(&sk, &TEST_KEY_ID, bytes),
            make_pubkey_blob(&pk, &TEST_KEY_ID),
        )
    }

    /// A lane `.tcat` whose entry HOSTS are the blocked domains — ONE encoder
    /// ([`encode_catalog`], the production author), so the byte layout can never drift.
    fn lane_catalog(hosts: &[&str]) -> Vec<u8> {
        let entries: Vec<CatalogEntry> = hosts
            .iter()
            .map(|h| CatalogEntry {
                name: format!("{h}-row"),
                host: (*h).to_string(),
                content_hash: [0u8; 32],
                cloaked: false,
            })
            .collect();
        encode_catalog(&entries, 1_784_000_000) // pinned epoch — deterministic test bytes
    }

    #[test]
    fn slug_and_source_id_are_stable_and_distinct() {
        let mut ids = Vec::new();
        for lane in UndergroundLane::ALL {
            assert_eq!(UndergroundLane::from_slug(lane.slug()), Some(lane));
            ids.push(lane.source_id());
        }
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 4, "four lanes, four distinct source_ids");
        assert_eq!(UndergroundLane::from_slug("innocent-slug"), None);
    }

    #[test]
    fn verified_catalog_arms_the_lane_truthfully() {
        let _g = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tcat = lane_catalog(&["61b-ads-one.example", "61b-ads-two.example"]);
        let (sig, pubkey) = signed(&tcat);

        let got = ingest_lane_catalog(UndergroundLane::Ads, &tcat, &sig, &pubkey, true, TEST_DAY)
            .expect("genuine signature must ingest");
        assert_eq!(
            got.domains, 2,
            "the lane matcher's own count — nothing invented"
        );
        assert_eq!(
            lane_counts()[0],
            2,
            "ads counter = the genuinely taken ingest"
        );
        assert!(blocklist::query("61b-ads-one.example"));
        assert!(
            blocklist::query("deep.sub.61b-ads-two.example"),
            "suffix cover — the SAME matcher law as every other list"
        );
        // Provenance: the terminal remembers WHICH lane armed it.
        let mask = blocklist::with_global(|m| {
            m.expect("matcher armed").source_mask("61b-ads-one.example")
        });
        assert!(
            trust::SourceRegistry::corroboration(mask) >= 1,
            "the lane's source bit rides the terminal"
        );
    }

    #[test]
    fn tampered_signature_fails_closed_and_counts_nothing() {
        let _g = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tcat = lane_catalog(&["61b-malware-fixture.example"]);
        let (mut sig, pubkey) = signed(&tcat);
        let last = sig.len() - 1;
        sig[last] ^= 0x01; // one flipped bit — the whole catalog is refused

        let got = ingest_lane_catalog(
            UndergroundLane::Malware,
            &tcat,
            &sig,
            &pubkey,
            true,
            TEST_DAY,
        );
        assert_eq!(got.unwrap_err(), LaneIngestFail::BadSignature);
        assert_eq!(lane_counts()[2], 0, "refused ingest counts NOTHING");
        assert!(
            !blocklist::query("61b-malware-fixture.example"),
            "fail-closed: nothing installed"
        );
    }

    #[test]
    fn absent_dir_leaves_every_lane_honestly_empty() {
        let dir = std::env::temp_dir().join("torta-61b-absent-lane-catalogs");
        let _ = std::fs::create_dir_all(&dir);
        let (_, pubkey) = signed(b"unused");
        for (_, r) in load_lanes_from_dir(&dir, &pubkey, TEST_DAY) {
            assert_eq!(r.unwrap_err(), LaneIngestFail::AbsentPair);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn on_disk_signed_pair_rehydrates_offline() {
        let _g = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("torta-61b-pair-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mk temp dir");

        let tcat = lane_catalog(&["61b-phishing-fixture.example"]);
        let (sig, pubkey) = signed(&tcat);
        let base = UndergroundLane::Phishing.catalog_base();
        std::fs::write(dir.join(base), &tcat).expect("write tcat");
        std::fs::write(dir.join(format!("{base}.sig")), &sig).expect("write sig sidecar");

        let got = load_lanes_from_dir(&dir, &pubkey, TEST_DAY);
        for (lane, r) in got {
            if lane == UndergroundLane::Phishing {
                let ok = r.expect("signed pair on disk must rehydrate");
                assert_eq!(ok.domains, 1);
                assert_eq!(lane_counts()[3], 1);
            } else {
                assert_eq!(r.unwrap_err(), LaneIngestFail::AbsentPair);
            }
        }
        assert!(blocklist::query("61b-phishing-fixture.example"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
