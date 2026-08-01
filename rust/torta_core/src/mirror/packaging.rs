/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Centauri Local Mirror — the **RESOURCE-PACKAGING POLICY** (#134 slice 4 · the size decision, made code).
//!
//! ## The decision (surfaced, not buried): the warm seed is an AUTHORITY, never a payload
//! LocalCDN ships its whole `resources/` asset tree in the extension XPI — **73 MiB / 1891 files**
//! ([`LOCALCDN_SEED_TREE_BYTES`]). Centauri does NOT. The seed Centauri ships is the signed **catalog of
//! content hashes** (a few KiB) plus the `(host, path, version)` map ([`super::localcdn_maps::FULL_MAPS`],
//! ~300 KiB of `&'static` data) — and the device **self-fills its own cache** on demand from the real CDNs,
//! ONE verified request per asset, EVER (the privacy flow, [`super::serve`]). The seed is an *authority that
//! the device verifies its self-filled bytes against* — strictly stronger than LocalCDN, which ships bytes
//! with **no per-serve content-address check**. So a few KiB buys the crown that 73 MiB of unverified bytes
//! could not.
//!
//! ## Three tiers (the [`SeedPolicy`] enum is the honest decision surface)
//! - **TIER A — `CatalogOnly` (the shipped DEFAULT):** ship ZERO asset bytes. A genuine miss self-fills with
//!   the one allowed CDN request (`LeakOnMiss`), or serves-nothing in strict mode (`BlockMissing` → CDN sees
//!   0). APK asset-byte delta = **0**. Out-of-box: ≤ 1 CDN request EVER per asset; 0 in strict.
//! - **TIER B — `WarmUpBatch` (designed now, opt-in):** [`warm_up`] self-fills a CURATED top-N list on the
//!   user's OWN device (each ≤ 1 request, honoring the privacy flow). The "warm seed" is thus a self-fill
//!   BATCH, not shipped bytes — still 0 APK weight, still 0 distribution attribution (the device fetched from
//!   the real CDN, like any browser cache would).
//! - **TIER C — `BundledSeed` (DEFERRED — not this wave):** a curated subset of asset bytes bundled in the
//!   APK. The ONLY policy that ships library bytes ([`SeedPolicy::ships_asset_bytes`]) — so the ONLY one that
//!   triggers the full bundled-library attribution chain (jQuery MIT · Bootstrap MIT · Font Awesome OFL/MIT ·
//!   MathJax Apache-2.0 · the THIRD_PARTY roster). Bundling 73 MiB silently is forbidden (the overhaul LAW);
//!   a curated TIER-C subset is a future wave's explicit decision, with its attribution chain wired then.
//!
//! ## The F9 curation guard (`is_packageable` — kills the cloak-without-coverage blackhole)
//! A cloaked CDN host resolves to the loopback; if its asset is NOT servable locally the request 404-
//! blackholes (cloaked away from the real CDN AND not served from device — *worse* than a leak, Chroma F9).
//! The sharpest blackhole is an oversized asset: an asset above [`MAX_PACKAGEABLE_BYTES`] fails
//! [`super::fetch::fetch_once`]'s `TooLarge` cap (`cache.rs` `MAX_ASSET_BYTES`) mid-stream, so it can never be
//! self-filled. [`is_packageable`] is the curation predicate the catalog author + the warm-up batch apply so
//! such an asset is EXCLUDED from the cloak/catalog set up front (it falls through to the real CDN, a one-
//! request leak, instead of blackholing). `MAX_PACKAGEABLE_BYTES == MAX_ASSET_BYTES` by construction so a
//! packaged/cloaked asset is ALWAYS fetchable — the curation cap and the fetch cap can never drift apart.
//!
//! ## STUDY-NOT-COPY
//! The mapping DATA ([`super::localcdn_maps`]) is a table of public, factual data points (CDN hosts, URL
//! base-paths, library + version strings) studied from the LocalCDN corpus and re-expressed as our own
//! `ResourceMap` Rust table — no source file is copied. The SERVE LOGIC (the resolver, the version ladder,
//! this packaging policy) is original clean-room Rust. No LocalCDN asset BYTES ship under the default TIER A,
//! so the bundled-library attribution chain does not attach this wave (it is gated to TIER C). The studied
//! lineage is credited in the root `NOTICE.md` (§C "The Centauri Local Mirror — provenance").
//!
//! Pure logic + an async batch driver; loopback-only, no-root, `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use super::cache::{CacheStore, ContentHash, MAX_ASSET_BYTES};
use super::catalog::Catalog;
use super::serve::{serve_name_private, CacheMode, InFlight, ServeVerdict};

/// The on-disk size of LocalCDN's full `resources/` asset tree (1891 files) — the seed Centauri DECLINES to
/// bundle under TIER A. Recorded as a constant so the size decision is explicit in code, not folklore:
/// shipping this would ~double a lean DNS APK AND drag the full THIRD_PARTY (jQuery/Bootstrap/MathJax/Font-
/// Awesome) attribution chain. TIER A ships **0** of it; the device self-fills on demand (≤ 1 CDN request
/// EVER per asset). The number is the measured corpus size (`localcdn/resources/`), kept for the dashboard's
/// "saved N MiB of APK weight" honesty + the test that pins it well above the per-asset cap.
pub const LOCALCDN_SEED_TREE_BYTES: u64 = 73 * 1024 * 1024;

/// The per-asset packaging ceiling — an asset larger than this is EXCLUDED from the catalog/cloak set.
///
/// Bound to [`MAX_ASSET_BYTES`] (the fetch leg's `TooLarge` cap) **by construction** so the curation cap and
/// the fetch cap can NEVER drift apart: a packaged/cloaked asset is therefore always self-fillable. An asset
/// above this ceiling would fail [`super::fetch::fetch_once`] mid-stream and, under a DNS cloak, 404-blackhole
/// (Chroma F9) — so it must never be cloaked; [`is_packageable`] excludes it.
pub const MAX_PACKAGEABLE_BYTES: usize = MAX_ASSET_BYTES;

/// The resource-packaging decision — WHICH asset bytes (if any) ship in the APK. The typed surface for the
/// size call (the UI/UniFFI slices expose this; the datapath default is [`SeedPolicy::CatalogOnly`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SeedPolicy {
    /// TIER A (the shipped default): ship ZERO asset bytes; self-fill on demand. APK asset delta = 0.
    #[default]
    CatalogOnly,
    /// TIER B (designed now, opt-in): a curated top-N self-fill BATCH on the user's OWN device ([`warm_up`]).
    /// Ships no bytes (the device fetches from the real CDN, like a browser cache) — still 0 APK weight.
    WarmUpBatch,
    /// TIER C (DEFERRED — not this wave): a curated subset of asset bytes bundled in the APK. The ONLY policy
    /// that ships library bytes, so the ONLY one that triggers the bundled-library attribution chain.
    BundledSeed,
}

impl SeedPolicy {
    /// `true` iff this policy ships library ASSET BYTES in the APK (only [`SeedPolicy::BundledSeed`]). This is
    /// the trigger for the full bundled-library attribution chain (jQuery MIT · Bootstrap MIT · Font Awesome
    /// OFL/MIT · MathJax Apache-2.0). The shipped default `CatalogOnly` and the opt-in `WarmUpBatch` ship 0.
    pub fn ships_asset_bytes(self) -> bool {
        matches!(self, SeedPolicy::BundledSeed)
    }
}

/// The F9 curation guard: an asset is packageable (catalog-/cloak-eligible) ONLY if it fits the fetch cap.
///
/// An asset larger than [`MAX_PACKAGEABLE_BYTES`] would fail [`super::fetch::fetch_once`]'s `TooLarge` cap and,
/// once its host is cloaked to the loopback, 404-blackhole (cloaked away from the real CDN AND not servable
/// locally — Chroma F9). Curation excludes it so the request falls through to the real CDN (a one-request
/// leak) instead of blackholing. The catalog author applies this off-device; the [`warm_up`] batch + any
/// runtime cloak-eligibility check apply it on-device. A zero-length asset is packageable (its hash is well
/// defined). Equality with the cap is INCLUSIVE (an exactly-`MAX` asset still fetches).
pub fn is_packageable(asset_bytes: usize) -> bool {
    asset_bytes <= MAX_PACKAGEABLE_BYTES
}

/// ★ #22 slice 2 — the multi-CDN failover ladder bound: at most this many ALTERNATE upstreams ride
/// behind a target's primary URL. The privacy honesty: each rung tried is one more host that learns
/// of interest in the asset — so the ladder is short, walked ONLY on transport failure (a success
/// stops it dead), and every rung stays hash-gated (the BLAKE2b content address is the authority,
/// so a hostile alternate CDN can serve nothing that isn't the pinned bytes — fail-closed).
pub const MAX_ALT_UPSTREAMS: usize = 2;

/// One TIER-B warm-up target: a catalog asset NAME (`<library>/<served_version>/<file>`, the catalog key the
/// sig gate resolves) plus the upstream URL to self-fill it from (the one allowed leak — build it with
/// [`super::serve::upstream_url`]). The name is host-independent; the url names the real CDN to fetch once.
///
/// ★ #22 slice 2 — `alt_urls` is the multi-CDN failover ladder: the SAME `<version>/<file>` on other
/// mapped CDN hosts carrying the library, tried in order ONLY when the rung above fails at transport
/// (see [`fetch_via_ladder`]). Cross-CDN substitution is safe by construction: whichever host answers,
/// only bytes matching the signed catalog's content address are ever cached or served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WarmUpTarget {
    /// The canonical catalog name (`<library>/<served_version>/<file>`) — the sig-gate lookup key.
    pub name: String,
    /// The catalog-pinned upstream `https://…` URL to self-fill the one allowed request from.
    pub url: String,
    /// Alternate upstream `https://…` URLs on OTHER mapped CDN hosts (≤ [`MAX_ALT_UPSTREAMS`]),
    /// primary-first ladder order. Empty = single-CDN target (the pre-slice-2 shape, still valid).
    pub alt_urls: Vec<String>,
}

impl WarmUpTarget {
    /// Build a single-CDN target from its catalog name + upstream url (no alternates).
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        WarmUpTarget {
            name: name.into(),
            url: url.into(),
            alt_urls: Vec::new(),
        }
    }

    /// ★ #22 slice 2 — build a multi-CDN target: primary url + the failover ladder (the caller is
    /// trusted to have capped `alt_urls` at [`MAX_ALT_UPSTREAMS`]; the ctor re-truncates defensively
    /// so a wider list can never widen the who-learns privacy surface).
    pub fn with_alternates(
        name: impl Into<String>,
        url: impl Into<String>,
        mut alt_urls: Vec<String>,
    ) -> Self {
        alt_urls.truncate(MAX_ALT_UPSTREAMS);
        WarmUpTarget {
            name: name.into(),
            url: url.into(),
            alt_urls,
        }
    }

    /// The full ladder in try-order: primary first, then each alternate.
    pub fn ladder(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.url.as_str()).chain(self.alt_urls.iter().map(String::as_str))
    }
}

/// ★ #22 slice 2 — walk a target's upstream ladder: try each rung's URL with `fetch` until one
/// answers; a rung's transport failure moves to the next, exhaustion is the batch's `failed`. The
/// hash gate does NOT live here — `fetch` itself is hash-gated (`fetch_leg` verifies the content
/// address before returning bytes), so a rung that answers WRONG bytes is a failed rung, and the
/// ladder correctly tries the next host for the REAL pinned content. Pure combinator (no sockets):
/// unit-testable with a closure, exactly the [`warm_up`] fetch-shape one level down.
pub async fn fetch_via_ladder<'t, F, Fut>(
    target: &'t WarmUpTarget,
    hash: ContentHash,
    mut fetch: F,
) -> Result<Vec<u8>, ()>
where
    F: FnMut(&'t str, ContentHash) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, ()>>,
{
    for url in target.ladder() {
        if let Ok(bytes) = fetch(url, hash).await {
            return Ok(bytes);
        }
    }
    Err(())
}

/// The TIER-B warm-up summary — the curated batch result, the CROWN made warmable WITHOUT shipped bytes.
///
/// `cdn_requests() == filled`: the only CDN requests a warm-up makes are the assets it self-fills, each
/// exactly once; every filled asset is then 0 CDN forever. `already_cached` + `not_in_catalog` cost 0 CDN.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WarmUpReport {
    /// Targets attempted.
    pub targets: u32,
    /// Already in the cache before the batch — served locally, 0 CDN (e.g. a duplicate target after the first).
    pub already_cached: u32,
    /// Self-filled with the one allowed CDN request, then cached + serveable.
    pub filled: u32,
    /// Skipped: the signed catalog does not authorize this name (sig gate) — 0 CDN, nothing fetched.
    pub not_in_catalog: u32,
    /// The one fetch failed (transport / oversize past [`MAX_PACKAGEABLE_BYTES`] / hash mismatch) — fail-
    /// closed, nothing cached. A genuine retry is still ≤ 1 against the real asset.
    pub failed: u32,
}

impl WarmUpReport {
    /// The number of CDN requests this warm-up made — EXACTLY the assets it self-filled (each ≤ 1). The crown
    /// math: `cdn_requests == filled`, and every filled asset is then 0 CDN forever.
    pub fn cdn_requests(self) -> u32 {
        self.filled
    }
}

/// Run a TIER-B warm-up: self-fill a CURATED list of catalog assets on the user's OWN device, honoring the
/// privacy flow (the sig gate + single-flight ≤ 1). This is the "warm seed" reborn as a self-fill BATCH — no
/// shipped library bytes, so 0 APK weight + 0 distribution attribution (the device fetched from the real CDN,
/// exactly like a browser cache). It is the TIER-B mechanism the [`SeedPolicy::WarmUpBatch`] knob triggers.
///
/// Each target drives [`super::serve::serve_name_private`] ONCE; the `cache` + the single-flight `inflight`
/// coordinator are SHARED across the batch, so a duplicate name self-fills at most once (the second hits the
/// now-warm cache). The batch runs **serially** (CPU-gentle on the host bench — no parallel fetch storm); a
/// genuine miss self-fills, an already-cached or uncatalogued target costs 0 CDN.
///
/// The batch always runs in [`CacheMode::LeakOnMiss`] — its PURPOSE is to fill; a `BlockMissing` warm-up
/// would fetch nothing, which is a contradiction. (Strict mode is a SERVE-time posture, not a warm-up one.)
///
/// `fetch` is the injected per-target upstream leg — `FnMut(&WarmUpTarget, ContentHash) -> Future<Output =
/// Result<Vec<u8>, ()>>`. In production it is [`super::serve::fetch_leg`] bound to the target's `url` + the
/// shared ring-pinned TLS (the typed `FetchError` mapped to the flow's unit error); in tests it is a counting
/// fake that PROVES the ≤ 1 + the sig gate without a socket. It is invoked AT MOST ONCE per target, and only
/// on a genuine miss (a cache hit never calls it — 0 CDN).
///
/// Oversize curation: a target whose bytes exceed [`MAX_PACKAGEABLE_BYTES`] should be excluded up front via
/// [`is_packageable`]; if one slips through, its fetch is refused (`TooLarge`) and it is counted `failed`
/// (fail-closed) rather than blackholing — the runtime backstop to the curation guard.
pub async fn warm_up<F, Fut>(
    catalog: &Catalog,
    cache: &Arc<Mutex<CacheStore>>,
    inflight: &InFlight,
    targets: &[WarmUpTarget],
    mut fetch: F,
) -> WarmUpReport
where
    F: FnMut(&WarmUpTarget, ContentHash) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, ()>>,
{
    let mut report = WarmUpReport {
        targets: targets.len() as u32,
        ..Default::default()
    };
    for target in targets {
        let verdict = serve_name_private(
            catalog,
            cache,
            inflight,
            CacheMode::LeakOnMiss,
            &target.name,
            |hash| fetch(target, hash),
        )
        .await;
        match verdict {
            ServeVerdict::ServedLocal(_) => report.already_cached += 1,
            ServeVerdict::LeakedThenServed(_) => report.filled += 1,
            ServeVerdict::NotInCatalog => report.not_in_catalog += 1,
            // BlockedMissing is unreachable in LeakOnMiss; folded with FetchFailed defensively.
            ServeVerdict::FetchFailed | ServeVerdict::BlockedMissing => report.failed += 1,
        }
    }
    report
}

#[cfg(test)]
mod tests {
    //! Host-pure, network-FREE proofs of the packaging policy: the TIER-A default ships 0 bytes, the F9
    //! curation guard excludes oversize assets, and the TIER-B warm-up self-fills a curated batch honoring the
    //! sig gate + ≤ 1 (the upstream leg is an INJECTED counting fake — no socket).

    use super::*;
    use crate::mirror::cache::content_hash;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Drive an async body on a fresh current-thread runtime (the crate has no `rt-multi-thread` tokio
    /// feature; the warm-up is serial, so a current-thread runtime is exactly right + deterministic).
    fn block<Fut: Future>(f: Fut) -> Fut::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(f)
    }

    /// A fresh shared content cache.
    fn empty_cache() -> Arc<Mutex<CacheStore>> {
        Arc::new(Mutex::new(CacheStore::new()))
    }

    /// Build a genuinely-signed `TCAT` catalog naming each `(name, hash)` entry, run through the REAL
    /// verify-sig-FIRST [`Catalog::parse_verified`] — so the returned [`Catalog`] is signature-proof exactly
    /// like the on-device install path (the `serve.rs`/`localcdn.rs` test signer shape; no production key).
    fn signed_catalog(entries: &[(&str, ContentHash)]) -> Catalog {
        use ed25519_dalek::{Signer, SigningKey};
        const KEY_ID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        const HOST: &str = "ajax.googleapis.com";
        let mut body = Vec::new();
        body.extend_from_slice(b"TCAT"); // magic
        body.extend_from_slice(&1u16.to_le_bytes()); // version = 1
        body.push(2u8); // hash_algo_id = BLAKE2B
        body.push(0u8); // header flags
        body.extend_from_slice(&0u64.to_le_bytes()); // reserved (freshness epoch — must be 0 today)
        body.extend_from_slice(&(entries.len() as u32).to_le_bytes()); // entry_count
        body.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        for (name, hash) in entries {
            body.push(0u8); // entry_flags
            body.extend_from_slice(hash); // content_hash[32]
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(&(HOST.len() as u16).to_le_bytes());
            body.extend_from_slice(HOST.as_bytes());
        }
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let mut pubkey = Vec::with_capacity(42);
        pubkey.extend_from_slice(b"Ed");
        pubkey.extend_from_slice(&KEY_ID);
        pubkey.extend_from_slice(&pk);
        let sig = sk.sign(&body);
        let mut sig_blob = Vec::with_capacity(74);
        sig_blob.extend_from_slice(b"Ed");
        sig_blob.extend_from_slice(&KEY_ID);
        sig_blob.extend_from_slice(&sig.to_bytes());
        Catalog::parse_verified(&body, &sig_blob, &pubkey)
            .expect("a genuinely signed test catalog verifies + parses")
    }

    #[test]
    fn seed_policy_default_is_catalog_only() {
        // TIER A is the SHIPPED default — ship zero asset bytes, self-fill on demand.
        assert_eq!(SeedPolicy::default(), SeedPolicy::CatalogOnly);
    }

    #[test]
    fn only_bundled_seed_ships_asset_bytes() {
        // The attribution trigger: only the (deferred) TIER-C BundledSeed ships library bytes; the two shipped
        // policies ship 0, so the bundled-library THIRD_PARTY chain does NOT attach this wave.
        assert!(!SeedPolicy::CatalogOnly.ships_asset_bytes());
        assert!(!SeedPolicy::WarmUpBatch.ships_asset_bytes());
        assert!(SeedPolicy::BundledSeed.ships_asset_bytes());
    }

    #[test]
    fn packageable_cap_equals_the_fetch_cap() {
        // The F9 alignment: a packaged/cloaked asset is ALWAYS fetchable because the curation cap IS the fetch
        // cap — they can never drift apart.
        assert_eq!(MAX_PACKAGEABLE_BYTES, MAX_ASSET_BYTES);
    }

    #[test]
    fn is_packageable_excludes_oversize_assets() {
        // The F9 curation guard: at/under the cap is packageable; one byte over is excluded (would TooLarge-
        // blackhole under cloak → must fall through to the real CDN instead).
        assert!(is_packageable(0), "a zero-length asset is packageable");
        assert!(
            is_packageable(MAX_PACKAGEABLE_BYTES),
            "exactly the cap still fetches"
        );
        assert!(
            !is_packageable(MAX_PACKAGEABLE_BYTES + 1),
            "one byte over is excluded"
        );
    }

    #[test]
    fn declined_seed_tree_is_far_above_the_per_asset_cap() {
        // The size decision, pinned: the 73 MiB tree we DECLINE to bundle dwarfs the 8 MiB per-asset cap — it
        // is a whole-tree payload, never a single packageable asset. (Documents WHY TIER A self-fills.)
        assert!(LOCALCDN_SEED_TREE_BYTES > MAX_PACKAGEABLE_BYTES as u64);
        assert_eq!(LOCALCDN_SEED_TREE_BYTES, 73 * 1024 * 1024);
    }

    #[test]
    fn warm_up_self_fills_uncached_targets_once_each() {
        // TIER B: a curated batch of two uncached, catalogued assets self-fills each exactly once. cdn_requests
        // == filled == 2; the device now serves both at 0 CDN.
        let jq = b"// jQuery 3.7.1".to_vec();
        let bs = b"/* bootstrap 5.3.8 */".to_vec();
        let jq_h = content_hash(&jq);
        let bs_h = content_hash(&bs);
        let catalog = signed_catalog(&[
            ("jquery/3.7.1/jquery.min.js", jq_h),
            ("twitter-bootstrap/5.3.8/css/bootstrap.min.css", bs_h),
        ]);
        let cache = empty_cache();
        let inflight = InFlight::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let targets = vec![
            WarmUpTarget::new(
                "jquery/3.7.1/jquery.min.js",
                "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
            ),
            WarmUpTarget::new(
                "twitter-bootstrap/5.3.8/css/bootstrap.min.css",
                "https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.8/css/bootstrap.min.css",
            ),
        ];

        let report = block(warm_up(&catalog, &cache, &inflight, &targets, |t, _h| {
            let calls = Arc::clone(&calls);
            let bytes = if t.name.starts_with("jquery") {
                jq.clone()
            } else {
                bs.clone()
            };
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<Vec<u8>, ()>(bytes)
            }
        }));

        assert_eq!(report.targets, 2);
        assert_eq!(report.filled, 2);
        assert_eq!(report.already_cached, 0);
        assert_eq!(
            report.cdn_requests(),
            2,
            "cdn_requests == filled (the crown math)"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "exactly one fetch per uncached asset"
        );
        assert_eq!(
            cache.lock().unwrap().len(),
            2,
            "both assets warmed into the cache"
        );
    }

    #[test]
    fn warm_up_skips_already_cached_targets_zero_cdn() {
        // A pre-cached target costs 0 CDN — counted already_cached, the fetch leg never fires.
        let jq = b"// jQuery 3.7.1 prewarmed".to_vec();
        let jq_h = content_hash(&jq);
        let catalog = signed_catalog(&[("jquery/3.7.1/jquery.min.js", jq_h)]);
        let cache = empty_cache();
        cache.lock().unwrap().insert_verified(jq_h, jq.clone());
        let inflight = InFlight::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let targets = vec![WarmUpTarget::new(
            "jquery/3.7.1/jquery.min.js",
            "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
        )];

        let report = block(warm_up(&catalog, &cache, &inflight, &targets, |_t, _h| {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<Vec<u8>, ()>(Vec::new())
            }
        }));

        assert_eq!(report.already_cached, 1);
        assert_eq!(report.filled, 0);
        assert_eq!(report.cdn_requests(), 0);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a cached target makes 0 CDN requests"
        );
    }

    #[test]
    fn warm_up_skips_uncatalogued_targets_via_the_sig_gate() {
        // A target the signed catalog does not authorize is not_in_catalog — the sig gate blocks it before any
        // fetch (no unverified asset, no egress for an unknown name).
        let catalog = Catalog::default(); // authorizes nothing
        let cache = empty_cache();
        let inflight = InFlight::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let targets = vec![WarmUpTarget::new(
            "jquery/3.7.1/jquery.min.js",
            "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
        )];

        let report = block(warm_up(&catalog, &cache, &inflight, &targets, |_t, _h| {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<Vec<u8>, ()>(Vec::new())
            }
        }));

        assert_eq!(report.not_in_catalog, 1);
        assert_eq!(report.filled, 0);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the sig gate blocks an uncatalogued name"
        );
    }

    #[test]
    fn warm_up_counts_fetch_failures_fail_closed() {
        // A fetch that returns wrong bytes (or, in production, a TooLarge oversize) is rejected at the
        // insert_verified gate → counted failed, nothing cached (poison-proof, the runtime F9 backstop).
        let jq = b"// the REAL jquery".to_vec();
        let jq_h = content_hash(&jq);
        let catalog = signed_catalog(&[("jquery/3.7.1/jquery.min.js", jq_h)]);
        let cache = empty_cache();
        let inflight = InFlight::new();
        let targets = vec![WarmUpTarget::new(
            "jquery/3.7.1/jquery.min.js",
            "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
        )];

        let report = block(warm_up(
            &catalog,
            &cache,
            &inflight,
            &targets,
            |_t, _h| async move {
                // a substituted/oversized upstream — different bytes ⇒ different content address ⇒ rejected.
                Ok::<Vec<u8>, ()>(b"// EVIL substituted payload".to_vec())
            },
        ));

        assert_eq!(report.failed, 1);
        assert_eq!(report.filled, 0);
        assert!(
            cache.lock().unwrap().is_empty(),
            "a poisoned fetch caches nothing"
        );
    }

    #[test]
    fn warm_up_dedups_a_duplicate_target_to_one_fetch() {
        // The ≤ 1 across a batch: the SAME asset listed twice self-fills once (first), then hits the warmed
        // cache (second) — one CDN request total. cdn_requests == filled == 1.
        let jq = b"// jQuery 3.7.1 dup".to_vec();
        let jq_h = content_hash(&jq);
        let catalog = signed_catalog(&[("jquery/3.7.1/jquery.min.js", jq_h)]);
        let cache = empty_cache();
        let inflight = InFlight::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let one = WarmUpTarget::new(
            "jquery/3.7.1/jquery.min.js",
            "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
        );
        let targets = vec![one.clone(), one];

        let report = block(warm_up(&catalog, &cache, &inflight, &targets, |_t, _h| {
            let calls = Arc::clone(&calls);
            let bytes = jq.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<Vec<u8>, ()>(bytes)
            }
        }));

        assert_eq!(report.targets, 2);
        assert_eq!(report.filled, 1, "the first encounter self-fills");
        assert_eq!(
            report.already_cached, 1,
            "the duplicate hits the warmed cache"
        );
        assert_eq!(report.cdn_requests(), 1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "≤ 1 across the batch: one fetch for the duplicate"
        );
    }

    // ---- ★ #22 slice 2: the multi-CDN failover ladder (pure combinator, no sockets) ----

    #[test]
    fn ladder_stops_at_the_first_rung_that_answers() {
        // A healthy primary means the alternates are NEVER contacted — the privacy floor: success
        // widens the who-learns surface by zero hosts.
        let target = WarmUpTarget::with_alternates(
            "jquery/3.7.1/jquery.min.js",
            "https://primary.example/jq.js",
            vec![
                "https://alt-a.example/jq.js".to_string(),
                "https://alt-b.example/jq.js".to_string(),
            ],
        );
        let tried = std::cell::RefCell::new(Vec::new());
        let out = block(fetch_via_ladder(&target, [9u8; 32], |url, _h| {
            tried.borrow_mut().push(url.to_string());
            async { Ok::<Vec<u8>, ()>(vec![0xCA]) }
        }));
        assert_eq!(out, Ok(vec![0xCA]));
        assert_eq!(
            tried.into_inner(),
            vec!["https://primary.example/jq.js"],
            "one rung tried, zero alternates contacted"
        );
    }

    #[test]
    fn ladder_fails_over_to_the_next_cdn_and_exhaustion_is_err() {
        // Rung 1 dead, rung 2 answers ⇒ the batch still fills (the multi-CDN win). All rungs dead
        // ⇒ Err — the honest `failed`, never a fabricated fill.
        let target = WarmUpTarget::with_alternates(
            "jquery/3.7.1/jquery.min.js",
            "https://dead.example/jq.js",
            vec![
                "https://alive.example/jq.js".to_string(),
                "https://never-reached.example/jq.js".to_string(),
            ],
        );
        let tried = std::cell::RefCell::new(Vec::new());
        let out = block(fetch_via_ladder(&target, [9u8; 32], |url, _h| {
            tried.borrow_mut().push(url.to_string());
            let ok = url.contains("alive");
            async move {
                if ok {
                    Ok(vec![0xFE])
                } else {
                    Err(())
                }
            }
        }));
        assert_eq!(out, Ok(vec![0xFE]), "the second CDN rescues the fill");
        assert_eq!(
            tried.into_inner(),
            vec!["https://dead.example/jq.js", "https://alive.example/jq.js"],
            "walked in ladder order, stopped on success (rung 3 untouched)"
        );

        let all_dead = WarmUpTarget::with_alternates(
            "jquery/3.7.1/jquery.min.js",
            "https://dead-1.example/jq.js",
            vec!["https://dead-2.example/jq.js".to_string()],
        );
        let out = block(fetch_via_ladder(&all_dead, [9u8; 32], |_u, _h| async {
            Err::<Vec<u8>, ()>(())
        }));
        assert_eq!(out, Err(()), "exhaustion is an honest Err — the batch's `failed`");
    }

    #[test]
    fn with_alternates_re_truncates_past_the_privacy_cap() {
        // Defensive ctor law: a wider list can never widen the who-learns surface.
        let t = WarmUpTarget::with_alternates(
            "x/1/f.js",
            "https://p.example/f.js",
            (0..9).map(|i| format!("https://a{i}.example/f.js")).collect(),
        );
        assert_eq!(t.alt_urls.len(), MAX_ALT_UPSTREAMS);
        assert_eq!(t.ladder().count(), 1 + MAX_ALT_UPSTREAMS);
    }
}
