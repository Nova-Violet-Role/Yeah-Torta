/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Centauri Local Mirror — the **PRIVACY FLOW** (≤ 1 upstream request EVER per asset · slice 3).
//!
//! ## What this slice IS (the crown's serve-path guarantee, made literal)
//! The mirror's privacy property (`centauri-pillar.md`: "the CDN sees ≤ 1 request") is NOT a property of
//! any one file — it is a property of the SERVE ORDER. This module owns that order:
//!   1. **serve-from-cache FIRST** — a [`super::cache::CacheStore`] hit is served with ZERO CDN egress, and
//!      every serve is content-address GATED: the store only ever holds bytes whose BLAKE2b-256 equals their
//!      key (verified at insert — `cache.rs:80`/`cache.rs:290`), so a key hit is provably the catalog-pinned
//!      content WITHOUT a per-serve re-hash. LocalCDN does NO content-address check at all — we are stronger:
//!      the bytes matched their hash before they ever entered the store.
//!   2. **strict mode (the CROWN, opt-in)** — `BlockMissing` serves local-OR-nothing ⇒ the CDN sees **0**.
//!   3. **leak-on-miss (the safe default)** — a genuine miss self-fills with EXACTLY ONE upstream fetch
//!      ([`super::fetch::fetch_once`], `fetch.rs:78` — previously ORPHANED, Chroma F1; wired here via
//!      [`fetch_leg`]), hash-verifies it through the fail-closed cache gate, then serves + caches it. A
//!      subsequent request hits the cache ⇒ 0 CDN. So `≤ 1` upstream request EVER per asset.
//!
//! ## The keystone — single-flight (≤ 1 made literal under CONCURRENCY)
//! Serial fetch-once is already guaranteed by the never-evicting bounded cache (`cache.rs:311`): once an
//! asset is cached it is a [`super::cache::CacheLookup::Hit`] forever. But two CONCURRENT misses for the
//! SAME content address would each run `fetch_once` ⇒ **2** CDN requests ⇒ a broken crown (Chroma F1, second
//! cut: "there is no in-flight/dedup map in cache.rs"). [`InFlight`] is that missing piece: a per-content-
//! address single-flight coordinator (a keyed `tokio::sync::Mutex`) so the SECOND concurrent miss AWAITS the
//! first's fetch and then serves from the now-warm cache, rather than launching a parallel GET. `≤ 1` holds
//! under concurrency, not merely nominally.
//!
//! ## Fail-closed throughout (no unverified asset ever served — the sig gate)
//! [`serve_name_private`] is the sig-gated entry: ONLY the minisign-verified catalog
//! ([`super::catalog::Catalog::content_hash_for`], `catalog.rs:303`) maps a request name → a content
//! address. An unauthorized name is `NotInCatalog` and never touches the cache, the single-flight map, or
//! the network. A self-filled byte that does not hash to the catalog-pinned address is rejected at the
//! `insert_verified` gate (`cache.rs:302`, `ContentAddressMismatch`) ⇒ `FetchFailed`, never cached, never
//! served — a malicious/substituted CDN response can never poison the store (poison-proof self-fill).
//!
//! ## The mode toggle is INTERNAL here (slice 5 surfaces it)
//! [`CacheMode`] is the datapath bit (the `block-missing` semantics LocalCDN gates at `constants.js:141`,
//! default OFF). The UniFFI-bridged `CentauriCacheMode` + the dashboard counters (`served_locally`,
//! `cdn_fetches`) are the Venom slice-5 surface that maps onto this; this slice keeps the toggle a plain
//! internal enum so the privacy datapath is self-contained + host-testable.
//!
//! ## NO-BREAK + weight gate
//! Additive: the existing pure verdict fns ([`super::server::MirrorServer::serve_name`] /
//! `serve_cdn_url`) and the slice-2 host-aware route are UNCHANGED. The whole module is reached only through
//! the `mirror`-gated `mirror/mod.rs` (`lib.rs:84`), so a base Android `.so` (no `mirror`) compiles ZERO of
//! it and stays byte-identical (FIX-1 / Chroma F7). The fetch leg ([`fetch_leg`]) wraps the SAME base-dep
//! client stack `fetch_once` already uses — zero new deps, zero new features.
//!
//! Loopback-only, no-root, `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use super::cache::{CacheStore, ContentHash};
use super::catalog::Catalog;
use super::fetch::{fetch_once, FetchError};

/// Cache behaviour on a genuine miss — the CROWN opt-out toggle (the datapath twin of LocalCDN's
/// `block-missing`, default OFF, `constants.js:141`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CacheMode {
    /// SAFE DEFAULT: a genuine miss self-fills with EXACTLY ONE upstream fetch, then serves + caches it
    /// (≤ 1 CDN request EVER per asset). Matches upstream LocalCDN UX (block-missing OFF) — the asset still
    /// loads, the CDN just never sees it again.
    #[default]
    LeakOnMiss,
    /// STRICT (the crown): serve-local-OR-nothing ⇒ the CDN sees **0**. A miss serves nothing (no fetch
    /// leg); a cold asset is unreachable until it is warmed by other means. The user OPTS IN to this.
    BlockMissing,
}

/// The privacy-flow serve verdict — distinct from [`super::server::ServeOutcome`] (which carries the HTTP
/// bytes-or-status the loopback writes): this is the PRIVACY decision, naming WHY a serve cost 0 or ≤ 1 CDN
/// requests. The two served arms carry the verified bytes (content-address-checked by the store).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeVerdict {
    /// Cache hit — served from the device, the CDN saw 0 (the win). Bytes are content-address-verified,
    /// carried as the store's shared `Arc<[u8]>` — a zero-copy serve (D24), never a per-serve memcpy.
    ServedLocal(Arc<[u8]>),
    /// Miss in leak-on-miss mode — fetched ONCE (the ≤ 1), hash-verified, cached, served. Bytes verified,
    /// shared zero-copy from the store (D24).
    LeakedThenServed(Arc<[u8]>),
    /// Miss in strict mode — served NOTHING ⇒ the CDN saw 0 (the crown). No bytes, no egress.
    BlockedMissing,
    /// The request name is not authorized by the minisign-verified catalog (fail-closed). Never reaches the
    /// cache, the single-flight map, or the network.
    NotInCatalog,
    /// The one allowed upstream fetch failed (transport / oversize / hash-mismatch) — no bytes served,
    /// nothing cached (fail-closed). A retry is honest (the genuine asset was never obtained), still ≤ 1
    /// against the real asset.
    FetchFailed,
}

impl ServeVerdict {
    /// The served bytes for a verdict that produced an asset (`ServedLocal`/`LeakedThenServed`), else `None`.
    pub fn served_bytes(&self) -> Option<&[u8]> {
        match self {
            ServeVerdict::ServedLocal(b) | ServeVerdict::LeakedThenServed(b) => Some(&**b),
            _ => None,
        }
    }

    /// `true` iff this serve cost ZERO CDN requests (a local hit or a strict-mode block).
    pub fn is_zero_egress(&self) -> bool {
        matches!(
            self,
            ServeVerdict::ServedLocal(_) | ServeVerdict::BlockedMissing
        )
    }
}

/// The per-content-address single-flight coordinator — the keystone that makes `≤ 1` LITERAL under
/// concurrency (Chroma F1).
///
/// A keyed `tokio::sync::Mutex<()>` per in-flight content address: the first concurrent miss for an address
/// acquires the keyed lock and runs the one fetch; every other concurrent miss for the SAME address awaits
/// the keyed lock, then re-checks the cache (now warm) and serves WITHOUT a second upstream request. The map
/// is bounded by the live concurrent-miss set (and ultimately by the signed catalog, `cache.rs:63`
/// `MAX_ENTRIES`), and self-prunes a keyed lock the instant no caller still references it.
///
/// The map mutex is the std (sync) lock — held only for the O(1) map insert/lookup, NEVER across an `.await`
/// (the keyed `tokio::sync::Mutex` is the one held across the fetch await, which is exactly its purpose). A
/// poisoned map lock fails OPEN (`into_inner`) — a serve is never panicked by a coordinator-lock fault.
#[derive(Debug, Default)]
pub struct InFlight {
    locks: Mutex<HashMap<ContentHash, Arc<tokio::sync::Mutex<()>>>>,
}

impl InFlight {
    /// A fresh, empty single-flight coordinator.
    pub fn new() -> Self {
        InFlight {
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Get-or-create the keyed single-flight lock for `hash`. The returned `Arc` is the caller's reference;
    /// the map keeps its own, so a live keyed lock has `strong_count >= 2`. The map lock is held only for the
    /// O(1) entry insert — never across an await.
    fn slot(&self, hash: &ContentHash) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.locks.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(
            map.entry(*hash)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    /// Drop the keyed lock for `hash` IFF no other caller still references it — race-safe under the map lock.
    ///
    /// While the map lock is held, no other task can clone via [`InFlight::slot`] for the same key, so if the
    /// stored `Arc` is still the one we hold (`ptr_eq`) and only the map + our `held` reference it
    /// (`strong_count <= 2`), there is no concurrent waiter ⇒ remove it. Otherwise a waiter still holds a
    /// clone (`strong_count > 2`) ⇒ leave it; the LAST finisher prunes. A fresh miss simply re-creates the
    /// entry. Keeps the map bounded by the LIVE concurrent-miss set with zero correctness cost.
    fn prune(&self, hash: &ContentHash, held: &Arc<tokio::sync::Mutex<()>>) {
        let mut map = self.locks.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = map.get(hash) {
            if Arc::ptr_eq(existing, held) && Arc::strong_count(held) <= 2 {
                map.remove(hash);
            }
        }
    }

    /// The number of content addresses with a live keyed lock (the in-flight set size — a test/diag read).
    pub fn in_flight_len(&self) -> usize {
        self.locks.lock().map(|m| m.len()).unwrap_or(0)
    }
}

/// Read the verified bytes for a content address from the shared cache, cloning the store's shared
/// `Arc<[u8]>` handle (O(1), ZERO memcpy — D24) and dropping the lock immediately — the std cache guard is
/// NEVER held across an `.await` (the `await_holding_lock` discipline), and an up-to-8-MiB asset is no
/// longer copied under the lock. A poisoned cache lock fails OPEN (`into_inner`) — a serve is never
/// panicked by it.
fn cache_get(cache: &Arc<Mutex<CacheStore>>, hash: &ContentHash) -> Option<Arc<[u8]>> {
    let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
    guard.get(hash).map(super::cache::CacheEntry::bytes_arc)
}

/// Serve one ALREADY-AUTHORIZED content address through the privacy flow (`hash` MUST be a catalog-pinned
/// address — [`serve_name_private`] is the sig-gated front door that supplies it).
///
/// The serve ORDER is the privacy property:
///   1. **serve-from-cache FIRST** — a hit is `ServedLocal`, ZERO CDN egress, bytes content-address-verified.
///   2. **strict mode** — `BlockMissing` ⇒ `BlockedMissing` (the crown: CDN sees 0), no fetch leg.
///   3. **leak-on-miss** — single-flight (`inflight`) so concurrent misses for `hash` drive AT MOST ONE
///      `fetch`; the bytes are re-verified at the `insert_verified` gate (`cache.rs:290`) and only a content
///      match is cached + served (`LeakedThenServed`); a transport error, oversize, or hash-mismatch is
///      `FetchFailed` (fail-closed, nothing cached).
///
/// `fetch` is the injected upstream leg — `FnOnce(ContentHash) -> Future<Output = Result<Vec<u8>, ()>>`. In
/// production it is [`fetch_leg`] bound to the catalog-pinned URL + the shared ring-pinned TLS (mapped to the
/// unit error); in tests it is a counting fake that PROVES the ≤ 1 + single-flight without a socket. It is
/// called AT MOST ONCE per content address across all concurrent callers (the leader runs it; followers
/// re-hit the warmed cache and never call theirs).
pub async fn serve_addressed<F, Fut>(
    cache: &Arc<Mutex<CacheStore>>,
    inflight: &InFlight,
    mode: CacheMode,
    hash: ContentHash,
    fetch: F,
) -> ServeVerdict
where
    F: FnOnce(ContentHash) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, ()>>,
{
    // (1) serve-from-cache FIRST — 0 CDN egress; the store only holds content-address-verified bytes.
    if let Some(bytes) = cache_get(cache, &hash) {
        return ServeVerdict::ServedLocal(bytes);
    }
    // (2) strict mode (the CROWN): serve-local-OR-nothing ⇒ the CDN sees 0. No fetch leg, no egress.
    if mode == CacheMode::BlockMissing {
        return ServeVerdict::BlockedMissing;
    }
    // (3) leak-on-miss: single-flight fetch-ONCE. The keyed lock serializes concurrent misses for THIS
    //     address so only the leader fetches; followers await it then re-hit the warmed cache.
    let slot = inflight.slot(&hash);
    let verdict = {
        // The keyed `tokio::sync::Mutex` guard IS held across the fetch await — that is its purpose (the std
        // cache lock, by contrast, is never held across an await).
        let _guard = slot.lock().await;
        // Re-check under the keyed lock: a concurrent leader may have just filled the cache ⇒ serve, no
        // second fetch (the single-flight coalescing point — the ≤ 1 keystone).
        if let Some(bytes) = cache_get(cache, &hash) {
            ServeVerdict::ServedLocal(bytes)
        } else {
            match fetch(hash).await {
                Ok(fetched) => {
                    // verify-on-write: the store re-hashes the fetched bytes against the catalog-pinned
                    // `hash`; a mismatch (tampered/substituted upstream) is rejected fail-closed, never cached.
                    let stored = {
                        let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
                        guard.insert_verified(hash, fetched).is_some()
                    };
                    if stored {
                        // Serve the canonical STORED copy (content-address-verified), never the raw buffer.
                        match cache_get(cache, &hash) {
                            Some(bytes) => ServeVerdict::LeakedThenServed(bytes),
                            None => ServeVerdict::FetchFailed,
                        }
                    } else {
                        // Hash mismatch / store full ⇒ fail-closed: a poisoned fetch never serves.
                        ServeVerdict::FetchFailed
                    }
                }
                // Transport error / oversize ⇒ fail-closed, nothing cached.
                Err(()) => ServeVerdict::FetchFailed,
            }
        }
    };
    // Release the keyed lock for this address the instant no other caller references it (race-safe).
    inflight.prune(&hash, &slot);
    verdict
}

/// The sig-gated front door of the privacy flow: resolve a request `name` → its content address THROUGH the
/// minisign-verified catalog ([`Catalog::content_hash_for`], `catalog.rs:303`), then serve it through
/// [`serve_addressed`]. An unauthorized name is fail-closed `NotInCatalog` — it never touches the cache, the
/// single-flight map, or the network (no unverified asset is ever served, no egress for an unknown name).
pub async fn serve_name_private<F, Fut>(
    catalog: &Catalog,
    cache: &Arc<Mutex<CacheStore>>,
    inflight: &InFlight,
    mode: CacheMode,
    name: &str,
    fetch: F,
) -> ServeVerdict
where
    F: FnOnce(ContentHash) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, ()>>,
{
    // SIG-GATE — ONLY the minisign-verified catalog authorizes a name → content address.
    let hash = match catalog.content_hash_for(name) {
        Some(h) => h,
        None => return ServeVerdict::NotInCatalog,
    };
    serve_addressed(cache, inflight, mode, hash, fetch).await
}

/// The PRODUCTION fetch leg — bind the catalog-pinned upstream `url` + the shared ring-pinned `tls` to the
/// one allowed GET, hash-gated against `hash`. Wraps [`super::fetch::fetch_once`] (`fetch.rs:78`) so it is
/// REACHABLE from the serve path (it was orphaned — Chroma F1). The single-flight caller guarantees this runs
/// AT MOST ONCE per content address; the live serve maps the typed [`FetchError`] to the flow's unit error
/// (`.map_err(|_| ())`) at the call site (slice 6 logs the typed reason). The bytes returned are already
/// content-hash-verified by `fetch_once`, AND re-verified at the cache `insert_verified` gate — a double gate.
pub async fn fetch_leg(
    url: &str,
    hash: ContentHash,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Vec<u8>, FetchError> {
    fetch_once(url, &hash, tls).await
}

/// Reconstruct the catalog-pinned upstream URL for a resolved CDN asset — the ONE allowed leak target: the
/// SERVED version on the original CDN host (so a version-fallback fetches the bundled version's REAL bytes,
/// which then hash-match the signed catalog). `base_path` carries its trailing `/` (e.g. `/ajax/libs/jquery/`)
/// ⇒ `https://<host><base_path><served_version>/<file>`. https-only (re-enforced inside `fetch_once`).
pub fn upstream_url(host: &str, base_path: &str, served_version: &str, file: &str) -> String {
    format!("https://{host}{base_path}{served_version}/{file}")
}

/// The outcome of [`fetch_probe`] — a plain, FFI-free host-instrument report (no `rustls`, no `Arc<[u8]>` in
/// the signature) so a CLI caller prints it without pulling the mirror's client types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchProbeReport {
    /// `true` ONLY on a served arm (`LeakedThenServed`/`ServedLocal`) — the datapath obtained + served the
    /// content-address-verified bytes.
    pub ok: bool,
    /// The reached [`ServeVerdict`] as a stable label (`LeakedThenServed` / `ServedLocal` / `FetchFailed` /
    /// `BlockedMissing` / `NotInCatalog` / `BadHash`).
    pub verdict: &'static str,
    /// Bytes served on success (0 otherwise) — the witness that a REAL asset flowed back.
    pub served_len: usize,
    /// The 64-hex content address the fetch was pinned to (echoed for the audit line).
    pub expected_hex: String,
}

/// DEV/PROBE (not a shipped path): drive ONE real fetch-once through the live privacy datapath against a
/// genuine external CDN asset, pinned to a caller-supplied 64-hex BLAKE2b-256 content address. Proves the
/// #85 seam end-to-end with REAL egress — the shipped serve stays fail-closed (the seed catalog pins ZERO)
/// until a signed catalog carries real hashes; this instrument takes the pin DIRECTLY (never through the
/// catalog), so it does not widen the shipped trust surface. `rustls` stays internal (built here from the
/// shared ring-pinned config) so a CLI caller needs no TLS dep.
///
/// FAIL-CLOSED preserved: a hash-mismatch (the CDN changed the bytes) or a transport error is `FetchFailed`
/// with `ok = false` — the wrong bytes are never served, exactly like production.
pub async fn fetch_probe(url: &str, expected_hex: &str) -> FetchProbeReport {
    let expected = match super::cache::parse_hex_hash(expected_hex) {
        Some(h) => h,
        None => {
            return FetchProbeReport {
                ok: false,
                verdict: "BadHash",
                served_len: 0,
                expected_hex: expected_hex.to_string(),
            }
        }
    };
    let tls = Arc::new(crate::tls_shared::client_tls_config());
    let cache = Arc::new(Mutex::new(CacheStore::new()));
    let inflight = InFlight::new();
    let url_owned = url.to_string();
    let verdict = serve_addressed(
        &cache,
        &inflight,
        CacheMode::LeakOnMiss,
        expected,
        move |h| {
            let url = url_owned.clone();
            let tls = Arc::clone(&tls);
            async move { fetch_leg(&url, h, tls).await.map_err(|_| ()) }
        },
    )
    .await;
    let (ok, verdict, served_len) = match verdict {
        ServeVerdict::LeakedThenServed(b) => (true, "LeakedThenServed", b.len()),
        ServeVerdict::ServedLocal(b) => (true, "ServedLocal", b.len()),
        ServeVerdict::FetchFailed => (false, "FetchFailed", 0),
        ServeVerdict::BlockedMissing => (false, "BlockedMissing", 0),
        ServeVerdict::NotInCatalog => (false, "NotInCatalog", 0),
    };
    FetchProbeReport {
        ok,
        verdict,
        served_len,
        expected_hex: expected_hex.to_string(),
    }
}

#[cfg(test)]
mod tests {
    //! Host-pure, network-FREE proofs of the privacy flow: ≤ 1 CDN request (serial AND concurrent), the sig
    //! gate, the strict-mode crown (CDN sees 0), and fail-closed self-fill. The single-flight + cache-first
    //! ORDER is the proof surface; the upstream leg is an INJECTED counting fake (the real `fetch_once` is
    //! exercised type-level via [`fetch_leg`] on a cache-hit path that never opens a socket).

    use super::*;
    use crate::mirror::cache::content_hash;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Drive an async body to completion on a fresh current-thread runtime (the crate has NO
    /// `rt-multi-thread` tokio feature — `Cargo.toml:64` is `rt,net,time,sync,macros` — so concurrency is
    /// cooperative via `join!`, which is deterministic and exactly what the single-flight proof needs).
    fn block<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(f)
    }

    /// A shared content cache pre-seeded with `seed` assets (none by default).
    fn empty_cache() -> Arc<Mutex<CacheStore>> {
        Arc::new(Mutex::new(CacheStore::new()))
    }

    /// Build a genuinely-signed `TCAT` catalog naming each `(name, hash)` entry, run through the REAL
    /// verify-sig-FIRST [`Catalog::parse_verified`] — so the returned [`Catalog`] is signature-proof exactly
    /// like the on-device install path (the `catalog.rs`/`server.rs`/`object.rs` test signer; no production key).
    fn signed_catalog(entries: &[(&str, ContentHash)]) -> Catalog {
        use ed25519_dalek::{Signer, SigningKey};
        const KEY_ID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        const HOST: &str = "ajax.googleapis.com";
        let mut body = Vec::new();
        body.extend_from_slice(b"TCAT"); // magic
        body.extend_from_slice(&1u16.to_le_bytes()); // version = 1
        body.push(2u8); // hash_algo_id = BLAKE2B
        body.push(0u8); // header flags
        body.extend_from_slice(&0u64.to_le_bytes()); // reserved
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
    fn cache_mode_default_is_leak_on_miss() {
        // The SAFE default (matching upstream block-missing OFF) — strict is opt-in.
        assert_eq!(CacheMode::default(), CacheMode::LeakOnMiss);
    }

    #[test]
    fn serve_from_cache_first_is_zero_cdn() {
        // A cached asset is served from the device with ZERO CDN egress; the fetch leg is NEVER invoked.
        let bytes = b"// jQuery 3.7.1 cached".to_vec();
        let hash = content_hash(&bytes);
        let cache = empty_cache();
        cache.lock().unwrap().insert_verified(hash, bytes.clone());
        let inflight = InFlight::new();
        let calls = Arc::new(AtomicUsize::new(0));

        let verdict = block(serve_addressed(
            &cache,
            &inflight,
            CacheMode::LeakOnMiss,
            hash,
            {
                let calls = Arc::clone(&calls);
                move |_h| {
                    let calls = Arc::clone(&calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<Vec<u8>, ()>(Vec::new())
                    }
                }
            },
        ));

        assert_eq!(verdict, ServeVerdict::ServedLocal(bytes.clone().into()));
        assert!(verdict.is_zero_egress());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a cache hit makes ZERO CDN requests"
        );
        // per-serve content-address verify (stronger than LocalCDN's no-per-serve-check): served == its hash.
        assert_eq!(content_hash(verdict.served_bytes().unwrap()), hash);
    }

    #[test]
    fn miss_fetches_exactly_once_then_serves_forever_zero() {
        // Serial ≤ 1: an empty cache misses → fetch ONCE → cached + served; the SECOND request hits the cache
        // and the fetch count stays at 1 (the never-evicting bound makes "≤ 1 EVER" hold serially).
        let bytes = b"// jQuery 3.7.1 self-filled".to_vec();
        let hash = content_hash(&bytes);
        let cache = empty_cache();
        let inflight = InFlight::new();
        let calls = Arc::new(AtomicUsize::new(0));

        let first = block(serve_addressed(
            &cache,
            &inflight,
            CacheMode::LeakOnMiss,
            hash,
            {
                let calls = Arc::clone(&calls);
                let bytes = bytes.clone();
                move |_h| {
                    let calls = Arc::clone(&calls);
                    let bytes = bytes.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<Vec<u8>, ()>(bytes)
                    }
                }
            },
        ));
        assert_eq!(
            first,
            ServeVerdict::LeakedThenServed(bytes.clone().into()),
            "miss self-fills the one CDN request"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly ONE upstream fetch on the first miss"
        );

        let second = block(serve_addressed(
            &cache,
            &inflight,
            CacheMode::LeakOnMiss,
            hash,
            {
                let calls = Arc::clone(&calls);
                move |_h| {
                    let calls = Arc::clone(&calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<Vec<u8>, ()>(Vec::new())
                    }
                }
            },
        ));
        assert_eq!(
            second,
            ServeVerdict::ServedLocal(bytes.into()),
            "the second request hits the warmed cache"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "≤ 1 EVER: the CDN is never re-asked for a cached asset"
        );
        assert_eq!(cache.lock().unwrap().len(), 1, "exactly one cached copy");
    }

    #[test]
    fn concurrent_misses_coalesce_to_one_fetch() {
        // THE KEYSTONE (Chroma F1, second cut): 5 CONCURRENT misses for the SAME content address must drive
        // EXACTLY ONE upstream fetch (single-flight), not 5. The fetcher yields while "fetching" so the four
        // followers park on the keyed lock; when the leader fills the cache they re-hit it without a 2nd GET.
        let bytes = b"// jQuery 3.7.1 concurrent".to_vec();
        let hash = content_hash(&bytes);
        let cache = empty_cache();
        let inflight = InFlight::new();
        let calls = Arc::new(AtomicUsize::new(0));

        macro_rules! one {
            () => {{
                let bytes = bytes.clone();
                let calls = Arc::clone(&calls);
                move |_h: ContentHash| async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    // Hold the keyed lock across a yield so the other four genuinely contend for it.
                    tokio::task::yield_now().await;
                    Ok::<Vec<u8>, ()>(bytes)
                }
            }};
        }

        let v = block(async {
            tokio::join!(
                serve_addressed(&cache, &inflight, CacheMode::LeakOnMiss, hash, one!()),
                serve_addressed(&cache, &inflight, CacheMode::LeakOnMiss, hash, one!()),
                serve_addressed(&cache, &inflight, CacheMode::LeakOnMiss, hash, one!()),
                serve_addressed(&cache, &inflight, CacheMode::LeakOnMiss, hash, one!()),
                serve_addressed(&cache, &inflight, CacheMode::LeakOnMiss, hash, one!()),
            )
        });

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "single-flight: 5 concurrent misses coalesce to EXACTLY ONE CDN request"
        );
        // Every concurrent caller is served the verified asset (one leader LeakedThenServed, the rest ServedLocal).
        for verdict in [v.0, v.1, v.2, v.3, v.4] {
            assert_eq!(
                verdict.served_bytes(),
                Some(bytes.as_slice()),
                "every concurrent caller is served the verified bytes"
            );
        }
        assert_eq!(
            cache.lock().unwrap().len(),
            1,
            "exactly one cached copy after the storm"
        );
        assert_eq!(
            inflight.in_flight_len(),
            0,
            "the keyed lock is pruned once all callers finish"
        );
    }

    #[test]
    fn strict_mode_serves_nothing_on_miss_so_cdn_sees_zero() {
        // The CROWN: in BlockMissing, a miss serves NOTHING (no fetch leg) ⇒ the CDN sees 0.
        let bytes = b"// uncached asset".to_vec();
        let hash = content_hash(&bytes);
        let cache = empty_cache();
        let inflight = InFlight::new();
        let calls = Arc::new(AtomicUsize::new(0));

        let verdict = block(serve_addressed(
            &cache,
            &inflight,
            CacheMode::BlockMissing,
            hash,
            {
                let calls = Arc::clone(&calls);
                move |_h| {
                    let calls = Arc::clone(&calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<Vec<u8>, ()>(Vec::new())
                    }
                }
            },
        ));
        assert_eq!(verdict, ServeVerdict::BlockedMissing);
        assert!(
            verdict.is_zero_egress(),
            "strict-mode miss is zero egress (the crown)"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "strict mode NEVER fetches — the CDN sees 0"
        );
        assert!(
            cache.lock().unwrap().is_empty(),
            "nothing cached on a strict-mode miss"
        );

        // But a CACHED asset is still served in strict mode (serve-local IS the point).
        cache.lock().unwrap().insert_verified(hash, bytes.clone());
        let hit = block(serve_addressed(
            &cache,
            &inflight,
            CacheMode::BlockMissing,
            hash,
            move |_h| async move { Ok::<Vec<u8>, ()>(Vec::new()) },
        ));
        assert_eq!(
            hit,
            ServeVerdict::ServedLocal(bytes.into()),
            "strict mode still serves a cached asset"
        );
    }

    #[test]
    fn sig_gate_unauthorized_name_is_not_in_catalog_zero_cdn() {
        // The sig gate: an EMPTY (or non-covering) catalog authorizes NOTHING ⇒ NotInCatalog, and the fetch
        // leg is never reached (no unverified asset served, no egress for an unknown name).
        let catalog = Catalog::default();
        let cache = empty_cache();
        let inflight = InFlight::new();
        let calls = Arc::new(AtomicUsize::new(0));

        let verdict = block(serve_name_private(
            &catalog,
            &cache,
            &inflight,
            CacheMode::LeakOnMiss,
            "jquery/3.7.1/jquery.min.js",
            {
                let calls = Arc::clone(&calls);
                move |_h| {
                    let calls = Arc::clone(&calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<Vec<u8>, ()>(Vec::new())
                    }
                }
            },
        ));
        assert_eq!(verdict, ServeVerdict::NotInCatalog);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "an unauthorized name never touches the network"
        );
    }

    #[test]
    fn sig_gate_authorized_name_self_fills_once() {
        // An AUTHORIZED name (signed catalog) with an empty cache self-fills the one CDN request through the
        // sig-gated front door — proving name → content-hash → serve_addressed end-to-end.
        let bytes = b"// jQuery 3.7.1 authorized".to_vec();
        let hash = content_hash(&bytes);
        let name = "jquery/3.7.1/jquery.min.js";
        let catalog = signed_catalog(&[(name, hash)]);
        let cache = empty_cache();
        let inflight = InFlight::new();
        let calls = Arc::new(AtomicUsize::new(0));

        let verdict = block(serve_name_private(
            &catalog,
            &cache,
            &inflight,
            CacheMode::LeakOnMiss,
            name,
            {
                let calls = Arc::clone(&calls);
                let bytes = bytes.clone();
                move |h| {
                    let calls = Arc::clone(&calls);
                    let bytes = bytes.clone();
                    async move {
                        // the flow handed us the catalog-pinned content address.
                        assert_eq!(
                            h, hash,
                            "serve_name_private resolves the catalog content address"
                        );
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<Vec<u8>, ()>(bytes)
                    }
                }
            },
        ));
        assert_eq!(verdict, ServeVerdict::LeakedThenServed(bytes.into()));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the authorized name self-fills exactly once"
        );
    }

    #[test]
    fn fetch_returning_wrong_bytes_is_fail_closed_and_caches_nothing() {
        // POISON-PROOF self-fill: a malicious/substituted upstream that returns bytes NOT matching the
        // catalog-pinned hash is rejected at the insert_verified gate ⇒ FetchFailed, nothing cached, the
        // next lookup is still a miss (the genuine asset was never obtained — never a wrong-hash serve).
        let bytes = b"// the REAL jQuery".to_vec();
        let hash = content_hash(&bytes);
        let cache = empty_cache();
        let inflight = InFlight::new();

        let verdict = block(serve_addressed(
            &cache,
            &inflight,
            CacheMode::LeakOnMiss,
            hash,
            {
                move |_h| async move {
                    // a substituted/tampered response — different bytes ⇒ different content address.
                    Ok::<Vec<u8>, ()>(b"// EVIL substituted payload".to_vec())
                }
            },
        ));
        assert_eq!(
            verdict,
            ServeVerdict::FetchFailed,
            "wrong-hash bytes are rejected fail-closed"
        );
        assert!(
            cache.lock().unwrap().is_empty(),
            "a poisoned fetch caches NOTHING"
        );
    }

    #[test]
    fn fetch_transport_error_is_fail_closed() {
        // A transport error (the unit Err) ⇒ FetchFailed, nothing cached.
        let hash = content_hash(b"whatever");
        let cache = empty_cache();
        let inflight = InFlight::new();
        let verdict = block(serve_addressed(
            &cache,
            &inflight,
            CacheMode::LeakOnMiss,
            hash,
            move |_h| async move { Err::<Vec<u8>, ()>(()) },
        ));
        assert_eq!(verdict, ServeVerdict::FetchFailed);
        assert!(cache.lock().unwrap().is_empty());
    }

    #[test]
    fn inflight_prunes_after_a_serial_serve() {
        // After a single serve completes, the keyed single-flight lock is pruned (the in-flight map is
        // bounded by the LIVE concurrent-miss set, not leaked).
        let bytes = b"// asset".to_vec();
        let hash = content_hash(&bytes);
        let cache = empty_cache();
        let inflight = InFlight::new();
        let _ = block(serve_addressed(
            &cache,
            &inflight,
            CacheMode::LeakOnMiss,
            hash,
            {
                let bytes = bytes.clone();
                move |_h| async move { Ok::<Vec<u8>, ()>(bytes) }
            },
        ));
        assert_eq!(
            inflight.in_flight_len(),
            0,
            "the keyed lock is pruned after the serve finishes"
        );
    }

    #[test]
    fn production_fetch_leg_wires_into_the_flow_and_a_hit_makes_zero_cdn_requests() {
        // De-orphan proof (Chroma F1): the PRODUCTION fetch leg (`fetch_leg` → `fetch_once` over real ring-
        // pinned TLS) type-checks into serve_addressed. Network-FREE: the cache is pre-filled so the request
        // HITS at step 1 — the production closure is built (proving the wiring compiles) but NEVER awaited, so
        // no socket is opened. A hit is 0 CDN egress.
        let bytes = b"// jQuery 3.7.1 cached".to_vec();
        let hash = content_hash(&bytes);
        let cache = empty_cache();
        cache.lock().unwrap().insert_verified(hash, bytes.clone());
        let inflight = InFlight::new();
        let tls = Arc::new(crate::tls_shared::client_tls_config());
        let url = upstream_url(
            "cdnjs.cloudflare.com",
            "/ajax/libs/jquery/",
            "3.7.1",
            "jquery.min.js",
        );

        let verdict = block(serve_addressed(
            &cache,
            &inflight,
            CacheMode::LeakOnMiss,
            hash,
            {
                let tls = Arc::clone(&tls);
                move |h| {
                    let tls = Arc::clone(&tls);
                    let url = url.clone();
                    async move { fetch_leg(&url, h, tls).await.map_err(|_| ()) }
                }
            },
        ));
        assert_eq!(
            verdict,
            ServeVerdict::ServedLocal(bytes.into()),
            "a hit serves locally — the production leg never fires"
        );
    }

    #[test]
    fn upstream_url_reconstructs_the_served_cdn_url() {
        // The one allowed leak target: the SERVED version on the original host, https-only.
        assert_eq!(
            upstream_url(
                "ajax.googleapis.com",
                "/ajax/libs/jquery/",
                "3.7.1",
                "jquery.min.js"
            ),
            "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"
        );
        // a nested file tail is preserved.
        assert_eq!(
            upstream_url(
                "cdnjs.cloudflare.com",
                "/ajax/libs/twitter-bootstrap/",
                "5.3.3",
                "css/bootstrap.min.css"
            ),
            "https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/5.3.3/css/bootstrap.min.css"
        );
    }
}
