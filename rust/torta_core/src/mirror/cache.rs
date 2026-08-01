/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Centauri Local Mirror — the **content-addressed** cache (E').
//!
//! The cache is the heart of the pillar's trust story: every asset is keyed by the BLAKE2b-256 of its
//! bytes, so the store serves a cached asset ONLY on a hash match, and on a miss it fetches ONCE,
//! hash-verifies, and only then caches (verify-on-write / verify-on-read). Because the key IS the content
//! digest, a tampered or truncated cache file can never be served — its bytes would hash to a different key.
//!
//! ## The three load-bearing invariants (mirror-spec §3.2 / §3.3, `centauri-mirror.md:584`-shape)
//! 1. **content-addressed** — `key == BLAKE2b-256(bytes)` for EVERY stored entry, enforced by the only
//!    constructor [`CacheEntry::new`] and re-checked at the [`CacheStore::insert_verified`] gate.
//! 2. **fail-closed** — the store NEVER serves unverified bytes. On a content-address mismatch the bytes
//!    are rejected (not cached, not served); when the bounded store is FULL a new asset is rejected
//!    rather than evicting a verified asset to make room for an unverified fetch (these are
//!    minisign-catalog-pinned assets — a full cache is a "served what we have", never a "serve stale").
//! 3. **fetch-ONCE** — a cache miss yields a [`CacheLookup::Miss`] token the caller redeems with exactly
//!    ONE upstream fetch (`fetch.rs`), whose bytes flow back through `insert_verified`; a subsequent
//!    lookup is a [`CacheLookup::Hit`] (≤1 upstream request EVER per asset — the §3.1 privacy property).
//!
//! ## STATUS (all real — the scaffold notes are history)
//! REAL + type-checked + unit/property-proven on the host: content-addressing, the verify-on-write gate,
//! the bounded fail-closed policy, the serve-on-hash-match read, the fetch-ONCE lookup token, the on-disk
//! atomic write-then-rename backing store, AND (D23/D24) the O(1) `HashMap<ContentHash, CacheEntry>` index
//! with `Arc<[u8]>` zero-copy serves — a content-addressed store whose address IS its index.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

/// A 32-byte content address (BLAKE2b-256 of the asset bytes) — the cache key.
pub type ContentHash = [u8; 32];

/// The per-asset byte ceiling: an asset larger than this is refused at the gate (never hashed-and-stored).
///
/// Mirrors the resolver datapath's bounded-read discipline (`resolver/do53.rs:37` `MAX_RESPONSE = 64 KiB`),
/// "sized up for assets" per mirror-spec §3.3 — a CDN library file is small (KB–low-MB), so a generous
/// 8 MiB cap is a fail-closed guard against a hostile/oversized fetch exhausting memory, NOT a tuning knob.
pub const MAX_ASSET_BYTES: usize = 8 * 1024 * 1024;

/// The bounded store ceiling: the maximum number of distinct content-addressed assets the cache holds.
///
/// The cache is **bounded** (mirror-spec §3.2). When the store is full a NEW asset is rejected
/// fail-closed — these are signed-catalog-pinned assets, so a full cache means "we already serve all we
/// were authorized to hold", never "evict a verified asset to cache an unverified fetch". The curated CDN
/// allowlist is small (cdnjs/jsdelivr/fonts/unpkg — §3.1), so 1024 is a comfortable ceiling, not a churn point.
pub const MAX_ENTRIES: usize = 1024;

/// One content-addressed cache entry: the asset bytes plus their verified content address.
///
/// Invariant (enforced by the constructor): `hash == content_hash(&bytes)`. The cache never stores an
/// entry whose key does not match its bytes, so [`CacheStore::get`] can serve on a key match with no
/// re-hash needed at read time (a verify-on-write store). The fields stay private so the invariant cannot
/// be bypassed by a struct literal.
///
/// **Zero-copy serves (D24):** the bytes live in an `Arc<[u8]>`, so a serve clones the `Arc` (O(1)) via
/// [`CacheEntry::bytes_arc`] and drops the store lock immediately — no up-to-8-MiB memcpy under the lock,
/// same never-hold-across-await safety. `CacheEntry::clone` is likewise O(1) (the serve-snapshot clone
/// shares the immutable bytes instead of re-copying every asset).
#[derive(Clone, Debug)]
pub struct CacheEntry {
    hash: ContentHash,
    bytes: Arc<[u8]>,
}

impl CacheEntry {
    /// Build an entry, computing + binding its content address. The only constructor: it guarantees the
    /// `hash == content_hash(bytes)` invariant for every entry that enters the store.
    pub fn new(bytes: Vec<u8>) -> Self {
        let hash = content_hash(&bytes);
        CacheEntry {
            hash,
            bytes: bytes.into(),
        }
    }

    /// The entry's content address (its cache key).
    pub fn hash(&self) -> ContentHash {
        self.hash
    }

    /// Borrow the cached asset bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Clone the shared handle to the cached asset bytes — the O(1) zero-copy serve read (D24): the caller
    /// gets the verified bytes WITHOUT a memcpy and the store guard can drop immediately.
    pub fn bytes_arc(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }

    /// The byte length of the cached asset (the dashboard's "X MB cached" feed).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Is the cached asset empty? (A zero-length asset is well-defined — its hash is `BLAKE2b-256("")`.)
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Compute the content address of an asset: `BLAKE2b-256(bytes)`. ONE digest discipline for the
/// content-addressed cache (NEVER the forgeable FNV-1a flagged at `blocklist.rs:362`).
///
/// The 32-byte spine type is `blake2::Blake2b::<U32>` — the parametrized 32-byte BLAKE2b (cited
/// `blake2-0.10.6/src/lib.rs:135` `pub type Blake2b<OutSize> = CoreWrapper<Blake2bCore<OutSize>>`), NOT the
/// 64-byte `Blake2b512` alias (`lib.rs:137`). Its `OutputSize = U32` ⇒ `finalize().into() : [u8; 32]` is
/// byte-width-identical to the prior `Sha256` output, so every `ContentHash` `[u8; 32]` site is
/// unchanged in shape (`blake2::Digest` is the SAME `digest 0.10` trait `sha2` used — `lib.rs:83`).
pub fn content_hash(bytes: &[u8]) -> ContentHash {
    let mut h = Blake2b::<U32>::new();
    h.update(bytes);
    h.finalize().into()
}

/// Lower-case hex of a 32-byte content address — the on-disk content-addressed FILENAME. Deterministic +
/// allocation-bounded (exactly 64 chars), the same one-way name→hash mapping [`parse_hex_hash`] inverts.
fn hex_lower(hash: &ContentHash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in hash.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Parse a 64-char lower-case-hex filename back into a 32-byte content address, or `None` if it is not
/// exactly a 64-hex string (so a stray `.tmp` / non-asset file in the cache dir is skipped on rehydrate).
pub(crate) fn parse_hex_hash(name: &str) -> Option<ContentHash> {
    if name.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = name.as_bytes();
    for i in 0..32 {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// One hex digit → its nibble value, or `None` for a non-hex byte (accepts lower-case; the on-disk names
/// are written lower-case by [`hex_lower`], so upper-case is treated as a non-asset filename and skipped).
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// The outcome of a content-addressed lookup — the fetch-ONCE state machine in ONE type.
///
/// A [`CacheLookup::Hit`] carries the verified cached bytes (serve directly). A [`CacheLookup::Miss`]
/// carries the `wanted` content address: the caller (`fetch.rs`) does EXACTLY ONE upstream fetch, then
/// drives the bytes back through [`CacheStore::insert_verified`] with this same `wanted` hash — so a
/// mismatch is rejected at the gate and a verified fetch is cached for every future hit. Modelling the
/// miss as a token (not a bare `None`) makes "do one fetch, verify against the catalog hash" the only
/// shape the caller can write — fetch-once idempotency by construction.
#[derive(Clone, Debug)]
pub enum CacheLookup<'a> {
    /// The asset is cached and verified-by-construction — serve these bytes (no upstream contact).
    Hit(&'a CacheEntry),
    /// The asset is absent — fetch ONCE off the CDN, then `insert_verified(wanted, fetched_bytes)`.
    Miss { wanted: ContentHash },
}

impl CacheLookup<'_> {
    /// `true` iff this lookup found a verified cached asset.
    pub fn is_hit(&self) -> bool {
        matches!(self, CacheLookup::Hit(_))
    }

    /// `true` iff this lookup missed (the caller owes exactly one upstream fetch).
    pub fn is_miss(&self) -> bool {
        matches!(self, CacheLookup::Miss { .. })
    }
}

/// Why an `insert_verified` was refused — a typed verdict, never an unwinding error across the boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheReject {
    /// `content_hash(bytes) != expected`: the fetched bytes are NOT the catalog-pinned asset → never cache
    /// (the fail-closed core — a tampered/wrong fetch is rejected, never cached, never served).
    ContentAddressMismatch,
    /// The asset exceeds [`MAX_ASSET_BYTES`] → refused before hashing (a bounded-read guard).
    TooLarge,
    /// The bounded store is FULL ([`MAX_ENTRIES`] reached) and this is a NEW address → refused fail-closed
    /// (never evict a verified asset to admit an unverified fetch).
    StoreFull,
}

/// The content-addressed cache store: a bounded index of `ContentHash → CacheEntry`.
///
/// **The address IS the index (D23):** a `HashMap<ContentHash, CacheEntry>` (`[u8; 32]` is `Eq + Hash`),
/// so `insert`-dedup / `contains` / `get` / `get_bytes` are all O(1) — the old `Vec` scaffold paid a
/// linear 32-byte-compare scan per serve/lookup, up to [`MAX_ENTRIES`]. The on-disk backing (atomic
/// write-then-rename per verified asset) keys by the same hash. The store enforces the THREE invariants
/// (content-addressed, fail-closed, bounded) regardless of backing.
#[derive(Debug)]
pub struct CacheStore {
    entries: HashMap<ContentHash, CacheEntry>,
    /// The maximum number of assets this store admits (defaults to [`MAX_ENTRIES`]).
    capacity: usize,
    /// The on-disk content-addressed backing directory, if this store is disk-backed. `None` ⇒ in-memory
    /// only (the test shape). When `Some(dir)`, a verified insert is mirrored to `dir/<hex-hash>`
    /// via an atomic tmp+rename ([`CacheStore::with_dir`] / [`CacheStore::load_from_disk`]).
    dir: Option<PathBuf>,
}

impl Default for CacheStore {
    fn default() -> Self {
        CacheStore::new()
    }
}

impl CacheStore {
    /// A fresh, empty cache store at the default [`MAX_ENTRIES`] bound (in-memory only).
    pub fn new() -> Self {
        CacheStore {
            entries: HashMap::new(),
            capacity: MAX_ENTRIES,
            dir: None,
        }
    }

    /// A fresh, empty store at an explicit bound (≥1; clamped to ≥1 so a degenerate `0` can't deadlock the
    /// fetch-once loop into never being able to cache). Used by tests + the dashboard's configurable cap.
    pub fn with_capacity(capacity: usize) -> Self {
        CacheStore {
            entries: HashMap::new(),
            capacity: capacity.max(1),
            dir: None,
        }
    }

    /// A fresh, empty **disk-backed** store at the default bound, persisting every verified asset to `dir`.
    ///
    /// The store is content-addressed on disk too: each verified asset lands at `dir/<hex(content_hash)>`
    /// written via atomic tmp+rename, so a crashed write never leaves a half-file under a valid key. The
    /// directory is NOT read here (the constructor is non-failing + battery-frugal — no boot IO scan); the
    /// caller rehydrates the in-memory index from disk explicitly via [`CacheStore::load_from_disk`]. The
    /// THREE invariants (content-addressed, fail-closed, bounded) hold identically whether or not `dir` is set.
    pub fn with_dir(dir: PathBuf) -> Self {
        CacheStore {
            entries: HashMap::new(),
            capacity: MAX_ENTRIES,
            dir: Some(dir),
        }
    }

    /// Insert an asset by VERIFYING its claimed content address (verify-on-write — the fail-closed gate).
    ///
    /// The caller passes the `expected` hash (from the minisign-verified catalog entry) and the fetched
    /// bytes; the store admits them ONLY if `content_hash(bytes) == expected` AND the bounded/size guards
    /// pass. Returns `Some(hash)` on success, `None` on ANY refusal (mismatch / oversize / full).
    ///
    /// This is the simple boolean-ish surface the loopback server + `fetch.rs` drive (`Some` ⇒ cached +
    /// serveable). When the caller needs the REASON for a refusal (the dashboard's "rejected: tampered"
    /// vs "rejected: cache full" telemetry), use [`CacheStore::try_insert_verified`] — this method is a
    /// thin `.ok()` over it, so the fail-closed semantics are identical.
    pub fn insert_verified(
        &mut self,
        expected: ContentHash,
        bytes: Vec<u8>,
    ) -> Option<ContentHash> {
        self.try_insert_verified(expected, bytes).ok()
    }

    /// The typed-verdict twin of [`CacheStore::insert_verified`]: same verify-on-write fail-closed gate,
    /// but returns WHY an asset was refused ([`CacheReject`]) instead of a bare `None`.
    ///
    /// Fail-closed order (cheapest reject first; NEVER hash an oversized buffer needlessly, NEVER admit
    /// past the bound): size guard → content-address verify → bound guard. An already-present address is a
    /// no-op success (idempotent re-insert: the same verified bytes are already served).
    pub fn try_insert_verified(
        &mut self,
        expected: ContentHash,
        bytes: Vec<u8>,
    ) -> Result<ContentHash, CacheReject> {
        // (1) bounded-read guard — refuse an oversized asset before doing any work on it.
        if bytes.len() > MAX_ASSET_BYTES {
            return Err(CacheReject::TooLarge);
        }
        // (2) content-address verify — the fail-closed core. Build through the only constructor (which
        //     binds hash == content_hash(bytes)) and compare against the catalog-pinned `expected`.
        let entry = CacheEntry::new(bytes);
        if entry.hash() != expected {
            return Err(CacheReject::ContentAddressMismatch); // wrong/tampered bytes ⇒ never cache.
        }
        self.admit(entry)
    }

    /// The shared bound/disk/insert tail of a verified admission (steps 3–5 of the fail-closed order —
    /// the entry's `hash == content_hash(bytes)` invariant already holds by construction/verification).
    fn admit(&mut self, entry: CacheEntry) -> Result<ContentHash, CacheReject> {
        let hash = entry.hash();
        // Idempotent: the same verified asset already present is a success (no second copy, no churn).
        if self.entries.contains_key(&hash) {
            return Ok(hash);
        }
        // (3) bound guard — a NEW address past the ceiling is refused fail-closed (never evict to admit).
        if self.entries.len() >= self.capacity {
            return Err(CacheReject::StoreFull);
        }
        // (4) on-disk write-through (disk-backed stores only) — persist the verified asset BEFORE admitting
        //     it to the in-memory index, atomically (tmp+rename). A disk write failure rejects the insert
        //     fail-closed (StoreFull): an asset we cannot durably persist is not silently kept memory-only,
        //     so the in-mem index never claims to hold what disk does not. In-memory stores skip this.
        if let Some(dir) = self.dir.clone() {
            if Self::write_to_disk(&dir, &hash, entry.bytes()).is_err() {
                return Err(CacheReject::StoreFull);
            }
        }
        // (5) the address IS the index (D23): one O(1) keyed insert.
        self.entries.insert(hash, entry);
        Ok(hash)
    }

    /// Persist a pre-verified [`CacheEntry`] (in-memory + on-disk write-through), returning `true` IFF it is
    /// admitted. The content-addressed/bounded/fail-closed gate is identical to [`CacheStore::insert_verified`]
    /// — an entry can only be built via the invariant-binding [`CacheEntry::new`] (private fields), so its
    /// `hash() == content_hash(bytes)` holds by construction: no trust-the-caller hole, and (D24) no
    /// re-hash/re-copy round-trip either — the shared `Arc<[u8]>` bytes are admitted as-is. An
    /// already-present address is an idempotent `true`. This is the boolean surface the JNI/fetch path drives
    /// after `fetch.rs` returns hash-verified bytes; it never serves or stores unverified bytes.
    pub fn insert_verified_entry(&mut self, entry: CacheEntry) -> bool {
        if entry.len() > MAX_ASSET_BYTES {
            return false; // the same bounded-read guard the byte path enforces first.
        }
        self.admit(entry).is_ok()
    }

    /// The on-disk content-addressed write: `dir/<hex(hash)>` via an atomic tmp+rename so a crashed/partial
    /// write never appears under a valid content-address key. Creates `dir` if absent. Idempotent: a
    /// rename over an existing file (same content address) is a harmless overwrite of identical bytes.
    fn write_to_disk(dir: &Path, hash: &ContentHash, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let name = hex_lower(hash);
        let final_path = dir.join(&name);
        // tmp name carries the hash so concurrent writers of distinct assets don't collide on one tmp.
        let tmp_path = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp_path, bytes)?;
        // rename is atomic on the same filesystem; on the rare rename failure, clean the tmp + propagate.
        match std::fs::rename(&tmp_path, &final_path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                Err(e)
            }
        }
    }

    /// Rehydrate the in-memory index from the on-disk content-addressed directory, returning the count of
    /// assets admitted. Each file is read, its bytes re-hashed, and admitted ONLY if its content address
    /// matches its FILENAME (`<hex-hash>`) — a tampered or renamed on-disk file is REJECTED (fail-closed:
    /// the disk is content-addressed too, never trusted by name alone). Oversized / over-bound / non-hex
    /// files are skipped. Safe to call on a non-`with_dir` store (no-op-ish — it still rehydrates from the
    /// passed `dir`, mirroring on-disk truth into memory). Battery-frugal: a single directory scan at start.
    pub fn load_from_disk(&mut self, dir: &Path) -> usize {
        let mut loaded = 0usize;
        let read_dir = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => return 0, // absent/unreadable dir ⇒ nothing to rehydrate (cold start), not an error.
        };
        for entry in read_dir.flatten() {
            // The filename must be a 64-hex content address; skip tmp files + anything malformed.
            let file_name = entry.file_name();
            let name = match file_name.to_str() {
                Some(n) => n,
                None => continue,
            };
            let claimed = match parse_hex_hash(name) {
                Some(h) => h,
                None => continue, // not a <hex-hash> file (e.g. a leftover `.tmp`) ⇒ skip.
            };
            let bytes = match std::fs::read(entry.path()) {
                Ok(b) => b,
                Err(_) => continue,
            };
            // REJECT a file whose bytes don't hash to its filename (tampered/renamed) — fail-closed.
            let entry = CacheEntry::new(bytes);
            if entry.hash() != claimed {
                continue;
            }
            // Admit through the SAME bounded/size gate (NOT re-writing to disk — it's already there).
            if entry.len() > MAX_ASSET_BYTES {
                continue;
            }
            if self.entries.contains_key(&entry.hash()) {
                continue; // already loaded (idempotent rehydrate).
            }
            if self.entries.len() >= self.capacity {
                break; // bounded store full ⇒ stop admitting (fail-closed, never over-bound).
            }
            self.entries.insert(entry.hash(), entry);
            loaded += 1;
        }
        loaded
    }

    /// Look up an asset by content address, returning the fetch-ONCE state-machine token.
    ///
    /// A present key ⇒ [`CacheLookup::Hit`] with the verified bytes (serve, no upstream contact); an absent
    /// key ⇒ [`CacheLookup::Miss`] carrying `wanted == hash`, which the caller redeems with exactly one
    /// upstream fetch + `insert_verified(wanted, …)`. This is the seam that makes "≤1 request EVER per
    /// asset" (§3.1) the only shape the caller can express.
    pub fn lookup(&self, hash: &ContentHash) -> CacheLookup<'_> {
        match self.get(hash) {
            Some(entry) => CacheLookup::Hit(entry),
            None => CacheLookup::Miss { wanted: *hash },
        }
    }

    /// Serve a cached asset by content address. Returns the entry IFF a matching key is present
    /// (content-addressed: serve only on hash match). `None` ⇒ a miss ⇒ the caller does the fetch-ONCE leg.
    /// Prefer [`CacheStore::lookup`] on the datapath — it makes the fetch-once obligation explicit.
    /// O(1) — the content address IS the index (D23).
    pub fn get(&self, hash: &ContentHash) -> Option<&CacheEntry> {
        self.entries.get(hash)
    }

    /// Borrow the verified bytes for a content address, if cached (the direct serve-on-match accessor).
    pub fn get_bytes(&self, hash: &ContentHash) -> Option<&[u8]> {
        self.get(hash).map(CacheEntry::bytes)
    }

    /// Is this content address already cached? O(1) keyed probe (D23).
    pub fn contains(&self, hash: &ContentHash) -> bool {
        self.entries.contains_key(hash)
    }

    /// The number of cached assets (the dashboard's "serving N libraries" count).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the cache empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The bounded store's capacity (the fail-closed ceiling).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Is the bounded store full? (A full store rejects a NEW address fail-closed.)
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.capacity
    }

    /// The total bytes held across all cached assets (the dashboard's "X MB never left your device" feed).
    pub fn total_bytes(&self) -> usize {
        self.entries.values().map(CacheEntry::len).sum()
    }

    /// Collect every cached asset's 32-byte content address (the serve-snapshot's content-address set).
    pub fn content_hashes(&self) -> Vec<ContentHash> {
        self.entries.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {

    /// A5 GUARD -- `MAX_ENTRIES` (= 1024, cache.rs:56) bounds the content-addressed store. The A5
    /// inventory found it had a NUMBER and no test naming it.
    ///
    /// Three arms, because a bound on a CACHE has a second, opposite failure mode. Refusing at the
    /// ceiling is only correct if the store never EVICTS to make room: cache.rs:201 states the
    /// policy as "never evict a verified asset to admit an unverified fetch". So the guard pins
    /// that a full store (a) refuses a NEW address with StoreFull, (b) still holds everything it
    /// held before the refusal, and (c) remains idempotent for an address it ALREADY has -- a full
    /// store that started rejecting re-puts of assets it is already serving would be a live outage.
    #[test]
    fn max_entries_refuses_fail_closed_and_never_evicts() {
        let mut store = CacheStore::new();
        let mut first: Option<ContentHash> = None;
        for i in 0..MAX_ENTRIES {
            let bytes = format!("asset-{i:06}").into_bytes();
            let h = content_hash(&bytes);
            if i == 0 {
                first = Some(h);
            }
            assert!(
                store.try_insert_verified(h, bytes).is_ok(),
                "admission {i} below the ceiling must succeed"
            );
        }

        // (a) a NEW address at the ceiling is refused, fail-closed.
        let newb = b"one-asset-too-many".to_vec();
        let newh = content_hash(&newb);
        assert!(
            matches!(
                store.try_insert_verified(newh, newb),
                Err(CacheReject::StoreFull)
            ),
            "a NEW address past MAX_ENTRIES must be refused with StoreFull"
        );

        // (b) the refusal evicted nothing -- the first asset admitted is still served.
        let first = first.expect("seeded");
        assert!(
            store.get(&first).is_some(),
            "a refusal must NEVER evict an already-verified asset"
        );

        // (c) a full store is still idempotent for an address it already holds.
        let again = b"asset-000000".to_vec();
        assert!(
            store.try_insert_verified(content_hash(&again), again).is_ok(),
            "re-putting an asset the store ALREADY holds must succeed even when full"
        );
    }
    use super::*;

    // ---- helpers -------------------------------------------------------------------------------------

    /// A deterministic pseudo-asset of `len` bytes seeded by `seed` (no rng dep — host-pure + reproducible).
    fn asset(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add(i as u8).wrapping_mul(31))
            .collect()
    }

    // ---- content-addressing (unit) -------------------------------------------------------------------

    #[test]
    fn content_hash_matches_blake2b() {
        let bytes = b"centauri catalog asset bytes";
        let mut h = Blake2b::<U32>::new();
        h.update(bytes);
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(content_hash(bytes), expect);
    }

    #[test]
    fn empty_asset_hashes_to_blake2b_of_empty() {
        // A zero-length asset is well-defined — BLAKE2b-256("").
        let mut h = Blake2b::<U32>::new();
        h.update(b"");
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(content_hash(b""), expect);
        let entry = CacheEntry::new(Vec::new());
        assert!(entry.is_empty());
        assert_eq!(entry.hash(), expect);
    }

    // ---- the verify-on-write gate (fail-closed) ------------------------------------------------------

    #[test]
    fn insert_verified_rejects_content_address_mismatch() {
        let mut store = CacheStore::new();
        let bytes = b"the real asset".to_vec();
        let wrong = [0u8; 32]; // not the real content address
                               // The typed surface names the reason; the Option surface (scaffold contract) returns None.
        assert_eq!(
            store.try_insert_verified(wrong, bytes.clone()),
            Err(CacheReject::ContentAddressMismatch),
            "a mismatch MUST NOT cache (fail-closed)"
        );
        assert_eq!(
            store.insert_verified(wrong, bytes),
            None,
            "Option surface ⇒ None on reject"
        );
        assert!(store.is_empty(), "a rejected asset never enters the store");
    }

    #[test]
    fn insert_verified_accepts_matching_hash_and_serves_on_match() {
        let mut store = CacheStore::new();
        let bytes = b"the real asset".to_vec();
        let h = content_hash(&bytes);
        assert_eq!(store.insert_verified(h, bytes.clone()), Some(h));
        let got = store
            .get(&h)
            .expect("a verified asset is served on its content address");
        assert_eq!(got.bytes(), bytes.as_slice());
        assert_eq!(store.get_bytes(&h), Some(bytes.as_slice()));
        assert!(
            store.get(&[0u8; 32]).is_none(),
            "a non-matching key is a miss"
        );
    }

    #[test]
    fn insert_verified_is_idempotent_on_repeat() {
        let mut store = CacheStore::new();
        let bytes = asset(7, 64);
        let h = content_hash(&bytes);
        assert_eq!(store.insert_verified(h, bytes.clone()), Some(h));
        // Re-inserting the SAME verified asset is a no-op success, not a second copy.
        assert_eq!(store.insert_verified(h, bytes), Some(h));
        assert_eq!(store.len(), 1, "an idempotent re-insert never duplicates");
    }

    #[test]
    fn insert_verified_rejects_oversized_asset() {
        let mut store = CacheStore::new();
        let big = vec![0u8; MAX_ASSET_BYTES + 1];
        let h = content_hash(&big);
        assert_eq!(
            store.try_insert_verified(h, big),
            Err(CacheReject::TooLarge),
            "an asset over the byte ceiling is refused before caching"
        );
        assert!(store.is_empty());
        // A small in-bounds asset is admissible (proves the size guard isn't over-rejecting).
        let edge = vec![1u8; 8];
        let he = content_hash(&edge);
        assert_eq!(store.insert_verified(he, edge), Some(he));
    }

    // ---- the bounded fail-closed policy --------------------------------------------------------------

    #[test]
    fn full_store_rejects_a_new_asset_fail_closed() {
        let mut store = CacheStore::with_capacity(2);
        for seed in 0u8..2 {
            let b = asset(seed, 16);
            let h = content_hash(&b);
            assert_eq!(store.insert_verified(h, b), Some(h));
        }
        assert!(store.is_full());
        // A THIRD distinct asset is refused — never evict a verified asset to admit a new fetch.
        let third = asset(2, 16);
        let h3 = content_hash(&third);
        assert_eq!(
            store.try_insert_verified(h3, third),
            Err(CacheReject::StoreFull),
            "a full bounded store rejects a NEW address fail-closed"
        );
        assert_eq!(store.len(), 2, "the store stays at capacity, no overflow");
        assert!(store.get(&h3).is_none(), "the rejected asset is NOT served");
    }

    #[test]
    fn full_store_still_accepts_an_already_present_asset() {
        let mut store = CacheStore::with_capacity(1);
        let b = asset(9, 16);
        let h = content_hash(&b);
        assert_eq!(store.insert_verified(h, b.clone()), Some(h));
        assert!(store.is_full());
        // Re-inserting the present asset succeeds even at capacity (idempotent, not a new admission).
        assert_eq!(store.insert_verified(h, b), Some(h));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn zero_capacity_is_clamped_so_one_asset_can_cache() {
        // A degenerate 0 must not deadlock the fetch-once loop into never being able to cache.
        let mut store = CacheStore::with_capacity(0);
        assert_eq!(store.capacity(), 1, "capacity is clamped to >=1");
        let b = asset(3, 8);
        let h = content_hash(&b);
        assert_eq!(store.insert_verified(h, b), Some(h));
    }

    // ---- the fetch-ONCE state machine ----------------------------------------------------------------

    #[test]
    fn lookup_miss_then_insert_then_hit() {
        let mut store = CacheStore::new();
        let bytes = asset(5, 128);
        let h = content_hash(&bytes);

        // First lookup: a MISS carrying the wanted address (the caller owes one fetch).
        match store.lookup(&h) {
            CacheLookup::Miss { wanted } => {
                assert_eq!(wanted, h, "the miss carries the wanted address")
            }
            CacheLookup::Hit(_) => panic!("an empty store must miss"),
        }
        // The caller fetches ONCE + verifies through insert_verified with that same wanted hash.
        assert_eq!(store.insert_verified(h, bytes.clone()), Some(h));
        // Now it's a HIT serving the verified bytes — no further upstream contact.
        match store.lookup(&h) {
            CacheLookup::Hit(entry) => assert_eq!(entry.bytes(), bytes.as_slice()),
            CacheLookup::Miss { .. } => panic!("a cached asset must hit"),
        }
        assert!(store.lookup(&h).is_hit());
        assert!(store.lookup(&[0u8; 32]).is_miss());
    }

    // ---- content-address snapshot --------------------------------------------------------------------

    #[test]
    fn store_content_hashes_are_exactly_the_cached_addresses() {
        let mut store = CacheStore::new();
        let mut want = Vec::new();
        for seed in 0u8..4 {
            let b = asset(seed, 32 + seed as usize);
            let h = content_hash(&b);
            assert_eq!(store.insert_verified(h, b), Some(h));
            want.push(h);
        }
        let hashes = store.content_hashes();
        assert_eq!(hashes.len(), 4);
        // Every returned hash is a cached content address.
        for hash in &hashes {
            assert!(
                want.contains(hash),
                "a returned hash must be a cached content address"
            );
        }
        assert_eq!(store.total_bytes(), 32 + 33 + 34 + 35);
    }

    // ---- hand-rolled property tests (no proptest dev-dep yet — see notes) -----------------------------

    /// PROPERTY: for ANY (seed,len) the round-trip holds — `content_hash(bytes)` always admits, and the
    /// served bytes equal the inserted bytes (content-addressing is a faithful key over the asset).
    #[test]
    fn prop_roundtrip_over_many_assets() {
        let mut store = CacheStore::with_capacity(MAX_ENTRIES);
        for seed in 0u8..40 {
            for &len in &[0usize, 1, 7, 64, 257, 4096] {
                let mut s = CacheStore::new();
                let b = asset(seed, len);
                let h = content_hash(&b);
                assert_eq!(
                    s.insert_verified(h, b.clone()),
                    Some(h),
                    "honest bytes always admit"
                );
                assert_eq!(
                    s.get_bytes(&h),
                    Some(b.as_slice()),
                    "served bytes == inserted bytes"
                );
            }
            // Also exercise distinct assets accumulating in one bounded store.
            let b = asset(seed, 16);
            let h = content_hash(&b);
            let _ = store.insert_verified(h, b);
        }
        assert!(
            store.len() <= store.capacity(),
            "the store never exceeds its bound"
        );
    }

    /// PROPERTY: tampering ANY byte of a cached asset's bytes makes them hash to a DIFFERENT address, so
    /// `insert_verified(original_hash, tampered_bytes)` is rejected (tamper → mismatch → reject). This is
    /// the core fail-closed guarantee: unverified bytes are NEVER served under a verified key.
    #[test]
    fn prop_any_tampered_byte_is_rejected() {
        for seed in 0u8..16 {
            let original = asset(seed, 96);
            let want = content_hash(&original);
            for i in 0..original.len() {
                let mut tampered = original.clone();
                tampered[i] ^= 0x01; // flip one bit of one byte
                let mut store = CacheStore::new();
                assert_eq!(
                    store.try_insert_verified(want, tampered),
                    Err(CacheReject::ContentAddressMismatch),
                    "tampering byte {i} of asset {seed} must be rejected at the content-address gate"
                );
                assert!(store.is_empty(), "a tampered asset never enters the store");
            }
        }
    }

    /// PROPERTY: truncation (a prefix of the real bytes) also fails the content-address gate — a truncated
    /// download can never be served as the full asset.
    #[test]
    fn prop_truncated_asset_is_rejected() {
        for seed in 0u8..16 {
            let original = asset(seed, 200);
            let want = content_hash(&original);
            for cut in [0usize, 1, 50, 199] {
                let truncated = original[..cut].to_vec();
                let mut store = CacheStore::new();
                assert_eq!(
                    store.try_insert_verified(want, truncated),
                    Err(CacheReject::ContentAddressMismatch),
                    "a truncated ({cut}/200) asset {seed} must be rejected"
                );
            }
        }
    }

    /// PROPERTY: fetch-once idempotency — redeeming a miss N times with the SAME verified bytes leaves the
    /// store with exactly ONE copy (the caller can never be coaxed into N stored copies / N upstream rows).
    #[test]
    fn prop_fetch_once_idempotency() {
        for seed in 0u8..16 {
            let mut store = CacheStore::new();
            let b = asset(seed, 80);
            let h = content_hash(&b);
            assert!(store.lookup(&h).is_miss(), "first lookup misses");
            for _ in 0..5 {
                assert_eq!(store.insert_verified(h, b.clone()), Some(h));
                assert!(
                    store.lookup(&h).is_hit(),
                    "after the one fetch it always hits"
                );
            }
            assert_eq!(
                store.len(),
                1,
                "≤1 stored copy regardless of repeated redemption"
            );
        }
    }

    // ---- on-disk write-through + rehydrate (atomic, content-addressed, fail-closed) -------------------

    /// A unique-per-test temp dir under the OS temp root (no external rng dep — a process-unique counter +
    /// the test's seed give a collision-free path). Returns the path; the test cleans it up at the end.
    fn temp_cache_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("torta-centauri-cache-{tag}-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&dir); // start clean if a prior run leaked it.
        dir
    }

    #[test]
    fn hex_roundtrip_is_faithful() {
        for seed in 0u8..32 {
            let h = content_hash(&asset(seed, 17));
            let name = hex_lower(&h);
            assert_eq!(name.len(), 64, "a content address is exactly 64 hex chars");
            assert_eq!(
                parse_hex_hash(&name),
                Some(h),
                "hex name → hash round-trips"
            );
        }
        // A non-hex / wrong-length name is rejected (so a stray .tmp is skipped on rehydrate).
        assert_eq!(parse_hex_hash(".abc.tmp"), None);
        assert_eq!(parse_hex_hash("not-a-hash"), None);
        assert_eq!(parse_hex_hash(&"g".repeat(64)), None, "non-hex char ⇒ None");
        assert_eq!(parse_hex_hash(&"a".repeat(63)), None, "wrong length ⇒ None");
    }

    #[test]
    fn disk_write_through_persists_under_the_content_address() {
        let dir = temp_cache_dir("write-through");
        let mut store = CacheStore::with_dir(dir.clone());
        let bytes = asset(11, 256);
        let h = content_hash(&bytes);
        assert_eq!(store.insert_verified(h, bytes.clone()), Some(h));
        // The asset landed on disk at dir/<hex-hash> with EXACTLY the verified bytes.
        let on_disk = dir.join(hex_lower(&h));
        assert!(
            on_disk.exists(),
            "a verified insert writes the asset to disk"
        );
        assert_eq!(
            std::fs::read(&on_disk).unwrap(),
            bytes,
            "disk bytes == verified bytes"
        );
        // No tmp file is left behind after the atomic rename.
        let tmp = dir.join(format!(".{}.tmp", hex_lower(&h)));
        assert!(
            !tmp.exists(),
            "the tmp file is renamed away (atomic), never left dangling"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_mismatch_is_never_written() {
        let dir = temp_cache_dir("mismatch");
        let mut store = CacheStore::with_dir(dir.clone());
        let bytes = asset(3, 64);
        let wrong = [0u8; 32]; // not the real content address
        assert_eq!(
            store.insert_verified(wrong, bytes),
            None,
            "a mismatch is rejected"
        );
        // Fail-closed: nothing was written for the bogus address, and the dir holds zero assets.
        let count = std::fs::read_dir(&dir).map(|rd| rd.count()).unwrap_or(0);
        assert_eq!(count, 0, "a rejected (mismatched) asset is never persisted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_disk_rehydrates_verified_assets() {
        let dir = temp_cache_dir("rehydrate");
        // Write three verified assets through a disk-backed store.
        let mut writer = CacheStore::with_dir(dir.clone());
        let mut want = Vec::new();
        for seed in 0u8..3 {
            let b = asset(seed, 100 + seed as usize);
            let h = content_hash(&b);
            assert_eq!(writer.insert_verified(h, b), Some(h));
            want.push(h);
        }
        // A FRESH store rehydrates them from disk and serves them by content address.
        let mut reader = CacheStore::with_dir(dir.clone());
        let loaded = reader.load_from_disk(&dir);
        assert_eq!(loaded, 3, "all three verified assets rehydrate");
        for h in &want {
            assert!(
                reader.get(h).is_some(),
                "a rehydrated asset is served on its content address"
            );
        }
        // Rehydrate is idempotent — a second load admits zero new entries.
        assert_eq!(reader.load_from_disk(&dir), 0, "no duplicate rehydration");
        assert_eq!(reader.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_disk_rejects_a_tampered_file_fail_closed() {
        let dir = temp_cache_dir("tampered");
        let mut writer = CacheStore::with_dir(dir.clone());
        let good = asset(8, 128);
        let hg = content_hash(&good);
        assert_eq!(writer.insert_verified(hg, good), Some(hg));
        // Plant a TAMPERED file: bytes that do NOT hash to their <hex-hash> filename.
        let liar_name = hex_lower(&content_hash(&asset(99, 40))); // a valid-looking 64-hex name…
        std::fs::write(
            dir.join(&liar_name),
            b"these bytes do not match the filename",
        )
        .unwrap();
        // Also plant a stray non-hash file (must be skipped, not error).
        std::fs::write(dir.join("README.txt"), b"not an asset").unwrap();
        let mut reader = CacheStore::with_dir(dir.clone());
        let loaded = reader.load_from_disk(&dir);
        assert_eq!(
            loaded, 1,
            "only the genuine content-addressed asset rehydrates; tamper is rejected"
        );
        assert!(reader.get(&hg).is_some(), "the honest asset is present");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_disk_on_absent_dir_is_zero_not_error() {
        let dir = temp_cache_dir("absent");
        let mut store = CacheStore::with_dir(dir.clone());
        // Never created — a cold start rehydrates zero, never panics.
        assert_eq!(
            store.load_from_disk(&dir),
            0,
            "an absent cache dir is a cold start, not an error"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn insert_verified_entry_admits_and_persists() {
        let dir = temp_cache_dir("entry");
        let mut store = CacheStore::with_dir(dir.clone());
        let entry = CacheEntry::new(asset(21, 64));
        let h = entry.hash();
        assert!(
            store.insert_verified_entry(entry),
            "a pre-verified entry is admitted"
        );
        assert!(store.get(&h).is_some(), "served by content address");
        assert!(dir.join(hex_lower(&h)).exists(), "persisted to disk");
        // Idempotent: re-inserting the same entry is a true no-op (no duplicate, no error).
        assert!(store.insert_verified_entry(CacheEntry::new(asset(21, 64))));
        assert_eq!(store.len(), 1, "idempotent entry-insert never duplicates");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
