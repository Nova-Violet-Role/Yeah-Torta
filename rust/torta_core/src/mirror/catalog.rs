/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Centauri Local Mirror — the **Haskell-signed CDN catalog** parser + the **DNS-cloak seam** (E').
//!
//! The catalog is the manifest of content-addressed assets the mirror may serve: each entry pins an asset
//! by its BLAKE2b-256 content address, names the loopback request name the server routes on, and flags
//! whether the asset's host is **cloaked** (DNS-redirected to the `10.1.10.3` tun sentinel so the local mirror answers
//! instead of the real CDN). The catalog is authored + minisign-signed OFFLINE by the native-linux GHC
//! 9.4.7 Centauri brain on the Home VM (ADR-001 Amendment 1: the Haskell brain signs, the Rust loopback
//! serves).
//!
//! ## Verify-sig-FIRST (load-bearing — REUSE, never duplicate Ed25519)
//! Before a single catalog byte is trusted, the raw catalog bytes are authenticated through
//! [`crate::signature::verify_minisign`] **verbatim** — the SAME 5-step legacy-`Ed` 74-byte-blob /
//! 42-byte-pinned-key path (`signature.rs:91`) the blocklist artifact channel uses. The catalog is "just
//! another `.tblk`-shaped signed artifact" (it even reuses the `TBLK`-discipline header shape, `blocklist.rs:51-64`);
//! there is NO second Ed25519 here. Only after a `true` verdict does [`Catalog::parse_verified`] read the
//! body, so an unverified catalog never becomes a [`Catalog`] value (parse-DON'T-validate: the type IS proof).
//!
//! ## Wire format (`TCAT` — TBLK-discipline, the blocklist codec twin, `blocklist.rs:51-64`)
//! Fixed-width little-endian header (24 bytes), mirroring the `TBLK` header discipline so one codec mindset
//! covers both artifact families on the same signed channel:
//!
//! ```text
//!   off 0  : magic     b"TCAT"           (4 bytes)              — distinct family from b"TBLK" (blocklist)
//!   off 4  : u16       format_version    (v1 = CATALOG_VERSION, v2 = CATALOG_VERSION_FRESHNESS)
//!   off 6  : u8        hash_algo_id      (= HASH_ALGO_BLAKE2B; matches the content-addressed cache digest)
//!   off 7  : u8        flags             (reserved, must be 0)
//!   off 8  : u64       v1: reserved (must be 0) · v2: authored_at_secs — the FRESHNESS EPOCH (unix
//!                      seconds the author stamped at signing; 0 = author declined to stamp). The v1
//!                      reservation was earmarked for exactly this ("future catalog-meta / freshness
//!                      epoch") and v2 spends it: the parser accepts BOTH versions (v1 ⇒ epoch 0), the
//!                      device encoder authors v2, and the signature covers the epoch like every other
//!                      body byte — a post-sign freshness rewrite fails `verify_minisign` (★ #22 slice 2).
//!   off 16 : u32       entry_count
//!   off 20 : u32       reserved2         (must be 0)
//! Body (off 24): `entry_count` records, each:
//!   u8        entry_flags                (bit0 = CLOAK: host is DNS-redirected to the 10.1.10.3 sentinel)
//!   u8[32]    content_hash               (BLAKE2b-256 content address — the cache key)
//!   u16  LE   name_len                   (1..=MAX_NAME_BYTES)  + that many UTF-8 bytes (the request name)
//!   u16  LE   host_len                   (1..=MAX_HOST_BYTES)  + that many UTF-8 bytes (the CDN hostname)
//! ```
//!
//! The body is the catalog the Ed25519 signature covers WHOLE (so any post-sign mutation — a flipped cloak
//! flag, a swapped content hash, an extra entry — changes the signed message and fails `verify_minisign`,
//! exactly as a flipped `hash_algo_id` fails for the blocklist artifact, `signature.rs:46-48`).
//!
//! ## The DNS-cloak seam (spec the seam — do NOT wire the datapath this round)
//! [`Catalog::cloak_set`] projects the verified catalog into a [`CloakSet`]: the set of hostnames the
//! resolver/blocklist path should answer as the `10.1.10.3` sentinel. The lookup mirrors `blocklist.rs:211 is_blocked`'s
//! consult shape (`normalize` + exact host match) so the cloak path consults it the SAME way the blocklist
//! consults its trie — a host-name → loopback decision, read-only, never perturbing any fingerprint. This
//! round defines + tests the seam; the datapath wiring (the cloak-rules-file write at
//! `PathVars.java:280 getDNSCryptCloakingRulesPath`, or an in-resolver consult) lands with the Forge crew.

#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use super::cache::ContentHash;
use crate::signature::verify_minisign;

/// Catalog wire magic — a DISTINCT artifact family from the blocklist's `b"TBLK"` (`blocklist.rs:61`), so a
/// blocklist `.tblk` and a CDN catalog can never be confused on the shared signed channel (the §3.7-Q7
/// artifact-family collision concern, made concrete in the magic byte).
const CATALOG_MAGIC: [u8; 4] = *b"TCAT";
/// The catalog wire-format version (bumped only on an incompatible layout change).
const CATALOG_VERSION: u16 = 1;
/// ★ #22 slice 2 — TCAT v2: identical layout to v1 EXCEPT the off-8 reserved u64 becomes the
/// authored-at freshness epoch (unix secs). The parser accepts v1 AND v2 (v1 catalogs — e.g. the
/// offline GHC brain's — keep verifying forever with epoch 0); the device encoder authors v2. This
/// is a compatible SPEND of the v1 reservation, not a layout change: every field offset is shared.
const CATALOG_VERSION_FRESHNESS: u16 = 2;
/// BLAKE2b-256 content-address digest id — the SAME digest the content-addressed cache
/// use (`cache.rs:47 ContentHash`), NEVER the forgeable FNV (`blocklist.rs:362`,
/// flagged at `signature.rs:14-18`). The id space across the signed channel: `0` = FNV-1a (the `.tblk`
/// set-integrity self-check, `blocklist.rs:63` — REJECTED here as a content-address digest), `1` = the
/// legacy SHA-256 spine (RESERVED + REJECTED below for back-compat clarity, never re-used), `2` = the
/// BLAKE2b-256 spine this build accepts.
const HASH_ALGO_BLAKE2B: u8 = 2;
/// The legacy SHA-256 content-address id (`1`). The spine moved off SHA-256 to BLAKE2b-256 — this id is
/// kept ONLY as a named reserved value so the id is never accidentally re-used for a future algo, and to
/// DOCUMENT that a stale SHA-256-tagged catalog (`hash_algo_id == 1`) is REJECTED by the
/// `!= HASH_ALGO_BLAKE2B` parse gate (not silently re-interpreted). Reserved/rejected, never accepted.
const HASH_ALGO_SHA256_LEGACY: u8 = 1;

/// How many signed catalogs were refused for carrying the RETIRED SHA-256 content-address id.
///
/// This is the device-observable half of [`CatalogError::LegacyHashAlgo`] — see the comment at the
/// gate for why the typed variant alone would not survive the downstream boundaries.
///
/// Non-zero means a correctly-signed but PRE-MIGRATION catalog reached this device: the operator
/// should re-fetch a current one. It does NOT indicate corruption or an attack.
static LEGACY_ALGO_REJECTIONS: AtomicU64 = AtomicU64::new(0);

/// Reader for [`LEGACY_ALGO_REJECTIONS`]. Honest zero is the expected reading.
pub fn legacy_algo_rejections() -> u64 {
    LEGACY_ALGO_REJECTIONS.load(Ordering::Relaxed)
}

// ★ THERE IS DELIBERATELY NO `reset_..._for_test()` HERE (removed 2026-08-01).
//
// One existed and was never called, which the compiler reported as dead code. It was not merely
// unused -- it was UNUSABLE, and keeping it around was an invitation to a flaky suite. This counter
// is PROCESS-GLOBAL and the test runner is parallel, so a reset performed by one test lands in the
// middle of another test's measurement. `a_retired_algorithm_catalog_moves_the_alarm` records that
// exact failure being observed for a weaker reason (`left: 2, right: 1`, because a 256-id sweep in
// a sibling test bumped the same counter concurrently).
//
// The pattern that survives parallelism, and the one every test here uses instead:
//
//     let _g = LEGACY_ALARM_TEST_LOCK.lock()...;     // serialize against other counter tests
//     let before = legacy_algo_rejections();          // measure a DELTA, never an absolute
//     ... trip the real gate ...
//     assert_eq!(legacy_algo_rejections(), before + 1);
//
// Note the delta is asserted with `==`, not `>=`: a `>=` would pass just as happily if unrelated
// code bumped the counter, which is precisely what the alarm exists to detect.
/// Fixed header length: magic(4) + version(2) + algo(1) + flags(1) + reserved(8) + count(4) + reserved2(4).
const CATALOG_HEADER_LEN: usize = 24;

/// The sentinel IP every cloaked host resolves to (the local mirror answers instead of the real CDN).
/// `10.1.10.3` ([`crate::resolver::local::CLOAK_SENTINEL_V4`]) — NOT `127.0.0.1`: a loopback answer
/// escapes the tun (apps route `127/8` locally, bypassing the ARMED datapath), so cloaked answers must
/// ride the tun sentinel the forwarder recognizes and hairpins to the mirror (`server.rs`).
const CLOAK_LOOPBACK: IpAddr = IpAddr::V4(crate::resolver::local::CLOAK_SENTINEL_V4);

/// Per-entry flag: the asset's host is DNS-cloaked to `127.0.0.1`. Bit 0 of an entry's `entry_flags` byte.
const ENTRY_FLAG_CLOAK: u8 = 0b0000_0001;
/// Every other entry-flag bit is reserved (must be 0) — an unknown flag bit is a `Malformed` reject, so a
/// future flag can't be silently ignored by an old build.
const ENTRY_FLAGS_KNOWN_MASK: u8 = ENTRY_FLAG_CLOAK;

/// Bounds on the variable-width body fields (DNS-realistic; reject pathological lengths before allocating —
/// the `blocklist.rs:36-39 MAX_NAME_LEN/MAX_LINE_BYTES` bounded-reader discipline).
const MAX_NAME_BYTES: usize = 512;
/// A hostname is at most 253 bytes on the wire (DNS limit, `blocklist.rs:36`); cap there.
const MAX_HOST_BYTES: usize = 253;
/// A hard ceiling on entry_count so a forged header can't make us pre-reserve unbounded memory. (The body
/// length is still validated byte-by-byte; this only bounds the up-front `Vec::with_capacity`.)
const MAX_ENTRIES: usize = 100_000;

/// One catalog entry: an asset pinned by its content address, the loopback name the server routes on, and
/// the CDN host (cloaked or not).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogEntry {
    /// The asset's request name (the loopback path the server serves it under, e.g. a list filename).
    pub name: String,
    /// The CDN hostname this asset belongs to (e.g. `cdnjs.cloudflare.com`) — the cloak-set member.
    pub host: String,
    /// The asset's BLAKE2b-256 content address — the cache key the server matches against (content-addressed).
    pub content_hash: ContentHash,
    /// Is this asset's host DNS-cloaked to `127.0.0.1` (the mirror answers instead of the real CDN)?
    pub cloaked: bool,
}

/// The DNS-cloak seam: the set of hostnames the resolver/blocklist cloak path should answer as `127.0.0.1`.
///
/// This is the SPEC of the seam (this round), not the datapath wiring. [`CloakSet::cloak_ip`] mirrors the
/// `blocklist.rs:211 is_blocked` consult shape — normalize the queried name, exact-match the host set —
/// so the cloak path consults it the SAME way the blocklist consults its trie. It is READ-ONLY and feeds
/// no fingerprint (the `trust.rs:567 score_never_perturbs_fingerprint` invariant: cloaking rides ALONGSIDE
/// the set, never inside any hash).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CloakSet {
    /// Sorted, de-duplicated, normalized cloaked hostnames (sorted for deterministic iteration + a stable
    /// cloak-rules-file write, mirroring the `blocklist.rs:60` sorted-on-disk discipline).
    hosts: Vec<String>,
}

impl CloakSet {
    /// True iff `host` (after normalization) is in the cloak set — the cloak path's verdict query.
    pub fn is_cloaked(&self, host: &str) -> bool {
        let h = normalize_host(host);
        if h.is_empty() {
            return false;
        }
        self.hosts.binary_search(&h).is_ok()
    }

    /// The sentinel IP a cloaked host resolves to, or `None` if `host` is not cloaked. This is the seam the
    /// resolver/blocklist cloak path consults: a `Some(10.1.10.3)` means "answer locally" (mirror it),
    /// `None` means "let it resolve normally". Mirrors `is_blocked`'s `Some/None`-shaped verdict.
    pub fn cloak_ip(&self, host: &str) -> Option<IpAddr> {
        if self.is_cloaked(host) {
            Some(CLOAK_LOOPBACK)
        } else {
            None
        }
    }

    /// Borrow the sorted, normalized cloaked hostnames (the cloak-rules-file write source, `PathVars.java:280`).
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// The number of cloaked hosts.
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Is the cloak set empty?
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

/// A signature-verified Centauri catalog: the set of assets the mirror is authorized to serve.
///
/// Constructed ONLY via [`Catalog::parse_verified`], so a `Catalog` value is proof that the minisign
/// signature over the catalog bytes verified against the pinned Centauri key. An unverified catalog never
/// becomes a `Catalog` (parse-don't-validate: the verified body is the only path into the type).
#[derive(Clone, Debug, Default)]
pub struct Catalog {
    entries: Vec<CatalogEntry>,
    /// The v2 freshness epoch: unix seconds the author stamped at signing. `0` for a v1 catalog (the
    /// reservation era) or an author that declined to stamp — 0 always reads as "freshness unknown",
    /// never as 1970-is-stale (consumers must treat 0 as absent, not ancient).
    authored_at_secs: u64,
}

/// Why a catalog was rejected — never an unwinding error across the boundary, always a typed verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogError {
    /// The minisign signature over the catalog bytes did not verify (verify-sig-FIRST gate failed).
    BadSignature,
    /// The signature verified, but the catalog body was malformed: a bad magic / version / hash-algo id, a
    /// truncated record, an out-of-bounds length, an unknown flag bit, or non-UTF-8 name/host bytes.
    Malformed,
    /// The signature verified and the body is well-formed, but it is tagged with the RETIRED
    /// SHA-256 content-address id (`HASH_ALGO_SHA256_LEGACY` = 1). The spine moved to BLAKE2b-256.
    ///
    /// Rejected exactly as hard as `Malformed` — this variant weakens nothing, and the accept gate
    /// is still "id == BLAKE2b and nothing else". It exists because the two mean different things
    /// to whoever has to act: `Malformed` says the file is corrupt or hostile, while this says the
    /// file is INTACT and simply predates the spine migration, so the fix is "re-fetch a current
    /// catalog", not "your download is broken". Collapsing them sends an operator hunting a
    /// corruption that is not there.
    LegacyHashAlgo,
}

impl Catalog {
    /// Parse a catalog ONLY after its minisign signature verifies — the verify-sig-FIRST contract.
    ///
    /// - `bytes`       : the RAW catalog bytes (the exact bytes the offline GHC brain signed).
    /// - `sig_blob`    : the base64-DECODED 74-byte minisign signature blob (caller decodes the `.minisig`).
    /// - `pubkey_blob` : the base64-DECODED 42-byte pinned Centauri public key.
    ///
    /// Returns the verified [`Catalog`] on success, or a [`CatalogError`] (`BadSignature` if the gate
    /// fails — checked FIRST, before any parsing; `Malformed` if the verified body cannot be read). Never
    /// panics on any input — every length read is bounds-checked, never an unwrap on attacker bytes (the
    /// `signature.rs:121` FFI-input discipline).
    pub fn parse_verified(
        bytes: &[u8],
        sig_blob: &[u8],
        pubkey_blob: &[u8],
    ) -> Result<Catalog, CatalogError> {
        // Step 1 — verify-sig-FIRST. REUSE the shipped minisign verifier verbatim (no duplicate Ed25519).
        // A `false` here means tampered/forged/absent → reject before a single body byte is interpreted.
        if !verify_minisign(bytes, sig_blob, pubkey_blob) {
            return Err(CatalogError::BadSignature);
        }
        // Step 2 — only now read the (authenticated) body. The signature already covers these exact bytes,
        // so a structural failure here is a producer bug, never an attack vector — still a typed `Malformed`,
        // never a panic.
        Self::parse_body(bytes)
    }

    /// Parse the (already signature-verified) catalog body into entries.
    ///
    /// Fail-CLOSED: any header mismatch, truncation, out-of-bounds length, unknown flag, or non-UTF-8 field
    /// yields `Malformed` (never a partial catalog, never a panic). The whole-body Ed25519 signature already
    /// covers these bytes; this validates the STRUCTURE the producer must honor.
    fn parse_body(verified: &[u8]) -> Result<Catalog, CatalogError> {
        if verified.len() < CATALOG_HEADER_LEN {
            return Err(CatalogError::Malformed);
        }
        // --- Header (fixed 24 bytes, little-endian) ---
        if verified[0..4] != CATALOG_MAGIC {
            return Err(CatalogError::Malformed);
        }
        let version = u16::from_le_bytes([verified[4], verified[5]]);
        if version != CATALOG_VERSION && version != CATALOG_VERSION_FRESHNESS {
            return Err(CatalogError::Malformed);
        }
        // Only the BLAKE2b-256 content-address digest is accepted. The legacy SHA-256 id
        // (`HASH_ALGO_SHA256_LEGACY` = 1) and the FNV id (`0`) are both REJECTED here — a stale or
        // wrong-algo catalog never parses, returning a typed `Malformed` (NEVER a panic, the
        // `catalog.rs` "never panics on any input" FFI-input discipline).
        if verified[6] == HASH_ALGO_SHA256_LEGACY {
            // Same rejection, distinguishable reason. An INTACT pre-migration catalog is not a
            // corrupt one, and telling an operator "malformed" would send them hunting a
            // corruption that does not exist. The accept gate below is unchanged.
            //
            // The counter is not redundant with the typed variant. Every CURRENT downstream
            // boundary (`blocklist/catalogs.rs`, `lib.rs`, `mirror/object.rs`) folds this back into
            // its own `Malformed`, because widening three more error enums would cascade into the
            // Kotlin bindings for a diagnostic. Without the counter the distinction would therefore
            // be ERASED everywhere the device can see it, and the typed variant would be
            // decorative — a reason that exists only in a signature nobody reads.
            LEGACY_ALGO_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            return Err(CatalogError::LegacyHashAlgo);
        }
        if verified[6] != HASH_ALGO_BLAKE2B {
            return Err(CatalogError::Malformed);
        }
        if verified[7] != 0 {
            return Err(CatalogError::Malformed); // reserved header flags must be 0
        }
        // off 8..16 — v1: reserved u64, must be 0 (the strict-reservation law keeps the field
        // spendable). v2: the authored-at freshness epoch, any value (0 = "author declined").
        let authored_at_secs = if version == CATALOG_VERSION_FRESHNESS {
            u64::from_le_bytes([
                verified[8],
                verified[9],
                verified[10],
                verified[11],
                verified[12],
                verified[13],
                verified[14],
                verified[15],
            ])
        } else {
            if verified[8..16].iter().any(|&b| b != 0) {
                return Err(CatalogError::Malformed);
            }
            0
        };
        let entry_count =
            u32::from_le_bytes([verified[16], verified[17], verified[18], verified[19]]) as usize;
        // off 20..24 reserved2 u32 — must be 0.
        if verified[20..24].iter().any(|&b| b != 0) {
            return Err(CatalogError::Malformed);
        }
        if entry_count > MAX_ENTRIES {
            return Err(CatalogError::Malformed);
        }

        // --- Body: `entry_count` variable-width records, parsed with a moving, bounds-checked cursor ---
        let mut entries: Vec<CatalogEntry> = Vec::with_capacity(entry_count);
        let mut cur = CATALOG_HEADER_LEN;

        for _ in 0..entry_count {
            // entry_flags (1 byte)
            let entry_flags = *verified.get(cur).ok_or(CatalogError::Malformed)?;
            cur += 1;
            if entry_flags & !ENTRY_FLAGS_KNOWN_MASK != 0 {
                return Err(CatalogError::Malformed); // an unknown flag bit ⇒ reject (no silent ignore)
            }
            let cloaked = entry_flags & ENTRY_FLAG_CLOAK != 0;

            // content_hash (32 bytes)
            let hash_end = cur.checked_add(32).ok_or(CatalogError::Malformed)?;
            let hash_slice = verified.get(cur..hash_end).ok_or(CatalogError::Malformed)?;
            let mut content_hash: ContentHash = [0u8; 32];
            content_hash.copy_from_slice(hash_slice);
            cur = hash_end;

            // name: u16 LE len + UTF-8 bytes
            let name = read_len_prefixed_str(verified, &mut cur, MAX_NAME_BYTES)?;
            // host: u16 LE len + UTF-8 bytes
            let host = read_len_prefixed_str(verified, &mut cur, MAX_HOST_BYTES)?;

            entries.push(CatalogEntry {
                name,
                host: normalize_host(&host),
                content_hash,
                cloaked,
            });
        }

        // No trailing garbage after the declared records (a length-confusion guard, `dns.rs`-style strictness).
        if cur != verified.len() {
            return Err(CatalogError::Malformed);
        }

        Ok(Catalog {
            entries,
            authored_at_secs,
        })
    }

    /// Borrow the authorized asset entries.
    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    /// The v2 freshness epoch (unix secs the author stamped at signing), `0` = unknown (a v1 catalog
    /// or an author that declined). Consumers MUST read 0 as "absent", never as "ancient" — the age
    /// math is `now - epoch` ONLY when `epoch != 0` (★ #22 slice 2).
    pub fn authored_at_secs(&self) -> u64 {
        self.authored_at_secs
    }

    /// Look up an asset's content address by its request name (the server's routing query).
    pub fn content_hash_for(&self, name: &str) -> Option<ContentHash> {
        self.entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.content_hash)
    }

    /// Project the verified catalog into the [`CloakSet`] — the DNS-cloak seam the resolver/blocklist path
    /// consults. Only entries flagged `cloaked` contribute their (normalized) host; the result is sorted +
    /// de-duplicated so the lookup is a `binary_search` (the `is_cloaked` consult). This is the seam, not
    /// the datapath: the Forge crew wires it into the cloak-rules write / in-resolver consult.
    pub fn cloak_set(&self) -> CloakSet {
        let mut hosts: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.cloaked)
            .map(|e| e.host.clone()) // already normalized at parse time
            .filter(|h| !h.is_empty())
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        CloakSet { hosts }
    }

    /// The number of authorized assets in the catalog.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the catalog empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Read a `u16` little-endian length-prefixed UTF-8 string at `*cur`, advancing the cursor. Bounds-checked
/// (length ≤ `max` and within the buffer) and UTF-8-validated; any failure is `Malformed`, never a panic.
fn read_len_prefixed_str(buf: &[u8], cur: &mut usize, max: usize) -> Result<String, CatalogError> {
    let len_end = cur.checked_add(2).ok_or(CatalogError::Malformed)?;
    let len_bytes = buf.get(*cur..len_end).ok_or(CatalogError::Malformed)?;
    let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
    if len == 0 || len > max {
        return Err(CatalogError::Malformed); // empty or over-long field ⇒ reject
    }
    let str_end = len_end.checked_add(len).ok_or(CatalogError::Malformed)?;
    let str_bytes = buf.get(len_end..str_end).ok_or(CatalogError::Malformed)?;
    let s = std::str::from_utf8(str_bytes)
        .map_err(|_| CatalogError::Malformed)?
        .to_string();
    *cur = str_end;
    Ok(s)
}

/// Normalize a hostname for cloak-set membership: trim, lowercase, drop a single trailing dot (FQDN form).
/// Mirrors the spirit of `blocklist.rs normalize` (the consult-shape parity) so a queried name and a
/// catalog host compare identically. Pure ASCII-fold only (a punycode `xn--` host stays as-is — the
/// homograph layer is the DNS Guardian's concern, §2.C, deliberately NOT folded here).
fn normalize_host(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.');
    trimmed.to_ascii_lowercase()
}

/// Encode a well-formed `TCAT` catalog body for `entries` — the PRODUCTION authoring twin of the parser
/// [`Catalog::parse_verified`] (they share ONE byte layout, so a round-trip is guaranteed by construction).
/// The offline GHC brain OR an on-device [`super::devkey::DeviceKey`] signs the bytes this returns; the
/// signature covers the WHOLE body. Emits the pinned BLAKE2b-256 hash-algo id and zeroed reserved fields, so
/// the output parses IFF each entry is within bounds (name `1..=MAX_NAME_BYTES`, host `1..=MAX_HOST_BYTES`);
/// names/hosts are emitted verbatim (the caller is the trusted author — the parser normalizes the host on
/// read). A name/host longer than `u16::MAX` would truncate its length prefix and then fail the parser's
/// bounds gate (never a wrong-but-parseable catalog); realistic catalog fields are far under that.
/// ★ #22 slice 2 — the encoder authors TCAT v2: `authored_at_secs` is the freshness epoch stamped
/// into the off-8 field (pass the signing moment's unix secs; `0` = decline the stamp — still a
/// valid v2 catalog that reads as "freshness unknown"). Deterministic for a fixed input (tests pass
/// a pinned epoch, never a live clock).
pub fn encode_catalog(entries: &[CatalogEntry], authored_at_secs: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&CATALOG_MAGIC);
    out.extend_from_slice(&CATALOG_VERSION_FRESHNESS.to_le_bytes());
    out.push(HASH_ALGO_BLAKE2B);
    out.push(0u8); // header flags (reserved, must be 0)
    out.extend_from_slice(&authored_at_secs.to_le_bytes()); // v2: the freshness epoch
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
    for e in entries {
        let flags = if e.cloaked { ENTRY_FLAG_CLOAK } else { 0 };
        out.push(flags);
        out.extend_from_slice(&e.content_hash);
        let nb = e.name.as_bytes();
        out.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        out.extend_from_slice(nb);
        let hb = e.host.as_bytes();
        out.extend_from_slice(&(hb.len() as u16).to_le_bytes());
        out.extend_from_slice(hb);
    }
    out
}

#[cfg(test)]
mod tests {

    /// A5 GUARD -- `MAX_HOST_BYTES` (= 253, catalog.rs:129) is the per-field ceiling handed to
    /// `read_len_prefixed_str`, the length-prefixed reader that walks a SIGNATURE-VERIFIED catalog
    /// blob. The A5 inventory found it had a NUMBER and no test naming it.
    ///
    /// The reader is the one place a 16-bit length from the blob decides how far the cursor moves,
    /// so it carries four separate refusals. Verified bytes are not TRUSTED bytes: a signature says
    /// the publisher sent them, not that they are well-formed, and the whole point of this reader
    /// is that a malformed field is refused rather than walked off the end of the buffer.
    #[test]
    fn len_prefixed_reader_refuses_every_malformed_shape() {
        // A well-formed field at exactly the ceiling is ACCEPTED (non-vacuity first).
        let host = "a".repeat(MAX_HOST_BYTES);
        let mut buf = (host.len() as u16).to_le_bytes().to_vec();
        buf.extend_from_slice(host.as_bytes());
        let mut cur = 0usize;
        let got = read_len_prefixed_str(&buf, &mut cur, MAX_HOST_BYTES).expect("at the ceiling");
        assert_eq!(got.len(), MAX_HOST_BYTES, "a field AT the cap must parse");
        assert_eq!(cur, buf.len(), "the cursor advances exactly past the field");

        // (1) OVER the ceiling -> refused, even though the bytes are all present.
        let big = "a".repeat(MAX_HOST_BYTES + 1);
        let mut buf2 = (big.len() as u16).to_le_bytes().to_vec();
        buf2.extend_from_slice(big.as_bytes());
        let mut cur2 = 0usize;
        assert!(
            read_len_prefixed_str(&buf2, &mut cur2, MAX_HOST_BYTES).is_err(),
            "a field OVER the cap must be refused"
        );
        assert_eq!(cur2, 0, "a refused read must NOT advance the cursor");

        // (2) a ZERO length is refused (an empty field is malformed, not an empty string).
        let mut cur3 = 0usize;
        assert!(
            read_len_prefixed_str(&[0, 0, b'x'], &mut cur3, MAX_HOST_BYTES).is_err(),
            "a zero-length field must be refused"
        );

        // (3) a length that RUNS PAST the buffer is refused -- the over-read this reader exists
        //     to prevent. 8 declared, 3 present.
        let mut cur4 = 0usize;
        assert!(
            read_len_prefixed_str(&[8, 0, b'a', b'b', b'c'], &mut cur4, MAX_HOST_BYTES).is_err(),
            "a length past the end of the buffer must be refused, never over-read"
        );

        // (4) non-UTF-8 bytes are refused rather than lossily substituted.
        let mut cur5 = 0usize;
        assert!(
            read_len_prefixed_str(&[2, 0, 0xFF, 0xFE], &mut cur5, MAX_HOST_BYTES).is_err(),
            "invalid UTF-8 must be refused, never replaced with U+FFFD"
        );
    }
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_KEY_ID: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];

    // ---- minisign blob helpers (mirror signature.rs:148/157 EXACTLY — the legacy `Ed` shape) ----

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

    // ---- catalog wire-format builder (the producer's exact byte layout, host-side) ----

    struct WireEntry {
        name: &'static str,
        host: &'static str,
        content_hash: [u8; 32],
        cloaked: bool,
    }

    /// Encode a well-formed `TCAT` catalog body for the given test entries — delegates to the PRODUCTION
    /// [`encode_catalog`] (the `&'static str` `WireEntry` is a test-authoring convenience; ONE encoder, so
    /// the byte layout can never drift between test vectors and the shipped author).
    fn build_catalog(entries: &[WireEntry]) -> Vec<u8> {
        let cat: Vec<CatalogEntry> = entries
            .iter()
            .map(|e| CatalogEntry {
                name: e.name.to_string(),
                host: e.host.to_string(), // verbatim (the parser normalizes on read) — layout parity
                content_hash: e.content_hash,
                cloaked: e.cloaked,
            })
            .collect();
        encode_catalog(&cat, 1_784_000_000) // pinned v2 epoch — deterministic test bytes
    }

    fn signed(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let sig = sign_legacy(&sk, &TEST_KEY_ID, bytes);
        let pubkey = make_pubkey_blob(&pk, &TEST_KEY_ID);
        (sig, pubkey)
    }

    fn sample_entries() -> Vec<WireEntry> {
        vec![
            WireEntry {
                name: "jquery-3.7.1.min.js",
                host: "cdnjs.cloudflare.com",
                content_hash: [0x11; 32],
                cloaked: true,
            },
            WireEntry {
                name: "roboto.css",
                host: "fonts.googleapis.com",
                content_hash: [0x22; 32],
                cloaked: true,
            },
            WireEntry {
                name: "uncloaked-asset.js",
                host: "unpkg.com",
                content_hash: [0x33; 32],
                cloaked: false,
            },
        ]
    }

    // ---- verify-sig-FIRST gate ----

    #[test]
    fn parse_rejects_bad_signature_before_parsing() {
        // A well-formed catalog body but a bogus signature ⇒ BadSignature, body never interpreted.
        let body = build_catalog(&sample_entries());
        let bogus_sig = [0u8; 74];
        let (_good_sig, pubkey) = signed(&body);
        let verdict = Catalog::parse_verified(&body, &bogus_sig, &pubkey);
        assert_eq!(
            verdict.unwrap_err(),
            CatalogError::BadSignature,
            "verify-sig-FIRST: a bad signature is rejected before any body parse"
        );
    }

    #[test]
    fn parse_rejects_tampered_body_at_the_signature_gate() {
        // Sign the genuine body, then flip one cloak flag. The whole-body Ed25519 signature covers it, so
        // verify_minisign fails — the tampered catalog never parses (signature.rs:46-48 parity).
        let body = build_catalog(&sample_entries());
        let (sig, pubkey) = signed(&body);
        let mut tampered = body.clone();
        // The first entry's flags byte sits right after the 24-byte header.
        tampered[CATALOG_HEADER_LEN] ^= ENTRY_FLAG_CLOAK;
        assert_eq!(
            Catalog::parse_verified(&tampered, &sig, &pubkey).unwrap_err(),
            CatalogError::BadSignature,
            "a post-sign body mutation must fail at the signature gate"
        );
    }

    // ---- valid → parsed host/hash set ----

    #[test]
    fn device_signed_catalog_round_trips_against_its_own_pubkey() {
        // Rung 2: a per-device DeviceKey AUTHORS a content catalog (production encode_catalog) + the mirror
        // VERIFIES it against THAT device's own pubkey — the ownership loop closed engine-side.
        use crate::mirror::devkey::DeviceKey;
        let key = DeviceKey::from_seed(&[0x5a; 32]);
        let entries = vec![CatalogEntry {
            name: "nautilus-offline/index.html".to_string(),
            host: "nautilus.local".to_string(),
            content_hash: [0xab; 32],
            cloaked: false,
        }];
        let body = encode_catalog(&entries, 1_784_000_000);
        let sig = key.sign(&body);
        let cat = Catalog::parse_verified(&body, &sig, &key.pubkey_blob())
            .expect("a device-signed catalog verifies against its own device pubkey");
        assert_eq!(
            cat.authored_at_secs(),
            1_784_000_000,
            "the v2 freshness epoch round-trips through sign + verify + parse"
        );
        assert_eq!(cat.len(), 1);
        assert_eq!(
            cat.content_hash_for("nautilus-offline/index.html"),
            Some([0xab; 32])
        );
        // A DIFFERENT device's pubkey MUST reject it — per-device authority, no cross-device trust.
        let other = DeviceKey::from_seed(&[0x5b; 32]);
        assert_eq!(
            Catalog::parse_verified(&body, &sig, &other.pubkey_blob()).unwrap_err(),
            CatalogError::BadSignature,
            "another install's key is not this install's authority"
        );
    }

    #[test]
    fn parse_accepts_and_reads_a_genuinely_signed_catalog() {
        let body = build_catalog(&sample_entries());
        let (sig, pubkey) = signed(&body);
        let cat = Catalog::parse_verified(&body, &sig, &pubkey)
            .expect("a genuinely signed, well-formed catalog must verify-then-parse");
        assert_eq!(cat.len(), 3);

        // host + hash set is read back exactly.
        assert_eq!(
            cat.content_hash_for("jquery-3.7.1.min.js"),
            Some([0x11; 32])
        );
        assert_eq!(cat.content_hash_for("roboto.css"), Some([0x22; 32]));
        assert_eq!(cat.content_hash_for("unpkg-missing"), None);

        let e0 = &cat.entries()[0];
        assert_eq!(e0.name, "jquery-3.7.1.min.js");
        assert_eq!(e0.host, "cdnjs.cloudflare.com");
        assert!(e0.cloaked);
        assert!(
            !cat.entries()[2].cloaked,
            "the uncloaked entry stays uncloaked"
        );
    }

    #[test]
    fn empty_catalog_is_well_defined() {
        let body = build_catalog(&[]);
        let (sig, pubkey) = signed(&body);
        let cat = Catalog::parse_verified(&body, &sig, &pubkey)
            .expect("an empty signed catalog is valid");
        assert!(cat.is_empty());
        assert_eq!(cat.len(), 0);
        assert!(cat.cloak_set().is_empty(), "no entries ⇒ no cloaked hosts");
    }

    // ---- the DNS-cloak seam ----

    #[test]
    fn cloak_set_collects_only_cloaked_hosts_sorted_deduped() {
        let body = build_catalog(&sample_entries());
        let (sig, pubkey) = signed(&body);
        let cat = Catalog::parse_verified(&body, &sig, &pubkey).unwrap();
        let cloak = cat.cloak_set();

        // Only the two cloaked hosts; the uncloaked unpkg.com is absent; sorted.
        assert_eq!(
            cloak.hosts(),
            &[
                "cdnjs.cloudflare.com".to_string(),
                "fonts.googleapis.com".to_string()
            ]
        );
        assert_eq!(cloak.len(), 2);
        assert!(
            !cloak.hosts().iter().any(|h| h == "unpkg.com"),
            "an uncloaked host never enters the seam"
        );
    }

    #[test]
    fn cloak_ip_maps_a_cloaked_host_to_loopback_and_others_to_none() {
        let body = build_catalog(&sample_entries());
        let (sig, pubkey) = signed(&body);
        let cat = Catalog::parse_verified(&body, &sig, &pubkey).unwrap();
        let cloak = cat.cloak_set();

        assert_eq!(
            cloak.cloak_ip("cdnjs.cloudflare.com"),
            Some(IpAddr::V4(crate::resolver::local::CLOAK_SENTINEL_V4)),
            "a cloaked host resolves to the 10.1.10.3 tun sentinel"
        );
        assert!(cloak.is_cloaked("fonts.googleapis.com"));
        assert_eq!(
            cloak.cloak_ip("unpkg.com"),
            None,
            "an uncloaked host is not redirected"
        );
        assert_eq!(
            cloak.cloak_ip("example.com"),
            None,
            "an off-catalog host is never cloaked"
        );
    }

    #[test]
    fn cloak_lookup_normalizes_like_the_blocklist_consult() {
        // The seam mirrors blocklist.rs:211 is_blocked's normalize-then-match shape: a trailing dot + mixed
        // case + surrounding whitespace must match the stored host.
        let body = build_catalog(&sample_entries());
        let (sig, pubkey) = signed(&body);
        let cat = Catalog::parse_verified(&body, &sig, &pubkey).unwrap();
        let cloak = cat.cloak_set();

        assert!(
            cloak.is_cloaked("CDNJS.Cloudflare.COM"),
            "case-insensitive host match"
        );
        assert!(
            cloak.is_cloaked("cdnjs.cloudflare.com."),
            "trailing FQDN dot is normalized away"
        );
        assert!(
            cloak.is_cloaked("  fonts.googleapis.com  "),
            "surrounding whitespace is trimmed"
        );
        assert!(!cloak.is_cloaked(""), "the empty query is never cloaked");
    }

    #[test]
    fn parse_normalizes_a_mixed_case_host_into_the_entry() {
        // A producer that emits a mixed-case host still lands normalized, so the cloak seam is consistent.
        let entries = vec![WireEntry {
            name: "x.js",
            host: "CDN.Example.COM.",
            content_hash: [0x44; 32],
            cloaked: true,
        }];
        let body = build_catalog(&entries);
        let (sig, pubkey) = signed(&body);
        let cat = Catalog::parse_verified(&body, &sig, &pubkey).unwrap();
        assert_eq!(
            cat.entries()[0].host,
            "cdn.example.com",
            "host normalized at parse time"
        );
        assert!(cat.cloak_set().is_cloaked("cdn.example.com"));
    }

    // ---- malformed body rejects (post-signature structural strictness) ----

    /// Re-sign a (possibly mutated) body so it passes the signature gate, isolating the body parser.
    fn parse_resigned(body: &[u8]) -> Result<Catalog, CatalogError> {
        let (sig, pubkey) = signed(body);
        Catalog::parse_verified(body, &sig, &pubkey)
    }

    #[test]
    fn rejects_bad_magic() {
        let mut body = build_catalog(&sample_entries());
        body[0] = b'X'; // corrupt the magic
        assert_eq!(parse_resigned(&body).unwrap_err(), CatalogError::Malformed);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut body = build_catalog(&sample_entries());
        body[4] = 0x09; // version low byte → 9
        assert_eq!(parse_resigned(&body).unwrap_err(), CatalogError::Malformed);
    }

    /// `LEGACY_ALGO_REJECTIONS` is a PROCESS-GLOBAL counter, so any two tests that trip it cannot
    /// run concurrently and still make exact-delta assertions. Measured, not guessed: this test
    /// first failed with `left: 2, right: 1` because `rejects_wrong_hash_algo_id`'s 256-id sweep
    /// includes id 1 and was incrementing the same counter in parallel.
    ///
    /// Serialized rather than weakened to `>=`. A `>=` assertion would pass just as happily if the
    /// counter were bumped by unrelated code, which is precisely what it is supposed to detect.
    static LEGACY_ALARM_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The retired-algorithm alarm moves when a REAL pre-migration catalog is refused, through the
    /// real gate with the real signed fixture -- not a synthetic counter bump.
    ///
    /// Without this the counter could be a constant zero and every other integrity test would
    /// still pass, because they only assert it is non-negative.
    #[test]
    fn a_retired_algorithm_catalog_moves_the_alarm() {
        let _g = LEGACY_ALARM_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let before = legacy_algo_rejections();

        let mut body_legacy = build_catalog(&sample_entries());
        body_legacy[6] = HASH_ALGO_SHA256_LEGACY;
        assert_eq!(
            parse_resigned(&body_legacy).unwrap_err(),
            CatalogError::LegacyHashAlgo
        );

        assert_eq!(
            legacy_algo_rejections(),
            before + 1,
            "refusing a retired-algorithm catalog must MOVE the alarm, or the device-observable \
             half of the reason does not exist and the typed variant is decorative"
        );

        // A catalog refused for a DIFFERENT reason must NOT move this alarm -- otherwise it is a
        // generic rejection counter wearing a specific name.
        let mark = legacy_algo_rejections();
        let mut body_fnv = build_catalog(&sample_entries());
        body_fnv[6] = 0x00;
        assert_eq!(
            parse_resigned(&body_fnv).unwrap_err(),
            CatalogError::Malformed
        );
        assert_eq!(
            legacy_algo_rejections(),
            mark,
            "an unknown-algorithm rejection must NOT be counted as a retired-algorithm one"
        );
    }

    #[test]
    fn rejects_wrong_hash_algo_id() {
        // Shares the process-global legacy alarm with the test above (its 256-id sweep trips id 1).
        let _g = LEGACY_ALARM_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // The FNV id (`0`) — forbidden as a content-address digest.
        let mut body = build_catalog(&sample_entries());
        body[6] = 0x00;
        assert_eq!(parse_resigned(&body).unwrap_err(), CatalogError::Malformed);

        // The LEGACY SHA-256 id (`1`) — the spine moved to BLAKE2b-256; a stale SHA-256-tagged catalog is
        // REJECTED, never silently re-interpreted (the migration's back-compat property).
        //
        // The expected value moved from `Malformed` to `LegacyHashAlgo` in the same edit that
        // introduced the variant. Justified from the property, not from what makes this pass: the
        // SECURITY claim is "id 1 is refused", and that is unchanged and still asserted by
        // `unwrap_err()` below. What changed is only the reported REASON, which is now strictly
        // more precise — an intact pre-migration catalog is no longer described as corrupt.
        let mut body_legacy = build_catalog(&sample_entries());
        body_legacy[6] = 0x01;
        let legacy_err = parse_resigned(&body_legacy).unwrap_err();
        assert_eq!(legacy_err, CatalogError::LegacyHashAlgo);
        assert_ne!(
            legacy_err,
            CatalogError::Malformed,
            "the retired-algorithm reason must stay DISTINGUISHABLE from corruption, or adding the \
             variant bought nothing"
        );

        // Every other byte value is refused too. The proof settles all 256 ids
        // (D:\\Lean\\proofs\\Proofs\\CatalogHashAlgo.lean, `every_other_id_is_rejected`); this
        // sweep keeps the Rust honest against that model rather than sampling three values.
        for id in 0u8..=255 {
            if id == 2 {
                continue; // BLAKE2b — the ONLY accepted id
            }
            let mut b = build_catalog(&sample_entries());
            b[6] = id;
            assert!(
                parse_resigned(&b).is_err(),
                "hash_algo_id {id} must be refused; only BLAKE2b (2) is accepted"
            );
        }

        // NON-VACUITY: the accepted id genuinely parses, so the sweep above is not passing merely
        // because every catalog this fixture builds is broken.
        let good = build_catalog(&sample_entries());
        assert_eq!(good[6], 0x02, "the fixture must build a BLAKE2b-tagged catalog");
        assert!(
            parse_resigned(&good).is_ok(),
            "BLAKE2b must be ACCEPTED, or the rejection sweep proves nothing"
        );

        // An unknown future id (`3`) — only the pinned BLAKE2b-256 id (`2`) is accepted.
        let mut body_unknown = build_catalog(&sample_entries());
        body_unknown[6] = 0x03;
        assert_eq!(
            parse_resigned(&body_unknown).unwrap_err(),
            CatalogError::Malformed
        );

        // SANITY: the genuine BLAKE2b-256 id (`2`, what build_catalog emits) parses.
        let good = build_catalog(&sample_entries());
        assert_eq!(good[6], HASH_ALGO_BLAKE2B);
        assert!(
            parse_resigned(&good).is_ok(),
            "the pinned BLAKE2b-256 id is accepted"
        );
    }

    #[test]
    fn rejects_nonzero_reserved_fields() {
        // ★ #22 slice 2 — the off-8 law SPLIT by version: on a v2 body those bytes ARE the
        // freshness epoch (mutating the LSB is a *data* change the re-sign makes valid)…
        let mut body = build_catalog(&sample_entries());
        body[8] = 0x01; // v2: epoch LSB 0x00 → 0x01 ⇒ 1_784_000_000 + 1
        let cat = parse_resigned(&body).expect("v2: off-8 is the epoch, not a reservation");
        assert_eq!(cat.authored_at_secs(), 1_784_000_001);

        // …while a v1 body keeps the strict reservation law: nonzero off-8 ⇒ Malformed.
        let mut v1 = build_catalog(&sample_entries());
        v1[4..6].copy_from_slice(&CATALOG_VERSION.to_le_bytes());
        assert_eq!(
            parse_resigned(&v1).unwrap_err(),
            CatalogError::Malformed,
            "v1 + nonzero off-8 (the epoch bytes the v2 encoder stamped) must stay rejected"
        );

        let mut body2 = build_catalog(&sample_entries());
        body2[7] = 0x01; // reserved header flags must be 0 (both versions)
        assert_eq!(parse_resigned(&body2).unwrap_err(), CatalogError::Malformed);

        let mut body3 = build_catalog(&sample_entries());
        body3[20] = 0x01; // reserved2 u32 must be 0 (both versions)
        assert_eq!(parse_resigned(&body3).unwrap_err(), CatalogError::Malformed);
    }

    #[test]
    fn v1_catalog_still_parses_with_epoch_zero() {
        // ★ #22 slice 2 — the compatibility half of the TCAT v2 spend: a v1 body (version 1,
        // off-8 zeroed — every catalog the offline GHC brain ever signed) parses forever, and its
        // freshness reads as ABSENT (0), never as ancient.
        let mut v1 = build_catalog(&sample_entries());
        v1[4..6].copy_from_slice(&CATALOG_VERSION.to_le_bytes());
        v1[8..16].fill(0);
        let cat = parse_resigned(&v1).expect("a clean v1 body parses under the dual-version gate");
        assert_eq!(cat.entries().len(), sample_entries().len());
        assert_eq!(cat.authored_at_secs(), 0, "v1 ⇒ freshness unknown, epoch 0");
    }

    #[test]
    fn rejects_unknown_entry_flag_bit() {
        let mut body = build_catalog(&sample_entries());
        body[CATALOG_HEADER_LEN] = 0b1000_0000; // an unknown entry-flag bit
        assert_eq!(parse_resigned(&body).unwrap_err(), CatalogError::Malformed);
    }

    #[test]
    fn rejects_truncated_body() {
        let body = build_catalog(&sample_entries());
        let truncated = &body[..body.len() - 5]; // drop the tail of the last record
        assert_eq!(
            parse_resigned(truncated).unwrap_err(),
            CatalogError::Malformed
        );
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut body = build_catalog(&sample_entries());
        body.extend_from_slice(b"GARBAGE"); // extra bytes after the declared records
        assert_eq!(parse_resigned(&body).unwrap_err(), CatalogError::Malformed);
    }

    #[test]
    fn rejects_header_shorter_than_24_bytes() {
        let short = b"TCAT".to_vec();
        assert_eq!(parse_resigned(&short).unwrap_err(), CatalogError::Malformed);
    }

    #[test]
    fn rejects_overlarge_entry_count_without_oom() {
        // A forged header claiming a huge entry_count must reject on the count gate, never pre-reserve
        // unbounded memory (the MAX_ENTRIES guard).
        let mut body = build_catalog(&[]);
        let huge = (MAX_ENTRIES as u32 + 1).to_le_bytes();
        body[16..20].copy_from_slice(&huge);
        assert_eq!(parse_resigned(&body).unwrap_err(), CatalogError::Malformed);
    }

    #[test]
    fn rejects_zero_length_name_field() {
        // Hand-build a one-entry body whose name length is 0 (forbidden).
        let mut body = Vec::new();
        body.extend_from_slice(&CATALOG_MAGIC);
        body.extend_from_slice(&CATALOG_VERSION.to_le_bytes());
        body.push(HASH_ALGO_BLAKE2B);
        body.push(0u8);
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes()); // 1 entry
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(0u8); // flags
        body.extend_from_slice(&[0u8; 32]); // hash
        body.extend_from_slice(&0u16.to_le_bytes()); // name_len = 0  ⇒ reject
        assert_eq!(parse_resigned(&body).unwrap_err(), CatalogError::Malformed);
    }
}
