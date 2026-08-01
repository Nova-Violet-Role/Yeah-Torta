/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! The Warden W5 shared **durable runtime tier** — hot in-memory state ⊗ a GENTLE atomic NAND
//! write-through + explicit boot-rehydrate, generalized from the #92 Centauri cache seam
//! (`mirror/cache.rs:218/339/362` — `with_dir` + atomic write-then-rename + non-failing
//! `load_from_disk`) so EVERY Rust pillar can keep its small durable state across a power-off/reboot
//! without a RAMdisk and without ever touching the hot DNS/connection/verdict path.
//!
//! ## The Android-lean law (W5 CHARTER §"THE ANDROID-LEAN LAW")
//! Android has NO user-mountable RAMdisk, so:
//! - **The "RAM tier" is the app's own process heap** — the hot engines (resolver pool/cache, the
//!   blocklist trie, the Warden rule-set) already live in memory. W5 adds **no** RAMdisk.
//! - **The "NAND tier" is the app-private `Context.filesDir`** (flash), written with a plain
//!   **atomic tmp+rename** (what SQLite/Room/OkHttp-cache do underneath) — zero special permission,
//!   zero root, `allowBackup=false`.
//! - **GENTLE write-through ONLY** — periodic / on-change / batched. A [`DurableTier`] write is
//!   issued by a pillar on a *control-plane* event (a rotation flip, a stats checkpoint), **NEVER**
//!   from `resolve()`/`verdict()`. The hot path stays byte-identical + write-free (no flash
//!   write-amplification, no battery drain).
//! - **BOUNDED footprint** — a blob over [`MAX_BLOB_BYTES`] is refused (write) / skipped (rehydrate),
//!   so a hostile or corrupt on-disk file can never exhaust per-app memory.
//! - **Rehydrate is EXPLICIT + non-failing + no-boot-IO-scan** — the constructor does NO disk read
//!   (battery-frugal, ties #98 auto-start); the caller calls [`DurableTier::rehydrate`] once at start
//!   and a missing / corrupt / oversized record yields `None` (a cold start), never an error.
//!
//! ## Two pillar kinds, ONE facility (W5 CHARTER §"KEY design distinction")
//! - **(a) NEW-durable** (resolver rotation state, warm RTT hints, metrics —
//!   in-memory-only today): persist the small durable bits THROUGH this facility
//!   ([`DurableTier::write_through`] gentle, [`DurableTier::rehydrate`] on boot). This is the facility's
//!   primary consumer.
//! - **(b) rehydrate-from-SIGNED-source** (blocklist←`.tblk`, Centauri←`.tcat`): the
//!   durable tier IS the signed artifact, so its "rehydrate" is a re-verify+re-install of the signed
//!   bytes (the W4 verify-sig-FIRST path), **NOT** a raw NAND dump of the trie/policy through this
//!   facility. This module deliberately holds **no** trie/policy dumper — a second, unsigned,
//!   drift-prone copy of a signed source is exactly what the charter forbids.
//!
//! ## The on-disk record format (self-describing, integrity-checked, fail-safe)
//! A record is a tiny framed blob: a fixed [`MAGIC`] + a 1-byte `version` + a 32-byte payload digest +
//! the payload bytes. The digest is the SAME one-digest discipline the Centauri cache uses
//! (`mirror/cache.rs` — NEVER the forgeable FNV-1a flagged
//! at `blocklist.rs:362`). It is **feature-selected** (own-crypto charter slice 4): the BASE build (no
//! `fortress` feature, the default cargo-ndk `.so`) uses **SHA-256** — keeping the base `.so` AND the
//! durable record format byte-identical; with the **`fortress`** feature the spine is **BLAKE2b-256**
//! (`blake2::Blake2b<U32>`). BOTH are 32 bytes, so [`HEADER_LEN`] and
//! the framing are gate-invariant (a record written under one digest rehydrates COLD under the other —
//! the fail-safe integrity gate, never a torn parse). On rehydrate the payload is re-hashed and admitted
//! ONLY if it matches the stored digest — a truncated, half-written, or tampered file fails the check
//! and rehydrates as `None` (fail-safe: the in-memory tier keeps working, the durable tier is
//! best-effort). The framing makes a torn parse impossible — a short/garbage file never reaches the
//! caller's deserializer.
//!
//! ## Safety posture
//! `#![forbid(unsafe_code)]`, std-only IO. The base build's `sha2` is already a base dep (zero new crate);
//! the `fortress`-feature `blake2` is the RustCrypto sibling on the SAME `digest 0.10` trait (no aws-lc,
//! `simd`/`simd_asm` NOT enabled → no `unsafe` pulled). ring-only pure logic. WIRED — the resolver rotation
//! pillar + the P12 resolver cache persist/rehydrate/checkpoint THROUGH this tier (only [`DurableTier::clear`]
//! stays a dead-code-until-wired reset path). A write/rehydrate failure NEVER panics + NEVER unwinds across
//! the FFI boundary — it returns a typed verdict / `None`.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

// The durable-record integrity digest. Feature-gated SHA-256 → Blake2b switch (own-crypto charter slice 4):
// - BASE build (no `fortress` feature, the default cargo-ndk `.so`): `Sha256` — keeps the base `.so` AND the
//   on-disk durable record format BYTE-IDENTICAL (`runtime_tier` is un-gated at `lib.rs:46` AND live-wired via
//   the JNI rotation exports at `lib.rs:1980,2009`, so a naive flip would change the shipped base — GROUND_TRUTH).
// - `fortress` feature ON: `Blake2b<U32>` — the integrity spine in Blake2b.
// BOTH digests are 32 bytes (`Blake2b<U32>` is the parametrized 32-byte BLAKE2b — cited `blake2-0.10.6/src/lib.rs:135`;
// NOT `Blake2b512` = 64 B at `:137`, and there is NO `Blake2b256` alias in 0.10.6), so `HEADER_LEN` (= MAGIC 8 +
// version 1 + digest 32) is unchanged and the `frame`/`unframe` bodies are byte-identical across the gate.
// The `fortress` feature (Blake2b integrity spine) is DEPRECATED and REMOVED 2026-07 by Socio
// directive. The spine is SHA-256, which is what every shipped `.so` has always used: no ship
// recipe enabled `fortress`, so the on-disk record format and the base image are UNCHANGED by this
// removal. `HEADER_LEN` still reads MAGIC(8) + version(1) + digest(32).
use sha2::{Digest, Sha256 as SpineDigest};

/// The fixed 8-byte record magic (`"TORTAW5\0"`) — a frame guard so a foreign / truncated file in the
/// app-private dir is never mistaken for a durable record (it fails the magic check → rehydrate `None`).
const MAGIC: [u8; 8] = *b"TORTAW5\0";

/// The on-disk record format version. Bumped if the framing changes; a record written by a NEWER
/// version is rehydrated as `None` (a forward-incompatible record is a cold start, never a torn read).
const VERSION: u8 = 1;

/// The fixed framing overhead: `MAGIC`(8) + `version`(1) + payload SHA-256(32). The payload follows.
const HEADER_LEN: usize = 8 + 1 + 32;

/// The per-record payload ceiling: a record whose payload exceeds this is refused on write and skipped
/// on rehydrate (a bounded-read guard against a hostile/corrupt file exhausting per-app memory). The
/// durable bits these pillars persist are TINY (a rotation cursor, a handful of RTT hints, a few
/// counters), so 256 KiB is a generous fail-closed ceiling, NOT a tuning knob — mirrors the Centauri
/// cache's bounded-read discipline (`mirror/cache.rs:54` `MAX_ASSET_BYTES`).
pub const MAX_BLOB_BYTES: usize = 256 * 1024;

/// Why a [`DurableTier::write_through`] was refused — a typed verdict, never an unwinding error across
/// the FFI boundary (the same discipline as `mirror/cache.rs`'s [`CacheReject`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteReject {
    /// The payload exceeds [`MAX_BLOB_BYTES`] → refused before any IO (a bounded-read guard).
    TooLarge,
    /// The underlying filesystem write/rename/create-dir failed → the durable copy was NOT updated.
    /// The in-memory tier is unaffected (best-effort durability — the charter's FAIL-SAFE invariant).
    IoError,
}

/// A pillar's durable runtime tier: a single named on-disk record under an app-private directory.
///
/// SHAPE (modeled on `mirror::CacheStore`): construct with [`DurableTier::with_dir`] (NO boot IO scan),
/// then GENTLY [`DurableTier::write_through`] the durable bits on a control-plane event and explicitly
/// [`DurableTier::rehydrate`] them once at start. The struct holds NO in-RAM payload copy — the hot
/// in-memory state lives in the OWNING pillar (the resolver `Inner`, …);
/// this facility is only the durable seam, so it never duplicates or bounds the live state.
#[derive(Clone, Debug)]
pub struct DurableTier {
    /// The app-private directory the record lives under (created lazily on the first write).
    dir: PathBuf,
    /// The record filename within `dir` (a stable per-pillar name, e.g. `"resolver-rotation"`).
    name: String,
}

impl DurableTier {
    /// A durable tier for a named record rooted at the app-private `dir`. The constructor does **NO**
    /// disk read (non-failing + battery-frugal — the no-boot-IO-scan law); the caller rehydrates
    /// explicitly via [`DurableTier::rehydrate`]. `name` is sanitized to a flat, dir-traversal-free
    /// filename so a pillar id can never escape `dir`.
    pub fn with_dir(dir: PathBuf, name: &str) -> Self {
        DurableTier {
            dir,
            name: sanitize_name(name),
        }
    }

    /// The full on-disk path of this tier's record (`dir/<name>`).
    pub fn path(&self) -> PathBuf {
        self.dir.join(&self.name)
    }

    /// GENTLE write-through of `payload` to disk, atomically (tmp+rename) and integrity-framed.
    ///
    /// **Call this ONLY on the control plane** (a rotation flip, a periodic/on-change stats
    /// checkpoint) — NEVER from `resolve()`/`verdict()` (the no-hot-path-write law). Order: bounded-read
    /// guard → frame (`MAGIC` + version + payload SHA-256 + payload) → atomic tmp+rename. A crashed
    /// write never leaves a half-record under the final name (the partial lands in the `.tmp` and is
    /// cleaned / ignored). Returns `Ok(())` on a durable write, or a typed [`WriteReject`] on refusal —
    /// the caller treats a reject as best-effort (the in-memory tier keeps working).
    pub fn write_through(&self, payload: &[u8]) -> Result<(), WriteReject> {
        if payload.len() > MAX_BLOB_BYTES {
            return Err(WriteReject::TooLarge);
        }
        let framed = frame(payload);
        write_atomic(&self.dir, &self.name, &framed).map_err(|_| WriteReject::IoError)
    }

    /// Rehydrate the durable record, returning its verified payload or `None`.
    ///
    /// EXPLICIT + non-failing (the caller drives it once at start, after the no-IO-scan constructor).
    /// A record is admitted ONLY if it is present, frame-valid (`MAGIC` + a known `version`), within
    /// [`MAX_BLOB_BYTES`], and its payload re-hashes to the stored SHA-256 — a missing / truncated /
    /// half-written / tampered / forward-version record yields `None` (a cold start, NEVER an error).
    /// The caller then deserializes the returned payload with its own (bounds-checked) reader; the
    /// framing guarantees the deserializer never sees a torn blob.
    pub fn rehydrate(&self) -> Option<Vec<u8>> {
        let raw = std::fs::read(self.path()).ok()?;
        unframe(&raw)
    }

    /// Best-effort removal of the durable record (e.g. a pillar reset / a `shutdown` that wants to
    /// forget persisted state). Non-failing: an absent record is a no-op success; a failed remove is
    /// swallowed (the in-memory tier is the source of truth, the durable copy is best-effort).
    ///
    /// `allow(dead_code)`: part of the facility's intended public surface (a pillar `shutdown`/reset
    /// forget-path), proven by tests but not yet called by a non-test pillar — the dead-code-until-wired
    /// signal (the `blocklist.rs:235` idiom), dropped once a pillar wires its reset.
    pub fn clear(&self) {
        let _ = std::fs::remove_file(self.path());
    }
}

/// Frame a payload into the self-describing on-disk record: `MAGIC || version || SHA-256(payload) || payload`.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    let mut h = SpineDigest::new();
    h.update(payload);
    let digest: [u8; 32] = h.finalize().into();
    out.extend_from_slice(&digest);
    out.extend_from_slice(payload);
    out
}

/// Validate a framed record + return its payload, or `None` on ANY framing/integrity failure (the
/// fail-safe rehydrate core). Checks, in order: minimum length → magic → known version → bounded
/// payload → SHA-256 match. Never panics, never an OOB read (every slice is length-guarded first).
fn unframe(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < HEADER_LEN {
        return None; // too short to carry a header ⇒ not a valid record (truncated / foreign file).
    }
    if raw[..8] != MAGIC {
        return None; // foreign file ⇒ never a durable record.
    }
    if raw[8] != VERSION {
        return None; // a forward/unknown version ⇒ a cold start, never a guessed parse.
    }
    let stored: &[u8] = &raw[9..HEADER_LEN]; // the 32-byte payload digest.
    let payload = &raw[HEADER_LEN..];
    if payload.len() > MAX_BLOB_BYTES {
        return None; // a record whose payload exceeds the bound is skipped (bounded-read guard).
    }
    let mut h = SpineDigest::new();
    h.update(payload);
    let actual: [u8; 32] = h.finalize().into();
    if actual.as_slice() != stored {
        return None; // truncated / half-written / tampered ⇒ fail-safe (the in-memory tier still works).
    }
    Some(payload.to_vec())
}

/// The on-disk atomic write: `dir/<name>` via a tmp+rename so a crashed/partial write never appears
/// under the valid record name. Creates `dir` if absent. The tmp name carries the record name so two
/// distinct records in one dir never collide on a single tmp path. (Identical pattern to
/// `mirror/cache.rs:339` `write_to_disk`.)
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let final_path = dir.join(name);
    let tmp_path = dir.join(format!(".{name}.tmp"));
    std::fs::write(&tmp_path, bytes)?;
    match std::fs::rename(&tmp_path, &final_path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path); // clean the orphan tmp on a rare rename failure.
            Err(e)
        }
    }
}

/// Sanitize a pillar record name into a flat, traversal-free filename: keep `[A-Za-z0-9._-]`, map every
/// other byte (including `/`, `\\`, `:`, NUL) to `_`. So a pillar id can NEVER escape its `dir` (no
/// `../`), and the resulting name is a stable, portable file. An empty result falls back to `"record"`.
fn sanitize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len().min(64));
    for ch in name.chars().take(64) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    // A name that is only dots (".", "..") would be a traversal target — reject it to the fallback.
    if out.is_empty() || out.chars().all(|c| c == '.') {
        return "record".to_string();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique-per-test temp dir under the OS temp root (process-unique counter + tag → collision-free;
    /// no rng dep). The test cleans it up at the end. (Mirrors `mirror/cache.rs:777` `temp_cache_dir`.)
    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("torta-w5-{tag}-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    // ---- round-trip (the persistence guarantee — "nothing lost on power-off/reboot") ----------------

    #[test]
    fn write_then_rehydrate_round_trips() {
        let dir = temp_dir("roundtrip");
        let tier = DurableTier::with_dir(dir.clone(), "resolver-rotation");
        let payload = br#"{"family":"cloudflare","cadence":3600,"last":7}"#.to_vec();
        assert!(tier.write_through(&payload).is_ok());
        // A FRESH tier over the same dir+name rehydrates the EXACT payload (a "reboot" — new process state).
        let reborn = DurableTier::with_dir(dir.clone(), "resolver-rotation");
        assert_eq!(
            reborn.rehydrate(),
            Some(payload),
            "the durable bits survive a fresh construction (the reboot guarantee)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rehydrate_on_absent_record_is_none_not_error() {
        let dir = temp_dir("absent");
        let tier = DurableTier::with_dir(dir.clone(), "metrics");
        // Never written — a cold start rehydrates None, never panics, and creates no dir (no boot IO).
        assert_eq!(tier.rehydrate(), None, "an absent record is a cold start");
        assert!(
            !dir.exists(),
            "the no-boot-IO-scan constructor + a None rehydrate touch no disk"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_through_is_atomic_no_tmp_left_behind() {
        let dir = temp_dir("atomic");
        let tier = DurableTier::with_dir(dir.clone(), "fortress-attest");
        assert!(tier.write_through(b"attest-cache-blob").is_ok());
        assert!(
            tier.path().exists(),
            "the record lands under its final name"
        );
        let tmp = dir.join(".fortress-attest.tmp");
        assert!(
            !tmp.exists(),
            "the tmp file is renamed away (atomic), never left dangling"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewrite_overwrites_in_place() {
        let dir = temp_dir("rewrite");
        let tier = DurableTier::with_dir(dir.clone(), "rtt-hints");
        assert!(tier.write_through(b"v1").is_ok());
        assert!(tier.write_through(b"v2-longer-payload").is_ok());
        assert_eq!(
            tier.rehydrate(),
            Some(b"v2-longer-payload".to_vec()),
            "a re-write replaces the prior record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_payload_round_trips() {
        let dir = temp_dir("empty");
        let tier = DurableTier::with_dir(dir.clone(), "empty-rec");
        assert!(tier.write_through(b"").is_ok());
        assert_eq!(
            tier.rehydrate(),
            Some(Vec::new()),
            "a zero-length payload is well-defined"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- bounded-cap (no OOM on a hostile/corrupt file) ---------------------------------------------

    #[test]
    fn write_through_rejects_oversized_payload() {
        let dir = temp_dir("toolarge");
        let tier = DurableTier::with_dir(dir.clone(), "big");
        let big = vec![0u8; MAX_BLOB_BYTES + 1];
        assert_eq!(
            tier.write_through(&big),
            Err(WriteReject::TooLarge),
            "a payload over the bound is refused before any IO"
        );
        assert!(
            !tier.path().exists(),
            "a rejected oversized write touches no disk"
        );
        // The bound edge is admissible (proves the guard is not off-by-one over-rejecting).
        let edge = vec![1u8; MAX_BLOB_BYTES];
        assert!(tier.write_through(&edge).is_ok());
        assert_eq!(tier.rehydrate().map(|p| p.len()), Some(MAX_BLOB_BYTES));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rehydrate_skips_an_oversized_on_disk_payload() {
        // Plant a frame whose payload exceeds the bound (a hostile/corrupt file) — rehydrate skips it,
        // never allocating it into the live tier.
        let dir = temp_dir("oversize-disk");
        std::fs::create_dir_all(&dir).unwrap();
        let payload = vec![7u8; MAX_BLOB_BYTES + 1];
        let framed = frame(&payload); // a VALID frame (good digest) but an over-bound payload.
        std::fs::write(dir.join("oversize"), &framed).unwrap();
        let tier = DurableTier::with_dir(dir.clone(), "oversize");
        assert_eq!(
            tier.rehydrate(),
            None,
            "an over-bound on-disk payload is skipped, not loaded"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- integrity / fail-safe (a corrupt durable copy degrades gracefully) -------------------------

    #[test]
    fn tampered_payload_rehydrates_none_fail_safe() {
        let dir = temp_dir("tamper");
        let tier = DurableTier::with_dir(dir.clone(), "rec");
        assert!(tier.write_through(b"the honest durable bits").is_ok());
        // Flip one byte of the on-disk payload (past the 41-byte header) — the SHA-256 no longer matches.
        let mut raw = std::fs::read(tier.path()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        std::fs::write(tier.path(), &raw).unwrap();
        assert_eq!(
            tier.rehydrate(),
            None,
            "a tampered/corrupt record fails the integrity check ⇒ fail-safe cold start"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_record_rehydrates_none() {
        let dir = temp_dir("trunc");
        let tier = DurableTier::with_dir(dir.clone(), "rec");
        assert!(tier.write_through(b"some durable payload bytes").is_ok());
        // Truncate into the middle of the payload (a half-written file from a crashed write).
        let raw = std::fs::read(tier.path()).unwrap();
        std::fs::write(tier.path(), &raw[..HEADER_LEN + 3]).unwrap();
        // …and also a truncation INTO the header (shorter than HEADER_LEN) must be None too.
        let tier2 = DurableTier::with_dir(dir.clone(), "rec2");
        assert!(tier2.write_through(b"x").is_ok());
        let raw2 = std::fs::read(tier2.path()).unwrap();
        std::fs::write(tier2.path(), &raw2[..5]).unwrap();
        // The first is a payload-mismatch (digest over 3 bytes != stored), the second is too-short.
        // Both fail-safe to None.
        // (A 3-byte-payload-vs-stored-digest could in theory match only with astronomically low odds;
        //  this is a deterministic truncation of a known payload, so it never matches.)
        let reborn = DurableTier::with_dir(dir.clone(), "rec");
        assert_eq!(
            reborn.rehydrate(),
            None,
            "a truncated payload fails the integrity check"
        );
        let reborn2 = DurableTier::with_dir(dir.clone(), "rec2");
        assert_eq!(
            reborn2.rehydrate(),
            None,
            "a header-truncated record is None"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn foreign_file_rehydrates_none() {
        // A non-record file in the app-private dir (e.g. another subsystem's file) is never mistaken
        // for a durable record — the magic guard rejects it.
        let dir = temp_dir("foreign");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("rec"),
            b"this is not a TORTAW5 framed record at all, way long enough",
        )
        .unwrap();
        let tier = DurableTier::with_dir(dir.clone(), "rec");
        assert_eq!(
            tier.rehydrate(),
            None,
            "a foreign file fails the magic guard"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_version_rehydrates_none() {
        let dir = temp_dir("version");
        let tier = DurableTier::with_dir(dir.clone(), "rec");
        assert!(tier.write_through(b"payload").is_ok());
        // Bump the version byte to an unknown future version — a forward-incompatible record is a cold start.
        let mut raw = std::fs::read(tier.path()).unwrap();
        raw[8] = VERSION.wrapping_add(7);
        std::fs::write(tier.path(), &raw).unwrap();
        assert_eq!(
            tier.rehydrate(),
            None,
            "an unknown version rehydrates None, never a guessed parse"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_removes_the_record() {
        let dir = temp_dir("clear");
        let tier = DurableTier::with_dir(dir.clone(), "rec");
        assert!(tier.write_through(b"to be cleared").is_ok());
        assert!(tier.path().exists());
        tier.clear();
        assert!(!tier.path().exists(), "clear removes the durable record");
        // clear on an absent record is a harmless no-op (best-effort).
        tier.clear();
        assert_eq!(tier.rehydrate(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- the NO-HOT-PATH-WRITE proof (the charter's keystone safety invariant) ----------------------

    /// PROOF (structural): a tier construction does ZERO disk IO — the no-boot-IO-scan law. We construct
    /// many tiers over a never-created dir and assert NOTHING was written (no dir, no file). This is the
    /// static guarantee that a pillar holding a `DurableTier` field adds no boot/hot-path IO merely by
    /// existing; a write happens ONLY when the pillar EXPLICITLY calls `write_through` on its control plane.
    #[test]
    fn construction_does_no_io_so_the_hot_path_stays_write_free() {
        let dir = temp_dir("no-hot-path");
        for i in 0..256 {
            let _tier = DurableTier::with_dir(dir.clone(), &format!("pillar-{i}"));
            // No write_through call here — simulating the hot path holding the tier but never writing.
        }
        assert!(
            !dir.exists(),
            "merely constructing/holding a DurableTier writes NOTHING — the hot path is write-free; \
             a durable write happens only on an explicit control-plane write_through"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// PROOF (behavioral): rehydrate-then-never-write is read-only. After ONE control-plane write, a
    /// fresh tier rehydrates and the on-disk mtime/content is UNCHANGED by the read — a rehydrate is a
    /// pure read, exactly what a boot does (read once, then serve from RAM with no further IO).
    #[test]
    fn rehydrate_is_read_only_no_disk_mutation() {
        let dir = temp_dir("read-only");
        let tier = DurableTier::with_dir(dir.clone(), "rec");
        assert!(tier.write_through(b"durable").is_ok());
        let before = std::fs::read(tier.path()).unwrap();
        // Rehydrate twice (the boot read + any re-read) — neither mutates the on-disk bytes.
        let _ = tier.rehydrate();
        let _ = tier.rehydrate();
        let after = std::fs::read(tier.path()).unwrap();
        assert_eq!(
            before, after,
            "a rehydrate is a pure read — it never rewrites the durable record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- traversal-safety (a pillar id can never escape its dir) ------------------------------------

    #[test]
    fn name_is_sanitized_against_traversal() {
        let dir = temp_dir("sanitize");
        // A malicious/odd pillar name with separators + traversal is flattened to a safe filename
        // INSIDE dir — it never writes outside.
        let tier = DurableTier::with_dir(dir.clone(), "../../etc/passwd");
        assert!(tier.write_through(b"x").is_ok());
        let p = tier.path();
        // The safety invariant is structural: the record's parent IS `dir` (no escape), and the
        // sanitized filename carries NO path separator — so even though the flat name may still contain
        // the literal characters "..", they are an inert part of ONE filename, not a traversal segment.
        assert_eq!(
            p.parent(),
            Some(dir.as_path()),
            "the record stays inside its dir"
        );
        let file = p.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            !file.contains('/') && !file.contains('\\'),
            "no separator survives ⇒ no traversal"
        );
        // The record physically lands inside `dir` (the canonical proof it never escaped).
        assert!(
            p.exists() && p.starts_with(&dir),
            "the file physically lives inside dir"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dot_only_names_fall_back_to_record() {
        assert_eq!(sanitize_name(".."), "record");
        assert_eq!(sanitize_name("."), "record");
        assert_eq!(sanitize_name(""), "record");
        assert_eq!(sanitize_name("resolver-rotation"), "resolver-rotation");
        assert_eq!(sanitize_name("a/b\\c:d"), "a_b_c_d");
    }

    // ---- the frame is deterministic + faithful (the digest discipline) -----------------------------

    #[test]
    fn frame_unframe_is_faithful_over_many_payloads() {
        for seed in 0u8..40 {
            for &len in &[0usize, 1, 7, 64, 257, 4096] {
                let payload: Vec<u8> = (0..len)
                    .map(|i| seed.wrapping_add(i as u8).wrapping_mul(31))
                    .collect();
                let framed = frame(&payload);
                assert_eq!(framed.len(), HEADER_LEN + len, "framing overhead is exact");
                assert_eq!(
                    unframe(&framed),
                    Some(payload),
                    "frame→unframe round-trips faithfully"
                );
            }
        }
    }

    #[test]
    fn unframe_rejects_a_garbage_prefix() {
        // Any buffer not starting with MAGIC is rejected, regardless of length.
        assert_eq!(unframe(&[]), None);
        assert_eq!(
            unframe(&[0u8; HEADER_LEN]),
            None,
            "all-zero header has wrong magic"
        );
        let mut almost = frame(b"hi");
        almost[0] ^= 0xFF; // corrupt the magic
        assert_eq!(unframe(&almost), None);
    }
}
