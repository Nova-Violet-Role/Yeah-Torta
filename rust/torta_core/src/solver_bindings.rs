/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! THE SOLVER-BINDINGS STORE — the durable mirror of the Kotlin Stage-E `BindingCache`
//! (`solver/BindingCache.kt`: fingerprint → the binding the solver locked on that network), a
//! `#[derive(uniffi::Object)]` on the Inu FP2 template (`inu/object.rs` — the model citizen), the
//! ALWAYS-BUILT form alongside [`crate::inu::object::InuStore`].
//!
//! ## Why (#19 G10 — the RAM⊗NAND gap)
//! The Kotlin `BindingCache` is a pure in-RAM LRU (capacity 16 / TTL 6 h) — the cost-amortizer that
//! turns a 1–2 s `transport × resolver × relay` race into a 0-cost map lookup on re-entering a known
//! network. Without a durable mirror it holds only within ONE process lifetime: every app restart
//! re-races every network. This store is the NAND seam that lets the cache survive process death:
//! rehydrate ONCE at manager start, gentle write-through on the two control-plane mutation points
//! (commit / invalidate — NEVER a per-query write, F16).
//!
//! ## The pattern (the DurableTier-backed Object template, the `InuStore`/`GithubTrustEngine` shape)
//!   1. `#[derive(uniffi::Object)] pub struct SolverBindingStore` — `Mutex<Vec<SolverBindingRow>>`
//!      (the RAM hot tier) + a [`DurableTier`](crate::runtime_tier::DurableTier) (the NAND seam;
//!      record `"solver-bindings"`, atomic tmp+rename, integrity-framed `TORTAW5\0`+version+digest).
//!   2. `#[uniffi::constructor] fn new(durable_dir) -> Arc<Self>` — IO-FREE (the no-boot-IO-scan
//!      law); the caller drives [`rehydrate`](SolverBindingStore::rehydrate) explicitly.
//!   3. `#[uniffi::export] impl` — `&self` methods, each panic-firewalled to a safe default.
//!   4. The typed surface ([`SolverBindingRow`] / [`SolverTransport`]) is a uniffi Record/Enum —
//!      NEVER a flat string blob across the FFI.
//!
//! ## Two writers is a bug — one authoritative driver
//! KOTLIN (the `SolverCacheManager` + its `BindingCache`) is the authoritative driver; this store is
//! the durable tier. [`persist`](SolverBindingStore::persist) takes the FULL row set (RAM ⊗ NAND kept
//! identical); the TTL/staleness policy lives with the Kotlin cache (`lookup`/rehydrate-admit), never
//! duplicated here — the store remembers, the cache judges.
//!
//! ## Privacy (T20)
//! `fp_key` is the Kotlin `NetworkFingerprint.key` — an already-opaque FNV-1a digest ("contains no
//! raw SSID; safe to log/persist/compare", `NetworkFingerprint.kt`). No qname, no SSID, no PII ever
//! reaches this record.

#![forbid(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// The banked kind-(a) DurableTier record name (19.json: versioned from day 1 — the spine's
/// integrity frame `TORTAW5\0`+version+digest handles forward-compat).
pub(crate) const SOLVER_BINDINGS_RECORD_NAME: &str = "solver-bindings";

/// Payload codec version (INSIDE the spine's integrity frame). Bump on any row-shape change; a
/// foreign/forward version decodes to EMPTY (cold), never a guessed parse.
const BINDINGS_SNAP_VERSION: u8 = 1;

/// Row bound — the Kotlin cache caps at 16 networks (`BindingCache.DEFAULT_CAPACITY`); ×2 headroom
/// so a capacity bump never silently truncates, while a corrupt count can never balloon a decode.
const MAX_BINDING_ROWS: usize = 32;

/// The transport axis of a locked binding — mirrors the Kotlin `TransportKind` enum
/// (`BindingCache.kt:184`) variant-for-variant so the round-trip is lossless. A closed uniffi Enum,
/// never a flat string across the FFI.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolverTransport {
    Dnscrypt,
    Doh,
    Doh3,
    Doq,
}

impl SolverTransport {
    fn to_u8(self) -> u8 {
        match self {
            SolverTransport::Dnscrypt => 0,
            SolverTransport::Doh => 1,
            SolverTransport::Doh3 => 2,
            SolverTransport::Doq => 3,
        }
    }

    /// An unknown byte (a future transport) decodes to `None` — the row is SKIPPED, never guessed.
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(SolverTransport::Dnscrypt),
            1 => Some(SolverTransport::Doh),
            2 => Some(SolverTransport::Doh3),
            3 => Some(SolverTransport::Doq),
            _ => None,
        }
    }
}

/// ONE durable row of the Kotlin `BindingCache` map: the opaque network fingerprint key plus the
/// `LockedBinding` it stored (`BindingCache.kt:162` field-for-field — one cache record shape, no
/// parallel invention; the timestamps ride so the Kotlin TTL policy applies on rehydrate).
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct SolverBindingRow {
    /// The opaque privacy-safe `NetworkFingerprint.key` (`fp_…` decimal digest — no raw SSID).
    pub fp_key: String,
    /// The winning transport axis.
    pub transport: SolverTransport,
    /// The winning resolver id (the `ResolverRuntime.buildSpecsJson` / `RotationPing.Candidate.id` handle).
    pub resolver_id: String,
    /// The winning relay id, or empty = direct (Option folded to "" so the codec stays 1 shape).
    pub relay_id: String,
    /// The cwnd the YeAH brain settled on (0 = unknown/observed-only commit).
    pub tuned_cwnd: i32,
    /// The CAKE COBALT CoDel target the binding tuned to (0 = unknown).
    pub tuned_codel_target_ms: i64,
    /// Binding quality, LOWER = better (the §4 governor convention — the measured RTT).
    pub score: f64,
    /// Wall-clock when this binding was first locked (provenance / age).
    pub locked_at_ms: i64,
    /// Wall-clock of the last healthy observation — the Kotlin TTL anchor.
    pub last_healthy_at_ms: i64,
}

// ---- codec (the Inu discipline: version byte, BE ints, u16-length-prefixed strings, bounded) ----

fn put_str(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let len = b.len().min(u16::MAX as usize) as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&b[..len as usize]);
}

fn read_str(cur: &mut &[u8]) -> Option<String> {
    let len = read_u16_be(cur)? as usize;
    if cur.len() < len {
        return None;
    }
    let s = String::from_utf8_lossy(&cur[..len]).into_owned();
    *cur = &cur[len..];
    Some(s)
}

fn take_one(cur: &mut &[u8]) -> Option<u8> {
    let (&b, rest) = cur.split_first()?;
    *cur = rest;
    Some(b)
}

fn read_u16_be(cur: &mut &[u8]) -> Option<u16> {
    if cur.len() < 2 {
        return None;
    }
    let v = u16::from_be_bytes([cur[0], cur[1]]);
    *cur = &cur[2..];
    Some(v)
}

fn read_u32_be(cur: &mut &[u8]) -> Option<u32> {
    if cur.len() < 4 {
        return None;
    }
    let v = u32::from_be_bytes([cur[0], cur[1], cur[2], cur[3]]);
    *cur = &cur[4..];
    Some(v)
}

fn read_i32_be(cur: &mut &[u8]) -> Option<i32> {
    read_u32_be(cur).map(|v| v as i32)
}

fn read_i64_be(cur: &mut &[u8]) -> Option<i64> {
    if cur.len() < 8 {
        return None;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&cur[..8]);
    *cur = &cur[8..];
    Some(i64::from_be_bytes(a))
}

fn read_f64_be(cur: &mut &[u8]) -> Option<f64> {
    read_i64_be(cur).map(|bits| f64::from_bits(bits as u64))
}

/// Encode the FULL row set (bounded [`MAX_BINDING_ROWS`]) into the versioned payload the spine frames.
pub(crate) fn encode_rows(rows: &[SolverBindingRow]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + rows.len() * 64);
    out.push(BINDINGS_SNAP_VERSION);
    let count = rows.len().min(MAX_BINDING_ROWS) as u32;
    out.extend_from_slice(&count.to_be_bytes());
    for r in rows.iter().take(MAX_BINDING_ROWS) {
        put_str(&mut out, &r.fp_key);
        out.push(r.transport.to_u8());
        put_str(&mut out, &r.resolver_id);
        put_str(&mut out, &r.relay_id);
        out.extend_from_slice(&r.tuned_cwnd.to_be_bytes());
        out.extend_from_slice(&r.tuned_codel_target_ms.to_be_bytes());
        out.extend_from_slice(&r.score.to_bits().to_be_bytes());
        out.extend_from_slice(&r.locked_at_ms.to_be_bytes());
        out.extend_from_slice(&r.last_healthy_at_ms.to_be_bytes());
    }
    out
}

/// Decode a payload back into rows. Foreign/forward version ⇒ EMPTY (cold). A truncated tail keeps
/// what parsed cleanly (fail-safe); an unknown transport byte skips THAT row (cursor stays aligned).
pub(crate) fn decode_rows(payload: &[u8]) -> Vec<SolverBindingRow> {
    let mut cur = payload;
    let Some(ver) = take_one(&mut cur) else {
        return Vec::new();
    };
    if ver != BINDINGS_SNAP_VERSION {
        return Vec::new();
    }
    let Some(count) = read_u32_be(&mut cur) else {
        return Vec::new();
    };
    let capped = (count as usize).min(MAX_BINDING_ROWS);
    let mut rows = Vec::with_capacity(capped);
    for _ in 0..capped {
        let Some(fp_key) = read_str(&mut cur) else {
            break;
        };
        let Some(transport_b) = take_one(&mut cur) else {
            break;
        };
        let Some(resolver_id) = read_str(&mut cur) else {
            break;
        };
        let Some(relay_id) = read_str(&mut cur) else {
            break;
        };
        let Some(tuned_cwnd) = read_i32_be(&mut cur) else {
            break;
        };
        let Some(tuned_codel_target_ms) = read_i64_be(&mut cur) else {
            break;
        };
        let Some(score) = read_f64_be(&mut cur) else {
            break;
        };
        let Some(locked_at_ms) = read_i64_be(&mut cur) else {
            break;
        };
        let Some(last_healthy_at_ms) = read_i64_be(&mut cur) else {
            break;
        };
        // The unknown-transport row is fully consumed above (alignment held) then skipped here.
        if let Some(transport) = SolverTransport::from_u8(transport_b) {
            rows.push(SolverBindingRow {
                fp_key,
                transport,
                resolver_id,
                relay_id,
                tuned_cwnd,
                tuned_codel_target_ms,
                score,
                locked_at_ms,
                last_healthy_at_ms,
            });
        }
    }
    rows
}

/// THE SOLVER-BINDINGS STORE — the durable mirror of the Kotlin Stage-E `BindingCache`. RAM hot tier
/// (`Mutex<Vec<SolverBindingRow>>`) ⊗ NAND seam (a [`DurableTier`](crate::runtime_tier::DurableTier),
/// record [`SOLVER_BINDINGS_RECORD_NAME`]). Each method panic-firewalls its body — a bug returns a
/// safe default, never aborts the app.
#[derive(uniffi::Object)]
pub struct SolverBindingStore {
    ram: Mutex<Vec<SolverBindingRow>>,
    nand: crate::runtime_tier::DurableTier,
}

#[uniffi::export]
impl SolverBindingStore {
    /// Construct the store rooted at the app-private `durable_dir` (the SAME `runtime_tier` root the
    /// other durable pillars share — the G9 one-root law). IO-FREE (the no-boot-IO-scan law): RAM is
    /// empty; the caller drives [`rehydrate`](Self::rehydrate) ONCE at manager start.
    #[uniffi::constructor]
    pub fn new(durable_dir: String) -> Arc<Self> {
        let nand = crate::runtime_tier::DurableTier::with_dir(
            PathBuf::from(&durable_dir),
            SOLVER_BINDINGS_RECORD_NAME,
        );
        Arc::new(Self {
            ram: Mutex::new(Vec::new()),
            nand,
        })
    }

    /// Rehydrate the persisted rows from NAND into RAM and RETURN them (the boot read the Kotlin
    /// `BindingCache` admits through its OWN TTL policy — the store never judges staleness). Absent /
    /// corrupt / foreign / forward-version record ⇒ EMPTY (never an error, never a panic across the
    /// boundary). Call ONCE at manager start. Panic-firewalled → empty.
    pub fn rehydrate(&self) -> Vec<SolverBindingRow> {
        catch_unwind(AssertUnwindSafe(|| {
            let rows = match self.nand.rehydrate() {
                Some(blob) => decode_rows(&blob),
                None => Vec::new(),
            };
            if let Ok(mut g) = self.ram.lock() {
                *g = rows.clone();
            }
            rows
        }))
        .unwrap_or_default()
    }

    /// GENTLE write-through of the FULL row set to NAND + RAM (kept identical). CONTROL-PLANE ONLY —
    /// the two Kotlin mutation points (`BindingCache.commit` / `invalidate`), NEVER a per-query or
    /// poll write (F16). Bounded [`MAX_BINDING_ROWS`]. Returns `true` on a durable write; `false` on
    /// a [`WriteReject`](crate::runtime_tier::WriteReject) / panic — best-effort durability (RAM still
    /// updates so a later persist can retry the full set).
    pub fn persist(&self, rows: Vec<SolverBindingRow>) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            let bounded: Vec<SolverBindingRow> = rows.into_iter().take(MAX_BINDING_ROWS).collect();
            let ok = self.nand.write_through(&encode_rows(&bounded)).is_ok();
            if let Ok(mut g) = self.ram.lock() {
                *g = bounded;
            }
            ok
        }))
        .unwrap_or(false)
    }

    /// The current RAM-tier rows — a zero-IO diagnostics/dashboard read (F16 poll path). Panic/poison
    /// → empty.
    pub fn snapshot(&self) -> Vec<SolverBindingRow> {
        catch_unwind(AssertUnwindSafe(|| match self.ram.lock() {
            Ok(g) => g.clone(),
            Err(_) => Vec::new(),
        }))
        .unwrap_or_default()
    }

    /// Forget the persisted rows (NAND record removed + RAM emptied) — the Expert "forget solved
    /// networks" action (`BindingCache.clear` durable twin). Best-effort + non-failing. Panic → no-op.
    pub fn clear(&self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            self.nand.clear();
            if let Ok(mut g) = self.ram.lock() {
                g.clear();
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique-per-test temp dir (process-unique counter + tag → collision-free; no rng dep).
    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("torta-solverbind-{tag}-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn a_row(fp: &str, resolver: &str, healthy_at: i64) -> SolverBindingRow {
        SolverBindingRow {
            fp_key: fp.to_string(),
            transport: SolverTransport::Dnscrypt,
            resolver_id: resolver.to_string(),
            relay_id: String::new(),
            tuned_cwnd: 24,
            tuned_codel_target_ms: 5,
            score: 42.5,
            locked_at_ms: healthy_at - 1000,
            last_healthy_at_ms: healthy_at,
        }
    }

    // ---- THE REBOOT ROUND-TRIP (the cache survives process death — the #19 required prove) ----

    #[test]
    fn persist_then_a_fresh_store_rehydrates_the_same_rows() {
        let dir = temp_dir("reboot");
        let store = SolverBindingStore::new(dir.to_string_lossy().into_owned());
        let rows = vec![
            a_row("fp_11111", "quad9-dnscrypt-ip4-filter-pri", 1_000_000),
            SolverBindingRow {
                relay_id: "anon-cs-ore".to_string(),
                transport: SolverTransport::Doh3,
                ..a_row("fp_22222", "cloudflare", 2_000_000)
            },
        ];
        assert!(store.persist(rows.clone()), "the durable write succeeds");

        // A FRESH store over the SAME dir — a "reboot" (new process). Empty before rehydrate (no
        // boot IO), then the persisted rows come back field-for-field.
        let reborn = SolverBindingStore::new(dir.to_string_lossy().into_owned());
        assert!(
            reborn.snapshot().is_empty(),
            "cold before rehydrate (no boot IO)"
        );
        assert_eq!(
            reborn.rehydrate(),
            rows,
            "the locked bindings survive a reboot rehydrate (every field + the TTL anchor)"
        );
        assert_eq!(reborn.snapshot(), rows, "rehydrate populated the RAM tier");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cold_rehydrate_on_absent_record() {
        let dir = temp_dir("cold");
        let store = SolverBindingStore::new(dir.to_string_lossy().into_owned());
        assert!(store.rehydrate().is_empty(), "absent record ⇒ cold start");
        assert!(
            !dir.exists(),
            "the no-IO ctor + a cold rehydrate touch no disk"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_forgets_the_rows() {
        let dir = temp_dir("clear");
        let store = SolverBindingStore::new(dir.to_string_lossy().into_owned());
        assert!(store.persist(vec![a_row("fp_9", "adguard", 5)]));
        store.clear();
        assert!(store.snapshot().is_empty(), "clear resets RAM");
        let reborn = SolverBindingStore::new(dir.to_string_lossy().into_owned());
        assert!(
            reborn.rehydrate().is_empty(),
            "clear removed the durable record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decode_of_garbage_is_empty_not_panic() {
        assert!(decode_rows(b"").is_empty());
        assert!(
            decode_rows(b"\xff\xff\xff").is_empty(),
            "foreign version ⇒ cold"
        );
        assert!(
            decode_rows(&[BINDINGS_SNAP_VERSION]).is_empty(),
            "no count ⇒ cold"
        );
        // A claimed-huge count over a truncated body keeps only what parses (here: nothing).
        let mut lying = vec![BINDINGS_SNAP_VERSION];
        lying.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_rows(&lying).is_empty());
    }

    #[test]
    fn unknown_transport_row_is_skipped_alignment_held() {
        // Row 1 carries a FUTURE transport byte (7) — skipped; row 2 must still parse (alignment).
        let good = a_row("fp_good", "mullvad", 9);
        let mut rows = vec![a_row("fp_future", "someday", 3), good.clone()];
        let mut payload = encode_rows(&rows);
        // Surgically flip row 1's transport byte to an unknown value: it sits right after the
        // version(1)+count(4)+fp_key(2+len) prefix.
        let off = 1 + 4 + 2 + rows[0].fp_key.len();
        payload[off] = 7;
        let decoded = decode_rows(&payload);
        rows.remove(0);
        assert_eq!(
            decoded, rows,
            "unknown-transport row skipped, later rows intact"
        );
        assert_eq!(decoded, vec![good]);
    }

    #[test]
    fn row_bound_is_enforced_both_directions() {
        let rows: Vec<SolverBindingRow> =
            (0..64).map(|i| a_row(&format!("fp_{i}"), "r", i)).collect();
        let payload = encode_rows(&rows);
        let decoded = decode_rows(&payload);
        assert_eq!(decoded.len(), MAX_BINDING_ROWS, "encode caps at the bound");
        assert_eq!(
            &decoded[..],
            &rows[..MAX_BINDING_ROWS],
            "the first N survive"
        );
    }

    #[test]
    fn snapshot_does_not_write_disk() {
        // The poll path never touches NAND (F16): construct + snapshot many times ⇒ no dir created.
        let dir = temp_dir("poll-free");
        let store = SolverBindingStore::new(dir.to_string_lossy().into_owned());
        for _ in 0..64 {
            let _ = store.snapshot();
        }
        assert!(
            !dir.exists(),
            "snapshot is RAM-only (F16 no-hot-path-write)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
