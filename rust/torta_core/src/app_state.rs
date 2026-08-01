/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! # THE APP-STATE STORE — the G7-RESIDUAL typed DurableTier record (#21)
//!
//! The last load-bearing app-level flags living in `SharedPreferences` (the G7 audit's "state
//! offenders", distinct from user SETTINGS which stay in prefs by design), folded into ONE typed
//! RAM⊗NAND record on the Inu template ([`crate::inu::object::InuStore`] — the pattern
//! [`crate::solver_bindings::SolverBindingStore`] also rides):
//!
//! | field                   | legacy pref key (`TortaeKeys`)        | writer / reader seam            |
//! |-------------------------|---------------------------------------|---------------------------------|
//! | `saved_dnscrypt_state`  | `savedDNSCryptState`                  | ModulesStateLoop / Tile / Boot  |
//! | `operation_mode`        | `OPERATION_MODE`                      | AppModeManager / ModulesService |
//! | `vpn_service_enabled`   | `VPN_SERVICE_ENABLED`                 | ModulesStateLoop / ServiceVPN   |
//! | `default_preset_seeded` | `pref_default_preset_seeded`          | PresetFirstRun                  |
//!
//! (`INU_BOOT_REAPPLY` is NOT here — it belongs to the Inu pillar's own record,
//! [`crate::inu::InuState::boot_reapply`], absorbed the same #21 slice.)
//!
//! The schema carries ALL FOUR fields from day one so later call-site migrations (the
//! `operation_mode` / `vpn_service_enabled` seams are wide — 20/35 sites) need no format bump.
//! Single-process app (measured: the merged manifest declares 11 services, zero
//! `android:process`) — one store, one NAND record, no cross-process write hazard.
//!
//! Shape (the Object law, uniffi-full-power):
//!   1. `#[derive(uniffi::Object)] pub struct AppStateStore` — `Mutex<AppState>` RAM hot tier ⊗ a
//!      [`crate::runtime_tier::DurableTier`] NAND seam.
//!   2. `#[uniffi::constructor] fn new(durable_dir) -> Arc<Self>` — IO-FREE (the no-boot-IO-scan
//!      law); the caller calls [`rehydrate`](AppStateStore::rehydrate) ONCE at boot.
//!   3. Typed getters read RAM (no disk IO); typed setters are CONTROL-PLANE write-throughs
//!      (a state flip is always a control event, never a poll).
//!
//! Every method panic-firewalls to a safe default — a bug returns cold, never aborts the app.

#![forbid(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// The durable record name under the app-private durable dir (`<dir>/app-state`).
pub(crate) const APP_STATE_RECORD_NAME: &str = "app-state";

/// The blob format version — the FIRST payload byte. A record written by a NEWER version
/// rehydrates cold (the forward-incompat discipline — never a guessed parse). The outer
/// [`crate::runtime_tier::DurableTier`] frame (MAGIC + version + digest) already guards
/// foreignness + integrity; this inner byte only guards the payload framing.
const APP_STATE_SNAP_VERSION: u8 = 1;

/// Ceiling for each stored string (a module-state token / mode word is ≤ 32 B in practice) —
/// a hostile/corrupt length can never balloon the RAM tier.
const MAX_STATE_STR: usize = 128;

/// The typed app-level state record (the whole G7-RESIDUAL surface). Every field typed —
/// NEVER a stringly prefs bag (the uniffi-full-power law).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AppState {
    /// The persisted DNSCrypt module state token (was `savedDNSCryptState` — `ModuleState`
    /// enum-name strings: `RUNNING`/`STOPPED`/`UNDEFINED`/…). Kotlin owns the enum; the store
    /// carries the token opaquely (the cross-layer contract is the NAME string, as it was in prefs).
    pub saved_dnscrypt_state: String,
    /// The operation mode token (was `OPERATION_MODE` — `VPN_MODE`/`ROOT_MODE`/`PROXY_MODE`).
    /// SCHEMA SEAT: carried + persisted now; the 20-site call-site migration rides a later slice.
    pub operation_mode: String,
    /// The service-armed latch (was `VPN_SERVICE_ENABLED`). SCHEMA SEAT like `operation_mode`
    /// (35 sites migrate later; the field is live in the record either way).
    pub vpn_service_enabled: bool,
    /// The one-shot "default DNS preset seeded" latch (was `pref_default_preset_seeded`).
    pub default_preset_seeded: bool,
}

impl AppState {
    /// The cold baseline — exactly the legacy prefs defaults (absent key ⇒ `""` / `false`), so a
    /// cold rehydrate behaves byte-for-byte like a fresh install did on the prefs lane.
    pub(crate) fn cold() -> Self {
        AppState {
            saved_dnscrypt_state: String::new(),
            operation_mode: String::new(),
            vpn_service_enabled: false,
            default_preset_seeded: false,
        }
    }
}

// ===========================================================================================
// The on-disk codec (bounded, length-guarded, fail-safe — mirrors inu/mod.rs encode/decode)
// ===========================================================================================

/// Serialize [`AppState`] for [`crate::runtime_tier::DurableTier::write_through`]. Format
/// (big-endian):
///
/// ```text
/// version:u8 | flags:u8 (bit0=vpn_service_enabled, bit1=default_preset_seeded)
///   | dnscrypt_len:u16 | dnscrypt_bytes | mode_len:u16 | mode_bytes
/// ```
///
/// ~10-70 B — far under the durable tier's ceiling. Strings over [`MAX_STATE_STR`] are
/// truncated on encode (and refused on decode) so the blob is bounded from both sides.
pub(crate) fn encode_app_state(state: &AppState) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(8 + state.saved_dnscrypt_state.len() + state.operation_mode.len());
    out.push(APP_STATE_SNAP_VERSION);
    let mut flags = 0u8;
    if state.vpn_service_enabled {
        flags |= 0b0000_0001;
    }
    if state.default_preset_seeded {
        flags |= 0b0000_0010;
    }
    out.push(flags);
    put_bounded_str(&mut out, &state.saved_dnscrypt_state);
    put_bounded_str(&mut out, &state.operation_mode);
    out
}

/// Restore [`AppState`] from an [`encode_app_state`] payload (already integrity-checked by the
/// DurableTier frame). Length-guarded — a truncated/garbage tail, an over-bound string, or a
/// foreign/forward version yields [`AppState::cold`] (never an OOB read, never a panic).
pub(crate) fn decode_app_state(payload: &[u8]) -> AppState {
    let mut cur = payload;
    let Some(ver) = take_one(&mut cur) else {
        return AppState::cold();
    };
    if ver != APP_STATE_SNAP_VERSION {
        return AppState::cold(); // forward/foreign blob — a cold start, never a guessed parse.
    }
    let Some(flags) = take_one(&mut cur) else {
        return AppState::cold();
    };
    let Some(saved_dnscrypt_state) = read_bounded_str(&mut cur) else {
        return AppState::cold();
    };
    let Some(operation_mode) = read_bounded_str(&mut cur) else {
        return AppState::cold();
    };
    AppState {
        saved_dnscrypt_state,
        operation_mode,
        vpn_service_enabled: flags & 0b0000_0001 != 0,
        default_preset_seeded: flags & 0b0000_0010 != 0,
    }
}

/// Append a `u16`-length-prefixed UTF-8 string, truncated to [`MAX_STATE_STR`] (char-boundary
/// safe: a token here is ASCII in practice, but a multi-byte tail is dropped whole, never split).
fn put_bounded_str(buf: &mut Vec<u8>, s: &str) {
    let mut end = s.len().min(MAX_STATE_STR);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let b = &s.as_bytes()[..end];
    buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
    buf.extend_from_slice(b);
}

/// Read one length-prefixed string; `None` on truncation, over-bound length, or invalid UTF-8.
fn read_bounded_str(cur: &mut &[u8]) -> Option<String> {
    if cur.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([cur[0], cur[1]]) as usize;
    *cur = &cur[2..];
    if len > MAX_STATE_STR || cur.len() < len {
        return None;
    }
    let s = std::str::from_utf8(&cur[..len]).ok()?.to_owned();
    *cur = &cur[len..];
    Some(s)
}

/// Take one byte off the cursor.
fn take_one(cur: &mut &[u8]) -> Option<u8> {
    let (&b, rest) = cur.split_first()?;
    *cur = rest;
    Some(b)
}

// ===========================================================================================
// The store Object (RAM ⊗ NAND, the Inu template)
// ===========================================================================================

/// THE APP-STATE STORE — RAM hot tier (`Mutex<AppState>`) ⊗ NAND seam ([`DurableTier`]
/// (`crate::runtime_tier::DurableTier`)). Each method panic-firewalls its body.
#[derive(uniffi::Object)]
pub struct AppStateStore {
    /// RAM hot tier — the live [`AppState`] every getter reads.
    ram: Mutex<AppState>,
    /// NAND seam — the durable single-record mirror (atomic tmp+rename, integrity-framed).
    nand: crate::runtime_tier::DurableTier,
}

#[uniffi::export]
impl AppStateStore {
    /// Construct the store rooted at the app-private `durable_dir`. IO-FREE (the no-boot-IO-scan
    /// law): the RAM tier starts [`AppState::cold`]; call [`rehydrate`](Self::rehydrate) ONCE at
    /// boot to load the persisted state.
    #[uniffi::constructor]
    pub fn new(durable_dir: String) -> Arc<Self> {
        let nand = crate::runtime_tier::DurableTier::with_dir(
            PathBuf::from(&durable_dir),
            APP_STATE_RECORD_NAME,
        );
        Arc::new(Self {
            ram: Mutex::new(AppState::cold()),
            nand,
        })
    }

    /// Rehydrate the persisted [`AppState`] from NAND into RAM and RETURN it. Absent / corrupt /
    /// foreign / forward-version ⇒ [`AppState::cold`] (never an error across the boundary). Call
    /// ONCE at boot. Panic-firewalled → cold.
    pub fn rehydrate(&self) -> AppState {
        catch_unwind(AssertUnwindSafe(|| {
            let state = match self.nand.rehydrate() {
                Some(blob) => decode_app_state(&blob),
                None => AppState::cold(),
            };
            if let Ok(mut g) = self.ram.lock() {
                *g = state.clone();
            }
            state
        }))
        .unwrap_or_else(|_| AppState::cold())
    }

    /// The current RAM-tier [`AppState`] — a one-glance read, NO disk IO. Panic/poison → cold.
    pub fn snapshot(&self) -> AppState {
        catch_unwind(AssertUnwindSafe(|| match self.ram.lock() {
            Ok(g) => g.clone(),
            Err(_) => AppState::cold(),
        }))
        .unwrap_or_else(|_| AppState::cold())
    }

    /// The persisted DNSCrypt module-state token (`""` when never written — the legacy
    /// absent-key read). RAM read, no disk IO.
    pub fn saved_dnscrypt_state(&self) -> String {
        catch_unwind(AssertUnwindSafe(|| match self.ram.lock() {
            Ok(g) => g.saved_dnscrypt_state.clone(),
            Err(_) => String::new(),
        }))
        .unwrap_or_default()
    }

    /// Persist the DNSCrypt module-state token — CONTROL-PLANE write-through (a module state
    /// flip is a control event). Returns `true` on a durable write; RAM updates regardless
    /// (best-effort durability, the persist contract).
    pub fn set_saved_dnscrypt_state(&self, token: String) -> bool {
        self.mutate(move |s| s.saved_dnscrypt_state = token)
    }

    /// The operation-mode token (`""` when never written). RAM read, no disk IO.
    pub fn operation_mode(&self) -> String {
        catch_unwind(AssertUnwindSafe(|| match self.ram.lock() {
            Ok(g) => g.operation_mode.clone(),
            Err(_) => String::new(),
        }))
        .unwrap_or_default()
    }

    /// Persist the operation-mode token — CONTROL-PLANE write-through.
    pub fn set_operation_mode(&self, token: String) -> bool {
        self.mutate(move |s| s.operation_mode = token)
    }

    /// The service-armed latch. RAM read, no disk IO. Panic/poison → `false` (never a phantom
    /// armed service).
    pub fn vpn_service_enabled(&self) -> bool {
        catch_unwind(AssertUnwindSafe(|| match self.ram.lock() {
            Ok(g) => g.vpn_service_enabled,
            Err(_) => false,
        }))
        .unwrap_or(false)
    }

    /// Persist the service-armed latch — CONTROL-PLANE write-through.
    pub fn set_vpn_service_enabled(&self, on: bool) -> bool {
        self.mutate(move |s| s.vpn_service_enabled = on)
    }

    /// The one-shot "default preset seeded" latch. RAM read, no disk IO. Panic/poison → `false`
    /// (worst case the seeder re-checks — it is idempotent by design).
    pub fn default_preset_seeded(&self) -> bool {
        catch_unwind(AssertUnwindSafe(|| match self.ram.lock() {
            Ok(g) => g.default_preset_seeded,
            Err(_) => false,
        }))
        .unwrap_or(false)
    }

    /// Persist the seeded latch — CONTROL-PLANE write-through (fires once per install).
    pub fn set_default_preset_seeded(&self, on: bool) -> bool {
        self.mutate(move |s| s.default_preset_seeded = on)
    }

    /// Forget the persisted state (NAND record removed + RAM reset to cold) — the reset
    /// forget-path. Best-effort + non-failing. Panic → no-op.
    pub fn clear(&self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            self.nand.clear();
            if let Ok(mut g) = self.ram.lock() {
                *g = AppState::cold();
            }
        }));
    }
}

impl AppStateStore {
    /// Apply `f` to a clone of the RAM state, then write-through the result to NAND + RAM
    /// (keeping the tiers identical). The single body every typed setter rides. Returns `true`
    /// on a durable write; `false` on reject/poison/panic (RAM still updates when lockable).
    fn mutate(&self, f: impl FnOnce(&mut AppState)) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            let mut state = match self.ram.lock() {
                Ok(g) => g.clone(),
                Err(_) => return false,
            };
            f(&mut state);
            let ok = self.nand.write_through(&encode_app_state(&state)).is_ok();
            if let Ok(mut g) = self.ram.lock() {
                *g = state;
            }
            ok
        }))
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique-per-test temp dir (process-unique counter + tag — the inu/object.rs pattern).
    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("torta-appstate-{tag}-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn a_state() -> AppState {
        AppState {
            saved_dnscrypt_state: "RUNNING".into(),
            operation_mode: "VPN_MODE".into(),
            vpn_service_enabled: true,
            default_preset_seeded: true,
        }
    }

    #[test]
    fn codec_round_trips_every_field() {
        let state = a_state();
        assert_eq!(decode_app_state(&encode_app_state(&state)), state);
        // And the cold state round-trips too (the fresh-install identity).
        assert_eq!(
            decode_app_state(&encode_app_state(&AppState::cold())),
            AppState::cold()
        );
    }

    #[test]
    fn hostile_blobs_decode_cold_never_panic() {
        // Truncated, foreign-version, over-bound length, garbage UTF-8 — all cold, no panic.
        assert_eq!(decode_app_state(&[]), AppState::cold());
        assert_eq!(decode_app_state(&[99, 0]), AppState::cold()); // forward version
        assert_eq!(
            decode_app_state(&[APP_STATE_SNAP_VERSION]),
            AppState::cold()
        ); // no flags
           // Over-bound string length claim (0xFFFF) with a short tail.
        assert_eq!(
            decode_app_state(&[APP_STATE_SNAP_VERSION, 0, 0xFF, 0xFF, b'x']),
            AppState::cold()
        );
        // Invalid UTF-8 payload in the string slot.
        assert_eq!(
            decode_app_state(&[APP_STATE_SNAP_VERSION, 0, 0, 2, 0xC3, 0x28]),
            AppState::cold()
        );
    }

    #[test]
    fn over_long_token_is_truncated_on_encode_and_still_decodes() {
        let mut state = a_state();
        state.saved_dnscrypt_state = "S".repeat(MAX_STATE_STR + 50);
        let back = decode_app_state(&encode_app_state(&state));
        assert_eq!(back.saved_dnscrypt_state.len(), MAX_STATE_STR);
        assert_eq!(
            back.operation_mode, state.operation_mode,
            "the tail field survives the bound"
        );
    }

    #[test]
    fn store_writes_through_and_survives_reopen() {
        let dir = temp_dir("reopen");
        let store = AppStateStore::new(dir.to_string_lossy().into_owned());
        assert_eq!(
            store.rehydrate(),
            AppState::cold(),
            "fresh dir rehydrates cold"
        );
        assert!(store.set_saved_dnscrypt_state("RUNNING".into()));
        assert!(store.set_operation_mode("VPN_MODE".into()));
        assert!(store.set_vpn_service_enabled(true));
        assert!(store.set_default_preset_seeded(true));
        assert_eq!(store.snapshot(), a_state(), "RAM sees every write");
        // Process death: a REOPENED store rehydrates the full state from NAND.
        let reopened = AppStateStore::new(dir.to_string_lossy().into_owned());
        assert_eq!(
            reopened.rehydrate(),
            a_state(),
            "NAND read-back after reopen"
        );
        // The forget-path.
        reopened.clear();
        assert_eq!(reopened.snapshot(), AppState::cold());
        let cleared = AppStateStore::new(dir.to_string_lossy().into_owned());
        assert_eq!(
            cleared.rehydrate(),
            AppState::cold(),
            "clear removed the record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
