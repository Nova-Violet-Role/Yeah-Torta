/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! THE INU STORE — the stateful Wire Cake Inu durable-state pillar (a `#[derive(uniffi::Object)]`,
//! the ALWAYS-BUILT form, alongside [`crate::warden::object::WardenObject`] /
//! [`crate::beast::Beast`] / [`crate::blocklist::github::GithubTrustEngine`]).
//!
//! Kotlin constructs ONE `Arc<InuStore>` at boot (passing the app-private durable dir), calls
//! [`InuStore::rehydrate`] ONCE to load the persisted posture, then: reads [`InuStore::snapshot`] for the
//! SLINT dashboard (RAM, zero IO), calls [`InuStore::persist`] on each control-plane change (a grant, a
//! revert, a pair flip, an expert toggle, a status change), writes review lines via
//! [`InuStore::log_event`], and reads the friendly "protected" glance via [`InuStore::is_protected`].
//!
//! ## The pattern (the DurableTier-backed Object template — the `GithubTrustEngine` shape)
//!   1. `#[derive(uniffi::Object)] pub struct InuStore` — interior state is `Mutex<InuState>` (the RAM hot
//!      tier, the dashboard read surface) + a [`DurableTier`](crate::runtime_tier::DurableTier) (the NAND
//!      seam; `Clone`, `&self` methods, `Send + Sync` → no Mutex needed, the atomic tmp+rename IS the guard).
//!   2. `#[uniffi::constructor] fn new(durable_dir) -> Arc<Self>` — IO-FREE (the no-boot-IO-scan law); the
//!      RAM tier is [`InuState::cold`], the caller drives [`rehydrate`](InuStore::rehydrate) explicitly.
//!   3. `#[uniffi::export] impl InuStore` — `&self` methods, each panic-firewalled to a safe default.
//!   4. The typed surface (the Enums + Records) lives in [`super`] (`inu/mod.rs`) — the full-power
//!      [`InuState`] / [`InuPowerFlag`] / [`InuProvider`] / [`InuElevationStatus`] / [`InuBootDurability`] /
//!      [`InuPowerId`], NEVER a flat string.
//!
//! ## Two writers is a bug — one authoritative driver
//! Both Kotlin and Rust hold an [`InuState`]; KOTLIN is the authoritative driver, Rust is the durable+cache
//! tier for the dashboard read surface. [`persist`](InuStore::persist) takes the FULL state (keeping RAM ⊗
//! NAND identical); [`snapshot`](InuStore::snapshot) serves the dashboard from RAM. Never two writers.
//!
//! ## no-hot-path-write (F16) + panic firewall
//! [`persist`](InuStore::persist) issues the ONLY `write_through` — call it on the control plane, NEVER on an
//! availability/ping poll (the dashboard poll is [`snapshot`](InuStore::snapshot), boot is
//! [`rehydrate`](InuStore::rehydrate)). Every method wraps `catch_unwind(AssertUnwindSafe(...))` → a safe
//! default (`persist`→`false`, the reads→cold/`false`/`""`) so a bug never unwinds across the FFI boundary.
//!
//! ## Unsafe posture
//! `#![forbid(unsafe_code)]` (module-inner, under the crate's `#![forbid(unsafe_op_in_unsafe_fn)]`).

#![forbid(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::log;
use super::{decode_state, encode_state, InuEvent, InuProvider, InuState, INU_RECORD_NAME};

/// THE INU STORE — the Wire Cake Inu durable elevation/power-state pillar. Interior state is the RAM hot
/// tier (`Mutex<InuState>` — the dashboard read surface) ⊗ the NAND seam (a [`DurableTier`]). Each method
/// panic-firewalls its body — a bug returns a safe default, never aborts the app.
#[derive(uniffi::Object)]
pub struct InuStore {
    /// RAM hot tier — the live [`InuState`] the SLINT dashboard reads via [`InuStore::snapshot`].
    ram: Mutex<InuState>,
    /// NAND seam — the durable single-record mirror (atomic tmp+rename, integrity-framed, bounded).
    nand: crate::runtime_tier::DurableTier,
}

#[uniffi::export]
impl InuStore {
    /// Construct the store rooted at the app-private `durable_dir`. UniFFI Object ctors MUST return
    /// `Arc<Self>`. IO-FREE (the no-boot-IO-scan law, `runtime_tier.rs:131-140`): the RAM tier is
    /// [`InuState::cold`]; the caller calls [`rehydrate`](InuStore::rehydrate) ONCE at boot to load the
    /// persisted posture. `durable_dir` is the app-private `filesDir` (the no-permission NAND tier).
    #[uniffi::constructor]
    pub fn new(durable_dir: String) -> Arc<Self> {
        let nand = crate::runtime_tier::DurableTier::with_dir(
            PathBuf::from(&durable_dir),
            INU_RECORD_NAME,
        );
        Arc::new(Self {
            ram: Mutex::new(InuState::cold()),
            nand,
        })
    }

    /// Rehydrate the persisted [`InuState`] from NAND into the RAM tier and RETURN it (the boot read the
    /// SLINT dashboard + the boot-reapply plan consume). A cold / absent / corrupt / foreign / forward-
    /// version record yields [`InuState::cold`] (never an error, never a panic across the boundary). Call
    /// ONCE at boot. Panic-firewalled → cold.
    pub fn rehydrate(&self) -> InuState {
        catch_unwind(AssertUnwindSafe(|| {
            let state = match self.nand.rehydrate() {
                Some(blob) => decode_state(&blob),
                None => InuState::cold(),
            };
            if let Ok(mut g) = self.ram.lock() {
                *g = state.clone();
            }
            state
        }))
        .unwrap_or_else(|_| InuState::cold())
    }

    /// GENTLE write-through of the FULL [`InuState`] to NAND + the RAM tier (keeping them identical).
    /// CONTROL-PLANE ONLY (a grant / revert / pair flip / expert toggle / status change) — NEVER an
    /// availability/ping poll (the no-hot-path-write law, F16). `fully_protected` is RECOMPUTED from the
    /// powers (a caller-supplied value is ignored — it is derived). Returns `true` on a durable write;
    /// `false` on a [`WriteReject`](crate::runtime_tier::WriteReject) / panic — best-effort durability (the
    /// RAM tier still updates so the dashboard is correct even when the durable copy could not be written).
    pub fn persist(&self, state: InuState) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            let normalized = state.normalized();
            let ok = self.nand.write_through(&encode_state(&normalized)).is_ok();
            if let Ok(mut g) = self.ram.lock() {
                *g = normalized;
            }
            ok
        }))
        .unwrap_or(false)
    }

    /// The current RAM-tier [`InuState`] — the SLINT dashboard's one-glance read. NO disk IO (the poll
    /// path, F16). Panic/poison → [`InuState::cold`] (honest "off").
    pub fn snapshot(&self) -> InuState {
        catch_unwind(AssertUnwindSafe(|| match self.ram.lock() {
            Ok(g) => g.clone(),
            Err(_) => InuState::cold(),
        }))
        .unwrap_or_else(|_| InuState::cold())
    }

    /// The friendly "protected / not protected" glance (the RAM tier's derived
    /// [`fully_protected`](InuState::fully_protected)): at least one power desired AND every desired power
    /// last read back held. NO disk IO. Panic/poison → `false` (never a false "protected").
    pub fn is_protected(&self) -> bool {
        catch_unwind(AssertUnwindSafe(|| match self.ram.lock() {
            Ok(g) => g.fully_protected,
            Err(_) => false,
        }))
        .unwrap_or(false)
    }

    /// Append ONE elevation-event line to `query-inu.log` (the #133 per-pillar review feed). `event` is the
    /// TYPED [`InuEvent`] (PAIR / ELEVATE / GRANT / REVERT / SWITCH / DRIFT_REAPPLY / FAIL) — a closed set so
    /// the token can never drift across the FFI; `detail` is the open per-event text (the power token / uid /
    /// read-back result), sanitized so it can never tear the line schema. `now_ms` is the INJECTED wall
    /// clock. For a provider switch prefer [`log_provider_switch`](Self::log_provider_switch) (it frames the
    /// from→to). FAIL-OPEN + OFF the hot path (the explicit review-channel seam). An UNBOUND store (no dir
    /// resolvable) is a silent no-op. Panic → no-op.
    pub fn log_event(&self, event: InuEvent, provider: InuProvider, detail: String, now_ms: i64) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let path = self.query_inu_log_path();
            log::append_inu_event(&path, now_ms, event.label(), provider, &detail);
        }));
    }

    /// Append a PROVIDER-SWITCH line (`SWITCH`) — the active elevation channel changed `from`→`to`
    /// (Shizuku↔self-adb, the role-named switch). The typed both-provider event the single-provider
    /// [`log_event`](Self::log_event) cannot express: the `to` provider is the line's provider field, the
    /// `from` is carried as `from=<key>` (greppable both directions). FAIL-OPEN + OFF the hot path.
    /// Panic → no-op.
    pub fn log_provider_switch(&self, from: InuProvider, to: InuProvider, now_ms: i64) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let path = self.query_inu_log_path();
            log::append_provider_switch(&path, now_ms, from, to);
        }));
    }

    /// The most-recent `max_lines` of `query-inu.log` (oldest→newest, '\n'-joined) via the shared
    /// [`crate::log_tier`] tailer — the dashboard's "recent events" surface. Panic/IO → `""`.
    pub fn tail_log(&self, max_lines: u32) -> String {
        catch_unwind(AssertUnwindSafe(|| {
            crate::log_tier::log_tail_recent(
                &self.query_inu_log_path().to_string_lossy(),
                max_lines as usize,
            )
        }))
        .unwrap_or_default()
    }

    /// Seconds since `query-inu.log` was last written (the #126 anti-stale freshness signal), or `-1` if
    /// absent/unreadable. Panic → `-1`.
    pub fn log_stale_secs(&self) -> i64 {
        catch_unwind(AssertUnwindSafe(|| {
            crate::log_tier::log_stale_secs(&self.query_inu_log_path().to_string_lossy())
        }))
        .unwrap_or(-1)
    }

    /// The "re-establish elevation silently at boot" arm ([`InuState::boot_reapply`] — the #21
    /// G7-RESIDUAL absorb of `TortaeKeys.INU_BOOT_REAPPLY`). RAM read, NO disk IO (the poll path);
    /// callers rehydrate ONCE at boot first. Panic/poison → `false` (the legacy pref default —
    /// never a surprise boot elevation).
    pub fn boot_reapply(&self) -> bool {
        catch_unwind(AssertUnwindSafe(|| match self.ram.lock() {
            Ok(g) => g.boot_reapply,
            Err(_) => false,
        }))
        .unwrap_or(false)
    }

    /// Arm/disarm the boot re-apply ([`InuState::boot_reapply`]) — CONTROL-PLANE write-through (the
    /// SLINT pillar toggle + the one-shot legacy-pref absorb; never a poll). Rides [`persist`]
    /// (`Self::persist`) so RAM + NAND stay identical. Returns `true` on a durable write; `false` on
    /// reject/panic (RAM still updates — best-effort durability, the persist contract).
    pub fn set_boot_reapply(&self, on: bool) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            let mut state = match self.ram.lock() {
                Ok(g) => g.clone(),
                Err(_) => return false,
            };
            state.boot_reapply = on;
            self.persist(state)
        }))
        .unwrap_or(false)
    }

    /// Forget the persisted state (NAND record removed + RAM reset to [`InuState::cold`]) — the
    /// "disable protection" / uninstall / reset forget-path (#8 reversibility). Best-effort + non-failing.
    /// Panic → no-op.
    pub fn clear(&self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            self.nand.clear();
            if let Ok(mut g) = self.ram.lock() {
                *g = InuState::cold();
            }
        }));
    }
}

/// Rust-side reads that do NOT cross the UniFFI seam (deliberately OUTSIDE the exported `impl` — Kotlin
/// has no need for them, so they add no bindgen surface). Mirrors the shape the rotation pillar already
/// uses for exactly this problem: [`crate::resolver::rotation::RotationState::rehydrate_opt`].
impl InuStore {
    /// Rehydrate, distinguishing **"no record"** from **"a record that decoded to cold-ish values"** —
    /// a distinction `rehydrate() == InuState::cold()` structurally CANNOT make. `None` means nothing was
    /// ever persisted; `Some(state)` means a real record exists, even if every field happens to sit at its
    /// default. NEVER on a hot path — a control-plane / boot read.
    ///
    /// This exists because torta_ui's Inu rail must choose between the REAL Kotlin-driven store and a
    /// seeded demo posture, and getting that backwards renders invented elevation state over the user's
    /// own. The `!= cold()` predicate shipped first and is right in every case observed on device, but it
    /// misreads one real case: a record persisted while all fields sit at defaults would read as
    /// never-written. `rotation.rs:140` documents that exact trap for the sibling pillar; this closes it
    /// for Inu with the same shape instead of a second approximation.
    pub fn rehydrate_exists(&self) -> Option<InuState> {
        catch_unwind(AssertUnwindSafe(|| {
            let blob = self.nand.rehydrate()?;
            let state = crate::inu::decode_state(&blob);
            if let Ok(mut g) = self.ram.lock() {
                *g = state.clone();
            }
            Some(state)
        }))
        .unwrap_or(None)
    }
}

impl InuStore {
    /// The on-disk path of the per-pillar `query-inu.log` — a SIBLING of the Inu state blob under the
    /// pillar's app-private durable dir (`nand.path().with_file_name(...)`, the warden `query-warden.log`
    /// pattern). Not a UniFFI export — an internal path helper.
    fn query_inu_log_path(&self) -> PathBuf {
        self.nand.path().with_file_name(log::QUERY_INU_LOG_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inu::{InuBootDurability, InuElevationStatus, InuPowerFlag, InuPowerId};

    /// A unique-per-test temp dir (process-unique counter + tag → collision-free; no rng dep).
    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("torta-inu-{tag}-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn a_state() -> InuState {
        InuState {
            elevation_status: InuElevationStatus::Elevated,
            provider: InuProvider::SelfAdb,
            paired: true,
            granted_at: 1_751_000_000_999,
            expert_enabled: true,
            boot_reapply: true, // #21 — the store sample rides bit2 SET.
            powers: vec![
                InuPowerFlag {
                    id: InuPowerId::AlwaysOnVpn,
                    desired: true,
                    last_verified: 111,
                    last_result: true,
                    durability: InuBootDurability::Durable,
                },
                InuPowerFlag {
                    id: InuPowerId::BatteryStandbyBucket,
                    desired: true,
                    last_verified: 222,
                    last_result: true,
                    durability: InuBootDurability::DriftProne,
                },
            ],
            fully_protected: false, // deliberately wrong — persist must recompute it to true
        }
    }

    // ---- THE REBOOT ROUND-TRIP (the migrated state survives a rehydrate — the task's required test) --

    #[test]
    fn persist_then_a_fresh_store_rehydrates_the_same_state() {
        let dir = temp_dir("reboot");
        let store = InuStore::new(dir.to_string_lossy().into_owned());
        let state = a_state();
        assert!(store.persist(state.clone()), "the durable write succeeds");

        // A FRESH InuStore over the SAME dir — a "reboot" (new process state). Its cold RAM must load the
        // persisted posture on rehydrate.
        let reborn = InuStore::new(dir.to_string_lossy().into_owned());
        assert_eq!(
            reborn.snapshot(),
            InuState::cold(),
            "cold before rehydrate (no boot IO)"
        );
        let loaded = reborn.rehydrate();

        // The persisted state comes back — with fully_protected RECOMPUTED to true (persist normalized it).
        let mut expected = state;
        expected.fully_protected = true;
        assert_eq!(
            loaded, expected,
            "the migrated/granted state survives a reboot rehydrate (all fields + recomputed protected)"
        );
        assert_eq!(
            reborn.snapshot(),
            expected,
            "rehydrate populated the RAM tier"
        );
        assert!(reborn.is_protected(), "the friendly glance is protected");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rehydrate_exists_separates_absent_from_persisted_cold() {
        // THE case `rehydrate() != cold()` cannot see, and the reason `rehydrate_exists` exists.
        let dir = temp_dir("exists");
        let store = InuStore::new(dir.to_string_lossy().into_owned());
        assert!(
            store.rehydrate_exists().is_none(),
            "absent record ⇒ None (nothing was ever persisted)"
        );

        // Persist a state whose every field sits at its default — a REAL record that is byte-for-byte
        // indistinguishable from cold by value. torta_ui's Inu rail must still treat this as the user's
        // own state and NOT paint the seeded demo posture over it.
        assert!(store.persist(InuState::cold()), "cold-valued persist lands");
        assert_eq!(
            store.rehydrate(),
            InuState::cold(),
            "by VALUE it is identical to never-written — this is the trap"
        );
        assert!(
            store.rehydrate_exists().is_some(),
            "a persisted cold-valued record is FOUND ⇒ Some (the distinction == cold() cannot make)"
        );

        // And the old predicate is provably wrong on this same record.
        assert!(
            !(store.rehydrate() != InuState::cold()),
            "the shipped-first `!= cold()` predicate reads this REAL record as never-written"
        );
    }

    #[test]
    fn cold_rehydrate_on_absent_record() {
        let dir = temp_dir("cold");
        let store = InuStore::new(dir.to_string_lossy().into_owned());
        assert_eq!(
            store.rehydrate(),
            InuState::cold(),
            "absent record ⇒ cold start"
        );
        assert!(
            !dir.exists(),
            "the no-IO ctor + a cold rehydrate touch no disk"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #21 — `set_boot_reapply` is a control-plane write-through: the flip lands in RAM AND NAND,
    /// and a REOPENED store (fresh process, same dir) rehydrates the flipped value.
    #[test]
    fn set_boot_reapply_writes_through_and_survives_reopen() {
        let dir = temp_dir("bootreapply");
        let store = InuStore::new(dir.to_string_lossy().into_owned());
        assert!(store.persist(a_state()), "seed state (boot_reapply=true) persists");
        assert!(store.boot_reapply(), "RAM sees the armed seed");
        assert!(store.set_boot_reapply(false), "the disarm write-through lands durably");
        assert!(!store.boot_reapply(), "RAM sees the disarm");
        let reopened = InuStore::new(dir.to_string_lossy().into_owned());
        let state = reopened.rehydrate();
        assert!(!state.boot_reapply, "the disarm survived process death (NAND read-back)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_normalizes_fully_protected() {
        let dir = temp_dir("normalize");
        let store = InuStore::new(dir.to_string_lossy().into_owned());
        // A desired-but-NOT-held power ⇒ fully_protected must be FALSE even if the caller passes true.
        let state = InuState {
            elevation_status: InuElevationStatus::Elevated,
            provider: InuProvider::Shizuku,
            paired: true,
            granted_at: 1,
            expert_enabled: false,
            boot_reapply: false,
            powers: vec![InuPowerFlag {
                id: InuPowerId::Lockdown,
                desired: true,
                last_verified: 5,
                last_result: false,
                durability: InuBootDurability::Durable,
            }],
            fully_protected: true, // wrong
        };
        store.persist(state);
        assert!(
            !store.is_protected(),
            "persist recomputes fully_protected from the powers (desired-but-not-held ⇒ not protected)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_forgets_the_state() {
        let dir = temp_dir("clear");
        let store = InuStore::new(dir.to_string_lossy().into_owned());
        assert!(store.persist(a_state()));
        store.clear();
        assert_eq!(store.snapshot(), InuState::cold(), "clear resets RAM");
        // A fresh store rehydrates cold (the NAND record is gone).
        let reborn = InuStore::new(dir.to_string_lossy().into_owned());
        assert_eq!(
            reborn.rehydrate(),
            InuState::cold(),
            "clear removed the durable record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- the log seam (the per-pillar review feed) --------------------------------------------------

    #[test]
    fn log_event_round_trips_through_the_pillar_log() {
        let dir = temp_dir("log");
        let store = InuStore::new(dir.to_string_lossy().into_owned());
        // The role-named events, TYPED: a grant, an elevate, an ADB-pair, a boot-reapply, and a provider
        // switch (Shizuku→self-adb) — each written with its canonical InuEvent label.
        store.log_event(
            InuEvent::Grant,
            InuProvider::SelfAdb,
            "lockdown=held".to_string(),
            100,
        );
        store.log_event(
            InuEvent::Elevate,
            InuProvider::SelfAdb,
            "uid=2000".to_string(),
            101,
        );
        store.log_event(InuEvent::Pair, InuProvider::SelfAdb, "ok".to_string(), 102);
        store.log_event(
            InuEvent::DriftReapply,
            InuProvider::SelfAdb,
            "battery_standby_bucket=held".to_string(),
            103,
        );
        store.log_provider_switch(InuProvider::Shizuku, InuProvider::SelfAdb, 104);
        let tail = store.tail_log(10);
        assert!(
            tail.contains("GRANT self-adb lockdown=held"),
            "grant line logged: {tail}"
        );
        assert!(
            tail.contains("ELEVATE self-adb uid=2000"),
            "elevate line logged: {tail}"
        );
        assert!(
            tail.contains("PAIR self-adb ok"),
            "pair line logged: {tail}"
        );
        assert!(
            tail.contains("DRIFT_REAPPLY self-adb battery_standby_bucket=held"),
            "boot-reapply line logged: {tail}"
        );
        assert!(
            tail.contains("SWITCH self-adb from=shizuku"),
            "provider-switch line logged with from→to: {tail}"
        );
        // The log sits BESIDE the state blob (a sibling under the same dir).
        assert!(
            dir.join(log::QUERY_INU_LOG_NAME).exists(),
            "query-inu.log lives beside the state"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_does_not_write_disk() {
        // The poll path (snapshot / is_protected) never touches NAND (F16). Construct, snapshot many times,
        // and assert NO durable record was written (only persist writes).
        let dir = temp_dir("poll-free");
        let store = InuStore::new(dir.to_string_lossy().into_owned());
        for _ in 0..64 {
            let _ = store.snapshot();
            let _ = store.is_protected();
        }
        assert!(
            !dir.exists(),
            "snapshot/is_protected are RAM-only — the poll path writes NOTHING (F16 no-hot-path-write)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
