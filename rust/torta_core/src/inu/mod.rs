/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! WIRE CAKE INU — the elevation / power-state RAM⊗NAND core (the crown neither Shizuku nor our old
//! stack had). This is the Rust half of the `wire_cake_inu` pillar: it REPLACES the Kotlin
//! `SharedPreferencesPowerStateStore` (the `wireless_debug_power_map` string blob + the two grant
//! booleans) with a full-power typed [`InuState`] persisted through [`crate::runtime_tier::DurableTier`]
//! (the RAM heap ⊗ NAND atomic-tmp+rename tier). Kotlin drives; Rust caches + persists + logs.
//!
//! ## What lives here vs what stays Kotlin (the honest seam — this is a Kotlin-heavy pillar)
//! The elevation LOGIC (ADB pairing, the Shizuku binder, the grant/read-back convergence) is inherently
//! Android/Kotlin and STAYS there (`GrantEngine`, `ShizukuElevation`, `AdbConnectionManager`). The RUST
//! piece is ONLY the DURABLE STATE + its typed UniFFI surface: the elevation status, the active provider,
//! the ADB-pair flags, the per-power grant map, and the boot-reapply durability tags. The ADB key/cert
//! (RSA-2048 + X.509, `AdbConnectionManager.java:75-76`) STAY as `filesDir` binary artifacts managed by
//! libadb — [`InuState`] carries only a derived `paired: bool`, NEVER the key bytes.
//!
//! ## The migration is a KOTLIN concern (the F9/F10 data-loss rescue)
//! The `durability` tag (Durable vs DriftProne) is derived from `PowerCatalogue.driftProne`, which is
//! Kotlin data — Rust does NOT know which powers drift, so it never guesses it (a second source of truth
//! would drift). The `RustPowerStateStore : PowerStateStore` Kotlin wrapper does the one-time migration:
//! on first construct, if [`InuStore::rehydrate`] is cold AND the old `WIRELESS_DEBUG_POWER_MAP` pref has
//! data, it `PowerStateCodec.decode`s it, maps each `PowerState` → [`InuPowerFlag`] (setting `durability`
//! from `PowerCatalogue.driftProne`), folds the two grant booleans into `paired`/`granted_at`, builds an
//! [`InuState`], and calls [`InuStore::persist`] ONCE. Rust's job is a faithful, typed store — never the
//! migration reader (which needs `Context` + the catalogue).
//!
//! ## The RAM⊗NAND + no-hot-path-write law (load-bearing)
//! [`InuStore::persist`] issues a [`DurableTier::write_through`](crate::runtime_tier::DurableTier::write_through)
//! ONLY on a CONTROL-PLANE event (a grant, a revert, a pair flip, an expert toggle, a status change) — NEVER
//! from an availability poll (`ShizukuElevation.availability()` is polled on UI focus; a write per poll would
//! flash-write-amplify). The dashboard poll calls [`InuStore::snapshot`] (RAM, zero IO); boot calls
//! [`InuStore::rehydrate`] once. This is the same law [`crate::runtime_tier`] documents (`runtime_tier.rs:20-23`).
//!
//! ## Base-build-safe (byte-identical baseline)
//! This module is UN-gated (always built, like [`crate::warden`] / [`crate::beast`]) and pulls NO
//! feature-gated dep — only std + [`crate::runtime_tier`] (SHA-256 base spine) + [`crate::log_tier`] + the
//! base `uniffi` scaffolding. So it compiles clean in the base cargo-ndk `.so` AND under `--features
//! pure_rust` (the x86_64 Universal). No `fortress`-only type is referenced.
//!
//! ## Safety posture
//! `#![forbid(unsafe_code)]` (module-inner, under the crate's `#![forbid(unsafe_op_in_unsafe_fn)]`,
//! `lib.rs:20`). std-only IO through the durable tier; every UniFFI method in [`object`] is
//! panic-firewalled → a bug returns a safe default, never unwinds across the FFI boundary.

#![forbid(unsafe_code)]

mod log;
pub mod object;

/// The DurableTier record name for the Inu state (a stable per-pillar filename under the app-private
/// `filesDir`, sanitized by [`crate::runtime_tier::DurableTier::with_dir`]). `query-inu.log` is its
/// sibling (see [`log::QUERY_INU_LOG_NAME`]).
pub(crate) const INU_RECORD_NAME: &str = "wire-cake-inu-state";

/// The Inu state blob format version — the FIRST payload byte. Bumped if the framing changes; a record
/// written by a NEWER version rehydrates as a cold start (the forward-incompat discipline — never a
/// guessed parse). The outer [`crate::runtime_tier::DurableTier`] frame (MAGIC + version + digest) already
/// guards foreignness + integrity, so this inner version byte only guards the payload framing.
const INU_SNAP_VERSION: u8 = 1;

/// A defensive cap on the persisted power rows (there are only 12 real powers — [`InuPowerId`]). A blob
/// carrying more is truncated on encode / stops on decode, so a hostile/corrupt count can never balloon
/// the tiny record. Well under the durable tier's 256 KiB ceiling.
const MAX_INU_POWERS: usize = 64;

// ===========================================================================================
// Enums (the full-power UniFFI-bridged typed surface — NEVER a flat string)
// ===========================================================================================

/// The coarse elevation lifecycle — the UniFFI-bridged twin of the Kotlin `ElevationState` machine
/// (`ElevationState.kt:22-54`, declaration order). `code()` is the STABLE ordinal the SLINT dashboard +
/// Kotlin decode contract read (`elevation-status:int` — Violet's `InuDashboard` contract:
/// `0 RESTING · 1 FETCHING(discovering/pairing/connecting) · … · 4 ELEVATED`). Data-free — the transient
/// `Failed` reason/detail is NOT persisted (it is a live signal, not durable state).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum InuElevationStatus {
    /// Nothing in flight — the resting state (`ElevationState.Idle`).
    Idle = 0,
    /// Locating the privileged channel (`ElevationState.Discovering`).
    Discovering = 1,
    /// Establishing trust — SPAKE2 + TLS pairing (`ElevationState.Pairing`).
    Pairing = 2,
    /// Opening the privileged shell (`ElevationState.Connecting`).
    Connecting = 3,
    /// A live privileged session is held — UID-2000 commands run (`ElevationState.Elevated`).
    Elevated = 4,
    /// The absorbing failure state (`ElevationState.Failed`); the reason/detail is transient, not stored.
    Failed = 5,
}

impl InuElevationStatus {
    /// The stable ordinal (the SLINT/Kotlin decode contract). `#[repr(i32)]` makes this a zero-cost cast.
    /// Not called from lib code yet (the Kotlin/SLINT executors + tests read it) — asserted in tests.
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Stable `u8` for the durable blob (a FORMAT CONTRACT — never renumber).
    fn to_u8(self) -> u8 {
        self as u8
    }

    /// Decode the durable byte; an unknown/forward ordinal maps to the inert [`Idle`](Self::Idle)
    /// (fail-safe — never an over-claim of elevation).
    fn from_u8(b: u8) -> Self {
        match b {
            1 => Self::Discovering,
            2 => Self::Pairing,
            3 => Self::Connecting,
            4 => Self::Elevated,
            5 => Self::Failed,
            _ => Self::Idle,
        }
    }
}

/// The active elevation provider — the UniFFI-bridged provider surface the dashboard renders.
///
/// GROUND_TRUTH reconciliation (surfaced, not silently picked): the Kotlin `ProviderId` has exactly TWO
/// routing channels — `SHIZUKU("shizuku")` + `SELF_ADB("self-adb")` (`ElevationProvider.kt:58-59`). The
/// brief's "Shizuku/LibAdb/Stub" conflated the CHANNEL with the self-ADB BACKEND (`LibAdbElevation` vs
/// `StubAdbElevation`). This enum models what the DASHBOARD sees (Violet's `InuDashboard` contract:
/// `active-provider:int 0 NONE · 1 SHIZUKU · 2 SELF-ADB · 3 STUB`): [`SelfAdb`](Self::SelfAdb) = the
/// self-ADB channel on the LIVE libadb backend; [`Stub`](Self::Stub) = the self-ADB channel on the inert
/// `StubAdbElevation` backend (surfaced distinctly so the UI can say "demo stub"). The in-app-binder
/// provider (the banked Stage-3 "exceeds Shizuku" spike) would append as a new ordinal 4 (`Inu`) if it
/// ever lands — enums are append-safe, so the 0..3 dashboard contract stays stable.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum InuProvider {
    /// Not elevated — no channel is the active provider.
    None = 0,
    /// The Shizuku channel (`ProviderId.SHIZUKU`).
    Shizuku = 1,
    /// The self-ADB channel on the live libadb backend (`ProviderId.SELF_ADB` + `LibAdbElevation`).
    SelfAdb = 2,
    /// The self-ADB channel on the inert stub backend (`StubAdbElevation`, `isImplemented=false`) — a
    /// demo/unimplemented state the dashboard surfaces distinctly.
    Stub = 3,
}

impl InuProvider {
    /// The stable ordinal (the SLINT/Kotlin decode contract). Not called from lib code yet (the Kotlin/
    /// SLINT executors + tests read it) — the documented-contract surface, asserted in tests.
    pub fn code(self) -> i32 {
        self as i32
    }

    /// The stable key token — the human-legible provider id used in `query-inu.log` + the Kotlin mapping
    /// (`ProviderId.displayId`: "shizuku" / "self-adb"; "stub" for the inert backend; "none" unelevated).
    pub fn key(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Shizuku => "shizuku",
            Self::SelfAdb => "self-adb",
            Self::Stub => "stub",
        }
    }

    /// Parse a provider key back to the enum; an unknown token → [`None`](Self::None) (fail-safe). The
    /// Kotlin-mapping contract (`ProviderId.displayId` → this enum); tested, not yet called from lib code.
    pub fn from_key(s: &str) -> Self {
        match s {
            "shizuku" => Self::Shizuku,
            "self-adb" => Self::SelfAdb,
            "stub" => Self::Stub,
            _ => Self::None,
        }
    }

    /// Stable `u8` for the durable blob (a FORMAT CONTRACT — never renumber).
    fn to_u8(self) -> u8 {
        self as u8
    }

    /// Decode the durable byte; an unknown/forward ordinal maps to [`None`](Self::None) (fail-safe).
    fn from_u8(b: u8) -> Self {
        match b {
            1 => Self::Shizuku,
            2 => Self::SelfAdb,
            3 => Self::Stub,
            _ => Self::None,
        }
    }
}

/// A power's persistence durability across a reboot — the UniFFI-bridged twin of Kotlin
/// `BootReapplyPolicy.Durability` (`BootReapplyPolicy.kt:26-31`, DURABLE first). Denormalized into each
/// [`InuPowerFlag`] so a boot [`InuStore::rehydrate`](object::InuStore::rehydrate) returns a
/// self-contained re-establish plan; the AUTHORITATIVE source stays `PowerCatalogue.driftProne` (Kotlin),
/// reconciled on the next grant.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum InuBootDurability {
    /// Survives a reboot in `secure` settings — re-verify only on boot.
    Durable = 0,
    /// The OS drifts it back (the standby bucket) — re-apply on every boot.
    DriftProne = 1,
}

impl InuBootDurability {
    /// The stable ordinal (the SLINT/Kotlin decode contract). Not called from lib code yet (the Kotlin/
    /// SLINT executors + tests read it) — the documented-contract surface, asserted in tests.
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// The stable identity of one privileged power — the UniFFI-bridged twin of Kotlin `PowerId`
/// (`PowerCatalogue.kt:38-50`). [`key()`](Self::key) / [`from_key()`](Self::from_key) return/parse the
/// EXACT `PowerId.key` strings — this is the cross-store-compat contract that makes the Kotlin
/// `PowerState` ⇄ [`InuPowerFlag`] mapping (and the F9/F10 migration) trivial + lossless. The durable
/// blob frames a power by its key STRING (reorder-proof + self-describing), never a positional ordinal.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum InuPowerId {
    AlwaysOnVpn = 0,
    Lockdown = 1,
    LockdownAllowlistEmpty = 2,
    BatteryBackground = 3,
    BatteryRunInBackground = 4,
    BatteryWakeLock = 5,
    BatteryDozeWhitelist = 6,
    BatteryStandbyBucket = 7,
    PostNotifications = 8,
    ReadLogs = 9,
    DataSaverBypass = 10,
    WriteSecureSettings = 11,
    // #63 S2 AMPLIFICATION — pillar-mapped elevated powers (append-only, ordinals NEVER reused). All
    // Tier-3 Expert opt-ins on the Kotlin side; the first three change GLOBAL OS scope (the DNS/privacy
    // sovereignty crown), the last three are self-target appops.
    PrivateDnsOff = 12,
    CaptivePortalOff = 13,
    WifiScanThrottleOff = 14,
    UsageStats = 15,
    ScheduleExactAlarm = 16,
    SystemAlertWindow = 17,
    // The STRONG DNS-ignore — a DNS-family power added after the appops but kept append-only (ordinal 18).
    // Distinct from `PrivateDnsOff` (which owns the `private_dns_mode` key): this purges the
    // `private_dns_specifier` DoT hostname so no pinned resolver survives even a mode flip (zero-leak).
    IgnoreSystemDns = 18,
    // Netstack sovereignty — stop the OS network-recommendation service steering around our userspace stack.
    NetworkRecommendationsOff = 19,
    // Advanced VPN — the ACTIVATE_VPN appop: (re)establish our VpnService with NO consent dialog (seamless
    // always-on across reinstall/reboot/crash). Distinct from the manifest BIND_VPN_SERVICE we already hold.
    ActivateVpn = 20,
}

impl InuPowerId {
    /// The stable ordinal (the SLINT/Kotlin decode contract). Not called from lib code yet (the Kotlin/
    /// SLINT executors + tests read it) — the documented-contract surface, asserted in tests.
    pub fn code(self) -> i32 {
        self as i32
    }

    /// The exact `PowerId.key` string (`PowerCatalogue.kt:39-50`) — the cross-store-compat + durable-blob
    /// framing key. NEVER change these strings (the on-disk + cross-language contract).
    pub fn key(self) -> &'static str {
        match self {
            Self::AlwaysOnVpn => "always_on_vpn",
            Self::Lockdown => "lockdown",
            Self::LockdownAllowlistEmpty => "lockdown_allowlist_empty",
            Self::BatteryBackground => "battery_background",
            Self::BatteryRunInBackground => "battery_run_in_background",
            Self::BatteryWakeLock => "battery_wake_lock",
            Self::BatteryDozeWhitelist => "battery_doze_whitelist",
            Self::BatteryStandbyBucket => "battery_standby_bucket",
            Self::PostNotifications => "post_notifications",
            Self::ReadLogs => "read_logs",
            Self::DataSaverBypass => "data_saver_bypass",
            Self::WriteSecureSettings => "write_secure_settings",
            Self::PrivateDnsOff => "private_dns_off",
            Self::CaptivePortalOff => "captive_portal_off",
            Self::WifiScanThrottleOff => "wifi_scan_throttle_off",
            Self::UsageStats => "usage_stats",
            Self::ScheduleExactAlarm => "schedule_exact_alarm",
            Self::SystemAlertWindow => "system_alert_window",
            Self::IgnoreSystemDns => "ignore_system_dns",
            Self::NetworkRecommendationsOff => "network_recommendations_off",
            Self::ActivateVpn => "activate_vpn",
        }
    }

    /// Parse a `PowerId.key` string back to the enum; an unknown key → `None` (the caller skips that row —
    /// the `PowerStateCodec.decode` `mapNotNull` fail-safe, `GrantEngine.kt:182`).
    pub fn from_key(s: &str) -> Option<Self> {
        Some(match s {
            "always_on_vpn" => Self::AlwaysOnVpn,
            "lockdown" => Self::Lockdown,
            "lockdown_allowlist_empty" => Self::LockdownAllowlistEmpty,
            "battery_background" => Self::BatteryBackground,
            "battery_run_in_background" => Self::BatteryRunInBackground,
            "battery_wake_lock" => Self::BatteryWakeLock,
            "battery_doze_whitelist" => Self::BatteryDozeWhitelist,
            "battery_standby_bucket" => Self::BatteryStandbyBucket,
            "post_notifications" => Self::PostNotifications,
            "read_logs" => Self::ReadLogs,
            "data_saver_bypass" => Self::DataSaverBypass,
            "write_secure_settings" => Self::WriteSecureSettings,
            "private_dns_off" => Self::PrivateDnsOff,
            "captive_portal_off" => Self::CaptivePortalOff,
            "wifi_scan_throttle_off" => Self::WifiScanThrottleOff,
            "usage_stats" => Self::UsageStats,
            "schedule_exact_alarm" => Self::ScheduleExactAlarm,
            "system_alert_window" => Self::SystemAlertWindow,
            "ignore_system_dns" => Self::IgnoreSystemDns,
            "network_recommendations_off" => Self::NetworkRecommendationsOff,
            "activate_vpn" => Self::ActivateVpn,
            _ => return None,
        })
    }
}

/// The class of a logged elevation event — the typed, CLOSED set the Inu writes to `query-inu.log` (the
/// #133 per-pillar review feed, [`log::append_inu_event`]). Typed (NOT a free string) so the event token
/// can never drift across the FFI / Kotlin call sites — every writer emits the SAME canonical
/// [`label()`](Self::label), keeping the log greppable + consistent (the Socio's review channel). Only the
/// EVENT is a closed enum; the `detail` (the power token / uid / from-provider) stays an open sanitized
/// string. Append-safe: a future event is a NEW variant, never a renamed string. These are the events the
/// role names — a grant, an ADB-pair, a provider switch (Shizuku↔self-adb), a boot-reapply — made
/// first-class.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum InuEvent {
    /// An ADB pairing landed (the self-ADB SPAKE2/TLS pair, or a Shizuku bind) → `PAIR`.
    Pair = 0,
    /// A privileged session opened — UID-2000 commands can now run → `ELEVATE`.
    Elevate = 1,
    /// A power was granted / re-applied (the `detail` names the power + read-back result) → `GRANT`.
    Grant = 2,
    /// A power was reverted (the "disable protection" undo path, #8 reversibility) → `REVERT`.
    Revert = 3,
    /// The active provider switched (Shizuku↔self-adb) → `SWITCH`; prefer
    /// [`InuStore::log_provider_switch`](object::InuStore::log_provider_switch) which frames the from→to.
    ProviderSwitch = 4,
    /// A drift-prone power was re-applied on boot (the boot-reapply re-establish, the #1 live-gap closer)
    /// → `DRIFT_REAPPLY`.
    DriftReapply = 5,
    /// An elevation step failed (a pair/grant/read-back error) — the honest fault line → `FAIL`.
    Fail = 6,
}

impl InuEvent {
    /// The canonical, greppable UPPERCASE token written to `query-inu.log`. STABLE — never rename (the
    /// on-disk + cross-language log contract; a debug tailer greps these). `ProviderSwitch` → `SWITCH`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pair => "PAIR",
            Self::Elevate => "ELEVATE",
            Self::Grant => "GRANT",
            Self::Revert => "REVERT",
            Self::ProviderSwitch => "SWITCH",
            Self::DriftReapply => "DRIFT_REAPPLY",
            Self::Fail => "FAIL",
        }
    }
}

// ===========================================================================================
// Records (the full-power typed state — NEVER a flat string)
// ===========================================================================================

/// One privileged power's persisted state — the UniFFI-bridged twin of Kotlin `PowerState`
/// (`GrantEngine.kt:149-154`) plus the derived [`durability`](Self::durability) boot tag. Field-parity
/// with `PowerState` makes the round-trip provably lossless. The `reverseCmd` is NOT here (it is a
/// compile-time constant in `PowerOp`, `PowerCatalogue.kt:80`, rebuilt via `PowerCatalogue.build(pkg)`;
/// `revertAll` reads only `desired` from the store — `GrantEngine.kt:55-77`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct InuPowerFlag {
    /// Which power (the join key to `PowerCatalogue`).
    pub id: InuPowerId,
    /// The user intends this power held (`PowerState.desired`) — Shizuku's `onetime` "protect once" maps
    /// to `false`, "keep protected" to `true`.
    pub desired: bool,
    /// Epoch-ms of the last verify (`PowerState.lastVerified`).
    pub last_verified: i64,
    /// The last LIVE read-back result — held (`true`) or not (`PowerState.lastResult`). Never inferred.
    pub last_result: bool,
    /// The boot durability tag (denormalized from `PowerCatalogue.driftProne`; Kotlin sets it).
    pub durability: InuBootDurability,
}

/// The whole Inu elevation / power state — the full-power typed replacement for the four
/// `SharedPreferencesPowerStateStore` keys (`TortaeKeys.java:162,163,167,172`), folded into ONE record.
/// Every field is typed (enum / Record list / bool / i64) — NEVER a flat string (the uniffi-full-power
/// law). The ADB key/cert bytes stay in `filesDir`; this carries only the derived [`paired`](Self::paired).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct InuState {
    /// The coarse elevation lifecycle (live/advisory; the `Failed` reason is not persisted).
    pub elevation_status: InuElevationStatus,
    /// The active / last-used provider (`WIRELESS_DEBUG` had NO persisted provider — this is a NEW field).
    pub provider: InuProvider,
    /// Derived pair flag (was `WIRELESS_DEBUG_GRANTED`); the RSA key/cert bytes stay in `filesDir`.
    pub paired: bool,
    /// Epoch-ms of the grant (was `WIRELESS_DEBUG_GRANTED_AT`).
    pub granted_at: i64,
    /// The Expert-mode toggle (was `WIRELESS_DEBUG_EXPERT` = `pref_wireless_debug_expert`) — the SLINT
    /// Expert reveal writes it through here.
    pub expert_enabled: bool,
    /// The "re-establish elevation silently at boot" arm (was `TortaeKeys.INU_BOOT_REAPPLY` =
    /// `pref_inu_boot_reapply` — the #21 G7-RESIDUAL absorb: the last Inu flag living outside this
    /// record). Rides `hdr_flags` bit2 in the blob — a pre-absorb v1 blob (bit clear) decodes `false`,
    /// exactly the legacy pref default, so NO version bump is needed (additive-default-false bit).
    pub boot_reapply: bool,
    /// The per-power grant map (was the `WIRELESS_DEBUG_POWER_MAP` `PowerStateCodec` string).
    pub powers: Vec<InuPowerFlag>,
    /// DERIVED, not persisted: `true` iff at least one power is desired AND every desired power last read
    /// back held — the friendly "protected / not protected" dashboard glance. Recomputed on
    /// encode/decode/persist; a caller-supplied value is IGNORED. Distinct from the catalogue-relative
    /// `GrantEngine.isFullyProtected` (`GrantEngine.kt:133-136`, "every catalogue power held"), which
    /// Kotlin still owns.
    pub fully_protected: bool,
}

impl InuState {
    /// The cold baseline — an unelevated, unpaired, no-powers state (the default rehydrate on an absent /
    /// corrupt record).
    ///
    /// `pub` because it is the only exact answer to "has this record ever been written?": [`rehydrate`]
    /// returns exactly this value for an absent record (`object.rs:88`), and [`InuState`] derives
    /// `PartialEq`, so a consumer holding a rehydrated state can compare against it rather than guessing
    /// from one field. torta_ui's Inu rail uses precisely that to decide between the real Kotlin-driven
    /// store and its seeded fallback — a per-field heuristic there would misread a record written by a
    /// boot-reapply or provider change as never-written.
    ///
    /// [`rehydrate`]: crate::inu::object::InuStore::rehydrate
    pub fn cold() -> Self {
        InuState {
            elevation_status: InuElevationStatus::Idle,
            provider: InuProvider::None,
            paired: false,
            granted_at: 0,
            expert_enabled: false,
            boot_reapply: false,
            powers: Vec::new(),
            fully_protected: false,
        }
    }

    /// Return `self` with [`fully_protected`](Self::fully_protected) RECOMPUTED from the powers (a
    /// caller-supplied value is authoritative-derived, never trusted). Called by
    /// [`InuStore::persist`](object::InuStore::persist) before encoding.
    pub(crate) fn normalized(mut self) -> Self {
        self.fully_protected = compute_fully_protected(&self.powers);
        self
    }
}

/// The "protected" glance: at least one power is DESIRED and every desired power's last read-back HELD.
/// An all-undesired or empty set is NOT protected (nothing is being enforced).
fn compute_fully_protected(powers: &[InuPowerFlag]) -> bool {
    let mut any_desired = false;
    for p in powers {
        if p.desired {
            any_desired = true;
            if !p.last_result {
                return false;
            }
        }
    }
    any_desired
}

// ===========================================================================================
// The on-disk codec (bounded, length-guarded, fail-safe — mirrors warden/mod.rs snapshot/restore)
// ===========================================================================================

/// Serialize [`InuState`] into the bounded, self-describing payload for
/// [`crate::runtime_tier::DurableTier::write_through`]. Format (all big-endian, powers framed by their
/// stable KEY string so the blob is reorder-proof + self-describing):
///
/// ```text
/// version:u8 | hdr_flags:u8 (bit0=paired, bit1=expert) | status:u8 | provider:u8
///   | granted_at:i64 | power_count:u32
///   | powers[]: key_len:u16 | key_bytes | pf_flags:u8 (bit0=desired, bit1=last_result, bit2=drift_prone)
///              | last_verified:i64
/// ```
///
/// `fully_protected` is NOT encoded (it is derived on [`decode_state`]). The blob is ~40 B + ~30 B/power
/// (≈400 B for the full set) — far under the durable tier's 256 KiB ceiling.
pub(crate) fn encode_state(state: &InuState) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + state.powers.len() * 32);
    out.push(INU_SNAP_VERSION);
    let mut hdr = 0u8;
    if state.paired {
        hdr |= 0b0000_0001;
    }
    if state.expert_enabled {
        hdr |= 0b0000_0010;
    }
    if state.boot_reapply {
        hdr |= 0b0000_0100; // #21 — the boot-reapply arm (additive bit, see InuState::boot_reapply).
    }
    out.push(hdr);
    out.push(state.elevation_status.to_u8());
    out.push(state.provider.to_u8());
    out.extend_from_slice(&state.granted_at.to_be_bytes());
    let count = state.powers.len().min(MAX_INU_POWERS) as u32;
    out.extend_from_slice(&count.to_be_bytes());
    for p in state.powers.iter().take(MAX_INU_POWERS) {
        put_str(&mut out, p.id.key());
        let mut pf = 0u8;
        if p.desired {
            pf |= 0b0000_0001;
        }
        if p.last_result {
            pf |= 0b0000_0010;
        }
        if matches!(p.durability, InuBootDurability::DriftProne) {
            pf |= 0b0000_0100;
        }
        out.push(pf);
        out.extend_from_slice(&p.last_verified.to_be_bytes());
    }
    out
}

/// Restore [`InuState`] from an [`encode_state`] payload (handed back by the DurableTier, already
/// integrity-checked + bound-capped). Every field is length-guarded — a truncated/garbage tail simply
/// STOPS the parse (never an OOB read, never a panic). A foreign / forward-version blob is a cold start.
/// An unknown power KEY is consumed (to keep the cursor aligned) then SKIPPED (the `PowerStateCodec`
/// `mapNotNull` fail-safe). `fully_protected` is recomputed from the admitted powers.
pub(crate) fn decode_state(payload: &[u8]) -> InuState {
    let mut cur = payload;
    let Some(ver) = take_one(&mut cur) else {
        return InuState::cold();
    };
    if ver != INU_SNAP_VERSION {
        return InuState::cold(); // a foreign / forward-version blob is a cold start, never a guessed parse.
    }
    let Some(hdr) = take_one(&mut cur) else {
        return InuState::cold();
    };
    let Some(status_b) = take_one(&mut cur) else {
        return InuState::cold();
    };
    let Some(provider_b) = take_one(&mut cur) else {
        return InuState::cold();
    };
    let Some(granted_at) = read_i64_be(&mut cur) else {
        return InuState::cold();
    };
    let Some(count) = read_u32_be(&mut cur) else {
        return InuState::cold();
    };

    let mut powers: Vec<InuPowerFlag> = Vec::new();
    let capped = (count as usize).min(MAX_INU_POWERS);
    for _ in 0..capped {
        let Some(key) = read_str(&mut cur) else {
            break; // truncated tail — keep what parsed cleanly (fail-safe).
        };
        let Some(pf) = take_one(&mut cur) else {
            break;
        };
        let Some(last_verified) = read_i64_be(&mut cur) else {
            break;
        };
        // An unknown key is consumed above (cursor stays aligned) then skipped here.
        if let Some(id) = InuPowerId::from_key(&key) {
            powers.push(InuPowerFlag {
                id,
                desired: pf & 0b0000_0001 != 0,
                last_result: pf & 0b0000_0010 != 0,
                durability: if pf & 0b0000_0100 != 0 {
                    InuBootDurability::DriftProne
                } else {
                    InuBootDurability::Durable
                },
                last_verified,
            });
        }
    }

    InuState {
        elevation_status: InuElevationStatus::from_u8(status_b),
        provider: InuProvider::from_u8(provider_b),
        paired: hdr & 0b0000_0001 != 0,
        granted_at,
        expert_enabled: hdr & 0b0000_0010 != 0,
        boot_reapply: hdr & 0b0000_0100 != 0,
        fully_protected: compute_fully_protected(&powers),
        powers,
    }
}

// ---- length-guarded byte readers/writers (mirrors warden/mod.rs + github.rs, module-local) ----------

/// Append a `u16`-length-prefixed UTF-8 string (a byte string over `u16::MAX` is truncated to the bound).
fn put_str(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let len = b.len().min(u16::MAX as usize) as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&b[..len as usize]);
}

/// Read a `u16`-length-prefixed UTF-8 string off the cursor, advancing it; `None` on truncation.
fn read_str(cur: &mut &[u8]) -> Option<String> {
    let len = read_u16_be(cur)? as usize;
    if cur.len() < len {
        return None;
    }
    let s = String::from_utf8_lossy(&cur[..len]).into_owned();
    *cur = &cur[len..];
    Some(s)
}

/// Read one byte off the cursor, advancing it; `None` if empty.
fn take_one(cur: &mut &[u8]) -> Option<u8> {
    let (&b, rest) = cur.split_first()?;
    *cur = rest;
    Some(b)
}

/// Read a big-endian `u16` off the cursor, advancing it; `None` if fewer than 2 bytes remain.
fn read_u16_be(cur: &mut &[u8]) -> Option<u16> {
    if cur.len() < 2 {
        return None;
    }
    let v = u16::from_be_bytes([cur[0], cur[1]]);
    *cur = &cur[2..];
    Some(v)
}

/// Read a big-endian `u32` off the cursor, advancing it; `None` if fewer than 4 bytes remain.
fn read_u32_be(cur: &mut &[u8]) -> Option<u32> {
    if cur.len() < 4 {
        return None;
    }
    let v = u32::from_be_bytes([cur[0], cur[1], cur[2], cur[3]]);
    *cur = &cur[4..];
    Some(v)
}

/// Read a big-endian `i64` off the cursor, advancing it; `None` if fewer than 8 bytes remain.
fn read_i64_be(cur: &mut &[u8]) -> Option<i64> {
    if cur.len() < 8 {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&cur[..8]);
    *cur = &cur[8..];
    Some(i64::from_be_bytes(b))
}

/// A two-line user-facing notice (title + body) sourced from the canonical Rust layer. The repo is
/// `.xml`-free: user-facing copy rides the trio (Rust holds it → UniFFI bridges it → Kotlin-inject-wired
/// Kotlin renders it), never an Android string resource. Field-parity with an Android
/// `Notification.Builder` title/text pair.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct InuNotice {
    /// The notification title line.
    pub title: String,
    /// The notification body line.
    pub body: String,
}

/// #63 S3 — the SILENT boot re-arm foreground-notice copy. `WireCakeInuService.reapplyingNotification`
/// reads this over UniFFI while the Kotlin `reapplyOnBoot` reconnects codelessly and re-applies the
/// no-root powers after a reboot. Lives here (NOT `strings.xml`) so ALL user-facing Inu copy stays in one
/// canonical place — the first notification string migrated off the (now-forbidden) Android resource layer.
#[uniffi::export]
pub fn inu_rearm_notice() -> InuNotice {
    InuNotice {
        title: "Re-arming protection…".to_string(),
        body: "Restoring no-root powers after reboot.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flag(
        id: InuPowerId,
        desired: bool,
        lr: bool,
        d: InuBootDurability,
        lv: i64,
    ) -> InuPowerFlag {
        InuPowerFlag {
            id,
            desired,
            last_result: lr,
            durability: d,
            last_verified: lv,
        }
    }

    fn sample_full() -> InuState {
        // One flag per PowerId — the full 21-power set, mixed desired/result/durability.
        let ids = [
            InuPowerId::AlwaysOnVpn,
            InuPowerId::Lockdown,
            InuPowerId::LockdownAllowlistEmpty,
            InuPowerId::BatteryBackground,
            InuPowerId::BatteryRunInBackground,
            InuPowerId::BatteryWakeLock,
            InuPowerId::BatteryDozeWhitelist,
            InuPowerId::BatteryStandbyBucket,
            InuPowerId::PostNotifications,
            InuPowerId::ReadLogs,
            InuPowerId::DataSaverBypass,
            InuPowerId::WriteSecureSettings,
            InuPowerId::PrivateDnsOff,
            InuPowerId::CaptivePortalOff,
            InuPowerId::WifiScanThrottleOff,
            InuPowerId::UsageStats,
            InuPowerId::ScheduleExactAlarm,
            InuPowerId::SystemAlertWindow,
            InuPowerId::IgnoreSystemDns,
            InuPowerId::NetworkRecommendationsOff,
            InuPowerId::ActivateVpn,
        ];
        let powers = ids
            .iter()
            .enumerate()
            .map(|(i, &id)| {
                let drift = matches!(id, InuPowerId::BatteryStandbyBucket);
                flag(
                    id,
                    true,
                    true,
                    if drift {
                        InuBootDurability::DriftProne
                    } else {
                        InuBootDurability::Durable
                    },
                    1_751_000_000_000 + i as i64,
                )
            })
            .collect();
        InuState {
            elevation_status: InuElevationStatus::Elevated,
            provider: InuProvider::SelfAdb,
            paired: true,
            granted_at: 1_751_000_000_999,
            expert_enabled: true,
            boot_reapply: true, // #21 — bit2 SET in the full-roundtrip sample.
            powers,
            fully_protected: true,
        }
        .normalized()
    }

    // ---- THE ROUND-TRIP (the migrated state survives a rehydrate — the task's required test) --------

    #[test]
    fn encode_decode_round_trips_the_full_state() {
        let state = sample_full();
        let blob = encode_state(&state);
        let back = decode_state(&blob);
        assert_eq!(
            back, state,
            "the full 12-power InuState survives encode→decode byte-for-byte (the migrated state \
             survives a rehydrate)"
        );
        assert!(
            back.fully_protected,
            "all-desired all-held ⇒ fully_protected"
        );
    }

    #[test]
    fn empty_powers_round_trips() {
        let state = InuState {
            elevation_status: InuElevationStatus::Idle,
            provider: InuProvider::None,
            paired: false,
            granted_at: 0,
            expert_enabled: false,
            boot_reapply: false,
            powers: vec![],
            fully_protected: false,
        };
        let back = decode_state(&encode_state(&state));
        assert_eq!(back, state);
        assert!(
            !back.fully_protected,
            "an empty power set is NOT protected (nothing enforced)"
        );
    }

    /// #21 — the boot-reapply bit2 compat law: a blob with bit2 CLEAR is byte-identical to what a
    /// pre-absorb writer emitted (the ONLY change was the additive bit), and must decode
    /// `boot_reapply=false` (the legacy pref default); the armed sample round-trips bit2 SET.
    #[test]
    fn boot_reapply_bit_is_additive_default_false() {
        let mut disarmed = sample_full();
        disarmed.boot_reapply = false;
        let back = decode_state(&encode_state(&disarmed));
        assert!(
            !back.boot_reapply,
            "bit2-clear (≡ pre-absorb blob) decodes false"
        );
        let armed = sample_full();
        assert!(armed.boot_reapply, "sample_full arms bit2");
        assert!(
            decode_state(&encode_state(&armed)).boot_reapply,
            "the armed flag survives the roundtrip"
        );
    }

    #[test]
    fn single_power_and_flags_round_trip() {
        // A drift-prone, desired-but-NOT-held power (a drifted standby bucket) — every bit distinct.
        let state = InuState {
            elevation_status: InuElevationStatus::Failed,
            provider: InuProvider::Shizuku,
            paired: true,
            granted_at: 42,
            expert_enabled: false,
            boot_reapply: false,
            powers: vec![flag(
                InuPowerId::BatteryStandbyBucket,
                true,
                false,
                InuBootDurability::DriftProne,
                7,
            )],
            fully_protected: false,
        };
        let back = decode_state(&encode_state(&state));
        assert_eq!(back, state);
        assert!(
            !back.fully_protected,
            "a desired-but-not-held power ⇒ NOT fully protected"
        );
    }

    // ---- fully_protected derivation (the friendly dashboard glance) ---------------------------------

    #[test]
    fn fully_protected_requires_at_least_one_desired_all_held() {
        // desired+held ⇒ protected
        assert!(compute_fully_protected(&[flag(
            InuPowerId::Lockdown,
            true,
            true,
            InuBootDurability::Durable,
            0
        )]));
        // desired+not-held ⇒ NOT protected
        assert!(!compute_fully_protected(&[flag(
            InuPowerId::Lockdown,
            true,
            false,
            InuBootDurability::Durable,
            0
        )]));
        // only-undesired ⇒ NOT protected (nothing enforced)
        assert!(!compute_fully_protected(&[flag(
            InuPowerId::Lockdown,
            false,
            true,
            InuBootDurability::Durable,
            0
        )]));
        // empty ⇒ NOT protected
        assert!(!compute_fully_protected(&[]));
        // one desired-held + one undesired ⇒ protected (the undesired is ignored)
        assert!(compute_fully_protected(&[
            flag(
                InuPowerId::Lockdown,
                true,
                true,
                InuBootDurability::Durable,
                0
            ),
            flag(
                InuPowerId::ReadLogs,
                false,
                false,
                InuBootDurability::Durable,
                0
            ),
        ]));
    }

    // ---- fail-safe decode (the durable copy degrades gracefully) ------------------------------------

    #[test]
    fn empty_payload_decodes_cold() {
        assert_eq!(decode_state(&[]), InuState::cold());
    }

    #[test]
    fn wrong_version_decodes_cold() {
        let mut blob = encode_state(&sample_full());
        blob[0] = INU_SNAP_VERSION.wrapping_add(9);
        assert_eq!(
            decode_state(&blob),
            InuState::cold(),
            "a forward/unknown version is a cold start, never a guessed parse"
        );
    }

    #[test]
    fn truncated_header_decodes_cold() {
        let blob = encode_state(&sample_full());
        // Cut into the fixed header (before the power_count) — a torn record is cold.
        assert_eq!(decode_state(&blob[..5]), InuState::cold());
    }

    #[test]
    fn truncated_power_tail_keeps_what_parsed() {
        let state = sample_full();
        let blob = encode_state(&state);
        // Chop the last few bytes (a half-written final power row) — the parse stops, keeping the earlier
        // powers, and NEVER panics.
        let cut = decode_state(&blob[..blob.len() - 3]);
        assert!(
            cut.powers.len() < state.powers.len(),
            "a truncated tail drops the incomplete row, keeps the rest"
        );
        // The header fields still decoded.
        assert_eq!(cut.provider, state.provider);
        assert_eq!(cut.paired, state.paired);
    }

    #[test]
    fn unknown_provider_and_status_bytes_map_to_inert_defaults() {
        let mut blob = encode_state(&sample_full());
        // blob[2] = status, blob[3] = provider (after version, hdr).
        blob[2] = 200; // unknown status
        blob[3] = 200; // unknown provider
        let back = decode_state(&blob);
        assert_eq!(back.elevation_status, InuElevationStatus::Idle);
        assert_eq!(back.provider, InuProvider::None);
    }

    #[test]
    fn unknown_power_key_is_skipped_not_torn() {
        // Hand-frame a blob with ONE valid power + ONE unknown-key power between two valid ones, and prove
        // the unknown row is consumed+skipped WITHOUT losing cursor alignment for the row after it.
        let mut out = vec![
            INU_SNAP_VERSION,
            0u8, // hdr: not paired, not expert
            InuElevationStatus::Idle.to_u8(),
            InuProvider::None.to_u8(),
        ];
        out.extend_from_slice(&0i64.to_be_bytes()); // granted_at
        out.extend_from_slice(&3u32.to_be_bytes()); // 3 rows
        let mut push_row = |key: &str, pf: u8, lv: i64| {
            put_str(&mut out, key);
            out.push(pf);
            out.extend_from_slice(&lv.to_be_bytes());
        };
        push_row("always_on_vpn", 0b011, 100); // valid, desired+held
        push_row("some_future_power", 0b011, 200); // UNKNOWN key — must be skipped
        push_row("lockdown", 0b011, 300); // valid — proves alignment held past the unknown row

        let back = decode_state(&out);
        assert_eq!(
            back.powers.len(),
            2,
            "the unknown-key row is consumed+skipped; the two valid rows survive"
        );
        assert_eq!(back.powers[0].id, InuPowerId::AlwaysOnVpn);
        assert_eq!(back.powers[0].last_verified, 100);
        assert_eq!(
            back.powers[1].id,
            InuPowerId::Lockdown,
            "cursor alignment held past the unknown row (else this would be wrong/torn)"
        );
        assert_eq!(back.powers[1].last_verified, 300);
    }

    // ---- the enum key/ordinal contracts (the cross-store-compat guards) -----------------------------

    #[test]
    fn power_id_key_round_trips_all_twenty_one() {
        let all = [
            InuPowerId::AlwaysOnVpn,
            InuPowerId::Lockdown,
            InuPowerId::LockdownAllowlistEmpty,
            InuPowerId::BatteryBackground,
            InuPowerId::BatteryRunInBackground,
            InuPowerId::BatteryWakeLock,
            InuPowerId::BatteryDozeWhitelist,
            InuPowerId::BatteryStandbyBucket,
            InuPowerId::PostNotifications,
            InuPowerId::ReadLogs,
            InuPowerId::DataSaverBypass,
            InuPowerId::WriteSecureSettings,
            InuPowerId::PrivateDnsOff,
            InuPowerId::CaptivePortalOff,
            InuPowerId::WifiScanThrottleOff,
            InuPowerId::UsageStats,
            InuPowerId::ScheduleExactAlarm,
            InuPowerId::SystemAlertWindow,
            InuPowerId::IgnoreSystemDns,
            InuPowerId::NetworkRecommendationsOff,
            InuPowerId::ActivateVpn,
        ];
        for id in all {
            assert_eq!(
                InuPowerId::from_key(id.key()),
                Some(id),
                "key()↔from_key() round-trips for {id:?}"
            );
        }
        // The exact PowerCatalogue.kt key strings (the cross-language contract).
        assert_eq!(InuPowerId::AlwaysOnVpn.key(), "always_on_vpn");
        assert_eq!(
            InuPowerId::WriteSecureSettings.key(),
            "write_secure_settings"
        );
        // #63 S2 amplification keys — same PascalCase→snake_case contract; the Kotlin uniffi enum entry
        // is these uppercased (private_dns_off → PRIVATE_DNS_OFF), matching PowerId.key.uppercase().
        assert_eq!(InuPowerId::PrivateDnsOff.key(), "private_dns_off");
        assert_eq!(InuPowerId::CaptivePortalOff.key(), "captive_portal_off");
        assert_eq!(
            InuPowerId::WifiScanThrottleOff.key(),
            "wifi_scan_throttle_off"
        );
        assert_eq!(InuPowerId::UsageStats.key(), "usage_stats");
        assert_eq!(InuPowerId::ScheduleExactAlarm.key(), "schedule_exact_alarm");
        assert_eq!(InuPowerId::SystemAlertWindow.key(), "system_alert_window");
        assert_eq!(InuPowerId::IgnoreSystemDns.key(), "ignore_system_dns");
        assert_eq!(
            InuPowerId::NetworkRecommendationsOff.key(),
            "network_recommendations_off"
        );
        assert_eq!(InuPowerId::ActivateVpn.key(), "activate_vpn");
        assert_eq!(InuPowerId::from_key("not_a_power"), None);
    }

    #[test]
    fn power_id_amplification_ordinals_are_stable() {
        // Append-only ordinals — NEVER reused (the durable-blob + Kotlin decode contract).
        assert_eq!(InuPowerId::WriteSecureSettings.code(), 11);
        assert_eq!(InuPowerId::PrivateDnsOff.code(), 12);
        assert_eq!(InuPowerId::CaptivePortalOff.code(), 13);
        assert_eq!(InuPowerId::WifiScanThrottleOff.code(), 14);
        assert_eq!(InuPowerId::UsageStats.code(), 15);
        assert_eq!(InuPowerId::ScheduleExactAlarm.code(), 16);
        assert_eq!(InuPowerId::SystemAlertWindow.code(), 17);
        assert_eq!(InuPowerId::IgnoreSystemDns.code(), 18);
        assert_eq!(InuPowerId::NetworkRecommendationsOff.code(), 19);
        assert_eq!(InuPowerId::ActivateVpn.code(), 20);
    }

    #[test]
    fn enum_ordinals_are_stable() {
        // The SLINT/Kotlin decode contract — these ordinals are load-bearing (Violet's dashboard reads them).
        assert_eq!(InuElevationStatus::Idle.code(), 0);
        assert_eq!(InuElevationStatus::Elevated.code(), 4);
        assert_eq!(InuElevationStatus::Failed.code(), 5);
        assert_eq!(InuProvider::None.code(), 0);
        assert_eq!(InuProvider::Shizuku.code(), 1);
        assert_eq!(InuProvider::SelfAdb.code(), 2);
        assert_eq!(InuProvider::Stub.code(), 3);
        assert_eq!(InuBootDurability::Durable.code(), 0);
        assert_eq!(InuBootDurability::DriftProne.code(), 1);
    }

    #[test]
    fn provider_key_round_trips() {
        for p in [
            InuProvider::None,
            InuProvider::Shizuku,
            InuProvider::SelfAdb,
            InuProvider::Stub,
        ] {
            assert_eq!(InuProvider::from_key(p.key()), p);
        }
        assert_eq!(InuProvider::from_key("garbage"), InuProvider::None);
    }

    #[test]
    fn event_labels_are_canonical() {
        // Every event maps to its STABLE greppable token (the log contract a debug tailer greps). All 7
        // variants constructed here (also proves none is dead) — the role-named grant/pair/switch/reapply.
        assert_eq!(InuEvent::Pair.label(), "PAIR");
        assert_eq!(InuEvent::Elevate.label(), "ELEVATE");
        assert_eq!(InuEvent::Grant.label(), "GRANT");
        assert_eq!(InuEvent::Revert.label(), "REVERT");
        assert_eq!(InuEvent::ProviderSwitch.label(), "SWITCH");
        assert_eq!(InuEvent::DriftReapply.label(), "DRIFT_REAPPLY");
        assert_eq!(InuEvent::Fail.label(), "FAIL");
    }
}
