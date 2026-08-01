/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! THE CENTAURI OBJECT — the stateful Rust local-CDN mirror pillar (the R1.x.2 Object lift).
//!
//! The Centauri mirror was an early stateful pillar (after [`crate::beast::Beast`])
//! to become a stateful `#[derive(uniffi::Object)]`: Kotlin holds an `Arc<Centauri>` handle, constructs
//! it ONCE at boot, and drives its methods. This closes the "inert flat free-function" gap the audit
//! flagged — the content-addressed cache + the bound loopback port lived in a process-global
//! [`MirrorRuntime`] singleton ([`crate::MirrorRuntime`], `lib.rs:1470-1479`) reachable ONLY through the
//! flat `centauri_mirror_start` / `mirror_status` exports, with NO stateful handle Kotlin could hold an
//! `Arc` to. The Object makes the cache + serve state a LIVED accumulator the CentauriMirrorManager
//! drives directly, then reads a [`CentauriSnapshot`] for the dashboard.
//!
//! ## The pattern (the stateful-Object pillar template + a feature-gate)
//! Six-part surface, the pillar Object template applied to the Centauri mirror:
//!   1. `#[cfg(feature = "mirror")] #[derive(uniffi::Object)] pub struct Centauri` — interior state is
//!      `Mutex<T>` (std) + an `AtomicU16` for the bound port (lock-free read of the serve port). The
//!      crate is `#![forbid(unsafe_op_in_unsafe_fn)]` and this module is `#![forbid(unsafe_code)]`.
//!   2. `#[uniffi::constructor] fn new(cache_dir) -> Arc<Self>` — UniFFI Object ctors MUST return
//!      `Arc<Self>`. Builds the content-addressed [`CacheStore`] rooted at `cache_dir` (rehydrated from
//!      disk via the SAME #92 cache contract the flat `centauri_mirror_start` uses — math unchanged).
//!   3. `#[uniffi::export] impl Centauri` — `&self` methods, lock-then-act, each panic-firewalled.
//!   4. `#[derive(uniffi::Enum)] CentauriServeState` — the loopback serve lifecycle
//!      (`Stopped=0 · Starting=1 · Serving=2 · Failed=3`).
//!   5. `#[derive(uniffi::Record)] CentauriSnapshot` — the dashboard one-glance state (cache stats +
//!      serve port + the lived catalog/resolve counters).
//!   6. NO callback sink: the Centauri mirror is boot-static + serve-event-driven,
//!      not a hot streaming metric — Kotlin pulls a snapshot when it needs one.
//!
//! ## NO-BREAK CONTRACT (the load-bearing law)
//! The flat `#[uniffi::export]` fns in `lib.rs` (`mirror_install_catalog`, `centauri_cdn_hosts`,
//! `centauri_resolve_cdn`, `centauri_cloaking_rules`, `centauri_mirror_start`, `mirror_status`,
//! `rehydrate_centauri_from_signed`) STAY LIVE AND UNCHANGED. They are the stable surface:
//!   - [`crate::resolver`] never touches the mirror (the serve/resolve-cdn datapath is Rust-INTERNAL:
//!     `centauri_resolve_cdn` → `mirror::resolve_full` → `localcdn::resolve_full`, and the loopback
//!     `serve_cdn_url` calls the SAME `localcdn::resolve_full` server-side — NO Kotlin path resolves
//!     CDN URLs at runtime; the app only ASKS "is this covered" via the façade).
//!   - `CentauriMirrorManager.kt` + `CentauriArtifactManager.kt` compile against the Kotlin free-fn
//!     bindings today (`TortaCore.centauriMirrorStart`/`centauriMirrorStats`/...); those call-sites
//!     keep working byte-identically.
//!   - The `MIRROR_RUNTIME` OnceLock singleton (lib.rs:1479) keeps driving the LIVE serve loop +
//!     `mirror_status` reads the SAME store the loopback serves — the Object is ADDITIVE alongside,
//!     NOT a replacement (the singleton survives the Object refactor so the read-stats-vs-serve-bytes
//!     identity invariant holds for the flat path until the Socio's bindgen regen swaps the call-sites).
//!
//! The Object is ADDITIVE: Kotlin gets a NEW stateful surface alongside the flat fns. The math each
//! method performs is UNCHANGED — it DELEGATES to the SAME pure fns the flat exports wrap
//! (`mirror::Catalog::parse_verified`, `mirror::cdn_hosts`, `mirror::resolve_full`,
//! `mirror::cloaking_rules`, `CacheStore::len/total_bytes/is_full/capacity`,
//! `load_centauri_from_signed`). Zero CDN/catalog re-derivation.
//!
//! ## Panic firewall
//! Every Object method carries its OWN `catch_unwind(AssertUnwindSafe(...))` → a safe default (the
//! pillar fail-safe + the `lib.rs` flat-fn contract). A panic NEVER crosses the FFI boundary.
//!
//! ## Unsafe posture
//! `#![forbid(unsafe_code)]` (module-inner, under the crate's `#![forbid(unsafe_op_in_unsafe_fn)]`,
//! `lib.rs:20` — the same posture every `mirror/*.rs` carries). ring-free (the catalog hash is already
//! vendored via the `mirror::Catalog` minisign-verify path; no new deps).
//!
//! ## Feature gating
//! The WHOLE module is `#[cfg(feature = "mirror")]`-gated via the `pub mod object;` declaration in
//! `mirror/mod.rs` (itself under the crate-level `#[cfg(feature = "mirror")] pub mod mirror;` at
//! `lib.rs:84-85`). The struct + every export ALSO carry their own `#[cfg(feature = "mirror")]` —
//! doubly gated, so the BASE Android `.so` (cargo-ndk WITHOUT `--features mirror`) emits ZERO of
//! these symbols → byte-identical baseline (the Kotlin `ensureLoaded()` + try/catch façade keeps
//! degrading gracefully there, the crash-proof contract).

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use crate::{load_centauri_catalog_from_signed, CentauriRehydrateFail};
use crate::mirror::cache::content_hash;
use crate::mirror::{
    self, cdn_hosts, cloaking_rules_for, encode_catalog, resolve_full, CacheMode, CacheStore, Catalog,
    CatalogEntry, Resolution, ServeVerdict, Substitution,
};
use crate::mirror::{fetch_leg, upstream_url, InFlight, ServeOutcome, WarmUpTarget};

/// The bounded depth of the recent-serve ring the dashboard reads (the "what the mirror just served" feed).
/// Small + fixed: a glance feed, NOT the durable record (that is slice 6's `query-centauri.log`).
#[cfg(feature = "mirror")]
const RECENT_SERVES_CAP: usize = 64;

/// How many discovered hosts the LIVING-ROSTER dashboard surface shows (the top-hits slice of the growing
/// encyclopedia). Bounded so the `liveCentauriStats` flat-JSON crossing stays lean — the true distinct-host
/// total still rides the `discovered` scalar, so the header count is never capped by this display window.
#[cfg(feature = "mirror")]
const DISCOVERED_ROSTER_SHOWN: usize = 24;

// ===========================================================================================
// Enum (the UniFFI-bridged serve-state surface)
// ===========================================================================================

/// The loopback serve lifecycle, the UniFFI-bridged twin of the `MirrorRuntime` port semantics. The
/// `code()` is the STABLE ordinal the dashboard reads — `Stopped=0 · Starting=1 · Serving=2 ·
/// Failed=3` (the order mirrors the lived `centauri_mirror_start` flow: before start, while the
/// accept thread binds, once the port is known, and the sentinel on bind failure).
#[cfg(feature = "mirror")]
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CentauriServeState {
    /// The mirror has not been started (no loopback listener bound).
    Stopped = 0,
    /// The accept thread is building its runtime + binding the loopback listener.
    Starting = 1,
    /// The loopback listener is bound + the accept loop is driving (port > 0).
    Serving = 2,
    /// The listener failed to bind, or the accept thread panicked (port 0 / sentinel).
    Failed = 3,
}

#[cfg(feature = "mirror")]
impl CentauriServeState {
    /// The stable ordinal (the dashboard decode contract). The enum is `#[repr(i32)]` so this is a
    /// zero-cost cast; kept as a named fn so the ordinal contract is documented + asserted in tests.
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Decode a stable ordinal back to the serve state — the inverse of [`CentauriServeState::code`]. The
    /// Object stores the live serve lifecycle in an `AtomicU8` (`serve_state`); [`Centauri::snapshot`] reads
    /// it through this so the `Starting`/`Failed` arms (unreachable from a port-only inference) are LIVE.
    /// An out-of-range code degrades to `Stopped` (the safe baseline), never panics.
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => CentauriServeState::Starting,
            2 => CentauriServeState::Serving,
            3 => CentauriServeState::Failed,
            _ => CentauriServeState::Stopped,
        }
    }
}

// ===========================================================================================
// NEW typed Enums (slice 5 — the full UniFFI surface): the version-substitution verdict, the
// per-serve CROWN outcome, and the opt-out cache mode. Each is the UniFFI-bridged CROSS of a
// mirror-internal type (`localcdn::Substitution`, `serve::ServeVerdict`, `serve::CacheMode`) — the
// `From` impls keep them ONE source of truth, never a drifting parallel duplicate.
// ===========================================================================================

/// The version-substitution verdict the resolver reached for a CDN URL — the UniFFI-bridged twin of the
/// mirror-internal [`Substitution`] (localcdn.rs:45). Load-bearing for the F3 honesty split: an
/// integrity-pinned (SRI) consumer wants ONLY [`CentauriSubstitution::Exact`]; a fallback substitute would
/// fail its hash pin. The flat `resolve_cdn -> Option<String>` drops this verdict on the floor; the typed
/// [`Centauri::resolve_cdn_typed`] carries it (the full-power law: NEVER a flat string when a typed Enum fits).
#[cfg(feature = "mirror")]
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CentauriSubstitution {
    /// Byte-identical version requested and served (the only SRI-safe serve).
    Exact = 0,
    /// Same major, served ≥ requested minor.patch — backward-compatible, safe to serve.
    SafeNewer = 1,
    /// Same major, served is older than requested — may lack features; allowed but flagged.
    RiskyOlder = 2,
    /// Different major — the compatibility boundary; the resolver never serves this (returns `None`).
    Incompatible = 3,
    /// NO substitution verdict exists — the request served no bytes (a `NotInCatalog` miss: the host was
    /// a watched CDN but the path matched no library, so no version ladder ever ran). Distinct from
    /// `Exact`: a miss did not match a version, it matched nothing. The recent-serve ring renders this as
    /// an empty token so the dashboard never claims a phantom "exact" verdict on a 404. Tallies nothing.
    NotApplicable = 4,
}

#[cfg(feature = "mirror")]
impl From<Substitution> for CentauriSubstitution {
    fn from(s: Substitution) -> Self {
        match s {
            Substitution::Exact => CentauriSubstitution::Exact,
            Substitution::SafeNewer => CentauriSubstitution::SafeNewer,
            Substitution::RiskyOlder => CentauriSubstitution::RiskyOlder,
            Substitution::Incompatible => CentauriSubstitution::Incompatible,
        }
    }
}

/// The CROWN per-serve outcome — the data-free UniFFI-bridged cross of the mirror-internal
/// [`ServeVerdict`] (serve.rs:82, whose `ServedLocal(Vec<u8>)`/`LeakedThenServed(Vec<u8>)` payloads ride the
/// HTTP body, not the FFI). This is the verdict the dashboard + the recent-serve feed read; it encodes the
/// full ≤ 1-request lifecycle so "the CDN saw 0" becomes WITNESSABLE (Chroma F2), not asserted.
#[cfg(feature = "mirror")]
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CentauriServeOutcome {
    /// Cache hit → served from the device, the CDN saw 0 (the win). Bytes content-address-verified.
    ServedLocal = 0,
    /// Miss in leak-on-miss mode → fetch-ONCE (the ≤ 1) → hash-verified → cached → served.
    LeakedThenServed = 1,
    /// Miss in strict mode → served NOTHING ⇒ the CDN saw 0 (the crown). No bytes, no egress.
    BlockedMissing = 2,
    /// The request name is not authorized by the minisign-verified catalog (fail-closed, falls through).
    NotInCatalog = 3,
    /// The one allowed upstream fetch failed (transport / oversize / hash-mismatch) — no bytes served.
    FetchFailed = 4,
}

#[cfg(feature = "mirror")]
impl From<&ServeVerdict> for CentauriServeOutcome {
    fn from(v: &ServeVerdict) -> Self {
        match v {
            ServeVerdict::ServedLocal(_) => CentauriServeOutcome::ServedLocal,
            ServeVerdict::LeakedThenServed(_) => CentauriServeOutcome::LeakedThenServed,
            ServeVerdict::BlockedMissing => CentauriServeOutcome::BlockedMissing,
            ServeVerdict::NotInCatalog => CentauriServeOutcome::NotInCatalog,
            ServeVerdict::FetchFailed => CentauriServeOutcome::FetchFailed,
        }
    }
}

/// The opt-out CROWN toggle — the UniFFI-bridged surface of the mirror-internal [`CacheMode`] (serve.rs:67,
/// "the mode toggle is INTERNAL here; slice 5 surfaces it"). The safe default is [`CentauriCacheMode::
/// LeakOnMiss`] (a genuine miss self-fills with ≤ 1 upstream request, matching upstream LocalCDN UX); the
/// user OPTS IN to [`CentauriCacheMode::BlockMissing`] (serve-local-OR-nothing ⇒ the CDN sees 0 — the crown
/// ARMED). [`Centauri::set_cache_mode`] / [`Centauri::cache_mode`] drive it lock-free.
#[cfg(feature = "mirror")]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Enum)]
pub enum CentauriCacheMode {
    /// SAFE DEFAULT: a genuine miss leaks EXACTLY ONE self-fill request (then 0 forever, cached).
    #[default]
    LeakOnMiss = 0,
    /// STRICT (the crown ARMED): serve-local-OR-nothing ⇒ the CDN sees 0.
    BlockMissing = 1,
}

#[cfg(feature = "mirror")]
impl CentauriCacheMode {
    /// The stable `u8` code the Object stores in its `cache_mode` atomic (lock-free toggle).
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Decode the stored `u8` back to the mode (out-of-range ⇒ the safe `LeakOnMiss` default).
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => CentauriCacheMode::BlockMissing,
            _ => CentauriCacheMode::LeakOnMiss,
        }
    }
}

#[cfg(feature = "mirror")]
impl From<CacheMode> for CentauriCacheMode {
    fn from(m: CacheMode) -> Self {
        match m {
            CacheMode::LeakOnMiss => CentauriCacheMode::LeakOnMiss,
            CacheMode::BlockMissing => CentauriCacheMode::BlockMissing,
        }
    }
}

#[cfg(feature = "mirror")]
impl From<CentauriCacheMode> for CacheMode {
    /// The inverse cross — the live accept loop lowers the UniFFI toggle back to the datapath `CacheMode`
    /// it threads into [`crate::mirror::serve_addressed`] when it adopts the privacy flow (#85 seam).
    fn from(m: CentauriCacheMode) -> Self {
        match m {
            CentauriCacheMode::LeakOnMiss => CacheMode::LeakOnMiss,
            CentauriCacheMode::BlockMissing => CacheMode::BlockMissing,
        }
    }
}

// ===========================================================================================
// Typed Error (the 4th full-power UniFFI feature — #[derive(uniffi::Error)])
// ===========================================================================================

/// WHY a Centauri mirror security operation FAILED — the typed, UniFFI-bridged failure surface for
/// the Centauri Object's fallible methods. This is the FOURTH full-power UniFFI feature (a typed
/// `#[derive(uniffi::Error)]`): it replaces the lossy `bool`/`i32` returns of
/// [`Centauri::install_catalog`] / [`Centauri::rehydrate_from_signed`] / [`Centauri::start`] with a
/// `Result<_, CentauriError>` so Kotlin can `try/catch` ACTIONABLE failure reasons.
///
/// ## The variant map (GROUND_TRUTH — every variant maps to a REAL failure mode, none fabricated)
///   - [`InvalidSignature`] ⇄ [`Catalog::parse_verified`] returning [`CatalogError::BadSignature`]
///     (catalog.rs:208 — the verify-sig-FIRST gate failed; minisign over the catalog bytes did not
///     verify against the pinned Centauri key). The rehydrate path lifts the SAME mode via the typed
///     engine ([`crate::CentauriRehydrateFail::BadSignature`] — the banked split, landed).
///   - [`MalformedCatalog`] ⇄ [`CatalogError::Malformed`] (catalog.rs:223+ — the signature verified
///     but the catalog body could not be parsed: bad magic / version / hash-algo, a truncated record,
///     an out-of-bounds length, an unknown flag bit, non-UTF-8 name/host bytes). A producer bug, never
///     an attack vector (the body is already authenticated). The rehydrate path lifts the same mode via
///     [`crate::CentauriRehydrateFail::Malformed`].
///   - [`RehydrateFailed`] ⇄ [`crate::CentauriRehydrateFail::AbsentPair`] — the `.tcat`/`.sig` pair was
///     ABSENT on disk (cold start) or the durable file was unreadable. Distinct from `InvalidSignature`
///     so the operator can tell "no shipped catalog" from "catalog signature bad". (The historical
///     `load_centauri_from_signed` bool fold that projected ALL three modes here is split by the typed
///     [`crate::load_centauri_catalog_from_signed`] engine — each mode now maps to its own variant.)
///   - [`BindFailed`] ⇄ [`Centauri::start`]'s `-1` sentinel (the loopback listener failed to bind, or
///     the accept-thread panicked before reporting a port). Distinct from the catalog/rehydrate errors
///     (a bind failure is an OS-level resource exhaustion / port-conflict, NOT a security gate).
///   - [`Panic`] ⇄ the `catch_unwind` firewall fallback (a bug ⇒ typed error, never an abort across
///     the FFI boundary).
///
/// ## What is NOT here (scope-honest)
/// - [`Centauri::cdn_hosts`] / [`Centauri::resolve_cdn`] / [`Centauri::cloaking_rules`] are pure reads
///   over static data (the LocalCDN seed map) — infallible by construction (a poisoned lock is a bug,
///   panic-firewalled to an empty default). They STAY infallible.
/// - [`Centauri::snapshot`] / [`Centauri::status`] are pure reads over lived state — infallible.
///
/// ## `#[non_exhaustive]`
/// Future failure modes (e.g. a `CacheFull` once the bounded store rejects an insert) can be added
/// WITHOUT breaking the Kotlin binding — callers must handle the unknown-variant arm.
///
/// ## Kotlin contract
/// On the Socio's gradle regen, `CentauriError` becomes a Kotlin sealed/exception class. The `String`
/// reason field carries the human-readable detail for logs + the dashboard's expanded error card.
/// UniFFI auto-derives the `Display` impl from the variant name + field (via `thiserror`).
#[cfg(feature = "mirror")]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CentauriError {
    /// The minisign signature over the catalog bytes did not verify (verify-sig-FIRST gate failed).
    /// Maps [`CatalogError::BadSignature`] + the rehydrate path's signature failure.
    #[error("invalid signature: {reason}")]
    InvalidSignature { reason: String },

    /// The signature verified but the catalog body could not be parsed (bad magic / version / record /
    /// truncation / unknown flag / non-UTF-8). Maps [`CatalogError::Malformed`]. A producer bug.
    #[error("malformed catalog: {reason}")]
    MalformedCatalog { reason: String },

    /// The boot-rehydrate found no readable `.tcat`/`.sig` pair on disk (a cold start or an unreadable
    /// durable file) — [`crate::CentauriRehydrateFail::AbsentPair`], the typed split's non-signature
    /// mode (signature/body failures map to their own variants above).
    #[error("rehydrate failed: {reason}")]
    RehydrateFailed { reason: String },

    /// The loopback listener failed to bind (port exhaustion / OS denial) or the accept-thread panicked
    /// before reporting a port. Maps the `start()` `-1` sentinel. An OS-level failure, NOT a security gate.
    #[error("bind failed: {reason}")]
    BindFailed { reason: String },

    /// A panic inside the gate — the Object's `catch_unwind` firewall caught a bug and reports it as a
    /// typed error. Never expected in practice (the engine is panic-free); kept so the contract is total.
    #[error("panic: {reason}")]
    Panic { reason: String },
}

// ===========================================================================================
// Record (the dashboard snapshot)
// ===========================================================================================

/// One live Centauri snapshot — everything the dashboard renders about the content-addressed cache +
/// the loopback serve state. Kotlin pulls this via [`Centauri::snapshot`]; pure data, all fields
/// `pub`, flat primitives and the bridged enum (a dashboard one-glance snapshot Record).
#[cfg(feature = "mirror")]
#[derive(Debug, Clone, uniffi::Record)]
pub struct CentauriSnapshot {
    /// The number of cached assets (the dashboard's "serving N libraries" count,
    /// `CacheStore::len`, cache.rs:437).
    pub libraries: i64,
    /// The total bytes held across all cached assets (the "X bytes never left your device" feed,
    /// `CacheStore::total_bytes`, cache.rs:457).
    pub bytes: i64,
    /// Is the bounded content-addressed store full? (`CacheStore::is_full`, cache.rs:452).
    pub full: bool,
    /// The bounded store's capacity (the fail-closed ceiling, `CacheStore::capacity`, cache.rs:447).
    pub capacity: i64,
    /// The bound loopback port (`127.0.0.1:<port>`), or 0 before start / on bind failure.
    ///
    /// `i32` — the crate FFI convention for a u16 port (`ListenerSnapshot.port`, lib.rs). ★ E-FIX r3:
    /// this was `i16`, so any OS-assigned ephemeral port ≥ 32768 (e.g. 37955 = 0x9443) wrapped to a
    /// NEGATIVE display port (-27581) across the UniFFI boundary — witnessed live on the AVD. A u16
    /// NEVER fits an i16; it always fits an i32.
    pub serve_port: i32,
    /// The loopback serve lifecycle (Stops/Starting/Serving/Failed).
    pub serve_state: CentauriServeState,
    /// Running count of catalog install attempts (verify-sig-FIRST gate) since Object construction.
    pub catalog_installs_attempted: i64,
    /// Running count of catalog installs that VERIFIED + parsed (the `parse_verified` OK path).
    pub catalog_installs_verified: i64,
    /// Running count of CDN-URL resolve queries the Object answered (the `resolve_cdn` method).
    pub resolve_queries: i64,
    /// Running count of CDN-URL resolves that HIT a mapped catalog asset (resolve returned Some).
    pub resolve_hits: i64,
    /// Running count of `rehydrate_from_signed` boot-rehydrate attempts.
    pub rehydrates_attempted: i64,
    /// Running count of boot-rehydrates that verified a genuine signed catalog.
    pub rehydrates_verified: i64,
    // ---- slice 5 (the full UniFFI surface): catalog state + the CROWN witness counters ----
    /// CATALOG STATE: the number of assets the RETAINED signed catalog authorizes (`Catalog::len`,
    /// catalog.rs:328). 0 until the first `install_catalog` (every name fail-closed 404, the privacy
    /// default); > 0 once a verified catalog is installed (the loopback can serve those assets).
    pub catalog_assets: i64,
    /// ★ #22 slice 2 — the RETAINED catalog's TCAT v2 freshness epoch (unix secs the author stamped
    /// at signing, [`Catalog::authored_at_secs`]). `0` = freshness UNKNOWN (no catalog installed yet,
    /// a v1-era catalog, or an author that declined) — the dashboard MUST render 0 as an em-dash /
    /// "unknown", never as 1970. Nonzero ⇒ the "catalog age" tile is `now - this`.
    pub catalog_authored_at_secs: i64,
    /// The live opt-out CROWN toggle — `LeakOnMiss` (safe default) or `BlockMissing` (strict, the crown
    /// armed: serve-local-OR-nothing ⇒ the CDN sees 0). The dashboard's "cloak armed" indicator.
    pub cache_mode: CentauriCacheMode,
    /// THE CROWN witness — serves answered from the local cache with ZERO CDN egress
    /// ([`CentauriServeOutcome::ServedLocal`]). The "served locally N, the CDN never saw it" count.
    pub served_locally: i64,
    /// Cumulative bytes served from the device on a 0-egress local hit ("X bytes never left your device" —
    /// distinct from `bytes`, the cache SIZE; this is the running served-locally volume).
    pub served_bytes: i64,
    /// Genuine misses that leaked EXACTLY ONE self-fill request ([`CentauriServeOutcome::LeakedThenServed`])
    /// — the ≤ 1 proof. Per asset this is ≤ 1 (cached forever after); strict mode ⇒ stays 0.
    pub cdn_fetches: i64,
    /// Strict-mode misses served-nothing ([`CentauriServeOutcome::BlockedMissing`]) — the CDN saw 0 (the
    /// crown's hardest witness).
    pub blocked_missing: i64,
    /// Successful serves whose resolution was an EXACT version match (the SRI-safe split — F3 honesty).
    pub exact_serves: i64,
    /// Successful serves that required a version FALLBACK (SafeNewer/RiskyOlder) — the F3 split's other half
    /// (an SRI-pinned consumer would decline these; the dashboard renders the exact-vs-fallback ratio).
    pub fallback_serves: i64,
    // ---- CP-Centauri-Discovery (the LIVING watch-list) ----
    /// DISTINCT content-delivery hosts DISCOVERED on the datapath PAST the static LocalCDN corpus
    /// ([`crate::centauri_discovery::count`]). The dashboard's "N watched · M discovered" second half —
    /// the catalog GROWING with the user. 0 on a cold boot with no navigation yet.
    pub discovered: i64,
    /// Cumulative cdn-shaped OBSERVATIONS ever (survives the discovered-host cap; the "the encyclopedia
    /// has watched N times" volume, distinct from the distinct-host `discovered` count).
    pub discovered_observed: i64,
    /// The LIVING roster itself — the top discovered hostnames (hits-desc, host-asc), pipe-delimited and
    /// bounded ([`crate::centauri_discovery::discovered_line`]). The dashboard renders these as the
    /// "grown from your traffic" list beneath the static cloak watch-list, so the encyclopedia's growth is
    /// VISIBLE, not just a count. Empty on a cold boot; rides the flat-JSON bridge because the discovered
    /// store is resolver-side live state (absent from torta_ui's own linked config-authority core).
    pub discovered_hosts: String,
}

/// A typed CDN-URL resolution — the full-power cross of the mirror-internal [`Resolution`] (localcdn.rs:121).
/// Replaces the flat `resolve_cdn -> Option<String>` (which dropped everything but the canonical name): the
/// typed [`Centauri::resolve_cdn_typed`] returns this so Kotlin gets the library, both versions, the file, the
/// canonical catalog name, AND the F3-load-bearing [`CentauriSubstitution`] verdict (NEVER a flat string).
#[cfg(feature = "mirror")]
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CentauriResolution {
    /// The local library id (the bundle name), e.g. `"jquery"`.
    pub library: String,
    /// The version the CDN URL requested, e.g. `"3.6.2"`.
    pub requested_version: String,
    /// The version actually served after the version-fallback, e.g. `"3.7.1"`.
    pub served_version: String,
    /// The asset file tail, e.g. `"jquery.min.js"`.
    pub file: String,
    /// The host-independent canonical catalog name (`<library>/<served_version>/<file>`) — the catalog key.
    pub canonical_name: String,
    /// The substitution verdict (Exact ⇒ SRI-safe; a fallback would fail an integrity pin).
    pub substitution: CentauriSubstitution,
}

#[cfg(feature = "mirror")]
impl From<Resolution> for CentauriResolution {
    fn from(r: Resolution) -> Self {
        // Compute the canonical name while `r` is still whole, then move the owned fields out.
        let canonical_name = r.canonical_name();
        CentauriResolution {
            library: r.library,
            requested_version: r.requested_version,
            served_version: r.served_version,
            file: r.file,
            canonical_name,
            substitution: r.substitution.into(),
        }
    }
}

/// One serve event — the typed record of a single loopback serve (the structured twin of one
/// `query-centauri.log` line, slice 6, AND the dashboard's "what the mirror just served" feed item). The
/// `now_ms` clock is INJECTED by the caller (the #133 / warden pure-formatter discipline — the Object never
/// reads a wall clock), so the record is deterministic + host-testable. [`Centauri::record_serve`] consumes
/// it (bumping the CROWN counters) and rings it; [`Centauri::recent_serves`] reads the ring.
#[cfg(feature = "mirror")]
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CentauriServeRecord {
    /// The injected event clock (epoch millis) — supplied by the caller, never read from a wall clock here.
    pub now_ms: u64,
    /// The cloaked CDN host the request carried (`Host:` header), or empty if a path-only serve.
    pub host: String,
    /// The canonical catalog asset name served (`<library>/<served_version>/<file>`), or empty if unresolved.
    pub canonical_name: String,
    /// The local library id (empty if the URL did not resolve to a mapped library).
    pub library: String,
    /// The version the request asked for.
    pub requested_version: String,
    /// The version actually served (after fallback).
    pub served_version: String,
    /// The substitution verdict for this serve (drives the exact-vs-fallback dashboard split).
    pub substitution: CentauriSubstitution,
    /// The CROWN outcome (ServedLocal / LeakedThenServed / BlockedMissing / NotInCatalog / FetchFailed).
    pub outcome: CentauriServeOutcome,
    /// Bytes served (0 on BlockedMissing / NotInCatalog / FetchFailed).
    pub bytes: i64,
}

/// The TIER-B warm-up batch result, typed for the FFI (D04 — the UniFFI-bridged cross of the mirror-internal
/// [`crate::mirror::WarmUpReport`]): how many curated catalog assets a [`Centauri::warm_up`] batch attempted,
/// already held, self-filled (the ≤ 1 CDN requests), skipped at the sig gate, or failed fail-closed. The
/// crown math the dashboard renders: `filled` IS the batch's total CDN request count; every filled asset is
/// then 0 CDN forever.
#[cfg(feature = "mirror")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct CentauriWarmUpReport {
    /// Targets attempted (catalog assets with a mapped CDN upstream, capped by the caller's `max_targets`).
    pub targets: i64,
    /// Already in the cache before the batch — served locally, 0 CDN.
    pub already_cached: i64,
    /// Self-filled with the one allowed CDN request, then cached + serveable (== the batch's CDN requests).
    pub filled: i64,
    /// Skipped at the sig gate (the signed catalog does not authorize the name) — 0 CDN.
    pub not_in_catalog: i64,
    /// The one fetch failed (transport / oversize / hash mismatch) — fail-closed, nothing cached.
    pub failed: i64,
}

/// The Centauri per-serve PUSH channel (D26 — the proven Beast `with_foreign` one-reader discipline applied
/// to the mirror): the foreign (Kotlin) side provides the implementation, [`Centauri::attach_serve_sink`]
/// binds ONE reader, and the live accept loop pushes each [`CentauriServeRecord`] AS IT HAPPENS — deny/serve
/// bursts between dashboard polls are no longer invisible. Push and pull never drift: the pushed record is
/// built from the SAME trace that feeds the CROWN counters + the recent-serve ring + `query-centauri.log`.
#[cfg(feature = "mirror")]
#[uniffi::export(with_foreign)]
pub trait CentauriServeSink: Send + Sync {
    /// One serve event, pushed by the live accept loop (never called under a lock; never blocks a serve).
    fn on_serve(&self, record: CentauriServeRecord);
}

/// The content-addressed cache's stats as ONE typed Record — the full-power cross of the four loose
/// `CacheStore` reads (`len`/`total_bytes`/`is_full`/`capacity`). [`Centauri::cache_stat`] returns it so the
/// cache surface is typed in one read (the snapshot still embeds the same four numbers as its summary).
#[cfg(feature = "mirror")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct CentauriCacheStat {
    /// Cached assets (`CacheStore::len`).
    pub libraries: i64,
    /// Total bytes across all cached assets (`CacheStore::total_bytes`).
    pub bytes: i64,
    /// Is the bounded store full? (`CacheStore::is_full`).
    pub full: bool,
    /// The bounded store's capacity ceiling (`CacheStore::capacity`).
    pub capacity: i64,
}

/// The typed outcome of [`Centauri::arm_device_catalog`] — the sovereign on-device arming report (the SURPASS
/// of nautilus-rs's desktop-bin `CatalogSelfTest`/`DeviceLiveCatalog`, folded into ONE engine-native record
/// the running Object hands straight to the Kotlin dashboard). Every field is a REAL measured count of what
/// this install's OWN device key authored + installed — never a fabricated tally.
#[cfg(feature = "mirror")]
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CentauriArmReport {
    /// This install's public device identity (lower-hex `key_id`, 16 chars) — the authority that signed the
    /// catalog. Empty only on an unrecoverable device-key failure (the zeroed fail-safe report).
    pub key_id_hex: String,
    /// `true` on First Boot (a fresh device key was minted from OS entropy this call); `false` when the
    /// persisted 32-byte seed reloaded deterministically.
    pub minted: bool,
    /// App-OWNED seed assets hashed + admitted into the LIVE content-addressed cache — the honest
    /// `libraries=N` the chip reads (real 0-egress serves, never a placeholder-hash blackhole).
    pub cached_assets: i64,
    /// CDN cloak hosts authorized (content_hash=0, cloaked) — the GROWING redirect roster from the live
    /// `cdn_hosts()` set, tracked as it grows (never a frozen count).
    pub cloak_hosts: i64,
    /// Total catalog entries authored (`cached_assets` owned rows + `cloak_hosts` cloak rows).
    pub catalog_entries: i64,
    /// `true` IFF the device-signed catalog VERIFIED (`parse_verified` against THIS device's own pubkey) and
    /// installed into the running Object — the ownership loop closed on-device.
    pub installed: bool,
    /// `true` IFF the device-signed pair (`device-catalog.tcat` + `.sig`) was PERSISTED into the Object's
    /// durable cache dir (atomic tmp+rename, the `cache.rs` idiom) — the RAM⊗NAND half the arming pass
    /// previously dropped: the pillar now authors its OWN durable artifact, so the next boot rehydrates
    /// via [`Centauri::rehydrate_device_catalog`] WITHOUT re-hashing the content dir. `false` when the
    /// install failed (a catalog that did not self-verify must never become the durable truth) or the
    /// disk write failed (fail-open: the RAM install stands, the next boot re-authors).
    pub persisted: bool,
}

// ===========================================================================================
// Internal state holders (NOT UniFFI-derived — the Object owns them behind Mutex)
// ===========================================================================================

/// The shared LIVE serve counters — the CROWN witness made persistable-across-the-serve-boundary. Held in
/// an `Arc` of atomics so the live accept loop can CLONE the handle + bump it server-side once it adopts the
/// [`crate::mirror::serve_addressed`] privacy flow (the #85 downstream seam — the slice-2/3 "host-proven,
/// adoption-ready" posture). Today driven by [`Centauri::record_serve`] (host-proven + unit-tested end to
/// end). Relaxed ordering throughout: these are monotone dashboard counters, no inter-counter invariant.
#[cfg(feature = "mirror")]
#[derive(Debug, Default)]
struct CentauriLiveStats {
    /// 0-egress local cache hits ([`CentauriServeOutcome::ServedLocal`]).
    served_locally: AtomicI64,
    /// Cumulative bytes served on those 0-egress hits.
    served_bytes: AtomicI64,
    /// The ≤ 1 self-fills ([`CentauriServeOutcome::LeakedThenServed`]).
    cdn_fetches: AtomicI64,
    /// Strict-mode served-nothing blocks ([`CentauriServeOutcome::BlockedMissing`]).
    blocked_missing: AtomicI64,
    /// Successful serves at an EXACT version (the SRI-safe split).
    exact_serves: AtomicI64,
    /// Successful serves that needed a version FALLBACK (the F3 split's other half).
    fallback_serves: AtomicI64,
    /// LocalCDN URL→canonical resolutions performed (one per CDN-routed request). Lock-free atomics (moved
    /// here from the `CentauriStats` Mutex) so the LIVE accept-loop observer can tally the serve-path resolve
    /// WITHOUT a lock — the `resolve_cdn` / `resolve_cdn_typed` query-time entrypoints bump the SAME atomics,
    /// so the counter is honest across BOTH surfaces (a direct resolve check AND a real CDN serve).
    resolve_queries: AtomicI64,
    /// Of those resolutions, the ones that MATCHED a known LocalCDN library (`resolve_full` returned `Some`).
    resolve_hits: AtomicI64,
}

/// Running Centauri counters (the LIVED state the flat fns never accumulated — the flat
/// `mirror_status` rebuilds the string throwaway per call; the Object accumulates across the boot).
/// Held behind a `Mutex` inside the Object.
#[cfg(feature = "mirror")]
#[derive(Debug, Clone, Default)]
struct CentauriStats {
    catalog_installs_attempted: i64,
    catalog_installs_verified: i64,
    // resolve_queries / resolve_hits moved to the lock-free `CentauriLiveStats` (the Arc `live`) so the
    // accept-loop observer can tally serve-path resolves without a lock; the query-time resolve entrypoints
    // bump the SAME atomics.
    rehydrates_attempted: i64,
    rehydrates_verified: i64,
}

// ===========================================================================================
// THE CENTAURI OBJECT
// ===========================================================================================

/// THE CENTAURI — the stateful local-CDN mirror pillar. Kotlin constructs it ONCE at boot (passing
/// the app-private `cache_dir`), holds the `Arc` handle, then:
///   - installs + rehydrates the signed catalog via [`Centauri::install_catalog`] /
///     [`Centauri::rehydrate_from_signed`],
///   - reads the CDN host set + cloaking rules via [`Centauri::cdn_hosts`] /
///     [`Centauri::cloaking_rules`],
///   - asks "is this CDN URL covered" via [`Centauri::resolve_cdn`],
///   - starts the loopback mirror via [`Centauri::start`] (idempotent — mirrors the OnceLock
///     singleton semantics of the flat `centauri_mirror_start`),
///   - pulls a [`CentauriSnapshot`] for the dashboard via [`Centauri::snapshot`].
///
/// Interior state is `Mutex<T>` (std) + an `AtomicU16` for the serve port (lock-free read).
/// `#![forbid(unsafe_code)]` honored. The lock discipline is: lock, act, drop the
/// guard before any cross-method call (no holding a lock across an FFI/sink boundary). Each public
/// method panic-firewalls its body — a bug returns a safe default, never aborts the app.
#[cfg(feature = "mirror")]
#[derive(uniffi::Object)]
pub struct Centauri {
    /// The content-addressed cache rooted at the app-private `cache_dir` (the LIVED store the flat
    /// `MIRROR_RUNTIME` singleton held — here it is a per-Object field behind the Mutex). Rehydrated
    /// from disk on construction via the SAME #92 cache contract (`CacheStore::with_dir` +
    /// `load_from_disk`, the `mirror_load_from_disk` path the flat `centauri_mirror_start` uses).
    /// `Arc` (D04/D29): the SAME live store is shared with the loopback accept loop (`run_shared`) and
    /// the `warm_up` batch — a verified fill is servable immediately, and the dashboard snapshot reads
    /// the EXACT store the loopback serves (the read-stats-vs-serve-bytes identity, literal).
    cache: Arc<Mutex<CacheStore>>,
    /// The RETAINED signature-verified catalog (slice 2 — the DNS-plane→loopback serve). [`Centauri::
    /// install_catalog`] now RETAINS the verified `Catalog` here (was dropped on the floor), and
    /// [`Centauri::start`] threads a CLONE of it into the loopback [`MirrorServer`] so the serve path is
    /// authorized against the REAL installed catalog — not the empty default. `Catalog::default()` (empty
    /// ⇒ every name fail-closed 404, ZERO egress) until the first `install_catalog`; held behind a `Mutex`
    /// (a control-plane install is rare; the serve snapshot clones under the lock then drops the guard).
    catalog: Mutex<Catalog>,
    /// The bound loopback port (`127.0.0.1:<port>`), 0 before start / on bind failure. Atomic for
    /// lock-free dashboard reads (the snapshot reads it without taking the cache lock).
    port: AtomicU16,
    /// Running Centauri counters (catalog installs, resolve queries/hits, rehydrates).
    stats: Mutex<CentauriStats>,
    /// The app-private cache_dir the store is rooted at (retained for the start/rehydrate seam).
    cache_dir: std::path::PathBuf,
    /// The serve lifecycle state code (0=Stopped / 1=Starting / 2=Serving / 3=Failed), set by
    /// [`Centauri::start`]. Atomic for a lock-free snapshot read; WIRES the `Starting`/`Failed` enum arms a
    /// port-only inference could never reach.
    serve_state: AtomicU8,
    /// The CROWN opt-out toggle code (0=LeakOnMiss safe default / 1=BlockMissing strict), the UniFFI surface
    /// of the internal [`CacheMode`]. Lock-free; [`Centauri::set_cache_mode`] / [`Centauri::cache_mode`] drive
    /// it. The live serve path lowers it back to a [`CacheMode`] (the `From` cross) on the #85 adoption.
    cache_mode: AtomicU8,
    /// The shared LIVE serve counters (the CROWN witness). `Arc` so the live accept loop can clone + bump
    /// server-side on the #85 adoption; today driven by [`Centauri::record_serve`] (host-proven + tested).
    live: Arc<CentauriLiveStats>,
    /// A bounded ring (cap [`RECENT_SERVES_CAP`]) of the most recent serve events, newest at the back — the
    /// dashboard's "what the mirror just served" feed. The LIVE accept-loop observer pushes (D29 — the ring
    /// self-feeds on-device) alongside [`Centauri::record_serve`]; [`Centauri::recent_serves`] reads
    /// (newest-first). `Arc` so the accept thread shares it. NOT the durable record (`query-centauri.log`).
    recent: Arc<Mutex<VecDeque<CentauriServeRecord>>>,
    /// The ONE bound foreign per-serve reader (D26 — the Beast one-reader discipline): the live accept-loop
    /// observer pushes each serve record to it. `Arc<Mutex<…>>` so the accept thread shares the binding;
    /// [`Centauri::attach_serve_sink`] / [`Centauri::detach_serve_sink`] drive it. `None` ⇒ no push (poll-only).
    serve_sink: Arc<Mutex<Option<Arc<dyn CentauriServeSink>>>>,
}

#[cfg(feature = "mirror")]
#[uniffi::export]
impl Centauri {
    /// Construct the Centauri mirror rooted at the app-private `cache_dir`. UniFFI Object ctors MUST
    /// return `Arc<Self>`. Builds the content-addressed [`CacheStore`] via the #92 cache contract's
    /// `with_dir(PathBuf)` seam + rehydrates the verified on-disk index via `load_from_disk` (the
    /// SAME `mirror_store_with_dir` + `mirror_load_from_disk` path the flat `centauri_mirror_start`
    /// uses — math UNCHANGED, fail-closed: a tampered on-disk file is REJECTED by content-address).
    /// Never panics: a missing/unreadable dir rehydrates zero (cold-start baseline). The serve port
    /// starts at 0 (Stopped); call [`Centauri::start`] to bind the loopback listener.
    #[uniffi::constructor]
    pub fn new(cache_dir: String) -> Arc<Self> {
        let dir = std::path::PathBuf::from(&cache_dir);
        // Build + rehydrate — the SAME #92 seam the flat centauri_mirror_start drives. A panic here
        // (cold dir / IO glitch) degrades to a fresh empty store (constructible + honest, never a
        // panic across the FFI boundary).
        let store = catch_unwind(AssertUnwindSafe(|| {
            let path = dir.clone();
            let mut store = CacheStore::with_dir(path.clone());
            let _ = store.load_from_disk(&path);
            store
        }))
        .unwrap_or_else(|_| CacheStore::new());
        // ★ #65 — bind + rehydrate the ABSORB bindings from the same app-private dir. The bytes already
        // came back with the cache above; this restores WHICH content address each absorbed URL resolved
        // to, so a CDN absorbed yesterday still serves from this device today instead of being re-fetched.
        super::absorb::arm(dir.clone());
        Arc::new(Self {
            cache: Arc::new(Mutex::new(store)),
            // Empty until the first install_catalog ⇒ every name fail-closed 404 (the privacy-default).
            catalog: Mutex::new(Catalog::default()),
            port: AtomicU16::new(0),
            stats: Mutex::new(CentauriStats::default()),
            cache_dir: dir,
            // Stopped until start() binds; the safe leak-on-miss default until the user arms strict; a fresh
            // live-counter sink + an empty recent ring (the dashboard reads zeros honestly on a cold Object).
            serve_state: AtomicU8::new(CentauriServeState::Stopped as u8),
            cache_mode: AtomicU8::new(CentauriCacheMode::LeakOnMiss as u8),
            live: Arc::new(CentauriLiveStats::default()),
            recent: Arc::new(Mutex::new(VecDeque::with_capacity(RECENT_SERVES_CAP))),
            serve_sink: Arc::new(Mutex::new(None)),
        })
    }

    /// Verify-sig-FIRST install of a Haskell-signed Centauri catalog. Delegates to
    /// [`Catalog::parse_verified`] (catalog.rs:200, the SAME engine the flat
    /// [`crate::mirror_install_catalog`] wraps — math unchanged). Returns `Ok(())` ONLY when the
    /// minisign signature over the catalog bytes verifies against `pubkey` AND the body parses;
    /// `Err(CentauriError)` on `BadSignature`/`Malformed`/panic. Tallies the attempt + the verified
    /// outcome into the lived counters (the tally records the ATTEMPT regardless of the outcome — a
    /// failed install still increments `catalog_installs_attempted`, mirroring the lossy `bool`
    /// surface's accounting). Panic-firewalled → `Err(Panic)`.
    pub fn install_catalog(
        &self,
        bytes: Vec<u8>,
        sig: Vec<u8>,
        pubkey: Vec<u8>,
    ) -> Result<(), CentauriError> {
        // Drive the verify-sig-FIRST gate under the panic firewall. The closure returns the FULL
        // `Result<Catalog, CatalogError>` so we can lift the typed failure mode (NOT just a bool fold).
        // A panic ⇒ the `Err` arm of catch_unwind ⇒ we lift to `CentauriError::Panic` (distinct from
        // a real CatalogError::BadSignature, which the engine returned without panicking).
        let outcome = catch_unwind(AssertUnwindSafe(move || {
            Catalog::parse_verified(&bytes, &sig, &pubkey)
        }));
        // Lift to the bridged error. The tally records the ATTEMPT regardless; verified only on Ok.
        let lifted = match outcome {
            Ok(Ok(catalog)) => {
                // Slice 2 — RETAIN the verified catalog (was `Ok(Ok(_catalog)) => Ok(())`, dropped on the
                // floor). `start()` threads a clone into the loopback `MirrorServer` so the serve path is
                // authorized against the REAL catalog. A poisoned lock degrades to "not retained" (the
                // serve stays fail-closed 404), never a panic across the boundary.
                if let Ok(mut retained) = self.catalog.lock() {
                    *retained = catalog;
                }
                Ok(())
            }
            Ok(Err(crate::mirror::CatalogError::BadSignature)) => {
                Err(CentauriError::InvalidSignature {
                    reason: "catalog minisign signature did not verify against the pinned key"
                        .to_string(),
                })
            }
            Ok(Err(crate::mirror::CatalogError::Malformed)) => {
                Err(CentauriError::MalformedCatalog {
                    reason: "verified catalog body could not be parsed (bad magic/version/record)"
                        .to_string(),
                })
            }
            // The reason here is a free-form String, so unlike the two enum-typed boundaries this
            // one can carry the distinction WITHOUT widening anything — and it is the boundary an
            // operator actually reads. A pre-migration catalog is intact, correctly signed, and
            // simply old; telling them it is unparseable would send them hunting a corruption that
            // does not exist.
            Ok(Err(crate::mirror::CatalogError::LegacyHashAlgo)) => {
                Err(CentauriError::MalformedCatalog {
                    reason: "catalog uses the RETIRED SHA-256 content-address id (hash_algo_id=1); \
                             the spine moved to BLAKE2b-256 — re-fetch a current catalog"
                        .to_string(),
                })
            }
            Err(_panic) => Err(CentauriError::Panic {
                reason: "install_catalog: panic firewalled (bug fails typed)".to_string(),
            }),
        };
        // Tally the attempt + the verified outcome (the SAME accounting the lossy bool kept).
        if let Ok(mut stats) = self.stats.lock() {
            stats.catalog_installs_attempted += 1;
            if lifted.is_ok() {
                stats.catalog_installs_verified += 1;
            }
        }
        lifted
    }

    /// Sovereign on-device catalog arming — the living CDN-encyclopedia's boot faculty (Centauri SEES online
    /// CDN assets and TRANSPLANTS them offline so the user stops relying on online CDNs). This is the SURPASS
    /// of nautilus-rs's desktop-bin Rungs 2+3, made ENGINE-NATIVE, Object-model, and RAM⊗NAND-durable:
    /// nautilus authors its device catalog in a separate `nautilus-bin` harness over compile-time
    /// `include_bytes!` seed bytes and installs via the flat engine path; THIS is a first-class LIVE
    /// [`Centauri`] capability that seeds the running Object's OWN shared cache + installs into the running
    /// Object, persisting authority + transplanted content through the durable tier. The catalog it authors
    /// carries the encyclopedia's TWO states per asset — SEEN (a cloaked host, `content_hash=0`, redirect
    /// armed but not yet transplanted) and TRANSPLANTED (a real content address, the bytes served offline
    /// forever, the CDN never contacted):
    ///
    ///   1. **Load-or-MINT** this install's own Ed25519 content-authority ([`crate::mirror::DeviceKey`]) from
    ///      `<key_seed_dir>/device.key` — minted ONCE from OS entropy at First Boot, reloaded deterministically
    ///      every launch after. The 32-byte secret seed lives on-device only; possession IS this install's
    ///      Centauri authority (same app, different key per install — the ownership answer to reverse-CDN
    ///      interrogation). A truncated/oversized seed re-mints fail-forward (never serve a broken authority).
    ///   2. **Seed owned content**: read every app-OWNED asset the `content.tsv` manifest under `content_dir`
    ///      names (`<catalog-name>\t<relative-file>` per line; `#`/blank lines + `..`/separator-bearing files
    ///      skipped), hash each with the cache's BLAKE2b-256 content address, and admit it into the LIVE shared
    ///      [`CacheStore`] (verify-on-write + atomic disk write-through, so a reboot's ctor `load_from_disk`
    ///      rehydrates it). These are genuinely redistributable, app-owned bytes (Tortä's own offline pages +
    ///      licence) — REAL 0-egress serves, the honest `libraries=N`, NEVER a placeholder-hash blackhole.
    ///   3. **Author + install** a DEVICE-SIGNED catalog (verify-sig-FIRST against THIS device's OWN pubkey —
    ///      the same gate the mirror applies): one uncloaked entry per owned asset (host `torta.local`, its
    ///      REAL content address) + one cloak entry per LIVE [`Centauri::cdn_hosts`] roster host
    ///      (content_hash=0, cloaked — the GROWING redirect set, tracked live, never a frozen 12).
    ///
    /// MUST run BEFORE [`Centauri::start`] (start clones the catalog into the serve loop; a later install is
    /// not seen until restart). Idempotent + reversible: re-arming re-mints nothing (deterministic key),
    /// re-admits identical bytes as no-ops, and re-installs the SAME device-signed catalog. Panic-firewalled
    /// → a zeroed report (`installed=false`, `key_id_hex=""`).
    pub fn arm_device_catalog(&self, content_dir: String, key_seed_dir: String) -> CentauriArmReport {
        fn zeroed() -> CentauriArmReport {
            CentauriArmReport {
                key_id_hex: String::new(),
                minted: false,
                cached_assets: 0,
                cloak_hosts: 0,
                catalog_entries: 0,
                installed: false,
                persisted: false,
            }
        }
        catch_unwind(AssertUnwindSafe(|| {
            // 1. This install's sovereign signing authority (mint once, reload deterministically after).
            let (key, minted) = match load_or_mint_device_key(&key_seed_dir) {
                Some(pair) => pair,
                None => return zeroed(), // entropy/IO failure ⇒ device authority unavailable, fail-safe.
            };

            // 2. Seed the LIVE shared cache from the app-owned content manifest → real content-addressed
            //    entries. Each admitted asset becomes ONE uncloaked `torta.local` catalog row.
            let content_root = std::path::PathBuf::from(&content_dir);
            let mut entries: Vec<CatalogEntry> = Vec::new();
            let mut cached_assets: i64 = 0;
            for row in read_content_manifest(&content_root) {
                // Path-traversal guard: the manifest names a flat file in `content_dir`, never a subpath.
                if row.file.contains("..") || row.file.contains('/') || row.file.contains('\\') {
                    continue;
                }
                let bytes = match std::fs::read(content_root.join(&row.file)) {
                    Ok(b) => b,
                    Err(_) => continue, // a missing asset silently does not load (honest lower crown).
                };
                // Hash the REAL shipped bytes → the catalog's content address IS correct by construction, so a
                // cloaked CDN library serves 0-egress under its canonical name with NO pre-measured hash and
                // NO network fetch (the SURPASS of a fetch-once door: the pin ships already-filled).
                let hash = content_hash(&bytes);
                let admitted = match self.cache.lock() {
                    Ok(mut store) => store.insert_verified(hash, bytes).is_some(),
                    Err(_) => false,
                };
                if admitted {
                    cached_assets += 1;
                    entries.push(CatalogEntry {
                        name: row.name,
                        host: row.host,
                        content_hash: hash,
                        cloaked: row.cloaked,
                    });
                }
            }

            // 3a. The GROWING cloak roster — one cloaked entry per LIVE CDN host (content_hash=0: the redirect
            //     is armed, but nothing is cached until a real request self-fills it; strict mode ⇒ 0 egress).
            let hosts = self.cdn_hosts();
            let cloak_hosts = hosts.len() as i64;
            for host in hosts {
                entries.push(CatalogEntry {
                    name: host.clone(),
                    host,
                    content_hash: [0u8; 32],
                    cloaked: true,
                });
            }

            // 3b. Author → device-sign → install (verify-sig-FIRST against this device's OWN pubkey).
            // ★ #22 slice 2 — stamp the signing moment as the TCAT v2 freshness epoch (a clock
            // failure stamps 0 = "freshness unknown", the honest decline — never a fake epoch).
            let catalog_entries = entries.len() as i64;
            let authored_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let body = encode_catalog(&entries, authored_at);
            let sig = key.sign(&body).to_vec();
            let pubkey = key.pubkey_blob().to_vec();
            let installed = self
                .install_catalog(body.clone(), sig.clone(), pubkey)
                .is_ok();

            // 3c. PERSIST the device-signed pair into the durable cache dir (the RAM⊗NAND half this
            //     pass previously dropped — the pillar authors its OWN `.tcat`/`.sig`, never waiting
            //     for a host-side artifact that does not exist on a phone). Only a catalog that
            //     self-verified may become the durable truth; a failed disk write is fail-open (the
            //     RAM install stands, the next boot re-authors from content).
            let persisted = installed && persist_device_pair(&self.cache_dir, &body, &sig);

            CentauriArmReport {
                key_id_hex: hex_lower_key_id(&key.key_id()),
                minted,
                cached_assets,
                cloak_hosts,
                catalog_entries,
                installed,
                persisted,
            }
        }))
        .unwrap_or_else(|_| zeroed())
    }

    /// The LocalCDN→Centauri cloak host set (#134): every CDN host the mirror covers, sorted +
    /// de-duplicated. Delegates to [`cdn_hosts`] (localcdn.rs:188, the SAME pure fn the flat
    /// [`crate::centauri_cdn_hosts`] wraps). The host list is not secret (only served CONTENT is
    /// minisign-signed + content-addressed), so it is the static build-time set. Panic-firewalled
    /// → an empty list.
    pub fn cdn_hosts(&self) -> Vec<String> {
        catch_unwind(AssertUnwindSafe(|| {
            // The static LocalCDN corpus — the hosts this build ships knowledge of.
            let mut hosts: Vec<String> = cdn_hosts().iter().map(|h| h.to_string()).collect();

            // ★ #65 PROMOTION — plus the CDNs this device MET while the user browsed.
            //
            // This is the crossing that makes Centauri actually absorb. Discovery observed, classified
            // and persisted CDN-shaped hosts (`centauri_discovery::observe`), but nothing ever carried a
            // candidate into the served catalog — so a CDN met on a real site stayed a NAME in a ledger
            // and its assets were fetched from the real CDN forever. Joining the earned candidates here
            // gives each one a cloak row, exactly like a corpus host.
            //
            // The row carries `content_hash = 0` (see the roster loop above), so promotion pre-fetches
            // NOTHING: the redirect is armed, the FIRST request self-fills through the ≤1 fetch-once
            // crown, and every request after it is served from this device with ZERO egress.
            //
            // Dedup against the corpus is by exact normalized name — `promotable()` returns discovery's
            // own keys, which are already lower-cased + root-dot-stripped (`normalize`), and the corpus
            // is authored lower-case, so a host already shipped can never be promoted into a second row.
            //
            // Order is deterministic (corpus first, then hits-desc/host-asc) so the authored catalog is
            // reproducible across arms — a catalog that reshuffled every boot would re-sign for nothing.
            let promoted = crate::centauri_discovery::promotable();
            if !promoted.is_empty() {
                let known: std::collections::HashSet<&str> = hosts.iter().map(|h| h.as_str()).collect();
                let fresh: Vec<String> = promoted
                    .into_iter()
                    .filter(|h| !known.contains(h.as_str()))
                    .collect();
                // Publish the SAME set into the DNS-plane cloak. Without this the promoted host would
                // get a catalog row while its name still resolved to the real CDN — the request would
                // never reach Centauri and the absorption would be silently inert.
                super::localcdn::publish_promoted_cloak(fresh.clone());
                hosts.extend(fresh);
            } else {
                // Nothing earned promotion — clear any set a previous arm published, so a host that
                // fell out of the law stops being cloaked instead of lingering forever.
                super::localcdn::publish_promoted_cloak(Vec::new());
            }
            hosts
        }))
        .unwrap_or_default()
    }

    /// Resolve a CDN URL (a cloaked CDN host + its `/lib/version/file` path) to the canonical
    /// Centauri catalog asset name (`<library>/<served_version>/<file>`, host-independent, version-
    /// fallback applied), or `null` if the URL is not a mapped LocalCDN library. Delegates to
    /// [`resolve_full`] (localcdn.rs:173, the SAME pure fn the flat [`crate::centauri_resolve_cdn`]
    /// wraps — math unchanged). Tallies the query + the hit into the lived counters. Panic-firewalled
    /// → `null`.
    pub fn resolve_cdn(&self, host: String, path: String) -> Option<String> {
        let resolved = catch_unwind(AssertUnwindSafe(move || {
            resolve_full(&host, &path).map(|r| r.canonical_name())
        }))
        .unwrap_or(None);
        self.live.resolve_queries.fetch_add(1, Ordering::Relaxed);
        if resolved.is_some() {
            self.live.resolve_hits.fetch_add(1, Ordering::Relaxed);
        }
        resolved
    }

    /// The dnscrypt `cloaking-rules.txt` block (#134) for the opt-out local-CDN binding: one
    /// `<host> 127.0.0.1` line per cloaked CDN host, fenced by BEGIN/END markers. Delegates to
    /// [`cloaking_rules`] (localcdn.rs:230, the SAME pure fn the flat [`crate::centauri_cloaking_rules`]
    /// wraps — math unchanged). This GENERATES the rules text only — it never writes them (the live
    /// write + dnscrypt reload is the arming step, kept separate — reversible-by-construction).
    /// Panic-firewalled → an empty string.
    pub fn cloaking_rules(&self) -> String {
        catch_unwind(AssertUnwindSafe(|| self.servable_cloaking_rules()))
            .unwrap_or_default()
    }

    /// ★ CLOAK⊆SERVABLE — the cloak block for exactly the hosts THIS Centauri can serve.
    ///
    /// The old body delegated to the pure [`cloaking_rules`], which emits one line per `cdn_hosts()`
    /// corpus entry regardless of what the store holds. Measured on a real AVD run: **26 hosts
    /// cloaked, 1 servable** — 25 sinkholes into silence, which is the cascading
    /// `ERR_CONNECTION_CLOSED` the prime goal is chasing. See `cloaking_rules_for` for the full
    /// account and `Proofs/CloakServable.lean` for the proof that filtering by the store makes
    /// soundness unconditional (`derived_is_always_sound`) while never removing a working cloak
    /// (`fix_is_a_noop_on_a_complete_store`).
    ///
    /// The servable set is read from the content manifest — the SAME `content.tsv` the arming step
    /// hashes and admits — taking only rows marked `cloaked=true`. An owned `torta.local` page is
    /// never cloaked (it needs no DNS interception), so it is correctly absent.
    ///
    /// FAIL-CLOSED by construction: an absent, unreadable or empty manifest yields NO cloak lines, so
    /// the fenced block is written empty and nothing is sinkholed. That is the safe direction — a
    /// missing manifest must never mean "intercept the whole corpus".
    fn servable_cloaking_rules(&self) -> String {
        let hosts = self.servable_cloaked_hosts();
        cloaking_rules_for(&hosts)
    }

    /// The hosts this Centauri can actually serve a cloaked asset for, from `content.tsv`.
    ///
    /// Kept separate from the text generation so the SET is testable on its own — the defect was a set
    /// mismatch, and a test over rendered text would not have caught it.
    fn servable_cloaked_hosts(&self) -> Vec<String> {
        let content_dir = self.cache_dir.join("..").join("centauri_content");
        // The manifest lives beside the cache under the app's data dir; try the canonical sibling
        // first, then the cache dir itself (the flat/seed layouts both occur in the field).
        let mut rows = read_content_manifest(&content_dir);
        if rows.is_empty() {
            rows = read_content_manifest(&self.cache_dir);
        }
        let mut hosts: Vec<String> = rows
            .into_iter()
            .filter(|r| r.cloaked && !r.host.is_empty())
            .map(|r| r.host)
            .collect();
        // The PROMOTED lane is servable BY CONSTRUCTION: a host is promoted only after its asset was
        // absorbed into the store. Omitting it would silently disarm runtime discovery — caught by
        // `a_complete_store_reproduces_the_corpus_block_byte_for_byte` before it shipped.
        hosts.extend(crate::mirror::promoted_cloak_hosts());
        hosts.sort_unstable();
        hosts.dedup();
        // ★ CLOAK⊆SERVABLE (LIVE PATH) — publish the SAME set the rules file gets, so the resolver's
        // sinkhole gate and the written rules can never disagree. Fixing only the file would have left
        // the live path sinkholing the whole corpus while the file honestly listed one host.
        crate::mirror::publish_servable_cloak(&hosts);
        hosts
    }

    /// Start the in-app loopback Centauri Mirror, returning `Ok(port)` (the bound `127.0.0.1` port,
    /// >0) on success, or `Err(CentauriError::BindFailed)` / `Err(Panic)` on ANY failure. This is the
    /// Object twin of the flat [`crate::centauri_mirror_start`]. IDEMPOTENT: a second call returns
    /// `Ok(already_bound_port)` (the AtomicU16 port is set once; a non-zero value short-circuits).
    /// Drives the SAME #92 start contract: build a serve-snapshot off the Object's cache, bind the
    /// loopback listener on a DEDICATED tokio current-thread runtime on its OWN `centauri-mirror` OS
    /// thread (NEVER the resolver's private rt), read back the OS-assigned ephemeral port, spawn the
    /// accept loop.
    ///
    /// NOTE (no-break contract): the flat `centauri_mirror_start` keeps its OWN `MIRROR_RUNTIME`
    /// singleton driving the LIVE serve loop + `mirror_status` reads; this Object method is the
    /// ADDITIVE stateful twin. Both paths build an IDENTICAL serve-snapshot off the SAME
    /// `CacheStore::with_dir` + `load_from_disk` seam (math unchanged); the Kotlin call-site swaps
    /// to this method on the Socio's bindgen regen. Panic-firewalled → `Err(Panic)`.
    pub fn start(&self) -> Result<i32, CentauriError> {
        // Idempotent: a non-zero port means the loop is already bound — return it.
        let already = self.port.load(Ordering::Acquire);
        if already > 0 {
            return Ok(already as i32);
        }

        // Drive the bind under the panic firewall. The closure returns the raw i32 port-or-sentinel
        // (the SAME shape the lossy surface used internally); we lift it to Result after.
        let outcome: Result<i32, _> = catch_unwind(AssertUnwindSafe(|| {
            // Slice 5 — the serve enters Starting while the accept thread builds its runtime + binds (the
            // dashboard sees the transient bind-in-progress state, not just a Stopped→Serving jump).
            self.serve_state
                .store(CentauriServeState::Starting as u8, Ordering::Release);
            // D04/D29 — the loopback serves the LIVE SHARED store (the Object's own `Arc<Mutex<CacheStore>>`,
            // via `run_shared`), NOT a start-time snapshot: a `warm_up` self-fill or any later verified
            // insert is servable immediately (no restart), and the dashboard snapshot reads the EXACT store
            // the loopback serves. Slice 2 — the catalog is the RETAINED installed one (`install_catalog`
            // retains it; cloned under the lock, guard dropped before the thread spawn). Empty (no install
            // yet) ⇒ every name fail-closed 404, the leak-free default.
            let serve_catalog = match self.catalog.lock() {
                Ok(c) => c.clone(),
                Err(_) => Catalog::default(),
            };
            let serve_cache = Arc::clone(&self.cache);
            // D29 — the self-feeding review channel: the per-serve observer rings the recent-serve feed,
            // bumps the CROWN counters, appends `query-centauri.log`, and pushes the bound foreign sink.
            let observer = self.serve_observer();
            // #85 — the fetch-on-miss CROWN bundle. The live loopback becomes the consent-gated egress leg:
            // an AUTHORIZED `CacheMiss` (a watched CDN asset absent from the store) escalates to EXACTLY ONE
            // upstream `fetch_once` through the tested single-flight privacy flow, hash-verified on write,
            // then served + counted (`cdn_fetches++`). Three pieces: the ONE ring-pinned shared TLS
            // (`crate::tls_shared::client_tls_config` — the SAME canonical `ring` trust the resolver uses,
            // never aws-lc-rs), a FRESH single-flight coordinator (per serve-lifetime), and the live opt-out
            // CROWN toggle lowered to the datapath `CacheMode` (`BlockMissing` ⇒ strict, CDN sees 0). Passing
            // `Some(..)` is what ARMS stage 3; the legacy `run` path passes `None` and stays 503-on-miss.
            let fetch_ctx = mirror::server::FetchCtx {
                tls: Arc::new(crate::tls_shared::client_tls_config()),
                inflight: Arc::new(mirror::serve::InFlight::new()),
                mode: self.cache_mode().into(),
            };

            let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();
            let _accept_thread = std::thread::Builder::new()
                .name("centauri-mirror".to_string())
                .spawn(move || {
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(_) => {
                            let _ = port_tx.send(0);
                            return;
                        }
                    };
                    rt.block_on(async move {
                        // `run_shared` binds 127.0.0.1, reports the OS-assigned port, and spawns the accept
                        // loop ON THIS runtime (serving the shared store + the retained catalog, observed
                        // per-serve). Park forever after reporting the port so the current-thread runtime
                        // keeps driving the spawned loop for the process lifetime (the same detached-thread
                        // ownership the snapshot flow had — one runtime, one OS thread, parks when idle).
                        match mirror::server::run_shared(
                            mirror::ServerConfig::default(),
                            serve_catalog,
                            serve_cache,
                            Some(observer),
                            Some(fetch_ctx),
                        )
                        .await
                        {
                            Ok(port) => {
                                let _ = port_tx.send(port);
                                std::future::pending::<()>().await
                            }
                            Err(_) => {
                                let _ = port_tx.send(0);
                            }
                        }
                    });
                });

            let port = port_rx.recv().unwrap_or(0);
            // Record the bound port atomically (idempotency guard for the next call) + the live serve state:
            // a bound port ⇒ Serving, a 0 sentinel (bind failed / accept-thread early-out) ⇒ Failed.
            self.port.store(port, Ordering::Release);
            // ★ #65 — publish to the cross-path hairpin atomic so the netstack forwarder's sentinel
            // rewrite (`forwarder/run.rs::hairpin_dst` via `crate::mirror_hairpin_port`) sees THIS
            // Object-path port. Without it the shipping (Object) path left the hairpin at 0 → the
            // sentinel dial failed naturally → cloak ARMED but serve DORMANT (the AVD split-brain).
            if port > 0 {
                crate::MIRROR_HAIRPIN_PORT.store(port, Ordering::Release);
            }
            self.serve_state.store(
                if port > 0 {
                    CentauriServeState::Serving as u8
                } else {
                    CentauriServeState::Failed as u8
                },
                Ordering::Release,
            );
            // ★ CLOAK⊆SERVABLE — publish the servable set THE MOMENT the loopback is serving, and
            // ONLY then. This is what keeps the offline-CDN alive under the new gate: the gate is
            // fail-closed, so without a publish nothing is ever cloaked and Centauri goes dark — a
            // safe outcome but not a working one. Publishing here binds the cloak to the condition
            // that actually makes a sinkhole answerable: a serve loop is up AND the manifest names
            // the host. `port == 0` means the bind failed, so nothing is published and nothing is
            // intercepted — the DORMANT-serve split-brain (cloak armed, serve down, flows dead)
            // becomes impossible by construction rather than by vigilance.
            if port > 0 {
                let _ = self.servable_cloaked_hosts();
            } else {
                crate::mirror::publish_servable_cloak(&[]);
            }
            port as i32
        }));
        // Lift: Ok(port>0) ⇒ Ok(port); Ok(0) ⇒ BindFailed (bind failed / accept-thread panicked
        // before reporting); Err(panic_payload) ⇒ Panic. The `port` is already stored atomically
        // (a 0 store is a no-op for idempotency since the short-circuit checks >0).
        match outcome {
            Ok(port) if port > 0 => Ok(port),
            Ok(_zero) => Err(CentauriError::BindFailed {
                reason: "loopback listener failed to bind (port exhaustion / OS denial)"
                    .to_string(),
            }),
            Err(_panic) => {
                // The closure panicked mid-bind (serve_state stuck at Starting) ⇒ mark Failed for the dashboard.
                self.serve_state
                    .store(CentauriServeState::Failed as u8, Ordering::Release);
                Err(CentauriError::Panic {
                    reason: "start: panic firewalled (bug fails typed)".to_string(),
                })
            }
        }
    }

    /// The dashboard's one-glance Centauri status, as a structured [`CentauriSnapshot`] (the Object
    /// twin of the flat [`crate::mirror_status`] string — richer, but the cache numbers are the SAME
    /// REAL `CacheStore::len/total_bytes/is_full` the flat fn reads, never faked). Reports the LIVE
    /// Object cache + the bound serve port + the lived counters. Before [`Centauri::start`] the port
    /// is 0 + the serve state is Stopped. Pure read; panic-firewalled → an empty/zero snapshot.
    pub fn status(&self) -> CentauriSnapshot {
        self.snapshot()
    }

    /// The boot-rehydrate of the Centauri catalog from its signed `.tcat` durable source
    /// (the Object twin of the flat [`crate::rehydrate_centauri_from_signed`]). Delegates to
    /// [`load_centauri_catalog_from_signed`] (the SAME verify-sig-FIRST engine the flat export's bool
    /// fold wraps — math unchanged) and — the RETAIN seam, landed — on a genuine verify the parsed
    /// catalog REPLACES the retained one (exactly the [`Centauri::install_catalog`] retention: `start()`
    /// clones it into the loopback serve loop), so a rebooted device re-arms its serve authority from the
    /// durable `.tcat` WITHOUT a fresh install/arming pass. Returns `Ok(())` IFF a genuine `.tcat`
    /// verifies + parses; the failure modes are TYPED per variant (the split the old bool fold banked):
    ///   - absent/unreadable pair (cold start)      ⇒ [`CentauriError::RehydrateFailed`],
    ///   - signature did not verify                 ⇒ [`CentauriError::InvalidSignature`],
    ///   - verified but malformed body              ⇒ [`CentauriError::MalformedCatalog`].
    /// On ANY failure the retained catalog is left UNTOUCHED (fail-safe: a live serving set is never
    /// clobbered by a bad durable read). Tallies the attempt + the verified outcome into the lived
    /// counters. Panic-firewalled → `Err(Panic)`. The content cache's OWN durable tier is the `cache.rs`
    /// content-addressed store (rehydrated via the constructor's `load_from_disk`), NOT re-dumped here.
    pub fn rehydrate_from_signed(
        &self,
        base: String,
        pubkey: Vec<u8>,
    ) -> Result<(), CentauriError> {
        // Drive the verify-sig-FIRST typed rehydrate under the panic firewall. The closure returns the
        // typed result (Ok(catalog) ⇒ verified + parsed); a panic ⇒ the outer Err arm ⇒ Panic variant.
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            load_centauri_catalog_from_signed(&self.cache_dir, &base, &pubkey)
        }));
        // Lift: Ok(Ok(catalog)) ⇒ RETAIN + Ok(()); each typed fail ⇒ its honest variant; panic ⇒ Panic.
        let lifted = match outcome {
            Ok(Ok(catalog)) => {
                // THE RETAIN: the boot-verified catalog becomes the serve authority (a poisoned lock
                // drops the replace — the old set keeps serving; the verify still counts below).
                if let Ok(mut retained) = self.catalog.lock() {
                    *retained = catalog;
                }
                Ok(())
            }
            Ok(Err(CentauriRehydrateFail::AbsentPair)) => Err(CentauriError::RehydrateFailed {
                reason: format!(
                    "rehydrate of '{base}' found no readable .tcat/.sig pair (cold start)"
                ),
            }),
            Ok(Err(CentauriRehydrateFail::BadSignature)) => Err(CentauriError::InvalidSignature {
                reason: format!("durable '{base}' .tcat signature did not verify (forged/tampered/wrong key)"),
            }),
            Ok(Err(CentauriRehydrateFail::Malformed)) => Err(CentauriError::MalformedCatalog {
                reason: format!("durable '{base}' .tcat verified but its body is malformed"),
            }),
            Err(_panic) => Err(CentauriError::Panic {
                reason: "rehydrate_from_signed: panic firewalled (bug fails typed)".to_string(),
            }),
        };
        // Tally the attempt + the verified outcome (the SAME accounting the lossy bool kept).
        if let Ok(mut stats) = self.stats.lock() {
            stats.rehydrates_attempted += 1;
            if lifted.is_ok() {
                stats.rehydrates_verified += 1;
            }
        }
        lifted
    }

    /// THE SOVEREIGN BOOT LANE — rehydrate the DEVICE-authored catalog pair
    /// (`device-catalog.tcat` + `.sig`, persisted by [`Centauri::arm_device_catalog`] 3c) against
    /// THIS device's OWN key. Loads (or First-Boot mints) the device key from `key_seed_dir` and
    /// delegates to [`Centauri::rehydrate_from_signed`] with the device pubkey — the pubkey never
    /// crosses the FFI, the whole authority loop stays on-device (the sovereignty law: the app
    /// generates, signs, persists, AND verifies its own RAM⊗NAND artifact; no host-side "offline
    /// brain" is ever required for the device lane). A verified pair RETAINS as the serve
    /// authority WITHOUT re-hashing the content dir (the fast boot); the typed failures are the
    /// [`Centauri::rehydrate_from_signed`] set — an absent pair is the honest First-Boot
    /// `RehydrateFailed` (mint leaves no pair; the caller falls back to the arming pass, which
    /// now persists). An unavailable device key (entropy/IO failure) is `RehydrateFailed` too —
    /// no key, no possible author. Panic-firewalled by the delegate.
    pub fn rehydrate_device_catalog(
        &self,
        key_seed_dir: String,
    ) -> Result<(), CentauriError> {
        let key = match load_or_mint_device_key(&key_seed_dir) {
            Some((key, _minted)) => key,
            None => {
                return Err(CentauriError::RehydrateFailed {
                    reason: "device key unavailable (entropy/IO failure) — no device lane".to_string(),
                })
            }
        };
        let rehydrated = self.rehydrate_from_signed(
            DEVICE_CATALOG_BASE.to_string(),
            key.pubkey_blob().to_vec(),
        );

        // ★ #65 ROSTER FRESHNESS — a rehydrated catalog is only the truth while it still describes this
        // device's roster.
        //
        // The catalog is authored ONCE (first boot) and rehydrated on every boot after, because the
        // persisted pair is normally a strict superset of the shipped seed. But DISCOVERY keeps growing
        // between boots: a CDN the user met last week earned a cloak row that the pair authored before it
        // has never heard of. Rehydrating unconditionally would pin the device to its first-boot roster
        // forever — which is exactly why a discovered CDN was never absorbed no matter how often it was
        // seen (the catalog stayed frozen at its authored size).
        //
        // So: if any PROMOTED host is missing from the rehydrated catalog, decline the fast lane. The
        // caller's contract is "rehydrate succeeded ⇒ skip arming", so declining sends it into the
        // re-author branch, which rebuilds the roster (promotions included) and persists a fresh pair.
        // The next boot rehydrates THAT pair and takes the fast lane again — one re-author per genuinely
        // new CDN, not one per boot.
        if rehydrated.is_ok() {
            // The ledger must be LOADED before it can be consulted. The mirror arms early in tunnel
            // start — ahead of the resolver that normally arms discovery — so on a fresh process the
            // in-RAM store is still empty here even though the durable TSV is full. Arming it now (from
            // the same runtime-tier dir this function already received, which is exactly where
            // `centauri-discovered.tsv` lives) is idempotent and makes the check see the real roster
            // instead of an empty one. Without this the staleness test always passes vacuously and the
            // catalog stays frozen at its first-boot size forever.
            crate::centauri_discovery::arm(&key_seed_dir);
            let promoted = crate::centauri_discovery::promotable();
            if !promoted.is_empty() {
                let covered = self
                    .catalog
                    .lock()
                    .map(|c| {
                        promoted
                            .iter()
                            .all(|h| c.content_hash_for(h).is_some())
                    })
                    .unwrap_or(true); // a poisoned lock keeps the rehydrated catalog (never re-author on a fault)
                if !covered {
                    return Err(CentauriError::RehydrateFailed {
                        reason: "persisted catalog predates a promoted CDN — re-authoring the roster"
                            .to_string(),
                    });
                }
                // ★ #65 — MEASURED BUG: the catalog covered the promoted hosts, so this fast lane kept
                // the rehydrated roster and returned — WITHOUT ever publishing those hosts into the
                // DNS-plane cloak. Only the re-author branch published. So on every boot after the first
                // authoring, a promoted CDN held a catalog row while its name still resolved to the REAL
                // CDN: the request never reached Centauri and the absorb leg was silently inert (proven
                // on the AVD — `cdn.usefathom.com` at 43 discovery hits, cloak frozen at the 51 corpus
                // assets, and not one mirror log line for it). That is precisely the failure the
                // re-author branch documents guarding against; the fast lane simply never honoured it.
                //
                // Corpus hosts are filtered out because they are already cloaked — `is_cdn_host` is true
                // for them here and false for a promoted host that has not been published yet, which is
                // exactly the "fresh" set the re-author branch computes against its own roster.
                let fresh: Vec<String> = promoted
                    .iter()
                    .filter(|h| !super::localcdn::is_cdn_host(h))
                    .cloned()
                    .collect();
                if !fresh.is_empty() {
                    super::localcdn::publish_promoted_cloak(fresh);
                }
            }
        }
        rehydrated
    }

    /// Pull a [`CentauriSnapshot`] of the current cache + serve state + the lived counters (the
    /// dashboard read-path — pull, not push, since the Centauri mirror is boot-static + serve-event-
    /// driven, not a hot streaming metric). Pure read; panic-firewalled → an empty/zero snapshot.
    pub fn snapshot(&self) -> CentauriSnapshot {
        catch_unwind(AssertUnwindSafe(|| {
            // Lock-then-snapshot the cache (the read-stats-vs-serve-bytes identity invariant: the
            // SAME store the loopback serve-snapshot was seeded from).
            let (libraries, bytes, full, capacity) = match self.cache.lock() {
                Ok(cache) => (
                    cache.len() as i64,
                    cache.total_bytes() as i64,
                    cache.is_full(),
                    cache.capacity() as i64,
                ),
                // A poisoned lock ⇒ the zero baseline, never a panic across the boundary.
                Err(_) => (0, 0, false, 0),
            };
            // CATALOG STATE: the retained signed catalog's authorized-asset count (0 ⇒ the fail-closed
            // default) + its TCAT v2 freshness epoch (★ #22 slice 2; one lock, both reads).
            let (catalog_assets, catalog_authored_at_secs) = self
                .catalog
                .lock()
                .map(|c| (c.len() as i64, c.authored_at_secs() as i64))
                .unwrap_or((0, 0));
            let port = self.port.load(Ordering::Acquire);
            // Slice 5 — the LIVE serve state (the atomic `start()` drives), so Starting/Failed actually surface
            // (a port-only inference could only ever show Stopped/Serving).
            let serve_state =
                CentauriServeState::from_code(self.serve_state.load(Ordering::Acquire));
            let (
                installs_attempted,
                installs_verified,
                rehydrates_attempted,
                rehydrates_verified,
            ) = if let Ok(stats) = self.stats.lock() {
                (
                    stats.catalog_installs_attempted,
                    stats.catalog_installs_verified,
                    stats.rehydrates_attempted,
                    stats.rehydrates_verified,
                )
            } else {
                (0, 0, 0, 0)
            };
            // resolve_queries/hits are now lock-free atomics in `live` — the accept-loop observer tallies the
            // serve-path resolve there, the query-time `resolve_cdn*` entrypoints bump the SAME atomics.
            let resolve_queries = self.live.resolve_queries.load(Ordering::Relaxed);
            let resolve_hits = self.live.resolve_hits.load(Ordering::Relaxed);
            CentauriSnapshot {
                libraries,
                bytes,
                full,
                capacity,
                serve_port: i32::from(port),
                serve_state,
                catalog_installs_attempted: installs_attempted,
                catalog_installs_verified: installs_verified,
                resolve_queries,
                resolve_hits,
                rehydrates_attempted,
                rehydrates_verified,
                catalog_assets,
                catalog_authored_at_secs,
                cache_mode: self.cache_mode(),
                served_locally: self.live.served_locally.load(Ordering::Relaxed),
                served_bytes: self.live.served_bytes.load(Ordering::Relaxed),
                cdn_fetches: self.live.cdn_fetches.load(Ordering::Relaxed),
                blocked_missing: self.live.blocked_missing.load(Ordering::Relaxed),
                exact_serves: self.live.exact_serves.load(Ordering::Relaxed),
                fallback_serves: self.live.fallback_serves.load(Ordering::Relaxed),
                // CP-Centauri-Discovery — fold the living watch-list totals into the dashboard snapshot.
                // The discovery store is a process-global module twin of the Underground ledger (fed off
                // the resolver walk); the Centauri Object reads its totals here so the whole dashboard
                // rides the SAME liveCentauriStats crossing (no second bridge reader).
                discovered: crate::centauri_discovery::count() as i64,
                discovered_observed: crate::centauri_discovery::observed_total() as i64,
                // The living roster itself — top DISCOVERED_ROSTER_SHOWN hosts, pipe-delimited, bounded so
                // the flat-JSON crossing stays lean. Empty when nothing has been observed yet.
                discovered_hosts: crate::centauri_discovery::discovered_line(DISCOVERED_ROSTER_SHOWN),
            }
        }))
        .unwrap_or_else(|_| self.zeroed_snapshot())
    }

    // ===========================================================================================
    // Slice 5 — the NEW typed methods (the full UniFFI surface): the typed resolve, the CROWN toggle,
    // the typed cache stat, and the recent-serve feed. All `&self` reads/toggles, panic-firewalled.
    // ===========================================================================================

    /// Resolve a CDN URL to a fully-TYPED [`CentauriResolution`] (the full-power twin of the flat
    /// [`Centauri::resolve_cdn`], which returns only the canonical-name string). Carries the library, both
    /// versions, the file, the canonical catalog name, AND the [`CentauriSubstitution`] verdict — so an
    /// integrity-pinned (SRI) consumer can see whether the serve would be Exact or a fallback (F3). Delegates
    /// to the SAME [`resolve_full`] engine (math unchanged); tallies the query + the hit into the lived
    /// counters (the SAME accounting `resolve_cdn` keeps). Panic-firewalled → `null`.
    ///
    /// NO-BREAK: the flat `resolve_cdn` stays live byte-identical (the no-break contract) — this is the
    /// ADDITIVE typed surface the Kotlin call-site adopts on the Socio's bindgen regen.
    pub fn resolve_cdn_typed(&self, host: String, path: String) -> Option<CentauriResolution> {
        let resolved: Option<Resolution> =
            catch_unwind(AssertUnwindSafe(move || resolve_full(&host, &path))).unwrap_or(None);
        self.live.resolve_queries.fetch_add(1, Ordering::Relaxed);
        if resolved.is_some() {
            self.live.resolve_hits.fetch_add(1, Ordering::Relaxed);
        }
        resolved.map(CentauriResolution::from)
    }

    /// Arm/disarm the opt-out CROWN: [`CentauriCacheMode::LeakOnMiss`] (safe default — a miss self-fills with
    /// ≤ 1 upstream request) vs [`CentauriCacheMode::BlockMissing`] (strict, the crown ARMED — serve-local-OR-
    /// nothing ⇒ the CDN sees 0). Lock-free atomic store; the live serve path reads it (lowering it back to a
    /// [`CacheMode`] via the `From` cross) when it adopts the privacy flow (#85). Pure setter, never panics.
    pub fn set_cache_mode(&self, mode: CentauriCacheMode) {
        self.cache_mode.store(mode.code(), Ordering::Relaxed);
    }

    /// The live opt-out CROWN toggle ([`Centauri::set_cache_mode`]'s read-back; also embedded in the snapshot).
    /// Lock-free; an out-of-range stored code decodes to the safe `LeakOnMiss` default. Never panics.
    pub fn cache_mode(&self) -> CentauriCacheMode {
        CentauriCacheMode::from_code(self.cache_mode.load(Ordering::Relaxed))
    }

    /// The content-addressed cache's stats as ONE typed [`CentauriCacheStat`] (the full-power cross of the
    /// four loose `CacheStore` reads). The SAME REAL `len`/`total_bytes`/`is_full`/`capacity` the snapshot
    /// embeds, never faked. Pure read; panic-firewalled → a zeroed stat.
    pub fn cache_stat(&self) -> CentauriCacheStat {
        catch_unwind(AssertUnwindSafe(|| match self.cache.lock() {
            Ok(c) => CentauriCacheStat {
                libraries: c.len() as i64,
                bytes: c.total_bytes() as i64,
                full: c.is_full(),
                capacity: c.capacity() as i64,
            },
            Err(_) => CentauriCacheStat {
                libraries: 0,
                bytes: 0,
                full: false,
                capacity: 0,
            },
        }))
        .unwrap_or(CentauriCacheStat {
            libraries: 0,
            bytes: 0,
            full: false,
            capacity: 0,
        })
    }

    /// The most recent serve events (up to `max`), newest-first — the dashboard's "what the mirror just
    /// served" feed, read from the bounded in-Object ring (cap [`RECENT_SERVES_CAP`]). NOT the durable record
    /// (slice 6's `query-centauri.log`): a small glance feed. Pure read; panic-firewalled → an empty list.
    pub fn recent_serves(&self, max: u32) -> Vec<CentauriServeRecord> {
        catch_unwind(AssertUnwindSafe(|| {
            let ring = match self.recent.lock() {
                Ok(r) => r,
                Err(_) => return Vec::new(),
            };
            let n = (max as usize).min(ring.len());
            ring.iter().rev().take(n).cloned().collect()
        }))
        .unwrap_or_default()
    }

    /// The on-disk path of the per-pillar `query-centauri.log`, as a String for the FFI (D29 — the review
    /// channel made reachable from Kotlin; the `queryMasksolverLogPath` precedent). A sibling of the
    /// content-addressed cache the Object is rooted at (`cache_dir/query-centauri.log`) — the Object ALWAYS
    /// has a `cache_dir` (a constructor field), so unlike the Warden this is infallible. The dashboard's
    /// log-tail read path consumes it. Never panics (a pure join + lossless-enough lossy conversion).
    pub fn query_centauri_log_path(&self) -> String {
        self.log_path().to_string_lossy().into_owned()
    }

    /// The DURABLE review-channel twin of [`Centauri::record_serve`] (slice 6, the #133 `query-<pillar>.log`
    /// pattern — the `query-warden.log` precedent), EXPORTED for the Kotlin control plane (D29): append ONE
    /// human-legible line to [`Centauri::query_centauri_log_path`] THROUGH the shared RAM⊗NAND
    /// [`crate::log_tier`] substrate, THEN bump the live CROWN counters + the recent ring. ONE serve event,
    /// BOTH sinks — the CROWN ("the CDN sees ≤ 1 request") is AUDITABLE from the file, not merely asserted.
    /// The LIVE accept loop feeds the same sinks itself (the self-feeding observer); this export lets a
    /// Kotlin-side serve/deny decision join the same record. The log write is FAIL-OPEN inside `log_append`
    /// (a debug log NEVER breaks a serve); `rec.now_ms` is the INJECTED clock (the #133/warden
    /// clock-injection invariant — the Object never reads a wall clock in its methods).
    pub fn record_serve_logged(&self, rec: CentauriServeRecord) {
        // Durable sink FIRST (borrow the record), then move it into the live-counter sink.
        mirror::log::append_serve(&self.log_path(), &rec);
        self.record_serve(rec);
    }

    /// Bind the ONE foreign per-serve reader (D26 — the Beast `attach_sink` one-reader discipline): the live
    /// accept loop pushes every [`CentauriServeRecord`] to it as it happens (no polling; bursts between
    /// dashboard polls are no longer invisible). A re-attach REPLACES the previous reader. Never panics.
    pub fn attach_serve_sink(&self, sink: Arc<dyn CentauriServeSink>) {
        if let Ok(mut bound) = self.serve_sink.lock() {
            *bound = Some(sink);
        }
    }

    /// Unbind the foreign per-serve reader ([`Centauri::attach_serve_sink`]'s inverse) — the accept loop
    /// stops pushing (counters/ring/log keep self-feeding). Never panics.
    pub fn detach_serve_sink(&self) {
        if let Ok(mut bound) = self.serve_sink.lock() {
            *bound = None;
        }
    }

    /// Run a TIER-B warm-up batch (D04 — the "warm seed" as a curated SELF-FILL on the user's own device,
    /// `packaging.rs`): derive up to `max_targets` targets from the RETAINED signed catalog ∩ the LocalCDN
    /// map (each = a catalog asset name + its real-CDN upstream URL), then drive the privacy flow ONCE per
    /// target over the Object's LIVE shared store — a genuine miss self-fills with EXACTLY ONE hash-gated
    /// upstream request ([`fetch_leg`] over the shared ring-pinned TLS), an already-cached or uncatalogued
    /// target costs 0 CDN. Because the store is shared with the running loopback (`run_shared`), every
    /// filled asset is servable IMMEDIATELY — no restart. Serial + bounded (CPU/battery-gentle; the batch
    /// runs on a dedicated current-thread runtime on the CALLER's thread — Kotlin calls this from
    /// Dispatchers.IO, the crate's established blocking-bridge discipline). With no installed catalog the
    /// batch is an honest zero-target no-op (no egress). Panic-firewalled → a zeroed report.
    pub fn warm_up(&self, max_targets: u32) -> CentauriWarmUpReport {
        const ZEROED: CentauriWarmUpReport = CentauriWarmUpReport {
            targets: 0,
            already_cached: 0,
            filled: 0,
            not_in_catalog: 0,
            failed: 0,
        };
        catch_unwind(AssertUnwindSafe(|| {
            let catalog = match self.catalog.lock() {
                Ok(c) => c.clone(),
                Err(_) => Catalog::default(),
            };
            // Bound the batch hard (a warm-up is a curated top-N, never a whole-catalog crawl).
            let targets = warm_targets(&catalog, (max_targets as usize).min(MAX_WARM_UP_TARGETS));
            if targets.is_empty() {
                return ZEROED; // no catalog / nothing mapped ⇒ honest no-op, zero egress.
            }
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => {
                    return CentauriWarmUpReport {
                        targets: targets.len() as i64,
                        failed: targets.len() as i64,
                        ..ZEROED
                    }
                }
            };
            let inflight = InFlight::new();
            let tls = Arc::new(crate::tls_shared::client_tls_config());
            let cache = Arc::clone(&self.cache);
            let report = rt.block_on(mirror::warm_up(
                &catalog,
                &cache,
                &inflight,
                &targets,
                |t, h| {
                    // ★ #22 slice 2 — walk the target's multi-CDN ladder: primary, then each
                    // alternate ONLY on failure (fetch_leg is hash-gated, so a wrong-bytes host is
                    // a failed rung and the next host is tried for the REAL pinned content).
                    let tls = Arc::clone(&tls);
                    let target = t.clone();
                    async move {
                        mirror::fetch_via_ladder(&target, h, |url, hash| {
                            let tls = Arc::clone(&tls);
                            let url = url.to_string();
                            async move { fetch_leg(&url, hash, tls).await.map_err(|_| ()) }
                        })
                        .await
                    }
                },
            ));
            CentauriWarmUpReport {
                targets: report.targets as i64,
                already_cached: report.already_cached as i64,
                filled: report.filled as i64,
                not_in_catalog: report.not_in_catalog as i64,
                failed: report.failed as i64,
            }
        }))
        .unwrap_or(ZEROED)
    }
}

// ===========================================================================================
// Sovereign-arming helpers (Rust-INTERNAL, NOT `#[uniffi::export]`) — the device-key load/mint,
// owned-content manifest read, and key-id hex used by `Centauri::arm_device_catalog`. Absorbed from
// nautilus-rs's `centauri_catalog.rs` (study-not-copy) and made engine-native.
// ===========================================================================================

/// Load this install's per-device Centauri signing authority from `<dir>/device.key`, minting a fresh one
/// from OS entropy on First Boot (seed absent OR malformed) and persisting the 32-byte secret seed so the
/// SAME authority reloads across reboots. Reuses the engine's [`crate::mirror::DeviceKey`] (minisign legacy
/// `Ed`, no duplicate Ed25519). Returns `(key, minted)`; `None` only on an unrecoverable IO/entropy failure
/// (the caller treats `None` as "device authority unavailable" and fails safe — never a panic). The seed
/// NEVER leaves the device: possession of these bytes IS possession of this install's content-authority.
#[cfg(feature = "mirror")]
fn load_or_mint_device_key(dir: &str) -> Option<(crate::mirror::DeviceKey, bool)> {
    use crate::mirror::{DeviceKey, DEVICE_SEED_LEN};
    let dir = std::path::Path::new(dir);
    if std::fs::create_dir_all(dir).is_err() {
        return None;
    }
    let seed_path = dir.join("device.key");
    // Reload path: a well-formed 32-byte seed on disk → reconstruct the SAME authority (deterministic).
    if let Ok(bytes) = std::fs::read(&seed_path) {
        if bytes.len() == DEVICE_SEED_LEN {
            let mut seed = [0u8; DEVICE_SEED_LEN];
            seed.copy_from_slice(&bytes);
            return Some((DeviceKey::from_seed(&seed), false));
        }
        // A malformed seed (truncated/oversized) is treated as absent → re-mint (fail-forward).
    }
    // First-Boot mint: fresh OS entropy → persist the seed → return the new authority.
    let key = DeviceKey::generate().ok()?;
    if std::fs::write(&seed_path, key.secret_seed()).is_err() {
        return None;
    }
    Some((key, true))
}

/// The DEVICE-authored catalog pair basename — DISTINCT from the pinned-key lane's `catalog.tcat`
/// (`RuntimeTierManager.CENTAURI_BASE`, reserved for a future build-signed production artifact), so
/// the two authorities never collide on one filename. The pair lives in the Object's `cache_dir`
/// (the SAME dir [`Centauri::rehydrate_from_signed`] reads), beside the content-addressed store.
#[cfg(feature = "mirror")]
pub(crate) const DEVICE_CATALOG_BASE: &str = "device-catalog.tcat";

/// Atomically persist the device-signed pair into `dir`: `<dir>/device-catalog.tcat` + `.sig`, each
/// via the cache.rs tmp+rename idiom (a crashed/partial write never leaves a half-file under the
/// real name; a torn window between the two renames leaves body-without-sig, which
/// `read_signed_pair` reads as the honest ABSENT pair — the next boot re-authors). `false` on any
/// IO failure or an unrooted (empty) dir — fail-open, the caller's RAM install stands.
#[cfg(feature = "mirror")]
fn persist_device_pair(dir: &std::path::Path, body: &[u8], sig: &[u8]) -> bool {
    if dir.as_os_str().is_empty() {
        return false;
    }
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let write_atomic = |name: &str, bytes: &[u8]| -> bool {
        let tmp = dir.join(format!("{name}.tmp"));
        let dst = dir.join(name);
        std::fs::write(&tmp, bytes).is_ok() && std::fs::rename(&tmp, &dst).is_ok()
    };
    write_atomic(DEVICE_CATALOG_BASE, body)
        && write_atomic(&format!("{DEVICE_CATALOG_BASE}{}", crate::SIGNED_SIG_SUFFIX), sig)
}

/// One row of the content manifest: a shipped asset the arming hashes + admits, then authorizes in the
/// device-signed catalog. `host`/`cloaked` decide the serve identity — an app-OWNED page rides
/// `host=torta.local, cloaked=false` (an uncloaked local page); a shipped CDN library rides its REAL CDN
/// host + `cloaked=true` (the DNS cloak points the host at loopback, and the loopback serves THESE bytes
/// 0-egress under the canonical CDN name — a genuine offline CDN, the CDN never contacted).
#[cfg(feature = "mirror")]
struct ManifestRow {
    /// The host-independent catalog asset name the loopback routes by (`<library>/<version>/<file>` for a
    /// CDN asset, or a free path for an owned page).
    name: String,
    /// The serve host: `torta.local` for an owned page, or the REAL CDN host for a cloaked library.
    host: String,
    /// `true` ⇒ this host is DNS-cloaked to loopback (a CDN library served locally); `false` ⇒ an uncloaked
    /// local page.
    cloaked: bool,
    /// The asset's flat filename under the content dir (no separators — path-traversal is rejected upstream).
    file: String,
}

/// Read the content manifest `<dir>/content.tsv` → typed [`ManifestRow`]s. Each non-blank, non-`#` line is
/// TAB-separated in ONE of two shapes (both supported so an owned-only seed stays terse):
///   - `<name>\t<host>\t<cloaked:0|1>\t<file>`  — the full form (CDN library or explicit host/cloak), OR
///   - `<name>\t<file>`                          — the owned-page short form (host `torta.local`, uncloaked).
///
/// Malformed lines are skipped, and the row count is bounded (a curated seed, never an unbounded crawl). An
/// absent/unreadable manifest yields an empty list (the arming then authors a cloak-only catalog — honest
/// `libraries=0`).
#[cfg(feature = "mirror")]
fn read_content_manifest(dir: &std::path::Path) -> Vec<ManifestRow> {
    /// A curated seed manifest is small; cap it hard so a corrupt file can never balloon the batch.
    const MAX_MANIFEST_ROWS: usize = 512;
    let text = match std::fs::read_to_string(dir.join("content.tsv")) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<ManifestRow> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').map(str::trim).collect();
        let row = match cols.as_slice() {
            // Full form: name · host · cloaked · file.
            [name, host, cloaked, file] if !name.is_empty() && !host.is_empty() && !file.is_empty() => {
                ManifestRow {
                    name: (*name).to_string(),
                    host: (*host).to_string(),
                    cloaked: *cloaked == "1" || cloaked.eq_ignore_ascii_case("true"),
                    file: (*file).to_string(),
                }
            }
            // Short form: name · file (an app-owned local page).
            [name, file] if !name.is_empty() && !file.is_empty() => ManifestRow {
                name: (*name).to_string(),
                host: "torta.local".to_string(),
                cloaked: false,
                file: (*file).to_string(),
            },
            _ => continue, // any other shape is skipped (never a wrong-but-parsed row).
        };
        out.push(row);
        if out.len() >= MAX_MANIFEST_ROWS {
            break;
        }
    }
    out
}

/// Lower-case hex of the 8-byte device `key_id` (exactly 16 chars) — the human-legible public device
/// identity the arming report carries. Local twin of nautilus-rs's `hex_lower_key_id`.
#[cfg(feature = "mirror")]
fn hex_lower_key_id(id: &[u8; 8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(16);
    for &b in id {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ===========================================================================================
// Rust-INTERNAL half (NOT `#[uniffi::export]`): the in-crate serve recorder + the accept-loop
// observer adapter (D29 — the ring/counters/log SELF-FEED from the live loopback serves).
// ===========================================================================================

#[cfg(feature = "mirror")]
impl Centauri {
    /// Record ONE serve event: bump the CROWN counters per the outcome and push the record onto the bounded
    /// recent-serve ring. The LIVE accept loop drives the same core through its per-serve observer
    /// ([`Centauri::serve_observer`] → [`observe_trace`] — D29, the ring self-feeds on-device); this in-crate
    /// seam is the direct recorder (unit-proven end-to-end: a record in ⇒ the snapshot witnesses it). Never
    /// panics: a poisoned ring lock simply drops the feed entry (the counters still bump — lock-free atomics).
    ///
    /// The counter mapping (the CROWN math the dashboard renders):
    ///   - `ServedLocal`      ⇒ `served_locally` + `served_bytes` (0-egress) + the substitution split.
    ///   - `LeakedThenServed` ⇒ `cdn_fetches` (the ≤ 1 leak) + the substitution split.
    ///   - `BlockedMissing`   ⇒ `blocked_missing` (strict, the CDN saw 0).
    ///   - `NotInCatalog` / `FetchFailed` ⇒ no counter (no asset was served).
    pub fn record_serve(&self, rec: CentauriServeRecord) {
        apply_serve(&self.live, &self.recent, rec);
    }

    /// The on-disk path of the per-pillar `query-centauri.log` — a sibling of the content-addressed cache the
    /// Object is rooted at (`cache_dir` + [`crate::mirror::log::QUERY_CENTAURI_LOG_NAME`], the `query-<pillar>.
    /// log` convention #133). The Object ALWAYS has a `cache_dir` (a constructor field), so — unlike the Warden
    /// (which may be RAM-UNBOUND) — this is infallible: the pillar OWNS its log location, no FFI path plumbing.
    /// (The exported String twin is [`Centauri::query_centauri_log_path`] — D29.)
    fn log_path(&self) -> std::path::PathBuf {
        self.cache_dir.join(mirror::log::QUERY_CENTAURI_LOG_NAME)
    }

    /// Build the per-serve [`mirror::server::ServeObserver`] the live accept loop calls (D29): clones of the
    /// shared CROWN counters + the recent ring + the foreign-sink binding + the log path travel to the
    /// `centauri-mirror` accept thread; each traced serve becomes ONE [`CentauriServeRecord`] fed to ALL the
    /// sinks. The wall clock is injected HERE, by the accept-loop adapter — every Object METHOD stays
    /// clock-free (the #133/warden clock-injection invariant).
    fn serve_observer(&self) -> mirror::server::ServeObserver {
        let live = Arc::clone(&self.live);
        let recent = Arc::clone(&self.recent);
        let sink = Arc::clone(&self.serve_sink);
        let log_path = self.log_path();
        Arc::new(move |trace: mirror::server::ServeTrace<'_>| {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            observe_trace(&live, &recent, &sink, &log_path, now_ms, &trace);
        })
    }

    /// The zeroed snapshot for the panic-firewall fallback — reads the lock-free `cache_mode` (so even a
    /// poisoned cache/stats lock still reports the honest current toggle), everything else zero.
    fn zeroed_snapshot(&self) -> CentauriSnapshot {
        CentauriSnapshot {
            libraries: 0,
            bytes: 0,
            full: false,
            capacity: 0,
            serve_port: 0,
            serve_state: CentauriServeState::Stopped,
            catalog_installs_attempted: 0,
            catalog_installs_verified: 0,
            resolve_queries: 0,
            resolve_hits: 0,
            rehydrates_attempted: 0,
            rehydrates_verified: 0,
            catalog_assets: 0,
            catalog_authored_at_secs: 0,
            cache_mode: self.cache_mode(),
            served_locally: 0,
            served_bytes: 0,
            cdn_fetches: 0,
            blocked_missing: 0,
            exact_serves: 0,
            fallback_serves: 0,
            discovered: 0,
            discovered_observed: 0,
            discovered_hosts: String::new(),
        }
    }
}

/// The hard ceiling on a single [`Centauri::warm_up`] batch — a warm-up is a CURATED top-N self-fill,
/// never a whole-catalog crawl (CPU/battery/network-gentle; each target is still ≤ 1 request EVER).
#[cfg(feature = "mirror")]
const MAX_WARM_UP_TARGETS: usize = 256;

/// The shared serve-record core (D29): bump the CROWN counters per the outcome + ring the record, exactly
/// the [`Centauri::record_serve`] contract — factored free so BOTH drivers (the Object method and the
/// accept-loop observer, which cannot borrow `&self` across the thread) apply ONE law. Never panics: a
/// poisoned ring lock drops the feed entry; the counters are lock-free atomics.
#[cfg(feature = "mirror")]
fn apply_serve(
    live: &CentauriLiveStats,
    recent: &Mutex<VecDeque<CentauriServeRecord>>,
    rec: CentauriServeRecord,
) {
    match rec.outcome {
        CentauriServeOutcome::ServedLocal => {
            live.served_locally.fetch_add(1, Ordering::Relaxed);
            live.served_bytes
                .fetch_add(rec.bytes.max(0), Ordering::Relaxed);
            tally_substitution(live, rec.substitution);
        }
        CentauriServeOutcome::LeakedThenServed => {
            live.cdn_fetches.fetch_add(1, Ordering::Relaxed);
            tally_substitution(live, rec.substitution);
        }
        CentauriServeOutcome::BlockedMissing => {
            live.blocked_missing.fetch_add(1, Ordering::Relaxed);
        }
        CentauriServeOutcome::NotInCatalog | CentauriServeOutcome::FetchFailed => {}
    }
    // Push to the recent ring (newest at the back), bounded — drop the oldest on overflow.
    if let Ok(mut ring) = recent.lock() {
        if ring.len() >= RECENT_SERVES_CAP {
            ring.pop_front();
        }
        ring.push_back(rec);
    }
}

/// Tally a successful serve's substitution into the exact-vs-fallback split (F3). `Incompatible` is never
/// served (the resolver returns `None`), so it tallies nothing.
#[cfg(feature = "mirror")]
fn tally_substitution(live: &CentauriLiveStats, sub: CentauriSubstitution) {
    match sub {
        CentauriSubstitution::Exact => {
            live.exact_serves.fetch_add(1, Ordering::Relaxed);
        }
        CentauriSubstitution::SafeNewer | CentauriSubstitution::RiskyOlder => {
            live.fallback_serves.fetch_add(1, Ordering::Relaxed);
        }
        // Neither is a served-byte verdict: `Incompatible` is never served (resolver returns `None`),
        // `NotApplicable` is a non-serve miss. Both tally nothing into the exact-vs-fallback split.
        CentauriSubstitution::Incompatible | CentauriSubstitution::NotApplicable => {}
    }
}

/// Lift one accept-loop [`mirror::server::ServeTrace`] into a typed [`CentauriServeRecord`] (D29), or `None`
/// for a trace with no honest [`CentauriServeOutcome`] vocabulary:
///   - `Served(bytes)` ⇒ `ServedLocal` (a 0-egress hit off the live shared store) with the byte count + the
///     resolution's substitution (a path-keyed serve — no version ladder — is byte-identical ⇒ `Exact`).
///   - `LeakedThenServed(bytes)` ⇒ `LeakedThenServed` (#85, stage 3 armed): the miss escalated to EXACTLY ONE
///     hash-verified upstream `fetch_once`, cached, then served — `apply_serve` counts it into `cdn_fetches`
///     (the ≤ 1 self-fill crown) with the resolution's substitution split.
///   - `NotInCatalog` ⇒ `NotInCatalog` (fail-closed 404; ringed + logged, no counter — nothing served).
///   - `CacheMiss` (a miss with NO armed fetch ctx / unmapped upstream ⇒ fail-closed 503) and
///     `BlockedFingerprinter` (403 deny) are SKIPPED — neither maps onto the crown vocabulary without lying
///     (the HTTP status is their witness).
#[cfg(feature = "mirror")]
fn record_from_trace(
    now_ms: u64,
    trace: &mirror::server::ServeTrace<'_>,
) -> Option<CentauriServeRecord> {
    let (outcome, bytes) = match trace.outcome {
        ServeOutcome::Served(b) => (CentauriServeOutcome::ServedLocal, b.len() as i64),
        // #85 — the live fetch-on-miss seam fired: a watched CDN asset missed the store, leaked EXACTLY ONE
        // hash-verified upstream `fetch_once`, was cached, and served. This is the honest witness that
        // `apply_serve` counts into `cdn_fetches` (the ≤ 1 self-fill crown) + the substitution split.
        ServeOutcome::LeakedThenServed(b) => {
            (CentauriServeOutcome::LeakedThenServed, b.len() as i64)
        }
        ServeOutcome::NotInCatalog => (CentauriServeOutcome::NotInCatalog, 0),
        // An absorb that has not run yet is not a serve — it produces no witness, exactly like an
        // unfilled cache miss. The record is written when the absorb leg resolves it (LeakedThenServed).
        ServeOutcome::CacheMiss(_)
        | ServeOutcome::AbsorbMiss(_)
        | ServeOutcome::BlockedFingerprinter => return None,
    };
    let (library, requested_version, served_version, canonical_name) = match trace.resolution {
        Some(r) => (
            r.library.clone(),
            r.requested_version.clone(),
            r.served_version.clone(),
            r.canonical_name(),
        ),
        // No CDN-URL grammar ran: the path IS the catalog name, with empty version fields. Shared by a
        // path-keyed REAL serve (owned page / direct asset) AND a `NotInCatalog` miss — the substitution
        // below distinguishes them, since only one of the two actually served bytes.
        None => (
            String::new(),
            String::new(),
            String::new(),
            trace.path.trim_start_matches('/').to_string(),
        ),
    };
    // Substitution is a SERVED-BYTE verdict. A `NotInCatalog` miss served nothing, so it has NO verdict
    // (`NotApplicable`) — NEVER a phantom `Exact` that the dashboard would print as a real match on a 404.
    // A path-keyed real serve (resolution `None`, outcome `Served`) is byte-identical to the request ⇒ Exact.
    let substitution = if matches!(trace.outcome, ServeOutcome::NotInCatalog) {
        CentauriSubstitution::NotApplicable
    } else {
        match trace.resolution {
            Some(r) => r.substitution.into(),
            None => CentauriSubstitution::Exact,
        }
    };
    Some(CentauriServeRecord {
        now_ms,
        host: trace.host.to_string(),
        canonical_name,
        library,
        requested_version,
        served_version,
        substitution,
        outcome,
        bytes,
    })
}

/// The accept-loop observer core (D29): lift the trace to a record, then feed EVERY sink — the durable
/// `query-centauri.log` line FIRST (fail-open inside `append_serve` — a debug log never breaks a serve),
/// the CROWN counters + the recent ring, and finally the bound foreign [`CentauriServeSink`] (cloned OUT of
/// its lock — Kotlin is never called under a lock). Factored free of `&self` so the accept thread drives it
/// through clones AND the unit tests prove it without a socket.
#[cfg(feature = "mirror")]
fn observe_trace(
    live: &CentauriLiveStats,
    recent: &Mutex<VecDeque<CentauriServeRecord>>,
    sink: &Mutex<Option<Arc<dyn CentauriServeSink>>>,
    log_path: &std::path::Path,
    now_ms: u64,
    trace: &mirror::server::ServeTrace<'_>,
) {
    // Serve-path resolve tally (the CROWN's resolve witness): a request the live router sent through the
    // LocalCDN resolve leg — a watched CDN host that is NOT a hard-blocked fingerprinter — performed exactly
    // ONE `resolve_full`. Recompute the router's OWN gate with the SAME pure fns (`is_cdn_host` +
    // `is_blocked_fingerprinter`) so this can never drift from `route_host_aware_traced`: one query per
    // CDN-routed request, one hit when it MATCHED a known library (`trace.resolution.is_some()`). Path-keyed
    // / owned serves (a non-CDN `Host`) never resolve → never counted; the query-time `resolve_cdn*`
    // entrypoints bump the SAME atomics. Tallied BEFORE the record early-return: a watched host with an
    // unmapped path resolves (a MISS) yet yields no serve record.
    if !trace.host.is_empty()
        && super::localcdn::is_cdn_host(trace.host)
        && !super::localcdn::is_blocked_fingerprinter(trace.host, trace.path)
    {
        live.resolve_queries.fetch_add(1, Ordering::Relaxed);
        if trace.resolution.is_some() {
            live.resolve_hits.fetch_add(1, Ordering::Relaxed);
        }
    }
    let Some(rec) = record_from_trace(now_ms, trace) else {
        return;
    };
    mirror::log::append_serve(log_path, &rec);
    let bound = sink.lock().ok().and_then(|g| g.clone());
    if let Some(reader) = bound {
        reader.on_serve(rec.clone());
    }
    apply_serve(live, recent, rec);
}

/// Derive the TIER-B warm-up targets (D04): the RETAINED signed catalog's assets ∩ the LocalCDN map — for
/// each catalog entry whose canonical name parses as `<library>/<version>/<file>` and whose library is
/// mapped (preferring the entry's OWN CDN host, falling back to any host carrying the library), the target
/// is that name + its real-CDN upstream URL ([`upstream_url`]). Capped at `max`; an unmapped/unparseable
/// entry is skipped (never a fabricated URL). Pure — unit-testable without a catalog install or a socket.
#[cfg(feature = "mirror")]
fn warm_targets(catalog: &Catalog, max: usize) -> Vec<WarmUpTarget> {
    let mut targets = Vec::new();
    for entry in catalog.entries() {
        if targets.len() >= max {
            break;
        }
        let mut segs = entry.name.splitn(3, '/');
        let (Some(library), Some(version), Some(file)) = (segs.next(), segs.next(), segs.next())
        else {
            continue; // not the <library>/<version>/<file> grammar (e.g. a .tblk artifact) ⇒ skip.
        };
        if library.is_empty() || version.is_empty() || file.is_empty() {
            continue;
        }
        let map = mirror::FULL_MAPS
            .iter()
            .find(|m| m.library == library && m.host == entry.host)
            .or_else(|| mirror::FULL_MAPS.iter().find(|m| m.library == library));
        let Some(map) = map else {
            continue; // no mapped CDN upstream for this library ⇒ never fabricate a URL.
        };
        // ★ #22 slice 2 — the multi-CDN failover ladder: every OTHER mapped host carrying this
        // library becomes an alternate upstream (same `<version>/<file>`, real map coordinates —
        // never a fabricated URL), deduped by host, capped at MAX_ALT_UPSTREAMS. The hash gate
        // makes the substitution safe (only pinned bytes are ever cached); the short cap keeps
        // the who-learns privacy surface honest (rungs are tried ONLY on transport failure).
        let mut alt_urls: Vec<String> = Vec::new();
        let mut alt_hosts: Vec<&str> = Vec::new();
        for alt in mirror::FULL_MAPS.iter() {
            if alt_urls.len() >= mirror::MAX_ALT_UPSTREAMS {
                break;
            }
            if alt.library != library || alt.host == map.host || alt_hosts.contains(&alt.host) {
                continue; // same primary host / a host already on the ladder ⇒ no failover value.
            }
            alt_hosts.push(alt.host);
            alt_urls.push(upstream_url(alt.host, alt.base_path, version, file));
        }
        targets.push(WarmUpTarget::with_alternates(
            entry.name.clone(),
            upstream_url(map.host, map.base_path, version, file),
            alt_urls,
        ));
    }
    targets
}

#[cfg(all(test, feature = "mirror"))]
mod tests {
    use super::*;

    #[test]
    fn constructor_builds_empty_store_for_cold_dir() {
        // A cold/missing dir rehydrates zero (not a panic) — the constructible + honest baseline.
        let c = Centauri::new("/tmp/torta-centauri-object-test-cold".to_string());
        let snap = c.snapshot();
        assert_eq!(snap.libraries, 0, "cold cache ⇒ empty");
        assert_eq!(snap.bytes, 0);
        assert!(!snap.full);
        assert_eq!(snap.serve_port, 0, "not started ⇒ port 0");
        assert_eq!(snap.serve_state, CentauriServeState::Stopped);
        assert_eq!(snap.catalog_installs_attempted, 0);
    }

    #[test]
    fn install_catalog_with_empty_sig_is_invalid_signature_err() {
        let c = Centauri::new("/tmp/torta-centauri-object-test-install".to_string());
        // Empty sig ⇒ parse_verified returns BadSignature ⇒ Err(InvalidSignature), no panic.
        let err = c
            .install_catalog(vec![1, 2, 3], vec![], vec![0u8; 42])
            .expect_err("empty sig ⇒ Err(InvalidSignature)");
        assert!(
            matches!(err, CentauriError::InvalidSignature { .. }),
            "empty sig ⇒ InvalidSignature, got {err:?}"
        );
        let snap = c.snapshot();
        assert_eq!(snap.catalog_installs_attempted, 1, "attempt tallied");
        assert_eq!(snap.catalog_installs_verified, 0, "verify tallied false");
    }

    #[test]
    fn cdn_hosts_is_non_empty_pure_set() {
        let c = Centauri::new("/tmp/torta-centauri-object-test-hosts".to_string());
        let hosts = c.cdn_hosts();
        // The static build-time LocalCDN seed map is non-empty (SEED_MAPS).
        assert!(!hosts.is_empty(), "cdn_hosts returns the seeded set");
        // Idempotent + pure — two calls return the same set.
        let hosts2 = c.cdn_hosts();
        assert_eq!(hosts, hosts2);
    }

    #[test]
    fn cloaking_rules_is_fenced_block() {
        let c = Centauri::new("/tmp/torta-centauri-object-test-cloak".to_string());
        let rules = c.cloaking_rules();
        // The cloaking-rules block is fenced (BEGIN/END markers) + non-empty for the seed set.
        assert!(!rules.is_empty(), "cloaking_rules returns the fenced block");
    }

    #[test]
    fn resolve_cdn_unmapped_host_is_none() {
        let c = Centauri::new("/tmp/torta-centauri-object-test-resolve".to_string());
        // An unmapped host ⇒ None, tallied as a query but not a hit.
        let resolved = c.resolve_cdn("not-a-cdn.example.invalid".to_string(), "/x.js".to_string());
        assert!(resolved.is_none());
        let snap = c.snapshot();
        assert_eq!(snap.resolve_queries, 1);
        assert_eq!(snap.resolve_hits, 0);
    }

    #[test]
    fn rehydrate_from_signed_absent_pair_is_rehydrate_failed_err() {
        let c = Centauri::new("/tmp/torta-centauri-object-test-rehydrate".to_string());
        // No .tcat pair on disk ⇒ RehydrateFailed (cold start), tallied as an attempt.
        let err = c
            .rehydrate_from_signed("nonexistent.tcat".to_string(), vec![0u8; 42])
            .expect_err("absent .tcat ⇒ Err(RehydrateFailed)");
        assert!(
            matches!(err, CentauriError::RehydrateFailed { .. }),
            "absent pair ⇒ RehydrateFailed, got {err:?}"
        );
        let snap = c.snapshot();
        assert_eq!(snap.rehydrates_attempted, 1);
        assert_eq!(snap.rehydrates_verified, 0);
    }

    #[test]
    fn snapshot_is_consistent_across_reads() {
        let c = Centauri::new("/tmp/torta-centauri-object-test-consistent".to_string());
        let _ = c.install_catalog(vec![], vec![], vec![0u8; 42]);
        let s1 = c.snapshot();
        let s2 = c.snapshot();
        assert_eq!(s1.libraries, s2.libraries);
        assert_eq!(s1.catalog_installs_attempted, s2.catalog_installs_attempted);
        assert_eq!(s1.serve_port, s2.serve_port);
    }

    #[test]
    fn enum_codes_match_the_stable_ordinal_contract() {
        assert_eq!(CentauriServeState::Stopped.code(), 0);
        assert_eq!(CentauriServeState::Starting.code(), 1);
        assert_eq!(CentauriServeState::Serving.code(), 2);
        assert_eq!(CentauriServeState::Failed.code(), 3);
    }

    // ---- slice 6: record_serve_logged — the durable query-centauri.log review channel (#133) ----

    #[test]
    fn record_serve_logged_writes_query_centauri_log_and_bumps_counters() {
        // ONE serve event ⇒ BOTH sinks: the durable greppable line lands BESIDE the cache dir AND the live
        // CROWN counters witness it (the #133 review-channel twin of record_serve — the warden precedent).
        let mut dir = std::env::temp_dir();
        dir.push(format!("torta-centauri-querylog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let c = Centauri::new(dir.to_string_lossy().to_string());

        c.record_serve_logged(CentauriServeRecord {
            now_ms: 1_751_300_000_123,
            host: "cdnjs.cloudflare.com".to_string(),
            canonical_name: "jquery/3.6.0/jquery.min.js".to_string(),
            library: "jquery".to_string(),
            requested_version: "3.6.0".to_string(),
            served_version: "3.6.0".to_string(),
            substitution: CentauriSubstitution::Exact,
            outcome: CentauriServeOutcome::ServedLocal,
            bytes: 89_476,
        });

        // (1) the live CROWN counters witnessed the 0-egress local hit.
        let snap = c.snapshot();
        assert_eq!(
            snap.served_locally, 1,
            "the local hit bumped the CROWN counter"
        );
        assert_eq!(snap.served_bytes, 89_476);
        assert_eq!(snap.exact_serves, 1, "an exact serve is the SRI-safe split");

        // (2) the durable log line landed beside the cache dir, greppable.
        let log_path = c.log_path();
        assert_eq!(log_path, dir.join("query-centauri.log"));
        // The D29 exported String twin names the SAME path (the Kotlin log-tail read).
        assert_eq!(
            c.query_centauri_log_path(),
            log_path.to_string_lossy().into_owned()
        );
        let body = std::fs::read_to_string(&log_path).expect("query-centauri.log was written");
        assert!(
            body.contains("LOCAL cdnjs.cloudflare.com jquery/3.6.0/jquery.min.js exact 89476 -"),
            "the serve verdict is logged greppably: {body}"
        );
        assert!(
            !body.contains(" LEAK "),
            "a 0-egress local hit is never a LEAK line: {body}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_centauri_log_path_sits_beside_the_cache_dir() {
        // The per-pillar log is a sibling of the content-addressed cache in the SAME app-private cache dir.
        // ONE base for both sides. A hardcoded "/tmp/..." here passed on the Windows host (where it
        // becomes a creatable C:\tmp\...) and FAILED on the real Android target, whose root is
        // read-only — so the test only ever ran where it did not matter. Measured on the AVD.
        let base = std::env::temp_dir().join("torta-centauri-object-test-logpath");
        let c = Centauri::new(base.to_string_lossy().into_owned());
        assert_eq!(c.log_path(), base.join("query-centauri.log"));
        // The exported String twin (D29) is the same path, FFI-shaped.
        assert_eq!(
            c.query_centauri_log_path(),
            c.log_path().to_string_lossy().into_owned()
        );
    }

    // ---- slice 2: install_catalog RETAINS the verified catalog (so the loopback can serve it) ----

    /// Build a genuinely-signed 1-entry `TCAT` catalog naming `name` at content address `hash` for `host`,
    /// returning the `(body, sig_blob, pubkey)` triple [`Centauri::install_catalog`] consumes — the SAME
    /// self-signed test signer the `server.rs` e2e tests use (no production key; the pubkey is passed to
    /// `parse_verified`). Replicates the `catalog.rs` wire layout exactly.
    fn signed_one_entry_catalog(
        name: &str,
        hash: [u8; 32],
        host: &str,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use ed25519_dalek::{Signer, SigningKey};
        const KEY_ID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut body = Vec::new();
        body.extend_from_slice(b"TCAT"); // magic
        body.extend_from_slice(&1u16.to_le_bytes()); // version = 1
        body.push(2u8); // hash_algo_id = BLAKE2B
        body.push(0u8); // header flags
        body.extend_from_slice(&0u64.to_le_bytes()); // reserved
        body.extend_from_slice(&1u32.to_le_bytes()); // entry_count = 1
        body.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        body.push(0b0000_0001u8); // entry_flags: CLOAK
        body.extend_from_slice(&hash); // content_hash[32]
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&(host.len() as u16).to_le_bytes());
        body.extend_from_slice(host.as_bytes());

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
        (body, sig_blob, pubkey)
    }

    #[test]
    fn install_catalog_retains_the_verified_catalog() {
        let c = Centauri::new("/tmp/torta-centauri-object-test-retain".to_string());
        // Pre-install: the retained catalog is the empty default (every name fail-closed 404).
        assert_eq!(
            c.catalog.lock().unwrap().len(),
            0,
            "empty catalog before install"
        );
        let (body, sig, pubkey) = signed_one_entry_catalog(
            "jquery/3.7.1/jquery.min.js",
            [7u8; 32],
            "ajax.googleapis.com",
        );
        c.install_catalog(body, sig, pubkey)
            .expect("a genuinely signed 1-entry catalog installs Ok");
        // RETENTION (slice 2): the verified catalog is RETAINED (was dropped on the floor pre-slice-2), so
        // start() threads it into the loopback server — the loopback actually SERVES it (content-addressed).
        assert_eq!(
            c.catalog.lock().unwrap().len(),
            1,
            "install_catalog RETAINS the verified catalog (the loopback serves it, not the empty default)"
        );
        let snap = c.snapshot();
        assert_eq!(
            snap.catalog_installs_verified, 1,
            "verified install tallied"
        );
    }

    // ---- the RETAIN seam: rehydrate_from_signed retains the boot-verified catalog (typed split) ----

    /// A fresh per-test temp dir (process-id + tag suffixed) — rehydrate tests write real `.tcat` pairs.
    fn rehydrate_dir(tag: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("torta-centauri-rehydrate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create rehydrate test dir");
        dir
    }

    #[test]
    fn rehydrate_from_signed_retains_the_verified_catalog() {
        // A genuine on-disk `.tcat`/`.sig` pair → rehydrate verifies AND RETAINS (the landed seam): the
        // boot-verified catalog becomes the serve authority without a fresh install/arming pass.
        let dir = rehydrate_dir("retain");
        let (body, sig, pubkey) = signed_one_entry_catalog(
            "jquery/3.7.1/jquery.min.js",
            [7u8; 32],
            "ajax.googleapis.com",
        );
        std::fs::write(dir.join("seed.tcat"), &body).expect("write .tcat");
        std::fs::write(dir.join("seed.tcat.sig"), &sig).expect("write .sig");
        let c = Centauri::new(dir.to_string_lossy().to_string());
        assert_eq!(c.catalog.lock().unwrap().len(), 0, "cold ⇒ empty catalog");

        c.rehydrate_from_signed("seed.tcat".to_string(), pubkey)
            .expect("a genuine durable pair rehydrates Ok");

        assert_eq!(
            c.catalog.lock().unwrap().len(),
            1,
            "rehydrate RETAINS the boot-verified catalog (the loopback would serve it after start)"
        );
        let snap = c.snapshot();
        assert_eq!(snap.catalog_assets, 1, "the snapshot witnesses the retained set");
        assert_eq!(snap.rehydrates_attempted, 1, "attempt tallied");
        assert_eq!(snap.rehydrates_verified, 1, "verified outcome tallied");
    }

    #[test]
    fn rehydrate_absent_pair_is_rehydrate_failed_typed() {
        // No pair on disk (cold start) ⇒ the typed AbsentPair mode ⇒ RehydrateFailed — NOT a signature
        // error (the operator can tell "no shipped catalog" from "catalog signature bad").
        let dir = rehydrate_dir("absent");
        let c = Centauri::new(dir.to_string_lossy().to_string());
        let err = c
            .rehydrate_from_signed("seed.tcat".to_string(), vec![0u8; 42])
            .expect_err("absent pair ⇒ Err");
        assert!(
            matches!(err, CentauriError::RehydrateFailed { .. }),
            "absent pair ⇒ RehydrateFailed, got {err:?}"
        );
        let snap = c.snapshot();
        assert_eq!(snap.rehydrates_attempted, 1, "attempt tallied");
        assert_eq!(snap.rehydrates_verified, 0, "no verified outcome");
        assert_eq!(snap.catalog_assets, 0, "nothing retained");
    }

    #[test]
    fn rehydrate_bad_signature_is_invalid_signature_and_never_clobbers_retained() {
        // A tampered durable body under a LIVE retained catalog: the typed BadSignature mode lifts to
        // InvalidSignature AND the retained serving set stays untouched (fail-safe — a bad durable read
        // never clobbers a live serve authority).
        let dir = rehydrate_dir("tamper");
        let (body, sig, pubkey) = signed_one_entry_catalog(
            "jquery/3.7.1/jquery.min.js",
            [7u8; 32],
            "ajax.googleapis.com",
        );
        let c = Centauri::new(dir.to_string_lossy().to_string());
        c.install_catalog(body.clone(), sig.clone(), pubkey.clone())
            .expect("live install Ok");
        assert_eq!(c.catalog.lock().unwrap().len(), 1, "live serving set retained");
        // Tamper ONE body byte on disk — the sig no longer verifies over these bytes.
        let mut tampered = body;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        std::fs::write(dir.join("seed.tcat"), &tampered).expect("write tampered .tcat");
        std::fs::write(dir.join("seed.tcat.sig"), &sig).expect("write .sig");

        let err = c
            .rehydrate_from_signed("seed.tcat".to_string(), pubkey)
            .expect_err("tampered body ⇒ Err");
        assert!(
            matches!(err, CentauriError::InvalidSignature { .. }),
            "tampered durable ⇒ InvalidSignature (the typed split), got {err:?}"
        );
        assert_eq!(
            c.catalog.lock().unwrap().len(),
            1,
            "the live retained catalog is NEVER clobbered by a failed rehydrate"
        );
    }

    #[test]
    fn rehydrate_malformed_signed_body_is_malformed_catalog() {
        // A genuinely SIGNED but non-TCAT body: the verify-sig-FIRST gate passes, the parse fails ⇒ the
        // typed Malformed mode ⇒ MalformedCatalog (a producer bug, distinguishable from a forgery).
        use ed25519_dalek::{Signer, SigningKey};
        let dir = rehydrate_dir("malformed");
        let body = b"definitely not a TCAT catalog".to_vec();
        const KEY_ID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let mut pubkey = Vec::with_capacity(42);
        pubkey.extend_from_slice(b"Ed");
        pubkey.extend_from_slice(&KEY_ID);
        pubkey.extend_from_slice(&sk.verifying_key().to_bytes());
        let mut sig_blob = Vec::with_capacity(74);
        sig_blob.extend_from_slice(b"Ed");
        sig_blob.extend_from_slice(&KEY_ID);
        sig_blob.extend_from_slice(&sk.sign(&body).to_bytes());
        std::fs::write(dir.join("seed.tcat"), &body).expect("write .tcat");
        std::fs::write(dir.join("seed.tcat.sig"), &sig_blob).expect("write .sig");

        let c = Centauri::new(dir.to_string_lossy().to_string());
        let err = c
            .rehydrate_from_signed("seed.tcat".to_string(), pubkey)
            .expect_err("signed garbage ⇒ Err");
        assert!(
            matches!(err, CentauriError::MalformedCatalog { .. }),
            "signed-but-unparseable ⇒ MalformedCatalog (the typed split), got {err:?}"
        );
        assert_eq!(c.snapshot().catalog_assets, 0, "nothing retained");
    }

    // ---- slice 5: the full UniFFI typed surface ----

    /// Build a serve record for the `record_serve` CROWN-counter tests (the clock is injected, not read).
    fn serve_record(
        now_ms: u64,
        outcome: CentauriServeOutcome,
        substitution: CentauriSubstitution,
        bytes: i64,
    ) -> CentauriServeRecord {
        CentauriServeRecord {
            now_ms,
            host: "cdnjs.cloudflare.com".to_string(),
            canonical_name: "jquery/3.7.1/jquery.min.js".to_string(),
            library: "jquery".to_string(),
            requested_version: "3.7.1".to_string(),
            served_version: "3.7.1".to_string(),
            substitution,
            outcome,
            bytes,
        }
    }

    #[test]
    fn new_enums_cross_their_internal_twins_both_ways() {
        // Substitution → CentauriSubstitution (the F3 verdict cross).
        assert_eq!(
            CentauriSubstitution::from(Substitution::Exact),
            CentauriSubstitution::Exact
        );
        assert_eq!(
            CentauriSubstitution::from(Substitution::SafeNewer),
            CentauriSubstitution::SafeNewer
        );
        assert_eq!(
            CentauriSubstitution::from(Substitution::RiskyOlder),
            CentauriSubstitution::RiskyOlder
        );
        assert_eq!(
            CentauriSubstitution::from(Substitution::Incompatible),
            CentauriSubstitution::Incompatible
        );
        // CacheMode ↔ CentauriCacheMode (the CROWN toggle cross, both directions).
        assert_eq!(
            CentauriCacheMode::from(CacheMode::LeakOnMiss),
            CentauriCacheMode::LeakOnMiss
        );
        assert_eq!(
            CentauriCacheMode::from(CacheMode::BlockMissing),
            CentauriCacheMode::BlockMissing
        );
        assert_eq!(
            CacheMode::from(CentauriCacheMode::BlockMissing),
            CacheMode::BlockMissing
        );
        assert_eq!(
            CacheMode::from(CentauriCacheMode::LeakOnMiss),
            CacheMode::LeakOnMiss
        );
        // ServeVerdict → CentauriServeOutcome (the CROWN outcome cross — the live loop's `.into()` seam).
        assert_eq!(
            CentauriServeOutcome::from(&ServeVerdict::ServedLocal(vec![1].into())),
            CentauriServeOutcome::ServedLocal
        );
        assert_eq!(
            CentauriServeOutcome::from(&ServeVerdict::LeakedThenServed(vec![1].into())),
            CentauriServeOutcome::LeakedThenServed
        );
        assert_eq!(
            CentauriServeOutcome::from(&ServeVerdict::BlockedMissing),
            CentauriServeOutcome::BlockedMissing
        );
        assert_eq!(
            CentauriServeOutcome::from(&ServeVerdict::NotInCatalog),
            CentauriServeOutcome::NotInCatalog
        );
        assert_eq!(
            CentauriServeOutcome::from(&ServeVerdict::FetchFailed),
            CentauriServeOutcome::FetchFailed
        );
        // The stable code/from_code round-trips (the atomic-storage contract).
        for st in [
            CentauriServeState::Stopped,
            CentauriServeState::Starting,
            CentauriServeState::Serving,
            CentauriServeState::Failed,
        ] {
            assert_eq!(CentauriServeState::from_code(st.code() as u8), st);
        }
        for m in [
            CentauriCacheMode::LeakOnMiss,
            CentauriCacheMode::BlockMissing,
        ] {
            assert_eq!(CentauriCacheMode::from_code(m.code()), m);
        }
    }

    #[test]
    fn cache_mode_toggle_is_live_in_method_and_snapshot() {
        let c = Centauri::new("/tmp/torta-centauri-object-test-mode".to_string());
        // Safe default: LeakOnMiss (the crown DISARMED — leak ≤ 1 on a miss).
        assert_eq!(c.cache_mode(), CentauriCacheMode::LeakOnMiss);
        assert_eq!(c.snapshot().cache_mode, CentauriCacheMode::LeakOnMiss);
        // Arm strict: the crown (serve-local-OR-nothing ⇒ CDN sees 0).
        c.set_cache_mode(CentauriCacheMode::BlockMissing);
        assert_eq!(c.cache_mode(), CentauriCacheMode::BlockMissing);
        assert_eq!(c.snapshot().cache_mode, CentauriCacheMode::BlockMissing);
    }

    #[test]
    fn centauri_resolution_from_carries_substitution_and_canonical_name() {
        // A version-fallback resolution (requested 3.6.2, served 3.7.1) crosses to the typed Record with the
        // SafeNewer verdict + the host-independent canonical name.
        let r = Resolution {
            library: "jquery".to_string(),
            requested_version: "3.6.2".to_string(),
            served_version: "3.7.1".to_string(),
            file: "jquery.min.js".to_string(),
            substitution: Substitution::SafeNewer,
        };
        let typed = CentauriResolution::from(r);
        assert_eq!(typed.library, "jquery");
        assert_eq!(typed.requested_version, "3.6.2");
        assert_eq!(typed.served_version, "3.7.1");
        assert_eq!(typed.file, "jquery.min.js");
        assert_eq!(typed.canonical_name, "jquery/3.7.1/jquery.min.js");
        assert_eq!(typed.substitution, CentauriSubstitution::SafeNewer);
    }

    #[test]
    fn resolve_cdn_typed_resolves_a_mapped_url_and_tallies() {
        let c = Centauri::new("/tmp/torta-centauri-object-test-typed".to_string());
        // Build a real CDN URL from the FIRST mapped library that bundles a version (robust against the exact
        // FULL_MAPS contents): host + base_path + a bundled version + a file ⇒ an Exact-or-fallback resolve.
        let map = crate::mirror::FULL_MAPS
            .iter()
            .find(|m| !m.bundled_versions.is_empty())
            .expect("FULL_MAPS has at least one mapped library");
        let version = map.bundled_versions[0];
        let path = format!("{}{}/lib.min.js", map.base_path, version);
        let typed = c
            .resolve_cdn_typed(map.host.to_string(), path)
            .expect("a bundled-version CDN URL resolves");
        assert!(
            !typed.canonical_name.is_empty(),
            "the typed resolution carries the canonical name"
        );
        // The query + the hit are tallied into the lived counters (same accounting as the flat resolve_cdn).
        let snap = c.snapshot();
        assert_eq!(snap.resolve_queries, 1);
        assert_eq!(snap.resolve_hits, 1);
        // An unmapped host ⇒ None, tallied as a query but not a hit.
        assert!(c
            .resolve_cdn_typed("not-a-cdn.example.invalid".to_string(), "/x.js".to_string())
            .is_none());
        let snap2 = c.snapshot();
        assert_eq!(snap2.resolve_queries, 2);
        assert_eq!(snap2.resolve_hits, 1);
    }

    #[test]
    fn record_serve_witnesses_the_crown_counters() {
        // THE F2 FIX, proven: a serve event in ⇒ the snapshot witnesses "served locally / CDN saw 0",
        // never asserted. ServedLocal(Exact) + LeakedThenServed(SafeNewer) + BlockedMissing.
        let c = Centauri::new("/tmp/torta-centauri-object-test-record".to_string());
        c.record_serve(serve_record(
            1,
            CentauriServeOutcome::ServedLocal,
            CentauriSubstitution::Exact,
            100,
        ));
        c.record_serve(serve_record(
            2,
            CentauriServeOutcome::LeakedThenServed,
            CentauriSubstitution::SafeNewer,
            200,
        ));
        c.record_serve(serve_record(
            3,
            CentauriServeOutcome::BlockedMissing,
            CentauriSubstitution::Exact,
            0,
        ));
        // NotInCatalog / FetchFailed serve nothing ⇒ no counter (but still ring).
        c.record_serve(serve_record(
            4,
            CentauriServeOutcome::NotInCatalog,
            CentauriSubstitution::Incompatible,
            0,
        ));
        let s = c.snapshot();
        assert_eq!(s.served_locally, 1, "one 0-egress local hit");
        assert_eq!(s.served_bytes, 100, "0-egress bytes (only the local hit)");
        assert_eq!(s.cdn_fetches, 1, "one ≤1 self-fill leak");
        assert_eq!(s.blocked_missing, 1, "one strict-mode block (CDN saw 0)");
        assert_eq!(s.exact_serves, 1, "ServedLocal(Exact)");
        assert_eq!(s.fallback_serves, 1, "LeakedThenServed(SafeNewer)");
    }

    #[test]
    fn recent_serves_is_bounded_and_newest_first() {
        let c = Centauri::new("/tmp/torta-centauri-object-test-recent".to_string());
        let total = RECENT_SERVES_CAP + 5;
        for i in 0..total {
            c.record_serve(serve_record(
                i as u64,
                CentauriServeOutcome::ServedLocal,
                CentauriSubstitution::Exact,
                1,
            ));
        }
        // Bounded at the cap (the oldest 5 were evicted).
        assert_eq!(c.recent_serves(10_000).len(), RECENT_SERVES_CAP);
        // Newest-first: the head is the last record pushed.
        let recent = c.recent_serves(10);
        assert_eq!(recent.len(), 10);
        assert_eq!(
            recent[0].now_ms,
            (total - 1) as u64,
            "head is the newest serve"
        );
        assert_eq!(
            recent[9].now_ms,
            (total - 10) as u64,
            "tail of the window is older"
        );
    }

    #[test]
    fn cache_stat_matches_the_snapshot_cache_fields() {
        let c = Centauri::new("/tmp/torta-centauri-object-test-stat".to_string());
        let cs = c.cache_stat();
        let s = c.snapshot();
        assert_eq!(cs.libraries, s.libraries);
        assert_eq!(cs.bytes, s.bytes);
        assert_eq!(cs.full, s.full);
        assert_eq!(cs.capacity, s.capacity);
    }

    // ---- D29/D26/D04 — the self-feeding observer, the foreign sink, the warm-up derivation ----

    /// A counting foreign-sink fake: proves the accept-loop observer pushes each record to the ONE bound
    /// reader (D26 — the Beast one-reader discipline) without a socket or a Kotlin runtime.
    struct CountingSink {
        seen: std::sync::Mutex<Vec<CentauriServeRecord>>,
    }
    impl CentauriServeSink for CountingSink {
        fn on_serve(&self, record: CentauriServeRecord) {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(record);
            }
        }
    }

    #[test]
    fn observer_feeds_ring_counters_log_and_sink_from_a_served_trace() {
        // The D29 wire, end-to-end without a socket: ONE traced accept-loop serve ⇒ the CROWN counters,
        // the recent ring, query-centauri.log, AND the bound foreign sink ALL witness it.
        let mut dir = std::env::temp_dir();
        dir.push(format!("torta-centauri-observer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let c = Centauri::new(dir.to_string_lossy().to_string());
        let sink = Arc::new(CountingSink {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        c.attach_serve_sink(sink.clone());
        let observer = c.serve_observer();

        // A CDN-URL serve (resolution carried) whose verdict is a zero-copy local hit.
        let bytes: Arc<[u8]> = b"// jQuery 3.7.1 served".to_vec().into();
        let resolution = Resolution {
            library: "jquery".to_string(),
            requested_version: "3.6.2".to_string(),
            served_version: "3.7.1".to_string(),
            file: "jquery.min.js".to_string(),
            substitution: Substitution::SafeNewer,
        };
        observer(mirror::server::ServeTrace {
            host: "ajax.googleapis.com",
            path: "/ajax/libs/jquery/3.6.2/jquery.min.js",
            resolution: Some(&resolution),
            outcome: &ServeOutcome::Served(Arc::clone(&bytes)),
        });

        // (1) the CROWN counters witnessed the live serve (self-feeding — no record_serve call).
        let snap = c.snapshot();
        assert_eq!(snap.served_locally, 1, "the live loop feeds the counters");
        assert_eq!(snap.served_bytes, bytes.len() as i64);
        assert_eq!(snap.fallback_serves, 1, "SafeNewer ⇒ the fallback split");
        // (1b) the serve-path resolve tally: a CDN-routed serve that MATCHED ⇒ one query + one hit — the
        // dashboard's resolve-hits tile now populates from the LIVE loopback, not just a direct resolve_cdn.
        assert_eq!(snap.resolve_queries, 1, "CDN-routed serve ⇒ one resolve query");
        assert_eq!(snap.resolve_hits, 1, "the serve resolved to a known library ⇒ one hit");
        // (2) the recent ring self-fed (the on-device recentServes is no longer empty-forever).
        let recent = c.recent_serves(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].canonical_name, "jquery/3.7.1/jquery.min.js");
        assert_eq!(recent[0].outcome, CentauriServeOutcome::ServedLocal);
        // (3) the durable review line landed.
        let body = std::fs::read_to_string(c.log_path()).expect("query-centauri.log written");
        assert!(
            body.contains("jquery/3.7.1/jquery.min.js"),
            "logged: {body}"
        );
        // (4) the foreign sink was pushed exactly once (D26).
        assert_eq!(sink.seen.lock().unwrap().len(), 1, "one push per serve");

        // A fail-closed 404 rings + logs but bumps NO counter; CacheMiss/fingerprinter traces are skipped.
        observer(mirror::server::ServeTrace {
            host: "",
            path: "/unknown.tblk",
            resolution: None,
            outcome: &ServeOutcome::NotInCatalog,
        });
        observer(mirror::server::ServeTrace {
            host: "",
            path: "/warming.tblk",
            resolution: None,
            outcome: &ServeOutcome::CacheMiss([0u8; 32]),
        });
        let snap2 = c.snapshot();
        assert_eq!(snap2.served_locally, 1, "404 bumps no crown counter");
        // A non-CDN `Host` (here empty) never routes through the resolve leg ⇒ the resolve tally is UNMOVED
        // (owned/path-keyed serves are not resolves — the honest split).
        assert_eq!(snap2.resolve_queries, 1, "non-CDN traces don't resolve");
        assert_eq!(snap2.resolve_hits, 1, "non-CDN traces don't hit");
        assert_eq!(
            c.recent_serves(10).len(),
            2,
            "404 ringed; CacheMiss skipped"
        );
        // Detach: the loop stops pushing (counters/ring keep self-feeding).
        c.detach_serve_sink();
        observer(mirror::server::ServeTrace {
            host: "",
            path: "/x.tblk",
            resolution: None,
            outcome: &ServeOutcome::NotInCatalog,
        });
        assert_eq!(sink.seen.lock().unwrap().len(), 2, "detached ⇒ no push");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn observer_resolve_tally_splits_hit_from_miss_and_ignores_owned() {
        // The serve-path resolve witness, three honest cases through ONE observer:
        //   (a) a watched CDN host + a MAPPED path         ⇒ query +1, hit +1
        //   (b) a watched CDN host + an UNMAPPED path      ⇒ query +1, hit +0 (resolved as a miss)
        //   (c) an owned / path-keyed serve (non-CDN host) ⇒ query +0, hit +0 (never a resolve)
        let mut dir = std::env::temp_dir();
        dir.push(format!("torta-centauri-resolve-tally-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let c = Centauri::new(dir.to_string_lossy().to_string());
        let observer = c.serve_observer();

        // (a) the MAPPED CDN serve — resolution carried (a real library match).
        let bytes: Arc<[u8]> = b"// jquery".to_vec().into();
        let resolution = Resolution {
            library: "jquery".to_string(),
            requested_version: "3.7.1".to_string(),
            served_version: "3.7.1".to_string(),
            file: "jquery.min.js".to_string(),
            substitution: Substitution::Exact,
        };
        observer(mirror::server::ServeTrace {
            host: "ajax.googleapis.com",
            path: "/ajax/libs/jquery/3.7.1/jquery.min.js",
            resolution: Some(&resolution),
            outcome: &ServeOutcome::Served(Arc::clone(&bytes)),
        });
        let s = c.snapshot();
        assert_eq!(s.resolve_queries, 1, "(a) mapped CDN serve ⇒ one query");
        assert_eq!(s.resolve_hits, 1, "(a) mapped ⇒ one hit");

        // (b) a watched CDN host but an UNMAPPED path ⇒ the router resolved to a miss (resolution None,
        // NotInCatalog). The query is still real; the hit is NOT.
        observer(mirror::server::ServeTrace {
            host: "ajax.googleapis.com",
            path: "/ajax/libs/no-such-lib/9.9.9/x.js",
            resolution: None,
            outcome: &ServeOutcome::NotInCatalog,
        });
        let s = c.snapshot();
        assert_eq!(s.resolve_queries, 2, "(b) unmapped CDN path still queries");
        assert_eq!(s.resolve_hits, 1, "(b) an unmapped path is a MISS, not a hit");
        // The miss is ringed with NO substitution verdict — never a phantom `Exact` the dashboard would
        // print beside a 404. `recent_serves` is newest-first, so [0] is this miss.
        let miss = c.recent_serves(10);
        assert_eq!(miss[0].outcome, CentauriServeOutcome::NotInCatalog);
        assert_eq!(
            miss[0].substitution,
            CentauriSubstitution::NotApplicable,
            "(b) a NotInCatalog miss served nothing ⇒ NotApplicable, not Exact"
        );

        // (c) an owned page (non-CDN Host) — the path-keyed serve NEVER routes through the resolve leg.
        let owned: Arc<[u8]> = b"<!doctype html>".to_vec().into();
        observer(mirror::server::ServeTrace {
            host: "torta.local",
            path: "/torta-offline/index.html",
            resolution: None,
            outcome: &ServeOutcome::Served(Arc::clone(&owned)),
        });
        let s = c.snapshot();
        assert_eq!(s.resolve_queries, 2, "(c) an owned serve is NOT a resolve");
        assert_eq!(s.resolve_hits, 1, "(c) owned ⇒ no new hit");
        // Sanity: the owned page DID serve locally (it is a real serve, just not a resolve).
        assert_eq!(s.served_locally, 2, "both Served traces fed the serve counter");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn warm_targets_derive_from_catalog_intersect_map() {
        // D04: a catalog naming a MAPPED asset yields one target with the real-CDN upstream URL; an
        // unmapped/unparseable entry is skipped (never a fabricated URL).
        let (body, sig, pubkey) = signed_one_entry_catalog(
            "jquery/3.7.1/jquery.min.js",
            [7u8; 32],
            "ajax.googleapis.com",
        );
        let catalog = Catalog::parse_verified(&body, &sig, &pubkey).expect("signed catalog");
        let targets = warm_targets(&catalog, 16);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "jquery/3.7.1/jquery.min.js");
        assert_eq!(
            targets[0].url, "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
            "the upstream URL is the entry's own CDN host + the mapped base path"
        );
        // ★ #22 slice 2 — the multi-CDN failover ladder: jquery rides many mapped hosts, so the
        // alternate cap BINDS; every rung is a real map coordinate for the SAME version/file on a
        // DISTINCT non-primary host (never a fabricated URL, never the primary again).
        assert_eq!(
            targets[0].alt_urls.len(),
            crate::mirror::MAX_ALT_UPSTREAMS,
            "a many-host library fills the ladder to the cap"
        );
        for alt in &targets[0].alt_urls {
            assert!(alt.starts_with("https://"), "ladder rung is https: {alt}");
            assert!(
                alt.ends_with("/3.7.1/jquery.min.js"),
                "ladder rung carries the SAME served version + file: {alt}"
            );
            assert!(
                !alt.contains("ajax.googleapis.com"),
                "the primary host never reappears as its own alternate: {alt}"
            );
        }
        let hosts: Vec<&str> = targets[0]
            .alt_urls
            .iter()
            .map(|u| u.split('/').nth(2).unwrap_or(""))
            .collect();
        let mut dedup = hosts.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(hosts.len(), dedup.len(), "ladder hosts are distinct: {hosts:?}");
        // The cap is honored.
        assert!(warm_targets(&catalog, 0).is_empty());
        // An empty catalog derives zero targets (the honest no-op batch).
        assert!(warm_targets(&Catalog::default(), 16).is_empty());
    }

    #[test]
    fn warm_up_with_no_catalog_is_a_zero_target_no_op() {
        // D04 honesty: no installed catalog ⇒ zero targets, zero egress, a zeroed report — never a crawl.
        let c = Centauri::new("/tmp/torta-centauri-object-test-warmup-cold".to_string());
        let report = c.warm_up(32);
        assert_eq!(report.targets, 0);
        assert_eq!(report.filled, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(c.snapshot().libraries, 0, "nothing fetched, nothing cached");
    }

    #[test]
    fn start_marks_serving_and_snapshot_reflects_it() {
        // The LIVE Starting→Serving wiring (the dead enum arms made real): a cold Object is Stopped, start()
        // binds an ephemeral loopback port and the snapshot reports Serving with the bound port.
        let c = Centauri::new("/tmp/torta-centauri-object-test-serving".to_string());
        assert_eq!(c.snapshot().serve_state, CentauriServeState::Stopped);
        let port = c
            .start()
            .expect("the loopback binds an ephemeral port on 127.0.0.1");
        assert!(port > 0, "a real bound port");
        let s = c.snapshot();
        assert_eq!(s.serve_state, CentauriServeState::Serving);
        assert_eq!(
            s.serve_port, port,
            "the snapshot reports the bound port (i32 — never an i16 wrap)"
        );
        // Idempotent: a second start returns the already-bound port.
        assert_eq!(c.start().expect("idempotent start"), port);
    }

    #[test]
    fn arm_device_catalog_seeds_owned_content_and_installs_a_device_signed_catalog() {
        // The sovereign-arming vertical slice (SURPASS nautilus Rungs 2+3, engine-native + durable): an
        // app-owned asset is hashed + admitted into the LIVE cache, this install's OWN device key authors +
        // signs a catalog over it (+ the growing cloak roster), and the Object installs it against its own
        // pubkey — end to end, reboot-proof, idempotent.
        use std::fs;
        let base = std::env::temp_dir().join("torta-centauri-arm-test");
        let content_dir = base.join("content");
        let key_dir = base.join("keys");
        let cache_dir = base.join("cache");
        // Clean any prior run so mint/reload + cache counts are deterministic.
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&content_dir).expect("mk content dir");

        // TWO shipped assets exercising BOTH manifest shapes:
        //   • an app-OWNED page (short form → host torta.local, uncloaked), and
        //   • a cloaked CDN LIBRARY named by its canonical CDN path (full form → real host, cloaked) —
        //     the SURPASS: the real bytes ship, so it serves 0-egress under the CDN name with NO fetch.
        let owned: &[u8] = b"<!doctype html><title>Torta offline</title><h1>served 0-egress</h1>";
        let lib: &[u8] = b"/*! curated CDN library bytes - served locally, the CDN never contacted */\n";
        fs::write(content_dir.join("index.html"), owned).expect("write owned asset");
        fs::write(content_dir.join("lib.min.js"), lib).expect("write lib asset");
        fs::write(
            content_dir.join("content.tsv"),
            "# app-owned seed content (short form) + a cloaked CDN library (full form)\n\
             torta-offline/index.html\tindex.html\n\
             demo-lib/1.0.0/demo.min.js\tcdn.example.org\t1\tlib.min.js\n",
        )
        .expect("write manifest");

        let c = Centauri::new(cache_dir.to_string_lossy().into_owned());
        let report = c.arm_device_catalog(
            content_dir.to_string_lossy().into_owned(),
            key_dir.to_string_lossy().into_owned(),
        );

        // First Boot minted a fresh authority + persisted its 32-byte seed for reboot reload.
        assert!(report.minted, "first arm mints a fresh device key");
        assert_eq!(report.key_id_hex.len(), 16, "16-char lower-hex key id");
        assert!(
            key_dir.join("device.key").exists(),
            "the secret seed is persisted (reboot-proof authority)"
        );

        // BOTH shipped assets were hashed + admitted into the LIVE shared cache — the honest libraries=2.
        assert_eq!(report.cached_assets, 2, "the owned page + the cloaked CDN library both admitted");
        assert_eq!(c.snapshot().libraries, 2, "the LIVE cache holds both shipped assets");

        // The GROWING cloak roster was authored (one entry per live CDN host) + the catalog installed.
        assert!(report.cloak_hosts > 0, "the live cdn_hosts roster is non-empty");
        assert_eq!(
            report.catalog_entries,
            report.cached_assets + report.cloak_hosts,
            "every owned row + every cloak row is in the authored catalog"
        );
        assert!(
            report.installed,
            "the device-signed catalog verifies against its OWN pubkey + installs"
        );
        assert!(
            c.snapshot().catalog_assets >= 1,
            "the installed catalog is retained for the serve path"
        );
        // ★ #22 slice 2 — the device-signed catalog is TCAT v2: arming stamped the signing moment
        // as the freshness epoch, and the snapshot SURFACES it (a sane bound, not a wall-clock
        // threshold: any real clock is far past 2020 = 1_577_836_800).
        assert!(
            c.snapshot().catalog_authored_at_secs > 1_577_836_800,
            "arming stamps the TCAT v2 freshness epoch into the retained catalog, got {}",
            c.snapshot().catalog_authored_at_secs
        );

        // Reboot-proof + idempotent: a fresh Object over the SAME dirs rehydrates the owned asset from disk
        // (ctor load_from_disk), reloads the SAME device authority (minted=false), and re-installs an
        // identical catalog.
        let c2 = Centauri::new(cache_dir.to_string_lossy().into_owned());
        assert_eq!(
            c2.snapshot().libraries,
            2,
            "the ctor rehydrated BOTH transplanted assets from the content-addressed NAND cache (RAM←NAND)"
        );
        let report2 = c2.arm_device_catalog(
            content_dir.to_string_lossy().into_owned(),
            key_dir.to_string_lossy().into_owned(),
        );
        assert!(
            !report2.minted,
            "the persisted seed reloaded — same authority, no re-mint across reboot"
        );
        assert_eq!(
            report2.key_id_hex, report.key_id_hex,
            "the same device identity across reboot"
        );
        assert_eq!(
            report2.cached_assets, 2,
            "idempotent re-admit of the identical shipped bytes"
        );
        assert!(report2.installed);

        // 3c — the RAM⊗NAND half: the arming pass PERSISTED its own device-signed pair (the pillar
        // authors the durable artifact itself; no host-side producer exists on a phone).
        assert!(report.persisted, "the device-signed pair persisted to the cache dir");
        assert!(report2.persisted, "re-arm re-persists (overwrite of an identical authority)");
        assert!(
            cache_dir.join(DEVICE_CATALOG_BASE).is_file(),
            "device-catalog.tcat exists in the durable cache dir"
        );
        assert!(
            cache_dir
                .join(format!("{DEVICE_CATALOG_BASE}{}", crate::SIGNED_SIG_SUFFIX))
                .is_file(),
            "the .sig sidecar exists beside it"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn sovereign_loop_arm_persists_then_reboot_rehydrates_by_device_key() {
        // THE CLOSED SOVEREIGNTY LOOP (the #4 re-open): generate → device-sign → persist (RAM⊗NAND)
        // → reboot → rehydrate the pair against the DEVICE's OWN key — no host artifact, no pinned
        // build key, no content re-hash. The lane the study found unwritten, now written.
        use std::fs;
        let base = std::env::temp_dir().join("torta-centauri-sovereign-loop-test");
        let content_dir = base.join("content");
        let key_dir = base.join("keys");
        let cache_dir = base.join("cache");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&content_dir).expect("mk content dir");
        fs::write(content_dir.join("page.html"), b"<h1>sovereign</h1>").expect("write asset");
        fs::write(
            content_dir.join("content.tsv"),
            "torta-offline/page.html\tpage.html\n",
        )
        .expect("write manifest");

        // Boot 1: arm → author + install + PERSIST.
        let c = Centauri::new(cache_dir.to_string_lossy().into_owned());
        let report = c.arm_device_catalog(
            content_dir.to_string_lossy().into_owned(),
            key_dir.to_string_lossy().into_owned(),
        );
        assert!(report.installed && report.persisted, "boot 1 authors + persists");

        // Boot 2 (the fast lane): a FRESH Object rehydrates the persisted pair against the device
        // key alone — content_dir untouched, no re-hash, the catalog RETAINS as serve authority.
        let c2 = Centauri::new(cache_dir.to_string_lossy().into_owned());
        assert_eq!(
            c2.snapshot().catalog_assets,
            0,
            "before rehydrate the fresh Object holds no catalog"
        );
        c2.rehydrate_device_catalog(key_dir.to_string_lossy().into_owned())
            .expect("the device-authored pair verifies against the device's own key");
        assert!(
            c2.snapshot().catalog_assets >= 1,
            "the rehydrated catalog RETAINS as the serve authority"
        );

        // A WRONG key dir (a different device identity) must NOT verify the pair — the sovereignty
        // law's teeth: only THIS device's authority rehydrates its artifact.
        let c3 = Centauri::new(cache_dir.to_string_lossy().into_owned());
        let wrong_keys = base.join("wrong-keys");
        let err = c3
            .rehydrate_device_catalog(wrong_keys.to_string_lossy().into_owned())
            .expect_err("a foreign device key must not verify this device's pair");
        assert!(
            matches!(err, CentauriError::InvalidSignature { .. }),
            "typed as InvalidSignature, got: {err:?}"
        );

        // Tamper teeth: flip a byte in the persisted body ⇒ typed InvalidSignature, retained
        // catalog untouched (fail-safe).
        let tcat_path = cache_dir.join(DEVICE_CATALOG_BASE);
        let mut body = fs::read(&tcat_path).expect("read persisted body");
        let last = body.len() - 1;
        body[last] ^= 0xFF;
        fs::write(&tcat_path, &body).expect("write tampered body");
        let err = c2
            .rehydrate_device_catalog(key_dir.to_string_lossy().into_owned())
            .expect_err("a tampered body must not verify");
        assert!(
            matches!(err, CentauriError::InvalidSignature { .. }),
            "typed as InvalidSignature, got: {err:?}"
        );
        assert!(
            c2.snapshot().catalog_assets >= 1,
            "the previously retained catalog survives the failed rehydrate (fail-safe)"
        );

        let _ = fs::remove_dir_all(&base);
    }
}

#[cfg(all(test, feature = "mirror"))]
mod recent_ring_cap_tests {
    use super::*;

    fn rec(i: u64) -> CentauriServeRecord {
        CentauriServeRecord {
            now_ms: i,
            host: format!("cdn-{i}.example"),
            canonical_name: format!("lib/1.0.0/f{i}.js"),
            library: "lib".to_string(),
            requested_version: "1.0.0".to_string(),
            served_version: "1.0.0".to_string(),
            substitution: CentauriSubstitution::Exact,
            outcome: CentauriServeOutcome::ServedLocal,
            bytes: 1,
        }
    }

    /// A5 GUARD -- `MAX_MANIFEST_ROWS` (= 512, object.rs:1763) caps the curated seed manifest so a
    /// corrupt or hostile `content.tsv` can never balloon the arming batch. The A5 inventory found
    /// it had a NUMBER and no test naming it.
    ///
    /// Three arms. The cap alone is not the interesting property: the loop counts only rows it
    /// ACCEPTED, and `continue`s past malformed ones without counting. So a file of 2x the cap in
    /// junk lines followed by real rows must still yield real rows -- a cap that counted skipped
    /// lines would silently truncate a valid manifest that merely had comments at the top.
    #[test]
    fn max_manifest_rows_caps_accepted_rows_not_skipped_lines() {
        let dir = std::env::temp_dir().join("torta-manifest-cap");
        let _ = std::fs::create_dir_all(&dir);

        // (a) far more valid rows than the cap -> exactly the cap, and the FIRST rows survive.
        let mut tsv = String::new();
        for i in 0..(512 * 3) {
            tsv.push_str(&format!("name{i:05}	cdn.example	1	f{i:05}.js
"));
        }
        std::fs::write(dir.join("content.tsv"), &tsv).expect("write");
        let rows = read_content_manifest(&dir);
        assert_eq!(rows.len(), 512, "the manifest must saturate AT the cap");
        assert_eq!(
            rows.first().map(|r| r.name.as_str()),
            Some("name00000"),
            "the cap keeps the FIRST rows -- it breaks out, it does not resample"
        );

        // (b) comments and malformed lines are SKIPPED, not counted against the cap.
        let mut tsv2 = String::new();
        for i in 0..1200 {
            tsv2.push_str(&format!("# comment {i}
"));
            tsv2.push_str("junk-with-no-tabs
");
        }
        tsv2.push_str("real	cdn.example	1	real.js
");
        std::fs::write(dir.join("content.tsv"), &tsv2).expect("write");
        let rows2 = read_content_manifest(&dir);
        assert_eq!(
            rows2.len(),
            1,
            "skipped lines must NOT consume the row budget -- a commented manifest still parses"
        );
        assert_eq!(rows2[0].name, "real");

        // (c) the short form is accepted and defaults to the owned host.
        std::fs::write(dir.join("content.tsv"), "page	index.html
").expect("write");
        let rows3 = read_content_manifest(&dir);
        assert_eq!(rows3.len(), 1);
        assert_eq!(rows3[0].host, "torta.local");
        assert!(!rows3[0].cloaked);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A5 GUARD -- `RECENT_SERVES_CAP` (= 64) bounds the in-Object ring of recent serve events.
    /// The A5 inventory found it had a NUMBER and no test naming it: an unbounded ring fed by
    /// every serve is a memory leak proportional to traffic.
    ///
    /// Three arms, because length alone cannot see the two ways this breaks: the ring must
    /// saturate AT the cap, it must retain the NEWEST events (dropping the oldest, not the
    /// newest), and `recent_serves` must hand them back newest-FIRST as its doc claims.
    #[test]
    fn recent_serves_cap_is_64_and_the_breach_is_loud() {
        let dir = std::env::temp_dir().join("torta-centauri-ringcap");
        let c = Centauri::new(dir.to_string_lossy().to_string());
        let n = (RECENT_SERVES_CAP * 3) as u64;
        for i in 0..n {
            c.record_serve(rec(i));
        }

        let all = c.recent_serves(u32::MAX);
        assert_eq!(
            all.len(),
            RECENT_SERVES_CAP,
            "the ring must saturate AT the cap, never above it"
        );
        assert_eq!(
            all.first().map(|r| r.now_ms),
            Some(n - 1),
            "recent_serves is newest-FIRST -- the freshest serve leads"
        );
        assert_eq!(
            all.last().map(|r| r.now_ms),
            Some(n - RECENT_SERVES_CAP as u64),
            "the ring dropped the OLDEST events, not the newest"
        );
    }
}
