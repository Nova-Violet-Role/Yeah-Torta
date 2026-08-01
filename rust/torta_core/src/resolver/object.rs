/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! THE MASKSOLVER OBJECT — Slice 1 of the MaskSolver overhaul (the Resolver&Cache pillar's `#[derive(
//! uniffi::Object)]` lift). MaskSolver is the Genesis-named façade over the mature in-app resolver engine
//! (the SOLVE form — resolves resiliently — crossed with the CACHE form on RAM⊗NAND). Kotlin constructs a
//! single `Arc<MaskSolver>`, holds the handle, drives [`MaskSolver::resolve`]/[`configure`], and pulls a
//! typed [`MaskSolverSnapshot`] for the dashboard — replacing the hand-parsed `resolver_stats()` JSON
//! string with a full-power UniFFI Record.
//!
//! ## THE NO-FORK LAW (the cardinal design constraint — F1)
//! The Warden/Centauri Objects OWN their engine (`Mutex<Engine>` inside the Object). **MaskSolver
//! CANNOT copy that.** The resolver is a process-global `static RESOLVER: OnceLock<Resolver>` (`mod.rs`)
//! carrying the tokio runtime the LIVE `resolve()` datapath runs on. If MaskSolver held its own
//! `Mutex<Resolver>` there would be TWO engines — the flat `resolver_resolve` C-ABI datapath using
//! `RESOLVER`, the Object using its own — so the dashboard would read dead metrics while traffic flowed
//! through the other engine, plus a double-`configure` racing two runtimes.
//!
//! So `MaskSolver` is a **thin, engine-less delegating handle**. It owns ZERO resolver state — only its own
//! bound app-private durable dir (config for the cache/rotation persist target). Every engine op delegates
//! to the existing `resolver::*` free functions, which already lock the ONE `Resolver::global()`. Holding a
//! dir String is Object-local config, NEVER a second engine.
//!
//! ## The QUARTET surface (the Warden template — the NON-gated, ALWAYS-BUILT form)
//!   1. `#[derive(uniffi::Object)] pub struct MaskSolver` — interior state is `Mutex<Option<String>>` (the
//!      bound durable dir), NOT a resolver.
//!   2. `#[uniffi::constructor]` — [`new`](MaskSolver::new) (cold handle, binds the already-inited global)
//!      + the fallible [`with_upstreams`](MaskSolver::with_upstreams) (configure-then-handle).
//!   3. `#[uniffi::export] impl` — `&self` methods, each panic-firewalled, each delegating to a
//!      `resolver::*` free-fn (never re-implementing the exchange — so the runtime guard the QUIC transports
//!      need is never bypassed).
//!   4. `#[derive(uniffi::Record)]` typed twins — [`MaskSolverSnapshot`] (replaces the `resolver_stats()`
//!      String), [`MaskSolverCacheStats`], [`MaskSolverSolveState`], [`MaskSolverTransport`],
//!      [`MaskSolverRotation`] — every field a REAL read of the live engine, never faked.
//!   5. `#[derive(uniffi::Error)]` [`MaskSolverError`] — the typed control-plane failure surface (the
//!      `ConfigError` template).
//!
//! ## NO-BREAK CONTRACT (capabilities-intact — the live datapath cannot regress)
//! The flat `resolver_*` exports (`lib.rs`) + the `udp.c` inline bridge STAY LIVE and unchanged. They call
//! the SAME `resolver::*` free-fns MaskSolver wraps. The Object is a NEW surface OVER the engine, never a
//! rewrite of it. `stats()` (the JSON string) is preserved byte-identical — MaskSolver's [`snapshot`] is a
//! SECOND renderer over the identical atomics (the single-source proof, no parallel counter).
//!
//! ## Panic firewall (fail-open across FFI)
//! Every method carries its OWN `catch_unwind(AssertUnwindSafe(...))` → a safe default; a panic NEVER
//! crosses the FFI boundary (a panic across UniFFI is UB). A snapshot panic falls to an all-zero honest
//! "off"; a `resolve` panic falls to `None` (the datapath's "fall through to dnscrypt-proxy" contract).
//!
//! ## Unsafe posture
//! `#![forbid(unsafe_code)]` (module-inner). ring-free, allocation-light (the reads are the existing
//! pure-Rust atomics + a small durable rotation read).

#![forbid(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::rotation::RotationState;

// ===========================================================================================
// Typed Error (the UniFFI-bridged failure-reason surface — the ConfigError template)
// ===========================================================================================

/// WHY a MaskSolver control-plane op FAILED — the typed, UniFFI-bridged failure surface. Replaces a lossy
/// `null`/empty return with a `Result<_, MaskSolverError>` so Kotlin can `try/catch` an ACTIONABLE reason.
/// `#[non_exhaustive]` so a future failure mode is additive without breaking the Kotlin binding. UniFFI
/// auto-derives `Display` from the variant name + the `reason` field via `thiserror`.
///
/// NOTE: [`resolve`](MaskSolver::resolve) is deliberately NOT fallible — a resolution MISS is normal DNS
/// data (`None` ⇒ the datapath falls through to dnscrypt-proxy), never an FFI error. This typed error is
/// for the CONTROL plane (configure / persist / rehydrate).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum MaskSolverError {
    /// `configure` parsed the spec to ZERO usable upstreams — no transport could be built.
    #[error("no usable upstream in the configure spec: {reason}")]
    NoUpstreams { reason: String },

    /// A persist/rehydrate op needs a bound app-private durable dir but none was bound — call
    /// [`bind_durable`](MaskSolver::bind_durable) first.
    #[error("no durable dir bound: {reason}")]
    NotBound { reason: String },

    /// A panic inside the bridge — the `catch_unwind` firewall caught a bug and reports it as a typed
    /// error, never an abort across the FFI boundary. Never expected (the bridge is panic-free); kept so
    /// the contract is total.
    #[error("panic in the MaskSolver bridge: {reason}")]
    Panic { reason: String },
}

// ===========================================================================================
// Records (the UniFFI-bridged typed status surface — the full-power law: NEVER a flat string)
// ===========================================================================================

/// THE headline surface — the dashboard's one-glance MaskSolver status, the typed Record that REPLACES the
/// hand-parsed `resolver_stats()` JSON string. Every field is a REAL read of the SAME live `Stats` atomics
/// the flat `stats()` renders (the single-source proof: no parallel counter). All counts are `i64`
/// (UniFFI → Kotlin `Long`); the two derived RATES are computed in Rust (never in the UI) and GUARDED
/// against `queries == 0` (never a NaN). T20: COUNTS + rates only — never a qname / client-IP.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MaskSolverSnapshot {
    /// `true` once a pool is installed (an upstream set is configured).
    pub configured: bool,
    /// Live transport (upstream) count in the pool.
    pub transports: i64,
    /// Live cache entries (the RAM hot tier).
    pub cache_entries: i64,

    // ── the DERIVED metrics the cross adds (the dashboard headline) — Rust-computed, zero-guarded ──
    /// `cache_hits / queries`, in `[0.0, 1.0]`. GUARDED: `queries == 0` ⇒ `0.0` (never NaN).
    pub cache_hit_rate: f64,
    /// `answered / queries`, in `[0.0, 1.0]` — the SOLVE-form success rate. GUARDED: `queries == 0` ⇒ `0.0`.
    pub solve_success_rate: f64,

    // ── the raw counters (the same fields `stats()` renders) ──
    pub queries: i64,
    pub blocked: i64,
    pub cache_hits: i64,
    pub answered: i64,
    pub rejected: i64,
    /// The SOLVE-cross witness — the ladder exhausted (no transport answered) count.
    pub transport_miss: i64,
    pub panics: i64,

    // ── the CACHE-cross + rebind witnesses ──
    pub rebind_observed: i64,
    pub rebind_rejected: i64,
    /// (C-2) IDN look-alike query names SEEN — observe-by-default, counted even with the gate off.
    pub homograph_observed: i64,
    /// (C-2) IDN look-alike queries DENIED (NXDOMAIN, zero egress). Always `<= homograph_observed`.
    pub homograph_rejected: i64,
    /// RFC 8767 serve-stale — an expired-but-served cache entry answered while a refresh was due.
    pub serve_stale_served: i64,
    /// Live negative (NXDOMAIN/NODATA) cache entry gauge.
    pub neg_cache: i64,

    // ── the dnsmasq-completion + sovereign-rewire telemetry (honest ZERO until each feature is wired) ──
    /// BLOCKLIST sinkhole/redirect answers — **not** the Centauri cloak.
    ///
    /// Incremented only for `BlockAction::ZeroSink` (0.0.0.0 / ::) and `BlockAction::CustomIp` with a
    /// matching qtype family (`resolver/mod.rs:1993`, `:1997`, `:2010`). The DEFAULT block action is
    /// `NxDomain`, which deliberately takes NO cloak count — so this reads 0 whenever blocking is
    /// unarmed or every verdict is a plain NXDOMAIN, and that zero is CORRECT.
    ///
    /// ★ MISREAD ONCE (2026-07-26), so it is documented here. A live snapshot showed
    /// `"cloak_actions":0` beside `"centauri_cloak_sinkholes":8` and I filed it as a dead panel metric.
    /// It is not: the two count DIFFERENT events. `centauri_cloak_sinkholes` is the P9 Centauri
    /// DNS-plane cloak (`local::synth_loopback_answer`); this one is the blocklist's sink/redirect. The
    /// same snapshot read `"blocked":0`, which makes 0 here exactly right. The name is the trap — "cloak"
    /// reads as Centauri to anyone who has been in `mirror/`. Panels binding a "cloak" tile want
    /// `centauri_cloak_sinkholes`; this field belongs to a BLOCKLIST tile.
    pub cloak_actions: i64,
    pub local_record_hits: i64,
    pub bogus_priv_stops: i64,
    pub never_forward_stops: i64,
    pub filter_rr_drops: i64,
    pub ad_bit_pass_through: i64,
    pub dns64_synth: i64,
    pub centauri_cloak_sinkholes: i64,
}

/// The focused cache slice for the dashboard cache-card — the CACHE-cross witnesses in one glance.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MaskSolverCacheStats {
    pub entries: i64,
    pub hits: i64,
    /// `hits / queries`, GUARDED against `queries == 0`.
    pub hit_rate: f64,
    pub serve_stale_served: i64,
    pub neg_cache: i64,
}

/// The per-upstream health twin of `pool::TransportStats` (R7 RTT/loss EWMA) — the SOLVE-form felt-truth.
/// T20: the stable transport id label only, never an upstream url/host.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MaskSolverTransport {
    /// The stable transport id (`Transport::id()`) — a label, never PII.
    pub id: String,
    /// Smoothed RTT in ms; `None` until the first reply (UniFFI → Kotlin `Double?`).
    pub rtt_ms_ewma: Option<f64>,
    /// Smoothed loss fraction in `[0.0, 1.0]`.
    pub loss_ewma: f64,
    /// Total exchanges attempted against this transport.
    pub samples: i64,
}

/// The rotation cursor twin of `rotation::RotationState` — the diversity state. Sourced from the
/// LAST-PERSISTED durable record (torta_core holds no live in-RAM rotation; the Kotlin `RotationManager`
/// owns the in-flight cursor + persists it). So this is the last-persisted cursor, NOT an in-flight flip;
/// an UNBOUND MaskSolver reads a cold zero (the honest baseline).
#[derive(Debug, Clone, uniffi::Record)]
pub struct MaskSolverRotation {
    pub last_family: String,
    pub cadence_secs: i64,
    pub rotation_index: i64,
    /// Warm RTT-hint count carried across a reboot (a COUNT — never an id/rtt pair, T20).
    pub hint_count: i64,
}

/// One warm RTT hint — the typed twin of a `rotation::RotationState.rtt_hints` entry (a `(String, u32)`
/// pair). UniFFI cannot bridge a bare tuple, so the warm-RTT leaderboard crosses the FFI as a
/// `Vec<RttHint>` (the full-power law: a typed LIST, never a flat string / a bare count). T20: `id` is the
/// stable transport LABEL (`Transport::id()`) — never an upstream url/host/qname; `rtt_ms` is the last-known
/// RTT carried across a reboot (`u32` widened to the UniFFI `i64` / Kotlin `Long`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct RttHint {
    /// The stable transport id label — a warm-RTT key, never PII (T20).
    pub id: String,
    /// The last-known warm RTT in ms (the durable hint), widened to `i64` for the Kotlin `Long`.
    pub rtt_ms: i64,
}

/// THE ROTATION PILLAR headline — the FULL-power typed surface for the DEDICATED Rotation dashboard (the
/// live wheel + cadence dial + warm-RTT leaderboard). The full-power twin of the flat
/// `rehydrate_resolver_rotation` summary string (`"family=… cadence=… index=… hints=<n>"`, `lib.rs`): every
/// field a typed value, and the warm-RTT hints a typed LIST — not the bare [`MaskSolverRotation::hint_count`]
/// the compact embedded twin carries. Sourced from the LAST-PERSISTED durable [`rotation::RotationState`] via
/// a control-plane READ ([`rotation::RotationState::rehydrate_opt`]) — NEVER the resolve hot path; an UNBOUND
/// handle / a cold boot / a fault reads the honest cold zero.
///
/// This is a SECOND, richer READ granularity BESIDE the compact [`MaskSolverRotation`] (which stays the
/// embedded `MaskSolverSolveState.rotation` strip) — the SAME multi-granularity pattern this file already
/// uses ([`MaskSolverSnapshot`] headline vs [`MaskSolverCacheStats`] slice vs [`MaskSolverSolveState`]). It
/// does NOT replace or fork the compact twin.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RotationSnapshot {
    /// The operator family selected at the last flip (`rotation::RotationState.last_family`), or `""` cold.
    pub last_family: String,
    /// The durable rotation cadence in seconds — a REFLECTION of the Kotlin cadence pref persisted on the
    /// last flip (the live timer's authority is the pref, not this; a reboot shows the last-persisted value).
    pub cadence_secs: i64,
    /// The last rotation index — the diversity cursor + the `RotationSelector` shuffle seed; resumes WHERE it
    /// left off across a reboot (never re-lands at 0).
    pub rotation_index: i64,
    /// Seconds until the next scheduled flip. torta_core holds NO live clock and persists no flip timestamp
    /// (the no-fork / clock-free law — the same reason `resolve_logged` takes an INJECTED `now_ms`), so the
    /// DURABLE read reports `0` here; the Kotlin host computes the live countdown from its rotation timer
    /// (`cadence − elapsedSinceLastFlip`) and pushes it onto the SLINT `next-flip-secs` in-out. An honest
    /// host-filled field — the SAME posture as this file's "honest ZERO until wired" counters.
    pub next_flip_secs: i64,
    /// The warm-RTT leaderboard — the FULL typed hint list (bounded to `rotation::MAX_RTT_HINTS = 64`), the
    /// full-power replacement for the compact [`MaskSolverRotation::hint_count`]. Empty when cold / no feed.
    pub rtt_hints: Vec<RttHint>,
    /// `true` when a real durable record was resumed at boot (a WARM start), `false` on a cold start (no
    /// record / a corrupt read / an unbound handle). The dashboard's "resumed warm" badge — the #98 crown
    /// witness (a rebooted phone kept its rotation schedule instead of restarting cold at family 0).
    pub rehydrated_warm: bool,
}

/// The active resolution STRATEGY — the SOLVE-form failover mode, the typed UniFFI twin of the internal
/// `pool::Strategy`. Surfaced so the dashboard shows WHICH mode is resolving. `StrictOrder` = the sequential
/// first-Ok ladder (the base `.so` default); `AllServers` = the `--all-servers` concurrent happy-eyeballs
/// race; `Fastest` = the health-ordered mode the SOLVE resilient ladder realizes (ordered by the per-
/// transport RTT/loss EWMA). A REAL read of the live Expert toggles (`pool::active_strategy`) — never faked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MaskSolverStrategy {
    /// The sequential first-Ok-wins ladder — the only behaviour the base `.so` ships.
    StrictOrder,
    /// The `--all-servers` concurrent happy-eyeballs race (first Ok wins).
    AllServers,
    /// The health-ordered resilient mode the SOLVE ladder realizes (RTT/loss EWMA ordering).
    Fastest,
}

/// The SOLVE-form surface — per-upstream health + the rotation cursor + the per-query deadline + the active
/// strategy + the SOLVE-cross resilience counters. The typed home of the slice-2 SOLVE telemetry the flat
/// `resolver_stats()` JSON string carried untyped.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MaskSolverSolveState {
    pub transports: Vec<MaskSolverTransport>,
    pub rotation: MaskSolverRotation,
    pub timeout_ms: i64,
    /// The ladder-exhaustion tally (the SOLVE-cross witness).
    pub transport_miss: i64,
    /// The standing egress resolution mode for an un-pinned query (a live toggle read).
    pub strategy: MaskSolverStrategy,

    // ── the SOLVE-cross resilience witnesses (slice 2 telemetry). Honest ZERO until the SOLVE_LADDER Expert
    //    toggle arms the ladder. T20: COUNTS only — never a qname/IP. ──
    /// Queries where the verdict-gated ladder advanced PAST its first upstream (a soft-fail retry).
    pub solve_retries: i64,
    /// Per-leg RETRYABLE soft-fails (SERVFAIL/REFUSED/TC/timeout/malformed) the ladder skipped past.
    pub solve_soft_fails: i64,
    /// Authoritative NEGATIVES (NXDOMAIN) classified TERMINAL — the ladder stopped (the neg-cache feed).
    pub solve_hard_negatives: i64,
    /// Times the WHOLE ordered ladder exhausted with only soft-fails (a resilient miss).
    pub solve_ladder_exhausted: i64,
    /// Times the health ranking PROMOTED a non-configured-first upstream to the ladder head.
    pub solve_upstream_promotions: i64,
}

// ===========================================================================================
// Small helpers (rate guard + honest-off defaults)
// ===========================================================================================

/// A GUARDED rate — `num / den` as `f64`, or `0.0` when `den == 0` (never a NaN divide-by-zero, F2). Both
/// inputs are counts with `num <= den` for the rates we surface (`cache_hits`/`answered` ≤ `queries`), so
/// the result stays in `[0.0, 1.0]`.
fn rate(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

/// The all-zero snapshot — the honest "off" a poisoned lock / panic falls to.
fn zero_snapshot() -> MaskSolverSnapshot {
    MaskSolverSnapshot {
        configured: false,
        transports: 0,
        cache_entries: 0,
        cache_hit_rate: 0.0,
        solve_success_rate: 0.0,
        queries: 0,
        blocked: 0,
        cache_hits: 0,
        answered: 0,
        rejected: 0,
        transport_miss: 0,
        panics: 0,
        rebind_observed: 0,
        rebind_rejected: 0,
        homograph_observed: 0,
        homograph_rejected: 0,
        serve_stale_served: 0,
        neg_cache: 0,
        cloak_actions: 0,
        local_record_hits: 0,
        bogus_priv_stops: 0,
        never_forward_stops: 0,
        filter_rr_drops: 0,
        ad_bit_pass_through: 0,
        dns64_synth: 0,
        centauri_cloak_sinkholes: 0,
    }
}

/// The cold rotation cursor — the honest baseline for an unbound handle / a fault.
fn cold_rotation() -> MaskSolverRotation {
    MaskSolverRotation {
        last_family: String::new(),
        cadence_secs: 0,
        rotation_index: 0,
        hint_count: 0,
    }
}

/// The cold [`RotationSnapshot`] — the honest baseline for an UNBOUND handle / a cold boot / a fault (no
/// durable record found). `rehydrated_warm: false` is the load-bearing signal (a cold start, NOT a warm
/// resume); the warm-RTT list is empty; `next_flip_secs` is 0 (the host-filled live value).
fn cold_rotation_snapshot() -> RotationSnapshot {
    RotationSnapshot {
        last_family: String::new(),
        cadence_secs: 0,
        rotation_index: 0,
        next_flip_secs: 0,
        rtt_hints: Vec::new(),
        rehydrated_warm: false,
    }
}

/// Map the internal `pool::Strategy` to its typed UniFFI twin ([`MaskSolverStrategy`]). An exhaustive match
/// inside a fn body — the internal engine type NEVER leaks into a public signature.
fn map_strategy(s: super::pool::Strategy) -> MaskSolverStrategy {
    match s {
        super::pool::Strategy::StrictOrder => MaskSolverStrategy::StrictOrder,
        super::pool::Strategy::AllServers => MaskSolverStrategy::AllServers,
        super::pool::Strategy::Fastest => MaskSolverStrategy::Fastest,
        // RoundRobin is a Nautilus (host) egress mode — no `.kt` toggle sets it, so on Android
        // `active_strategy()` never returns it and this arm is unreachable there. Map to its closest
        // typed twin `AllServers` (both spread the stream across EVERY server) rather than add a new
        // `MaskSolverStrategy` variant, which would drift the read-only Android UniFFI binding.
        super::pool::Strategy::RoundRobin => MaskSolverStrategy::AllServers,
    }
}

// ===========================================================================================
// THE MASKSOLVER OBJECT
// ===========================================================================================

/// THE MASKSOLVER — the Genesis-named façade over the mature resolver engine. Kotlin constructs it ONCE,
/// holds the `Arc`, then drives resolve/configure/the Expert toggles and pulls a [`MaskSolverSnapshot`].
///
/// Interior state is ONLY the bound app-private durable dir (`Mutex<Option<String>>`) — NOT a resolver
/// (the no-fork law, F1). Every engine op delegates to a `resolver::*` free-fn over the ONE
/// `Resolver::global()`. Each public method panic-firewalls its body — a bug returns a safe default,
/// never aborts across the FFI boundary.
#[derive(uniffi::Object)]
pub struct MaskSolver {
    /// Object-local config ONLY — the bound app-private durable dir (the cache/rotation persist target).
    /// NOT a resolver: the engine is the process-global `RESOLVER`. Holding a dir is config, never a
    /// second engine.
    durable_dir: Mutex<Option<String>>,
}

#[uniffi::export]
impl MaskSolver {
    /// Construct a COLD handle — binds the already-inited global lazily; constructs NO engine (contrast the
    /// engine-owning Warden ctor). IO-free, infallible → `Arc<Self>`. Arm the durable dir via
    /// [`bind_durable`](MaskSolver::bind_durable) and configure via [`configure`](MaskSolver::configure).
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            durable_dir: Mutex::new(None),
        })
    }

    /// A CONFIGURING constructor — delegates to `resolver::configure` (the atomic pool build + cache clear)
    /// then returns the handle. Additive; the flat `resolver_configure` export stays live (NO-BREAK). Fails
    /// with [`MaskSolverError::NoUpstreams`] when the spec parses to zero usable upstreams.
    #[uniffi::constructor]
    pub fn with_upstreams(
        specs_json: String,
        timeout_ms: u64,
        cache_cap: u32,
    ) -> Result<Arc<Self>, MaskSolverError> {
        catch_unwind(AssertUnwindSafe(|| {
            super::configure(&specs_json, timeout_ms, cache_cap as usize)
                .map(|_| {
                    Arc::new(Self {
                        durable_dir: Mutex::new(None),
                    })
                })
                .ok_or_else(|| MaskSolverError::NoUpstreams {
                    reason: "the spec parsed to zero usable upstreams".to_string(),
                })
        }))
        .unwrap_or_else(|_| {
            Err(MaskSolverError::Panic {
                reason: "with_upstreams".to_string(),
            })
        })
    }

    /// Bind (or re-bind) the app-private durable dir — the cache/rotation persist target the
    /// persist/rehydrate ops + the rotation read use. Idempotent config; panic-firewalled to a no-op.
    ///
    /// ★ E-FIX r3 — binding ALSO arms the process-global datapath review feed
    /// ([`super::arm_query_log`]): the C tun seam (`torta_resolve` → `resolve_datapath`) starts
    /// appending its classified outcome lines to `query-masksolver.log` under this dir, so the
    /// BLOCK/NXDOMAIN/GUARD/REBIND verdicts become witnessable on-device (the log existed; the live
    /// datapath never wrote it).
    pub fn bind_durable(&self, dir: String) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            super::arm_query_log(&dir);
            if let Ok(mut guard) = self.durable_dir.lock() {
                *guard = Some(dir);
            }
        }));
    }

    /// THE DATAPATH — resolve one wire query, delegating to `resolver::resolve` (which itself holds the
    /// resolver runtime guard the QUIC transports need — the Object NEVER re-implements the exchange, F8).
    /// Returns `Some(wire)` or `None` (a MISS ⇒ the caller falls through to dnscrypt-proxy — a miss is
    /// DATA, not an error). Doubly panic-firewalled (the free-fn firewalls too) → `None`.
    pub fn resolve(&self, query: Vec<u8>) -> Option<Vec<u8>> {
        catch_unwind(AssertUnwindSafe(|| super::resolve(&query))).unwrap_or(None)
    }

    /// SLICE 6 — THE LOGGED DATAPATH (the Socio's review-channel seam). IDENTICAL to
    /// [`resolve`](MaskSolver::resolve) PLUS it appends ONE human-legible line to the MaskSolver's per-pillar
    /// `query-masksolver.log` (the #133 [`crate::log_tier`] RAM⊗NAND substrate — the `query.log` /
    /// `query-warden.log` precedent) recording the resolve OUTCOME (HIT / STALE / SOLVE / LOCAL / BLOCK /
    /// GUARD / REBIND / REJECT / MISS) + the numeric qtype. The classification is the datapath's GROUND
    /// TRUTH (a stack-local, never a global); the log write is FAIL-OPEN + OFF the pure hot path — call THIS
    /// for the resolve feed, the plain [`resolve`](MaskSolver::resolve) for the hot resolver path. The line
    /// lands beside the resolver's durable cache/rotation blobs in the bound durable dir
    /// ([`bind_durable`](MaskSolver::bind_durable)); an UNBOUND MaskSolver silently resolves WITHOUT logging
    /// (no dir → no log, never an error). `now_ms` is the injected wall clock. A log write NEVER changes the
    /// returned answer. Doubly panic-firewalled → `None`.
    pub fn resolve_logged(&self, query: Vec<u8>, now_ms: u64) -> Option<Vec<u8>> {
        catch_unwind(AssertUnwindSafe(|| match self.log_path_buf() {
            Some(path) => super::resolve_logged(&query, now_ms, &path),
            // UNBOUND ⇒ no log location; still resolve (a miss is DATA), just write no review line.
            None => super::resolve(&query),
        }))
        .unwrap_or(None)
    }

    /// The on-disk path of the per-pillar `query-masksolver.log` (a sibling of the resolver's durable
    /// cache/rotation blobs under the bound durable dir) — the read anchor for the SLINT dashboard's
    /// [`crate::log_tier::log_tail_recent`] review feed (slice 8). `None` when UNBOUND (RAM-only; a resolve
    /// still works, it simply writes no review log — the fail-safe). Panic-firewalled → `None`.
    pub fn query_masksolver_log_path(&self) -> Option<String> {
        catch_unwind(AssertUnwindSafe(|| {
            self.log_path_buf()
                .map(|p| p.to_string_lossy().into_owned())
        }))
        .unwrap_or(None)
    }

    /// (Re)configure the resolver — delegates to `resolver::configure` (atomic pool swap + cache clear, so
    /// a swapped upstream set never serves the previous resolver's answers, F10). Returns the summary
    /// (`ready=N transports=…`) or [`MaskSolverError::NoUpstreams`]. Panic-firewalled → typed `Panic`.
    pub fn configure(
        &self,
        specs_json: String,
        timeout_ms: u64,
        cache_cap: u32,
    ) -> Result<String, MaskSolverError> {
        catch_unwind(AssertUnwindSafe(|| {
            super::configure(&specs_json, timeout_ms, cache_cap as usize).ok_or_else(|| {
                MaskSolverError::NoUpstreams {
                    reason: "the spec parsed to zero usable upstreams".to_string(),
                }
            })
        }))
        .unwrap_or_else(|_| {
            Err(MaskSolverError::Panic {
                reason: "configure".to_string(),
            })
        })
    }

    /// THE headline read — a typed [`MaskSolverSnapshot`] over the SAME live atomics `stats()` renders
    /// (the single-source proof — no engine fork). The two rates are Rust-computed + zero-guarded.
    /// Panic-firewalled → an all-zero honest-off snapshot.
    pub fn snapshot(&self) -> MaskSolverSnapshot {
        catch_unwind(AssertUnwindSafe(|| {
            let r = super::read_stats_raw();
            MaskSolverSnapshot {
                configured: r.configured,
                transports: r.transports as i64,
                cache_entries: r.cache_entries as i64,
                cache_hit_rate: rate(r.cache_hits, r.queries),
                solve_success_rate: rate(r.answered, r.queries),
                queries: r.queries as i64,
                blocked: r.blocked as i64,
                cache_hits: r.cache_hits as i64,
                answered: r.answered as i64,
                rejected: r.rejected as i64,
                transport_miss: r.transport_miss as i64,
                panics: r.panics as i64,
                rebind_observed: r.rebind_observed as i64,
                rebind_rejected: r.rebind_rejected as i64,
                homograph_observed: r.homograph_observed as i64,
                homograph_rejected: r.homograph_rejected as i64,
                serve_stale_served: r.serve_stale_served as i64,
                neg_cache: r.neg_cache as i64,
                cloak_actions: r.cloak_actions as i64,
                local_record_hits: r.local_record_hits as i64,
                bogus_priv_stops: r.bogus_priv_stops as i64,
                never_forward_stops: r.never_forward_stops as i64,
                filter_rr_drops: r.filter_rr_drops as i64,
                ad_bit_pass_through: r.ad_bit_pass_through as i64,
                dns64_synth: r.dns64_synth as i64,
                centauri_cloak_sinkholes: r.centauri_cloak_sinkholes as i64,
            }
        }))
        .unwrap_or_else(|_| zero_snapshot())
    }

    /// The `stats()` twin of [`snapshot`](MaskSolver::snapshot) (the Object mirror of the flat `stats()`) —
    /// identical typed read, the richer name kept for parity with the other pillars' Objects.
    pub fn stats(&self) -> MaskSolverSnapshot {
        self.snapshot()
    }

    /// The focused cache slice — the CACHE-cross witnesses. Panic-firewalled → an all-zero cache stat.
    pub fn cache_stats(&self) -> MaskSolverCacheStats {
        catch_unwind(AssertUnwindSafe(|| {
            let r = super::read_stats_raw();
            MaskSolverCacheStats {
                entries: r.cache_entries as i64,
                hits: r.cache_hits as i64,
                hit_rate: rate(r.cache_hits, r.queries),
                serve_stale_served: r.serve_stale_served as i64,
                neg_cache: r.neg_cache as i64,
            }
        }))
        .unwrap_or(MaskSolverCacheStats {
            entries: 0,
            hits: 0,
            hit_rate: 0.0,
            serve_stale_served: 0,
            neg_cache: 0,
        })
    }

    /// The SOLVE-form surface — per-upstream RTT/loss EWMA + the rotation cursor + the per-query deadline.
    /// The transports are a LIVE pool read; the rotation is the last-persisted durable cursor (cold when
    /// unbound). Panic-firewalled → an empty solve state.
    pub fn solve_state(&self) -> MaskSolverSolveState {
        catch_unwind(AssertUnwindSafe(|| {
            let view = super::pool_view();
            let transports = view
                .transports
                .into_iter()
                .map(|t| MaskSolverTransport {
                    id: t.id,
                    rtt_ms_ewma: t.rtt_ms_ewma,
                    loss_ewma: t.loss_ewma,
                    samples: t.samples as i64,
                })
                .collect();
            MaskSolverSolveState {
                transports,
                rotation: self.read_rotation(),
                timeout_ms: view.timeout_ms as i64,
                transport_miss: view.transport_miss as i64,
                strategy: map_strategy(super::pool::active_strategy()),
                solve_retries: view.solve_retries as i64,
                solve_soft_fails: view.solve_soft_fails as i64,
                solve_hard_negatives: view.solve_hard_negatives as i64,
                solve_ladder_exhausted: view.solve_ladder_exhausted as i64,
                solve_upstream_promotions: view.solve_upstream_promotions as i64,
            }
        }))
        .unwrap_or_else(|_| MaskSolverSolveState {
            transports: Vec::new(),
            rotation: cold_rotation(),
            timeout_ms: 0,
            transport_miss: 0,
            strategy: MaskSolverStrategy::StrictOrder,
            solve_retries: 0,
            solve_soft_fails: 0,
            solve_hard_negatives: 0,
            solve_ladder_exhausted: 0,
            solve_upstream_promotions: 0,
        })
    }

    /// THE ROTATION headline read — a typed [`RotationSnapshot`] over the LAST-PERSISTED durable rotation
    /// record in the bound durable dir (the full-power twin of the flat `rehydrate_resolver_rotation` summary
    /// string). Carries the typed warm-RTT LIST + the `rehydrated_warm` crown flag the compact embedded
    /// [`MaskSolverRotation`] (in [`solve_state`](MaskSolver::solve_state)) omits — the dedicated Rotation
    /// dashboard's source. A control-plane READ ([`rotation::RotationState::rehydrate_opt`]), NEVER the
    /// resolve hot path; an UNBOUND handle reads the honest cold zero. `next_flip_secs` is host-filled
    /// (torta_core is clock-free — see the field doc). Panic-firewalled → a cold snapshot.
    pub fn rotation_snapshot(&self) -> RotationSnapshot {
        catch_unwind(AssertUnwindSafe(|| self.read_rotation_snapshot()))
            .unwrap_or_else(|_| cold_rotation_snapshot())
    }

    /// Persist the live cache to the bound durable dir (RAM⊗NAND write-through, control-plane only).
    /// Delegates to `resolver::persist_cache` (which releases the inner lock before NAND IO, F10). Returns
    /// the bytes written; errors [`MaskSolverError::NotBound`] when no dir is bound.
    pub fn persist_cache(&self) -> Result<i64, MaskSolverError> {
        let dir = self.bound_dir()?;
        Ok(catch_unwind(AssertUnwindSafe(|| super::persist_cache(&dir) as i64)).unwrap_or(0))
    }

    /// Rehydrate the cache from the bound durable dir (NAND read on the hot path's behalf). Delegates to
    /// `resolver::rehydrate_cache`. Returns the count admitted; errors [`MaskSolverError::NotBound`] when
    /// no dir is bound.
    pub fn rehydrate_cache(&self) -> Result<i64, MaskSolverError> {
        let dir = self.bound_dir()?;
        Ok(catch_unwind(AssertUnwindSafe(|| super::rehydrate_cache(&dir) as i64)).unwrap_or(0))
    }

    /// Idempotent teardown — delegates to `resolver::shutdown` (drop the pool/cache, keep the parked
    /// runtime for a later reconfigure). Panic-firewalled to a no-op.
    pub fn shutdown(&self) {
        let _ = catch_unwind(AssertUnwindSafe(super::shutdown));
    }

    // ── the Expert toggles — thin delegations to the `resolver::set_*` free-fns, each panic → no-op ──

    /// Expert `--stop-dns-rebind` enforce (P12). Delegates to `resolver::set_rebind_enforce`.
    pub fn set_rebind_enforce(&self, on: bool) {
        let _ = catch_unwind(AssertUnwindSafe(|| super::set_rebind_enforce(on)));
    }

    /// Expert `--bogus-priv` (R5). Delegates to `resolver::set_bogus_priv`.
    pub fn set_bogus_priv(&self, on: bool) {
        let _ = catch_unwind(AssertUnwindSafe(|| super::set_bogus_priv(on)));
    }

    /// Expert `--proxy-dnssec` (N3). Delegates to `resolver::set_proxy_dnssec`.
    pub fn set_proxy_dnssec(&self, on: bool) {
        let _ = catch_unwind(AssertUnwindSafe(|| super::set_proxy_dnssec(on)));
    }

    /// Expert `--filter-rr` (N1) — install the RR-type strip set + the RFC8482 ANY-defang flag. Delegates
    /// to `resolver::set_filter_rr`.
    pub fn set_filter_rr(&self, drop_types: Vec<u16>, any_defang: bool) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            super::set_filter_rr(&drop_types, any_defang)
        }));
    }

    /// Expert cache-RR gate. Delegates to `resolver::set_cache_rr`.
    pub fn set_cache_rr(&self, on: bool) {
        let _ = catch_unwind(AssertUnwindSafe(|| super::set_cache_rr(on)));
    }

    /// Expert `--all-servers` concurrent-race toggle (R6). Delegates to `resolver::set_all_servers`.
    pub fn set_all_servers(&self, on: bool) {
        let _ = catch_unwind(AssertUnwindSafe(|| super::set_all_servers(on)));
    }

    /// Expert SOLVE-cross toggle (slice 2) — arm/disarm the resilient-resolution ladder. OFF by default ⇒
    /// the egress takes today's sequential/`--all-servers` path, behaviourally byte-identical; ON ⇒ the
    /// verdict-gated, health-ordered, bounded ladder (`solve_state().strategy` reports `Fastest`). Delegates
    /// to `resolver::set_solve_ladder`. Panic-firewalled → no-op.
    pub fn set_solve_ladder(&self, on: bool) {
        let _ = catch_unwind(AssertUnwindSafe(|| super::set_solve_ladder(on)));
    }

    /// Expert never-forward privacy-guard toggle. Delegates to `resolver::set_never_forward_enabled`.
    pub fn set_never_forward_enabled(&self, on: bool) {
        let _ = catch_unwind(AssertUnwindSafe(|| super::set_never_forward_enabled(on)));
    }

    /// Sovereign-rewire DNS64 prefix store (slice 4) — install the NAT64 prefixes (CSV). Delegates to
    /// `resolver::set_dns64_prefixes`.
    pub fn set_dns64_prefixes(&self, csv: String) {
        let _ = catch_unwind(AssertUnwindSafe(|| super::set_dns64_prefixes(&csv)));
    }

    /// P9 Centauri DNS-plane cloak toggle (mirror-feature-gated). On a base (`mirror`-absent) build the
    /// method stays present (a stable Kotlin surface) but no-ops — the cloak consult compiles only under
    /// `mirror`. Delegates to `resolver::set_centauri_cloak` when built.
    pub fn set_centauri_cloak(&self, on: bool) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            #[cfg(feature = "mirror")]
            super::set_centauri_cloak(on);
            #[cfg(not(feature = "mirror"))]
            let _ = on;
        }));
    }
}

// Non-exported helpers (a plain `impl`, NOT `#[uniffi::export]`).
impl MaskSolver {
    /// The bound durable dir, or [`MaskSolverError::NotBound`] — the persist/rehydrate precondition.
    fn bound_dir(&self) -> Result<String, MaskSolverError> {
        match self.durable_dir.lock() {
            Ok(guard) => guard.clone().ok_or_else(|| MaskSolverError::NotBound {
                reason: "call bind_durable(dir) first".to_string(),
            }),
            Err(_) => Err(MaskSolverError::NotBound {
                reason: "durable-dir lock poisoned".to_string(),
            }),
        }
    }

    /// The rotation cursor from the bound durable dir (a REAL read of the last-persisted record), or a cold
    /// zero when unbound. Never the hot path.
    fn read_rotation(&self) -> MaskSolverRotation {
        let dir = match self.durable_dir.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => None,
        };
        match dir {
            Some(d) => {
                let st = RotationState::rehydrate(PathBuf::from(d));
                MaskSolverRotation {
                    last_family: st.last_family,
                    cadence_secs: st.cadence_secs as i64,
                    rotation_index: st.rotation_index as i64,
                    hint_count: st.rtt_hints.len() as i64,
                }
            }
            None => cold_rotation(),
        }
    }

    /// The rich [`RotationSnapshot`] from the bound durable dir — a REAL read of the last-persisted record,
    /// mapping the warm-RTT `(id, rtt)` pairs to the typed [`RttHint`] list + setting `rehydrated_warm` from
    /// whether a durable record was FOUND ([`rotation::RotationState::rehydrate_opt`], not `== cold()`).
    /// `next_flip_secs` stays 0 (host-filled — torta_core holds no live clock). A cold zero when UNBOUND or
    /// when no record exists. Never the hot path — the control-plane dashboard read.
    fn read_rotation_snapshot(&self) -> RotationSnapshot {
        let dir = match self.durable_dir.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => None,
        };
        match dir {
            Some(d) => match RotationState::rehydrate_opt(PathBuf::from(d)) {
                Some(st) => RotationSnapshot {
                    last_family: st.last_family,
                    cadence_secs: st.cadence_secs as i64,
                    rotation_index: st.rotation_index as i64,
                    // torta_core is clock-free: the durable read reports 0; the Kotlin host pushes the live
                    // countdown onto the SLINT `next-flip-secs` in-out (the no-fork / clock-free law).
                    next_flip_secs: 0,
                    rtt_hints: st
                        .rtt_hints
                        .into_iter()
                        .map(|(id, rtt)| RttHint {
                            id,
                            rtt_ms: i64::from(rtt),
                        })
                        .collect(),
                    rehydrated_warm: true,
                },
                None => cold_rotation_snapshot(),
            },
            None => cold_rotation_snapshot(),
        }
    }

    /// The `query-masksolver.log` path under the bound durable dir (a sibling of the resolver's cache/
    /// rotation blobs, [`super::log::QUERY_MASKSOLVER_LOG_NAME`]), or `None` when UNBOUND. Never the hot
    /// path — the slice-6 logged seam + the dashboard path-getter call it.
    fn log_path_buf(&self) -> Option<PathBuf> {
        let dir = self.durable_dir.lock().ok()?.clone()?;
        Some(PathBuf::from(dir).join(super::log::QUERY_MASKSOLVER_LOG_NAME))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique app-private durable dir for a test (process-scoped, collision-free).
    fn unique_dir(tag: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!(
                "torta-masksolver-{}-{}-{}",
                tag,
                std::process::id(),
                n
            ))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn new_constructs_and_snapshot_is_panic_free_with_bounded_rates() {
        // The Object constructs; a snapshot NEVER panics and the two rates are always FINITE + in [0,1]
        // (the queries==0 guard prevents a NaN divide) — an invariant that holds under any concurrent
        // global state (the resolver is a process-global singleton shared across the test binary).
        let ms = MaskSolver::new();
        let s = ms.snapshot();
        assert!(
            s.cache_hit_rate.is_finite() && (0.0..=1.0).contains(&s.cache_hit_rate),
            "cache_hit_rate must be finite + in [0,1], got {}",
            s.cache_hit_rate
        );
        assert!(
            s.solve_success_rate.is_finite() && (0.0..=1.0).contains(&s.solve_success_rate),
            "solve_success_rate must be finite + in [0,1], got {}",
            s.solve_success_rate
        );
        // `stats()` is the byte-twin of `snapshot()`.
        let _ = ms.stats();
        let _ = ms.cache_stats();
        let _ = ms.solve_state();
    }

    #[test]
    fn snapshot_reads_the_same_live_atomic_resolve_bumps_no_fork() {
        // THE no-fork proof (F1): a `resolve()` through the Object bumps the SAME `queries` atomic the
        // Object's `snapshot()` reads. `queries` is monotonic across the whole process (fetch_add, never
        // reset), so `after >= before + 1` holds even under concurrent test load. If the Object held its
        // OWN forked engine, its snapshot would NOT see the datapath's increment.
        let ms = MaskSolver::new();
        let before = ms.snapshot().queries;
        // Garbage bytes: `resolve` bumps `queries` at the top, then `parse_question` returns None ⇒ a
        // clean miss (`None`), never a panic.
        let out = ms.resolve(vec![0u8; 4]);
        assert!(out.is_none(), "a 4-byte garbage query is a clean miss");
        let after = ms.snapshot().queries;
        assert!(
            after > before,
            "the Object snapshot must observe the resolve() increment (before={before} after={after}) \
             — a divergence would prove a forked engine",
        );
    }

    #[test]
    fn configure_through_the_object_builds_a_loopback_do53_arm() {
        // The Object's configure delegates to the SAME `resolver::configure`; the summary is the
        // return-value (concurrency-safe, like the engine's own configure tests).
        // ★ #100 — "the SAME resolver::configure" is exactly why this needs the gate: the Object is a
        // handle, not a separate engine, so this INSTALLS into the one process-global pool.
        let _serial = crate::resolver::lock_global_for_test();
        let ms = MaskSolver::new();
        let summary = ms
            .configure(
                r#"{"upstreams":[{"id":"do53:proxy","transport":"do53","url":"127.0.0.1:5354"}]}"#
                    .to_string(),
                3000,
                1024,
            )
            .expect("a loopback do53 upstream must configure through the Object");
        assert_eq!(summary, "ready=1 transports=do53:proxy");
    }

    #[test]
    fn configure_with_no_usable_upstream_is_typed_no_upstreams_error() {
        let ms = MaskSolver::new();
        let err = ms
            .configure(
                r#"{"upstreams":[{"id":"x","transport":"doh3"}]}"#.to_string(),
                3000,
                64,
            )
            .expect_err("a no-url doh3-only spec must fail typed");
        assert!(matches!(err, MaskSolverError::NoUpstreams { .. }));
    }

    #[test]
    fn with_upstreams_ctor_configures_or_errors_typed() {
        // ★ #100 — the Ok arm installs a real loopback pool into the process-global.
        let _serial = crate::resolver::lock_global_for_test();
        let ok = MaskSolver::with_upstreams(
            r#"{"upstreams":[{"id":"do53:proxy","transport":"do53","url":"127.0.0.1:5354"}]}"#
                .to_string(),
            3000,
            256,
        );
        assert!(ok.is_ok(), "a loopback do53 spec must build the handle");
        // `Arc<MaskSolver>` (the Ok type) is not `Debug`, so assert via `matches!` on the Err arm rather
        // than `.unwrap_err()` (which would require the Ok type to be Debug).
        let bad = MaskSolver::with_upstreams(r#"{"upstreams":[]}"#.to_string(), 3000, 256);
        assert!(matches!(bad, Err(MaskSolverError::NoUpstreams { .. })));
    }

    #[test]
    fn persist_without_bound_dir_is_typed_not_bound() {
        let ms = MaskSolver::new();
        assert!(matches!(
            ms.persist_cache().unwrap_err(),
            MaskSolverError::NotBound { .. }
        ));
        assert!(matches!(
            ms.rehydrate_cache().unwrap_err(),
            MaskSolverError::NotBound { .. }
        ));
    }

    #[test]
    fn bound_persist_rehydrate_round_trips_without_error() {
        // Bind a unique dir, configure, then persist + rehydrate — both return Ok (the count is
        // best-effort under a shared global; the CONTRACT proven here is "bound ⇒ no NotBound + no panic").
        // ★ #100 — installs a pool; takes the shared gate.
        let _serial = crate::resolver::lock_global_for_test();
        let ms = MaskSolver::new();
        ms.bind_durable(unique_dir("persist"));
        let _ = ms.configure(
            r#"{"upstreams":[{"id":"do53:proxy","transport":"do53","url":"127.0.0.1:5354"}]}"#
                .to_string(),
            3000,
            1024,
        );
        assert!(ms.persist_cache().is_ok(), "a bound persist must not error");
        assert!(
            ms.rehydrate_cache().is_ok(),
            "a bound rehydrate must not error"
        );
    }

    #[test]
    fn expert_toggles_are_panic_free_noops() {
        // Serialize against the resolver-global tests: this test flips the process-global
        // never-forward guard the datapath tests depend on (the crate charter at lib.rs).
        let _g = crate::lock_resolver_global();
        // Every Expert toggle delegates + panic-firewalls; drive them all once (no assertion beyond
        // "does not panic / does not brick the process").
        let ms = MaskSolver::new();
        ms.set_rebind_enforce(true);
        ms.set_rebind_enforce(false);
        ms.set_bogus_priv(true);
        ms.set_proxy_dnssec(true);
        ms.set_filter_rr(vec![65u16, 64u16], true);
        ms.set_cache_rr(true);
        ms.set_all_servers(true);
        ms.set_never_forward_enabled(true);
        ms.set_dns64_prefixes("64:ff9b::/96".to_string());
        ms.set_centauri_cloak(true);
        // reset the process-global toggles we flipped so we don't leak state into sibling tests.
        ms.set_rebind_enforce(false);
        ms.set_bogus_priv(false);
        ms.set_proxy_dnssec(false);
        ms.set_filter_rr(vec![], false);
        ms.set_cache_rr(false);
        ms.set_all_servers(false);
        ms.set_never_forward_enabled(false);
        ms.set_dns64_prefixes(String::new());
        ms.set_centauri_cloak(false);
    }

    #[test]
    fn solve_state_surfaces_the_typed_strategy_and_solve_counters() {
        use crate::resolver::pool::Strategy;

        // (1) the typed twin maps the internal `pool::Strategy` faithfully — a PURE, deterministic proof
        //     (no process-global toggle state, so no cross-test race).
        assert_eq!(
            map_strategy(Strategy::StrictOrder),
            MaskSolverStrategy::StrictOrder
        );
        assert_eq!(
            map_strategy(Strategy::AllServers),
            MaskSolverStrategy::AllServers
        );
        assert_eq!(map_strategy(Strategy::Fastest), MaskSolverStrategy::Fastest);

        // (2) solve_state surfaces a valid strategy + the 5 SOLVE-cross counters (typed i64, honest ZERO
        //     until the ladder fires); the Object toggle is panic-free. Race-safe: it asserts NO absolute
        //     value on a globally-mutated toggle (only the enum is well-formed + the counts are readable).
        let ms = MaskSolver::new();
        ms.set_solve_ladder(true);
        ms.set_solve_ladder(false);
        let st = ms.solve_state();
        assert!(matches!(
            st.strategy,
            MaskSolverStrategy::StrictOrder
                | MaskSolverStrategy::AllServers
                | MaskSolverStrategy::Fastest
        ));
        // The counts are surfaced + typed; a COUNT is never negative (the fields exist ⇒ the surface is
        // complete relative to the flat `stats()` JSON solve_* keys).
        assert!(st.solve_retries >= 0);
        assert!(st.solve_soft_fails >= 0);
        assert!(st.solve_hard_negatives >= 0);
        assert!(st.solve_ladder_exhausted >= 0);
        assert!(st.solve_upstream_promotions >= 0);
    }

    #[test]
    fn resolve_logged_writes_query_masksolver_log_when_bound() {
        // SLICE 6 feelsAlive: a BOUND MaskSolver's resolve_logged appends ONE outcome line to
        // query-masksolver.log, readable back through the SAME #133 log_tier tailer (the shared write→read
        // proof the per-pillar log is wired to the substrate, not a bespoke file). A 4-byte garbage query is
        // a clean MISS (parse fails → no answer, no panic) ⇒ a `MISS` line.
        let ms = MaskSolver::new();
        ms.bind_durable(unique_dir("log"));
        let path = ms
            .query_masksolver_log_path()
            .expect("a bound MaskSolver surfaces its query-masksolver.log path");
        assert!(
            path.ends_with(crate::resolver::log::QUERY_MASKSOLVER_LOG_NAME),
            "the log path sits beside the durable blobs: {path}"
        );

        let out = ms.resolve_logged(vec![0u8; 4], 1_751_000_000_000);
        assert!(out.is_none(), "a 4-byte garbage query is a clean miss");

        let got = crate::log_tier::log_tail_recent(&path, 10);
        assert!(
            got.contains("1751000000000 MISS"),
            "the resolve outcome round-trips into query-masksolver.log: {got}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_logged_unbound_is_silent_noop_but_still_resolves() {
        // An UNBOUND MaskSolver has no log location: resolve_logged still resolves (a miss is DATA) and
        // surfaces NO path — never an error, never a panic (the fail-safe).
        let ms = MaskSolver::new();
        assert!(
            ms.query_masksolver_log_path().is_none(),
            "an unbound MaskSolver surfaces no log path"
        );
        let out = ms.resolve_logged(vec![0u8; 4], 1_000);
        assert!(
            out.is_none(),
            "unbound resolve_logged still resolves (a clean miss), writes no log"
        );
    }

    #[test]
    fn rotation_snapshot_round_trips_the_typed_cursor_hints_and_warm_flag() {
        // The full-power RotationSnapshot READ: a bound MaskSolver reads back a persisted durable record as a
        // TYPED snapshot — the cursor + cadence + the FULL typed warm-RTT LIST + rehydrated_warm=true (the
        // #98 crown). This is the full-power twin of the flat `rehydrate_resolver_rotation` summary: a typed
        // `Vec<RttHint>`, never a flat string / a bare count.
        use crate::resolver::rotation::RotationState;
        let dir = unique_dir("rot-snap");
        // Persist a warm cursor with two RTT hints through the durable engine (the control plane).
        let mut st = RotationState::cold();
        st.cadence_secs = 1800;
        st.rotate_to("mullvad", 5);
        st.observe_rtt("doh:cf", 21);
        st.observe_rtt("dnscrypt:quad9", 34);
        assert!(
            st.persist(PathBuf::from(&dir)),
            "a control-plane persist writes durably"
        );

        let ms = MaskSolver::new();
        ms.bind_durable(dir.clone());
        let snap = ms.rotation_snapshot();

        assert_eq!(
            snap.last_family, "mullvad",
            "the warm family resumed (not cold at family 0)"
        );
        assert_eq!(snap.cadence_secs, 1800, "the durable cadence resumed");
        assert_eq!(
            snap.rotation_index, 5,
            "the rotation index resumed at 5, not 0"
        );
        assert!(
            snap.rehydrated_warm,
            "a FOUND durable record ⇒ a WARM resume (the crown flag)"
        );
        assert_eq!(
            snap.next_flip_secs, 0,
            "torta_core is clock-free ⇒ the durable read is 0; the host fills the live countdown"
        );
        // The typed warm-RTT LIST (order-independent) — full-power, never a flat string / bare count.
        assert_eq!(
            snap.rtt_hints.len(),
            2,
            "both warm hints crossed as a typed list"
        );
        let cf = snap
            .rtt_hints
            .iter()
            .find(|h| h.id == "doh:cf")
            .expect("the cf warm hint is present in the typed list");
        assert_eq!(cf.rtt_ms, 21);
        let q9 = snap
            .rtt_hints
            .iter()
            .find(|h| h.id == "dnscrypt:quad9")
            .expect("the quad9 warm hint is present in the typed list");
        assert_eq!(q9.rtt_ms, 34);
        let _ = std::fs::remove_dir_all(PathBuf::from(&dir));
    }

    #[test]
    fn rotation_snapshot_unbound_and_empty_dir_are_honest_cold() {
        // UNBOUND ⇒ a cold snapshot (no dir): rehydrated_warm=false, empty hints. And a BOUND-but-empty dir
        // (no record yet) is ALSO honest-cold (rehydrated_warm=false) — the found-vs-cold signal the flat
        // summary string cannot give.
        let ms = MaskSolver::new();
        let unbound = ms.rotation_snapshot();
        assert!(
            !unbound.rehydrated_warm,
            "an unbound handle is a cold start, never a warm resume"
        );
        assert!(unbound.last_family.is_empty());
        assert_eq!(unbound.rotation_index, 0);
        assert!(unbound.rtt_hints.is_empty());

        ms.bind_durable(unique_dir("rot-cold"));
        let cold = ms.rotation_snapshot();
        assert!(
            !cold.rehydrated_warm,
            "a bound-but-empty dir (no record) is still a cold start"
        );
        assert!(cold.rtt_hints.is_empty());
    }
}
