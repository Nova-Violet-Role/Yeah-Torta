/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Transport pool — Wave 2b minimal: hold the configured transports and apply the per-query timeout.
//!
//! The full pool (Wave 2c+) does happy-eyeballs across upstreams, the encrypted-only fallback ladder
//! (DoH3 → DoH2 → DNSCrypt → fail-closed), per-upstream RTT/loss stats, and the YeAH cwnd pacing
//! in-flight queries. For 2b we ship exactly the seam the resolver needs: try transports in order,
//! each bounded by `tokio::time::timeout`, and return the first wire-format answer (validation is the
//! resolver's job, not the pool's — the pool deals in opaque bytes).

use std::collections::HashMap;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use super::transport::Transport;

/// P12 `--all-servers` / fastest-upstream selection POLICY. The resolver picks ONE of these and the
/// pool honours it; the default is [`Strategy::StrictOrder`] — byte-for-byte today's sequential
/// `exchange` ladder, so a default `.so` is unchanged until the Expert switch flips it.
///
/// - `StrictOrder` — try transports in configured order, first `Ok` wins ([`Pool::exchange`]). Today.
/// - `AllServers`  — happy-eyeballs RACE: fire ALL transports concurrently, first `Ok` wins, slow/erroring
///   upstreams never block a fast one ([`Pool::exchange_all`]). dnsmasq `--all-servers`.
/// - `Fastest`     — race a SUBSET ordered by the R7 RTT/loss EWMA (lowest-RTT first); the ranking
///   itself is P10 policy that READS [`Pool::transport_stats`] — the pool only records the data + races.
///
/// `#[allow(dead_code)]`: the enum is the shared seam R6 (race) + R7 (EWMA) hang on; it is dead until the
/// JNI+Kotlin Expert toggle (D3 `pref_dnsmasq_all_servers`) drives it through `mod.rs`, keeping the base
/// `.so` byte-identical (the dead-code-until-wired law, §4 of the SSOT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Strategy {
    /// Sequential, first-Ok-wins ladder — the only behaviour the base `.so` ships.
    #[default]
    StrictOrder,
    /// Concurrent happy-eyeballs race across ALL transports — first Ok wins.
    AllServers,
    /// Race ordered by the RTT/loss EWMA (ranking is P10 policy, reading [`Pool::transport_stats`]).
    Fastest,
    /// Per-query ROUND-ROBIN — each query starts the ladder at the next transport in the ring
    /// (`rr_cursor++ % len`), first `Ok` from there wins, then falls forward if that upstream is down.
    /// Spreads the query stream across the WHOLE armed slate (every server + relay is used ⇒ no single
    /// resolver profiles the client, the privacy spread) instead of pinning the one fastest winner. The
    /// Nautilus host arms this at the serve egress (`resolver_set_round_robin`); the base `.so` never
    /// flips it ⇒ byte-identical (the dead-code-until-wired law, SSOT §4). dnscrypt-proxy `round-robin`.
    RoundRobin,
}

/// P12 Expert toggle — `DNSMASQ_ALL_SERVERS` (default OFF, `PreferenceKeys.java:251`). Holds the active
/// [`Strategy`] discriminant: `0` = [`Strategy::StrictOrder`] (today's sequential ladder, the only
/// behaviour the base `.so` ships — keeps it byte-identical, SSOT §4), `1` = [`Strategy::AllServers`]
/// (the R6 concurrent race, [`Pool::exchange_all`]). Default `0`. Pushed from Kotlin via
/// `TortaCore.nativeResolverSetAllServers`; read at the resolver egress (`mod.rs:614`).
static POOL_STRATEGY: AtomicU8 = AtomicU8::new(0);

/// Set the `--all-servers` race on/off (the `DNSMASQ_ALL_SERVERS` Expert toggle).
pub fn set_all_servers(on: bool) {
    POOL_STRATEGY.store(u8::from(on), Ordering::Relaxed);
}

/// R6 read accessor — is the `--all-servers` concurrent race active? The resolver egress picks
/// [`Pool::exchange_all`] over the sequential [`Pool::exchange`] when this is `true` and no conditional
/// route already pinned an upstream.
pub fn all_servers_enabled() -> bool {
    POOL_STRATEGY.load(Ordering::Relaxed) == 1
}

/// SOLVE cross (slice 2) — the `SOLVE_LADDER` Expert toggle (default OFF). Holds the resilient-resolution
/// ladder on/off flag: OFF (`false`) ⇒ the resolver egress takes today's `exchange`/`exchange_all` path,
/// behaviourally byte-identical (the dead-code-until-wired law, SSOT §4); ON ⇒ the egress runs
/// [`Pool::solve_exchange`] — the verdict-gated, health-ordered, bounded single-pass ladder. A standalone
/// `AtomicBool` (the `POOL_STRATEGY` template) flipped independently of an upstream reconfigure (a P10
/// rotation must NOT reset the user's resilience choice). Driven from Kotlin via a `resolver_set_*` flat
/// export + the MaskSolver Object toggle (wired by slice 4).
static SOLVE_LADDER: AtomicBool = AtomicBool::new(false);

/// Arm/disarm the SOLVE-cross resilient ladder (slice 2). OFF by default; idempotent, lock-free. Wired by
/// slice 4 — `resolver::set_solve_ladder` (the re-export), the flat `resolver_set_solve_ladder` export, and
/// the `MaskSolver::set_solve_ladder` Object toggle all delegate here.
pub fn set_solve_ladder(on: bool) {
    SOLVE_LADDER.store(on, Ordering::Relaxed);
}

/// Is the SOLVE-cross resilient ladder armed? The resolver egress picks [`Pool::solve_exchange`] over the
/// sequential `exchange`/`exchange_all` when this is `true` and no conditional route pinned an upstream.
pub fn solve_ladder_enabled() -> bool {
    SOLVE_LADDER.load(Ordering::Relaxed)
}

/// ROUND-ROBIN egress toggle (default OFF). ON ⇒ an un-pinned query takes [`Pool::exchange_round_robin`]
/// — the ladder starts at the next transport in the ring, spreading the stream across the WHOLE armed
/// slate (privacy spread: every server + relay gets used, no single resolver sees the whole stream)
/// rather than pinning the one fastest/first winner. A standalone `AtomicBool` (the `POOL_STRATEGY`
/// template) flipped independently of a reconfigure (a P10 rotation must NOT reset the spread choice).
/// OFF by default ⇒ the egress is behaviourally byte-identical (dead-code-until-wired, SSOT §4). The
/// Nautilus host drives it via the flat `resolver_set_round_robin` export at the serve arm.
static ROUND_ROBIN: AtomicBool = AtomicBool::new(false);

/// Arm/disarm the per-query round-robin egress. OFF by default; idempotent, lock-free.
pub fn set_round_robin(on: bool) {
    ROUND_ROBIN.store(on, Ordering::Relaxed);
}

/// The DURABLE per-query deadline OVERRIDE in milliseconds (0 = honour the Pool's own configured timeout,
/// the byte-identical default). The MaskSolver SETTINGS `timeout` stepper stages a value and commits it
/// here on `reapply-config()`; every exchange path consults [`Pool::effective_timeout`] so the new deadline
/// bites the NEXT query WITHOUT a reconfigure, and survives one (the override is a process-global the
/// exchange always reads, so a P10 rotation rebuild keeps it). A standalone atomic, lock-free.
static QUERY_TIMEOUT_MS_OVERRIDE: AtomicU64 = AtomicU64::new(0);

/// Set the durable per-query timeout override in ms (0 = defer to the Pool's configured timeout).
pub fn set_query_timeout_ms(ms: u64) {
    QUERY_TIMEOUT_MS_OVERRIDE.store(ms, Ordering::Relaxed);
}
/// The durable per-query timeout override in ms (0 = none). The SETTINGS pane reads it back.
pub fn query_timeout_ms_override() -> u64 {
    QUERY_TIMEOUT_MS_OVERRIDE.load(Ordering::Relaxed)
}

/// Is the per-query round-robin egress armed? The resolver egress picks [`Pool::exchange_round_robin`]
/// over every other strategy (it takes precedence) when this is `true` and no conditional route pinned
/// an upstream.
pub fn round_robin_enabled() -> bool {
    ROUND_ROBIN.load(Ordering::Relaxed)
}

/// The DEFAULT egress [`Strategy`] for an UN-pinned query — the toggle-selected resolution mode the
/// SOLVE-form dashboard surfaces (slice 4, the `MaskSolverSolveState.strategy` source). Mirrors the resolver
/// egress precedence (`mod.rs`): the SOLVE resilient ladder (health-ordered by the RTT/loss EWMA ⇒
/// [`Strategy::Fastest`]) wins over the `--all-servers` concurrent race ([`Strategy::AllServers`]) which wins
/// over the sequential default ([`Strategy::StrictOrder`]). A per-query conditional route pins ONE upstream
/// regardless — that is a per-query override, not the standing mode, so it is not reported here. A pure
/// lock-free read of the two Expert toggles (never fabricated).
pub fn active_strategy() -> Strategy {
    if round_robin_enabled() {
        Strategy::RoundRobin
    } else if solve_ladder_enabled() {
        Strategy::Fastest
    } else if all_servers_enabled() {
        Strategy::AllServers
    } else {
        Strategy::StrictOrder
    }
}

/// SOLVE cross (slice 2) — the counter sink the verdict-gated ladder bumps as a side-effect. Holds
/// BORROWED handles to the resolver's `Stats` atomics (the single stats source, `mod.rs`); the pool WRITES
/// them exactly as it writes the RTT/loss EWMA, but never OWNS them. Passed by the resolver egress so
/// [`Pool::solve_exchange`] can report retries/soft-fails/hard-negatives/exhaustion WITHOUT returning a
/// richer type — the egress `match` stays uniformly `Option<Vec<u8>>` across every arm.
pub struct SolveCounters<'a> {
    /// A query where the ladder advanced PAST its first upstream before getting through / hitting a terminal.
    pub retries: &'a AtomicU64,
    /// Per-leg RETRYABLE soft-fails (SERVFAIL/REFUSED/TC/malformed/channel-error/timeout) laddered past.
    pub soft_fails: &'a AtomicU64,
    /// Authoritative NEGATIVES (NXDOMAIN) classified TERMINAL — the neg-cache feed witness (slice 3).
    pub hard_negatives: &'a AtomicU64,
    /// The WHOLE ordered ladder exhausted with only soft-fails (no upstream got through) — a resilient miss.
    pub exhausted: &'a AtomicU64,
}

/// Per-transport health DATA (R7) — an RTT + loss EWMA keyed on `Transport::id()`. **DATA ONLY**: this
/// records the signal; it NEVER ranks or promotes (that is P10 selection policy — the load-bearing
/// data/policy split, SSOT R7). `Strategy::Fastest` READS this; the pool only writes it.
#[derive(Debug, Clone, Copy)]
pub struct TransportStats {
    /// Smoothed round-trip time, milliseconds. `None` until the first reply is observed.
    pub rtt_ms_ewma: Option<f64>,
    /// Smoothed loss fraction in `[0.0, 1.0]` — 1.0 contribution on error/timeout, 0.0 on success.
    pub loss_ewma: f64,
    /// Total exchanges attempted against this transport (denominator sanity; not a ranking input here).
    pub samples: u64,
}

impl TransportStats {
    /// EWMA smoothing factor — α=0.2 weights the last ~5 samples, the classic happy-eyeballs window.
    /// Bounded in (0,1) so both EWMAs are contractions ⇒ provably bounded (the R7 test asserts this).
    const ALPHA: f64 = 0.2;

    fn new() -> Self {
        TransportStats {
            rtt_ms_ewma: None,
            loss_ewma: 0.0,
            samples: 0,
        }
    }

    /// Fold one observation in. `rtt` is `Some(elapsed)` on success, `None` on error/timeout (which also
    /// pushes `loss` toward 1.0). Monotone-bounded: `loss_ewma` stays in `[0,1]`, `rtt_ms_ewma` stays a
    /// convex blend of observed positive RTTs (never negative, never unbounded for bounded inputs).
    fn observe(&mut self, rtt: Option<Duration>) {
        self.samples = self.samples.saturating_add(1);
        let loss_sample = if rtt.is_some() { 0.0 } else { 1.0 };
        self.loss_ewma = Self::ALPHA * loss_sample + (1.0 - Self::ALPHA) * self.loss_ewma;
        if let Some(d) = rtt {
            let ms = d.as_secs_f64() * 1000.0;
            self.rtt_ms_ewma = Some(match self.rtt_ms_ewma {
                Some(prev) => Self::ALPHA * ms + (1.0 - Self::ALPHA) * prev,
                None => ms, // seed on the first real RTT — no warm-up bias toward zero
            });
        }
    }
}

/// The ordered set of encrypted upstreams + the per-query deadline.
pub struct Pool {
    transports: Vec<Arc<dyn Transport>>,
    timeout: Duration,
    /// R7 per-transport RTT/loss EWMA, keyed on `Transport::id()`. `Mutex` (not atomics) because an EWMA
    /// update is a read-modify-write of two floats; contention is nil (one in-flight query per
    /// current-thread runtime, `mod.rs:181`). DATA ONLY — never read for ranking inside the pool.
    stats: Mutex<HashMap<String, TransportStats>>,
    /// ★ E-FIX r5 — does this pool hold the loopback Go-proxy arm (MODE 1)? Computed ONCE at
    /// construction ([`Transport::is_loopback_proxy`]) so the query-feed's per-query consult is a
    /// plain bool read, never a per-query transport scan. The two pool modes are never mixed
    /// (`buildSpecsJson` emits EITHER the dnscrypt-stamp set OR the single loopback do53).
    has_loopback_proxy: bool,
    /// ★ GENESIS A2 (2026-07-05) — the index (into `transports`) of the transport that answered the
    /// LAST successful exchange, or `usize::MAX` if none. Set at each exchange method's win site (where
    /// `transport.id()` is already known) so the resolver can attribute the query.log row to the real
    /// DNSCrypt server (the Rust twin of Go `plugin_forward.go:371`'s `serverName` capture). Read by
    /// [`last_winner_id`] right after the egress returns — on the Android tun loop the egress is
    /// sequential per packet, so the read is stable for THIS query (the rare cross-query window under a
    /// multi-worker runtime would at worst mis-attribute a log line, the same class Go's shared plugin
    /// state has — acceptable for a visibility feed, never the answer).
    last_winner: AtomicUsize,
    /// Round-robin ring position — the transport index the NEXT un-pinned query starts its ladder at
    /// under [`Strategy::RoundRobin`] ([`Pool::exchange_round_robin`]). Bumped once per query (wrapping
    /// on `usize`, taken `% len` at read) so the query stream walks the whole slate. Per-pool: a
    /// reconfigure builds a fresh pool ⇒ the walk restarts at 0 with the new slate. `0` when unused.
    rr_cursor: AtomicUsize,
}

impl Pool {
    pub fn new(transports: Vec<Arc<dyn Transport>>, timeout: Duration) -> Self {
        // R7: pre-seed an empty stats slot per transport id so a `transport_stats()` read is total
        // (every configured upstream has an entry even before its first exchange).
        let mut stats = HashMap::with_capacity(transports.len());
        for t in &transports {
            stats
                .entry(t.id().to_string())
                .or_insert_with(TransportStats::new);
        }
        let has_loopback_proxy = transports.iter().any(|t| t.is_loopback_proxy());
        Pool {
            transports,
            timeout,
            stats: Mutex::new(stats),
            has_loopback_proxy,
            last_winner: AtomicUsize::new(usize::MAX),
            rr_cursor: AtomicUsize::new(0),
        }
    }

    /// ★ GENESIS A2 — the winning transport's `id()` (the DNSCrypt server name) for the last successful
    /// exchange, or `None` if no transport answered. The query.log feed attribute (serverName column).
    pub fn last_winner_id(&self) -> Option<String> {
        let idx = self.last_winner.load(Ordering::Relaxed);
        if idx == usize::MAX {
            None
        } else {
            self.transports.get(idx).map(|t| t.id().to_string())
        }
    }

    /// ★ CP-Attribution — the winning transport's UDP-family flag ([`Transport::is_udp_family`]) for the
    /// last successful exchange: `Some(true)` for a DNSCrypt/Do53 winner, `Some(false)` for
    /// DoH/DoH3/ODoH, `None` if no transport has answered. Read at the SAME seam as [`last_winner_id`]
    /// (right after a forwarded resolve returns) so the family and the server name agree on ONE winner.
    pub fn last_winner_is_udp(&self) -> Option<bool> {
        let idx = self.last_winner.load(Ordering::Relaxed);
        if idx == usize::MAX {
            None
        } else {
            self.transports.get(idx).map(|t| t.is_udp_family())
        }
    }

    /// ★ G5 — the winning transport's relay NAME ([`Transport::relay_name`]) for the last successful
    /// exchange: `Some(name)` for a DNSCrypt winner riding a NAMED relay chain, `None` for a direct
    /// winner, a nameless (bare-stamp) relay, or a non-relay transport. Read at the SAME seam as
    /// [`last_winner_id`] so the relay name and the server name agree on ONE winner (the query.log
    /// `relay` column — the anonymization proof).
    pub fn last_winner_relay(&self) -> Option<String> {
        let idx = self.last_winner.load(Ordering::Relaxed);
        if idx == usize::MAX {
            None
        } else {
            self.transports
                .get(idx)
                .and_then(|t| t.relay_name().map(str::to_string))
        }
    }

    /// ★ E-FIX r5 read accessor — see the field doc. Pure bool; the query-feed's no-double-count
    /// discriminator (`query_feed::feed_status` skips live-forward rows the Go writer owns).
    pub fn has_loopback_proxy(&self) -> bool {
        self.has_loopback_proxy
    }

    /// R7 — fold one observation into a transport's RTT/loss EWMA. DATA ONLY (no ranking). Poison-safe
    /// (`into_inner` on a poisoned lock — a panicked prior holder must not strand the resolver).
    ///
    /// D45 — the slots are PRE-SEEDED per transport id at [`Pool::new`], so the per-exchange hot path
    /// is a borrowed `get_mut` (zero allocs); the `entry(id.to_string())` id-String mint survives only
    /// on the never-in-practice cold fallback (an id the ctor did not seed).
    fn record(&self, id: &str, rtt: Option<Duration>) {
        let mut map = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = map.get_mut(id) {
            slot.observe(rtt);
            return;
        }
        map.entry(id.to_string())
            .or_insert_with(TransportStats::new)
            .observe(rtt);
    }

    /// R7 read accessor — a snapshot of the per-transport RTT/loss EWMA for `Strategy::Fastest`'s P10
    /// ranking policy (which lives OUTSIDE the pool) and for the dashboard. Pure read; never ranks.
    pub fn transport_stats(&self) -> HashMap<String, TransportStats> {
        self.stats.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// R7 warm-start (#98) — seed each UNLEARNED transport's RTT EWMA from a durable warm hint (the
    /// boot-rehydrate "prefer the fastest last upstream" consumer of
    /// [`super::rotation::RotationState::rtt_hint`]). A CONTROL-PLANE call (once at configure/boot, NEVER
    /// the resolve path): for every configured transport whose EWMA is still cold (`rtt_ms_ewma == None`,
    /// no live sample yet), if `hint(id)` yields a last-known RTT, seed it so `Strategy::Fastest`'s ranking
    /// (which lives OUTSIDE the pool) starts warm instead of `f64::INFINITY`. A transport that has ALREADY
    /// learned a live RTT this session is LEFT ALONE — live data always wins over a stale hint. DATA ONLY
    /// (no ranking here); returns the count seeded. Poison-safe (`into_inner` on a poisoned lock).
    pub fn warm_start_rtt(&self, hint: impl Fn(&str) -> Option<u32>) -> usize {
        let mut map = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        let mut seeded = 0usize;
        for t in &self.transports {
            let id = t.id();
            let slot = map
                .entry(id.to_string())
                .or_insert_with(TransportStats::new);
            if slot.rtt_ms_ewma.is_none() {
                if let Some(ms) = hint(id) {
                    slot.rtt_ms_ewma = Some(f64::from(ms));
                    seeded += 1;
                }
            }
        }
        seeded
    }

    pub fn len(&self) -> usize {
        self.transports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transports.is_empty()
    }

    /// Stable ids of the configured transports — the per-upstream stats seam (2c reports RTT/loss
    /// keyed on these). `configure` already builds the summary string directly, so unused for 2b.
    pub fn ids(&self) -> Vec<String> {
        self.transports.iter().map(|t| t.id().to_string()).collect()
    }

    /// The per-query deadline this exchange should honour: the durable SETTINGS override
    /// ([`query_timeout_ms_override`]) when it is non-zero, else the Pool's own configured `timeout`. Every
    /// `tokio::time::timeout` guard in the exchange paths reads THIS (not the raw field) so the MaskSolver
    /// SETTINGS `timeout` knob bites live. Byte-identical to the old behaviour while the override is 0.
    fn effective_timeout(&self) -> Duration {
        let ov = query_timeout_ms_override();
        if ov > 0 {
            Duration::from_millis(ov)
        } else {
            self.timeout
        }
    }

    /// Try each transport in order, each bounded by the per-query timeout. Returns the first
    /// successful (opaque) response bytes, or `None` if every transport errored or timed out. The
    /// resolver runs `dns::validate_response` on whatever this returns — the pool never trusts it.
    pub async fn exchange(&self, query_wire: &[u8]) -> Option<Vec<u8>> {
        for (idx, transport) in self.transports.iter().enumerate() {
            // ★ 2.1.18-absorb (measurement honesty) — any one-time SETUP (DNSCrypt cert
            // fetch/verify) runs BEFORE the stopwatch, bounded by the same per-query deadline but
            // UNTIMED for the EWMA: `TransportStats::observe` seeds on the FIRST sample, and a
            // seed poisoned by cert-transfer time misprices the transport for its whole life
            // (rotation ranking consumes these EWMAs). No-op (ready future) for every transport
            // except DnsCrypt-with-cold-cert; a warm-setup fault is deliberately ignored — the
            // timed exchange right after surfaces + records the real failure as the loss sample.
            let _ = tokio::time::timeout(self.effective_timeout(), transport.warm_setup()).await;
            // R7: time the exchange and fold the RTT (Ok) or a loss sample (Err/timeout) into the EWMA.
            let started = Instant::now();
            match tokio::time::timeout(self.effective_timeout(), transport.exchange(query_wire))
                .await
            {
                Ok(Ok(response)) => {
                    self.record(transport.id(), Some(started.elapsed()));
                    self.last_winner.store(idx, Ordering::Relaxed); // ★ GENESIS A2 — attribute the row
                    return Some(response);
                }
                Ok(Err(_)) => {
                    self.record(transport.id(), None); // transport error → loss sample (no qname logged)
                    continue; // try the next upstream
                }
                Err(_) => {
                    self.record(transport.id(), None); // timed out → loss sample
                    continue; // try the next upstream
                }
            }
        }
        None
    }

    /// Per-query ROUND-ROBIN ([`Strategy::RoundRobin`]). Each call bumps `rr_cursor` and starts the
    /// ladder at `start = rr_cursor % len`, trying `start, start+1, …` (wrapping) so consecutive queries
    /// begin at consecutive transports — the stream WALKS the whole armed slate (every server + relay is
    /// exercised, the privacy spread). Still first-`Ok`-wins from the start point, so a dead upstream at
    /// the cursor never strands the query: it falls FORWARD to the next live one (same resilience +
    /// exhaustion contract as [`exchange`](Self::exchange), `None` iff every transport failed). R7 folds
    /// each attempt's RTT/loss; `last_winner` is the REAL winning index so the query.log server+relay
    /// name the transport that actually answered.
    pub async fn exchange_round_robin(&self, query_wire: &[u8]) -> Option<Vec<u8>> {
        let n = self.transports.len();
        if n == 0 {
            return None;
        }
        // Bump once per query (wrapping) — the walk advances even if `start` itself errors below.
        let start = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % n;
        for step in 0..n {
            let idx = (start + step) % n;
            let transport = &self.transports[idx];
            // ★ 2.1.18-absorb — untimed setup before the stopwatch (see `exchange` for the law).
            let _ = tokio::time::timeout(self.effective_timeout(), transport.warm_setup()).await;
            let started = Instant::now();
            match tokio::time::timeout(self.effective_timeout(), transport.exchange(query_wire))
                .await
            {
                Ok(Ok(response)) => {
                    self.record(transport.id(), Some(started.elapsed()));
                    self.last_winner.store(idx, Ordering::Relaxed); // ★ GENESIS A2 — attribute the row
                    return Some(response);
                }
                Ok(Err(_)) => {
                    self.record(transport.id(), None); // errored → fall forward to the next in the ring
                    continue;
                }
                Err(_) => {
                    self.record(transport.id(), None); // timed out → fall forward
                    continue;
                }
            }
        }
        None
    }

    /// P12 conditional routing (`routing::Router`): exchange via the transport whose `id()` matches
    /// `upstream_id` FIRST, then fall through to the normal [`exchange`](Self::exchange) ladder over
    /// the remaining transports. So a routed name PREFERS its mapped upstream but is never stranded if
    /// that one transport is down — it degrades to the default behavior, never to a hard failure.
    ///
    /// The chosen transport is still bounded by the same per-query `timeout`; the resolver still runs
    /// `dns::validate_response` on whatever comes back (the pool deals in opaque bytes). If
    /// `upstream_id` matches no configured transport (e.g. it was dropped on a P10 re-configure
    /// between the router lookup and here), this is exactly `exchange()` — the default ladder.
    pub async fn exchange_via(&self, query_wire: &[u8], upstream_id: &str) -> Option<Vec<u8>> {
        // 1. Preferred upstream first (if present).
        if let Some((pidx, preferred)) = self
            .transports
            .iter()
            .enumerate()
            .find(|(_, t)| t.id() == upstream_id)
        {
            // ★ 2.1.18-absorb — untimed setup before the stopwatch (see `exchange` for the law).
            let _ = tokio::time::timeout(self.effective_timeout(), preferred.warm_setup()).await;
            let started = Instant::now();
            match tokio::time::timeout(self.effective_timeout(), preferred.exchange(query_wire))
                .await
            {
                Ok(Ok(response)) => {
                    self.record(preferred.id(), Some(started.elapsed()));
                    self.last_winner.store(pidx, Ordering::Relaxed); // ★ GENESIS A2
                    return Some(response);
                }
                Ok(Err(_)) => self.record(preferred.id(), None), // errored → fall through (loss sample)
                Err(_) => self.record(preferred.id(), None), // timed out → fall through (loss sample)
            }
        }
        // 2. Fall through: every OTHER transport, in order (skip the one we just tried).
        for (idx, transport) in self.transports.iter().enumerate() {
            if transport.id() == upstream_id {
                continue; // already tried the preferred one above
            }
            // ★ 2.1.18-absorb — untimed setup before the stopwatch (see `exchange` for the law).
            let _ = tokio::time::timeout(self.effective_timeout(), transport.warm_setup()).await;
            let started = Instant::now();
            match tokio::time::timeout(self.effective_timeout(), transport.exchange(query_wire))
                .await
            {
                Ok(Ok(response)) => {
                    self.record(transport.id(), Some(started.elapsed()));
                    self.last_winner.store(idx, Ordering::Relaxed); // ★ GENESIS A2
                    return Some(response);
                }
                Ok(Err(_)) => self.record(transport.id(), None),
                Err(_) => self.record(transport.id(), None),
            }
        }
        None
    }

    /// R6 — `--all-servers` happy-eyeballs RACE. Fire EVERY transport CONCURRENTLY (each bounded by the
    /// same per-query `timeout`) and return the FIRST `Ok` wire bytes; a slow or erroring upstream NEVER
    /// blocks a fast one, and the first success short-circuits the rest. `None` iff every transport
    /// errored or timed out — the same exhaustion contract as [`exchange`](Self::exchange), so the
    /// resolver's `Ok(Ok(None)) ⇒ transport_miss` arm (`mod.rs:410`) is unchanged.
    ///
    /// Zero-dep by design: the crate carries no `futures`/`FuturesUnordered` (Cargo.toml pulls only
    /// `tokio` rt/net/time/sync/macros), so the race is hand-rolled over a `Vec<Pin<Box<..>>>` with
    /// `std::future::poll_fn` — poll each racer once per wake, first `Ready(Some)` wins. On the
    /// current-thread runtime (`mod.rs:181`, ONE worker) this is CONCURRENT, not parallel — the SSOT R6
    /// caution: no thread-pool assumption, the futures interleave on the single worker.
    ///
    /// The pool still deals in OPAQUE bytes — the resolver runs `dns::validate_response` on the winner
    /// (`mod.rs:429`), exactly as for `exchange`. R7: each racer folds its own RTT/loss into the EWMA as
    /// it settles, win or lose (so a losing-but-fast transport still updates its stats).
    // P12 R6 WIRED: driven by `Strategy::AllServers` (the `DNSMASQ_ALL_SERVERS` Expert toggle) — the
    // resolver egress (`mod.rs:614`) calls this when `pool::all_servers_enabled()` and no route is pinned.
    pub async fn exchange_all(&self, query_wire: &[u8]) -> Option<Vec<u8>> {
        if self.transports.is_empty() {
            return None;
        }
        // One boxed, timeout-bounded racer per transport. Each yields `Option<Vec<u8>>` AND records its
        // own EWMA on settle. `Box<dyn Future>` (not `async fn`) keeps the heterogeneous set in one Vec.
        type Racer<'a> = Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + 'a>>;
        let mut racers: Vec<Racer<'_>> = self
            .transports
            .iter()
            .enumerate()
            .map(|(idx, transport)| {
                let fut = async move {
                    // ★ 2.1.18-absorb — untimed setup before the stopwatch (see `exchange`).
                    let _ = tokio::time::timeout(self.effective_timeout(), transport.warm_setup())
                        .await;
                    let started = Instant::now();
                    match tokio::time::timeout(
                        self.effective_timeout(),
                        transport.exchange(query_wire),
                    )
                    .await
                    {
                        Ok(Ok(response)) => {
                            self.record(transport.id(), Some(started.elapsed()));
                            self.last_winner.store(idx, Ordering::Relaxed); // ★ GENESIS A2
                            Some(response)
                        }
                        Ok(Err(_)) => {
                            self.record(transport.id(), None);
                            None
                        }
                        Err(_) => {
                            self.record(transport.id(), None);
                            None
                        }
                    }
                };
                Box::pin(fut) as Racer<'_>
            })
            .collect();

        // `done[i]` retires a racer that has already resolved to `None`. CRITICAL: a `Future` must NEVER
        // be polled again after it returns `Ready` (contract violation — may panic on a fused/`async`
        // state machine). So we poll ONLY not-yet-done racers each wake; the FIRST to produce `Some`
        // wins and the rest are dropped (their in-flight exchanges are cancelled — no qname, no leak).
        // When every racer is done-`None`, the pool is exhausted ⇒ `None`. `poll_fn` is `std` (1.64).
        let mut done = vec![false; racers.len()];
        poll_fn(move |cx| {
            let mut all_done = true;
            for (i, racer) in racers.iter_mut().enumerate() {
                if done[i] {
                    continue; // already resolved to None — never re-poll a completed future
                }
                match racer.as_mut().poll(cx) {
                    Poll::Ready(Some(bytes)) => return Poll::Ready(Some(bytes)), // first Ok wins
                    Poll::Ready(None) => done[i] = true, // this one lost/failed
                    Poll::Pending => all_done = false,   // still racing
                }
            }
            if all_done {
                Poll::Ready(None) // every transport errored or timed out
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// SOLVE cross (slice 2) — the verdict-gated, HEALTH-ORDERED, bounded SINGLE-PASS resolution ladder:
    /// the FlareSolverr SOLVE form (retry / deadline-envelope / terminal-vs-retryable / fail-open) crossed
    /// with the transports + the R7 RTT/loss EWMA, reimplemented as ORIGINAL Rust. Where `exchange` returns
    /// the FIRST bytes any transport hands back (a fast SERVFAIL wins, then `validate_response` drops it → a
    /// miss, and the next upstream is NEVER tried), `solve_exchange` returns the first answer that GETS
    /// THROUGH: it CLASSIFIES each reply via the injected `verdict` and LADDERS past retryable soft-fails to
    /// the next, healthier upstream — the "resolves resiliently AND gets through" half.
    ///
    /// - `order` — the health-ranked transport INDICES (lowest loss, then lowest RTT), computed by the
    ///   resolver-side ranking policy (the R7 data/policy split: the pool RECORDS, the resolver RANKS). The
    ///   pass is bounded to `order.len()` legs — ONE pass, no N-pass same-transport retry (the outer
    ///   `mod.rs` wall-clock deadline bounds the whole thing; the per-leg `timeout` bounds each leg).
    /// - `verdict` — INJECTED so the pool stays DNS-DUMB: it never parses a reply, it only matches the
    ///   3-way `SolveVerdict` the resolver's `dns::solve_verdict` returns. `GotThrough`/`Terminal` STOP the
    ///   ladder (a validated answer / an authoritative negative — both real answers); `SoftFail` ladders on.
    /// - `counters` — the resolver's `Stats` atomics the ladder bumps (retries / soft-fails / hard-
    ///   negatives / exhaustion). The pool writes them as a side-effect, exactly like the EWMA.
    ///
    /// R7 twist (the SOLVE-cross EDGE over `exchange`): a `SoftFail` reply is recorded as a LOSS, not an RTT
    /// success — a fast SERVFAIL must DEMOTE a broken upstream, not reward it. `GotThrough`/`Terminal` (real
    /// answers, done correctly) record the RTT. So the EWMA learns "who gets THROUGH", not "who replies
    /// fastest with garbage" — feeding the health ranking a better signal each pass.
    ///
    /// Returns the first through/terminal answer's OPAQUE bytes (the resolver's `validate_response` still
    /// authenticates the winner), or `None` when every ordered leg soft-failed/errored/timed out — the SAME
    /// exhaustion contract as `exchange` (so the resolver's `Ok(Ok(None)) ⇒ transport_miss` arm is
    /// byte-identical). A best-effort soft-fail body is deliberately NOT returned: SERVFAIL/REFUSED/TC all
    /// fail `validate_response`, so returning one has no downstream value — `None` is the honest miss.
    pub async fn solve_exchange(
        &self,
        query_wire: &[u8],
        order: &[usize],
        verdict: &dyn Fn(&[u8]) -> crate::dns::SolveVerdict,
        counters: &SolveCounters<'_>,
    ) -> Option<Vec<u8>> {
        use crate::dns::SolveVerdict;
        if self.transports.is_empty() {
            return None;
        }
        let mut tried = 0usize; // legs already skipped past on a soft-fail (0 ⇒ the head leg won)
        for &idx in order {
            let Some(transport) = self.transports.get(idx) else {
                continue; // defensive: a stale/out-of-range index (order built from a prior config) — skip
            };
            // ★ 2.1.18-absorb — untimed setup before the stopwatch (see `exchange` for the law).
            let _ = tokio::time::timeout(self.effective_timeout(), transport.warm_setup()).await;
            let started = Instant::now();
            match tokio::time::timeout(self.effective_timeout(), transport.exchange(query_wire))
                .await
            {
                Ok(Ok(bytes)) => match verdict(&bytes) {
                    SolveVerdict::GotThrough => {
                        // Got through — reward the upstream (real RTT), count a retry if we laddered here.
                        self.record(transport.id(), Some(started.elapsed()));
                        self.last_winner.store(idx, Ordering::Relaxed); // ★ GENESIS A2
                        if tried > 0 {
                            counters.retries.fetch_add(1, Ordering::Relaxed);
                        }
                        return Some(bytes);
                    }
                    SolveVerdict::Terminal(_) => {
                        // Authoritative negative (NXDOMAIN) — the real answer (the slice-3 neg-cache feed).
                        // The server did its job correctly + fast ⇒ reward it (real RTT); stop the ladder.
                        self.record(transport.id(), Some(started.elapsed()));
                        self.last_winner.store(idx, Ordering::Relaxed); // ★ GENESIS A2
                        counters.hard_negatives.fetch_add(1, Ordering::Relaxed);
                        if tried > 0 {
                            counters.retries.fetch_add(1, Ordering::Relaxed);
                        }
                        return Some(bytes);
                    }
                    SolveVerdict::SoftFail(_) => {
                        // A reply, but not a THROUGH — penalize as a LOSS (a fast SERVFAIL must NOT rank a
                        // broken upstream first: the SOLVE-cross edge over `exchange`), then ladder on.
                        self.record(transport.id(), None);
                        counters.soft_fails.fetch_add(1, Ordering::Relaxed);
                        tried += 1;
                    }
                },
                Ok(Err(_)) => {
                    // Channel error — a soft-fail: penalize (loss) + ladder to the next upstream.
                    self.record(transport.id(), None);
                    counters.soft_fails.fetch_add(1, Ordering::Relaxed);
                    tried += 1;
                }
                Err(_) => {
                    // Per-transport timeout — a soft-fail: penalize (loss) + ladder.
                    self.record(transport.id(), None);
                    counters.soft_fails.fetch_add(1, Ordering::Relaxed);
                    tried += 1;
                }
            }
        }
        // Exhausted: every ordered leg soft-failed/errored/timed out — no upstream got through. Fail-open to
        // None (the `exchange` exhaustion contract). `tried > 0` guards the counter so an empty order (never
        // produced by the resolver, which passes `0..n`) is not miscounted as an exhausted ladder.
        if tried > 0 {
            counters.exhausted.fetch_add(1, Ordering::Relaxed);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    //! R6 (the `--all-servers` race) + R7 (the RTT/loss EWMA) live HERE, NOT in the std-only
    //! `p12_evoke_integration.rs` (its header `:33-37` keeps it transport-free). These are
    //! `#[tokio::test]` because the race + the per-transport timeout need a reactor; the flavor is
    //! `current_thread`, matching the production runtime shape (`mod.rs:181`) so a passing race here
    //! is a passing race on the phone — CONCURRENT, never thread-pool-parallel.

    use super::*;
    use crate::resolver::transport::{ExchangeFuture, Transport, TransportError, WarmFuture};

    /// A controllable mock transport: a stable `id`, a settle `delay`, and an `ok`/err outcome. It
    /// touches no socket — `exchange` just sleeps `delay` then yields the canned result. This is the
    /// race fixture; it never parses DNS (the pool deals in opaque bytes, exactly like a real one).
    struct MockTransport {
        id: String,
        delay: Duration,
        ok: bool,
        body: Vec<u8>,
    }

    impl MockTransport {
        fn ok(id: &str, delay_ms: u64, body: &[u8]) -> Arc<dyn Transport> {
            Arc::new(MockTransport {
                id: id.to_string(),
                delay: Duration::from_millis(delay_ms),
                ok: true,
                body: body.to_vec(),
            })
        }
        fn err(id: &str, delay_ms: u64) -> Arc<dyn Transport> {
            Arc::new(MockTransport {
                id: id.to_string(),
                delay: Duration::from_millis(delay_ms),
                ok: false,
                body: Vec::new(),
            })
        }
    }

    impl Transport for MockTransport {
        fn id(&self) -> &str {
            &self.id
        }
        fn exchange<'a>(&'a self, _query_wire: &'a [u8]) -> ExchangeFuture<'a> {
            Box::pin(async move {
                tokio::time::sleep(self.delay).await;
                if self.ok {
                    Ok(self.body.clone())
                } else {
                    Err(TransportError::Exchange("mock".into()))
                }
            })
        }
    }

    // ---- ★ E-FIX r5: the pool-level loopback-proxy flag (the query-feed no-double-count law) ----

    /// A mock that marks itself as the loopback Go-proxy arm (the Do53 override).
    struct LoopbackMock;
    impl Transport for LoopbackMock {
        fn id(&self) -> &str {
            "do53:proxy"
        }
        fn exchange<'a>(&'a self, _query_wire: &'a [u8]) -> ExchangeFuture<'a> {
            Box::pin(async move { Err(TransportError::Exchange("unused".into())) })
        }
        fn is_loopback_proxy(&self) -> bool {
            true
        }
    }

    #[test]
    fn pool_flags_the_loopback_proxy_arm_at_construction() {
        // MODE 2 shape (direct transports only) → false: the feed owns the live-forward rows.
        let direct = Pool::new(
            vec![MockTransport::ok("dnscrypt:a", 0, b"X")],
            Duration::from_millis(50),
        );
        assert!(!direct.has_loopback_proxy());
        // MODE 1 shape (the loopback do53 arm present) → true: the Go writer owns them.
        let go = Pool::new(
            vec![Arc::new(LoopbackMock) as Arc<dyn Transport>],
            Duration::from_millis(50),
        );
        assert!(go.has_loopback_proxy());
        // An empty pool is trivially not the Go mode.
        assert!(!Pool::new(Vec::new(), Duration::from_millis(50)).has_loopback_proxy());
    }

    // ---- R6: `--all-servers` happy-eyeballs race ----

    #[tokio::test(flavor = "current_thread")]
    async fn all_servers_race_first_ok_wins_each_still_validated() {
        // Three transports: a SLOW Ok, a fast Ok, and a fast error. The fast Ok must win regardless of
        // pool ORDER (it is listed LAST), and the fast error must NOT short-circuit the win. The pool
        // returns the winner's opaque bytes; the resolver (not the pool) runs validate_response —
        // here we assert the bytes are the FAST upstream's, proving "first Ok wins, order-independent".
        // Real-time delays (the crate carries no tokio `test-util`, so no paused clock) — kept small so
        // the suite stays sub-second, with a wide slow/fast gap so the race outcome is deterministic.
        let pool = Pool::new(
            vec![
                MockTransport::ok("slow", 80, b"SLOW".to_vec().as_slice()),
                MockTransport::err("fast-err", 2),
                MockTransport::ok("fast-ok", 4, b"FAST".to_vec().as_slice()),
            ],
            Duration::from_millis(5000),
        );
        let got = pool.exchange_all(b"\x00\x00").await;
        assert_eq!(
            got.as_deref(),
            Some(&b"FAST"[..]),
            "the fastest Ok wins, not the listed-first slow one"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn all_servers_race_a_slow_transport_never_blocks_a_fast_one() {
        // The pathological order: a SLOW transport listed FIRST, a 1 ms transport listed SECOND. A
        // sequential ladder would pay the slow leg in full; the race returns as soon as the snappy leg
        // settles, proving the slow one never blocks the fast one (real-time, no paused clock available).
        let pool = Pool::new(
            vec![
                MockTransport::ok("glacial", 80, b"GLACIAL".to_vec().as_slice()),
                MockTransport::ok("snappy", 1, b"SNAPPY".to_vec().as_slice()),
            ],
            Duration::from_millis(5000),
        );
        let got = pool.exchange_all(b"\x00\x00").await;
        assert_eq!(
            got.as_deref(),
            Some(&b"SNAPPY"[..]),
            "the snappy transport wins; the glacial one never blocks it"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn all_servers_race_all_error_yields_none_like_exchange() {
        // Every transport errors ⇒ None — the SAME exhaustion contract as `exchange`, so the resolver's
        // `Ok(Ok(None)) ⇒ transport_miss` arm is unchanged whether StrictOrder or AllServers is chosen.
        let pool = Pool::new(
            vec![MockTransport::err("e1", 5), MockTransport::err("e2", 8)],
            Duration::from_millis(5000),
        );
        assert_eq!(
            pool.exchange_all(b"\x00\x00").await,
            None,
            "all-error race exhausts to None"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn all_servers_race_empty_pool_is_none() {
        let pool = Pool::new(Vec::new(), Duration::from_millis(5000));
        assert_eq!(
            pool.exchange_all(b"\x00\x00").await,
            None,
            "an empty pool never strands the caller"
        );
    }

    // ---- ★ 2.1.18-absorb: the warm-before-stopwatch seam (latency excludes setup) ----
    //
    // NO wall-clock thresholds here (the [[host-hardware-reality]] law above): the seam is proven by
    // (a) ORDER — `warm_setup` completes before `exchange` begins (the stopwatch starts on the line
    // between them, so setup time is structurally outside the timed window), and (b) FAIL-OPEN — a
    // HUNG warm_setup is abandoned at the per-query deadline (virtual clock, zero real waiting) and
    // the leg still exchanges + answers: a dead cert server must never wedge the ladder.

    /// Records the call ORDER: `warm_setup` pushes "warm", `exchange` pushes "exchange".
    struct SequenceMock {
        seq: Arc<Mutex<Vec<&'static str>>>,
    }
    impl Transport for SequenceMock {
        fn id(&self) -> &str {
            "mock:sequence"
        }
        fn warm_setup<'a>(&'a self) -> WarmFuture<'a> {
            Box::pin(async move {
                self.seq.lock().unwrap().push("warm");
            })
        }
        fn exchange<'a>(&'a self, _query_wire: &'a [u8]) -> ExchangeFuture<'a> {
            Box::pin(async move {
                self.seq.lock().unwrap().push("exchange");
                Ok(vec![0xAA])
            })
        }
    }

    #[tokio::test]
    async fn warm_setup_completes_before_the_timed_exchange_begins() {
        let seq = Arc::new(Mutex::new(Vec::new()));
        let pool = Pool::new(
            vec![Arc::new(SequenceMock { seq: seq.clone() }) as Arc<dyn Transport>],
            Duration::from_secs(2),
        );
        let got = pool.exchange(b"\x00\x00").await;
        assert_eq!(got, Some(vec![0xAA]));
        assert_eq!(
            *seq.lock().unwrap(),
            vec!["warm", "exchange"],
            "setup must fully settle BEFORE the exchange (the stopwatch sits between them)"
        );
    }

    /// A warm_setup that never returns inside any sane deadline (a dead/fragment-blackholed cert
    /// server); the exchange itself is instant (the cert turned out to be cached, say).
    struct HungWarmMock;
    impl Transport for HungWarmMock {
        fn id(&self) -> &str {
            "mock:hung-warm"
        }
        fn warm_setup<'a>(&'a self) -> WarmFuture<'a> {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            })
        }
        fn exchange<'a>(&'a self, _query_wire: &'a [u8]) -> ExchangeFuture<'a> {
            Box::pin(async move { Ok(vec![0xBB]) })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn hung_warm_setup_is_abandoned_at_the_deadline_and_the_leg_still_answers() {
        // start_paused: the 3600-s "hang" and the 2-s deadline advance on the VIRTUAL clock — zero
        // real waiting, fully deterministic under suite load. The timeout around warm_setup fires,
        // the warm future is dropped, and the leg proceeds to its (timed) exchange unharmed.
        let pool = Pool::new(
            vec![Arc::new(HungWarmMock) as Arc<dyn Transport>],
            Duration::from_secs(2),
        );
        let got = pool.exchange(b"\x00\x00").await;
        assert_eq!(
            got,
            Some(vec![0xBB]),
            "a hung setup must be abandoned at the deadline, never wedging the leg"
        );
    }

    // ---- R7: per-transport RTT/loss EWMA — DATA ONLY (NO ranking assertion: that is P10 policy) ----
    //
    // The EWMA MATH (`TransportStats::observe`) is a PURE synchronous fn, so its invariants are tested
    // DIRECTLY with SYNTHETIC `Duration`s — ZERO sleeps, ZERO runtime, fully DETERMINISTIC. This is the
    // load-robust way: racing real `tokio::time::sleep`s against a 400-test suite on a near-90% i7
    // ([[host-hardware-reality]]) makes any wall-clock threshold a flaky false-red. We test the contract
    // (monotone · bounded · seeds-without-zero-bias · converges · discriminates) on the math, and keep
    // ONE async smoke that the pool actually RECORDS through `exchange_all` (asserting only the
    // load-independent facts: a slot exists, samples advanced, bounds hold).

    #[test]
    fn ewma_seeds_on_first_rtt_without_warmup_bias() {
        // The seed branch (`None => ms`) takes the RAW first measurement — NOT a blend toward a phantom
        // zero. A warm-up bug would have produced a FRACTION of the real RTT on sample 1.
        let mut s = TransportStats::new();
        s.observe(Some(Duration::from_millis(30)));
        assert_eq!(
            s.rtt_ms_ewma,
            Some(30.0),
            "first RTT seeds to the raw measurement exactly, no zero-blend"
        );
        assert_eq!(
            s.loss_ewma, 0.0,
            "a successful first sample contributes zero loss"
        );
        assert_eq!(s.samples, 1);
    }

    #[test]
    fn ewma_rtt_is_bounded_by_the_observed_envelope_and_converges() {
        // Feed a constant 40ms: the EWMA must CONVERGE to 40 (a convex blend of identical samples is the
        // sample), stay finite, and never leave the observed envelope [40,40]. Bounded + monotone-to-fix.
        let mut s = TransportStats::new();
        for _ in 0..50 {
            s.observe(Some(Duration::from_millis(40)));
        }
        let rtt = s.rtt_ms_ewma.expect("learned an RTT");
        assert!(
            (rtt - 40.0).abs() < 1e-9,
            "constant 40ms samples converge the EWMA to exactly 40, got {rtt}"
        );
        // Mixed bounded samples: the EWMA stays within [min,max] of the observed values (convex blend).
        let mut m = TransportStats::new();
        for d in [10u64, 90, 10, 90, 50, 30] {
            m.observe(Some(Duration::from_millis(d)));
        }
        let r = m.rtt_ms_ewma.expect("learned an RTT");
        assert!(
            (10.0..=90.0).contains(&r),
            "EWMA stays inside the observed [10,90] envelope, got {r}"
        );
        assert!(r.is_finite(), "EWMA is always finite for finite inputs");
    }

    #[test]
    fn ewma_loss_stays_in_unit_interval_and_discriminates() {
        // An always-failing transport (every `observe(None)`) drives loss toward 1.0 but NEVER past it;
        // an always-succeeding one drives it toward 0.0 but NEVER below it. Both bounded in [0,1], and
        // the failing one's loss is strictly the larger — the discrimination signal P10 will rank on.
        let mut dead = TransportStats::new();
        let mut healthy = TransportStats::new();
        for _ in 0..30 {
            dead.observe(None);
            healthy.observe(Some(Duration::from_millis(15)));
        }
        assert!(
            (0.0..=1.0).contains(&dead.loss_ewma),
            "dead loss EWMA bounded by [0,1], got {}",
            dead.loss_ewma
        );
        assert!(
            (0.0..=1.0).contains(&healthy.loss_ewma),
            "healthy loss EWMA bounded by [0,1], got {}",
            healthy.loss_ewma
        );
        assert!(
            dead.loss_ewma > healthy.loss_ewma,
            "the dead transport's loss EWMA exceeds the healthy one's"
        );
        assert!(
            dead.loss_ewma > 0.99,
            "30 consecutive losses drive the EWMA arbitrarily close to 1.0, got {}",
            dead.loss_ewma
        );
        assert!(
            healthy.loss_ewma < 0.01,
            "30 consecutive successes drive the EWMA arbitrarily close to 0.0, got {}",
            healthy.loss_ewma
        );
        // A never-succeeding transport learns NO RTT — an erroring observation folds only a loss sample.
        assert!(
            dead.rtt_ms_ewma.is_none(),
            "a never-succeeding transport learns no RTT"
        );
    }

    #[test]
    fn ewma_samples_count_is_monotone_and_saturating() {
        let mut s = TransportStats::new();
        for i in 1..=5u64 {
            s.observe(if i % 2 == 0 {
                None
            } else {
                Some(Duration::from_millis(5))
            });
            assert_eq!(s.samples, i, "samples increments once per observation");
        }
    }

    #[test]
    fn warm_start_seeds_unlearned_transports_and_spares_learned_ones() {
        // The #98 boot warm-start consumer of the durable RTT hints: seed each UNLEARNED transport's RTT
        // EWMA from its last-known hint, but NEVER clobber a transport that already learned a live RTT.
        let pool = Pool::new(
            vec![
                MockTransport::ok("cold-a", 0, b"x"),
                MockTransport::ok("cold-b", 0, b"x"),
                MockTransport::ok("hot", 0, b"x"),
            ],
            Duration::from_millis(1000),
        );
        // "hot" already learned a live 12ms RTT this session (a real sample); the two cold ones never did.
        pool.record("hot", Some(Duration::from_millis(12)));

        // Durable warm hints: a fast value for cold-a, a STALE value for hot (must NOT win over live),
        // nothing for cold-b.
        let seeded = pool.warm_start_rtt(|id| match id {
            "cold-a" => Some(40u32),
            "hot" => Some(999u32), // stale — the live 12ms sample must be preserved.
            _ => None,             // cold-b has no hint → stays cold.
        });
        assert_eq!(
            seeded, 1,
            "only the UNLEARNED transport that HAS a hint is seeded (cold-a)"
        );

        let stats = pool.transport_stats();
        assert_eq!(
            stats["cold-a"].rtt_ms_ewma,
            Some(40.0),
            "a cold transport is warm-started from its durable hint"
        );
        assert!(
            stats["cold-b"].rtt_ms_ewma.is_none(),
            "a cold transport with no hint stays cold"
        );
        let hot = stats["hot"].rtt_ms_ewma.expect("hot learned a live RTT");
        assert!(
            (hot - 12.0).abs() < 1e-9,
            "a transport with a live RTT is NOT clobbered by a stale warm hint, got {hot}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exchange_all_records_the_winner_on_the_live_path_loadrobust_smoke() {
        // WIRING smoke: prove the R7 hook fires on the LIVE race path (not just in the unit math). The
        // load-robust invariant of a SHORT-CIRCUITING race: the WINNER always records its RTT (the loser
        // racers are CANCELLED the instant the winner returns, so a loser only records if it happened to
        // settle first — NOT guaranteed under load, so we never assert on the loser's slot). Asserts only
        // load-independent facts: the winner's bytes came back, its slot has a sample + a bounded EWMA.
        let pool = Pool::new(
            vec![
                MockTransport::err("slow-loser", 200), // listed first but slow → almost surely cancelled
                MockTransport::ok("winner", 1, b"WIN".to_vec().as_slice()),
            ],
            Duration::from_millis(5000),
        );
        let got = pool.exchange_all(b"\x00\x00").await;
        assert_eq!(
            got.as_deref(),
            Some(&b"WIN"[..]),
            "the fast Ok transport wins the live race"
        );
        let stats = pool.transport_stats();
        let winner = stats.get("winner").expect("the winner has a stats slot");
        assert!(
            winner.samples >= 1,
            "the winning exchange recorded an R7 sample on the live path"
        );
        let rtt = winner
            .rtt_ms_ewma
            .expect("the winner folded its RTT into the EWMA");
        assert!(
            rtt.is_finite() && rtt > 0.0,
            "the recorded RTT is a positive finite ms value, got {rtt}"
        );
        assert!(
            (0.0..=1.0).contains(&winner.loss_ewma),
            "the winner's loss EWMA is bounded, got {}",
            winner.loss_ewma
        );
        // Every configured transport always has a PRE-SEEDED slot (Pool::new), even one that was cancelled.
        assert!(
            stats.contains_key("slow-loser"),
            "every configured transport has a pre-seeded stats slot"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn strategy_default_is_strict_order() {
        // The base `.so` ships StrictOrder — the dead-code-until-wired default. A Default derive proves
        // a Strategy-typed field initializes to today's sequential behaviour with no Expert opt-in.
        assert_eq!(Strategy::default(), Strategy::StrictOrder);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn round_robin_walks_the_ring_naming_each_transport_in_turn() {
        // The privacy spread: consecutive queries START at consecutive transports, so the query.log
        // winner (last_winner) walks the WHOLE slate instead of pinning one. Three ok mocks, three
        // queries ⇒ each names a different upstream in ring order; a fourth wraps back to the head.
        let pool = Pool::new(
            vec![
                MockTransport::ok("srv-a", 0, b"A"),
                MockTransport::ok("srv-b", 0, b"B"),
                MockTransport::ok("srv-c", 0, b"C"),
            ],
            Duration::from_millis(5000),
        );
        let mut walk = Vec::new();
        for _ in 0..3 {
            let _ = pool.exchange_round_robin(b"\x00\x00").await;
            walk.push(pool.last_winner_id().expect("a transport answered"));
        }
        assert_eq!(
            walk,
            vec![
                "srv-a".to_string(),
                "srv-b".to_string(),
                "srv-c".to_string()
            ],
            "round-robin walks the ring in order — every server used, not one pinned"
        );
        let _ = pool.exchange_round_robin(b"\x00\x00").await;
        assert_eq!(
            pool.last_winner_id().as_deref(),
            Some("srv-a"),
            "the ring wraps back to the head on the 4th query"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn round_robin_falls_forward_past_a_dead_upstream() {
        // Resilience: if the cursor lands on a down transport, the ladder falls FORWARD to the next live
        // one (never strands the query) — the same exhaustion contract as `exchange`, and the row
        // attributes to the REAL winner, not the dead cursor slot.
        let pool = Pool::new(
            vec![
                MockTransport::err("dead-head", 0), // rr_cursor starts here on query 1
                MockTransport::ok("live-b", 0, b"B"),
                MockTransport::ok("live-c", 0, b"C"),
            ],
            Duration::from_millis(5000),
        );
        let got = pool.exchange_round_robin(b"\x00\x00").await;
        assert_eq!(
            got.as_deref(),
            Some(&b"B"[..]),
            "fell forward past the dead head to the next live upstream"
        );
        assert_eq!(
            pool.last_winner_id().as_deref(),
            Some("live-b"),
            "the row attributes to the real winner, not the dead cursor slot"
        );
    }

    #[test]
    fn round_robin_toggle_takes_egress_precedence() {
        // The toggle flips lock-free and WINS the egress precedence (checked before Fastest/all-servers)
        // so arming it at the serve makes the walk govern regardless of the other modes.
        let prev = round_robin_enabled();
        set_round_robin(true);
        assert!(round_robin_enabled(), "flips ON");
        assert_eq!(
            active_strategy(),
            Strategy::RoundRobin,
            "round-robin wins the egress precedence when armed"
        );
        set_round_robin(false);
        assert!(!round_robin_enabled(), "flips OFF");
        set_round_robin(prev); // restore
    }

    // ---- SOLVE cross (slice 2): the verdict-gated, health-ordered resilient ladder ----
    use std::sync::atomic::AtomicU64;

    /// A test-only verdict that classifies the MOCK bodies (`b"THROUGH"`/`b"NX"`/anything-else) WITHOUT
    /// parsing DNS — the real `dns::solve_verdict` header classifier is unit-tested in `dns.rs`. This keeps
    /// the LADDER tests (ordering / retry / terminal-stop / exhaustion / EWMA) independent of the codec.
    fn mock_verdict(body: &[u8]) -> crate::dns::SolveVerdict {
        use crate::dns::{SoftReason, SolveVerdict, TerminalReason};
        match body {
            b"THROUGH" => SolveVerdict::GotThrough,
            b"NX" => SolveVerdict::Terminal(TerminalReason::NxDomain),
            _ => SolveVerdict::SoftFail(SoftReason::ServerFailure),
        }
    }

    /// Four zeroed atomics backing a `SolveCounters` — indexed retries[0] / soft_fails[1] / hard[2] / exh[3].
    fn counter_store() -> [AtomicU64; 4] {
        [
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
        ]
    }
    fn counters_of(store: &[AtomicU64; 4]) -> SolveCounters<'_> {
        SolveCounters {
            retries: &store[0],
            soft_fails: &store[1],
            hard_negatives: &store[2],
            exhausted: &store[3],
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn solve_ladder_stops_at_first_got_through_and_counts_the_retry() {
        // [soft, through] — the head soft-fails, the ladder advances and the 2nd gets through.
        let pool = Pool::new(
            vec![
                MockTransport::ok("soft", 1, b"SOFT".to_vec().as_slice()),
                MockTransport::ok("through", 1, b"THROUGH".to_vec().as_slice()),
            ],
            Duration::from_millis(5000),
        );
        let store = counter_store();
        let verdict: &dyn Fn(&[u8]) -> crate::dns::SolveVerdict = &mock_verdict;
        let got = pool
            .solve_exchange(b"\x00\x00", &[0, 1], verdict, &counters_of(&store))
            .await;
        assert_eq!(
            got.as_deref(),
            Some(&b"THROUGH"[..]),
            "the ladder gets THROUGH"
        );
        assert_eq!(store[1].load(Ordering::Relaxed), 1, "one soft-fail leg");
        assert_eq!(
            store[0].load(Ordering::Relaxed),
            1,
            "one retry (laddered past leg 1)"
        );
        assert_eq!(store[2].load(Ordering::Relaxed), 0, "no terminal");
        assert_eq!(store[3].load(Ordering::Relaxed), 0, "not exhausted");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn solve_ladder_terminal_nxdomain_stops_before_the_rest() {
        // [soft, nx, through] — the NX is TERMINAL: the ladder returns it and NEVER reaches "through".
        let pool = Pool::new(
            vec![
                MockTransport::ok("soft", 1, b"SOFT".to_vec().as_slice()),
                MockTransport::ok("nx", 1, b"NX".to_vec().as_slice()),
                MockTransport::ok("through", 1, b"THROUGH".to_vec().as_slice()),
            ],
            Duration::from_millis(5000),
        );
        let store = counter_store();
        let verdict: &dyn Fn(&[u8]) -> crate::dns::SolveVerdict = &mock_verdict;
        let got = pool
            .solve_exchange(b"\x00\x00", &[0, 1, 2], verdict, &counters_of(&store))
            .await;
        assert_eq!(
            got.as_deref(),
            Some(&b"NX"[..]),
            "the authoritative negative is returned, not THROUGH"
        );
        assert_eq!(
            store[2].load(Ordering::Relaxed),
            1,
            "one hard-negative (NXDOMAIN)"
        );
        assert_eq!(
            store[1].load(Ordering::Relaxed),
            1,
            "one soft-fail before it"
        );
        assert_eq!(
            store[0].load(Ordering::Relaxed),
            1,
            "one retry (laddered to the NX)"
        );
        assert_eq!(store[3].load(Ordering::Relaxed), 0, "not exhausted");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn solve_ladder_all_soft_fails_exhausts_to_none_like_exchange() {
        let pool = Pool::new(
            vec![
                MockTransport::ok("s1", 1, b"SOFT".to_vec().as_slice()),
                MockTransport::ok("s2", 1, b"SOFT".to_vec().as_slice()),
            ],
            Duration::from_millis(5000),
        );
        let store = counter_store();
        let verdict: &dyn Fn(&[u8]) -> crate::dns::SolveVerdict = &mock_verdict;
        let got = pool
            .solve_exchange(b"\x00\x00", &[0, 1], verdict, &counters_of(&store))
            .await;
        assert_eq!(
            got, None,
            "all soft-fails exhaust to None (the exchange contract)"
        );
        assert_eq!(store[1].load(Ordering::Relaxed), 2, "both legs soft-failed");
        assert_eq!(
            store[3].load(Ordering::Relaxed),
            1,
            "the ladder exhausted once"
        );
        assert_eq!(
            store[0].load(Ordering::Relaxed),
            0,
            "no retry counted on a full miss"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn solve_ladder_transport_error_is_a_soft_fail_and_ladders_on() {
        // A channel error (not a DNS reply) is a soft-fail: the ladder skips to the healthy upstream.
        let pool = Pool::new(
            vec![
                MockTransport::err("dead", 1),
                MockTransport::ok("through", 1, b"THROUGH".to_vec().as_slice()),
            ],
            Duration::from_millis(5000),
        );
        let store = counter_store();
        let verdict: &dyn Fn(&[u8]) -> crate::dns::SolveVerdict = &mock_verdict;
        let got = pool
            .solve_exchange(b"\x00\x00", &[0, 1], verdict, &counters_of(&store))
            .await;
        assert_eq!(got.as_deref(), Some(&b"THROUGH"[..]));
        assert_eq!(
            store[1].load(Ordering::Relaxed),
            1,
            "the channel error counted as a soft-fail"
        );
        assert_eq!(store[0].load(Ordering::Relaxed), 1, "one retry");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn solve_ladder_penalizes_a_soft_fail_as_loss_not_rtt() {
        // THE SOLVE-cross edge: a fast SOFT-fail is recorded as a LOSS (so ranking demotes it), while the
        // through upstream records its RTT. `exchange` would have rewarded the soft-failer with a fast RTT.
        let pool = Pool::new(
            vec![
                MockTransport::ok("softfast", 1, b"SOFT".to_vec().as_slice()),
                MockTransport::ok("through", 1, b"THROUGH".to_vec().as_slice()),
            ],
            Duration::from_millis(5000),
        );
        let store = counter_store();
        let verdict: &dyn Fn(&[u8]) -> crate::dns::SolveVerdict = &mock_verdict;
        let _ = pool
            .solve_exchange(b"\x00\x00", &[0, 1], verdict, &counters_of(&store))
            .await;
        let stats = pool.transport_stats();
        let soft = stats.get("softfast").expect("soft slot");
        assert!(soft.samples >= 1, "the soft-failer recorded a sample");
        assert!(
            soft.rtt_ms_ewma.is_none(),
            "a soft-fail records NO rtt (loss only) — it is not rewarded"
        );
        assert!(soft.loss_ewma > 0.0, "the soft-failer took a loss sample");
        let through = stats.get("through").expect("through slot");
        assert!(
            through.rtt_ms_ewma.is_some(),
            "the through upstream recorded its rtt"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn solve_ladder_empty_pool_is_none() {
        let pool = Pool::new(Vec::new(), Duration::from_millis(5000));
        let store = counter_store();
        let verdict: &dyn Fn(&[u8]) -> crate::dns::SolveVerdict = &mock_verdict;
        assert_eq!(
            pool.solve_exchange(b"\x00\x00", &[], verdict, &counters_of(&store))
                .await,
            None
        );
        assert_eq!(
            store[3].load(Ordering::Relaxed),
            0,
            "an empty pool is not a laddered exhaustion"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn solve_ladder_head_leg_through_counts_no_retry() {
        let pool = Pool::new(
            vec![
                MockTransport::ok("through", 1, b"THROUGH".to_vec().as_slice()),
                MockTransport::ok("soft", 1, b"SOFT".to_vec().as_slice()),
            ],
            Duration::from_millis(5000),
        );
        let store = counter_store();
        let verdict: &dyn Fn(&[u8]) -> crate::dns::SolveVerdict = &mock_verdict;
        let got = pool
            .solve_exchange(b"\x00\x00", &[0, 1], verdict, &counters_of(&store))
            .await;
        assert_eq!(got.as_deref(), Some(&b"THROUGH"[..]));
        assert_eq!(
            store[0].load(Ordering::Relaxed),
            0,
            "the head leg won — no retry"
        );
        assert_eq!(store[1].load(Ordering::Relaxed), 0, "no soft-fail");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn solve_ladder_honors_the_ranked_order() {
        // The order [1,0] tries transport index 1 FIRST — it gets through, index 0 is never touched.
        let pool = Pool::new(
            vec![
                MockTransport::ok("soft", 1, b"SOFT".to_vec().as_slice()),
                MockTransport::ok("through", 1, b"THROUGH".to_vec().as_slice()),
            ],
            Duration::from_millis(5000),
        );
        let store = counter_store();
        let verdict: &dyn Fn(&[u8]) -> crate::dns::SolveVerdict = &mock_verdict;
        let got = pool
            .solve_exchange(b"\x00\x00", &[1, 0], verdict, &counters_of(&store))
            .await;
        assert_eq!(
            got.as_deref(),
            Some(&b"THROUGH"[..]),
            "the ranked-first upstream wins"
        );
        assert_eq!(
            store[1].load(Ordering::Relaxed),
            0,
            "the soft leg was ranked last, never tried"
        );
        assert_eq!(
            store[0].load(Ordering::Relaxed),
            0,
            "no retry — the ranked head got through"
        );
    }
}
