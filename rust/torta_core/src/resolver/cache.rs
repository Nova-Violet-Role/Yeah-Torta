/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! The answer cache — Wave 2e (the full design the 2b stub described).
//!
//! 2e finishes the cache the 2b stub (`Vec<u8>` value, insertion-order eviction, never auto-expires)
//! left as TODOs. The shape is a bounded LRU keyed on the **validated** `(qname_lower,qtype,qclass)`
//! tuple, with:
//!   - **TTL-aware expiry** — every entry carries `{wire, stored, ttl_secs}` and is aged on `get()`,
//!     closing the **C1 forever-cache hazard**. The per-record TTL is read from the validated answer
//!     via [`crate::dns::answer_records`] (un-dead-coding `AnswerRecord.ttl`, dns.rs:191), taking the
//!     MIN across Answer records — the standard resolver-cache rule.
//!   - **Negative caching** — a validated NXDOMAIN/NODATA denial is cached with a **bounded** neg-TTL
//!     so a denial can never pin forever (the exact forever-cache bug the 2b stub avoided by not
//!     caching denials at all). The neg-TTL is supplied by the caller (the SOA-minimum once the
//!     Authority skimmer surfaces it) and is **hard-clamped** to [`Cache::neg_ttl_ceiling`].
//!   - **True LRU** — `get()` touches the key to MRU in the recency index (D16: O(log n), clone-free
//!     hash-first lookup — never an O(n) scan per hit), so eviction drops the genuinely
//!     least-recently-used entry, not merely the oldest-inserted.
//!   - **min/max TTL clamps** — `put` clamps the derived TTL into `[ttl_floor, ttl_ceiling]`. The floor
//!     is an Expert-only `configure()` knob (default 0 = off); the ceiling has a sane default and bounds
//!     how long a stale/rotated IP survives (insurance for P10 rotation / a blocklist re-arm).
//!   - **Epoch = blocklist fingerprint** — every entry stamps the blocklist fingerprint it was stored
//!     under; `get()` re-reads the LIVE fingerprint ([`crate::blocklist::installed_fingerprint`],
//!     blocklist.rs:581) and treats an entry whose epoch differs as a MISS. This is the load-bearing
//!     new invariant: a blocklist re-arm WITHOUT a `configure()` rebuild still invalidates stale
//!     answers (configure's whole-`Inner` swap was the only invalidation in 2b, mod.rs:217).
//!   - **serve-stale (RFC 8767)** — OFF by default (`serve_stale_secs = 0`). When enabled, an expired
//!     entry may still be served up to the staleness bound; it STILL honors the epoch (a stale answer
//!     for a now-blocked name is never served). The background-refresh half (which collides with the
//!     T24 "spawn no tasks" firewall) is the caller's job — this module only retains the bytes.
//!
//! **MaskSolver CACHE-cross (slice 3 — the dnsmasq CACHE form × RAM⊗NAND, original Rust, EXCEEDS both):**
//!   - **serve-stale-WHILE-REVALIDATE SIGNAL** — [`Cache::get_hit`] reports [`Freshness::Fresh`] vs
//!     [`Freshness::Stale`] so the RESOLVER fires ONE coalesced background revalidation (the cache still
//!     spawns nothing — T24). [`Cache::get`] stays the byte-identical `Option<Vec<u8>>` wrapper.
//!   - **tri-state serve-stale** — `StaleMode` `Off`/`Window(d)`/`Unbounded` (dnsmasq's `0`/`<n>`/`-1`).
//!   - **COLD-BOOT serve-stale (the original neither source has)** — the v2 snapshot persists stale-eligible
//!     entries with a second wall-clock deadline, so a just-booted device serves-stale INSTANTLY from its
//!     own NAND⊗RAM while the resolver revalidates. dnsmasq has NO persistence; the v1 cache was fresh-only.
//!   - **rebind PERSIST-gate** — [`Cache::restore_gated`] re-runs the live rebind decision on every
//!     rehydrated (incl. cold-boot-stale) wire, so a poison answer can never be resurrected from NAND.
//!   - **RFC 2308 SOA-derived neg-TTL** — [`Cache::put_negative_from_response`] via
//!     [`crate::dns::negative_ttl_from_soa`] (`min(SOA TTL, SOA MINIMUM)`), still hard-clamped.
//!   - **IMMORTAL host records** — [`Cache::put_immortal`] pins a record exempt from TTL expiry AND cap
//!     eviction (dnsmasq's `F_IMMORTAL`), distinct from the TTL-clamped/evictable [`Cache::put_local`].
//!   - **explicit-0 do-not-cache** — [`Cache::set_honor_zero_ttl`] opt-in (default off = byte-identical).
//!
//! **NEVER cache failure as success.** SERVFAIL(2)/REFUSED(5) are already rejected upstream by
//! `dns::validate_response` (dns.rs:291); the resolver only calls [`Cache::put`] / [`Cache::put_negative`]
//! with a `validate_response`-approved answer, and negatives carry a bounded TTL — there is no path in
//! this module that stores a failure as a positive.
//!
//! The cache is keyed on the question tuple, NOT raw query bytes, because two queries for the same name
//! differ only in their transaction ID — caching on bytes would never hit. We store the validated
//! response and the caller rewrites its ID (and re-echoes 0x20 casing) on the way out.

#![forbid(unsafe_code)]
// Additive P12 seams (N2 cacheable-type set, R4 local-ttl clamp, N3 AD-bit cache discipline) ship
// dead-code-until-wired: the JNI+Kotlin Expert toggles drive them, so the `.so` stays byte-identical
// until the seam is wired. The 2e core fns above are live; the additive `pub` surface below is gated.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::dns::DnsQuestion;

/// The DNS wire-byte that carries the **AD (Authenticated Data)** bit, RFC 4035 §3.2.3: header byte 3,
/// mask `0x20` (`dns-protocol.h` `HB4_AD 0x20`). AD shares byte 3 with the RCODE low-nibble and the
/// Z/CD bits, so the mask is **precise** — only `0x20` is ever touched. (N3.)
const AD_BIT_MASK: u8 = 0x20;

/// The MEASURED default cacheable-type set (N2). The dnsmasq man page overstates the default as
/// {A,AAAA,CNAME,SRV}, but the canonical C **excludes CNAME as standalone cache data** (`rfc1035.c`
/// around the `qtype != T_CNAME` gate: *"do not cache data from CNAME queries"* — CNAME is chain-
/// followed only, never cached as terminal data). Clean-roomed from the measured set, NOT the man page:
///   A = 1 · AAAA = 28 · SRV = 33 · PTR = 12
/// A user may widen this (HTTPS=65, SVCB=64, TXT=16, MX=15, …) or pick the cache-all sentinel.
const DEFAULT_CACHEABLE_TYPES: [u16; 4] = [1, 28, 33, 12];

/// The service-binding RR types governed by the `DNSMASQ_CACHE_RR` Expert toggle — SVCB = 64, HTTPS = 65
/// (RFC 9460 §14.1). These are the modern records that carry HTTP/3 + ECH hints; caching them speeds the
/// happy-eyeballs path but a user may decline (e.g. to keep ECH config from being pinned across a rotation).
const RTYPE_SVCB: u16 = 64;
const RTYPE_HTTPS: u16 = 65;

/// P12 Expert toggle — `DNSMASQ_CACHE_RR` (default ON = cache HTTPS/SVCB, `PreferenceKeys.java:248`). When
/// OFF, a validated answer whose FIRST Answer record is SVCB/HTTPS is NOT cached, regardless of the
/// instance's `cacheable_types` policy (the A/AAAA/SRV/PTR default set is unaffected). Default `true`
/// mirrors the pref default. Pushed from Kotlin via `TortaCore.nativeResolverSetCacheRr`.
static CACHE_RR_ENABLED: AtomicBool = AtomicBool::new(true);

/// Set whether SVCB/HTTPS RRs are cacheable (the `DNSMASQ_CACHE_RR` Expert toggle).
pub fn set_cache_rr(on: bool) {
    CACHE_RR_ENABLED.store(on, Ordering::Relaxed);
}

/// Read the live `DNSMASQ_CACHE_RR` toggle (the SETTINGS pane read-back; `stats()` surfaces it so the
/// MaskSolver Expert pane shows the ENGINE's real state on entry, never an optimistic UI echo).
pub fn cache_rr_enabled() -> bool {
    CACHE_RR_ENABLED.load(Ordering::Relaxed)
}

// ── The DURABLE Expert cache-shape intents (2-FEED-MaskSolver SETTINGS). serve-stale + the TTL clamps
//    are per-`Cache`-instance fields (below) set at `configure()` construction — but the SETTINGS pane
//    must arm them LIVE, without a full reconfigure, and have the choice SURVIVE the next reconfigure.
//    These process-global atomics are that durable intent: `configure()` SEEDS the new Cache from them
//    (so a rebuild preserves the user's choice) and the resolver-level `set_serve_stale`/`set_ttl_*`
//    mutate the HELD instance immediately (so the knob bites now). 0 is the byte-identical default for
//    all three (serve-stale OFF · no TTL floor · ceiling→24h default), so an untouched build behaves
//    EXACTLY as before this wire. Mirrors the `CACHE_RR_ENABLED` live-toggle precedent above.
static SERVE_STALE_SECS: AtomicU64 = AtomicU64::new(0);
static TTL_FLOOR_SECS: AtomicU64 = AtomicU64::new(0);
static TTL_CEILING_SECS: AtomicU64 = AtomicU64::new(0);

/// Record the durable serve-stale window intent (0 OFF · `u64::MAX` unbounded · else window secs).
pub fn set_serve_stale_secs(secs: u64) {
    SERVE_STALE_SECS.store(secs, Ordering::Relaxed);
}
/// Record the durable positive-TTL floor intent (`min-cache-ttl`; 0 = no floor).
pub fn set_ttl_floor_secs(secs: u64) {
    TTL_FLOOR_SECS.store(secs, Ordering::Relaxed);
}
/// Record the durable positive-TTL ceiling intent (`max-cache-ttl`; 0 → the 24h default).
pub fn set_ttl_ceiling_secs(secs: u64) {
    TTL_CEILING_SECS.store(secs, Ordering::Relaxed);
}
/// The DURABLE `--cache-rr` TYPE-SET intent (the R4 `cacheable_types` policy), same pattern as the
/// three atomics above but a SET, so it needs a lock rather than an atomic.
///
/// `None` (the default) = cache every validated positive — byte-identical to the pre-wire behaviour.
/// `Some(set)` = cache only positives whose first Answer record is one of these RR types.
///
/// DISTINCT FROM `CACHE_RR_ENABLED`, and the two compose rather than duplicate: that toggle is the
/// P12 SVCB/HTTPS veto applied BEFORE this policy in [`Cache::is_type_cacheable`], so turning it off
/// declines service-binding records no matter how wide this set is. This is the general narrowing
/// knob dnsmasq spells `--cache-rr`.
static CACHEABLE_TYPES_INTENT: std::sync::Mutex<Option<Vec<u16>>> = std::sync::Mutex::new(None);

/// Record the durable cacheable-TYPE-set intent. An EMPTY slice means "cache all" (the sentinel), so
/// a UI that clears every checkbox widens rather than silently disabling the cache entirely — the
/// dangerous reading of an empty set.
pub fn set_cacheable_types_intent(types: &[u16]) {
    let mut g = CACHEABLE_TYPES_INTENT
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *g = if types.is_empty() {
        None
    } else {
        Some(types.to_vec())
    };
}

/// Record the durable intent to use the MEASURED dnsmasq default opt-in set {A, AAAA, SRV, PTR}.
pub fn set_cacheable_types_default() {
    let mut g = CACHEABLE_TYPES_INTENT
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *g = Some(DEFAULT_CACHEABLE_TYPES.to_vec());
}

/// The DURABLE explicit-0 do-not-cache intent (`Cache::set_honor_zero_ttl`). Same live+durable
/// shape as the atomics above; `false` is the byte-identical default, so an untouched build is
/// unchanged.
///
/// The engine already HONOURED this flag at the put gate (`is_cacheable_positive`); only the setter
/// was unreachable, so the behaviour was implemented and could never be switched on.
static HONOR_ZERO_TTL: AtomicBool = AtomicBool::new(false);

/// Record the durable explicit-0 do-not-cache intent.
pub fn set_honor_zero_ttl_intent(on: bool) {
    HONOR_ZERO_TTL.store(on, Ordering::Relaxed);
}

/// The durable explicit-0 do-not-cache intent — `configure()` seeds the Cache from it; the SETTINGS
/// pane reads it back (the engine's real state, never an optimistic UI echo).
pub fn honor_zero_ttl_intent() -> bool {
    HONOR_ZERO_TTL.load(Ordering::Relaxed)
}

/// THE SENTINEL, named once so the two seams that consult it cannot disagree.
///
/// `configure()` decides between `with_policy` (cache-all) and `with_cacheable_types` (narrowed),
/// and the live-arm `resolver::set_cacheable_types` decides between `set_cacheable_all` and
/// `set_cacheable_types`. Both are asking the SAME question, and both used to spell it out
/// separately as `types.is_empty()` — so a future change to what "empty" means (say, a `[0]`
/// wildcard) would have had to be made in two places, and missing one would leave the boot path
/// and the settings pane caching different things until the next reconfigure.
///
/// TRUE = cache every validated positive. A cleared settings pane WIDENS the cache; it must never
/// be read as "cache nothing", which would silently disable caching the moment a user unticked the
/// last checkbox. Proved for every RR type and every chosen set in
/// `D:/Lean/proofs/Proofs/CacheableTypes.lean` (`empty_admits_everything`, and
/// `an_empty_only_set_would_cache_nothing` which states the alternative that was rejected).
pub fn intent_is_cache_all(types: &[u16]) -> bool {
    types.is_empty()
}

/// The durable cacheable-type-set intent — `configure()` seeds the Cache from it; the SETTINGS pane
/// reads it back. Empty vec = cache-all (the `All` sentinel).
pub fn cacheable_types_intent() -> Vec<u16> {
    CACHEABLE_TYPES_INTENT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default()
}

/// The durable serve-stale window intent — `configure()` seeds the Cache from it; the SETTINGS pane reads it.
pub fn serve_stale_secs() -> u64 {
    SERVE_STALE_SECS.load(Ordering::Relaxed)
}
/// The durable positive-TTL floor intent.
pub fn ttl_floor_secs() -> u64 {
    TTL_FLOOR_SECS.load(Ordering::Relaxed)
}
/// The durable positive-TTL ceiling intent (0 = the 24h default).
pub fn ttl_ceiling_secs() -> u64 {
    TTL_CEILING_SECS.load(Ordering::Relaxed)
}

/// The DURABLE `--cache-size` intent (0 = honour the caller's `configure(cache_cap)` param; > 0 = the
/// SETTINGS pane's staged override). `configure()` prefers this when non-zero so a reconfigure preserves
/// the user's chosen size; the resolver-level `set_cache_cap` mutates the HELD instance immediately
/// (evict-down) so the knob bites now. 0 is byte-identical to the pre-wire behaviour. Same live+durable
/// pattern as the serve-stale / TTL intents above.
static CACHE_CAP_INTENT: AtomicUsize = AtomicUsize::new(0);

/// Record the durable `--cache-size` intent (0 = defer to the `configure()` param, else the override).
pub fn set_cache_cap_intent(cap: usize) {
    CACHE_CAP_INTENT.store(cap, Ordering::Relaxed);
}
/// The durable `--cache-size` intent — `configure()` prefers it when > 0; the SETTINGS pane reads it back.
pub fn cache_cap_intent() -> usize {
    CACHE_CAP_INTENT.load(Ordering::Relaxed)
}

/// The cache key — the validated question tuple. Lowercased qname (DNS is case-insensitive) so two
/// differently-cased questions for the same name collapse to one entry.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    qname: String,
    qtype: u16,
    qclass: u16,
}

impl Key {
    fn from_question(q: &DnsQuestion) -> Self {
        // parse_question already lowercases qname.
        Key {
            qname: q.qname.clone(),
            qtype: q.qtype,
            qclass: q.qclass,
        }
    }

    /// D16 — the CLONE-FREE identity check for the hash-first hit path: does this OWNED key match the
    /// live question? A borrowed compare (no qname `String` mint on a pure hit). Collision-safe: a
    /// hash collision with a DIFFERENT identity fails here ⇒ a MISS + re-resolve, never a wrong answer.
    fn matches(&self, q: &DnsQuestion) -> bool {
        self.qtype == q.qtype && self.qclass == q.qclass && self.qname == q.qname
    }
}

/// D16 — the fixed-seed identity hash over the question tuple, computed from BORROWED fields (no
/// `Key` mint / qname clone on the lookup hot path). `DefaultHasher::new()` is deterministic within
/// the process (the same fixed-key SipHash the Warden `DecisionCache` twin uses — `warden/mod.rs`),
/// which is all a process-local cache index needs. Identity is RE-CHECKED via [`Key::matches`] on
/// every hit, so a collision can only ever cost a miss, never serve wrong bytes.
fn question_hash(qname: &str, qtype: u16, qclass: u16) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    qname.hash(&mut h);
    qtype.hash(&mut h);
    qclass.hash(&mut h);
    h.finish()
}

/// D16 — one cache slot behind the identity hash: the OWNED key (for the collision-safe identity
/// re-check), the entry, and its recency sequence (the `recency` BTreeMap row that replaces the old
/// O(n) `Vec<Key>` scan). The Warden `DecisionCache` twin shape (`warden/mod.rs` D20) — the two
/// caches deliberately share this design.
struct Slot {
    key: Key,
    entry: Entry,
    seq: u64,
}

/// Whether a cached entry is a positive answer or a negative (NXDOMAIN/NODATA) denial. Kept so a
/// future stats/serve-stale path can distinguish them; both store the validated wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Positive,
    Negative,
}

/// **Serve-stale-while-revalidate SIGNAL (MaskSolver CACHE-cross, slice 3).** Whether a cache hit was
/// served from a still-fresh entry or from an expired-but-within-stale-bound entry. The cache SIGNALS
/// staleness; the RESOLVER acts on it — on [`Freshness::Stale`] it fires ONE coalesced background
/// revalidation (the RFC 8767 refresh half, studied from dnsmasq `forward.c`'s post-serve `fd=-1`
/// forward), honoring the T24 "spawn no tasks inside the cache" firewall. **The cache itself spawns
/// nothing** — it only retains the bytes and reports their freshness.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Freshness {
    /// Within TTL (or immortal) — no revalidation needed.
    Fresh,
    /// Expired but served under serve-stale — the resolver SHOULD revalidate in the background.
    Stale,
}

/// A cache hit paired with its [`Freshness`]. Returned by [`Cache::get_hit`]; the thin [`Cache::get`]
/// wrapper discards the freshness for the byte-identical legacy `Option<Vec<u8>>` shape the datapath
/// (mod.rs) still calls.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CacheHit {
    /// The validated wire bytes (the caller still rewrites the transaction ID + 0x20 casing).
    pub wire: Vec<u8>,
    /// Whether the bytes were served fresh or stale.
    pub freshness: Freshness,
}

/// **The serve-stale bound — dnsmasq's tri-state `cache_max_expiry` (0 / -1 / <n>, `cache.c`),
/// reimplemented as original Rust.** `Off` = an expired entry is a hard miss (today's default, the
/// byte-identical legacy behaviour). `Window(d)` = an expired entry is usable up to `d` past its TTL.
/// `Unbounded` = an expired entry is usable regardless of how long ago it expired (dnsmasq's `-1`; the
/// cache degrades to approximately LRU-only, still epoch-gated). The `serve_stale_secs` `configure()`
/// knob maps `0 → Off`, `u64::MAX → Unbounded`, any other `n → Window(n)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StaleMode {
    Off,
    Window(Duration),
    Unbounded,
}

impl StaleMode {
    /// Map the flat `serve_stale_secs` `configure()` knob onto the tri-state. `0` = OFF (byte-identical
    /// legacy default); the `u64::MAX` sentinel = UNBOUNDED (dnsmasq's `-1`); any other value = a bounded
    /// window. Keeps every existing `with_policy(..)` caller (which passes `0` or a finite window)
    /// behaviourally identical.
    fn from_secs(serve_stale_secs: u64) -> Self {
        match serve_stale_secs {
            0 => StaleMode::Off,
            u64::MAX => StaleMode::Unbounded,
            n => StaleMode::Window(Duration::from_secs(n)),
        }
    }
}

/// Which record types the positive cache is willing to store (N2 — `--cache-rr`). `All` is the
/// constructed default and is **byte-identically today's behaviour** (no type gate at all — every
/// validated positive is cached). `Only(set)` is the Expert opt-in that NARROWS caching to the named
/// types; the `=ANY` config sentinel maps back to `All` (cache-all). The set is consulted ONLY on the
/// put path, and only when the answer type is determinable — an indeterminable wire FAILS OPEN to
/// cacheable, so this can never regress the 2e locks that cache a non-DNS placeholder wire
/// (integration `cache_key_round_trips`, which `put`s `vec![7,7,7]` and demands a hit).
#[derive(Clone, PartialEq, Eq, Debug)]
enum CacheableTypes {
    /// Cache every validated positive (today's behaviour; the constructed default; the `=ANY` sentinel).
    All,
    /// Cache only positives whose first Answer record is one of these RR types.
    Only(HashSet<u16>),
}

impl CacheableTypes {
    /// The measured default opt-in set {A, AAAA, SRV, PTR} — used when a caller asks for the dnsmasq
    /// default `--cache-rr` set rather than `All`. (Exposed via [`Cache::with_cacheable_types`].)
    fn default_set() -> HashSet<u16> {
        DEFAULT_CACHEABLE_TYPES.iter().copied().collect()
    }

    /// Is a positive answer of first-record type `rtype` cacheable under this policy?
    /// `All` → always; `Only(set)` → membership. (The fail-open "type indeterminable" decision is the
    /// CALLER's, in [`Cache::is_type_cacheable`], not here — this is the pure set predicate.)
    fn admits(&self, rtype: u16) -> bool {
        match self {
            CacheableTypes::All => true,
            CacheableTypes::Only(set) => set.contains(&rtype),
        }
    }
}

/// One TTL-aware cache entry. The `epoch` is the blocklist fingerprint under which this answer was
/// stored — a `get()` whose live fingerprint differs treats the entry as invalid (the new 2e
/// invalidation invariant). `stored + ttl` is the freshness deadline; `serve-stale` (when enabled)
/// extends usability past it but NEVER past the epoch check.
#[derive(Clone)]
struct Entry {
    wire: Vec<u8>,
    stored: Instant,
    ttl: Duration,
    kind: Kind,
    epoch: u64,
    /// D — IMMORTAL (dnsmasq's `F_IMMORTAL` / host-record class): exempt from BOTH TTL expiry AND cap
    /// eviction. `false` for every ordinary answer; `true` only for a [`Cache::put_immortal`] pin.
    immortal: bool,
    /// B-CROWN — a COLD-BOOT-STALE per-entry deadline. `None` for a live entry (it uses the cache's
    /// global [`StaleMode`] window). `Some(instant)` for an entry rehydrated PAST its TTL from the NAND
    /// snapshot: it is serve-stale-usable until this persisted deadline REGARDLESS of the live window, so
    /// a just-booted device answers instantly from its own durable cache while the resolver revalidates.
    stale_deadline: Option<Instant>,
}

impl Entry {
    /// Elapsed since the entry was stored.
    fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.stored)
    }

    /// Fresh = within its TTL (an IMMORTAL entry is always fresh — it never ages out). A COLD-BOOT-STALE
    /// entry (`stale_deadline = Some`) is BY CONSTRUCTION past its TTL — it is never fresh (it always
    /// signals [`Freshness::Stale`] so the resolver revalidates).
    fn is_fresh(&self, now: Instant) -> bool {
        if self.immortal {
            return true;
        }
        if self.stale_deadline.is_some() {
            return false; // a rehydrated cold-boot-stale entry is never fresh
        }
        self.age(now) <= self.ttl
    }

    /// Usable-stale = expired, but still serve-stale-usable. An IMMORTAL entry is never "stale" (always
    /// fresh). A COLD-BOOT-STALE entry (`stale_deadline = Some`) is usable until its persisted per-entry
    /// deadline, independent of the live window + its (zeroed) ttl (B-CROWN) — this is checked FIRST so a
    /// `ttl == 0` cold-boot entry can never be mis-read via the age/ttl comparison. A live entry
    /// (`stale_deadline = None`) honors the cache's global mode: `Off` never, `Unbounded` always,
    /// `Window(w)` up to `w` past its TTL.
    fn is_usable_stale(&self, now: Instant, mode: StaleMode) -> bool {
        if self.immortal {
            return false;
        }
        if let Some(deadline) = self.stale_deadline {
            return now < deadline; // cold-boot: bounded SOLELY by the persisted deadline
        }
        let age = self.age(now);
        if age <= self.ttl {
            return false; // still fresh — not stale
        }
        match mode {
            StaleMode::Off => false,
            StaleMode::Unbounded => true,
            StaleMode::Window(w) => age <= self.ttl.saturating_add(w),
        }
    }
}

/// A bounded LRU answer cache (Wave 2e). TTL-aware, negative-caching, epoch-invalidated.
///
/// Never stores a non-success: the resolver only calls [`put`](Cache::put) /
/// [`put_negative`](Cache::put_negative) with a `validate_response`-approved answer, and a negative
/// carries a bounded TTL so a denial can never pin forever.
pub struct Cache {
    /// D16 — identity-hash → slot (key + entry + recency seq). The hit path hashes the BORROWED
    /// question (zero clones) and re-checks identity via [`Key::matches`] — O(1) lookup, collision =
    /// miss, never a wrong answer.
    map: HashMap<u64, Slot>,
    /// D16 — the recency index: monotonic `seq` → identity hash. Replaces the old `order: Vec<Key>`
    /// whose `touch` was an O(n) `position` scan + `remove` memmove PER HIT. Touch/evict are now
    /// O(log n); lowest seq = LRU-most, highest = MRU (snapshot iterates `.rev()` for MRU-first).
    recency: BTreeMap<u64, u64>,
    /// D16 — the monotonic recency counter (u64 never wraps in practice: 2^64 touches).
    seq: u64,
    cap: usize,
    /// Lower clamp on a stored TTL (`min-cache-ttl`). 0 = off (Expert-only `configure()` knob).
    ttl_floor: Duration,
    /// Upper clamp on a positive TTL (`max-cache-ttl`). Bounds how long a stale/rotated IP survives.
    ttl_ceiling: Duration,
    /// Hard upper clamp on a NEGATIVE (NXDOMAIN/NODATA) TTL — a denial can never pin past this even
    /// if the caller hands an enormous SOA-minimum. The forever-cache guard for the negative path.
    neg_ttl_ceiling: Duration,
    /// serve-stale bound past expiry — dnsmasq's tri-state `cache_max_expiry` (`Off` = an expired entry
    /// is a hard miss, the default; `Window(d)`; `Unbounded`). Reimplemented from the flat `Duration`
    /// the 2e stub carried (0=off/N=window) so an `Unbounded` mode + the Fresh/Stale SIGNAL are possible.
    stale_mode: StaleMode,
    /// The blocklist fingerprint captured at construction (`configure()` time).
    ///
    /// DOC CORRECTED against the code. This previously claimed the value is "stamped onto every
    /// entry stored" -- it is NOT, and never was. `insert` is called with `current_epoch()` at each
    /// put site (`put`, `put_negative`, `put_local`, `put_immortal`), so an entry carries the epoch
    /// LIVE AT THE MOMENT IT WAS STORED, not the one the cache was built under.
    ///
    /// That difference is load-bearing and the code has it RIGHT: entries stored after a blocklist
    /// re-arm carry the NEW fingerprint and survive the `get()` gate, while entries stored before it
    /// carry the old one and are invalidated. Had entries actually been stamped with this field, a
    /// re-arm without reconfigure would have invalidated the ENTIRE cache forever after -- every
    /// subsequent put would stamp a fingerprint that no longer matches the live one, and every read
    /// would miss. The doc described a bug the implementation does not have.
    ///
    /// The field's honest role is DIAGNOSTIC: it records which blocklist generation this cache was
    /// constructed under, so `cache_diagnostics()` can report whether the cache predates the live
    /// blocklist. Read via [`Cache::configured_epoch`].
    epoch: u64,
    /// N2 — which RR types the positive cache stores. `All` by default (= today; the `=ANY` sentinel).
    /// `Only(set)` is the Expert `--cache-rr` opt-in that narrows caching.
    cacheable_types: CacheableTypes,
    /// R4 — optional local-record TTL clamp. When `Some(ttl)`, [`Cache::put_local`] stamps a pinned
    /// local record with THIS ttl (clamped sane, never 0) instead of deriving one from the synthesized
    /// answer's Answer-section TTL. `None` (default) ⇒ no local-ttl override (local records, if any,
    /// fall back to the ordinary positive-TTL derivation). Folds in the SPEC R4 `local-ttl` knob.
    ///
    /// **`#[cfg(test)]` — and the reason is a design finding, not a convenience.** The R4 cluster
    /// (this field, `set_local_ttl`, `local_record_ttl`, `put_local`, `put_immortal`) was built to
    /// cache pinned local records. The datapath that shipped answers pins at
    /// `resolver/mod.rs:1843` (`local::local_answer_if_pinned`), roughly 120 lines BEFORE the cache
    /// is consulted at `:1962` — so a cached pin can never be reached.
    ///
    /// That ordering is CORRECT and should not be changed to make this code live. `lookup_pinned`
    /// is already a RAM hit behind a single relaxed atomic fast-gate (`local.rs:143`), so putting a
    /// cache in front of it saves nothing measurable, while introducing a coherency obligation —
    /// every pin edit would have to invalidate the cached copies or the resolver would serve a
    /// stale answer for a name the user just changed. Wiring this in would buy a staleness bug for
    /// no gain. The honest verdict is that the pin path made this cluster redundant.
    ///
    /// So it is classified rather than silenced. `allow(dead_code)` said "this might be used and I
    /// do not want to hear about it". `#[cfg(test)]` says "the test suite is its only caller", the
    /// compiler ENFORCES that, and the items leave the shipped `.so` entirely — the TTL-clamp laws
    /// stay covered by `local_record_uses_the_local_ttl_clamp_when_set` and
    /// `local_ttl_is_floored_at_1s_and_capped_at_the_ceiling`, so the knowledge is preserved
    /// executably rather than as a comment.
    #[cfg(test)]
    local_ttl: Option<Duration>,
    /// F (MaskSolver CACHE-cross) — honor a genuine 0-TTL answer as "use once, DO NOT cache" (dnsmasq's
    /// `cache.c` `ttl == 0 && cache_max_expiry == 0 ⇒ insert_error`). `false` (default) = today's
    /// behaviour, byte-identical: an explicit-0 or missing TTL both fall to the 30s bounded fallback. When
    /// `true` AND serve-stale is `Off`, an answer whose Answer-section min TTL is EXPLICITLY 0 is declined
    /// (an indeterminable wire still fails open — the placeholder-wire locks stay green). With serve-stale
    /// ON, a 0-TTL answer IS cached (there is stale value in retaining it), faithful to dnsmasq.
    honor_zero_ttl: bool,
}

/// Default positive TTL ceiling (24h) — bounds how long any cached IP survives without a refresh,
/// the insurance the P12 SHOULD `max-cache-ttl` row asks for (sane default, no toggle).
const DEFAULT_TTL_CEILING_SECS: u64 = 86_400;
/// Default hard ceiling on a NEGATIVE TTL (5 min). RFC 2308 recommends bounding negative caching;
/// this is the forever-cache guard the 2b stub avoided by not caching denials at all.
const DEFAULT_NEG_TTL_CEILING_SECS: u64 = 300;
/// Fallback positive TTL when a validated answer carries NO usable TTL (e.g. a malformed/zero-answer
/// wire that still passed the keystone). Small + bounded; never zero (a 0 would expire instantly,
/// thrashing the cache to a no-op).
const DEFAULT_FALLBACK_TTL_SECS: u64 = 30;

/// On-disk snapshot format version for the RAM⊗NAND cache persistence (P12 — the "Remember" boost). A
/// snapshot written by a NEWER version rehydrates as a cold start (the same forward-incompat discipline
/// as `runtime_tier::VERSION`), never a guessed parse. Bumped only if the per-entry framing below changes.
///
/// **v2 (MaskSolver CACHE-cross, slice 3):** each entry gains a second wall-clock deadline
/// `stale_until_unix` after `expiry_unix` — the COLD-BOOT SERVE-STALE original neither source has
/// (dnsmasq has no persistence; the v1 cache persisted FRESH-only). A v1 blob on a v2 build is a clean
/// cold start via the version gate below (a one-time miss on upgrade, never a guessed parse).
const SNAP_VERSION: u8 = 2;

impl Cache {
    /// Construct with the default clamps and serve-stale OFF, capturing the current blocklist epoch.
    ///
    /// TEST-ONLY, and `#[cfg(test)]` rather than `allow(dead_code)` on purpose. Production builds
    /// the cache through [`with_policy`](Cache::with_policy), which is the only path that carries
    /// the operator's TTL floor/ceiling and serve-stale window; `new` exists so a test can say
    /// "a cache, default policy" in one line.
    ///
    /// The attribute is a strictly STRONGER statement than the allow it replaces. `allow(dead_code)`
    /// says "this might be used and I do not want to hear about it"; `#[cfg(test)]` says "this is
    /// test support", and the compiler ENFORCES it — if production code ever reaches for this
    /// constructor and silently skips the policy clamps, the build breaks instead of shipping a
    /// cache with default ceilings. It also drops the item from the shipped `.so` entirely.
    #[cfg(test)]
    pub fn new(cap: usize) -> Self {
        Self::with_policy(
            cap,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            0,
        )
    }

    /// Full constructor — the `configure()` install point passes the Expert TTL floor (default 0 = off),
    /// the positive ceiling, the negative ceiling, and the serve-stale window (0 = off). Captures the
    /// live blocklist fingerprint as the cache epoch.
    pub fn with_policy(
        cap: usize,
        ttl_floor_secs: u64,
        ttl_ceiling_secs: u64,
        neg_ttl_ceiling_secs: u64,
        serve_stale_secs: u64,
    ) -> Self {
        // A 0 ceiling would clamp every TTL to 0 (instant expiry) — coerce to the sane default so a
        // mis-config can never silently disable the cache. The floor legitimately may be 0 (= off).
        let ttl_ceiling = if ttl_ceiling_secs == 0 {
            DEFAULT_TTL_CEILING_SECS
        } else {
            ttl_ceiling_secs
        };
        let neg_ceiling = if neg_ttl_ceiling_secs == 0 {
            DEFAULT_NEG_TTL_CEILING_SECS
        } else {
            neg_ttl_ceiling_secs
        };
        Cache {
            map: HashMap::new(),
            recency: BTreeMap::new(),
            seq: 0,
            cap: cap.max(1),
            ttl_floor: Duration::from_secs(ttl_floor_secs),
            ttl_ceiling: Duration::from_secs(ttl_ceiling),
            neg_ttl_ceiling: Duration::from_secs(neg_ceiling),
            // serve_stale_secs: 0 → Off (byte-identical default), u64::MAX → Unbounded, else Window(n).
            stale_mode: StaleMode::from_secs(serve_stale_secs),
            epoch: current_epoch(),
            // N2 default = cache-all (today's behaviour; no type gate). R4 default = no local-ttl
            // override. F default = do NOT honor explicit-0 (30s-fallback, today's behaviour). All are
            // flipped via the additive setters/extension ctor below, never here, so `new`/`with_policy`
            // callers + every shipped test stay byte-identical.
            cacheable_types: CacheableTypes::All,
            #[cfg(test)]
            local_ttl: None,
            honor_zero_ttl: false,
        }
    }

    /// N2 extension constructor — build with an explicit `--cache-rr` cacheable-type set on top of the
    /// full policy. Pass an EMPTY `types` slice for the dnsmasq **default** set {A,AAAA,SRV,PTR}; pass
    /// types to NARROW to exactly those; the `=ANY` sentinel is expressed by NOT calling this (or by
    /// [`Cache::set_cacheable_all`]) so the cache stays `All`. Additive — leaves `new`/`with_policy`
    /// untouched. (Dead-code-until-wired: the configure() seam calls this when the user opts in.)
    pub fn with_cacheable_types(
        cap: usize,
        ttl_floor_secs: u64,
        ttl_ceiling_secs: u64,
        neg_ttl_ceiling_secs: u64,
        serve_stale_secs: u64,
        types: &[u16],
    ) -> Self {
        let mut c = Self::with_policy(
            cap,
            ttl_floor_secs,
            ttl_ceiling_secs,
            neg_ttl_ceiling_secs,
            serve_stale_secs,
        );
        c.set_cacheable_types(types);
        c
    }

    /// The configured capacity (the `--cache-size`). Surfaced so `resolver::stats()` can carry the real
    /// cap onto the MaskSolver SETTINGS pane (the pane shows entries/cap, not just the live entry count).
    pub fn cap(&self) -> usize {
        self.cap
    }

    // ── LIVE Expert cache-shape mutators (2-FEED-MaskSolver SETTINGS). The resolver-level setters lock the
    //    held `inner` and call these so the knob bites the RUNNING cache immediately (no reconfigure wait);
    //    the durable global intents above make the choice survive the next `configure()` rebuild. Each
    //    coerces exactly as `with_policy` does, so a live set and a reconfigure land on the SAME field value.

    /// Live-set the positive-TTL floor (`min-cache-ttl`; 0 = no floor). Affects entries stored AFTER this.
    pub fn set_ttl_floor(&mut self, secs: u64) {
        self.ttl_floor = Duration::from_secs(secs);
    }
    /// Live-set the positive-TTL ceiling (`max-cache-ttl`; 0 → the 24h default, matching `with_policy`).
    pub fn set_ttl_ceiling(&mut self, secs: u64) {
        let ceiling = if secs == 0 {
            DEFAULT_TTL_CEILING_SECS
        } else {
            secs
        };
        self.ttl_ceiling = Duration::from_secs(ceiling);
    }
    /// Live-set the serve-stale window (0 OFF · `u64::MAX` unbounded · else window secs — the tri-state map).
    pub fn set_stale_mode_secs(&mut self, secs: u64) {
        self.stale_mode = StaleMode::from_secs(secs);
    }
    /// Live-set the `--cache-size` capacity (clamped to >= 1, matching `new`/`with_policy`). Shrinking
    /// evicts the coldest evictable entries down to the new cap NOW (immortal pins survive — same rule as
    /// ordinary eviction); growing just raises the ceiling. The MaskSolver SETTINGS staged cache-cap
    /// commits through here on `reapply-config()`.
    pub fn set_cap(&mut self, cap: usize) {
        self.cap = cap.max(1);
        self.evict_to_cap();
    }

    /// Fetch a still-valid response for `q`, if cached. Returns `None` (a miss) when the entry is
    /// expired (serve-stale off / past the stale window), or when its epoch no longer matches the LIVE
    /// blocklist fingerprint (a re-arm invalidates lazily). A hit TOUCHES the key to the back of the
    /// LRU order. The returned bytes still carry the cached response's transaction ID — the caller
    /// rewrites bytes 0..2 to the live query's ID (and re-echoes 0x20 question casing).
    ///
    /// A thin wrapper over [`get_hit`](Cache::get_hit) that discards the [`Freshness`].
    ///
    /// TEST-ONLY as of the RFC 8767 serve-stale wiring. The doc used to read "the datapath (mod.rs)
    /// that only wants the bytes calls this" — that CEASED TO BE TRUE when `resolve_inner` was moved
    /// onto `get_hit` so a stale hit could be reported as `ServeStale` instead of being
    /// indistinguishable from a fresh one. The sentence survived the change and named a caller that
    /// no longer existed; correcting it is part of this edit, because a doc that claims a
    /// non-existent production caller is exactly how dead code stays invisible.
    ///
    /// Kept rather than deleted because it earns its place in the tests: it is the reference the
    /// byte-identity assertions compare `get_hit` against, so the freshness-reporting path is
    /// pinned to return the SAME bytes the simple path does. `#[cfg(test)]` states that fact and
    /// lets the compiler enforce it.
    #[cfg(test)]
    pub fn get(&mut self, q: &DnsQuestion) -> Option<Vec<u8>> {
        self.get_at(q, Instant::now(), current_epoch())
    }

    /// Testable core of [`get`]: `now` + `live_epoch` injected so tests need no real clock / blocklist.
    #[cfg(test)]
    fn get_at(&mut self, q: &DnsQuestion, now: Instant, live_epoch: u64) -> Option<Vec<u8>> {
        self.get_hit_at(q, now, live_epoch).map(|hit| hit.wire)
    }

    /// **Serve-stale-while-revalidate SIGNAL (MaskSolver CACHE-cross, slice 3).** Fetch a still-usable
    /// response for `q` AND report whether it was served [`Freshness::Fresh`] or [`Freshness::Stale`], so
    /// the RESOLVER can fire ONE coalesced background revalidation on a stale hit (the RFC 8767 refresh
    /// half — the cache spawns nothing, T24). Same LRU-touch / epoch-gate / eviction discipline as
    /// [`get`]; the ONLY addition is the freshness tag. Miss ⇒ `None`.
    pub fn get_hit(&mut self, q: &DnsQuestion) -> Option<CacheHit> {
        self.get_hit_at(q, Instant::now(), current_epoch())
    }

    /// Testable core of [`get_hit`]: `now` + `live_epoch` injected so tests need no real clock/blocklist.
    /// D16 — CLONE-FREE hit path: the BORROWED question is hashed (no `Key` mint), the slot's owned key
    /// re-checks identity, and the recency touch is O(log n) (was an O(n) `Vec` scan + memmove per HIT).
    fn get_hit_at(&mut self, q: &DnsQuestion, now: Instant, live_epoch: u64) -> Option<CacheHit> {
        let h = question_hash(&q.qname, q.qtype, q.qclass);
        let mode = self.stale_mode;

        let (hit, evict) = {
            let slot = self.map.get(&h)?;
            // D16 collision guard — a hash collision with a DIFFERENT identity is a plain MISS
            // (re-resolve), NEVER the other identity's bytes. The colliding resident is left alone.
            if !slot.key.matches(q) {
                return None;
            }
            let entry = &slot.entry;
            // EPOCH GATE first — a stale-list answer is invalid regardless of TTL / serve-stale.
            // This is the load-bearing 2e invariant: a blocklist re-arm (new fingerprint) without
            // a configure() rebuild invalidates every entry stored under the old epoch.
            if entry.epoch != live_epoch {
                (None, true)
            } else if entry.is_fresh(now) {
                (
                    Some(CacheHit {
                        wire: entry.wire.clone(),
                        freshness: Freshness::Fresh,
                    }),
                    false,
                )
            } else if entry.is_usable_stale(now, mode) {
                // serve-stale: the expired-but-usable bytes (epoch already honored). SIGNAL Stale so
                // the resolver revalidates. `is_usable_stale` folds in Off (never) / Unbounded /
                // Window(w) / the cold-boot per-entry deadline — one predicate, no external guard.
                (
                    Some(CacheHit {
                        wire: entry.wire.clone(),
                        freshness: Freshness::Stale,
                    }),
                    false,
                )
            } else {
                // Expired past any stale bound — drop it.
                (None, true)
            }
        };

        if evict {
            self.remove_hash(h);
            return None;
        }

        if hit.is_some() {
            self.touch(h);
        }
        hit
    }

    /// Store a validated POSITIVE `response` for question `q`. TTL is derived as the MIN per-record TTL
    /// across the Answer section (reusing [`crate::dns::answer_records`]), then clamped into
    /// `[ttl_floor, ttl_ceiling]`. Evicts the LRU entry past `cap`.
    ///
    /// The resolver only reaches this with a `validate_response`-approved positive answer (RCODE==0 &&
    /// ANCOUNT>0); a SERVFAIL/REFUSED never gets here (dns.rs:291). Never stores failure-as-success.
    pub fn put(&mut self, q: &DnsQuestion, response: Vec<u8>) {
        // N2 — under an `Only(set)` cache-rr policy, decline a determinable non-member type (fail-open
        // on an indeterminable wire so the 2e placeholder-wire locks + the `All` default are unchanged).
        if !self.is_type_cacheable(&response) {
            return;
        }
        // F (CACHE-cross) — dnsmasq's 0-TTL "use once, do NOT cache". Honored ONLY when opted in AND
        // serve-stale is Off; default OFF ⇒ today's 30s-fallback behaviour (byte-identical). An
        // indeterminable wire is never "explicitly 0" (fails open), so the placeholder-wire locks hold.
        if self.honor_zero_ttl
            && self.stale_mode == StaleMode::Off
            && Self::is_explicit_zero_ttl(&response)
        {
            return;
        }
        let ttl = self.positive_ttl(&response);
        self.insert(q, response, ttl, Kind::Positive, current_epoch());
    }

    /// Store a validated NEGATIVE (NXDOMAIN/NODATA) denial for question `q` with a caller-supplied
    /// `neg_ttl_secs` (the Authority SOA-minimum once the dns.rs skimmer surfaces it; until then a
    /// small bounded default chosen by the caller). The TTL is **hard-clamped** to `neg_ttl_ceiling`
    /// so a denial can NEVER pin forever — the precise forever-cache bug the 2b stub avoided by not
    /// caching denials at all. SERVFAIL/REFUSED are NOT negatives and never reach here (dns.rs:291).
    pub fn put_negative(&mut self, q: &DnsQuestion, response: Vec<u8>, neg_ttl_secs: u32) {
        let ttl = self.negative_ttl(neg_ttl_secs);
        self.insert(q, response, ttl, Kind::Negative, current_epoch());
    }

    /// **A (CACHE-cross) — store a NEGATIVE denial, deriving the neg-TTL from the response's SOA.** The
    /// SOA-minimum skimmer [`crate::dns::negative_ttl_from_soa`] surfaces `min(SOA TTL, SOA MINIMUM)`
    /// (RFC 2308 §5, studied from dnsmasq `find_soa`); a denial WITHOUT an SOA falls back to
    /// `default_neg_ttl_secs`. Either way the value is still hard-clamped to `neg_ttl_ceiling` by
    /// [`put_negative`](Cache::put_negative). This closes the `put_negative` TODO ("the Authority
    /// SOA-minimum once the dns.rs skimmer surfaces it") — the skimmer now surfaces it.
    pub fn put_negative_from_response(
        &mut self,
        q: &DnsQuestion,
        response: Vec<u8>,
        default_neg_ttl_secs: u32,
    ) {
        let neg_ttl = crate::dns::negative_ttl_from_soa(&response).unwrap_or(default_neg_ttl_secs);
        self.put_negative(q, response, neg_ttl);
    }

    /// F helper — does this validated positive carry an EXPLICIT 0 TTL (a determinable Answer section
    /// whose MIN per-record TTL is exactly 0)? Reuses the SAME [`crate::dns::answer_records`] skimmer
    /// (never a 2nd parser). An indeterminable wire (no/empty/un-skimmable Answer section) is NOT
    /// "explicitly 0" ⇒ returns `false` (fails open to cacheable) — the placeholder-wire locks stay green.
    fn is_explicit_zero_ttl(response: &[u8]) -> bool {
        crate::dns::answer_records(response)
            .and_then(|recs| recs.iter().map(|r| r.ttl).min())
            .map(|min| min == 0)
            .unwrap_or(false)
    }

    /// F setter — opt in to honoring an explicit 0-TTL as "do not cache" (default OFF = 30s fallback).
    /// Independent of `configure()` (the standalone-toggle discipline). Only effective when serve-stale
    /// is Off (a stale-serving cache retains a 0-TTL answer to serve stale, faithful to dnsmasq).
    pub fn set_honor_zero_ttl(&mut self, on: bool) {
        self.honor_zero_ttl = on;
    }

    /// Derive a positive entry's TTL: MIN per-record TTL across the Answer section, clamped into
    /// `[ttl_floor, ttl_ceiling]`; a missing/zero answer-TTL falls back to a small bounded default.
    fn positive_ttl(&self, response: &[u8]) -> Duration {
        let min_ttl = crate::dns::answer_records(response)
            .and_then(|recs| recs.iter().map(|r| r.ttl).min())
            .filter(|&t| t > 0)
            .unwrap_or(DEFAULT_FALLBACK_TTL_SECS as u32);
        self.clamp_positive(Duration::from_secs(min_ttl as u64))
    }

    /// Derive a negative entry's TTL: the caller's neg-TTL, clamped DOWN to the negative ceiling and
    /// UP to at least 1s (never 0 = instant expiry / no-op). The floor clamp does NOT apply to
    /// negatives — a denial must never be artificially extended by a positive min-cache-ttl knob.
    fn negative_ttl(&self, neg_ttl_secs: u32) -> Duration {
        let secs = (neg_ttl_secs as u64)
            .min(self.neg_ttl_ceiling.as_secs())
            .max(1);
        Duration::from_secs(secs)
    }

    /// Apply the `[ttl_floor, ttl_ceiling]` clamp to a positive TTL. (`min-cache-ttl` raises tiny TTLs;
    /// `max-cache-ttl` caps long ones.)
    fn clamp_positive(&self, ttl: Duration) -> Duration {
        ttl.max(self.ttl_floor).min(self.ttl_ceiling)
    }

    // ---- N2 · cacheable-type set (`--cache-rr`) ------------------------------------------------

    /// Expert setter — flip the `--cache-rr` cacheable-type set independently of `configure()` so a P10
    /// rotation never resets the user's choice (the standalone-toggle discipline, mirroring
    /// `set_rebind_enforce` in mod.rs). An EMPTY slice installs the measured DEFAULT set {A,AAAA,SRV,PTR};
    /// a non-empty slice narrows to exactly those types; use [`Cache::set_cacheable_all`] for cache-all.
    pub fn set_cacheable_types(&mut self, types: &[u16]) {
        let set: HashSet<u16> = if types.is_empty() {
            CacheableTypes::default_set()
        } else {
            // The `=ANY` sentinel (255, QTYPE ANY) means "cache every type" → degrade to All.
            if types.contains(&255) {
                self.cacheable_types = CacheableTypes::All;
                return;
            }
            types.iter().copied().collect()
        };
        self.cacheable_types = CacheableTypes::Only(set);
    }

    /// Expert setter — restore cache-all (the `=ANY` sentinel / today's default behaviour).
    pub fn set_cacheable_all(&mut self) {
        self.cacheable_types = CacheableTypes::All;
    }

    /// N2 put-gate: is this validated positive `response` cacheable under the current `--cache-rr`
    /// policy? Reads the FIRST Answer record's RR type via the REUSED [`crate::dns::answer_records`]
    /// skimmer (never a 2nd parser — the LAW). **Fails OPEN**: a wire with no determinable Answer type
    /// (too short, no answer records, un-skimmable) is treated as cacheable, so the `All` default and
    /// the 2e placeholder-wire locks (`cache_key_round_trips` puts `vec![7,7,7]`) keep their behaviour.
    /// Only a DETERMINABLE type under an `Only(set)` policy can ever decline the put.
    fn is_type_cacheable(&self, response: &[u8]) -> bool {
        // P12 toggle (`DNSMASQ_CACHE_RR`): when disabled, an answer whose first record is SVCB/HTTPS is
        // declined regardless of the instance policy. Reuses the same `answer_records` skimmer (never a
        // 2nd parser — the LAW); fails OPEN (indeterminable wire ⇒ fall through to the instance decision).
        if !CACHE_RR_ENABLED.load(Ordering::Relaxed) {
            if let Some(recs) = crate::dns::answer_records(response) {
                if let Some(first) = recs.first() {
                    if first.rtype == RTYPE_SVCB || first.rtype == RTYPE_HTTPS {
                        return false;
                    }
                }
            }
        }
        match &self.cacheable_types {
            CacheableTypes::All => true,
            CacheableTypes::Only(_) => match crate::dns::answer_records(response) {
                // Determinable: gate on the first Answer record's type.
                Some(recs) if !recs.is_empty() => self.cacheable_types.admits(recs[0].rtype),
                // Indeterminable (no/empty answer section, un-skimmable) → FAIL OPEN (cache it).
                _ => true,
            },
        }
    }

    // ---- R4 · local-record TTL clamp -----------------------------------------------------------

    /// R4 setter — install (or clear, with `None`) the local-record TTL override. When set,
    /// [`Cache::put_local`] stamps a pinned local record with this TTL instead of deriving one from the
    /// synthesized wire. Independent of `configure()` (the standalone-toggle discipline). Clamped to the
    /// positive ceiling and floored at ≥1s on use (never 0 = instant expiry) — see `local_record_ttl`.
    #[cfg(test)]
    pub fn set_local_ttl(&mut self, ttl: Option<Duration>) {
        self.local_ttl = ttl;
    }

    /// Resolve the TTL for a pinned local record: the configured `local_ttl` if present (floored at 1s,
    /// capped at the positive ceiling so a local pin can't outlive the `max-cache-ttl` insurance),
    /// otherwise fall back to the ordinary positive derivation from the synthesized answer.
    #[cfg(test)]
    fn local_record_ttl(&self, response: &[u8]) -> Duration {
        match self.local_ttl {
            Some(ttl) => {
                let floored = if ttl < Duration::from_secs(1) {
                    Duration::from_secs(1)
                } else {
                    ttl
                };
                floored.min(self.ttl_ceiling)
            }
            None => self.positive_ttl(response),
        }
    }

    /// R4 — store a PINNED LOCAL record (the `host-record`/`addn-hosts` synthesized answer, no egress)
    /// using the local-ttl clamp. Distinct from [`put`](Cache::put): a local record's TTL comes from the
    /// `local-ttl` knob (when set), NOT the answer wire — a synthesized local answer has whatever TTL we
    /// chose, and the user controls how long it pins. Still epoch-stamped + LRU-managed + AD-stripped
    /// like any insert. The N2 type gate is NOT applied to local records (a user-pinned record the user
    /// explicitly asked us to keep is always cacheable, regardless of the `--cache-rr` upstream policy).
    #[cfg(test)]
    pub fn put_local(&mut self, q: &DnsQuestion, response: Vec<u8>) {
        let ttl = self.local_record_ttl(&response);
        self.insert(q, response, ttl, Kind::Positive, current_epoch());
    }

    // ---- D · immortal (host-record) class ------------------------------------------------------

    /// **D (CACHE-cross) — store a TRULY IMMORTAL record** (dnsmasq's `F_IMMORTAL` / the pinned
    /// `F_HOSTS`/`F_CONFIG` class that `cache_scan_free` NEVER frees). Exempt from BOTH TTL expiry AND
    /// cap eviction — only a `configure()` rebuild / [`clear`](Cache::clear) removes it. Distinct from
    /// [`put_local`](Cache::put_local), which is TTL-clamped AND still LRU-evictable: an immortal pin is a
    /// record the user asked us to keep unconditionally (an `address=/host/ip` literal). Still
    /// AD-stripped + epoch-stamped like any insert. Immortals bypass `cap`, so a runaway host-list is
    /// user config, not a leak (host-record counts are tiny); they are NOT carried in the NAND snapshot
    /// (they are config-derived and re-installed on `configure()`).
    #[cfg(test)]
    pub fn put_immortal(&mut self, q: &DnsQuestion, mut response: Vec<u8>) {
        Self::strip_ad_bit(&mut response);
        let key = Key::from_question(q);
        let entry = Entry {
            wire: response,
            stored: Instant::now(),
            ttl: Duration::ZERO, // irrelevant — `is_fresh` short-circuits `true` for an immortal
            kind: Kind::Positive,
            epoch: current_epoch(),
            immortal: true,
            stale_deadline: None,
        };
        self.insert_entry(key, entry);
    }

    // ---- N3 · AD-bit cache discipline ----------------------------------------------------------

    /// N3 — clear the AD (Authenticated Data) bit on a wire in-place (header byte 3, mask `0x20`). The
    /// cache ALWAYS calls this on insert: AD is a property of the **upstream exchange, not the cached
    /// RRset** (dnsmasq man: caching AD "is not technically possible"), so a cached/cache-served answer
    /// must NEVER carry an AD bit — that would serve a stale AD cross-context (the #1 false-green trap).
    /// The live forward-path pass-through of `--proxy-dnssec` is the RESOLVER's job (mod.rs); this module
    /// guarantees only that the bit never SURVIVES into or out of the cache. Precise mask: RCODE/Z/CD on
    /// byte 3 are untouched. No-op on a sub-header wire (the placeholder-wire locks stay green).
    fn strip_ad_bit(wire: &mut [u8]) {
        if wire.len() > 3 {
            wire[3] &= !AD_BIT_MASK;
        }
    }

    /// Shared insert: store/replace an ordinary (mortal) entry, maintain the LRU order, evict past `cap`.
    fn insert(
        &mut self,
        q: &DnsQuestion,
        mut response: Vec<u8>,
        ttl: Duration,
        kind: Kind,
        epoch: u64,
    ) {
        // N3 — ALWAYS clear the AD bit on the way into the cache. AD describes the upstream exchange, not
        // the cached RRset, so a cache-served answer must never carry a stale AD (caveat-a discipline).
        Self::strip_ad_bit(&mut response);
        let key = Key::from_question(q);
        let entry = Entry {
            wire: response,
            stored: Instant::now(),
            ttl,
            kind,
            epoch,
            immortal: false,
            stale_deadline: None,
        };
        self.insert_entry(key, entry);
    }

    /// Store/replace `entry` at `key`, refresh its recency to MRU, then evict to `cap`. The ONE
    /// map/recency/evict discipline every insert path (ordinary / immortal / restored) funnels through —
    /// so the LRU + cap invariant lives in exactly one place. D16: an insert over an existing hash
    /// (same identity OR a rare collision) replaces the slot and drops the old recency row — a collision
    /// evicts the colliding resident (a bounded, hash-random one-entry cost, never a wrong answer).
    fn insert_entry(&mut self, key: Key, entry: Entry) {
        let h = question_hash(&key.qname, key.qtype, key.qclass);
        self.seq += 1;
        let seq = self.seq;
        if let Some(old) = self.map.insert(h, Slot { key, entry, seq }) {
            self.recency.remove(&old.seq);
        }
        self.recency.insert(seq, h);
        self.evict_to_cap();
    }

    /// Evict down to `cap`, dropping the LRU-most NON-immortal entry each pass (D — immortals bypass cap).
    /// D16: the victim is the LOWEST-seq non-immortal in the recency index — O(log n) + a bounded skip
    /// over any immortals parked at the LRU end (immortal counts are tiny, host-record class). If every
    /// remaining entry is immortal, eviction STOPS (immortals bypass `cap` by design — a documented bound).
    fn evict_to_cap(&mut self) {
        while self.map.len() > self.cap {
            let victim = self
                .recency
                .iter()
                .find(|(_, h)| self.map.get(h).is_some_and(|s| !s.entry.immortal))
                .map(|(&seq, &h)| (seq, h));
            let Some((seq, h)) = victim else {
                break; // all remaining entries are immortal — they bypass cap (documented)
            };
            self.recency.remove(&seq);
            self.map.remove(&h);
        }
    }

    /// D16 — refresh the slot at identity-hash `h` to MRU (highest seq). O(log n); no-op if absent.
    fn touch(&mut self, h: u64) {
        if let Some(slot) = self.map.get_mut(&h) {
            let old_seq = slot.seq;
            self.seq += 1;
            slot.seq = self.seq;
            let new_seq = slot.seq;
            self.recency.remove(&old_seq);
            self.recency.insert(new_seq, h);
        }
    }

    /// D16 — drop the slot at identity-hash `h` together with its recency row (the epoch/expiry evict).
    fn remove_hash(&mut self, h: u64) {
        if let Some(slot) = self.map.remove(&h) {
            self.recency.remove(&slot.seq);
        }
    }

    /// Test/diagnostic peek at the stored entry for `q` (identity-checked, no LRU touch, no clone).
    #[cfg(test)]
    fn peek_entry(&self, q: &DnsQuestion) -> Option<&Entry> {
        self.map
            .get(&question_hash(&q.qname, q.qtype, q.qclass))
            .filter(|slot| slot.key.matches(q))
            .map(|slot| &slot.entry)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The blocklist generation this cache was CONSTRUCTED under (see the [`Cache::epoch`] field).
    ///
    /// Compare against [`current_epoch`] to learn whether the blocklist has been re-armed since
    /// `configure()` ran. A drift here is NORMAL and harmless -- entries are epoch-gated
    /// individually at put time, so a drifted cache invalidates exactly the entries that predate
    /// the re-arm and keeps the rest. It is reported because "why did my cache empty out?" is
    /// otherwise unanswerable from the outside.
    pub fn configured_epoch(&self) -> u64 {
        self.epoch
    }

    /// The LIVE blocklist generation, for the same comparison from outside this module.
    pub fn live_epoch() -> u64 {
        current_epoch()
    }

    /// Drop every entry — the explicit invalidation seam (the reconfigure/shutdown path already
    /// replaces the whole `Inner`). Distinct from the lazy per-entry epoch gate in `get()`.
    pub fn clear(&mut self) {
        self.map.clear();
        self.recency.clear();
    }

    /// **RAM⊗NAND cache persistence (P12 — the "Remember" boost) · SNAPSHOT (v2, COLD-BOOT SERVE-STALE).**
    /// Serialize the live cache into a bounded, self-describing payload for
    /// [`crate::runtime_tier::DurableTier::write_through`] (RAM-hot heap → a GENTLE atomic NAND
    /// write-through). MRU-FIRST: when the `budget` (the DurableTier 256 KiB ceiling less framing) is
    /// reached, the FRESHEST entries survive — the cache's own value ordering.
    ///
    /// **The MaskSolver original neither source has:** carry FRESH answers AND — when serve-stale is on —
    /// STALE-eligible answers too, each with TWO wall-clock deadlines: `expiry_unix` (the TTL boundary)
    /// and `stale_until_unix` (the serve-stale boundary). dnsmasq has NO persistence (every reboot is a
    /// cold cache); the v1 cache persisted FRESH-only. v2 lets a just-booted device serve-stale INSTANTLY
    /// from its own NAND while the resolver revalidates — "SOLVES resiliently AND CACHES on RAM⊗NAND".
    /// `Instant` is monotonic (meaningless across a restart), so both deadlines are wall-clock anchored
    /// and re-derived on restore. The blocklist `epoch` rides along so a re-arm across the reboot still
    /// invalidates. IMMORTALS are NOT carried (config-derived, re-installed on `configure()`).
    /// CONTROL-PLANE only — NEVER `resolve()`.
    pub fn snapshot(&self, now: Instant, now_unix: u64, budget: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(budget.min(8192));
        out.push(SNAP_VERSION);
        out.extend_from_slice(&0u32.to_be_bytes()); // entry-count placeholder (back-patched below)
        let mut count: u32 = 0;
        // D16 — MRU = the HIGHEST seq in the recency index; iterate reversed so the freshest entries
        // claim the budget first (the same MRU-first law the old `order.iter().rev()` walk had).
        for (_, h) in self.recency.iter().rev() {
            let Some(slot) = self.map.get(h) else {
                continue;
            };
            let (key, entry) = (&slot.key, &slot.entry);
            // Immortals are config-derived (re-installed on configure) — never persisted here.
            if entry.immortal {
                continue;
            }
            let fresh = entry.is_fresh(now);
            let stale_ok = entry.is_usable_stale(now, self.stale_mode);
            if !fresh && !stale_ok {
                continue; // neither within-TTL nor cold-boot-stale-eligible — nothing to carry
            }
            // Two wall-clock deadlines. expiry = when it stops being fresh; stale_until = when it stops
            // being serve-stale-usable. For a FRESH entry both extend forward; for an already-STALE entry
            // expiry == now and stale_until = the remaining stale grace. Off ⇒ stale_until == expiry
            // (fresh-only, byte-identical v1 semantics); Unbounded ⇒ u64::MAX (dnsmasq's serve-forever).
            let age_s = entry.age(now).as_secs();
            let ttl_s = entry.ttl.as_secs();
            let fresh_remaining = ttl_s.saturating_sub(age_s);
            let expiry_unix = now_unix.saturating_add(fresh_remaining);
            let stale_until_unix = match self.stale_mode {
                StaleMode::Off => expiry_unix,
                StaleMode::Unbounded => u64::MAX,
                StaleMode::Window(w) => {
                    // stale ends at `ttl + w` measured from `stored`; the remaining grace from `now`.
                    let stale_end_from_stored = ttl_s.saturating_add(w.as_secs());
                    now_unix.saturating_add(stale_end_from_stored.saturating_sub(age_s))
                }
            };
            let qname = key.qname.as_bytes();
            let (Ok(qname_len), Ok(wire_len)) =
                (u16::try_from(qname.len()), u32::try_from(entry.wire.len()))
            else {
                continue; // a length never seen on a DNS wire — skip, never silently truncate
            };
            // qname_len(2) qname qtype(2) qclass(2) kind(1) expiry(8) stale_until(8) epoch(8) wire_len(4) wire
            let entry_size = 2 + qname.len() + 2 + 2 + 1 + 8 + 8 + 8 + 4 + entry.wire.len();
            if out.len().saturating_add(entry_size) > budget {
                break; // budget reached — the freshest already landed (MRU-first)
            }
            out.extend_from_slice(&qname_len.to_be_bytes());
            out.extend_from_slice(qname);
            out.extend_from_slice(&key.qtype.to_be_bytes());
            out.extend_from_slice(&key.qclass.to_be_bytes());
            out.push(match entry.kind {
                Kind::Positive => 0,
                Kind::Negative => 1,
            });
            out.extend_from_slice(&expiry_unix.to_be_bytes());
            out.extend_from_slice(&stale_until_unix.to_be_bytes());
            out.extend_from_slice(&entry.epoch.to_be_bytes());
            out.extend_from_slice(&wire_len.to_be_bytes());
            out.extend_from_slice(&entry.wire);
            count = count.saturating_add(1);
        }
        out[1..5].copy_from_slice(&count.to_be_bytes());
        out
    }

    /// **RAM⊗NAND cache persistence (P12) · RESTORE.** Repopulate the cache from a [`snapshot`](Cache::snapshot)
    /// payload (handed back by [`crate::runtime_tier::DurableTier::rehydrate`], already integrity-checked +
    /// frame-bound-capped by the tier). Every field is length-guarded — a malformed/truncated tail simply
    /// STOPS the parse (never an OOB read, never a panic). An entry is admitted ONLY if it is (a) not
    /// wall-clock-expired (`expiry_unix > now_unix` — an entry that died while the device was off is
    /// dropped) and (b) under the LIVE blocklist `epoch` (a re-arm across the reboot drops the rest).
    /// Inserted in snapshot order so the LRU ordering is preserved (freshest stays MRU). Returns the count
    /// admitted (observability). CONTROL-PLANE only.
    ///
    /// EPOCH: restored entries keep their ORIGINAL blocklist epoch; the live re-arm check is left to
    /// [`get_at`](Cache::get_at)'s existing lazy gate (an entry whose epoch no longer matches the live
    /// fingerprint is a MISS at lookup). This is deliberately NOT an eager restore-time skip — the
    /// blocklist may rehydrate AFTER the resolver configures, and an eager skip would wrongly drop every
    /// entry while the fingerprint is still cold.
    ///
    /// **v2 admission (COLD-BOOT SERVE-STALE):** an entry still within `expiry_unix` rehydrates FRESH
    /// (identical to v1). An entry PAST `expiry_unix` but before `stale_until_unix` — AND only when this
    /// cache's serve-stale is on — rehydrates COLD-BOOT-STALE (ttl=0, a per-entry `stale_deadline` = the
    /// persisted `stale_until`), so the first post-reboot query serves it instantly while the resolver
    /// revalidates. Everything else is dropped.
    /// TEST-ONLY since the rehydrate path moved to [`restore_gated`](Cache::restore_gated).
    ///
    /// The always-admit closure is precisely what made the durable-poison gap possible: an entry
    /// cached before the user armed rebind-enforce came straight back out of NAND with the live gate
    /// never re-run on it. Production now supplies the real rebind decision, and this unconditional
    /// variant is kept ONLY so parser tests can exercise the framing (truncated tails, foreign
    /// versions, cold-boot-stale admission) without also constructing a gate.
    ///
    /// `#[cfg(test)]` rather than an allow, because the distinction is worth having the compiler
    /// enforce: if a future rehydrate path reaches for the convenient unconditional restore, that is
    /// a security regression, and it should fail to build rather than quietly ship.
    #[cfg(test)]
    pub fn restore(&mut self, payload: &[u8], now: Instant, now_unix: u64) -> usize {
        self.restore_with(payload, now, now_unix, &|_| true)
    }

    /// **C (CACHE-cross) — RESTORE with a re-gate closure (the rebind persist-gate).** Identical to
    /// [`restore`](Cache::restore) but every candidate wire is passed to `admit` FIRST; a wire the closure
    /// rejects is DROPPED at rehydrate, never resurrected onto the fast path. The resolver supplies the
    /// SAME live rebind decision it enforces on the resolve path (`resolver::rebind::is_rebind` +
    /// the NAME allowlist), so an answer cached BEFORE the user enabled rebind-enforce (or before the
    /// allowlist shrank) can never survive a reboot as a durable poison — the gap the live resolve-path
    /// gate misses (it never re-runs on a rehydrated entry). Interlocks with cold-boot-stale: a persisted
    /// STALE entry is re-gated too, so the crown can never make a rebind answer durable.
    pub fn restore_gated(
        &mut self,
        payload: &[u8],
        now: Instant,
        now_unix: u64,
        admit: &dyn Fn(&[u8]) -> bool,
    ) -> usize {
        self.restore_with(payload, now, now_unix, admit)
    }

    /// The ONE restore parser (never a 2nd) — `restore` passes an always-admit closure, `restore_gated`
    /// passes the live rebind re-gate. Bounds-guarded throughout: a truncated/hostile tail STOPS the parse
    /// cleanly (never an OOB read, never a panic). `admit` runs on the parsed wire BEFORE insertion.
    fn restore_with(
        &mut self,
        payload: &[u8],
        now: Instant,
        now_unix: u64,
        admit: &dyn Fn(&[u8]) -> bool,
    ) -> usize {
        let mut cur = payload;
        let Some((&ver, rest)) = cur.split_first() else {
            return 0;
        };
        if ver != SNAP_VERSION {
            return 0; // a foreign / forward-version snapshot is a cold start, never a guessed parse
        }
        cur = rest;
        let Some(count) = read_u32(&mut cur) else {
            return 0;
        };
        let mut restored = 0usize;
        for _ in 0..count {
            let Some(qname_len) = read_u16(&mut cur) else {
                break;
            };
            let Some(qname_bytes) = take(&mut cur, qname_len as usize) else {
                break;
            };
            let Ok(qname) = std::str::from_utf8(qname_bytes) else {
                break; // a non-UTF-8 qname is corruption (parse_question only ever yields UTF-8)
            };
            let qname = qname.to_owned();
            let Some(qtype) = read_u16(&mut cur) else {
                break;
            };
            let Some(qclass) = read_u16(&mut cur) else {
                break;
            };
            let Some(kind_byte) = take(&mut cur, 1) else {
                break;
            };
            let Some(expiry_unix) = read_u64(&mut cur) else {
                break;
            };
            let Some(stale_until_unix) = read_u64(&mut cur) else {
                break;
            };
            let Some(epoch) = read_u64(&mut cur) else {
                break;
            };
            let Some(wire_len) = read_u32(&mut cur) else {
                break;
            };
            let Some(wire) = take(&mut cur, wire_len as usize) else {
                break;
            };
            // Decide freshness (v2 cold-boot-stale). FRESH: still within its TTL wall-clock deadline.
            // COLD-BOOT-STALE: past the TTL but before the persisted stale deadline AND this cache serves
            // stale — admit with ttl=0 + a per-entry `stale_deadline`. Otherwise drop.
            let (ttl, stale_deadline) = if now_unix < expiry_unix {
                (Duration::from_secs(expiry_unix - now_unix), None)
            } else if self.stale_mode != StaleMode::Off && now_unix < stale_until_unix {
                let grace = stale_until_unix.saturating_sub(now_unix);
                (Duration::ZERO, Some(now + Duration::from_secs(grace)))
            } else {
                continue; // wall-clock-dead (fresh AND stale windows both passed while the device was off)
            };
            // The rebind persist-gate (C): drop a wire the live policy rejects, never resurrect it.
            if !admit(wire) {
                continue;
            }
            let kind = if kind_byte[0] == 1 {
                Kind::Negative
            } else {
                Kind::Positive
            };
            let key = Key {
                qname,
                qtype,
                qclass,
            };
            // Build the REHYDRATED entry (the wire was AD-stripped at its original `insert`, re-stamped
            // as-is) and funnel it through the ONE `insert_entry` map/order/evict discipline — so a restore
            // obeys the same `cap` + LRU + immortal-skip as any insert. `stored = now`; cold-boot-stale
            // entries carry ttl=0 + the per-entry `stale_deadline`.
            let entry = Entry {
                wire: wire.to_vec(),
                stored: now,
                ttl,
                kind,
                epoch,
                immortal: false,
                stale_deadline,
            };
            self.insert_entry(key, entry);
            restored = restored.saturating_add(1);
        }
        restored
    }
}

/// The current blocklist epoch — the installed list's set-deterministic content fingerprint
/// (blocklist.rs:581; 0 if no list is installed). REUSED, not re-derived: a blocklist re-arm changes
/// this value, which is exactly what `get()`'s epoch gate keys on.
fn current_epoch() -> u64 {
    crate::blocklist::installed_fingerprint()
}

/// Take the first `n` bytes off the cursor, advancing it; `None` if fewer than `n` remain. The
/// bounds-guard that makes [`Cache::restore`] OOB-proof on a truncated / hostile snapshot tail.
fn take<'a>(cur: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if cur.len() < n {
        return None;
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Some(head)
}

/// Read a big-endian `u16` off the cursor (advancing it), or `None` if it is short.
fn read_u16(cur: &mut &[u8]) -> Option<u16> {
    let b = take(cur, 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

/// Read a big-endian `u32` off the cursor (advancing it), or `None` if it is short.
fn read_u32(cur: &mut &[u8]) -> Option<u32> {
    let b = take(cur, 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a big-endian `u64` off the cursor (advancing it), or `None` if it is short.
fn read_u64(cur: &mut &[u8]) -> Option<u64> {
    let b = take(cur, 8)?;
    Some(u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{build_query, parse_question};

    fn q(name: &str) -> DnsQuestion {
        parse_question(&build_query(0x1234, name, 1)).expect("question")
    }

    // ---- RAM⊗NAND cache persistence (P12 "Remember" boost) — snapshot/restore --------------------

    /// The persistence guarantee: a snapshot of FRESH entries restores into a fresh cache (a "reboot")
    /// and every answer is served back. The exact-wire match proves the bytes survive, not just the key.
    #[test]
    fn snapshot_restore_round_trips_fresh_entries() {
        let now = Instant::now();
        let now_unix = 1_000_000u64;
        let mut src = Cache::new(16);
        src.put(&q("a.example.com"), vec![1, 2, 3]);
        src.put(&q("b.example.com"), vec![4, 5, 6]);
        src.put(&q("c.example.com"), vec![7, 8, 9]);
        assert_eq!(src.len(), 3);
        let snap = src.snapshot(now, now_unix, 65_536);
        // A FRESH cache (the reboot) rehydrates all three…
        let mut dst = Cache::new(16);
        let restored = dst.restore(&snap, now, now_unix);
        assert_eq!(
            restored, 3,
            "all three fresh entries survive the round-trip"
        );
        assert_eq!(dst.len(), 3);
        // …and the exact wire bytes are served back (epoch 0 — no blocklist in the test).
        assert_eq!(
            dst.get_at(&q("a.example.com"), now, current_epoch()),
            Some(vec![1, 2, 3]),
            "the restored answer is served byte-for-byte"
        );
        assert_eq!(
            dst.get_at(&q("c.example.com"), now, current_epoch()),
            Some(vec![7, 8, 9])
        );
    }

    /// An entry whose WALL-CLOCK deadline passed while the device was off is dropped at restore — the
    /// reason the snapshot stores a wall-clock expiry (not the monotonic `Instant`).
    #[test]
    fn restore_drops_wall_clock_expired_entries() {
        let now = Instant::now();
        let mut src = Cache::new(16);
        src.put(&q("x.example.com"), vec![1, 2, 3]); // fallback TTL 30s
        let snap = src.snapshot(now, 1_000, 65_536); // wall-clock expiry ≈ 1_030
        let mut dst = Cache::new(16);
        // "reboot" 1_000 s later — well past the 30 s deadline: the device was off.
        let restored = dst.restore(&snap, now, 2_000);
        assert_eq!(
            restored, 0,
            "an entry expired during off-time is dropped on restore"
        );
        assert_eq!(dst.len(), 0);
    }

    /// Restore is OOB-proof: a truncated tail STOPS the parse, garbage/empty restores nothing — never a
    /// panic, never an out-of-bounds read (the bounds-guarded cursor).
    #[test]
    fn restore_is_oob_proof_on_hostile_payload() {
        let now = Instant::now();
        let mut src = Cache::new(16);
        src.put(&q("y.example.com"), vec![1, 2, 3, 4, 5]);
        src.put(&q("z.example.com"), vec![6, 7, 8, 9]);
        let snap = src.snapshot(now, 1_000, 65_536);
        // A mid-entry truncation: the parse stops cleanly at the short field.
        let mut dst = Cache::new(16);
        let restored = dst.restore(&snap[..snap.len() / 2], now, 1_000);
        assert!(
            restored <= 2,
            "a truncated tail stops the parse, never panics"
        );
        // Garbage / empty / wrong-version payloads restore nothing.
        let mut dst2 = Cache::new(16);
        assert_eq!(dst2.restore(&[9, 9, 9], now, 1_000), 0);
        assert_eq!(dst2.restore(&[], now, 1_000), 0);
        assert_eq!(
            dst2.restore(&[SNAP_VERSION], now, 1_000),
            0,
            "header-only is no entries"
        );
    }

    /// Build a minimal VALIDATED-SHAPE positive A response for `name` with a single A record at `ttl`.
    /// Header: QR=1, RCODE=0, QD=1, AN=1. Question echoes `build_query`; one A record (name pointer
    /// 0xC00C → question at offset 12, type=1, class=1, ttl, rdlength=4, 4-byte IP). This mirrors a real
    /// answer closely enough that `dns::answer_records` reads the per-record TTL back.
    fn positive_response(name: &str, ttl: u32) -> Vec<u8> {
        let query = build_query(0x1234, name, 1);
        let mut r = query.clone();
        // flags: QR=1 (0x80 on byte 2), RCODE=0.
        r[2] = 0x80;
        r[3] = 0x00;
        // ANCOUNT = 1 (bytes 6..8); QDCOUNT already 1; NS/AR = 0.
        r[6] = 0x00;
        r[7] = 0x01;
        // Append ONE A record: name pointer to the question (0xC0 0x0C), type=1, class=1, ttl, rdlen=4, IP.
        r.extend_from_slice(&[0xC0, 0x0C]); // compressed name → offset 12 (the question)
        r.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        r.extend_from_slice(&ttl.to_be_bytes()); // TTL
        r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
        r.extend_from_slice(&[93, 184, 216, 34]); // 93.184.216.34
        r
    }

    #[test]
    fn put_then_get_round_trips_on_the_question_tuple() {
        let mut c = Cache::new(4);
        assert!(c.get(&q("example.com")).is_none());
        let resp = positive_response("example.com", 3600);
        c.put(&q("example.com"), resp.clone());
        assert_eq!(c.get(&q("example.com")), Some(resp.clone()));
        // a differently-cased / differently-ID'd query for the same name still hits
        assert_eq!(c.get(&q("EXAMPLE.com")), Some(resp));
    }

    #[test]
    fn evicts_lru_not_merely_oldest_inserted() {
        let mut c = Cache::new(2);
        c.put(&q("a.com"), positive_response("a.com", 3600));
        c.put(&q("b.com"), positive_response("b.com", 3600));
        // Touch a.com so it becomes MRU; b.com is now the LRU.
        assert!(c.get(&q("a.com")).is_some());
        c.put(&q("c.com"), positive_response("c.com", 3600)); // evicts the LRU = b.com, NOT a.com
        assert!(
            c.get(&q("a.com")).is_some(),
            "a.com was touched → survives true-LRU eviction"
        );
        assert!(c.get(&q("b.com")).is_none(), "b.com was the LRU → evicted");
        assert!(c.get(&q("c.com")).is_some());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn insertion_order_eviction_still_holds_without_touch() {
        // With no get() between puts, the front of `order` is the oldest insert — eviction matches the
        // 2b guarantee the stub's test asserted.
        let mut c = Cache::new(2);
        c.put(&q("a.com"), positive_response("a.com", 3600));
        c.put(&q("b.com"), positive_response("b.com", 3600));
        c.put(&q("c.com"), positive_response("c.com", 3600)); // evicts a.com
        assert!(c.get(&q("a.com")).is_none());
        assert!(c.get(&q("b.com")).is_some());
        assert!(c.get(&q("c.com")).is_some());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn d16_hash_first_recency_survives_a_large_working_set() {
        // D16 — the O(1)/O(log n) recency index must behave EXACTLY like the old O(n) Vec LRU under a
        // large, churny set: fill to cap, keep one hot key touched, churn the rest, and prove the hot
        // key never evicts while cold keys roll over. A regression here would mean the seq/recency
        // bookkeeping drifted from the map.
        let cap = 64usize;
        let mut c = Cache::new(cap);
        for i in 0..cap {
            c.put(
                &q(&format!("host{i}.example")),
                positive_response("h", 3600),
            );
        }
        assert_eq!(c.len(), cap);
        // Insert 200 fresh names, touching the hot key BEFORE each insert so it is always MRU and
        // never the eviction victim (the touch must precede the put that triggers evict_to_cap).
        for i in cap..(cap + 200) {
            assert!(
                c.get(&q("host0.example")).is_some(),
                "the continuously-touched hot key never evicts (i={i})"
            );
            c.put(
                &q(&format!("host{i}.example")),
                positive_response("h", 3600),
            );
        }
        assert!(
            c.get(&q("host0.example")).is_some(),
            "the hot key survived the whole churn"
        );
        assert_eq!(c.len(), cap, "the cap holds exactly across the churn");
        // A never-touched early cold key has long since rolled out.
        assert!(
            c.get(&q("host5.example")).is_none(),
            "a cold key churned out under the cap"
        );
    }

    #[test]
    fn ttl_expiry_makes_get_a_miss_and_drops_the_entry() {
        let mut c = Cache::new(4);
        let resp = positive_response("example.com", 10); // 10s TTL
        c.put(&q("example.com"), resp);
        let t0 = Instant::now();
        let epoch = current_epoch();
        // Fresh at +5s.
        assert!(c
            .get_at(&q("example.com"), t0 + Duration::from_secs(5), epoch)
            .is_some());
        // Expired at +11s → miss AND the entry is dropped (no serve-stale by default).
        assert!(c
            .get_at(&q("example.com"), t0 + Duration::from_secs(11), epoch)
            .is_none());
        assert_eq!(c.len(), 0, "expired entry is evicted on the miss");
    }

    #[test]
    fn min_ttl_floor_raises_a_tiny_ttl() {
        // floor 60s, ceiling default; a 5s answer is clamped UP to 60s.
        let mut c = Cache::with_policy(
            4,
            60,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            0,
        );
        c.put(&q("cdn.example"), positive_response("cdn.example", 5));
        let t0 = Instant::now();
        let epoch = current_epoch();
        // Still fresh at +30s (would have expired at the raw 5s TTL).
        assert!(c
            .get_at(&q("cdn.example"), t0 + Duration::from_secs(30), epoch)
            .is_some());
    }

    #[test]
    fn max_ttl_ceiling_caps_a_huge_ttl() {
        // ceiling 100s; a 1-day answer is clamped DOWN to 100s.
        let mut c = Cache::with_policy(4, 0, 100, DEFAULT_NEG_TTL_CEILING_SECS, 0);
        c.put(
            &q("slow.example"),
            positive_response("slow.example", 86_400),
        );
        let t0 = Instant::now();
        let epoch = current_epoch();
        assert!(c
            .get_at(&q("slow.example"), t0 + Duration::from_secs(50), epoch)
            .is_some());
        assert!(
            c.get_at(&q("slow.example"), t0 + Duration::from_secs(101), epoch)
                .is_none(),
            "TTL was clamped to the 100s ceiling"
        );
    }

    #[test]
    fn negative_ttl_is_hard_clamped_to_the_ceiling() {
        // neg ceiling 60s; a caller-supplied 1-hour SOA-min is clamped DOWN to 60s so a denial can
        // never pin forever (the forever-cache guard).
        let mut c = Cache::with_policy(4, 0, DEFAULT_TTL_CEILING_SECS, 60, 0);
        // A negative is still a validated wire; reuse the positive shape (content irrelevant to TTL).
        let denial = positive_response("nope.example", 0);
        c.put_negative(&q("nope.example"), denial, 3600);
        let t0 = Instant::now();
        let epoch = current_epoch();
        assert!(c
            .get_at(&q("nope.example"), t0 + Duration::from_secs(30), epoch)
            .is_some());
        assert!(
            c.get_at(&q("nope.example"), t0 + Duration::from_secs(61), epoch)
                .is_none(),
            "neg-TTL clamped to the 60s ceiling — a denial never pins forever"
        );
    }

    #[test]
    fn negative_ttl_never_zero() {
        // A 0 neg-TTL is raised to ≥1s so a denial doesn't expire instantly into a re-query storm.
        let mut c = Cache::with_policy(4, 0, DEFAULT_TTL_CEILING_SECS, 300, 0);
        let denial = positive_response("zero.example", 0);
        c.put_negative(&q("zero.example"), denial, 0);
        let t0 = Instant::now();
        let epoch = current_epoch();
        assert!(c.get_at(&q("zero.example"), t0, epoch).is_some());
    }

    #[test]
    fn epoch_change_invalidates_lazily_without_reconfigure() {
        // THE load-bearing 2e invariant: an entry stored under epoch E is a MISS once the LIVE epoch
        // changes (a blocklist re-arm), with NO configure() rebuild.
        let mut c = Cache::new(4);
        c.put(&q("example.com"), positive_response("example.com", 3600));
        let t0 = Instant::now();
        let stored_epoch = c.peek_entry(&q("example.com")).unwrap().epoch;
        // Same epoch → fresh hit.
        assert!(c.get_at(&q("example.com"), t0, stored_epoch).is_some());
        // A DIFFERENT live epoch → miss + drop, even though the TTL is far from expiry.
        let new_epoch = stored_epoch.wrapping_add(0xDEAD_BEEF);
        assert!(c.get_at(&q("example.com"), t0, new_epoch).is_none());
        assert_eq!(c.len(), 0, "stale-epoch entry is evicted on the miss");
    }

    #[test]
    fn serve_stale_returns_expired_within_window_but_off_by_default() {
        let t0 = Instant::now();
        let epoch = current_epoch();

        // Default: serve-stale OFF → expired is a hard miss.
        let mut off = Cache::new(4);
        off.put(&q("a.example"), positive_response("a.example", 10));
        assert!(off
            .get_at(&q("a.example"), t0 + Duration::from_secs(11), epoch)
            .is_none());

        // serve-stale 30s window: expired at +11s but within the 30s stale window → still served.
        let mut on = Cache::with_policy(
            4,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            30,
        );
        on.put(&q("a.example"), positive_response("a.example", 10));
        assert!(
            on.get_at(&q("a.example"), t0 + Duration::from_secs(11), epoch)
                .is_some(),
            "within the serve-stale window the expired bytes are served"
        );
        // Past the stale window (10s TTL + 30s stale = 40s) → miss.
        assert!(on
            .get_at(&q("a.example"), t0 + Duration::from_secs(45), epoch)
            .is_none());
    }

    #[test]
    fn serve_stale_still_honors_the_epoch() {
        // serve-stale must NEVER serve a stale answer for a now-invalidated (re-armed-blocklist) name.
        let mut c = Cache::with_policy(
            4,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            300,
        );
        c.put(
            &q("blocked.example"),
            positive_response("blocked.example", 10),
        );
        let t0 = Instant::now();
        let stored_epoch = c.peek_entry(&q("blocked.example")).unwrap().epoch;
        // Expired but within the stale window AND a changed epoch → still a miss (epoch gate wins).
        let new_epoch = stored_epoch.wrapping_add(7);
        assert!(c
            .get_at(
                &q("blocked.example"),
                t0 + Duration::from_secs(11),
                new_epoch
            )
            .is_none());
    }

    #[test]
    fn zero_ceiling_config_coerces_to_a_sane_default_never_disables_cache() {
        // A 0 positive-ceiling would clamp every TTL to 0 (instant expiry); with_policy coerces it.
        let mut c = Cache::with_policy(4, 0, 0, 0, 0);
        c.put(&q("ok.example"), positive_response("ok.example", 3600));
        let t0 = Instant::now();
        let epoch = current_epoch();
        assert!(
            c.get_at(&q("ok.example"), t0 + Duration::from_secs(60), epoch)
                .is_some(),
            "a 0 ceiling must not silently disable the cache"
        );
    }

    #[test]
    fn replacing_a_key_refreshes_its_lru_position() {
        let mut c = Cache::new(2);
        c.put(&q("a.com"), positive_response("a.com", 3600));
        c.put(&q("b.com"), positive_response("b.com", 3600));
        // Re-put a.com → it becomes MRU (b.com is now LRU), and len stays 2.
        c.put(&q("a.com"), positive_response("a.com", 3600));
        assert_eq!(c.len(), 2);
        c.put(&q("c.com"), positive_response("c.com", 3600)); // evicts the LRU = b.com
        assert!(c.get(&q("a.com")).is_some());
        assert!(c.get(&q("b.com")).is_none());
        assert!(c.get(&q("c.com")).is_some());
    }

    #[test]
    fn kind_is_recorded_distinctly() {
        let mut c = Cache::new(4);
        c.put(&q("pos.example"), positive_response("pos.example", 100));
        c.put_negative(&q("neg.example"), positive_response("neg.example", 0), 60);
        assert_eq!(
            c.peek_entry(&q("pos.example")).unwrap().kind,
            Kind::Positive
        );
        assert_eq!(
            c.peek_entry(&q("neg.example")).unwrap().kind,
            Kind::Negative
        );
    }

    // ---- P12 additive seams: N2 (cacheable-type set), R4 (local-ttl), N3 (AD-bit discipline) -----

    /// Build a minimal VALIDATED-SHAPE positive response for `name` whose single Answer record carries
    /// the given RR `rtype` (mirrors `positive_response`, which is hard-wired to A=1). `rdlen`/RDATA are
    /// 4 bytes of placeholder — `answer_records` reads the type from the fixed-offset TYPE field, the
    /// RDATA bytes are opaque (the skimmer never interprets RDATA). The question is built as `A` so the
    /// key is deterministic, but the ANSWER's type is what the N2 gate reads.
    fn typed_response(name: &str, rtype: u16, ttl: u32) -> Vec<u8> {
        let mut r = build_query(0x1234, name, 1);
        r[2] = 0x80; // QR=1
        r[3] = 0x00; // RCODE=0
        r[6] = 0x00;
        r[7] = 0x01; // ANCOUNT=1
        r.extend_from_slice(&[0xC0, 0x0C]); // name pointer → question
        r.extend_from_slice(&rtype.to_be_bytes()); // TYPE = the type under test
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        r.extend_from_slice(&ttl.to_be_bytes()); // TTL
        r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
        r.extend_from_slice(&[10, 0, 0, 1]); // opaque RDATA
        r
    }

    // ----- N2 -----

    /// N2: the MEASURED default cacheable set is {A=1, AAAA=28, SRV=33, PTR=12} — NOT the man page's
    /// overstated {A,AAAA,CNAME,SRV} (CNAME is excluded as standalone cache data, `rfc1035.c`). Under
    /// the default `--cache-rr` set, A/AAAA/SRV/PTR cache; HTTPS(65) does NOT — until opted in.
    /// (Spec-continuity name uses "cname" for the row; the assertion is against the measured set.)
    #[test]
    fn cache_rr_default_set_holds_a_aaaa_srv_ptr_only_extras_opt_in() {
        // EMPTY slice installs the dnsmasq DEFAULT set {A,AAAA,SRV,PTR}.
        let mut c = Cache::with_cacheable_types(
            8,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            0,
            &[],
        );

        // A(1), AAAA(28), SRV(33), PTR(12) are all in the default set → cached.
        for (name, ty) in [
            ("a.example", 1u16),
            ("aaaa.example", 28),
            ("srv.example", 33),
            ("ptr.example", 12),
        ] {
            c.put(&q(name), typed_response(name, ty, 3600));
            assert!(
                c.get(&q(name)).is_some(),
                "{name} (type {ty}) is in the default set → cached"
            );
        }

        // HTTPS(65) is NOT in the default set → the put is declined (not cached).
        c.put(
            &q("https.example"),
            typed_response("https.example", 65, 3600),
        );
        assert!(
            c.get(&q("https.example")).is_none(),
            "HTTPS(65) not in default set → not cached"
        );

        // Opt-in: widen to include HTTPS(65) → now it caches.
        c.set_cacheable_types(&[1, 28, 33, 12, 65]);
        c.put(
            &q("https.example"),
            typed_response("https.example", 65, 3600),
        );
        assert!(
            c.get(&q("https.example")).is_some(),
            "after opt-in to HTTPS(65) → cached"
        );
    }

    /// N2: the constructed default (`new`/`with_policy`) is cache-ALL — byte-identical today's behaviour
    /// (no type gate). A non-default-set type like TXT(16) caches on a plain `new` cache. This is what
    /// keeps the 21 shipped tests + the two integration key-locks green (they never opt in to a set).
    #[test]
    fn default_cache_is_cache_all_no_type_gate() {
        let mut c = Cache::new(8);
        c.put(&q("txt.example"), typed_response("txt.example", 16, 3600)); // TXT, not in any opt-in set
        assert!(
            c.get(&q("txt.example")).is_some(),
            "default (All) caches every type — today's behaviour"
        );
    }

    /// N2: the `=ANY` sentinel (255) collapses an explicit set request back to cache-all, and a
    /// short/indeterminable wire FAILS OPEN to cacheable even under a narrow `Only(set)` policy — so the
    /// integration lock that `put`s a 3-byte placeholder wire and demands a hit can never regress.
    #[test]
    fn cache_rr_any_sentinel_and_indeterminable_wire_fail_open() {
        // ANY sentinel → All.
        let mut any = Cache::with_cacheable_types(
            8,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            0,
            &[255],
        );
        any.put(&q("txt.example"), typed_response("txt.example", 16, 3600));
        assert!(
            any.get(&q("txt.example")).is_some(),
            "=ANY sentinel ⇒ cache-all"
        );

        // Narrow set {A}, but a 3-byte non-DNS wire is indeterminable → FAIL OPEN (the integ-lock shape).
        let mut narrow = Cache::with_cacheable_types(
            8,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            0,
            &[1],
        );
        narrow.put(&q("placeholder.example"), vec![7, 7, 7]);
        assert!(
            narrow.get(&q("placeholder.example")).is_some(),
            "an indeterminable wire fails open to cacheable even under a narrow set (integ-lock safety)"
        );
    }

    // ----- R4 -----

    /// R4: a pinned local record stamped via `put_local` uses the configured `local-ttl` clamp (floored
    /// ≥1s, capped at the positive ceiling), NOT the answer wire's TTL. With local-ttl 120s, a record
    /// whose wire says 5s survives to +60s; with no override, `put_local` falls back to the wire TTL.
    #[test]
    fn local_record_uses_the_local_ttl_clamp_when_set() {
        let t0 = Instant::now();
        let epoch = current_epoch();

        // local-ttl = 120s overrides the wire's 5s TTL → still fresh at +60s.
        let mut pinned = Cache::new(4);
        pinned.set_local_ttl(Some(Duration::from_secs(120)));
        pinned.put_local(&q("myhost.local"), typed_response("myhost.local", 1, 5));
        assert!(
            pinned
                .get_at(&q("myhost.local"), t0 + Duration::from_secs(60), epoch)
                .is_some(),
            "local-ttl 120s holds past the wire's 5s TTL"
        );

        // No override → put_local falls back to the wire TTL (5s) → expired at +10s.
        let mut fallback = Cache::new(4);
        fallback.put_local(&q("other.local"), typed_response("other.local", 1, 5));
        assert!(
            fallback
                .get_at(&q("other.local"), t0 + Duration::from_secs(10), epoch)
                .is_none(),
            "no local-ttl override ⇒ falls back to the wire's 5s TTL"
        );
    }

    /// R4: a local-ttl is floored at ≥1s (a 0 override would expire instantly) and capped at the
    /// positive ceiling (a local pin can't outlive the `max-cache-ttl` insurance).
    #[test]
    fn local_ttl_is_floored_at_1s_and_capped_at_the_ceiling() {
        let t0 = Instant::now();
        let epoch = current_epoch();

        // Zero override → floored to ≥1s (entry present at t0, not instantly gone).
        let mut zero = Cache::new(4);
        zero.set_local_ttl(Some(Duration::ZERO));
        zero.put_local(&q("z.local"), typed_response("z.local", 1, 3600));
        assert!(
            zero.get_at(&q("z.local"), t0, epoch).is_some(),
            "0 local-ttl floored to ≥1s, not instant-expiry"
        );

        // Huge override on a 100s ceiling → capped to 100s (gone by +101s).
        let mut huge = Cache::with_policy(4, 0, 100, DEFAULT_NEG_TTL_CEILING_SECS, 0);
        huge.set_local_ttl(Some(Duration::from_secs(86_400)));
        huge.put_local(&q("h.local"), typed_response("h.local", 1, 3600));
        assert!(
            huge.get_at(&q("h.local"), t0 + Duration::from_secs(50), epoch)
                .is_some(),
            "fresh within the 100s cap"
        );
        assert!(
            huge.get_at(&q("h.local"), t0 + Duration::from_secs(101), epoch)
                .is_none(),
            "local-ttl capped at the 100s positive ceiling"
        );
    }

    // ----- N3 -----

    /// Build a positive A response with the AD bit (byte 3, 0x20) SET — to prove the cache strips it.
    fn positive_response_with_ad(name: &str, ttl: u32) -> Vec<u8> {
        let mut r = positive_response(name, ttl);
        r[3] |= AD_BIT_MASK; // upstream set AD (claims authenticated data)
        r
    }

    /// N3 — the load-bearing cache-discipline half (FALSE-GREEN TRAP #2): the cache must NEVER serve a
    /// stale AD bit cross-context. An upstream answer with AD set is stored AD-cleared, and a cache HIT
    /// returns the answer with AD=0 — even though the original upstream wire had AD=1. (The live
    /// forward-path `--proxy-dnssec` pass-through is the resolver's job, mod.rs; this proves the cache
    /// never lets AD survive into or out of itself.)
    #[test]
    fn proxy_dnssec_passes_ad_bit_through_but_never_serves_a_stale_ad_bit_cross_context() {
        let mut c = Cache::new(4);
        let upstream = positive_response_with_ad("secure.example", 3600);
        assert_eq!(
            upstream[3] & AD_BIT_MASK,
            AD_BIT_MASK,
            "precondition: upstream wire HAS the AD bit set"
        );

        c.put(&q("secure.example"), upstream.clone());
        let hit = c.get(&q("secure.example")).expect("cache hit");
        assert_eq!(
            hit[3] & AD_BIT_MASK,
            0,
            "a cache-served answer must NEVER carry the AD bit — AD describes the upstream exchange, not the cached RRset"
        );
        // And the rest of byte 3 (RCODE low nibble) is intact — the mask was precise.
        assert_eq!(
            hit[3] & 0x0F,
            upstream[3] & 0x0F,
            "RCODE low-nibble untouched — AD mask is precise (0x20 only)"
        );
    }

    /// N3: `strip_ad_bit` is precise — it clears ONLY 0x20, leaving RCODE/Z/CD on byte 3 intact, and is
    /// a no-op on a sub-header wire (the 3-byte placeholder-wire locks stay green).
    #[test]
    fn strip_ad_bit_is_precise_and_safe_on_short_wires() {
        // All other byte-3 bits set, AD set → only AD cleared.
        let mut w = vec![0u8, 0, 0, 0xFF];
        Cache::strip_ad_bit(&mut w);
        assert_eq!(
            w[3],
            0xFF & !AD_BIT_MASK,
            "only the 0x20 AD bit cleared; the rest of byte 3 survives"
        );

        // Sub-header wire → no panic, no change.
        let mut short = vec![1u8, 2, 3];
        Cache::strip_ad_bit(&mut short);
        assert_eq!(short, vec![1u8, 2, 3], "no-op on a sub-header wire");
    }

    // ---- MaskSolver CACHE-cross (slice 3): SOLVE×CACHE×RAM⊗NAND synthesis ------------------------

    // ----- B · serve-stale-while-revalidate SIGNAL (get_hit → Fresh/Stale) -----

    /// B: `get_hit` reports [`Freshness::Fresh`] within TTL and [`Freshness::Stale`] within the serve-stale
    /// window (the revalidation signal the resolver acts on), then a hard miss past the window.
    #[test]
    fn get_hit_reports_fresh_then_stale_then_miss() {
        let mut c = Cache::with_policy(
            4,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            30, // serve-stale window 30s
        );
        c.put(&q("a.example"), positive_response("a.example", 10)); // 10s TTL
        let t0 = Instant::now();
        let epoch = current_epoch();
        // The public real-clock `get_hit` reports Fresh immediately after the put.
        assert_eq!(
            c.get_hit(&q("a.example"))
                .expect("live fresh hit")
                .freshness,
            Freshness::Fresh
        );
        // Fresh at +5s.
        let fresh = c
            .get_hit_at(&q("a.example"), t0 + Duration::from_secs(5), epoch)
            .expect("fresh hit");
        assert_eq!(fresh.freshness, Freshness::Fresh);
        // Expired at +11s but within the 30s stale window → served STALE (signal: revalidate).
        let stale = c
            .get_hit_at(&q("a.example"), t0 + Duration::from_secs(11), epoch)
            .expect("stale hit");
        assert_eq!(
            stale.freshness,
            Freshness::Stale,
            "expired-within-window serves stale + signals revalidate"
        );
        // Past the stale window (10 + 30 = 40s) → miss.
        assert!(c
            .get_hit_at(&q("a.example"), t0 + Duration::from_secs(45), epoch)
            .is_none());
    }

    /// B: the `Unbounded` mode (dnsmasq's `-1`, the `u64::MAX` sentinel) serves an expired entry
    /// REGARDLESS of how long ago it expired — where a finite window would miss.
    #[test]
    fn unbounded_serve_stale_serves_regardless_of_age() {
        let mut c = Cache::with_policy(
            4,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            u64::MAX, // → StaleMode::Unbounded
        );
        c.put(&q("old.example"), positive_response("old.example", 10));
        let t0 = Instant::now();
        let epoch = current_epoch();
        // A full DAY past expiry → still served STALE (unbounded).
        let hit = c
            .get_hit_at(&q("old.example"), t0 + Duration::from_secs(86_400), epoch)
            .expect("unbounded stale hit");
        assert_eq!(hit.freshness, Freshness::Stale);
    }

    // ----- B-CROWN · cold-boot serve-stale (the original neither source has) -----

    /// B-CROWN: a stale-eligible entry survives a REBOOT and the first post-reboot query serves it STALE
    /// (instant from NAND⊗RAM while the resolver revalidates) — "SOLVES resiliently AND CACHES on RAM⊗NAND",
    /// the exact original the brief demands. dnsmasq has no persistence; the v1 cache persisted fresh-only.
    #[test]
    fn cold_boot_serve_stale_survives_a_reboot_and_signals_revalidate() {
        let now = Instant::now();
        // src serves stale (30s window). Put a 10s-TTL answer; snapshot while still fresh at unix 1005
        // (expiry ≈ 1015, stale_until ≈ 1045).
        let mut src = Cache::with_policy(
            16,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            30,
        );
        src.put(&q("hot.example"), positive_response("hot.example", 10));
        let snap = src.snapshot(now, 1_005, 65_536);
        // "reboot" at unix 1025 — PAST the TTL expiry (1015) but WITHIN the stale window (1045).
        let mut dst = Cache::with_policy(
            16,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            30,
        );
        let restored = dst.restore(&snap, now, 1_025);
        assert_eq!(
            restored, 1,
            "a stale-eligible entry survives the reboot (cold-boot serve-stale)"
        );
        // The first post-reboot query serves it STALE — the crown.
        let hit = dst
            .get_hit_at(&q("hot.example"), now, current_epoch())
            .expect("cold-boot stale hit");
        assert_eq!(
            hit.freshness,
            Freshness::Stale,
            "cold-boot answer serves stale + signals revalidate"
        );
    }

    /// B-CROWN: a past-TTL entry is NOT cold-boot-admitted when the restored cache does NOT serve stale
    /// (no cold-boot-stale without a stale policy). And a still-fresh entry rehydrates fresh regardless.
    #[test]
    fn cold_boot_stale_dropped_when_restored_cache_does_not_serve_stale() {
        let now = Instant::now();
        let mut src = Cache::with_policy(
            16,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            30,
        );
        src.put(&q("hot.example"), positive_response("hot.example", 10));
        let snap = src.snapshot(now, 1_005, 65_536); // expiry ≈ 1015, stale_until ≈ 1045
                                                     // dst serve-stale OFF, "reboot" at 1025 (past 1015, within 1045) → NOT admitted.
        let mut off = Cache::new(16);
        assert_eq!(
            off.restore(&snap, now, 1_025),
            0,
            "serve-stale OFF ⇒ a past-TTL entry is not cold-boot-admitted"
        );
        // But a still-fresh reboot (at 1010, before expiry 1015) rehydrates fresh even with serve-stale OFF.
        let mut off2 = Cache::new(16);
        assert_eq!(
            off2.restore(&snap, now, 1_010),
            1,
            "fresh entries rehydrate regardless of stale policy"
        );
        let hit = off2
            .get_hit_at(&q("hot.example"), now, current_epoch())
            .expect("fresh rehydrate");
        assert_eq!(hit.freshness, Freshness::Fresh);
    }

    // ----- C · rebind persist-gate (restore_gated) -----

    /// C: `restore_gated` DROPS a rehydrated wire the live policy rejects (the rebind persist-gate),
    /// closing the persist/serve-stale resurrection window the live resolve-path gate misses. The
    /// ungated `restore` admits both — the gate is the resolver's explicit choice.
    #[test]
    fn restore_gated_drops_a_wire_the_live_policy_rejects() {
        let now = Instant::now();
        let mut src = Cache::new(16);
        src.put(&q("good.example"), positive_response("good.example", 3600));
        src.put(
            &q("rebind.example"),
            positive_response("rebind.example", 3600),
        );
        let snap = src.snapshot(now, 1_000, 65_536);

        // The resolver's live re-gate stand-in: reject any wire whose question carries "rebind"
        // (a proxy for `guardian::is_rebind` + the NAME allowlist the resolver supplies).
        let mut dst = Cache::new(16);
        let restored = dst.restore_gated(&snap, now, 1_000, &|wire| {
            !wire.windows(6).any(|w| w == b"rebind".as_slice())
        });
        assert_eq!(
            restored, 1,
            "the rejected (rebind) wire is dropped at rehydrate; the good one is admitted"
        );
        assert!(dst
            .get_at(&q("good.example"), now, current_epoch())
            .is_some());
        assert!(
            dst.get_at(&q("rebind.example"), now, current_epoch())
                .is_none(),
            "a rebind answer is never resurrected from NAND"
        );

        // Ungated restore admits BOTH — the gate is opt-in.
        let mut ungated = Cache::new(16);
        assert_eq!(
            ungated.restore(&snap, now, 1_000),
            2,
            "ungated restore admits both — the gate is the resolver's choice"
        );
    }

    // ----- D · immortal (host-record) class -----

    /// D: an immortal record is exempt from BOTH TTL expiry AND cap eviction — only a rebuild/clear
    /// removes it. Mortal entries stay bounded to `cap`; the immortal survives regardless.
    #[test]
    fn immortal_records_survive_expiry_and_cap_eviction() {
        let t0 = Instant::now();
        let epoch = current_epoch();
        let mut c = Cache::new(2);
        c.put_immortal(&q("host.local"), positive_response("host.local", 1)); // wire says 1s
                                                                              // Never ages out — served a full day past its wire TTL.
        assert!(
            c.get_at(&q("host.local"), t0 + Duration::from_secs(86_400), epoch)
                .is_some(),
            "immortal never expires"
        );
        // Overflow the cap with mortal entries; the immortal is NEVER evicted.
        c.put(&q("m1.com"), positive_response("m1.com", 3600));
        c.put(&q("m2.com"), positive_response("m2.com", 3600));
        c.put(&q("m3.com"), positive_response("m3.com", 3600));
        assert!(
            c.get_at(&q("host.local"), t0, epoch).is_some(),
            "immortal bypasses cap eviction"
        );
        // Exactly one mortal slot survives (cap 2 − 1 immortal) — the newest, m3.
        let mortal_hits = ["m1.com", "m2.com", "m3.com"]
            .iter()
            .filter(|n| c.get_at(&q(n), t0, epoch).is_some())
            .count();
        assert_eq!(
            mortal_hits, 1,
            "mortal entries stay bounded to cap; the newest survives"
        );
        assert!(
            c.get_at(&q("m3.com"), t0, epoch).is_some(),
            "the most-recent mortal is the survivor"
        );
    }

    // ----- F · explicit-0-TTL "do not cache" (opt-in) -----

    /// F: with the opt-in ON and serve-stale Off, an EXPLICIT 0-TTL positive is declined ("use once, do
    /// not cache", dnsmasq); default OFF keeps today's 30s-fallback behaviour; an indeterminable wire
    /// fails open; and with serve-stale ON a 0-TTL answer IS cached (to serve stale).
    #[test]
    fn honor_zero_ttl_declines_explicit_zero_only_when_opted_in_and_stale_off() {
        let t0 = Instant::now();
        let epoch = current_epoch();

        // Default OFF: an explicit-0 positive is cached (30s fallback) — byte-identical legacy behaviour.
        let mut legacy = Cache::new(4);
        legacy.put(&q("z.example"), positive_response("z.example", 0));
        assert!(
            legacy.get_at(&q("z.example"), t0, epoch).is_some(),
            "default OFF ⇒ explicit-0 still cached (30s fallback)"
        );

        // Opted in + serve-stale Off: the explicit-0 positive is DECLINED.
        let mut honor = Cache::new(4);
        honor.set_honor_zero_ttl(true);
        honor.put(&q("z.example"), positive_response("z.example", 0));
        assert!(
            honor.get_at(&q("z.example"), t0, epoch).is_none(),
            "honor-0 + stale-off ⇒ explicit-0 not cached"
        );
        // A NON-zero TTL is unaffected by the toggle.
        honor.put(&q("ok.example"), positive_response("ok.example", 300));
        assert!(
            honor.get_at(&q("ok.example"), t0, epoch).is_some(),
            "a non-zero TTL still caches under honor-0"
        );
        // An indeterminable wire is never "explicitly 0" → fails open → cached (placeholder-wire lock).
        honor.put(&q("ph.example"), vec![7, 7, 7]);
        assert!(
            honor.get_at(&q("ph.example"), t0, epoch).is_some(),
            "indeterminable wire fails open even under honor-0"
        );

        // serve-stale ON: an explicit-0 IS cached (stale value in retaining it, faithful to dnsmasq).
        let mut stale = Cache::with_policy(
            4,
            0,
            DEFAULT_TTL_CEILING_SECS,
            DEFAULT_NEG_TTL_CEILING_SECS,
            30,
        );
        stale.set_honor_zero_ttl(true);
        stale.put(&q("z.example"), positive_response("z.example", 0));
        assert!(
            stale.get_at(&q("z.example"), t0, epoch).is_some(),
            "honor-0 + serve-stale ON ⇒ 0-TTL cached to serve stale"
        );
    }

    // ----- A · SOA-derived negative-cache TTL wiring (put_negative_from_response) -----

    /// A: `put_negative_from_response` derives the neg-TTL from the response's Authority SOA via
    /// [`crate::dns::negative_ttl_from_soa`] (proven in dns.rs), falling back to the caller default when
    /// no SOA is present, and the result is STILL hard-clamped to the negative ceiling (a denial never
    /// pins forever). This test proves the WIRING: a no-SOA denial uses the default, clamped to the ceiling.
    #[test]
    fn put_negative_from_response_falls_back_and_clamps_without_an_soa() {
        // neg ceiling 60s; a validated-shape denial with NO Authority SOA → uses the default (120s) →
        // hard-clamped DOWN to 60s.
        let mut c = Cache::with_policy(4, 0, DEFAULT_TTL_CEILING_SECS, 60, 0);
        let denial = positive_response("gone.example", 0); // no Authority SOA in this wire
        c.put_negative_from_response(&q("gone.example"), denial, 120);
        let t0 = Instant::now();
        let epoch = current_epoch();
        assert!(
            c.get_at(&q("gone.example"), t0 + Duration::from_secs(30), epoch)
                .is_some(),
            "cached within the clamped neg-TTL"
        );
        assert!(
            c.get_at(&q("gone.example"), t0 + Duration::from_secs(61), epoch)
                .is_none(),
            "default 120 clamped DOWN to the 60s neg-ceiling — a denial never pins forever"
        );
    }

    // ========================================================================
    // FORMAL VERIFICATION GAPS - Tests for Caveman Prover findings
    // ========================================================================

    /// GAP 3: Cache LRU Eviction Correctness
    /// Proves: Eviction removes the least-recently-used non-immortal entry
    #[test]
    fn lru_eviction_removes_least_recently_used_non_immortal() {
        // Create cache with cap=2
        let mut c = Cache::with_policy(2, 0, DEFAULT_TTL_CEILING_SECS, DEFAULT_NEG_TTL_CEILING_SECS, 0);
        let t0 = Instant::now();
        let epoch = current_epoch();

        // Insert h1 (seq=0)
        c.put(&q("a.example"), positive_response("a.example", 300));
        // Insert h2 (seq=1) - h2 is now MRU (most recently used)
        c.put(&q("b.example"), positive_response("b.example", 300));
        // Insert h3 (seq=2) - should evict h1 (seq=0, the LRU)
        c.put(&q("c.example"), positive_response("c.example", 300));

        // Verify h1 was evicted (LRU with lowest seq)
        assert!(c.get_at(&q("a.example"), t0, epoch).is_none(), "h1 (LRU) should be evicted");
        // Verify h2 and h3 remain
        assert!(c.get_at(&q("b.example"), t0, epoch).is_some(), "h2 should remain");
        assert!(c.get_at(&q("c.example"), t0, epoch).is_some(), "h3 should remain");
    }

    /// GAP 3: LRU with immortal entries
    /// Proves: Eviction preserves immortal entries
    #[test]
    fn lru_eviction_preserves_immortal_entries() {
        let mut c = Cache::with_policy(2, 0, DEFAULT_TTL_CEILING_SECS, DEFAULT_NEG_TTL_CEILING_SECS, 0);
        let t0 = Instant::now();
        let epoch = current_epoch();

        // Insert immortal h1
        let h1 = q("immortal.example");
        c.put_immortal(&h1, positive_response("immortal.example", 300));
        // Insert normal h2
        c.put(&q("normal1.example"), positive_response("normal1.example", 300));
        // Insert normal h3 - should evict h2 (normal), NOT h1 (immortal)
        c.put(&q("normal2.example"), positive_response("normal2.example", 300));

        // Verify immortal h1 was NOT evicted
        assert!(c.get_at(&h1, t0, epoch).is_some(), "immortal entry should never be evicted");
        // Verify one normal was evicted
        assert!(c.len() == 2, "cache should have exactly 2 entries (1 immortal + 1 normal)");
    }

    /// GAP 3: Touch makes entry MRU
    /// Proves: Touch operation updates recency correctly
    #[test]
    fn touch_makes_entry_mru() {
        let mut c = Cache::with_policy(3, 0, DEFAULT_TTL_CEILING_SECS, DEFAULT_NEG_TTL_CEILING_SECS, 0);
        let t0 = Instant::now();
        let epoch = current_epoch();

        // Insert in order: h1, h2, h3
        c.put(&q("h1.example"), positive_response("h1.example", 300));
        c.put(&q("h2.example"), positive_response("h2.example", 300));
        c.put(&q("h3.example"), positive_response("h3.example", 300));

        // Touch h1 - now h1 should be MRU (most recently used)
        let _ = c.get_at(&q("h1.example"), t0, epoch); // get touches

        // Insert h4 - should evict h2 (the OLD LRU, not h1 which was touched)
        c.put(&q("h4.example"), positive_response("h4.example", 300));

        // Verify h1 remains (was touched = MRU)
        assert!(c.get_at(&q("h1.example"), t0, epoch).is_some(), "h1 (touched) should remain");
        // Verify h2 was evicted (was LRU before h1 was touched)
        assert!(c.get_at(&q("h2.example"), t0, epoch).is_none(), "h2 (old LRU) should be evicted");
    }

    /// GAP 2: Cache Replay Correctness
    /// Proves: Cache replay returns same verdict as fresh computation
    /// This is a simplified test - full proof would require modeling the entire verdict path
    #[test]
    fn cache_consistency_basic() {
        let mut c = Cache::with_policy(4, 0, DEFAULT_TTL_CEILING_SECS, DEFAULT_NEG_TTL_CEILING_SECS, 0);
        let t0 = Instant::now();
        let epoch = current_epoch();

        // Insert and get - should return same data
        let q = q("test.example");
        let resp = positive_response("test.example", 300);
        c.put(&q, resp.clone());

        let retrieved = c.get_at(&q, t0, epoch);
        assert!(retrieved.is_some(), "should find cached entry");
        assert_eq!(retrieved.unwrap(), resp, "cached data should match original");
    }

    /// GAP 2: Epoch gating prevents stale cache reads
    #[test]
    fn epoch_gating_prevents_stale_reads() {
        let mut c = Cache::with_policy(4, 0, DEFAULT_TTL_CEILING_SECS, DEFAULT_NEG_TTL_CEILING_SECS, 0);
        let t0 = Instant::now();
        let epoch1 = current_epoch();

        // Insert in epoch1
        c.put(&q("test.example"), positive_response("test.example", 300));

        // Verify readable in epoch1
        assert!(c.get_at(&q("test.example"), t0, epoch1).is_some(), "should find in same epoch");

        // Simulate epoch change (new blocklist fingerprint)
        let epoch2 = epoch1 + 1;

        // Should NOT find in different epoch (epoch gating)
        assert!(c.get_at(&q("test.example"), t0, epoch2).is_none(), "should NOT find in different epoch");
    }
}

// Note: GAP 1 (resolve_inner concurrency) and GAP 4 (ICMP echo reliability)
// require more complex integration tests that should be added to mod.rs and icmp.rs respectively.

/// RFC 2308 NEGATIVE CACHING, now wired into the live datapath (`resolver/mod.rs` gate C1).
///
/// The stub previously refused to cache denials at all, for a stated reason: "2b has no negative
/// TTL, so caching a denial here would pin it forever (the C1 forever-cache bug)". These tests exist
/// to prove that reason no longer applies -- a denial must be cached AND must expire, twice over:
/// by its own authoritative SOA TTL and again by the hard `neg_ttl_ceiling` clamp.
#[cfg(test)]
mod negative_caching_tests {
    use super::*;
    use crate::dns::{build_query, parse_question};

    fn q(name: &str) -> DnsQuestion {
        parse_question(&build_query(0x1234, name, 1)).expect("question")
    }

    /// An NXDOMAIN wire with an SOA in the Authority section carrying `ttl` and `minimum`.
    /// Built by hand so the SOA rdata layout (MNAME · RNAME · SERIAL · REFRESH · RETRY · EXPIRE ·
    /// MINIMUM) is exactly what `dns::negative_ttl_from_soa` reads positionally.
    fn nxdomain_with_soa(name: &str, soa_ttl: u32, soa_minimum: u32) -> Vec<u8> {
        let mut w = build_query(0x1234, name, 1);
        w[2] = 0x81; // QR=1, RD=1
        w[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
        w[6] = 0;
        w[7] = 0; // ANCOUNT = 0
        w[8] = 0;
        w[9] = 1; // NSCOUNT = 1
        // Authority RR: root name (0x00), TYPE=SOA(6), CLASS=IN(1), TTL, RDLENGTH, RDATA.
        w.push(0x00);
        w.extend_from_slice(&6u16.to_be_bytes());
        w.extend_from_slice(&1u16.to_be_bytes());
        w.extend_from_slice(&soa_ttl.to_be_bytes());
        // RDATA = MNAME(root) + RNAME(root) + five u32 = 1 + 1 + 20 = 22 bytes.
        w.extend_from_slice(&22u16.to_be_bytes());
        w.push(0x00); // MNAME = root
        w.push(0x00); // RNAME = root
        for v in [1u32, 2, 3, 4] {
            w.extend_from_slice(&v.to_be_bytes()); // SERIAL REFRESH RETRY EXPIRE
        }
        w.extend_from_slice(&soa_minimum.to_be_bytes()); // MINIMUM -- the last 4 bytes
        w
    }

    /// A denial IS cached and served back — the behaviour the stub did not have.
    #[test]
    fn a_denial_is_cached_and_served() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        let wire = nxdomain_with_soa("gone.example.com", 120, 120);
        c.put_negative_from_response(&q("gone.example.com"), wire.clone(), 30);
        assert_eq!(
            c.get_at(&q("gone.example.com"), now, current_epoch()),
            Some(wire),
            "a validated denial must be served from cache, byte-for-byte"
        );
    }

    /// THE FOREVER-CACHE GUARD. A denial must EXPIRE — this is the precise bug the original stub
    /// avoided by refusing to cache denials, so it is the property that licenses the wire.
    #[test]
    fn a_denial_expires_and_does_not_pin_forever() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        c.put_negative_from_response(
            &q("gone.example.com"),
            nxdomain_with_soa("gone.example.com", 60, 60),
            30,
        );
        assert!(
            c.get_at(&q("gone.example.com"), now, current_epoch()).is_some(),
            "fresh denial is served"
        );
        let later = now + Duration::from_secs(61);
        assert_eq!(
            c.get_at(&q("gone.example.com"), later, current_epoch()),
            None,
            "the denial MUST expire after its SOA TTL -- a pinned denial hides a name that has \
             since been created, which is exactly the forever-cache bug"
        );
    }

    /// A hostile SOA MINIMUM of ~136 years must NOT pin the denial: `put_negative` hard-clamps to
    /// `neg_ttl_ceiling` (300s default). Without the clamp a single malicious upstream reply could
    /// black-hole a domain for the life of the process.
    #[test]
    fn a_hostile_soa_minimum_is_clamped_to_the_ceiling() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        c.put_negative_from_response(
            &q("evil.example.com"),
            nxdomain_with_soa("evil.example.com", u32::MAX, u32::MAX),
            30,
        );
        // NON-VACUITY FIRST: prove it WAS cached, or the absence assertion below proves nothing.
        assert!(
            c.get_at(&q("evil.example.com"), now, current_epoch()).is_some(),
            "the denial must actually be cached before its expiry can mean anything"
        );
        let past_ceiling = now + Duration::from_secs(DEFAULT_NEG_TTL_CEILING_SECS + 1);
        assert_eq!(
            c.get_at(&q("evil.example.com"), past_ceiling, current_epoch()),
            None,
            "a giant SOA minimum must be clamped to neg_ttl_ceiling, never honoured"
        );
    }

    /// A denial with NO SOA falls back to the caller's bounded default rather than being rejected
    /// or cached indefinitely.
    #[test]
    fn a_soa_less_denial_uses_the_bounded_default() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        let mut wire = build_query(0x1234, "nosoa.example.com", 1);
        wire[2] = 0x81;
        wire[3] = 0x83; // NXDOMAIN, no Authority section
        c.put_negative_from_response(&q("nosoa.example.com"), wire, 30);
        assert!(
            c.get_at(&q("nosoa.example.com"), now, current_epoch()).is_some(),
            "an SOA-less denial is still cached, on the bounded default"
        );
        assert_eq!(
            c.get_at(&q("nosoa.example.com"), now + Duration::from_secs(31), current_epoch()),
            None,
            "and it expires on that default -- 30s, not forever"
        );
    }

    /// The SOA skimmer takes the SMALLER of the SOA's own TTL and its MINIMUM (RFC 2308 §5), so a
    /// small MINIMUM under a large TTL still expires early.
    #[test]
    fn the_smaller_of_soa_ttl_and_minimum_wins() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        c.put_negative_from_response(
            &q("small-min.example.com"),
            nxdomain_with_soa("small-min.example.com", 250, 10),
            30,
        );
        // NON-VACUITY FIRST: it must be live at 9s, so the miss at 11s is a real expiry.
        assert!(
            c.get_at(&q("small-min.example.com"), now + Duration::from_secs(9), current_epoch())
                .is_some(),
            "the denial is still inside MINIMUM=10 at 9s"
        );
        assert_eq!(
            c.get_at(&q("small-min.example.com"), now + Duration::from_secs(11), current_epoch()),
            None,
            "MINIMUM=10 must win over TTL=250 -- min(ttl, minimum), per RFC 2308 section 5"
        );
    }
}

/// RFC 8767 SERVE-STALE freshness reporting, now consumed by the datapath (`resolve_inner` reads
/// `get_hit` instead of `get`). The cache already SERVED stale bytes; what it could not do was say
/// so, leaving `serve_stale_served` and `ResolveOutcome::ServeStale` permanently zero.
///
/// The load-bearing property tested here is that `get_hit` changes only WHAT IS REPORTED -- it must
/// serve byte-identical bytes to `get` in every case, or the wire has altered the datapath.
#[cfg(test)]
mod serve_stale_freshness_tests {
    use super::*;
    use crate::dns::{build_query, parse_question};

    fn q(name: &str) -> DnsQuestion {
        parse_question(&build_query(0x1234, name, 1)).expect("question")
    }

    /// A fresh entry reports Fresh -- the ordinary case must not be mislabelled as stale, or the
    /// panel would cry outage on a healthy cache.
    #[test]
    fn a_fresh_entry_reports_fresh() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        c.set_stale_mode_secs(600);
        c.put(&q("fresh.example.com"), vec![1, 2, 3]);
        let hit = c
            .get_hit_at(&q("fresh.example.com"), now, current_epoch())
            .expect("fresh hit");
        assert_eq!(hit.freshness, Freshness::Fresh);
        assert_eq!(hit.wire, vec![1, 2, 3]);
    }

    /// AN EXPIRED entry inside the stale window reports Stale AND still serves. This is the case
    /// that was invisible: bytes went out, the counter did not move.
    #[test]
    fn an_expired_entry_in_the_window_reports_stale_and_still_serves() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        c.set_stale_mode_secs(600);
        c.put(&q("stale.example.com"), vec![9, 9, 9]); // fallback TTL 30s
        // NON-VACUITY: it is genuinely fresh first, so the Stale below is a real transition.
        assert_eq!(
            c.get_hit_at(&q("stale.example.com"), now, current_epoch())
                .expect("fresh first")
                .freshness,
            Freshness::Fresh
        );
        let past_ttl = now + Duration::from_secs(45);
        let hit = c
            .get_hit_at(&q("stale.example.com"), past_ttl, current_epoch())
            .expect("still served under serve-stale");
        assert_eq!(
            hit.freshness,
            Freshness::Stale,
            "past its TTL but inside the stale window MUST report Stale"
        );
        assert_eq!(hit.wire, vec![9, 9, 9], "and the bytes are still served");
    }

    /// With serve-stale OFF (the default posture) an expired entry is a hard MISS -- wiring the
    /// freshness signal must not have quietly enabled stale serving.
    #[test]
    fn serve_stale_off_still_misses_on_expiry() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        c.set_stale_mode_secs(0); // Off
        c.put(&q("off.example.com"), vec![4, 4, 4]);
        assert!(
            c.get_hit_at(&q("off.example.com"), now, current_epoch()).is_some(),
            "fresh is served"
        );
        assert!(
            c.get_hit_at(&q("off.example.com"), now + Duration::from_secs(45), current_epoch())
                .is_none(),
            "with serve-stale OFF an expired entry is a hard miss -- the wire must not change this"
        );
    }

    /// THE BEHAVIOUR-PRESERVATION LAW. `get_hit` must serve byte-identical bytes to `get` in every
    /// state, because `resolve_inner` swapped one for the other. If these ever disagree, the wire
    /// changed the datapath rather than only its telemetry.
    #[test]
    fn get_hit_serves_byte_identical_bytes_to_get() {
        for stale_secs in [0u64, 600] {
            for age in [0u64, 45] {
                let now = Instant::now();
                let at = now + Duration::from_secs(age);

                let mut a = Cache::new(16);
                a.set_stale_mode_secs(stale_secs);
                a.put(&q("same.example.com"), vec![7, 7, 7]);
                let via_get = a.get_at(&q("same.example.com"), at, current_epoch());

                let mut b = Cache::new(16);
                b.set_stale_mode_secs(stale_secs);
                b.put(&q("same.example.com"), vec![7, 7, 7]);
                let via_hit = b
                    .get_hit_at(&q("same.example.com"), at, current_epoch())
                    .map(|h| h.wire);

                assert_eq!(
                    via_get, via_hit,
                    "get and get_hit disagreed at stale_secs={stale_secs} age={age}s -- the \
                     freshness wire must change only what is REPORTED, never what is SERVED"
                );
            }
        }
    }

    /// The epoch gate outranks serve-stale: a blocklist re-arm invalidates a stale entry too.
    /// Without this, serve-stale would become a hole in the 2e invariant.
    #[test]
    fn the_epoch_gate_outranks_serve_stale() {
        let now = Instant::now();
        let mut c = Cache::new(16);
        c.set_stale_mode_secs(600);
        c.put(&q("epoch.example.com"), vec![5, 5, 5]);
        let live = current_epoch();
        assert!(
            c.get_hit_at(&q("epoch.example.com"), now, live).is_some(),
            "served under the epoch it was stored with"
        );
        assert!(
            c.get_hit_at(&q("epoch.example.com"), now + Duration::from_secs(45), live + 1)
                .is_none(),
            "a NEW epoch invalidates even a stale-window entry -- serve-stale is not a hole in 2e"
        );
    }
}

/// THE `--cache-rr` CACHEABLE-TYPE POLICY — narrowing the positive cache to chosen RR types.
///
/// The dangerous reading is an EMPTY set meaning "cache nothing", which would silently disable the
/// cache the moment a settings pane cleared its checkboxes. Empty is the cache-ALL sentinel, and
/// that is what these tests pin.
#[cfg(test)]
mod cacheable_types_tests {
    use super::*;

    /// Build a minimal positive reply whose first Answer record has type `rtype`.
    fn answer_of_type(rtype: u16) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(&[0x00, 0x01]); // id
        w.extend_from_slice(&[0x81, 0x80]); // QR + RD + RA, RCODE 0
        w.extend_from_slice(&[0x00, 0x01]); // qdcount 1
        w.extend_from_slice(&[0x00, 0x01]); // ancount 1
        w.extend_from_slice(&[0x00, 0x00]); // nscount
        w.extend_from_slice(&[0x00, 0x00]); // arcount
        // QNAME "a.example"
        w.push(1);
        w.extend_from_slice(b"a");
        w.push(7);
        w.extend_from_slice(b"example");
        w.push(0);
        w.extend_from_slice(&rtype.to_be_bytes()); // qtype
        w.extend_from_slice(&[0x00, 0x01]); // qclass IN
        // ANSWER: name pointer to offset 12, type, class, ttl, rdlen, rdata
        w.extend_from_slice(&[0xC0, 0x0C]);
        w.extend_from_slice(&rtype.to_be_bytes());
        w.extend_from_slice(&[0x00, 0x01]);
        w.extend_from_slice(&300u32.to_be_bytes());
        w.extend_from_slice(&4u16.to_be_bytes());
        w.extend_from_slice(&[93, 184, 216, 34]);
        w
    }

    /// THE SENTINEL. An empty set must WIDEN to cache-all, never collapse to cache-nothing.
    #[test]
    fn an_empty_set_means_cache_all_not_cache_nothing() {
        let mut c = Cache::new(16);
        c.set_cacheable_types(&[1]); // narrow first, so the widening is observable
        assert!(
            !c.is_type_cacheable(&answer_of_type(28)),
            "NON-VACUITY: AAAA is genuinely declined while narrowed to A only"
        );
        c.set_cacheable_all();
        assert!(
            c.is_type_cacheable(&answer_of_type(28)),
            "clearing the set must WIDEN to cache-all -- an empty set that cached NOTHING would \
             silently disable the cache the moment a settings pane cleared its checkboxes"
        );
    }

    /// A narrowed policy admits exactly its own types and declines the rest.
    #[test]
    fn a_narrowed_policy_admits_only_its_own_types() {
        let mut c = Cache::new(16);
        c.set_cacheable_types(&[1, 28]); // A + AAAA
        assert!(c.is_type_cacheable(&answer_of_type(1)), "A admitted");
        assert!(c.is_type_cacheable(&answer_of_type(28)), "AAAA admitted");
        assert!(!c.is_type_cacheable(&answer_of_type(16)), "TXT declined");
        assert!(!c.is_type_cacheable(&answer_of_type(15)), "MX declined");
    }

    /// The MEASURED dnsmasq default set is {A, AAAA, SRV, PTR} and excludes CNAME as terminal data.
    #[test]
    fn the_default_set_is_the_measured_dnsmasq_set() {
        let d = CacheableTypes::default_set();
        for t in [1u16, 28, 33, 12] {
            assert!(d.contains(&t), "the measured default set must contain {t}");
        }
        assert!(
            !d.contains(&5),
            "CNAME is chain-followed, never cached as terminal data (rfc1035.c qtype != T_CNAME)"
        );
        assert_eq!(d.len(), 4, "exactly the measured four");
    }

    /// FAIL-OPEN: an indeterminable wire is cached, so narrowing can never regress the 2e locks
    /// that cache a non-DNS placeholder wire.
    #[test]
    fn an_indeterminable_wire_fails_open_to_cacheable() {
        let mut c = Cache::new(16);
        c.set_cacheable_types(&[1]);
        assert!(
            c.is_type_cacheable(&[7, 7, 7]),
            "an un-skimmable wire must FAIL OPEN to cacheable -- the 2e placeholder lock"
        );
    }

    /// THE SENTINEL AS BOTH SEAMS ASK IT. `configure()` and the live-arm path both route through
    /// `intent_is_cache_all`, so this pins the one question they share.
    #[test]
    fn the_sentinel_reads_empty_as_cache_all() {
        assert!(
            intent_is_cache_all(&[]),
            "an EMPTY chosen set is the cache-ALL sentinel -- reading it as cache-nothing would \
             disable the cache the moment a settings pane cleared its last checkbox"
        );
        assert!(!intent_is_cache_all(&[1]), "a single chosen type genuinely narrows");
        assert!(
            !intent_is_cache_all(&DEFAULT_CACHEABLE_TYPES),
            "so does the measured default set"
        );
    }

    /// The durable intent round-trips, and empty clears it.
    #[test]
    fn the_durable_intent_round_trips() {
        set_cacheable_types_intent(&[1, 28]);
        assert_eq!(cacheable_types_intent(), vec![1u16, 28]);
        set_cacheable_types_default();
        let d = cacheable_types_intent();
        assert_eq!(d.len(), 4, "the default intent is the measured four");
        set_cacheable_types_intent(&[]);
        assert!(
            cacheable_types_intent().is_empty(),
            "an empty intent is the cache-all sentinel"
        );
    }
}

/// The durable-poison gate: `restore_gated` must let the live rebind decision veto a rehydrated
/// entry, which the unconditional `restore` cannot.
#[cfg(test)]
mod rehydrate_gate_tests {
    use super::*;
    use crate::dns::{build_query, parse_question};

    fn q(name: &str) -> DnsQuestion {
        parse_question(&build_query(0x1234, name, 1)).expect("question")
    }

    /// A closure that vetoes a specific payload stands in for the rebind decision. The point under
    /// test is the SEAM — that `admit` is consulted per entry and a `false` genuinely blocks the
    /// insertion — not the rebind predicate itself, which has its own suite.
    #[test]
    fn a_vetoed_wire_never_rehydrates() {
        let now = Instant::now();
        let now_unix = 1_000_000u64;

        let mut src = Cache::new(16);
        src.put(&q("clean.example.com"), vec![1, 2, 3]);
        src.put(&q("poison.example.com"), vec![9, 9, 9]);
        let snap = src.snapshot(now, now_unix, 65_536);

        // NON-VACUITY FIRST: ungated, BOTH come back. Without this the gated assertion below could
        // pass because the snapshot was empty or unparseable.
        let mut ungated = Cache::new(16);
        assert_eq!(
            ungated.restore(&snap, now, now_unix),
            2,
            "ungated restore must admit both, or the gated comparison proves nothing"
        );

        // Gated: the poison wire is refused, the clean one survives.
        let mut gated = Cache::new(16);
        let admitted = gated.restore_gated(&snap, now, now_unix, &|wire: &[u8]| wire != [9, 9, 9]);
        assert_eq!(admitted, 1, "exactly the clean entry rehydrates");
        assert_eq!(
            gated.get_at(&q("clean.example.com"), now, current_epoch()),
            Some(vec![1, 2, 3]),
            "the clean entry is served back byte-identically"
        );
        assert_eq!(
            gated.get_at(&q("poison.example.com"), now, current_epoch()),
            None,
            "the vetoed entry must NOT be resurrected — this is the durable-poison gap"
        );
    }

    /// An always-true gate is byte-identical to the ungated path, so arming the gate cannot cost a
    /// user cache hits when the rebind switch is OFF (the observe-only default).
    #[test]
    fn an_always_admit_gate_matches_the_ungated_path_exactly() {
        let now = Instant::now();
        let now_unix = 1_000_000u64;

        let mut src = Cache::new(16);
        src.put(&q("a.example.com"), vec![1]);
        src.put(&q("b.example.com"), vec![2]);
        src.put(&q("c.example.com"), vec![3]);
        let snap = src.snapshot(now, now_unix, 65_536);

        let mut ungated = Cache::new(16);
        let mut gated = Cache::new(16);
        let n_ungated = ungated.restore(&snap, now, now_unix);
        let n_gated = gated.restore_gated(&snap, now, now_unix, &|_| true);

        assert_eq!(n_ungated, 3, "NON-VACUITY: the fixture must actually restore entries");
        assert_eq!(
            n_gated, n_ungated,
            "observe-only mode must rehydrate EXACTLY as before — no cache-hit regression"
        );
        for name in ["a.example.com", "b.example.com", "c.example.com"] {
            assert_eq!(
                gated.get_at(&q(name), now, current_epoch()),
                ungated.get_at(&q(name), now, current_epoch()),
                "{name} must be served identically by both paths"
            );
        }
    }

    /// `clear` genuinely empties the cache — the RAM twin of the rehydrate gate, used on the
    /// rebind-enforce OFF->ON edge.
    #[test]
    fn clear_empties_the_cache() {
        let mut c = Cache::new(16);
        c.put(&q("a.example.com"), vec![1, 2, 3]);
        c.put(&q("b.example.com"), vec![4, 5, 6]);
        assert_eq!(c.len(), 2, "NON-VACUITY: entries must exist before clearing");
        c.clear();
        assert_eq!(c.len(), 0, "clear must drop every entry");
        assert_eq!(
            c.get_at(&q("a.example.com"), Instant::now(), current_epoch()),
            None,
            "a cleared entry must not be served"
        );
    }
}
