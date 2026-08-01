/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Slice 5 — the DNSCrypt **auto-updater version-sync** (the Socio vision,
//! `sovereign-dnscrypt-rust-rewire` §2: "Auto-update dnscrypt feature, re-linkable to the Rust engine").
//!
//! ## What this IS (component-scoped version-sync)
//! Once the Rust DNSCrypt transport is the production default (slices 1-4), the Go
//! `libdnscrypt-proxy.so` binary updates with the APK — there is no separate binary to swap. What STILL
//! moves independently of the APK is the **DNSCrypt layer's data + capability envelope**: the relay/stamp
//! lists, the upstream protocol features (a new stamp type, a new relay-hop variant, a new cert format).
//! This module syncs THAT layer to the latest upstream — **without touching the Rust core**
//! (Beast / Warden / Fortress stay frozen at their APK version).
//!
//! ## The contract (the safety invariant — non-negotiable)
//! This module is **component-scoped**: it ONLY reads/writes the DNSCrypt layer's durable state
//! (the [`SyncState`] record: the last-checked upstream version + the last applied capability envelope).
//! It NEVER imports or mutates `crate::beast`, `crate::warden`, `crate::fortress`, `crate::mirror`, or
//! the resolver hot path (`resolver::resolve` / the pool / the cache). The `#![forbid(unsafe_code)]` +
//! the std-only deps enforce this statically — there is no `use crate::<core>` here at all. A sync can
//! never corrupt the core: the worst it can do is leave the DNSCrypt layer's own metadata stale, which
//! degrades to a re-fetch (fail-safe, same posture as [`super::rotation`]).
//!
//! ## The flow
//! 1. **Describe** — [`current_envelope()`] returns the capability envelope THIS build of the Rust
//!    transport speaks (a compile-time-true constant; updated only when the Rust transport itself gains
//!    a feature — e.g. the slice-2 relay hop lands ⇒ `"relay_hop"` flips to `true`).
//! 2. **Compare** — [`build_sync_plan`] takes an *upstream* envelope JSON (fetched by the existing
//!    Kotlin worker — the network stays on the Kotlin side, never in this crate) + the current envelope,
//!    and emits a [`SyncPlan`]: which capabilities the upstream has that we lack, which relay/stamp
//!    sources need a refresh, whether a protocol-feature gate (e.g. a new stamp type) is available.
//!    A strict semver compare (the worker's `isNewer` shape, ported to Rust) gates the whole thing.
//! 3. **Apply** — [`apply_sync_plan`] records the applied envelope into the [`DurableTier`] record. It
//!    does NOT swap binaries, does NOT touch the resolver pool, does NOT restart anything — it only
//!    advances the durable "last applied" marker so the next boot knows the layer is at version X.
//!    The actual relay/stamp-list refresh is dnscrypt-proxy's own minisign-verified `[sources]` refresh
//!    (the worker already triggers it); this module is the VERSION-COORDINATION layer above it.
//!
//! ## Serialization (tiny, hand-rolled, no serde — the 2b/rotation discipline)
//! Line-oriented `key=value`, the SAME posture as [`super::rotation`]. A malformed field is skipped
//! (the [`DurableTier`] integrity frame already guarantees the bytes are intact). Bounded, fail-safe.
//!
//! `#![forbid(unsafe_code)]`, std-only, zero new deps, zero `use crate::<core>`. PRIVATE +
//! dead-code-until-wired (the `rotation.rs:34` idiom) until the Kotlin `DnsCryptSyncManager` boot-rehydrate
//! + the worker's compare call it (the UniFFI exports in `lib.rs` reach it via `resolver::dnscrypt_update`).

#![forbid(unsafe_code)]

use std::path::PathBuf;

use crate::runtime_tier::DurableTier;

/// The stable on-disk record name for the DNSCrypt version-sync state (under the app-private dir).
/// One record per pillar (sibling of `resolver-rotation`); the [`DurableTier`] sanitizes it to a flat,
/// traversal-free filename.
const RECORD_NAME: &str = "dnscrypt-sync";

/// The protocol-version constant the Rust DNSCrypt transport (`super::dnscrypt`) implements today.
/// This is the DNSCrypt v2 wire protocol (the `crypto_secretbox` exchange) — the LAYER version, decoupled
/// from the bundled Go binary's semver (which ships with the APK). Semver-shaped for the strict compare.
/// Bumped ONLY when the Rust transport gains a wire-protocol feature (e.g. slice-2 relay hop lands).
pub const IMPLEMENTED_PROTOCOL_VERSION: &str = "2.1.0-rust";

/// A bound on the number of capability flags carried in an envelope (a hostile/corrupt upstream JSON
/// claiming thousands of flags is truncated here — bounded footprint, the [`DurableTier`]
/// `MAX_BLOB_BYTES` is the outer guard). NOT a tuning knob.
pub const MAX_CAPABILITY_FLAGS: usize = 64;

/// A bound on the number of relay/stamp source URLs tracked in an envelope. Same bounded-footprint
/// posture as [`MAX_CAPABILITY_FLAGS`].
pub const MAX_SOURCES: usize = 32;

/// The capability envelope the Rust DNSCrypt transport speaks RIGHT NOW (compile-time-true).
///
/// This is the **self-description** — what THIS build can do. It is the baseline [`build_sync_plan`]
/// diffs the upstream envelope against. The flags mirror the verified-gaps map from the FOUNDATION
/// AUDIT (slice-1 sovereign rewire, slice-2 relay hop, slice-3 loopback, slice-4 DNS64) so a plan can
/// name exactly which not-yet-wired capability an upstream feature would need.
///
/// (Public so the UniFFI export + the tests can read it; the fields are read-only by construction.)
pub struct Envelope {
    /// The protocol version this build implements ([`IMPLEMENTED_PROTOCOL_VERSION`]).
    pub protocol_version: String,
    /// Capability flags — `"cert_ed25519_verify"`, `"xchacha20poly1305_v2"`, `"xsalsa20poly1305_v1"`,
    /// `"stamp_resolver_0x01"`, `"stamp_relay_0x81_parse"`, `"relay_hop"` (slice-2 LANDED),
    /// `"loopback_listener"` (slice-3 LANDED), `"dns64_synthesis"` (slice-4 LANDED), …
    /// See [`current_envelope()`] for the full list this build owns.
    pub capabilities: Vec<String>,
    /// The relay/stamp source URLs this layer refreshes (dnscrypt-proxy's `[sources]` — the upstream
    /// list the worker already triggers a minisign-verified refresh of). May be empty.
    pub sources: Vec<String>,
}

/// The envelope THIS build speaks. The single source of truth for `build_sync_plan`'s "current" side.
/// Edit this (and only this) when a slice wires a new capability — e.g. when slice-2 lands, add
/// `"relay_hop"` to the `capabilities` vec here and the next sync plan will stop flagging it as missing.
pub fn current_envelope() -> Envelope {
    Envelope {
        protocol_version: IMPLEMENTED_PROTOCOL_VERSION.to_string(),
        capabilities: {
            // The capabilities THIS build implements, mirrored from the live resolver tree so a sync
            // plan never false-flags a capability the build already has. Each entry is `file:line`-grounded:
            // - cert_ed25519_verify / xchacha20poly1305_v2 / xsalsa20poly1305_v1 / x25519_key_exchange /
            //   stamp_resolver_0x01 / stamp_relay_0x81_parse — resolver/dnscrypt.rs (the v2 transport).
            // - relay_hop — slice-2 LANDED: dnscrypt.rs `wrap_for_relay` / `relayed_udp_then_tcp` +
            //   `set_relays`/`with_relays`/`parse_relay_chain` (the 0x81 anonymized-relay hop, multi-hop nest).
            // - loopback_listener — slice-3 LANDED: listener.rs `start_loopback` (binds 127.0.0.1, UDP+TCP).
            // - dns64_synthesis — slice-4 LANDED: dns64.rs `build_synth_aaaa` (RFC 6052 A→AAAA embedding).
            // - pqdnscrypt_xwing_0x0003 — the v2.1.17 absorb LANDED: dnscrypt.rs `pq_encrypted_exchange`
            //   / `pq_derive_shared_key` / the es-0x0003 cert parse+selection (X-Wing post-quantum
            //   hybrid KEM, Appendix-3 draft vectors pinned in the test corpus).
            // - key_rotate_on_network_change — SURPASSED, honestly claimable: upstream v2.1.17 rotates
            //   key material when the local network changes (linkability bounded per-network); Tortä
            //   generates a FRESH ephemeral X25519 keypair PER QUERY (dnscrypt.rs `encrypted_exchange`:
            //   `csprng_fill(&mut sk_bytes)` → `StaticSecret::from` on every exchange; PQ edition ditto
            //   with fresh encapsulation randomness) — linkability bounded per-query, a strictly
            //   stronger property. The coordinate names the PROPERTY upstream's rotation delivers, which this
            //   build holds (and exceeds); without it a distilled ≥2.1.17 envelope would false-flag a gap.
            // - per_query_ephemeral_keys — the Tortä-native strength as its own coordinate: upstream
            //   never emits it, so a sync-plan diff surfaces it in `extra_capabilities` — the honest
            //   "this build is AHEAD of upstream here" signal.
            // - pq_cert_fetch_fragmentation_hardening — the v2.1.18 absorb LANDED: dnscrypt.rs
            //   `relayed_tcp_then_udp` (TCP-first cert fetch when PQ is enabled — a 1320-byte
            //   es-0x0003 cert can never fit the classic 512-byte UDP ceiling, so UDP-first was a
            //   guaranteed TC round-trip or a silent fragment-drop hang; relay lane included).
            // - latency_excludes_setup — the v2.1.18 absorb LANDED: transport.rs `Transport::warm_setup`
            //   + the pool's warm-before-stopwatch seams (pool.rs, every `Instant::now` leg) — cert
            //   fetch/verify time never lands in the RTT EWMA (whose FIRST sample is the seed).
            // Add a new entry ONLY when a new wire-protocol feature lands in the resolver tree.
            vec![
                "cert_ed25519_verify".into(),
                "xchacha20poly1305_v2".into(),
                "xsalsa20poly1305_v1".into(),
                "x25519_key_exchange".into(),
                "stamp_resolver_0x01".into(),
                "stamp_relay_0x81_parse".into(),
                "relay_hop".into(),
                "loopback_listener".into(),
                "dns64_synthesis".into(),
                "pqdnscrypt_xwing_0x0003".into(),
                "key_rotate_on_network_change".into(),
                "per_query_ephemeral_keys".into(),
                "pq_cert_fetch_fragmentation_hardening".into(),
                "latency_excludes_setup".into(),
            ]
        },
        sources: vec![
            // dnscrypt-proxy's own minisign-verified `[sources]` URLs — the worker refreshes these.
            // Kept here as the baseline so a plan can diff them against an upstream envelope's list.
            "https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md".into(),
            "https://download.dnscrypt.info/relays-list/v3/relays.md".into(),
        ],
    }
}

/// The durable version-sync state — what the layer last synced TO. This is the "applied" marker the next
/// boot reads to know the layer is at version X with capabilities Y. Built cold by default
/// ([`SyncState::cold`]); [`SyncState::rehydrate`] warms it from disk at start; [`SyncState::persist`]
/// gently writes it back when a plan is applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncState {
    /// The upstream protocol version last applied (e.g. `"2.1.16"`), or empty on a cold start.
    /// This is the UPSTREAM version coordinate, distinct from [`IMPLEMENTED_PROTOCOL_VERSION`] (ours).
    pub last_applied_version: String,
    /// The capabilities the layer had at the last successful sync (so a boot knows what was applied).
    /// Bounded to [`MAX_CAPABILITY_FLAGS`].
    pub applied_capabilities: Vec<String>,
    /// Unix-epoch seconds of the last successful sync apply (0 ⇒ never). For freshness display +
    /// the worker's cadence gate.
    pub last_applied_secs: u64,
    /// The number of sync plans ever applied (a monotonic counter for diagnostics). Saturates at u64::MAX.
    pub apply_count: u64,
}

impl SyncState {
    /// A fresh cold sync state — the zero baseline a boot starts from when there is no durable record.
    pub fn cold() -> Self {
        SyncState::default()
    }

    // ---- the durable seam (GENTLE write-through + explicit rehydrate, via DurableTier) ----------------

    /// The [`DurableTier`] for this pillar rooted at the app-private `dir`. Constructing it does NO disk
    /// IO (the no-boot-IO-scan law — same as [`super::rotation::RotationState::tier`]).
    pub fn tier(dir: PathBuf) -> DurableTier {
        DurableTier::with_dir(dir, RECORD_NAME)
    }

    /// Rehydrate the sync state from the app-private `dir`, returning a warm [`SyncState`] (or a cold
    /// one if there is no valid record). EXPLICIT + non-failing: a missing / corrupt / oversized /
    /// tampered record yields [`SyncState::cold`], never an error. Call ONCE at start, never on the
    /// resolve path. Same fail-safe posture as [`super::rotation::RotationState::rehydrate`].
    pub fn rehydrate(dir: PathBuf) -> SyncState {
        match Self::tier(dir).rehydrate() {
            Some(bytes) => Self::decode(&bytes).unwrap_or_else(SyncState::cold),
            None => SyncState::cold(),
        }
    }

    /// GENTLY persist this sync state to the app-private `dir`, atomically (via [`DurableTier`]).
    /// Returns `true` on a durable write, `false` on any refusal (best-effort — same FAIL-SAFE as
    /// rotation). Call ONLY on the control plane (a sync apply), never from the resolve path.
    pub fn persist(&self, dir: PathBuf) -> bool {
        Self::tier(dir).write_through(&self.encode()).is_ok()
    }

    /// Encode the sync state into the tiny line-oriented durable payload (no serde). Format (one
    /// `key=value` per line; values are escaped of `\n`/`=`/`:` for the capability strings, same
    /// escaping as [`super::rotation`]): `version=<s>` · `applied=<secs>` · `count=<u64>` ·
    /// `cap=<flag>` (one per capability, bounded to [`MAX_CAPABILITY_FLAGS`]).
    fn encode(&self) -> Vec<u8> {
        let mut s = String::new();
        s.push_str("version=");
        s.push_str(&escape(&self.last_applied_version));
        s.push('\n');
        s.push_str(&format!("applied={}\n", self.last_applied_secs));
        s.push_str(&format!("count={}\n", self.apply_count));
        for cap in self.applied_capabilities.iter().take(MAX_CAPABILITY_FLAGS) {
            s.push_str("cap=");
            s.push_str(&escape(cap));
            s.push('\n');
        }
        s.into_bytes()
    }

    /// Decode the durable payload back into a [`SyncState`]. Tolerant + bounds-checked: an unknown key
    /// or a malformed value is SKIPPED (the record bytes are already integrity-verified by
    /// [`DurableTier`]). Capabilities past [`MAX_CAPABILITY_FLAGS`] are dropped (bounded).
    fn decode(bytes: &[u8]) -> Option<SyncState> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut state = SyncState::cold();
        for line in text.lines() {
            let (key, value) = match line.split_once('=') {
                Some(kv) => kv,
                None => continue, // a line without '=' is malformed → skip.
            };
            match key {
                "version" => state.last_applied_version = unescape(value),
                "applied" => {
                    if let Ok(v) = value.parse::<u64>() {
                        state.last_applied_secs = v;
                    }
                }
                "count" => {
                    if let Ok(v) = value.parse::<u64>() {
                        state.apply_count = v;
                    }
                }
                "cap" => {
                    if state.applied_capabilities.len() >= MAX_CAPABILITY_FLAGS {
                        continue; // bounded — drop flags past the ceiling.
                    }
                    state.applied_capabilities.push(unescape(value));
                }
                _ => continue, // unknown key → forward-tolerant skip (a future field won't break an old build).
            }
        }
        Some(state)
    }
}

/// Why a sync was not needed / was refused — a typed verdict, never an unwinding error across FFI.
/// Mirrors the shape of [`crate::runtime_tier::WriteReject`] (a typed refusal, not a panic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncNotNeeded {
    /// The upstream version is NOT newer than what we last applied (or than our implemented protocol
    /// version when there's no applied record). No plan emitted. Inert until the Kotlin
    /// DnsCryptSyncManager renders this verdict (slice-5 pub API).
    UpToDate,
    /// The upstream envelope JSON was malformed/empty/unparseable. No plan emitted; the caller retries.
    MalformedUpstream,
}

/// A sync plan — the diff between the upstream envelope and what THIS build speaks. This is the
/// **coordinate** the Kotlin UI renders ("DNSCrypt layer: 3 new capabilities available, 1 source changed")
/// and that the apply step records. It is deliberately a VALUE type (no side effects in the plan itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPlan {
    /// The upstream version this plan targets (semver string, e.g. `"2.1.16"`).
    pub upstream_version: String,
    /// Whether the upstream version is strictly newer than ours (the semver gate — `false` ⇒ no-op plan).
    pub is_newer: bool,
    /// Capabilities the upstream envelope claims that THIS build lacks (the "would-need" list). Each is
    /// a flag name; the Kotlin UI maps it to a human description. Empty when we're feature-complete.
    pub missing_capabilities: Vec<String>,
    /// Sources in the upstream envelope not in our current envelope (a refresh hint for the worker's
    /// minisign-verified `[sources]` refresh). Empty when the lists match.
    pub new_sources: Vec<String>,
    /// Capabilities WE have that the upstream envelope does NOT list (forward-compat note; informational
    /// — we don't down-grade). Usually empty.
    pub extra_capabilities: Vec<String>,
}

impl SyncPlan {
    /// A plan that represents "the upstream is older/equal — nothing to do" (the [`SyncNotNeeded::UpToDate`]
    /// verdict materialized as a no-op plan, so the UniFFI surface always returns a plan, never errors).
    fn noop(upstream_version: String) -> Self {
        SyncPlan {
            upstream_version,
            is_newer: false,
            missing_capabilities: Vec::new(),
            new_sources: Vec::new(),
            extra_capabilities: Vec::new(),
        }
    }

    /// Whether this plan has any work to do (capabilities to gain OR sources to refresh). Inert
    /// until the Kotlin DnsCryptSyncManager renders the plan (slice-5 pub API).
    pub fn has_work(&self) -> bool {
        self.is_newer && (!self.missing_capabilities.is_empty() || !self.new_sources.is_empty())
    }

    /// The TYPED reason this plan has nothing to do, or `None` when it does.
    ///
    /// [`build_sync_plan`] deliberately returns a no-op PLAN rather than `Err(UpToDate)`, so the
    /// UniFFI surface always hands back a plan and never errors. That left the caller inferring
    /// "up to date" from `is_newer == false` — an inference that silently becomes wrong the moment
    /// a newer upstream has nothing this build lacks, which reads as `is_newer == true` with an
    /// empty work list. This returns the verdict itself instead of asking every caller to
    /// re-derive it.
    ///
    /// `Some(UpToDate)` = upstream is not newer, OR is newer but asks nothing of us.
    /// `None` = there is real work.
    pub fn not_needed_reason(&self) -> Option<SyncNotNeeded> {
        if self.has_work() {
            None
        } else {
            Some(SyncNotNeeded::UpToDate)
        }
    }
}

/// Build a sync plan by diffing an upstream envelope (JSON, fetched by Kotlin) against THIS build's
/// current envelope ([`current_envelope`]).
///
/// The upstream JSON shape (hand-rolled, no serde — matches the rotation discipline):
/// ```text
/// version=2.1.16
/// cap=relay_hop
/// cap=dns64_synthesis
/// cap=new_stamp_type_0xXX
/// source=https://example.com/new-relays.md
/// ```
/// (line-oriented `key=value`; `cap=`/`source=` repeat). This is intentionally NOT the GitHub releases
/// API JSON — that's the Kotlin worker's job; this crate takes the already-distilled envelope so the
/// network + JSON parsing stays on the Kotlin side (the same split as the FOUNDATION AUDIT's Q2 verdict:
/// the Rust side is the VERSION-COORDINATION, not the fetcher).
///
/// Returns `Ok(plan)` for a parseable envelope, `Err(SyncNotNeeded)` for a malformed one. Never panics
/// (the UniFFI export wraps this in `catch_unwind` regardless, but this fn is itself panic-free).
pub fn build_sync_plan(upstream_envelope: &str) -> Result<SyncPlan, SyncNotNeeded> {
    let current = current_envelope();
    let (up_version, up_caps, up_sources) = parse_upstream_envelope(upstream_envelope)?;

    // The semver gate: only emit a real plan when upstream is strictly newer than what we IMPLEMENT.
    // (When we have an applied record, the worker compares against `last_applied_version` first in
    // Kotlin; this crate's gate is the harder one — our implemented protocol version.)
    let is_newer = semver_is_newer(&up_version, &current.protocol_version);

    if !is_newer {
        return Ok(SyncPlan::noop(up_version));
    }

    // Diff capabilities: what's in upstream but not in ours (missing), and vice-versa (extra).
    let missing_capabilities = up_caps
        .iter()
        .filter(|c| !current.capabilities.iter().any(|ours| ours == *c))
        .cloned()
        .collect();
    let extra_capabilities = current
        .capabilities
        .iter()
        .filter(|ours| !up_caps.iter().any(|c| c == *ours))
        .cloned()
        .collect();

    // Diff sources: what's in upstream but not in ours (a refresh hint).
    let new_sources = up_sources
        .iter()
        .filter(|s| !current.sources.iter().any(|ours| ours == *s))
        .cloned()
        .collect();

    Ok(SyncPlan {
        upstream_version: up_version,
        is_newer: true,
        missing_capabilities,
        new_sources,
        extra_capabilities,
    })
}

/// Apply a sync plan: advance the durable [`SyncState`] to record that the layer is now at the plan's
/// upstream version with its capabilities merged. This is the ONLY mutation — it touches the DNSCrypt
/// layer's durable record, NEVER the core. Returns `true` on a durable write.
///
/// **What this does NOT do** (the safety contract): it does not swap any binary, does not touch the
/// resolver pool/cache/hot path, does not restart the transport, does not import any core module. The
/// actual relay/stamp-list DATA refresh is dnscrypt-proxy's own minisign-verified `[sources]` refresh
/// (triggered by the Kotlin worker); this is the VERSION-COORDINATION marker above it.
pub fn apply_sync_plan(plan: &SyncPlan, now_secs: u64, dir: PathBuf) -> bool {
    if !plan.is_newer {
        // A no-op plan ⇒ no state change (idempotent; we don't bump `apply_count` for a no-op).
        // Still return true (the caller's "is the layer at the latest?" read stays consistent).
        let _ = SyncState::rehydrate(dir.clone()).persist(dir);
        return true;
    }
    let mut state = SyncState::rehydrate(dir.clone());
    state.last_applied_version = plan.upstream_version.clone();
    // Merge: keep our current applied capabilities, ADD the upstream's missing ones we just synced to
    // (dedup, bounded). This records "the layer now also speaks these upstream capabilities."
    let mut merged = state.applied_capabilities.clone();
    for cap in &plan.missing_capabilities {
        if merged.len() >= MAX_CAPABILITY_FLAGS {
            break;
        }
        if !merged.iter().any(|c| c == cap) {
            merged.push(cap.clone());
        }
    }
    state.applied_capabilities = merged;
    state.last_applied_secs = now_secs;
    state.apply_count = state.apply_count.saturating_add(1);
    state.persist(dir)
}

// ---- the parsing + semver helpers (panic-free, bounded, tolerant) ---------------------------------

/// Parse the upstream envelope (line-oriented `key=value`). Returns `(version, capabilities, sources)`
/// or `Err(SyncNotNeeded::MalformedUpstream)` for an unparseable/empty envelope. Bounded to
/// [`MAX_CAPABILITY_FLAGS`] / [`MAX_SOURCES`]; unknown keys are skipped (forward-tolerant).
fn parse_upstream_envelope(
    text: &str,
) -> Result<(String, Vec<String>, Vec<String>), SyncNotNeeded> {
    let mut version = String::new();
    let mut caps: Vec<String> = Vec::new();
    let mut sources: Vec<String> = Vec::new();
    let mut saw_any = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue, // a line without '=' is malformed → skip (tolerant, not fatal).
        };
        saw_any = true;
        match key.trim() {
            "version" => version = unescape(value.trim()),
            "cap" | "capability" => {
                if caps.len() < MAX_CAPABILITY_FLAGS {
                    caps.push(unescape(value.trim()));
                }
            }
            "source" | "src" => {
                if sources.len() < MAX_SOURCES {
                    sources.push(unescape(value.trim()));
                }
            }
            _ => continue, // unknown key → forward-tolerant skip.
        }
    }
    if !saw_any || version.is_empty() {
        return Err(SyncNotNeeded::MalformedUpstream);
    }
    Ok((version, caps, sources))
}

/// Strict 3-part numeric semver compare: `true` iff `a > b` (e.g. `2.1.16 > 2.1.9`).
///
/// This is the Rust port of `CheckDnsCryptBinaryUpdateWorker.isNewer` (the worker's Kotlin semver
/// compare, GROUND_TRUTH'd against `CheckDnsCryptBinaryUpdateWorker.kt:96-103`). Pre-release/build
/// suffixes are stripped (split on `-`/`+`), each numeric part is parsed defensively (non-numeric ⇒ 0),
/// and the compare is lexicographic on the 3-tuple. A version with FEWER parts is zero-padded.
pub fn semver_is_newer(a: &str, b: &str) -> bool {
    let va = parse_semver(a);
    let vb = parse_semver(b);
    for i in 0..3 {
        if va[i] != vb[i] {
            return va[i] > vb[i];
        }
    }
    false
}

/// Parse a semver string into a 3-element numeric array (the worker's `parse` shape, ported). Splits on
/// `.`/`-`/`+`, takes the first 3 numeric parts, zero-pads. Non-numeric ⇒ 0 (defensive).
fn parse_semver(version: &str) -> [u64; 3] {
    let parts: Vec<&str> = version.split(['.', '-', '+']).collect();
    let mut out = [0u64; 3];
    for (i, slot) in out.iter_mut().enumerate() {
        if let Some(p) = parts.get(i) {
            // Take the leading digit run (mirrors the worker's `takeWhile { it.isDigit() }`).
            let num: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(v) = num.parse::<u64>() {
                *slot = v;
            }
        }
    }
    out
}

/// Escape `\` `\n` `=` `:` in a field value so a capability/source string can never break the
/// line-oriented framing. The SAME escape as [`super::rotation::escape`] (REUSE-law — one escape shape
/// per durable payload family). Reversed by [`unescape`].
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '=' => out.push_str("\\e"),
            ':' => out.push_str("\\c"),
            c => out.push(c),
        }
    }
    out
}

/// Inverse of [`escape`] (the SAME unescape as [`super::rotation::unescape`]). An unterminated/unknown
/// escape is passed through literally (tolerant).
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('e') => out.push('='),
            Some('c') => out.push(':'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {

    /// A5 GUARD -- `MAX_SOURCES` (= 32, dnscrypt_update.rs:74) bounds the source list a remote
    /// envelope may push into this device. The A5 inventory found it had a NUMBER and no test
    /// naming it.
    ///
    /// Three arms, because the bound has TWO ways to be wrong and only one is about size. The
    /// parser is deliberately forward-TOLERANT: unknown keys and malformed lines are skipped
    /// rather than fatal. So an over-long source list must be TRUNCATED, never made an error --
    /// a hostile upstream that could turn 10k sources into `MalformedUpstream` would have a
    /// remote kill switch on the update path. And the truncation must keep the FIRST entries,
    /// because those are the ones the operator's envelope leads with.
    #[test]
    fn max_sources_truncates_and_never_becomes_a_remote_kill_switch() {
        let mut env = String::from("version=9.9.9
");
        for i in 0..(MAX_SOURCES * 10) {
            env.push_str(&format!("source=src{i:04}.example
"));
        }

        let parsed = parse_upstream_envelope(&env);
        let (version, _caps, sources) = parsed.expect(
            "an over-long source list must TRUNCATE, never fail -- a parse error here is a              remote kill switch on the update path",
        );
        assert_eq!(version, "9.9.9", "the envelope still parses end to end");
        assert_eq!(
            sources.len(),
            MAX_SOURCES,
            "the source list must saturate AT the cap"
        );
        assert_eq!(
            sources.first().map(String::as_str),
            Some("src0000.example"),
            "truncation keeps the FIRST sources -- the ones the envelope leads with"
        );
        assert_eq!(
            sources.last().map(String::as_str),
            Some(format!("src{:04}.example", MAX_SOURCES - 1).as_str()),
            "and stops exactly at the cap"
        );
    }
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("torta-dnscrypt-sync-{tag}-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    // ---- semver (the Rust port of the worker's compare) ----

    #[test]
    fn semver_newer_basic() {
        // The worker's canonical case: 2.1.16 > 2.1.9.
        assert!(semver_is_newer("2.1.16", "2.1.9"));
        assert!(!semver_is_newer("2.1.9", "2.1.16"));
    }

    #[test]
    fn semver_newer_major_minor() {
        assert!(semver_is_newer("3.0.0", "2.99.99"));
        assert!(semver_is_newer("2.2.0", "2.1.99"));
        assert!(!semver_is_newer("2.1.0", "2.1.0"));
    }

    #[test]
    fn semver_strips_prerelease_and_build() {
        // -rc1 / +build suffixes are stripped (split on - and +).
        assert!(semver_is_newer("2.2.0-rc1", "2.1.0"));
        assert!(!semver_is_newer("2.1.0+build.42", "2.1.0"));
    }

    #[test]
    fn semver_handles_garbage_gracefully() {
        // Non-numeric parts ⇒ 0 (defensive — never panics).
        assert!(!semver_is_newer("garbage", "0.0.0"));
        assert!(!semver_is_newer("1", "1.0.0")); // fewer parts ⇒ zero-padded ⇒ equal.
        assert!(semver_is_newer("1.2", "1.1")); // 1.2.0 > 1.1.0
    }

    // ---- envelope parse ----

    #[test]
    fn parse_well_formed_envelope() {
        let text = "version=2.1.16\n\
                    cap=relay_hop\n\
                    cap=dns64_synthesis\n\
                    source=https://example.com/relays.md\n\
                    # a comment line\n";
        let (v, caps, srcs) = parse_upstream_envelope(text).expect("well-formed");
        assert_eq!(v, "2.1.16");
        assert_eq!(
            caps,
            vec!["relay_hop".to_string(), "dns64_synthesis".into()]
        );
        assert_eq!(srcs, vec!["https://example.com/relays.md".to_string()]);
    }

    #[test]
    fn parse_empty_envelope_is_malformed() {
        assert_eq!(
            parse_upstream_envelope(""),
            Err(SyncNotNeeded::MalformedUpstream)
        );
        assert_eq!(
            parse_upstream_envelope("# only a comment\n\n"),
            Err(SyncNotNeeded::MalformedUpstream)
        );
    }

    #[test]
    fn parse_envelope_without_version_is_malformed() {
        // Capabilities but no version ⇒ malformed (the version is the coordinate the gate needs).
        assert_eq!(
            parse_upstream_envelope("cap=relay_hop\n"),
            Err(SyncNotNeeded::MalformedUpstream)
        );
    }

    #[test]
    fn parse_envelope_is_bounded() {
        // A hostile envelope with thousands of caps ⇒ truncated at MAX_CAPABILITY_FLAGS.
        let mut text = String::from("version=9.9.9\n");
        for i in 0..(MAX_CAPABILITY_FLAGS * 4) {
            text.push_str(&format!("cap=flag{i}\n"));
        }
        let (_, caps, _) = parse_upstream_envelope(&text).expect("parses");
        assert_eq!(caps.len(), MAX_CAPABILITY_FLAGS);
    }

    #[test]
    fn parse_envelope_unknown_key_is_forward_tolerant() {
        // A future field ("foo=bar") is skipped, not fatal.
        let text = "version=2.2.0\nfoo=bar\nbaz=qux\ncap=relay_hop\n";
        let (v, caps, _) = parse_upstream_envelope(text).expect("parses");
        assert_eq!(v, "2.2.0");
        assert_eq!(caps, vec!["relay_hop".to_string()]);
    }

    // ---- build_sync_plan ----

    #[test]
    fn plan_for_older_upstream_is_noop() {
        // Our implemented version is 2.1.0-rust (2.1.0 numerically). Upstream 2.0.0 is NOT newer.
        let plan = build_sync_plan("version=2.0.0\ncap=anything\n").expect("parses");
        assert!(!plan.is_newer);
        assert!(!plan.has_work());
    }

    #[test]
    fn plan_for_equal_upstream_is_noop() {
        let plan = build_sync_plan("version=2.1.0\n").expect("parses");
        assert!(!plan.is_newer);
    }

    #[test]
    fn plan_for_newer_upstream_flags_missing_capabilities() {
        // Upstream 2.2.0 claims a FUTURE capability we don't implement yet (`quic_stamp_0x0f` — a
        // synthetic not-yet-wired feature) alongside capabilities we DO own after the sovereign rewire
        // (`relay_hop` slice-2 · `dns64_synthesis` slice-4 — both LANDED, so MUST NOT be flagged missing).
        // The plan names only the genuinely-future one as missing.
        let text = "version=2.2.0\n\
                    cap=quic_stamp_0x0f\n\
                    cap=relay_hop\n\
                    cap=dns64_synthesis\n\
                    cap=cert_ed25519_verify\n"; // we HAVE these three ⇒ not missing
        let plan = build_sync_plan(text).expect("parses");
        assert!(plan.is_newer);
        assert!(plan
            .missing_capabilities
            .contains(&"quic_stamp_0x0f".to_string()));
        // relay_hop + dns64_synthesis shipped (dnscrypt.rs wrap_for_relay · dns64.rs build_synth_aaaa) —
        // the corrected current_envelope owns them, so a sync plan must NEVER flag them as missing.
        assert!(!plan.missing_capabilities.contains(&"relay_hop".to_string()));
        assert!(!plan
            .missing_capabilities
            .contains(&"dns64_synthesis".to_string()));
        assert!(!plan
            .missing_capabilities
            .contains(&"cert_ed25519_verify".to_string()));
        assert!(plan.has_work());
    }

    #[test]
    fn plan_for_distilled_2_1_18_envelope_names_zero_gaps_and_surfaces_the_surpass() {
        // ★ Slice 1 (the +300% capstone) — the EXACT envelope the Kotlin worker
        // (`CheckDnsCryptBinaryUpdateWorker.distillUpstreamEnvelope`) emits for an audited
        // upstream 2.1.18 tag. Every coordinate is owned by `current_envelope` (PQ absorbed in
        // the v2.1.17 wave; the two v2.1.18 deltas absorbed in this slice; key-rotation
        // SURPASSED by per-query ephemerals) ⇒ ZERO missing capabilities — the sync plan must
        // never name a false gap. And the diff surfaces `per_query_ephemeral_keys` as EXTRA:
        // upstream never emits that coordinate, so its presence is the honest "this build is
        // AHEAD" signal.
        let text = "version=2.1.18\n\
                    cap=pqdnscrypt_xwing_0x0003\n\
                    cap=key_rotate_on_network_change\n\
                    cap=pq_cert_fetch_fragmentation_hardening\n\
                    cap=latency_excludes_setup\n";
        let plan = build_sync_plan(text).expect("parses");
        assert!(plan.is_newer, "2.1.18 > 2.1.0-rust (the layer coordinate)");
        assert!(
            plan.missing_capabilities.is_empty(),
            "false gap named: {:?} — every audited 2.1.18 coordinate is owned/surpassed",
            plan.missing_capabilities
        );
        assert!(
            plan.extra_capabilities
                .contains(&"per_query_ephemeral_keys".to_string()),
            "the surpass coordinate must surface as extra (build ahead of upstream)"
        );
    }

    #[test]
    fn plan_flags_new_sources() {
        let text = "version=2.2.0\n\
                    source=https://example.com/new-relays.md\n";
        let plan = build_sync_plan(text).expect("parses");
        assert!(plan.is_newer);
        assert!(plan
            .new_sources
            .contains(&"https://example.com/new-relays.md".to_string()));
    }

    #[test]
    fn plan_malformed_upstream_is_err() {
        assert_eq!(build_sync_plan(""), Err(SyncNotNeeded::MalformedUpstream));
    }

    // ---- the durable round-trip ----

    #[test]
    fn sync_state_cold_is_zero() {
        let s = SyncState::cold();
        assert!(s.last_applied_version.is_empty());
        assert!(s.applied_capabilities.is_empty());
        assert_eq!(s.last_applied_secs, 0);
        assert_eq!(s.apply_count, 0);
    }

    #[test]
    fn sync_state_rehydrate_on_cold_dir_is_cold() {
        let dir = temp_dir("cold");
        let s = SyncState::rehydrate(dir.clone());
        assert_eq!(
            s,
            SyncState::cold(),
            "no record ⇒ cold start, never an error"
        );
        assert!(
            !dir.exists(),
            "DurableTier does not create the dir on a read"
        );
    }

    #[test]
    fn sync_state_round_trips_through_durable() {
        let dir = temp_dir("roundtrip");
        let mut s = SyncState::cold();
        s.last_applied_version = "2.1.16".into();
        s.applied_capabilities = vec!["relay_hop".into(), "dns64_synthesis".into()];
        s.last_applied_secs = 1_700_000_000;
        s.apply_count = 3;
        assert!(
            s.persist(dir.clone()),
            "durable write succeeds on a writable temp dir"
        );

        let reborn = SyncState::rehydrate(dir.clone());
        assert_eq!(
            reborn, s,
            "the round-trip is lossless for the bounded payload"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_state_decode_tolerates_unknown_keys() {
        // A future-shape record with an unknown key ("future=field") decodes with the unknown skipped.
        let bytes = b"version=2.2.0\nfuture=field\napplied=99\ncap=relay_hop\n";
        let s = SyncState::decode(bytes).expect("decodes");
        assert_eq!(s.last_applied_version, "2.2.0");
        assert_eq!(s.last_applied_secs, 99);
        assert_eq!(s.applied_capabilities, vec!["relay_hop".to_string()]);
    }

    #[test]
    fn sync_state_capabilities_escape_round_trip() {
        // A capability with `=`/`:`/`\` survives the escape → encode → decode → unescape round-trip.
        let dir = temp_dir("escape");
        let mut s = SyncState::cold();
        s.last_applied_version = "weird=ver:sion\\x".into();
        s.applied_capabilities = vec!["cap=with:back\\slash".into()];
        assert!(s.persist(dir.clone()));
        let reborn = SyncState::rehydrate(dir.clone());
        assert_eq!(reborn.last_applied_version, "weird=ver:sion\\x");
        assert_eq!(
            reborn.applied_capabilities,
            vec!["cap=with:back\\slash".to_string()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- apply_sync_plan ----

    #[test]
    fn apply_noop_plan_is_idempotent() {
        let dir = temp_dir("apply-noop");
        let plan = build_sync_plan("version=2.0.0\n").expect("parses"); // older ⇒ noop
        assert!(!plan.is_newer);
        // Applying a noop plan does not advance apply_count.
        let before = SyncState::rehydrate(dir.clone());
        let _ = apply_sync_plan(&plan, 1_700_000_000, dir.clone());
        let after = SyncState::rehydrate(dir.clone());
        assert_eq!(after.apply_count, before.apply_count);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_real_plan_advances_state_and_merges_capabilities() {
        let dir = temp_dir("apply-real");
        // A genuinely-FUTURE capability (not yet wired in the resolver tree) so build_sync_plan names it
        // missing; relay_hop/dns64_synthesis now ship and are OWNED by current_envelope, so they never
        // appear as missing and thus never get merged here.
        let plan = build_sync_plan("version=2.2.0\ncap=quic_stamp_0x0f\n").expect("parses");
        assert!(plan.is_newer);
        let ok = apply_sync_plan(&plan, 1_700_000_000, dir.clone());
        assert!(ok, "apply writes durably");

        let after = SyncState::rehydrate(dir.clone());
        assert_eq!(after.last_applied_version, "2.2.0");
        assert_eq!(after.last_applied_secs, 1_700_000_000);
        assert_eq!(after.apply_count, 1);
        // The missing capability is merged into the applied set.
        assert!(after
            .applied_capabilities
            .contains(&"quic_stamp_0x0f".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- the COMPONENT-SCOPED safety invariant (the keystone) ----

    #[test]
    fn current_envelope_does_not_name_any_core_module() {
        // The version-sync is component-scoped: the envelope never references Beast/Warden/Fortress/Mirror
        // capabilities — those are CORE concerns frozen at the APK version, NOT the DNSCrypt layer.
        let env = current_envelope();
        for cap in &env.capabilities {
            let lower = cap.to_ascii_lowercase();
            assert!(
                !lower.contains("beast")
                    && !lower.contains("warden")
                    && !lower.contains("fortress")
                    && !lower.contains("mirror")
                    && !lower.contains("cake")
                    && !lower.contains("cobalt"),
                "capability '{cap}' leaks a core concern into the DNSCrypt layer envelope"
            );
        }
    }
}
