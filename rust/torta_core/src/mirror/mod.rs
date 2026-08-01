/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! P9 Centauri Local Mirror (E') — the in-app pillar: a content-addressed cache served over a lean Rust
//! loopback micro-HTTP(S) server.
//!
//! ## What it is
//! The Centauri Local Mirror is a self-filling, on-device CDN: the offline Haskell brain (native-linux
//! GHC 9.4.7 on the Home VM, ADR-001) authors + minisign-signs a CDN **catalog** of content-addressed
//! assets; on-device, this module verifies the catalog signature (REUSING `signature::verify_minisign`
//! verbatim — no duplicate Ed25519), fetches each asset ONCE over the FIX-2 shared ring-pinned TLS,
//! hash-verifies + caches it (content-addressed: serve only on hash match), and serves it back over a
//! `127.0.0.1` loopback server.
//!
//! ## Runtime = Rust (the spike-RED default, ADR-001 Amendment 1)
//! The GHC-RTS-on-Android spike is RED-by-prerequisite (no android-cross GHC toolchain provisions — see
//! [`server`]). The lean Rust loopback server IS the shippable runtime; the Haskell brain stays the
//! offline author/signer. This is the expected default, NOT a pillar blocker.
//!
//! ## Weight discipline (FIX-1)
//! The ENTIRE module is gated behind the `mirror` Cargo feature (`lib.rs`: `#[cfg(feature = "mirror")]
//! mod mirror;`). All its new weight — hyper's `server` half (`hyper/server` + `hyper-util/server`/
//! `server-graceful`), the loopback listener, the cache/catalog logic — is ABSENT from a base Android
//! `.so` (no `mirror` feature → byte-identical baseline), exactly the `desktop`/`quic`/`doh3` discipline.
//!
//! ## Unsafe posture
//! `#![forbid(unsafe_code)]` here AND on every submodule head — the mirror is pure logic (cache index,
//! signature-gated parse, loopback routing); the only audited unsafe in the crate stays the FFI
//! marshalling in `lib.rs`/`desktop.rs`.
//!
//! ## SCAFFOLD STATUS
//! Public signatures + the verify-FIRST / content-addressed / serve-on-match contracts are real and
//! type-check; minimal bodies compile under `cargo check --features mirror`. The Forge crew fills the
//! on-disk atomic-write cache, the real catalog wire format, the fetch-ONCE leg, and the accept loop.

#![forbid(unsafe_code)]

pub mod absorb;
pub mod cache;
pub mod catalog;
pub mod devkey;
pub mod fetch;
pub mod localcdn;
pub mod localcdn_maps;
pub mod log;
pub mod object;
pub mod packaging;
pub mod serve;
pub mod server;
// ★ #66 — the device CA that lets the mirror ANSWER a browser's TLS handshake as the CDN, so a `:443`
// asset reaches the same absorb-once/serve-forever path the `:80` hairpin already uses.
pub mod tlsca;

// The mirror's intended public facade (the JNI/dashboard surface wires these once the bodies land):
//   - `cache::CacheStore`  — the content-addressed store,
//   - `catalog::Catalog`   — the signature-verified asset manifest (verify-sig-FIRST),
//   - `server::MirrorServer` — the loopback runtime.
// `allow(unused_imports)` is the scaffold signal: these names ARE the intended surface; the allow drops
// once the JNI `nativeCentauriMirror*` exports + the dashboard stats reference them.
#[allow(unused_imports)]
pub use cache::{CacheEntry, CacheStore, ContentHash};
#[allow(unused_imports)]
pub use catalog::{encode_catalog, Catalog, CatalogEntry, CatalogError};
// The per-device Centauri signing identity (First-Boot mint — the OWNERSHIP answer to reverse-CDN
// interrogation): each install mints its OWN Ed25519 key, secret seed on-device only, the pubkey blob its
// local content-authority. Same app, different key per install (the Underground Layer one-user-one-database
// model). Reuses `signature::verify_minisign` verbatim — no duplicate Ed25519.
#[allow(unused_imports)]
pub use devkey::{DeviceKey, DeviceKeyError, DEVICE_PUBKEY_BLOB_LEN, DEVICE_SEED_LEN, DEVICE_SIG_BLOB_LEN};
#[allow(unused_imports)]
pub use fetch::{fetch_once, FetchError};
#[allow(unused_imports)]
pub use localcdn::{
    best_bundled_version, cdn_hosts, cloaking_rules, cloaking_rules_for, is_cdn_host, promoted_cloak_hosts, publish_servable_cloak, publish_cloak_tls_trust, cloak_tls_trusted, is_servable_cloak_host, servable_cloak_count, resolve, resolve_full,
    Resolution, ResourceMap, Substitution, SEED_MAPS,
};
#[allow(unused_imports)]
pub use localcdn_maps::FULL_MAPS;
// The privacy flow (slice 3 — ≤ 1 upstream request EVER per asset): the serve-from-cache-first /
// fetch-once-on-miss orchestrator + the single-flight coordinator + the sig-gated front door. #85 LANDED —
// the live accept loop ([`server::run_shared`]) now escalates an authorized `CacheMiss` through
// [`serve::serve_addressed`] (driven over the shared `Arc<Mutex<CacheStore>>` + the shared `InFlight` + the
// ring-pinned TLS `fetch_leg`) whenever the Centauri Object binds a [`server::FetchCtx`]; the ≤ 1 + sig-gate
// guarantees, proven host-side here, are the ones the live seam inherits.
#[allow(unused_imports)]
pub use serve::{
    fetch_leg, fetch_probe, serve_addressed, serve_name_private, upstream_url, CacheMode,
    FetchProbeReport, InFlight, ServeVerdict,
};
// The resource-packaging policy (slice 4 — the size decision, made code): TIER A ships ZERO asset bytes
// (self-fill-on-demand is the default, the 73 MiB LocalCDN tree is DECLINED), the F9 curation guard
// (`MAX_PACKAGEABLE_BYTES == MAX_ASSET_BYTES` so a cloaked asset is always fetchable), and the TIER-B opt-in
// `warm_up` batch (a curated self-fill on the user's OWN device — the warm seed is an AUTHORITY of hashes,
// never shipped library bytes). The UniFFI/dashboard slices surface `SeedPolicy` + drive `warm_up`.
#[allow(unused_imports)]
pub use packaging::{
    fetch_via_ladder, is_packageable, warm_up, SeedPolicy, WarmUpReport, WarmUpTarget,
    LOCALCDN_SEED_TREE_BYTES, MAX_ALT_UPSTREAMS, MAX_PACKAGEABLE_BYTES,
};
#[allow(unused_imports)]
pub use server::{FetchCtx, MirrorServer, ServeOutcome, ServerConfig};
/// The SERVE LEDGER — the production instrument for "absorb once, serve forever". Before it
/// existed the only counter reached for (`cloak_actions`) measured blocklist sinkholes and could
/// never move for Centauri, so the pillar's central claim had no honest denominator.
pub use server::{serve_bytes, serve_hits, serve_misses, serve_unauthorized};
// The per-pillar serve log (slice 6 — the #133 `query-centauri.log`): the human-legible, greppable serve feed
// written through the shared RAM⊗NAND `crate::log_tier` substrate (the `query-warden.log` precedent). The
// Centauri Object's `record_serve_logged` seam appends one line per serve via `log::append_serve`, the durable
// twin of the in-RAM `record_serve` counters — the CROWN ("the CDN sees ≤ 1 request") made AUDITABLE.
#[allow(unused_imports)]
pub use log::{append_serve, format_serve_line, QUERY_CENTAURI_LOG_NAME};
