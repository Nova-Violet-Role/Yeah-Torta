/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Shared, **ring-pinned** rustls trust setup for every encrypted transport (DoH, DoH3, DoQ).
//!
//! Extracted verbatim from `doh.rs` (Wave 2b, the proven + cross-compiled config) so all three
//! transports authenticate the channel with the IDENTICAL trust anchors: on Android the v0.7
//! `BuilderVerifierExt` platform verifier (system trust), on every other target (incl. the Windows
//! host where `cargo check`/`cargo test` run) the static `webpki-roots` bundle. The provider is
//! pinned to **`ring`** end-to-end — NEVER aws-lc-rs (the cross-compile gate for cargo-ndk).
//!
//! **ALPN is transport-specific** and is therefore NOT set here:
//!   - DoH (HTTP/2)  advertises `h2` — stamped by the hyper-rustls builder's `enable_http2()`
//!     (NEVER pre-set on the config: `with_tls_config` asserts ALPN-empty, builder.rs:61),
//!   - DoH3 (HTTP/3) advertises `h3`,
//!   - DoQ  (RFC 9250) advertises `doq`.
//!     `client_tls_config()` returns a config with an EMPTY `alpn_protocols`; each transport sets its own
//!     (DoH via the hyper-rustls builder, the QUIC transports via [`with_alpn`]). QUIC wraps the resulting
//!     `Arc<rustls::ClientConfig>` with `quinn::crypto::rustls::QuicClientConfig::try_from(..)`.

use std::sync::Arc;

use rustls::ClientConfig;

/// Build the shared rustls client config with the `ring` provider and the right trust anchors for the
/// target. The returned config has **no ALPN** set — the caller (per transport) appends its own
/// (`h2` for DoH via the hyper-rustls builder, `h3` for DoH3, `doq` for DoQ).
///
/// FIX-2 (P9 Centauri Mirror): widened `pub(super)` → `pub(crate)` so the new sibling `crate::mirror`
/// (and the crate-level [`crate::tls_shared`] re-export it imports) can reuse the IDENTICAL ring-pinned
/// trust setup for its fetch-ONCE leg — no second TLS builder, no aws-lc-rs drift. The BODY is unchanged
/// (the cross-compile-proven android/host cfg split below is byte-identical), so cargo-ndk stays clean.
pub(crate) fn client_tls_config() -> ClientConfig {
    // Pin the ring provider explicitly — never depend on a process-global default being installed,
    // and never aws-lc-rs (cross-compile hazard for cargo-ndk).
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    build_with_roots(provider)
}

/// ★ #65 — BUILT-IN ROOTS ON EVERY TARGET, ANDROID INCLUDED.
///
/// This used to branch on Android into `rustls-platform-verifier`, whose own doc-comment stated the
/// requirement plainly: Kotlin MUST call `rustls_platform_verifier::android::init_with_env(&mut env,
/// context)` before the first TLS handshake, "wired in a later Kotlin shim wave". That wave never
/// landed. Without the JNI handle the verifier does not fail politely — it PANICS inside
/// `rustls-platform-verifier-0.7.0/src/android.rs:90` on the first certificate it is asked to check.
///
/// MEASURED on the emulator: every Centauri upstream fetch died there
/// (`thread 'centauri-mirror' panicked at ...android.rs:90`), which killed the serving connection
/// mid-response. That is why `CDN fetched` had never left 0 — not a missing feature, a trust path that
/// could not complete a single handshake on the platform the app actually ships to.
///
/// The static Mozilla root store is the honest fix and the code already called it "the Expert
/// 'built-in roots only' path on Android". It validates public CDN and DoH certificates exactly as
/// strictly; what it does not consult is the device's user-installed CAs — which for fetching public
/// assets is a defensible default, and arguably the safer one. Restoring the platform verifier is a
/// separate, self-contained job: wire the JNI init from Kotlin, then this branch can come back.
///
/// NEVER `danger_accept_invalid_certs` (T11).
fn build_with_roots(provider: Arc<rustls::crypto::CryptoProvider>) -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports TLS 1.2/1.3")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

// REMOVED 2026-07 with the DEPRECATED `quic`/`doh3` transports: `with_alpn`, which stamped the
// per-transport ALPN (`h3` / `doq`) onto the shared client config. Its only callers were DoH3 and
// DoQ; no shipped recipe built either.
