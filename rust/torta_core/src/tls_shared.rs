/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Crate-level shared TLS builder seam (P9 FIX-2).
//!
//! The cross-compile-proven, **ring-pinned** rustls client config lives in
//! [`crate::resolver::tls::client_tls_config`] (extracted verbatim from the Wave-2b DoH path; the
//! android platform-verifier vs. host webpki-roots split is the audited, cargo-ndk-clean body). The P9
//! Centauri Local Mirror ([`crate::mirror`]) is a NEW sibling of `resolver` and cannot reach a
//! `resolver`-private item, so this thin crate-level module **re-exports** the one canonical builder at a
//! crate-reachable path: `crate::tls_shared::client_tls_config()`.
//!
//! ## Why a re-export, not a moved/duplicated body
//! The TLS builder body is the single most cross-compile-sensitive code in the crate (the
//! `#[cfg(target_os = "android")]` platform-verifier branch at `resolver/tls.rs:38`, the verifier call at
//! `resolver/tls.rs:54`). Moving it risks perturbing that proven body. Re-exporting keeps **ONE** source
//! of truth — `resolver/tls.rs` stays the canonical, byte-identical builder; both `resolver` and `mirror`
//! authenticate every channel with the IDENTICAL `ring` trust anchors. NEVER aws-lc-rs (the cargo-ndk
//! gate); the provider is pinned to `ring` end-to-end inside `client_tls_config`.
//!
//! This module is NOT feature-gated: it carries zero new weight (a pure re-export of an already-compiled
//! item), so the base `.so` stays byte-identical whether or not the `mirror` feature is enabled. It is
//! only USED by the `mirror`-gated fetch leg; without `mirror`, the re-export is simply unreferenced.

// Re-export the one canonical ring-pinned client config builder at a crate-level path. `pub(crate)` so it
// is reachable from `crate::mirror::*` (a resolver-sibling) without widening the FFI/public API surface.
#[allow(unused_imports)]
pub(crate) use crate::resolver::tls::client_tls_config;

#[cfg(test)]
mod tests {
    //! FIX-2 seam tests — disjoint from `resolver::tls` (which has no test module) and from
    //! `resolver::mod::tests`. These PROVE the crate-level re-export is genuinely the ONE canonical
    //! ring-pinned builder, reachable at the path `crate::mirror` imports — not a second TLS config.
    //! Host-only + network-free: `client_tls_config()` only BUILDS the rustls config (no socket), and on
    //! the host target it takes the `webpki-roots` branch (`resolver/tls.rs:65`), never the android
    //! platform-verifier branch (`resolver/tls.rs:44`, gated `#[cfg(target_os = "android")]`).

    /// The re-export and the canonical source are the SAME fn item — one source of truth, no second
    /// TLS builder. Coercing both to a fn pointer and comparing addresses is the strongest in-language
    /// proof: identical addresses ⇒ literally the same code, so `mirror`'s fetch-ONCE leg and the
    /// resolver authenticate channels with byte-identical trust setup (no aws-lc-rs drift possible).
    #[test]
    fn reexport_is_the_one_canonical_builder() {
        let via_shared: fn() -> rustls::ClientConfig = super::client_tls_config;
        let via_resolver: fn() -> rustls::ClientConfig = crate::resolver::tls::client_tls_config;
        assert_eq!(
            via_shared as usize, via_resolver as usize,
            "crate::tls_shared::client_tls_config must BE crate::resolver::tls::client_tls_config \
             (a zero-weight re-export, not a duplicate builder) — FIX-2's single-source-of-truth",
        );
    }

    /// Building the shared config via the crate-level seam SUCCEEDS on the host — i.e. the `ring`
    /// provider is wired (the `.expect("ring provider supports TLS 1.2/1.3")` inside
    /// `client_tls_config` does not fire). If the crate ever drifted to aws-lc-rs OR lost the `ring`
    /// rustls feature, `default_provider()`/`builder_with_provider` would not yield a working
    /// TLS-1.2/1.3 config and this would panic. Network-free: only the config is constructed.
    #[test]
    fn shared_config_builds_ring_pinned_on_host() {
        // Reached via the SAME path `crate::mirror::server` uses, so this exercises the real seam.
        let cfg = super::client_tls_config();
        // The per-transport ALPN contract (resolver/tls.rs:19): the shared builder sets NO ALPN; each
        // caller (DoH/DoH3/DoQ — and now the mirror fetch leg) stamps its own. A non-empty alpn here
        // would mean the shared config leaked a transport-specific concern into the common builder.
        assert!(
            cfg.alpn_protocols.is_empty(),
            "the shared client config must carry NO ALPN — the per-transport ALPN contract",
        );
    }

    /// Two independent builds yield independent configs (the builder is a pure factory, not a shared
    /// mutable singleton) — so the mirror leg and the resolver each get their own config to stamp
    /// without cross-contaminating the other's ALPN/state. Network-free.
    #[test]
    fn each_call_yields_an_independent_config() {
        let mut a = super::client_tls_config();
        let b = super::client_tls_config();
        // Mutating one (as a transport would when stamping ALPN) must not perturb the other.
        a.alpn_protocols = vec![b"h2".to_vec()];
        assert!(
            b.alpn_protocols.is_empty(),
            "builds are independent: stamping ALPN on one config must not touch another",
        );
    }
}
