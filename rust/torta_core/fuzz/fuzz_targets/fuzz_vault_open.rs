/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

// Module B — Secret Vault: cargo-fuzz target for `fortress::vault::open`.
//
// Invariant (the P9 LAW for the Vault): open() over ARBITRARY bytes must NEVER panic, NEVER leak
// plaintext, and NEVER return a value for an unauthenticated blob. Every input is either a None
// (the overwhelming case — random bytes are not a valid AEAD record) or, in the astronomically
// unlikely event the fuzzer forges a tag, an authenticated plaintext. The fuzzer drives:
//   * the DEK (first 32 bytes of the input),
//   * an AAD slice (next, length-prefixed),
//   * the blob (the remainder),
// so it exercises wrong-key / wrong-aad / tampered-tag / truncated / oversized / short paths.
//
// ── WIRING (for the scaffold/Verify phase — NOT race-edited here) ──────────────────────────────
// This file is DISJOINT (owner: secret-vault). The crate `Cargo.toml` is owned by the scaffold; the
// `fuzz/` cargo-fuzz workspace is created ONCE by the P9-0 prelude. Add this stanza to `fuzz/Cargo.toml`:
//
//   [dependencies]
//   torta_core    = { path = ".." }
//   libfuzzer-sys = "0.4"
//   arbitrary     = { version = "1", features = ["derive"] }   # (shared by all fortress fuzz targets)
//
//   [[bin]]
//   name = "fuzz_vault_open"
//   path = "fuzz_targets/fuzz_vault_open.rs"
//   test = false
//   doc  = false
//
// Run (host): `cargo +nightly fuzz run fuzz_vault_open` from `rust/torta_core/`.
// NOTE: `fortress::vault` is currently a PRIVATE module (`mod fortress;` at lib.rs:39). To let the fuzz
// crate reach `vault::{seal,open,DEK_LEN}`, the scaffold should either (a) make `pub mod fortress` /
// `pub mod vault` (the §1 dashboard surface goes public anyway), or (b) add a thin
// `#[cfg(fuzzing)] pub use fortress::vault;` re-export. Tracked for Verify; the unit tests in
// vault.rs already cover the same never-panic/never-leak invariant deterministically on the host.

#![no_main]

use libfuzzer_sys::fuzz_target;
use torta_core::fortress::vault;

fuzz_target!(|data: &[u8]| {
    // Need at least a DEK to do anything; below that, there is nothing to fuzz.
    if data.len() < vault::DEK_LEN {
        return;
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&data[..vault::DEK_LEN]);
    let rest = &data[vault::DEK_LEN..];

    // Carve a length-prefixed AAD out of the next byte, then treat the remainder as the blob. This lets
    // the fuzzer explore the AAD-mismatch path as well as the blob-tamper paths.
    let (aad, blob) = if rest.is_empty() {
        (&[][..], &[][..])
    } else {
        let aad_len = (rest[0] as usize) % rest.len().max(1);
        let body = &rest[1..];
        let split = aad_len.min(body.len());
        (&body[..split], &body[split..])
    };

    // The whole contract: this must not panic and must not leak. We deliberately ignore the result —
    // a Some is a (vanishingly rare) genuinely-authenticated open; a None is the expected reject.
    let _ = vault::open(&dek, blob, aad);

    // Also drive a seal→open round trip on the trailing bytes as a plaintext, to fuzz the seal path's
    // buffer handling (the result MUST open back to the same bytes when present).
    if let Some(sealed) = vault::seal(&dek, blob, aad) {
        match vault::open(&dek, &sealed, aad) {
            Some(recovered) => assert_eq!(recovered, blob, "seal∘open round-trip must be exact"),
            None => panic!("a freshly-sealed blob must open under the same dek+aad"),
        }
    }
});
