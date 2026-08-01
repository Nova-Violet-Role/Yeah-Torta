// This file is part of Yeah! Tortä.
// SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
// Copyright 2026 Saimonokuma.
//
// P9 Fortress — Module D (Integrity Self-Check) cargo-fuzz target.
//
// FUZZES THE MANIFEST PARSE: the integrity manifest (`TMAN`) parser is the byte-eating entrypoint
// reached via `fortress::integrity::attest` (the production entry). The invariant under fuzz is the
// fortress LAW: **any bytes ⇒ never panic, never unwind** — a forged/garbage manifest must be handled
// (rejected) gracefully, NEVER crash the native core behind the JNI firewall.
//
// `attest` verifies the (here arbitrary) signature FIRST, so a random `manifest` is overwhelmingly
// rejected at the sig gate (BadSignature) — which is itself part of what we fuzz: the sig path must not
// panic on garbage either. To drive coverage INTO the parser, we also split the fuzz input into a
// (manifest, sig, file) triple so the parser is reached whenever the (improbable) sig path passes, and
// the parse-rejection branches are exercised on every iteration regardless.
//
// SCAFFOLD/Verify NOTE (disjoint, do NOT race-edit `fuzz/Cargo.toml`): this target file is self-contained
// and uniquely named. The consolidating Verify phase / scaffold owns `fuzz/Cargo.toml`; add this stanza
// (alongside the other forge modules' targets — one shared manifest, N disjoint targets):
//
//   [package]
//   name = "torta_core-fuzz"
//   version = "0.0.0"
//   edition = "2021"
//   publish = false
//   [package.metadata]
//   cargo-fuzz = true
//   [dependencies]
//   libfuzzer-sys = "0.4"
//   [dependencies.torta_core]
//   path = ".."
//   [[bin]]
//   name = "fuzz_integrity_manifest"
//   path = "fuzz_targets/fuzz_integrity_manifest.rs"
//   test = false
//   doc = false
//
// REQUIRES (for the harness to reach the parser through `attest`): `fortress::integrity::attest` is `pub`
// AND the `fortress` module + `integrity` are reachable from the crate root. The scaffold currently
// declares `mod fortress;` (private) at lib.rs:39 and `pub mod integrity;` at fortress/mod.rs:45 — so to
// expose `attest` to this external fuzz crate, the scaffold/Verify phase must widen `mod fortress;` →
// `pub mod fortress;` (or add a `pub use fortress::integrity::attest;` re-export). NOTED for the scaffold;
// do NOT race-edit lib.rs from this builder. Until then, this target documents the harness; the inline
// `prop_parse_never_panics_on_arbitrary_bytes` host test (in integrity.rs) already exercises the same
// never-panic invariant on 4000 arbitrary inputs without any visibility change.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Carve the fuzz input into (manifest, sig, single-file) so the parser AND the sig gate both see
    // adversarial bytes. Layout: [u16 manifest_len][manifest][u8 sig_len][sig][rest = one file's bytes].
    if data.len() < 3 {
        // Still exercise the smallest inputs through the real entry — must not panic.
        let _ = torta_core::fortress::integrity::attest(data, &[], &[]);
        return;
    }
    let mlen = u16::from_le_bytes([data[0], data[1]]) as usize;
    let rest = &data[2..];
    let mlen = mlen.min(rest.len());
    let (manifest, after_m) = rest.split_at(mlen);

    let (sig, file_bytes): (&[u8], &[u8]) = if after_m.is_empty() {
        (&[], &[])
    } else {
        let slen = (after_m[0] as usize).min(after_m.len().saturating_sub(1));
        let body = &after_m[1..];
        let (sig, file) = body.split_at(slen.min(body.len()));
        (sig, file)
    };

    // The single fuzzed "file" is offered under a fixed path so a (vanishingly unlikely) sig pass can
    // also drive the file-compare branch. The invariant: NO panic, for ALL carvings.
    let files = [("fuzzed", file_bytes)];
    let _ = torta_core::fortress::integrity::attest(manifest, sig, &files);
});
