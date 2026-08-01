// This file is part of Yeah! Tortä.
// SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
// Copyright 2026 Saimonokuma.
//
// P9 Fortress — Module C (DNS Guardian) cargo-fuzz target. THE HIGHEST FUZZ PRIORITY (classic CVE turf:
// DNS wire parsing + punycode decode + Unicode script logic — compression loops, OOB, length confusion,
// integer overflow in the RFC-3492 number loop).
//
// FUZZES `fortress::guardian::classify(response_wire, qname)` — the unifying Guardian entrypoint that
// (1) extracts the answer IPs through the bounded `dns::answer_records` skimmer (rebind check) and
// (2) runs the self-contained punycode decoder + script-confusable analysis (homograph check). The
// invariant under fuzz is the fortress LAW: **any bytes ⇒ never panic, never unwind, never an OOB read** —
// bounded exactly like `dns::read_name` (MAX_POINTER_JUMPS) and `guardian::punycode_decode`
// (MAX_PUNYCODE_OUT, every step `checked_*`). A hostile response/qname must yield a `Verdict`, never crash
// the native core behind the JNI firewall.
//
// We carve the fuzz input into (response_wire, qname) so BOTH the wire path and the string path see
// adversarial bytes every iteration: the qname is taken from the input via `from_utf8_lossy` so even
// invalid UTF-8 drives a real (lossy-decoded) string through the homograph logic.
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
//   name = "fuzz_guardian"
//   path = "fuzz_targets/fuzz_guardian.rs"
//   test = false
//   doc = false
//
// REQUIRES (for the harness to reach `classify` from this external fuzz crate): `fortress::guardian::classify`
// is `pub` AND the `fortress` module is reachable from the crate root. The scaffold currently declares
// `mod fortress;` (private) at lib.rs and `pub mod guardian;` at fortress/mod.rs — so to expose `classify`
// to this external fuzz crate, the scaffold/Verify phase must widen `mod fortress;` → `pub mod fortress;`
// (or add a `pub use fortress::guardian::classify;` re-export). NOTED for the scaffold; do NOT race-edit
// lib.rs from this builder. Until then, this target documents the harness; the inline
// `classify_malformed_wire_never_panics` + `punycode_bounded_never_panics_on_garbage` host tests (in
// guardian.rs) already exercise the same never-panic invariant without any visibility change.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Layout: [u16 wire_len][response_wire][rest = qname bytes (lossy UTF-8)].
    if data.len() < 2 {
        // Smallest inputs still go through the real entry — must not panic.
        let _ = torta_core::fortress::guardian::classify(data, "");
        return;
    }
    let wlen = u16::from_le_bytes([data[0], data[1]]) as usize;
    let rest = &data[2..];
    let wlen = wlen.min(rest.len());
    let (response_wire, qname_bytes) = rest.split_at(wlen);

    // Drive even invalid UTF-8 through the homograph string path (lossy decode never panics).
    let qname = String::from_utf8_lossy(qname_bytes);

    // The invariant: NO panic, NO OOB, for ALL carvings — the verdict itself is irrelevant to the fuzzer.
    let _ = torta_core::fortress::guardian::classify(response_wire, &qname);

    // Also exercise the with-query datapath gate: treat the qname bytes as a (garbage) query so the
    // keystone-reject branch is fuzzed too.
    let _ = torta_core::fortress::guardian::classify_with_query(qname_bytes, response_wire, &qname);
});
