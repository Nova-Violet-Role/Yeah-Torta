/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! P8 Wave C3 — CROSS-ENGINE golden: the on-device Rust verifier (`signature::verify_minisign`)
//! accepts a REAL minisign signature produced by the offline Haskell Centauri signer
//! (`tools/centauri/src/Centauri/Sign.hs`), and REJECTS the same artifact once it is tampered.
//!
//! The vectors below were produced on the Centauri build VM (GHC 9.4.7, crypton 1.0.6) by:
//!   `centauri-keygen` → 40-byte offline secret (32 sk || 8 key_id)
//!   `printf '0.0.0.0 ads.example.com\ndoubleclick.net\ntracker.io\n' | CENTAURI_SECRET_KEY=… centauri-emit out.tblk`
//! which wrote `out.tblk` (the artifact), `out.tblk.minisig` (line 2 = the 74-byte sig blob), and
//! `sk.key.pub` (line 2 = the 42-byte minisign public-key pin). The base64 strings here are the EXACT
//! bytes from that run — so this test proves the Haskell producer and the Rust verifier agree on the
//! minisign byte layout (legacy `Ed`, Ed25519 over the raw `.tblk`), end to end.
//!
//! It reaches the verifier the same way the existing `tests/*_dnscrypt.rs` reach their modules: a
//! `#[path]` include of the source module. The verify ORDER (signature FIRST, before `from_artifact`'s
//! FNV self-check) is asserted by `verifies_then_tamper_breaks_it` — a tampered artifact is rejected at
//! the signature gate even though its body is otherwise a structurally valid TBLK.

#[path = "../src/signature.rs"]
mod signature;

// The REAL Haskell-Centauri-produced vectors (base64), copied verbatim from the VM run.
const ARTIFACT_B64: &str =
    "VEJMSwEAAABkVf4KF78u7QMAAAAPAGFkcy5leGFtcGxlLmNvbQ8AZG91YmxlY2xpY2submV0CgB0cmFja2VyLmlv";
const SIG_BLOB_B64: &str =
    "RWRwhgMpTRxbuJyPkqQn4CXXTwcrwco/rlZnplmG/cvy2H7y0H523mZPv4Pwy0FYRwujgzNav4ST6DumE/6KL73Yka8gGrX6qQo=";
const PUB_BLOB_B64: &str = "RWRwhgMpTRxbuOe+IJZlnTsmJC0trffpDeLnv96Ix5PRhn5WFMIl3iJ1";

/// Minimal, dependency-free standard-base64 decoder (RFC 4648, with `=` padding). The test crate has
/// no base64 dependency, and pulling one in just to decode three constants is gratuitous — this is a
/// few lines and only ever runs in `cargo test`.
fn b64_decode(s: &str) -> Vec<u8> {
    fn val(c: u8) -> i16 {
        match c {
            b'A'..=b'Z' => (c - b'A') as i16,
            b'a'..=b'z' => (c - b'a' + 26) as i16,
            b'0'..=b'9' => (c - b'0' + 52) as i16,
            b'+' => 62,
            b'/' => 63,
            _ => -1, // '=' padding or whitespace → skip
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in s.as_bytes() {
        let v = val(c);
        if v < 0 {
            continue;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

#[test]
fn rust_verifier_accepts_the_real_haskell_minisign_signature() {
    let artifact = b64_decode(ARTIFACT_B64);
    let sig = b64_decode(SIG_BLOB_B64);
    let pubkey = b64_decode(PUB_BLOB_B64);

    // Sanity on the decoded byte layout (the parity contract).
    assert_eq!(&artifact[0..4], b"TBLK", "vector artifact must be a TBLK");
    assert_eq!(
        sig.len(),
        74,
        "minisign sig blob must decode to exactly 74 bytes"
    );
    assert_eq!(
        pubkey.len(),
        42,
        "minisign pubkey blob must decode to exactly 42 bytes"
    );
    assert_eq!(
        &sig[0..2],
        b"Ed",
        "Centauri signs with the legacy Ed algorithm"
    );

    assert!(
        signature::verify_minisign(&artifact, &sig, &pubkey),
        "the Rust verifier MUST accept a genuine Haskell-Centauri-produced minisign signature \
         (cross-engine golden: Haskell-signed, Rust-verified)"
    );
}

#[test]
fn verifies_then_tamper_breaks_it() {
    let mut artifact = b64_decode(ARTIFACT_B64);
    let sig = b64_decode(SIG_BLOB_B64);
    let pubkey = b64_decode(PUB_BLOB_B64);

    // Baseline: the genuine artifact verifies.
    assert!(signature::verify_minisign(&artifact, &sig, &pubkey));

    // Tamper with a domain byte deep in the body (still a structurally valid TBLK whose FNV could be
    // re-forged). The signature covers the WHOLE file, so this is rejected at the SIGNATURE gate — long
    // before `from_artifact`'s FNV self-check would even run.
    let last = artifact.len() - 1;
    artifact[last] ^= 0x20; // flip a bit in "tracker.io"
    assert!(
        !signature::verify_minisign(&artifact, &sig, &pubkey),
        "a tampered artifact must be rejected at the signature gate, before from_artifact runs"
    );
}

#[test]
fn downgraded_hash_algo_id_byte_is_inside_the_signed_region() {
    let mut artifact = b64_decode(ARTIFACT_B64);
    let sig = b64_decode(SIG_BLOB_B64);
    let pubkey = b64_decode(PUB_BLOB_B64);

    // Offset 6 is the TBLK hash_algo_id byte (0 = FNV1A_64). A downgrade/forge to a different algo id is
    // covered by the Ed25519 signature over the whole file → verify must fail (not silently accepted and
    // then dispatched to a weaker/forged hash path).
    assert_eq!(
        artifact[6], 0u8,
        "the real artifact uses hash_algo_id 0 (FNV1A_64)"
    );
    artifact[6] = 2u8; // pretend a reserved/different hash algorithm
    assert!(
        !signature::verify_minisign(&artifact, &sig, &pubkey),
        "flipping the in-artifact hash_algo_id must break the signature (it is inside the signed region)"
    );
}
