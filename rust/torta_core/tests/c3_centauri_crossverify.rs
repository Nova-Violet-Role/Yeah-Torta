/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! P8 Wave C3 — CROSS-ENGINE proof: the on-device Rust minisign verifier accepts a signature produced
//! by the REAL Centauri (Haskell, crypton Ed25519) signer, and rejects a tampered artifact / swapped key.
//!
//! These are NOT synthetic vectors — they are the literal bytes emitted by `centauri-keygen` +
//! `centauri-emit -- /tmp/c3.tblk` on the Home VM (GHC 9.4.7), captured as hex. If the Haskell `Ed`
//! legacy minisign blob and the Rust `verify_minisign` ever disagree on the byte layout (algo tag, key_id
//! placement, signed message = raw file), THIS test fails — it is the only thing that makes "the producer
//! and the on-device verifier agree" a measured fact rather than a claim.
//!
//! It pulls `signature.rs` in as a private module via `#[path]` (the established zero-pub-surface pattern
//! from `tests/diag_dnscrypt.rs` / `src/bin/blocklist_vectors.rs`), so it needs ZERO `pub` additions and
//! leaves the `.so` byte-identical.

#[path = "../src/signature.rs"]
mod signature;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// --- Captured from the Home VM (centauri-keygen + centauri-emit, crypton Ed25519). ---
const TBLK_HEX: &str = "54424c4b010000006455fe0a17bf2eed030000000f006164732e6578616d706c652e636f6d0f00646f75626c65636c69636b2e6e65740a00747261636b65722e696f";
const SIG_BLOB_HEX: &str = "4564b4b6cde311bf7a16da9bb003b67eb1078aa0d6b13a6d46baf5b63b5ea83bfb3c87841a463c4f2de48c812125805f1d989c26a547650099f28ea2e58ccf663833128788ecbe67e108";
const PUB_BLOB_HEX: &str =
    "4564b4b6cde311bf7a16397da16a5e31db8532a89a13b8869d04a8a8c8bd77de3ba9d4e0f7acf8525927";

#[test]
fn centauri_signature_verifies_on_device() {
    let tblk = hex(TBLK_HEX);
    let sig = hex(SIG_BLOB_HEX);
    let pubkey = hex(PUB_BLOB_HEX);
    assert_eq!(sig.len(), 74, "minisig blob must be 74 bytes");
    assert_eq!(pubkey.len(), 42, "pubkey blob must be 42 bytes");
    assert!(
        signature::verify_minisign(&tblk, &sig, &pubkey),
        "the Rust on-device verifier MUST accept the real Centauri (Haskell) minisign signature"
    );
}

#[test]
fn tampered_centauri_artifact_is_rejected() {
    let mut tblk = hex(TBLK_HEX);
    let sig = hex(SIG_BLOB_HEX);
    let pubkey = hex(PUB_BLOB_HEX);
    // Flip one byte of the canonical body (a domain byte) — the FNV could be re-forged, the sig cannot.
    let last = tblk.len() - 1;
    tblk[last] ^= 0x01;
    assert!(
        !signature::verify_minisign(&tblk, &sig, &pubkey),
        "a tampered Centauri artifact must be rejected at the signature gate"
    );
}

#[test]
fn swapped_pin_key_id_rejects_centauri_signature() {
    let tblk = hex(TBLK_HEX);
    let sig = hex(SIG_BLOB_HEX);
    let mut pubkey = hex(PUB_BLOB_HEX);
    // Corrupt the pinned key_id (offset 2..10) → key_id gate rejects even before curve math.
    pubkey[2] ^= 0xff;
    assert!(
        !signature::verify_minisign(&tblk, &sig, &pubkey),
        "a pin with a different key_id must reject the signature (swapped key)"
    );
}
