/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Minisign signature verifier — the P8 Wave C3 SECURITY BOUNDARY.
//!
//! A remote (opt-in, CDN-shipped) blocklist artifact is authenticated HERE, BEFORE a single byte of it
//! reaches [`crate::blocklist::from_artifact`]. The verify ORDER is load-bearing:
//!
//!   1. **minisign signature (THIS module)** — authenticates *provenance*: the bytes came from the
//!      holder of the offline Centauri secret key and were not altered in transit. Real Ed25519.
//!   2. **FNV-1a self-check (`blocklist::from_artifact`)** — authenticates *set-integrity ONLY*. FNV is
//!      non-cryptographic and forgeable (`blocklist.rs` flags it; P9 swaps the digest via the reserved
//!      `hash_algo_id` byte). It can prove "these bytes describe the set they claim", NEVER "these bytes
//!      came from us".
//!
//! A tampered artifact with a VALID FNV but a BAD/ABSENT signature MUST be rejected at THIS gate, before
//! `from_artifact` ever runs. The caller (`CentauriArtifactManager` on Kotlin / `compile_and_install_*`)
//! calls [`verify_minisign`] FIRST and only proceeds on `true`.
//!
//! ## Minisign on-disk format (the parity contract — measured against jedisct1/minisign)
//!
//! A `.minisig` is a text file; **line 2** is the load-bearing payload:
//!   `base64( signature_algorithm(2) || key_id(8) || ed25519_signature(64) )`  =  exactly **74 bytes**.
//!
//!   - `signature_algorithm` = `b"Ed"` (legacy: sign the RAW file) or `b"ED"` (prehashed: sign
//!     `BLAKE2b-512(file)`). Tortä's Centauri producer uses the **legacy `Ed`** variant so the on-device
//!     verify needs only Ed25519 (already linked via the DNSCrypt cert path) and **no BLAKE2b on the
//!     SIGNATURE path**. The prehashed `ED` tag is therefore REJECTED here (we never ship it), which also
//!     closes a hash-downgrade vector.
//!
//!     > **Channel separation (BLAKE2b spine vs the signature):** the integrity SPINE — the
//!     > runtime-tier durable digest (`runtime_tier`) and the Centauri
//!     > content-address (`mirror`) — uses **BLAKE2b-256** (`blake2::Blake2b::<U32>`, `Cargo.toml`).
//!     > That is a DIFFERENT cryptographic channel from THIS one: minisign still signs the **RAW** artifact
//!     > bytes with Ed25519 (legacy `Ed`), it does NOT prehash. The signed message covers the whole file —
//!     > including the artifact's `hash_algo_id` byte — so a downgrade of the integrity-spine id (e.g.
//!     > BLAKE2b `2` → SHA-256 `1` → FNV `0`) changes the signed value and fails `verify_strict` at step 5.
//!     > The two channels never mix: the prehashed-`ED` reject keeps BLAKE2b OUT of the on-device VERIFY
//!     > path even though BLAKE2b is the integrity spine elsewhere in the crate.
//!   - `key_id` (8 bytes) pins WHICH key signed; it MUST equal the pinned public key's `key_id` — a
//!     swapped-key attack (re-sign with a different keypair) fails this check.
//!   - `ed25519_signature` (64 bytes) over the signed value.
//!
//! The pinned **public key** decodes to exactly **42 bytes**:
//!   `signature_algorithm(2) || key_id(8) || ed25519_public_key(32)`.
//! Only the 32 raw pubkey bytes feed Ed25519 verify; the 8 `key_id` bytes are matched against the
//! signature blob's `key_id`. The minisign PRIVATE key never ships — it lives offline on the Centauri side.
//!
//! ## What is signed
//!
//! For the legacy `Ed` variant the signed message is the RAW `.tblk` artifact bytes. Because the Ed25519
//! signature covers the WHOLE artifact, any post-sign tampering — a flipped `hash_algo_id` byte
//! (downgrade attempt), a re-encoded body that FNV-collides, a single mutated domain — changes the signed
//! message and fails `verify_strict`. So "valid FNV + bad sig" and "downgraded hash_algo_id" both fail at
//! step 5 below, NOT at the (later, weaker) FNV gate.
//!
//! ## Verify order (load-bearing — every step rejects before the next)
//!   1. blob len must be exactly 74           → reject truncated / over-long signatures
//!   2. algo tag must be `b"Ed"`              → reject prehashed `ED` (we never ship it) and junk tags
//!   3. blob.key_id == pinned key_id          → reject a swapped key
//!   4. signed_value = raw artifact bytes      (legacy `Ed`)
//!   5. Ed25519 `verify_strict(pk32, msg, sig64)` → reject on any failure
//!
//! ONLY after `true` does the caller invoke `from_artifact` (the FNV self-check).
//!
//! ## Panic firewall / isolation
//! This module is pure logic; the JNI export in `lib.rs` and the desktop C-ABI in `desktop.rs` wrap every
//! call in `catch_unwind` exactly like the existing blocklist surface, so a malformed input returns the
//! safe default (`false`) and NEVER unwinds across the FFI boundary. It reuses `ed25519-dalek` (already a
//! BASE dependency on the DNSCrypt cert path, `Cargo.toml`) — **the SIGNATURE path itself pulls no new
//! crate and causes no `.so` size regression**. (The BLAKE2b integrity SPINE adds `blake2` to the crate,
//! but that rides a separate channel — `runtime_tier`/`mirror` — and never the verify path here.)

use ed25519_dalek::{Signature, VerifyingKey};

/// The legacy minisign signature-algorithm tag: `b"Ed"` (sign the RAW file). This is the ONLY tag Tortä
/// accepts — the prehashed `b"ED"` (sign `BLAKE2b-512(file)`) is rejected so the on-device verify needs
/// no BLAKE2b dependency, which also forecloses a hash-algorithm downgrade.
pub(crate) const MINISIGN_ALG_LEGACY: [u8; 2] = *b"Ed";

/// Decoded minisign signature blob length: algo(2) + key_id(8) + ed25519_sig(64).
const SIG_BLOB_LEN: usize = 2 + 8 + 64;
/// Decoded minisign public-key blob length: algo(2) + key_id(8) + ed25519_pk(32).
const PUBKEY_BLOB_LEN: usize = 2 + 8 + 32;
const KEY_ID_LEN: usize = 8;
const ED25519_SIG_LEN: usize = 64;
const ED25519_PK_LEN: usize = 32;

/// Verify a minisign `Ed` (legacy) signature over `artifact` against a pinned minisign public key.
///
/// - `artifact`   : the RAW `.tblk` bytes (the exact bytes that will later go to `from_artifact`).
/// - `sig_blob`   : the base64-DECODED line-2 of the `.minisig` (the 74-byte blob). The caller decodes the
///   text file; this fn takes the binary blob so the parser has ONE job. (The Kotlin/JNI
///   wrapper passes the decoded bytes; tests pass them directly.)
/// - `pubkey_blob`: the base64-DECODED pinned public key (the 42-byte blob).
///
/// Returns `true` ONLY if every step of the verify order passes. Returns `false` (never panics, never
/// errors out) on ANY malformation: wrong blob length, wrong algo tag, key_id mismatch, a bad pubkey, or
/// a failed Ed25519 `verify_strict`. This is set up so the caller's contract is dead simple — proceed to
/// `from_artifact` IFF this returned `true`.
pub fn verify_minisign(artifact: &[u8], sig_blob: &[u8], pubkey_blob: &[u8]) -> bool {
    // Step 1 — signature blob must be EXACTLY 74 bytes (reject truncated / padded / over-long sigs).
    if sig_blob.len() != SIG_BLOB_LEN {
        return false;
    }
    // The pinned public key must be EXACTLY 42 bytes (a malformed pin is a hard reject, not a soft pass).
    if pubkey_blob.len() != PUBKEY_BLOB_LEN {
        return false;
    }

    // Step 2 — algorithm tag must be the legacy `Ed`. Reject prehashed `ED` and any other tag. This is
    // INDEPENDENT of the artifact's internal `hash_algo_id` byte: the minisign algo lives in the sig blob,
    // so a downgrade of the in-artifact hash byte cannot masquerade as a different signature scheme.
    let sig_algo = [sig_blob[0], sig_blob[1]];
    if sig_algo != MINISIGN_ALG_LEGACY {
        return false;
    }

    // Step 3 — key_id must match the pinned key's key_id (reject a swapped key: a valid signature made
    // with a DIFFERENT keypair carries that key's id and is rejected here, before any curve math).
    let sig_key_id = &sig_blob[2..2 + KEY_ID_LEN];
    let pin_key_id = &pubkey_blob[2..2 + KEY_ID_LEN];
    // Constant-time-ish compare is unnecessary (key_id is public), but reject any mismatch.
    if sig_key_id != pin_key_id {
        return false;
    }

    // Extract the 64-byte Ed25519 signature and the 32-byte pinned public key.
    let sig_bytes: [u8; ED25519_SIG_LEN] = match sig_blob[2 + KEY_ID_LEN..].try_into() {
        Ok(a) => a,
        Err(_) => return false, // unreachable given the length check, but never unwrap on FFI input
    };
    let pk_bytes: [u8; ED25519_PK_LEN] = match pubkey_blob[2 + KEY_ID_LEN..].try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false, // not a valid curve point → reject
    };
    let signature = Signature::from_bytes(&sig_bytes);

    // Step 4 + 5 — the signed value for the legacy `Ed` variant is the RAW artifact bytes; `verify_strict`
    // (the same call the DNSCrypt cert path uses) rejects malleable/non-canonical signatures. ANY failure
    // here — a tampered artifact (FNV still valid), a flipped hash_algo_id, a forged sig — returns false.
    verifying_key.verify_strict(artifact, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // A fixed, deterministic key_id used across the test vectors (8 bytes).
    const TEST_KEY_ID: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];

    /// Build the 42-byte pinned public-key blob: `Ed`(2) || key_id(8) || pk(32).
    /// A5 GUARD -- the blob lengths must FOLLOW the Ed25519 sizes, not merely happen to equal them.
    ///
    /// `SIG_BLOB_LEN` is written `2 + 8 + 64` and `PUBKEY_BLOB_LEN` `2 + 8 + 32`: LITERALS, not
    /// `KEY_ID_LEN + ED25519_SIG_LEN`. Nothing today couples them, so a future edit to
    /// `ED25519_SIG_LEN` or `KEY_ID_LEN` leaves the blob-length checks silently disagreeing with
    /// the slice arithmetic at `sig_blob[2 + KEY_ID_LEN..]` -- which would then `try_into` a
    /// differently-sized array and take the `Err(_) => return false` arm. Every signature would be
    /// REJECTED -- fail-closed, but total.
    ///
    /// MEASURED (desynchronise `KEY_ID_LEN` 8 -> 9, blob literals untouched): 3 of 12 signature
    /// tests fail -- this one plus the two ACCEPTANCE tests. Every rejection test stays green,
    /// because a rejection test passes just as happily when EVERYTHING is rejected. So the existing
    /// suite does catch a desync, via the acceptance path; what this guard adds is the DIAGNOSIS.
    /// "SIG_BLOB_LEN must equal tag + key_id + signature" names the cause outright, where
    /// "a valid signature was rejected" sends the reader hunting through curve math first.
    ///
    /// It asserts the RELATIONSHIP rather than a snapshot of the values, so it survives a
    /// legitimate change to any one of them and fails only on a DESYNCHRONISED one.
    #[test]
    fn blob_lengths_follow_the_ed25519_sizes() {
        assert_eq!(
            SIG_BLOB_LEN,
            2 + KEY_ID_LEN + ED25519_SIG_LEN,
            "SIG_BLOB_LEN must equal tag + key_id + signature -- it is written as literals and              nothing else couples it to them"
        );
        assert_eq!(
            PUBKEY_BLOB_LEN,
            2 + KEY_ID_LEN + ED25519_PK_LEN,
            "PUBKEY_BLOB_LEN must equal tag + key_id + public key"
        );
        // The slice arithmetic the verify path actually performs must land exactly on the arrays
        // it try_into()s -- this is the consequence that makes the equalities above load-bearing.
        assert_eq!(
            SIG_BLOB_LEN - (2 + KEY_ID_LEN),
            ED25519_SIG_LEN,
            "sig_blob[2 + KEY_ID_LEN..] must be exactly an Ed25519 signature"
        );
        assert_eq!(
            PUBKEY_BLOB_LEN - (2 + KEY_ID_LEN),
            ED25519_PK_LEN,
            "pubkey_blob[2 + KEY_ID_LEN..] must be exactly an Ed25519 public key"
        );
    }

    fn make_pubkey_blob(pk: &[u8; 32], key_id: &[u8; 8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(PUBKEY_BLOB_LEN);
        v.extend_from_slice(&MINISIGN_ALG_LEGACY);
        v.extend_from_slice(key_id);
        v.extend_from_slice(pk);
        v
    }

    /// Build the 74-byte signature blob: algo(2) || key_id(8) || sig(64), legacy `Ed` over RAW `artifact`.
    fn sign_legacy(sk: &SigningKey, key_id: &[u8; 8], artifact: &[u8]) -> Vec<u8> {
        let sig = sk.sign(artifact); // legacy `Ed` = Ed25519 over the raw message
        let mut v = Vec::with_capacity(SIG_BLOB_LEN);
        v.extend_from_slice(&MINISIGN_ALG_LEGACY);
        v.extend_from_slice(key_id);
        v.extend_from_slice(&sig.to_bytes());
        v
    }

    fn test_signing_key() -> SigningKey {
        // Deterministic test key (NEVER a production key — that one is offline on the Centauri side).
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn accepts_a_valid_signature_over_the_artifact() {
        let sk = test_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let artifact = b"TBLK\x01\x00\x00\x00...the-real-bytes...";
        let sig_blob = sign_legacy(&sk, &TEST_KEY_ID, artifact);
        let pubkey_blob = make_pubkey_blob(&pk, &TEST_KEY_ID);
        assert!(
            verify_minisign(artifact, &sig_blob, &pubkey_blob),
            "a genuine Ed legacy signature over the exact artifact must verify"
        );
    }

    #[test]
    fn rejects_tampered_artifact_even_with_a_structurally_valid_blob() {
        // THE security-boundary test: the signature is well-formed (right len, right algo, right key_id),
        // but the artifact bytes were mutated after signing. The FNV self-check downstream might still be
        // forged to pass — this gate MUST reject FIRST, so from_artifact is never reached.
        let sk = test_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let original = b"TBLK\x01\x00\x00\x00 original artifact body";
        let sig_blob = sign_legacy(&sk, &TEST_KEY_ID, original);
        let pubkey_blob = make_pubkey_blob(&pk, &TEST_KEY_ID);

        let mut tampered = original.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF; // flip the final byte (a single mutated domain byte)
        assert!(
            !verify_minisign(&tampered, &sig_blob, &pubkey_blob),
            "a tampered artifact must be rejected at the SIGNATURE gate, before from_artifact runs"
        );
    }

    #[test]
    fn rejects_downgraded_hash_algo_id_byte() {
        // The artifact's internal hash_algo_id byte (offset 6) is part of the signed message. Flipping it
        // (a downgrade attempt) changes the signed value, so verify_strict fails at step 5 — the signature
        // covers the WHOLE file, not just the body.
        let sk = test_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let mut artifact = b"TBLK\x01\x00\x00\x00 body bytes here for the header".to_vec();
        let sig_blob = sign_legacy(&sk, &TEST_KEY_ID, &artifact);
        let pubkey_blob = make_pubkey_blob(&pk, &TEST_KEY_ID);

        // offset 6 is hash_algo_id in the TBLK header; downgrade/forge it.
        artifact[6] = 0x02; // pretend a different (reserved) hash algorithm
        assert!(
            !verify_minisign(&artifact, &sig_blob, &pubkey_blob),
            "a flipped hash_algo_id is inside the signed region → signature must fail"
        );
    }

    #[test]
    fn rejects_truncated_signature_blob() {
        let sk = test_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let artifact = b"TBLK\x01\x00\x00\x00 body";
        let sig_blob = sign_legacy(&sk, &TEST_KEY_ID, artifact);
        let pubkey_blob = make_pubkey_blob(&pk, &TEST_KEY_ID);

        // Drop the last byte → 73 bytes, not 74.
        let truncated = &sig_blob[..sig_blob.len() - 1];
        assert!(
            !verify_minisign(artifact, truncated, &pubkey_blob),
            "a sig blob that is not exactly 74 bytes must be rejected (truncated sig)"
        );
        // Also reject an over-long blob (75 bytes).
        let mut padded = sig_blob.clone();
        padded.push(0x00);
        assert!(
            !verify_minisign(artifact, &padded, &pubkey_blob),
            "an over-long sig blob must be rejected too"
        );
    }

    #[test]
    fn rejects_swapped_key_via_key_id_mismatch() {
        // An attacker re-signs the SAME artifact with a DIFFERENT keypair. The signature is cryptographically
        // valid for THAT key, but its key_id differs from the pinned key_id → rejected at step 3, before any
        // curve verify against the pinned key.
        let pinned_sk = test_signing_key();
        let pinned_pk = pinned_sk.verifying_key().to_bytes();
        let pubkey_blob = make_pubkey_blob(&pinned_pk, &TEST_KEY_ID);

        let attacker_sk = SigningKey::from_bytes(&[42u8; 32]);
        let attacker_key_id: [u8; 8] = [9, 9, 9, 9, 9, 9, 9, 9];
        let artifact = b"TBLK\x01\x00\x00\x00 body";
        let attacker_sig = sign_legacy(&attacker_sk, &attacker_key_id, artifact);

        assert!(
            !verify_minisign(artifact, &attacker_sig, &pubkey_blob),
            "a signature whose key_id != the pinned key_id must be rejected (swapped key)"
        );
    }

    #[test]
    fn rejects_signature_valid_for_a_different_key_with_matching_key_id() {
        // Defense in depth: even if an attacker forges the key_id to MATCH the pin (so step 3 passes), the
        // Ed25519 verify_strict against the pinned PUBLIC key fails — the curve math is the real gate.
        let pinned_sk = test_signing_key();
        let pinned_pk = pinned_sk.verifying_key().to_bytes();
        let pubkey_blob = make_pubkey_blob(&pinned_pk, &TEST_KEY_ID);

        let attacker_sk = SigningKey::from_bytes(&[42u8; 32]);
        let artifact = b"TBLK\x01\x00\x00\x00 body";
        // Forge the attacker's blob to carry the PINNED key_id.
        let forged = sign_legacy(&attacker_sk, &TEST_KEY_ID, artifact);

        assert!(
            !verify_minisign(artifact, &forged, &pubkey_blob),
            "a sig from a different key (even with a forged matching key_id) must fail verify_strict"
        );
    }

    #[test]
    fn rejects_prehashed_ed_tag() {
        // We never ship the prehashed `ED` variant (it would need BLAKE2b on-device). Even a blob that is
        // otherwise well-formed but tagged `ED` is rejected at step 2 — closing the prehash-downgrade door.
        let sk = test_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let artifact = b"TBLK\x01\x00\x00\x00 body";
        let mut sig_blob = sign_legacy(&sk, &TEST_KEY_ID, artifact);
        sig_blob[0] = b'E';
        sig_blob[1] = b'D'; // flip `Ed` → `ED`
        let pubkey_blob = make_pubkey_blob(&pk, &TEST_KEY_ID);
        assert!(
            !verify_minisign(artifact, &sig_blob, &pubkey_blob),
            "the prehashed ED algorithm tag must be rejected (we only accept legacy Ed)"
        );
    }

    #[test]
    fn rejects_absent_signature() {
        // An empty / absent signature blob is a hard reject (len != 74), so a remote artifact shipped with
        // NO .minisig can never arm: verify returns false and from_artifact is never reached.
        let sk = test_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let pubkey_blob = make_pubkey_blob(&pk, &TEST_KEY_ID);
        let artifact = b"TBLK\x01\x00\x00\x00 body";
        assert!(
            !verify_minisign(artifact, &[], &pubkey_blob),
            "an absent signature must be rejected"
        );
    }

    // ----------------------------------------------------------------------------------------------------
    // OWN-KEY authorship over the BLAKE2b integrity spine (the P9/#97 own-crypto round-trip)
    // ----------------------------------------------------------------------------------------------------
    //
    // The integrity SPINE switched SHA-256 → BLAKE2b-256 (the
    // runtime-tier durable digest in `runtime_tier`, and the Centauri content-address in `mirror`). The
    // signed artifacts therefore carry the BLAKE2b spine id `2` in their `hash_algo_id` header byte (off 6),
    // alongside the EXISTING ids `0` (FNV-1a `.tblk`, FROZEN) and `1` (SHA-256, the pre-switch catalog).
    //
    // The SIGNING channel is UNCHANGED by that switch: minisign still signs the RAW artifact bytes with the
    // Socio's OWN Ed25519 keypair (legacy `Ed`), it does NOT prehash. These tests prove the authorship
    // signature ROUND-TRIPS over a BLAKE2b-spine artifact, and — the security property — that the BLAKE2b
    // spine id byte is INSIDE the signed region, so a downgrade of it (BLAKE2b `2` → SHA-256 `1` → FNV `0`)
    // is caught by the SAME signature that authenticates authorship. No `blake2` dep is needed here: the
    // signature covers the RAW bytes regardless of which digest produced the spine values inside them.

    /// The BLAKE2b integrity-spine `hash_algo_id` (off 6 of a spine artifact header). This is the cross-slice
    /// constant the Build slices pin in lockstep: Rust `mirror/catalog.rs` `HASH_ALGO_BLAKE2B` AND Haskell
    /// `Catalog.hs` `hashAlgoBlake2b`. It MUST be `2` — NOT `0` (FNV `.tblk`, reserved) and NOT `1`
    /// (pre-switch SHA-256). The signature signs over an artifact CARRYING this byte; the byte itself is
    /// produced by the Build slices, this test only proves the authorship channel covers it.
    const HASH_ALGO_BLAKE2B: u8 = 2;

    /// Build a synthetic BLAKE2b-spine artifact: a `TBLK`-shaped header whose off-6 `hash_algo_id` byte is
    /// `HASH_ALGO_BLAKE2B`, followed by a 32-byte content-address slot (the `[u8;32]` width every BLAKE2b
    /// spine site uses — `Leaf.hash`, `ContentHash`, the runtime-tier frame digest) plus a body. We fabricate
    /// the 32-byte digest as fixed bytes (any 32 bytes — the SIGNATURE proves authorship over the WHOLE file,
    /// not the digest's correctness; the digest's correctness is the Build slices' own test vectors).
    fn make_blake2b_spine_artifact(content_address: [u8; 32], body: &[u8]) -> Vec<u8> {
        let mut a = Vec::with_capacity(7 + 32 + body.len());
        a.extend_from_slice(b"TBLK"); // magic (off 0..4)
        a.push(0x01); // format version (off 4)
        a.push(0x00); // flags (off 5)
        a.push(HASH_ALGO_BLAKE2B); // hash_algo_id (off 6) = BLAKE2b spine id `2`
        a.extend_from_slice(&content_address); // the 32-byte BLAKE2b content-address slot
        a.extend_from_slice(body);
        a
    }

    #[test]
    fn own_key_signs_and_verifies_a_blake2b_spine_artifact_round_trip() {
        // THE own-crypto round-trip: the Socio's own Ed25519 keypair signs an artifact bearing the BLAKE2b
        // spine id `2`, and verify_minisign accepts it against the pinned public key. This is the positive
        // authorship proof over the new spine — authorship is signed with Ed25519-over-RAW, the spine is
        // BLAKE2b inside the bytes, and the two compose.
        let sk = test_signing_key(); // the OWN keypair (production private key stays offline; this is the test key)
        let pk = sk.verifying_key().to_bytes();
        let pubkey_blob = make_pubkey_blob(&pk, &TEST_KEY_ID);

        let content_address = [0xB2u8; 32]; // a 32-byte BLAKE2b-256 content-address slot (any 32 bytes)
        let artifact = make_blake2b_spine_artifact(content_address, b"blake2b-spine body bytes");
        assert_eq!(
            artifact[6], HASH_ALGO_BLAKE2B,
            "the artifact must carry the BLAKE2b spine id 2 at off 6 (cross-slice lockstep constant)"
        );

        let sig_blob = sign_legacy(&sk, &TEST_KEY_ID, &artifact);
        assert!(
            verify_minisign(&artifact, &sig_blob, &pubkey_blob),
            "the OWN Ed25519 signature over a BLAKE2b-spine artifact must verify (authorship round-trip)"
        );
    }

    #[test]
    fn blake2b_spine_id_downgrade_fails_the_authorship_signature() {
        // THE security property: the BLAKE2b spine id byte (off 6) is INSIDE the signed region. An attacker
        // who downgrades the spine to SHA-256 (`2` → `1`) — or to FNV (`2` → `0`) — changes the signed value,
        // so verify_strict fails. The authorship signature is what defends the spine choice, exactly as it
        // defends every other byte (the existing rejects_downgraded_hash_algo_id_byte test proves the generic
        // case; this proves it specifically for the BLAKE2b → SHA-256/FNV downgrade direction).
        let sk = test_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let pubkey_blob = make_pubkey_blob(&pk, &TEST_KEY_ID);

        let content_address = [0xB2u8; 32];
        let artifact = make_blake2b_spine_artifact(content_address, b"blake2b-spine body bytes");
        let sig_blob = sign_legacy(&sk, &TEST_KEY_ID, &artifact);

        // Downgrade BLAKE2b (2) → SHA-256 (1): a different spine claimed under the SAME signature → reject.
        let mut downgraded_to_sha = artifact.clone();
        downgraded_to_sha[6] = 1; // SHA-256 id
        assert!(
            !verify_minisign(&downgraded_to_sha, &sig_blob, &pubkey_blob),
            "downgrading the spine id BLAKE2b(2)->SHA256(1) must fail the authorship signature"
        );

        // Downgrade BLAKE2b (2) → FNV (0): the weakest, non-cryptographic id → reject too.
        let mut downgraded_to_fnv = artifact.clone();
        downgraded_to_fnv[6] = 0; // FNV-1a id
        assert!(
            !verify_minisign(&downgraded_to_fnv, &sig_blob, &pubkey_blob),
            "downgrading the spine id BLAKE2b(2)->FNV(0) must fail the authorship signature"
        );
    }

    #[test]
    fn tampering_the_blake2b_content_address_fails_the_authorship_signature() {
        // The 32-byte BLAKE2b content-address slot is inside the signed region too: flipping a single byte of
        // it (a swapped asset that FNV/structurally still parses) changes the signed value → reject. This is
        // the content-address half of the spine being authorship-protected.
        let sk = test_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let pubkey_blob = make_pubkey_blob(&pk, &TEST_KEY_ID);

        let artifact = make_blake2b_spine_artifact([0xB2u8; 32], b"body");
        let sig_blob = sign_legacy(&sk, &TEST_KEY_ID, &artifact);

        let mut tampered = artifact.clone();
        tampered[7] ^= 0xFF; // flip the first byte of the 32-byte content-address slot (off 7)
        assert!(
            !verify_minisign(&tampered, &sig_blob, &pubkey_blob),
            "a tampered BLAKE2b content-address must fail the authorship signature"
        );
    }
}
