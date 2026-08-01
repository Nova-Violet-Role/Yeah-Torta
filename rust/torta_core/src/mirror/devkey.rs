/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Per-device Centauri signing identity (First-Boot mint) — the OWNERSHIP answer to reverse-CDN
//! interrogation.
//!
//! ## Why a per-device key (the sovereignty argument)
//! Nautilus II is a PORTABLE app: it must work on EVERY host that downloads it, not one blessed machine.
//! A single shipped Centauri signing key would make every install trust the SAME authority — a
//! class-wide key, a class-wide compromise. Instead, each install mints its OWN Ed25519 keypair ONCE, at
//! First Boot, from OS entropy. The secret seed persists ON-DEVICE ONLY (never shipped, never egressed);
//! the public-key blob becomes THIS device's local content-authority — the pin against which its own
//! Centauri catalog verifies. Same app, DIFFERENT key per install (the Underground Layer model: one user,
//! one database, no shared authority).
//!
//! ## What the key does vs what it does NOT
//! The BLAKE2b-256 content hash ([`super::cache::content_hash`]) proves an asset's INTEGRITY — the fetched
//! bytes are the right bytes. It is public, keyless, and does NOT decide WHICH `host → hash` mappings the
//! mirror is allowed to trust. THAT is the device key's job: it signs the catalog (the mapping list), so a
//! poisoned/substituted catalog — even one whose entries hash-verify individually — is rejected because it
//! carries no signature from THIS device's key. Content-address ≠ authorization; the two channels are
//! complementary and both required.
//!
//! ## Format reuse (no duplicate Ed25519)
//! The signing/verify format is minisign legacy `Ed` — byte-identical to [`crate::signature`]: the pubkey
//! blob is `algo(2) || key_id(8) || pk(32)` (42 B), the signature blob is `algo(2) || key_id(8) ||
//! sig(64)` (74 B), and [`DeviceKey::self_verify`] proves a fresh key round-trips through the SAME
//! [`crate::signature::verify_minisign`] gate the live catalog path uses. No second verifier, no crate
//! drift: `ed25519-dalek` is already linked (DNSCrypt cert path) and `getrandom` is already a dependency.
//!
//! ## key_id derivation
//! `key_id = BLAKE2b-256(public_key)[..8]` — a stable, collision-resistant device identity derived from
//! the PUBLIC key alone. No secret material touches the id; deriving it deterministically means a reloaded
//! key produces the same id, so a persisted-then-reloaded device is recognizably the same authority.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use super::cache::content_hash;
use crate::signature::{verify_minisign, MINISIGN_ALG_LEGACY};

/// Ed25519 seed length — the 32-byte secret that IS the device key (`SigningKey::from_bytes`).
pub const DEVICE_SEED_LEN: usize = 32;
/// minisign key_id length (8 bytes) — pins WHICH key signed.
pub const DEVICE_KEY_ID_LEN: usize = 8;
/// minisign public-key blob length: algo(2) + key_id(8) + pk(32).
pub const DEVICE_PUBKEY_BLOB_LEN: usize = 2 + DEVICE_KEY_ID_LEN + 32;
/// minisign signature blob length: algo(2) + key_id(8) + sig(64).
pub const DEVICE_SIG_BLOB_LEN: usize = 2 + DEVICE_KEY_ID_LEN + 64;

/// A per-install Centauri signing identity. The secret seed lives on-device only; the public-key blob is
/// the local content-authority against which THIS device's catalog verifies.
pub struct DeviceKey {
    signing: SigningKey,
    key_id: [u8; DEVICE_KEY_ID_LEN],
}

/// Why a device-key mint failed. Entropy is the only failure mode (the OS RNG was unavailable); everything
/// downstream is infallible byte-shuffling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKeyError {
    /// The OS entropy source (`getrandom`) was unavailable — mint could not proceed.
    Entropy,
}

impl DeviceKey {
    /// Mint a fresh device key from OS entropy. Called ONCE at First Boot; the caller persists
    /// [`DeviceKey::secret_seed`] to the durable on-device state dir and never again touches the network
    /// for this key.
    pub fn generate() -> Result<Self, DeviceKeyError> {
        let mut seed = [0u8; DEVICE_SEED_LEN];
        getrandom::getrandom(&mut seed).map_err(|_| DeviceKeyError::Entropy)?;
        Ok(Self::from_seed(&seed))
    }

    /// Reconstruct the device key from a persisted 32-byte seed — the reboot-proof load path. Infallible:
    /// every 32-byte value is a valid Ed25519 seed.
    pub fn from_seed(seed: &[u8; DEVICE_SEED_LEN]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let key_id = derive_key_id(&signing.verifying_key());
        Self { signing, key_id }
    }

    /// The 32-byte secret seed — persisted on-device only so the key survives a reboot. NEVER log it,
    /// NEVER transmit it: possession of this seed IS possession of the device's Centauri authority.
    pub fn secret_seed(&self) -> [u8; DEVICE_SEED_LEN] {
        self.signing.to_bytes()
    }

    /// The 8-byte key_id (`BLAKE2b-256(pk)[..8]`) — the deterministic, public device identity.
    pub fn key_id(&self) -> [u8; DEVICE_KEY_ID_LEN] {
        self.key_id
    }

    /// The 42-byte minisign public-key blob (`algo || key_id || pk`) — the local verify pin THIS device's
    /// catalog is checked against.
    pub fn pubkey_blob(&self) -> [u8; DEVICE_PUBKEY_BLOB_LEN] {
        let pk = self.signing.verifying_key().to_bytes();
        let mut blob = [0u8; DEVICE_PUBKEY_BLOB_LEN];
        blob[0..2].copy_from_slice(&MINISIGN_ALG_LEGACY);
        blob[2..2 + DEVICE_KEY_ID_LEN].copy_from_slice(&self.key_id);
        blob[2 + DEVICE_KEY_ID_LEN..].copy_from_slice(&pk);
        blob
    }

    /// Sign an artifact (a Centauri catalog) → the 74-byte minisign signature blob (`algo || key_id ||
    /// sig`), legacy `Ed` over the RAW bytes — byte-identical to [`crate::signature`]'s verify contract.
    pub fn sign(&self, artifact: &[u8]) -> [u8; DEVICE_SIG_BLOB_LEN] {
        let sig = self.signing.sign(artifact);
        let mut blob = [0u8; DEVICE_SIG_BLOB_LEN];
        blob[0..2].copy_from_slice(&MINISIGN_ALG_LEGACY);
        blob[2..2 + DEVICE_KEY_ID_LEN].copy_from_slice(&self.key_id);
        blob[2 + DEVICE_KEY_ID_LEN..].copy_from_slice(&sig.to_bytes());
        blob
    }

    /// Prove the key round-trips: sign a fixed probe, then verify it through the SAME
    /// [`crate::signature::verify_minisign`] gate the live catalog path uses. `true` ⇒ a valid,
    /// self-consistent signing identity (the First-Boot witness asserts this on both mint and reload).
    pub fn self_verify(&self) -> bool {
        const PROBE: &[u8] = b"centauri-device-key-self-verify";
        let sig = self.sign(PROBE);
        verify_minisign(PROBE, &sig, &self.pubkey_blob())
    }
}

/// `key_id = BLAKE2b-256(public_key)[..8]` — derived from the PUBLIC key alone (no secret leaks into the
/// id), deterministic so a reloaded key is the same recognizable authority.
fn derive_key_id(vk: &VerifyingKey) -> [u8; DEVICE_KEY_ID_LEN] {
    let full = content_hash(&vk.to_bytes());
    let mut id = [0u8; DEVICE_KEY_ID_LEN];
    id.copy_from_slice(&full[..DEVICE_KEY_ID_LEN]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_self_verifies() {
        let key = DeviceKey::generate().expect("os entropy");
        assert!(
            key.self_verify(),
            "a freshly minted device key must self-verify"
        );
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [0x42u8; DEVICE_SEED_LEN];
        let a = DeviceKey::from_seed(&seed);
        let b = DeviceKey::from_seed(&seed);
        assert_eq!(a.key_id(), b.key_id(), "same seed → same key_id");
        assert_eq!(
            a.pubkey_blob(),
            b.pubkey_blob(),
            "same seed → same pubkey blob"
        );
        assert!(a.self_verify());
    }

    #[test]
    fn secret_seed_round_trips() {
        let seed = [0x11u8; DEVICE_SEED_LEN];
        let key = DeviceKey::from_seed(&seed);
        assert_eq!(
            key.secret_seed(),
            seed,
            "the persisted seed reloads the same key"
        );
        let reloaded = DeviceKey::from_seed(&key.secret_seed());
        assert_eq!(reloaded.pubkey_blob(), key.pubkey_blob());
    }

    #[test]
    fn different_seeds_are_different_authorities() {
        let a = DeviceKey::from_seed(&[0x01u8; DEVICE_SEED_LEN]);
        let b = DeviceKey::from_seed(&[0x02u8; DEVICE_SEED_LEN]);
        assert_ne!(
            a.key_id(),
            b.key_id(),
            "distinct installs → distinct authorities"
        );
        assert_ne!(a.pubkey_blob(), b.pubkey_blob());
    }

    #[test]
    fn blob_lengths_match_minisign() {
        let key = DeviceKey::from_seed(&[0x7fu8; DEVICE_SEED_LEN]);
        assert_eq!(key.pubkey_blob().len(), DEVICE_PUBKEY_BLOB_LEN);
        assert_eq!(key.pubkey_blob().len(), 42);
        assert_eq!(key.sign(b"x").len(), DEVICE_SIG_BLOB_LEN);
        assert_eq!(key.sign(b"x").len(), 74);
    }

    #[test]
    fn algo_tag_is_legacy_ed() {
        let key = DeviceKey::from_seed(&[0x09u8; DEVICE_SEED_LEN]);
        assert_eq!(&key.pubkey_blob()[0..2], b"Ed");
        assert_eq!(&key.sign(b"x")[0..2], b"Ed");
    }

    #[test]
    fn tampered_artifact_fails_verify() {
        let key = DeviceKey::from_seed(&[0x55u8; DEVICE_SEED_LEN]);
        let sig = key.sign(b"catalog-bytes");
        // Same key, DIFFERENT artifact → the signature must not verify (integrity of the signed message).
        assert!(!verify_minisign(b"catalog-BYTES", &sig, &key.pubkey_blob()));
        assert!(verify_minisign(b"catalog-bytes", &sig, &key.pubkey_blob()));
    }

    #[test]
    fn swapped_key_fails_verify() {
        let a = DeviceKey::from_seed(&[0x21u8; DEVICE_SEED_LEN]);
        let b = DeviceKey::from_seed(&[0x22u8; DEVICE_SEED_LEN]);
        let sig = a.sign(b"catalog");
        // b's pin must reject a's signature (key_id mismatch + curve check) — no cross-device authority.
        assert!(!verify_minisign(b"catalog", &sig, &b.pubkey_blob()));
    }
}
