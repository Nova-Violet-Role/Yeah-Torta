/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Centauri Local Mirror — **host catalog-verify oracle** for the CDN-catalog cross-polyglot parity gate.
//!
//! This is a `src/bin` target gated behind the `mirror` feature. It exists ONLY on the host (NEVER built by
//! the on-device `cargo-ndk` pipeline — the base android build never sets `mirror`), so the cross-polyglot
//! differential gate can prove the offline Haskell `centauri-catalog-emit` producer emits a `.tcat` +
//! `.minisig` that the REAL on-device Rust path (`mirror::Catalog::parse_verified` →
//! `signature::verify_minisign` FIRST, then `parse_body`) accepts byte-for-byte — not a claim, the actual
//! shipped verifier.
//!
//! ## Usage
//!
//! ```text
//! catalog_verify_oracle <catalog.tcat> <catalog.tcat.minisig> <pubkey.b64>
//! ```
//!
//!   - `<catalog.tcat>`          : the RAW TCAT bytes the Haskell brain signed.
//!   - `<catalog.tcat.minisig>`  : the minisign sidecar (line 2 = base64(algo||key_id||sig)).
//!   - `<pubkey.b64>`            : the pinned 42-byte minisign public-key blob, base64 (one line; the
//!                                 `centauri-keygen` stdout pub blob).
//!
//! Prints, on success:
//!   `verified entries=<n>` then one `entry <cloak> <name> <host> <hash_hex>` line per entry,
//! and exits 0. On a rejected catalog prints `bad_signature` / `malformed` and exits 1; on an I/O / decode
//! error prints `error: <msg>` to stderr and exits 2. The bin makes the parity JUDGEMENT here: a real
//! Haskell-produced catalog MUST come back `verified`, a tampered one MUST come back `bad_signature`.
//!
//! ADR-001 note: auto-discovered under `src/bin/`, NOT a Cargo dependency — the Haskell brain stays fenced.

use std::process::ExitCode;

use torta_core::mirror::{Catalog, CatalogError};

/// Minimal base64 (standard alphabet, with '=' padding) decoder — std-only, no new dep. Mirrors the
/// minisign line-2 / pub-blob base64 the producer renders. Returns Err on a non-alphabet byte / bad length.
fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            other => Err(format!("non-base64 byte 0x{other:02x}")),
        }
    }
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let clean: Vec<u8> = clean.into_iter().take_while(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in &clean {
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

fn run() -> Result<ExitCode, String> {
    let mut args = std::env::args().skip(1);
    let tcat_path = args
        .next()
        .ok_or("usage: catalog_verify_oracle <catalog.tcat> <catalog.tcat.minisig> <pubkey.b64>")?;
    let sig_path = args
        .next()
        .ok_or("usage: catalog_verify_oracle <catalog.tcat> <catalog.tcat.minisig> <pubkey.b64>")?;
    let pub_path = args
        .next()
        .ok_or("usage: catalog_verify_oracle <catalog.tcat> <catalog.tcat.minisig> <pubkey.b64>")?;

    let tcat = std::fs::read(&tcat_path).map_err(|e| format!("read {tcat_path}: {e}"))?;

    // minisign: line 2 is the load-bearing base64 blob (line 1 is the `untrusted comment:` header).
    let sig_text =
        std::fs::read_to_string(&sig_path).map_err(|e| format!("read {sig_path}: {e}"))?;
    let sig_line2 = sig_text
        .lines()
        .nth(1)
        .ok_or_else(|| format!("{sig_path}: no line 2 (minisign sig blob)"))?;
    let sig_blob = b64_decode(sig_line2.trim())?;

    // pubkey: the producer's pub blob may itself be a 2-line minisign .pub (comment + blob) or a bare
    // base64 line. Take the LAST non-empty line (the blob) so both shapes work.
    let pub_text =
        std::fs::read_to_string(&pub_path).map_err(|e| format!("read {pub_path}: {e}"))?;
    let pub_line = pub_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .next_back()
        .ok_or_else(|| format!("{pub_path}: empty"))?;
    let pubkey_blob = b64_decode(pub_line)?;

    match Catalog::parse_verified(&tcat, &sig_blob, &pubkey_blob) {
        Ok(cat) => {
            let entries = cat.entries();
            println!("verified entries={}", entries.len());
            for e in entries {
                let hex: String = e.content_hash.iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "entry {} {} {} {}",
                    if e.cloaked { "cloak" } else { "plain" },
                    e.name,
                    e.host,
                    hex
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(CatalogError::BadSignature) => {
            println!("bad_signature");
            Ok(ExitCode::from(1))
        }
        Err(CatalogError::Malformed) => {
            println!("malformed");
            Ok(ExitCode::from(1))
        }
        // ★ ADDED 2026-07-31 to repair a build that had been RED at HEAD:
        //   `error[E0004]: non-exhaustive patterns: `Err(CatalogError::LegacyHashAlgo)` not covered`
        //
        // The variant carries a DISTINCT token, not a fold into `malformed`, for the exact reason
        // `mirror/catalog.rs:221-229` gives: `Malformed` tells an operator the file is corrupt or
        // hostile, while this one says the file is INTACT and merely predates the BLAKE2b spine
        // migration — the remedy is "re-fetch a current catalog", not "your download is broken".
        // An oracle that printed `malformed` here would send the reader hunting a corruption that
        // does not exist, and would make the two cases indistinguishable to any harness parsing it.
        //
        // The REJECTION is unchanged and exactly as hard: exit 1, no entries printed. This arm adds
        // a name, never an acceptance.
        Err(CatalogError::LegacyHashAlgo) => {
            println!("legacy_hash_algo");
            Ok(ExitCode::from(1))
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
