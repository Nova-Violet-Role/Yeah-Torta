/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Beast spec-harness — **host differential oracle** for the DNS anti-poisoning keystone.
//!
//! This is a `src/bin` target (the crate is `crate-type = ["cdylib", "rlib"]`, so a bin is a SEPARATE
//! compilation unit that leaves the Android `.so` byte-identical — ZERO `.so` impact, ZERO new deps,
//! std-only). It is NEVER built by the on-device `cargo-ndk` pipeline; it exists only on the host so the
//! cross-polyglot differential gate (the Centauri Haskell `BeastSpec.hs` spec ⟺ the REAL Rust
//! `validate_response`) can compare ACTUAL verdicts on the SAME generated wire vectors — not a claim.
//!
//! It reuses the EXACT zero-pub-surface trick `blocklist_vectors.rs` / `tests/diag_dnscrypt.rs` use:
//! pull `dns.rs` in as a PRIVATE module of the bin via `#[path]`. `lib.rs` declares `mod dns;`
//! PRIVATELY, so the crate surface does not export it; loading the source file directly here needs ZERO
//! `pub` additions to `lib.rs` and zero change to the DNS codec. (`dns.rs` already marks its public items
//! `pub` and applies `#![cfg_attr(not(test), allow(dead_code))]`, so the bin builds warning-clean.)
//!
//! ## Usage (one verdict per invocation)
//!
//! ```text
//! dns_validate_oracle <query_hex> <response_hex>   -> one token line on stdout
//! ```
//!
//! Reads two lowercase-hex byte strings (the query wire + the response wire), runs the REAL
//! `validate_response`, and prints ONE lower-snake token mirroring `BeastSpec.hs`'s `verdictToken`:
//!
//! ```text
//! accept | malformed | not_a_response | id_mismatch | question_mismatch
//!        | answer_walk | rcode_failure | truncated | extra_questions | trailing_bytes
//! ```
//!
//! The bin makes NO parity judgement itself — it just emits the REAL verdict the Haskell property
//! compares against. A bad-hex / arg-count error prints `error: <msg>` to stderr and exits 2.
//!
//! ADR-001 note: this bin is auto-discovered under `src/bin/` — it is NOT a dependency in any Cargo.toml,
//! so it does not breach `isolation-lint.{sh,ps1}` (the Haskell brain stays fenced from gradle/cargo).

#[path = "../dns.rs"]
mod dns;

use dns::{validate_response, RejectReason};
use std::process::ExitCode;

/// The stable wire token — MUST match `BeastSpec.hs`'s `verdictToken`.
fn token(r: Result<(), RejectReason>) -> &'static str {
    match r {
        Ok(()) => "accept",
        Err(RejectReason::Malformed) => "malformed",
        Err(RejectReason::NotAResponse) => "not_a_response",
        Err(RejectReason::IdMismatch) => "id_mismatch",
        Err(RejectReason::QuestionMismatch) => "question_mismatch",
        Err(RejectReason::AnswerWalk) => "answer_walk",
        Err(RejectReason::RcodeFailure) => "rcode_failure",
        Err(RejectReason::Truncated) => "truncated",
        Err(RejectReason::ExtraQuestions) => "extra_questions",
        Err(RejectReason::TrailingBytes) => "trailing_bytes",
    }
}

/// Decode a lowercase/uppercase hex string into bytes. Returns Err on odd length / non-hex.
fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(format!("hex length is odd ({})", s.len()));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!("non-hex byte 0x{other:02x}")),
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let query_hex = match args.next() {
        Some(a) => a,
        None => {
            eprintln!("error: usage: dns_validate_oracle <query_hex> <response_hex>");
            return ExitCode::from(2);
        }
    };
    let resp_hex = match args.next() {
        Some(a) => a,
        None => {
            eprintln!("error: usage: dns_validate_oracle <query_hex> <response_hex>");
            return ExitCode::from(2);
        }
    };

    let query = match from_hex(&query_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: bad query hex: {e}");
            return ExitCode::from(2);
        }
    };
    let response = match from_hex(&resp_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: bad response hex: {e}");
            return ExitCode::from(2);
        }
    };

    let verdict = validate_response(&query, &response);
    println!("{}", token(verdict));
    ExitCode::SUCCESS
}
