/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! P8 Wave C2 — **host parity oracle** for the blocklist codec.
//!
//! This is a `src/bin` target (the crate is `crate-type = ["cdylib", "rlib"]`, so a bin is a SEPARATE
//! compilation unit that leaves the Android `.so` byte-identical — ZERO `.so` impact, ZERO new deps,
//! std-only). It is NEVER built by the on-device `cargo-ndk` pipeline; it exists only on the host so the
//! cross-engine parity gate can run the REAL Rust `compile_text` / `Matcher::from_artifact` / `is_blocked`
//! against the Centauri (Haskell) emitter's output and compare ACTUAL bytes — not a static claim.
//!
//! It reuses the EXACT zero-pub-surface trick the in-tree integration tests already use
//! (`tests/diag_dnscrypt.rs`): pull `blocklist.rs` in as a private module of the bin via `#[path]`.
//! `lib.rs` declares `mod blocklist;` PRIVATELY, so the crate surface does not export it; loading the
//! source file directly here needs ZERO `pub` additions to `lib.rs` and zero change to the legacy text
//! path / fingerprint. The nested `#[path = "blocklist/trust.rs"]` inside `blocklist.rs` resolves
//! relative to `src/`, so it loads transparently from here too.
//!
//! ## Modes (dispatched by `argv[1]`)
//!
//! - `text`     — read a raw blocklist from STDIN, `compile_text` it, print `"<count> <fp:016x>"`.
//!                Same `{:016x}` lower-hex format the JNI layer logs (`fp={:016x}`).
//! - `artifact` — read a `.tblk` artifact from STDIN (or the path in `argv[2]`), run
//!                `Matcher::from_artifact`. On `None` (any Centauri drift: codepoint-vs-byte hashing,
//!                ascii-vs-Unicode lowercase, non-wrapping arithmetic, sort/endian skew — all surface as
//!                the embedded-fingerprint self-check failing), print `none` and exit 1 (parity FAIL).
//!                On `Some(m)`, print `"<count> <fp:016x>"` then one `"<probe> <true|false>"` line per
//!                probe (the probe set is the fixed list below, or, if extra args / a `--probes <file>`
//!                are given, those domains) via `is_blocked`.
//!
//! The bin makes NO parity judgement itself — it just emits REAL numbers/verdicts that the (separate)
//! Parity stage compares between the two engines.

// Load the matcher source directly as a private module — the established zero-pub-surface pattern from
// `tests/diag_dnscrypt.rs`. `#[allow(dead_code)]` covers the many `pub` items this bin does not call
// (compile_file, query, install_*, to_artifact, A2 provenance, …) so the bin builds warning-clean
// without touching `blocklist.rs`. This applies to the whole path-loaded module.
/// ★ THE `crate::underground` SEAM THIS ORACLE MUST SUPPLY — added 2026-07-31 to repair a build
/// that had been RED at HEAD.
///
/// `blocklist.rs` is pulled in below with `#[path]`, so inside it `crate::` means THIS BIN, not the
/// library. When `blocklist::resolve_source_reputations` (`blocklist.rs:719`) grew calls to
/// `crate::underground::reputation_rows` / `::corroborates_bad`, the library kept compiling and this
/// bin stopped:
///   `error[E0433]: cannot find `underground` in `crate``  (blocklist.rs:720 and :731)
/// The `#[path]` trick buys a zero-`pub` surface at the cost of this: every new `crate::` reference
/// inside the included file is a silent break of every bin that includes it.
///
/// The shim is deliberately NOT a plausible stand-in. `resolve_source_reputations` is reputation
/// scoring, not codec parity, and this oracle exists only to compare `compile_text` /
/// `Matcher::from_artifact` bytes against Centauri's emitter. So each function PANICS: if a future
/// change routes the parity path through reputation, this oracle dies loudly instead of silently
/// scoring parity against a fabricated Underground that always answers "no evidence".
/// A stub that returned `0` / `false` would be exactly the "error path rendering as a benign state"
/// failure the master names.
mod underground {
    /// Never reached by the parity modes; see the module comment.
    pub(crate) fn reputation_rows() -> usize {
        unreachable!(
            "blocklist_vectors is a CODEC parity oracle -- it must never enter reputation scoring; \
             reaching this means the parity path now depends on the Underground and the oracle's \
             claim would be meaningless"
        )
    }

    /// Never reached by the parity modes; see the module comment.
    pub(crate) fn corroborates_bad(_host: &str) -> bool {
        unreachable!(
            "blocklist_vectors is a CODEC parity oracle -- it must never enter reputation scoring; \
             reaching this means the parity path now depends on the Underground and the oracle's \
             claim would be meaningless"
        )
    }
}

// ★ WARNING AUDIT (2026-08-01). The `#[path]` include below is deliberate -- it lets this oracle
// exercise library internals WITHOUT the library exporting them (the zero-`pub` surface described
// above). The cost is that this bin compiles the WHOLE module while calling only the slice it
// needs, so rustc correctly reports the remainder as dead: 54 of the 189 warnings in a test build
// came from exactly this pattern, and NONE of them describe real rot -- the library itself uses
// those items, and the library's own build is still analysed for dead code normally.
//
// The allow is therefore scoped to THIS INCLUSION ONLY -- not the library, not the crate. Silencing
// it crate-wide, or making the items `pub` to please the compiler, would each hide a genuinely
// unused item somewhere else. That is the trade that turns a warning list into noise nobody reads,
// and a warning nobody reads is the same as no warning at all.
#[allow(dead_code)]
#[path = "../blocklist.rs"]
mod blocklist;

use blocklist::{compile_text, Matcher};
use std::io::{Read, Write};
use std::process::ExitCode;

/// Fixed probe set mirroring the in-tree `artifact_roundtrip` test plus Unicode-fold / TLD-edge cases.
/// Covers: positive match, subsumption (parent zone covers descendants), negative, label-boundary
/// false-positive guard, Unicode case-fold (`café` ↔ `CAFÉ`), Cyrillic, trailing dot, and a bare TLD.
/// The parity gate runs these SAME probes against the Centauri-produced artifact and a Rust-built one.
const DEFAULT_PROBES: &[&str] = &[
    "x.ads.example.com",
    "a.tracker.io",
    "plain.net",
    "ads.doubleclick.net",
    "deep.sub.doubleclick.net",
    "doubleclick.net.evil.com",
    "café.com",
    "www.café.com",
    "CAFÉ.com",
    "trailing.dot.net",
    "net",
    "example.com",
    "notplain.net",
];

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mode = match args.next() {
        Some(m) => m,
        None => return usage(),
    };

    match mode.as_str() {
        "text" => run_text(),
        "artifact" => run_artifact(args.collect()),
        _ => usage(),
    }
}

/// TEXT mode: STDIN bytes → `&str` → `compile_text` → `"<count> <fp:016x>"`.
///
/// Reads ALL of STDIN (the parity lists are valid UTF-8). `from_utf8_lossy` is faithful for valid UTF-8;
/// the real on-device JNI path also receives a `&str` (via `env.get_string`) and `compile_reader` feeds
/// `text.as_bytes()` back through, so a valid-UTF-8 list round-trips byte-identically here.
fn run_text() -> ExitCode {
    let mut buf = Vec::new();
    if let Err(e) = std::io::stdin().lock().read_to_end(&mut buf) {
        eprintln!("blocklist_vectors: failed to read stdin: {e}");
        return ExitCode::from(2);
    }
    let text = String::from_utf8_lossy(&buf);
    let m = compile_text(&text);
    println!("{} {:016x}", m.count(), m.fingerprint());
    ExitCode::SUCCESS
}

/// ARTIFACT mode: read a `.tblk` (from `argv[2]` path if given, else STDIN) → `from_artifact`.
///
/// `None` ⇒ the artifact's embedded fingerprint did not match the set the body recomputes to (the
/// structural self-check in `from_artifact`) — i.e. the producer (Centauri) drifted from Rust's exact
/// canonicalization/hash. Print `none` and exit 1 so the parity gate reads a hard FAIL signal.
/// `Some(m)` ⇒ print `"<count> <fp:016x>"`, then one `"<probe> <true|false>"` verdict per probe.
///
/// Remaining args select the probe set: none ⇒ `DEFAULT_PROBES`; `--probes <file>` ⇒ one domain per
/// non-empty line of `<file>`; otherwise the args ARE the probe domains.
fn run_artifact(rest: Vec<String>) -> ExitCode {
    // First arg (if present and not a flag) is a path to the .tblk; otherwise read STDIN.
    let mut iter = rest.into_iter().peekable();
    let artifact_path = match iter.peek() {
        Some(a) if !a.starts_with("--") => iter.next(),
        _ => None,
    };

    let bytes = match read_artifact(artifact_path.as_deref()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("blocklist_vectors: failed to read artifact: {e}");
            return ExitCode::from(2);
        }
    };

    let probes = match collect_probes(iter.collect()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("blocklist_vectors: {e}");
            return ExitCode::from(2);
        }
    };

    let m: Matcher = match Matcher::from_artifact(&bytes) {
        Some(m) => m,
        None => {
            // Drift / tamper / truncation ⇒ rejected. Hard parity-fail signal.
            println!("none");
            return ExitCode::from(1);
        }
    };

    // Buffer the verdict block so the whole report is one atomic write to the shuttle/pipe.
    let mut out = String::new();
    out.push_str(&format!("{} {:016x}\n", m.count(), m.fingerprint()));
    for probe in &probes {
        out.push_str(&format!("{} {}\n", probe, m.is_blocked(probe)));
    }
    let _ = std::io::stdout().lock().write_all(out.as_bytes());
    ExitCode::SUCCESS
}

/// Read the artifact bytes from `path` (if `Some`) or STDIN (if `None`).
fn read_artifact(path: Option<&str>) -> std::io::Result<Vec<u8>> {
    match path {
        Some(p) => std::fs::read(p),
        None => {
            let mut buf = Vec::new();
            std::io::stdin().lock().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

/// Resolve the probe set from the remaining args:
/// - `[]`                       → the fixed `DEFAULT_PROBES`
/// - `["--probes", "<file>"]`   → one domain per non-empty, non-`#` line of `<file>`
/// - `["a.com", "b.com", …]`    → those domains, verbatim
fn collect_probes(args: Vec<String>) -> Result<Vec<String>, String> {
    if args.is_empty() {
        return Ok(DEFAULT_PROBES.iter().map(|s| s.to_string()).collect());
    }
    if args[0] == "--probes" {
        let file = args
            .get(1)
            .ok_or_else(|| "--probes requires a file path".to_string())?;
        let text = std::fs::read_to_string(file)
            .map_err(|e| format!("failed to read probes file {file}: {e}"))?;
        let probes: Vec<String> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_string())
            .collect();
        return Ok(probes);
    }
    Ok(args)
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  \
         blocklist_vectors text                       < list.txt       -> \"<count> <fp:016x>\"\n  \
         blocklist_vectors artifact [<file.tblk>] [probes...]          -> \"<count> <fp:016x>\" + \"<probe> <bool>\" lines\n  \
         blocklist_vectors artifact <file.tblk> --probes <probes.txt>  -> verdicts for one-domain-per-line probes\n\
         \n\
         artifact reads STDIN when no <file.tblk> path is given; prints \"none\" and exits 1 on a rejected (drifted) artifact."
    );
    ExitCode::from(2)
}
