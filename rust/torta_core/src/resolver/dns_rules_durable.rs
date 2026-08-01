/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! W5 DurableTier mirror for the user-authored DNSCrypt single-rule lists (#12 slice 2 / RAMxNAND Opt-2).
//!
//! The five `*-single.txt` files — `blacklist-single` / `whitelist-single` / `ip-blacklist-single` /
//! `forwarding-rules-single` / `cloaking-rules-single` — hold the user's OWN hand-added DNS rules. They are
//! the ONLY DNSCrypt rule files NOT re-derivable from a signed remote source (the `*-remote.txt` lists are
//! re-fetched, the `*-local.txt` / bundled lists ship in the asset pack), so a wipe of `app_data` loses them
//! for good. This module gives each a durable RAM⊗NAND mirror, exactly mirroring the `dnscrypt-config`
//! self-owned-record precedent (#12 slice 1) and `resolver::rotation`:
//!
//! - the DURABLE truth is a framed per-list [`crate::runtime_tier::DurableTier`] record (MAGIC + version +
//!   SHA-256, atomic tmp+rename, 256 KiB-bounded), carrying the EXACT loose-file bytes;
//! - the loose `*-single.txt` stays the DERIVED view the Kotlin `DnsRulesDataSource` reader parses.
//!
//! [`persist_list`] runs on the CONTROL plane (a committed rule edit — Kotlin `saveSingle*Rules`);
//! [`materialize_list`] restores the loose file from the record when Kotlin finds it MISSING (a lazy
//! boot/load recovery — never when the file is present, so an intentionally-emptied list stays empty).
//! NEVER on the resolve hot path. Both are fail-safe (a refusal leaves the in-memory/on-disk state intact).

use crate::runtime_tier::DurableTier;
use std::io::Write;
use std::path::Path;

/// Serialize a rule list into the EXACT bytes the Kotlin `FileManager.atomicWriteLines` writes: each line
/// followed by `'\n'` (a trailing newline after the last line too — matching #11's `PrintWriter.println`
/// byte-form). So a round trip through the durable record reproduces a byte-identical loose file the reader
/// already accepts, with zero format drift.
fn encode_lines(lines: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    out
}

/// Persist a user single-rule list to its named DurableTier `record` under the app-private `dir` (RAM heap →
/// NAND atomic tmp+rename, integrity-framed). `record` is a bare basename — DurableTier sanitizes it
/// traversal-free, so a caller-supplied name can never escape `dir`. Returns `true` on a durable write,
/// `false` on ANY refusal (an over-budget blob, an IO fault) — best-effort: the loose file the caller
/// already wrote is untouched (the FAIL-SAFE invariant). Control-plane ONLY — a committed rule edit.
pub fn persist_list(dir: &Path, record: &str, lines: &[String]) -> bool {
    let tier = DurableTier::with_dir(dir.to_path_buf(), record);
    tier.write_through(&encode_lines(lines)).is_ok()
}

/// Re-materialize the loose single-rule file at `path` from its named DurableTier `record` under `dir` — the
/// recovery half. Rehydrates the framed record; on a present + integrity-valid record, atomically writes its
/// payload (the exact loose-file bytes) to `path` (create parent → `.tmp` → flush → fsync → rename, so a
/// crash before the rename never truncates the live file). Returns `true` IFF a record was present AND the
/// file was written; `false` on a cold / corrupt / tampered / absent record or an IO fault (the caller then
/// treats the list as empty — a true cold start). Boot/load ONLY — never the resolve path.
pub fn materialize_list(dir: &Path, record: &str, path: &Path) -> bool {
    let tier = DurableTier::with_dir(dir.to_path_buf(), record);
    match tier.rehydrate() {
        Some(bytes) => write_file_atomic(path, &bytes).is_ok(),
        None => false,
    }
}

/// Atomic write of `bytes` to `path`: create the parent dir, write a sibling `.<name>.tmp`, flush + fsync,
/// then rename onto the final name (POSIX atomic replace on the same filesystem — the Android target). A
/// crash before the rename leaves the live file whole; the torn partial lands only in the `.tmp`. The same
/// tmp+rename discipline as `dnscrypt_config::write_toml_atomic` (#12 slice 1) and the shared DurableTier.
fn write_file_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent();
    if let Some(p) = parent {
        std::fs::create_dir_all(p)?;
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rules-single.txt".to_string());
    let tmp = match parent {
        Some(p) => p.join(format!(".{file_name}.tmp")),
        None => std::path::PathBuf::from(format!(".{file_name}.tmp")),
    };
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        let _ = f.sync_all();
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp); // clean the orphan tmp on a rare rename failure.
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A unique-per-test temp dir under the OS temp root (process-unique counter + tag → collision-free; no
    /// rng dep). Mirrors `runtime_tier::tests::temp_dir`.
    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("torta-dnsrules-{tag}-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn persist_then_materialize_round_trips_exact_bytes() {
        let dir = temp_dir("rt");
        let tier_dir = dir.join("runtime_tier");
        let loose = dir.join("dnscrypt-proxy").join("blacklist-single.txt");
        // RFC 5737 / RFC 3849 addresses only — no live resolver in test data.
        let lines = vec![
            "example.com".to_string(),
            "*.ads.example.net".to_string(),
            "203.0.113.7".to_string(),
        ];
        assert!(persist_list(&tier_dir, "dnscrypt-single-blacklist", &lines));
        // The loose file is absent -> materialize restores it byte-for-byte.
        assert!(materialize_list(
            &tier_dir,
            "dnscrypt-single-blacklist",
            &loose
        ));
        let got = std::fs::read(&loose).unwrap();
        assert_eq!(got, encode_lines(&lines));
        // Reader-form: three '\n'-terminated lines (what FileManager.atomicWriteLines would have written).
        assert_eq!(
            String::from_utf8_lossy(&got),
            "example.com\n*.ads.example.net\n203.0.113.7\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn materialize_on_cold_record_returns_false_and_writes_nothing() {
        let dir = temp_dir("cold");
        let tier_dir = dir.join("runtime_tier");
        let loose = dir.join("dnscrypt-proxy").join("whitelist-single.txt");
        // No record was ever persisted -> a true cold start, no file laid down.
        assert!(!materialize_list(
            &tier_dir,
            "dnscrypt-single-whitelist",
            &loose
        ));
        assert!(!loose.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_list_persists_and_restores_empty() {
        let dir = temp_dir("empty");
        let tier_dir = dir.join("runtime_tier");
        let loose = dir.join("dnscrypt-proxy").join("cloaking-rules-single.txt");
        // An intentionally-emptied list is a real state: persist zero lines, restore an empty file (NOT a
        // cold miss) so recovery never resurrects rules the user deleted.
        assert!(persist_list(&tier_dir, "dnscrypt-single-cloaking", &[]));
        assert!(materialize_list(
            &tier_dir,
            "dnscrypt-single-cloaking",
            &loose
        ));
        assert_eq!(std::fs::read(&loose).unwrap(), Vec::<u8>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overwrites_a_stale_loose_file_in_place() {
        let dir = temp_dir("overwrite");
        let tier_dir = dir.join("runtime_tier");
        let loose = dir.join("dnscrypt-proxy").join("forwarding-rules-single.txt");
        std::fs::create_dir_all(loose.parent().unwrap()).unwrap();
        std::fs::write(&loose, b"stale garbage\n").unwrap();
        let lines = vec!["example.org 192.0.2.53".to_string()];
        assert!(persist_list(&tier_dir, "dnscrypt-single-forwarding", &lines));
        assert!(materialize_list(
            &tier_dir,
            "dnscrypt-single-forwarding",
            &loose
        ));
        assert_eq!(std::fs::read(&loose).unwrap(), encode_lines(&lines));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
