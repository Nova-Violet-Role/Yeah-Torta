/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! RAM⊗NAND log fast-tier (#120) — an incremental tailer that reads ONLY the NEW bytes of an
//! on-NAND log file into a bounded RAM ring, so the Kotlin side never full-re-reads the file.
//!
//! ## Why
//! The old Kotlin path ([`OwnFileReader::readLastLines`]) opened a `BufferedReader` at byte 0 and read
//! the WHOLE `DnsCrypt.log` — plus a `FileShortener` rewrite when long — on every ~10s state-loop tick
//! (a full disk read + a `LinkedList` build/drop churn). That is the IO spike + RAM drain this tier
//! removes: the **NAND log file is the durable SOURCE; the RAM ring is the hot tier**, the same RAM⊗NAND
//! split [`crate::runtime_tier`] uses for the control-plane pillars.
//!
//! ## Shape
//! A process-global registry keyed by absolute path holds one [`Tailer`] per log. Each [`Tailer::poll`]
//! seeks to the saved byte-offset, reads at most [`MAX_POLL_BYTES`] of NEW bytes, splits on lines, and
//! pushes into a bounded [`VecDeque`] ring (drops oldest at [`RING_CAP`]). Rotation/truncation is fail-safe:
//! a file shorter than the saved offset resets the tailer (re-read from 0, still bounded). The readiness
//! marker (`" OK "` / `"lowest initial latency"` — the SAME signal `DNSCryptLogParser` keys
//! "started successfully" on) is latched as new lines arrive, so Kotlin reads ONE bool instead of
//! re-scanning. Every IO error degrades to "no new data" (the ring + offset stand); the FFI callers in
//! `lib.rs` wrap these in the panic guards, so a poison can never cross the boundary.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;

/// Bounded RAM tier: the most-recent N lines kept per log (older lines drop). Comfortably above the
/// Kotlin consumer's 80-line window so a tick that reads a burst still has full context.
const RING_CAP: usize = 256;

/// Per-poll read ceiling (1 MiB): a guard so a huge append — or a first-touch of an already-large file —
/// can never balloon a single poll. The remainder is picked up on the next tick (bounded, incremental).
const MAX_POLL_BYTES: u64 = 1 << 20;

/// One log's incremental tail state: where we've read to, the recent-line ring, and the latched marker.
struct Tailer {
    offset: u64,
    ring: VecDeque<String>,
    started_ok: bool,
}

impl Tailer {
    fn new() -> Self {
        Tailer {
            offset: 0,
            ring: VecDeque::with_capacity(RING_CAP),
            started_ok: false,
        }
    }

    /// Read ONLY the bytes after `offset`; push new lines into the ring; latch the readiness marker.
    /// Fail-open: any IO error leaves the tailer untouched (no new data, keep the ring).
    fn poll(&mut self, path: &str) {
        let mut f = match File::open(path) {
            Ok(f) => f,
            Err(_) => return, // absent/locked → no new data, keep what we have
        };
        let len = match f.metadata() {
            Ok(m) => m.len(),
            Err(_) => return,
        };
        // Rotation/truncation guard: a file shorter than we last saw ⇒ reset + re-read from 0.
        if len < self.offset {
            self.offset = 0;
            self.ring.clear();
            self.started_ok = false;
        }
        if len <= self.offset {
            return; // nothing new since the last poll
        }
        let to_read = (len - self.offset).min(MAX_POLL_BYTES);
        if f.seek(SeekFrom::Start(self.offset)).is_err() {
            return;
        }
        let mut buf = vec![0u8; to_read as usize];
        let n = match f.read(&mut buf) {
            Ok(n) => n,
            Err(_) => return,
        };
        self.offset = self.offset.saturating_add(n as u64);
        let text = String::from_utf8_lossy(&buf[..n]);
        for line in text.lines() {
            if !self.started_ok
                && (line.contains(" OK ") || line.contains("lowest initial latency"))
            {
                self.started_ok = true;
            }
            if self.ring.len() == RING_CAP {
                self.ring.pop_front();
            }
            self.ring.push_back(line.to_string());
        }
    }

    /// The last `max` lines, oldest→newest, '\n'-joined (the shape the Kotlin reader expects).
    fn recent(&self, max: usize) -> String {
        let take = self.ring.len().min(max);
        let skip = self.ring.len() - take;
        let mut out = String::new();
        for (i, line) in self.ring.iter().skip(skip).enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(line);
        }
        out
    }
}

/// Process-global tailer registry. `Mutex<Option<…>>` for a const-initializable `static` (no lazy
/// dependency); a poisoned lock is recovered via `into_inner` so one panicking caller can never wedge
/// the whole tier for the rest of the process.
static REGISTRY: Mutex<Option<HashMap<String, Tailer>>> = Mutex::new(None);

fn with_tailer<R>(path: &str, f: impl FnOnce(&mut Tailer) -> R) -> R {
    let mut guard = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let tailer = map.entry(path.to_string()).or_insert_with(Tailer::new);
    f(tailer)
}

/// Poll the log + return its most-recent `max_lines` (oldest→newest, '\n'-joined). The hot path the
/// Kotlin `ModulesLogRepositoryImpl` calls instead of `OwnFileReader`'s full re-read.
pub fn log_tail_recent(path: &str, max_lines: usize) -> String {
    with_tailer(path, |t| {
        t.poll(path);
        t.recent(max_lines)
    })
}

/// Poll the log + return whether the dnscrypt-proxy readiness marker has been seen — the SAME signal
/// `DNSCryptLogParser` latches, computed once in Rust so Kotlin never re-scans the file.
pub fn log_started_ok(path: &str) -> bool {
    with_tailer(path, |t| {
        t.poll(path);
        t.started_ok
    })
}

/// Seconds since `path` was last modified — the STALENESS signal (#126 anti-starvation). A log that is
/// getting real-time updates has a small age; one that stopped (dnscrypt stalled, or genuinely idle) has
/// a large age. Returns the age in seconds, or `-1` if the file is absent/unreadable (the caller treats
/// `-1` as "unknown"). Pure `stat` — no tailer state, off the hot path; pairs with dnscrypt-proxy's own
/// size/age log rotation (the anti-bloat half) so the RAM⊗NAND log tier is bounded AND freshness-aware.
pub fn log_stale_secs(path: &str) -> i64 {
    match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(mtime) => match std::time::SystemTime::now().duration_since(mtime) {
            Ok(age) => i64::try_from(age.as_secs()).unwrap_or(i64::MAX),
            Err(_) => 0, // mtime in the future (clock skew) ⇒ treat as fresh
        },
        Err(_) => -1, // absent / unreadable ⇒ unknown
    }
}

/// Per-pillar `query-<pillar>.log` size cap (256 KiB) and the tail kept when it overflows (128 KiB) — the
/// #126 anti-bloat rewrite, so a chatty pillar can never grow its log without bound.
const MAX_LOG_BYTES: u64 = 256 * 1024;
const KEEP_BYTES: usize = 128 * 1024;

/// #133 — the per-pillar log WRITE path: append ONE event line to a `query-<pillar>.log`. This is the ONE
/// shared substrate every pillar writes through, so the pillars SHARE a format + the [`log_tail_recent`]
/// read/debug path — the way dnscrypt-proxy's `query.log`/`DnsCrypt.log` feed every dashboard. Each pillar
/// stays distinct by its OWN file + its own line content (defined per pillar), but a unified debug view can
/// tail every `query-*.log` and correlate by timestamp. RAM⊗NAND: the NAND file is the durable tier, bounded
/// by a line-boundary-preserving tail rewrite (tmp+rename) at [`MAX_LOG_BYTES`]. FAIL-OPEN: any IO error is a
/// silent no-op — a debug log must NEVER break a pillar's hot path.
pub fn log_append(path: &str, line: &str) {
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(mut f) => {
            let _ = writeln!(f, "{line}");
        }
        Err(_) => return,
    }
    // Anti-bloat: past the cap, rewrite keeping the last KEEP_BYTES from the next line boundary (never a torn
    // first line). The [`Tailer`]'s rotation guard (len < offset ⇒ reset) re-syncs the reader after this.
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_LOG_BYTES {
            if let Ok(content) = std::fs::read(path) {
                let cut = content.len().saturating_sub(KEEP_BYTES);
                let start = content[cut..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map(|i| cut + i + 1)
                    .unwrap_or(cut);
                let tmp = format!("{path}.tmp");
                if std::fs::write(&tmp, &content[start..]).is_ok() {
                    let _ = std::fs::rename(&tmp, path);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A5 GUARD -- `KEEP_BYTES` (= 128 KiB, log_tier.rs:163) governs WHAT SURVIVES a rotation.
    /// The existing overflow test asserts only `size <= MAX_LOG_BYTES`, which is true of an empty
    /// file, of a file truncated mid-line, and of one that kept the OLDEST bytes instead of the
    /// newest. Size alone cannot see any of those.
    ///
    /// Three arms: the rotation keeps roughly KEEP_BYTES (not everything, not nothing), it cuts at
    /// a LINE BOUNDARY so the first surviving line is never torn, and the NEWEST line survives --
    /// a log that rotated away the most recent event is a log that is lying to the dashboard.
    #[test]
    fn keep_bytes_governs_what_survives_a_rotation() {
        let p = tmp("keepbytes");
        let path = p.to_string_lossy().to_string();
        // Every line carries a distinctive PREFIX. A homogeneous payload cannot detect a torn
        // cut -- a mid-line slice of "yyyy..." is still all-y and looks like a whole line. The
        // prefix is what makes the line-boundary arm able to fail (found by mutation M-A5j).
        for i in 0..400 {
            log_append(&path, &format!("HEAD{i:04}-{}", "y".repeat(990)));
        }
        log_append(&path, "HEAD9999-NEWEST-LINE-MARKER");

        let content = std::fs::read_to_string(&p).expect("read back");
        // The rotation keeps `len - start` where `start >= cut = len - KEEP_BYTES`, so it retains
        // AT MOST KEEP_BYTES -- but appends resume immediately afterwards, so what is observable
        // from outside is the steady-state bound, not the post-rotation size. MEASURED here: 136155
        // bytes, i.e. a rotation plus ~5 KiB of subsequent appends.
        assert!(
            content.len() <= MAX_LOG_BYTES as usize,
            "the file stays under the rotation cap: {} bytes",
            content.len()
        );
        assert!(
            content.len() > KEEP_BYTES / 2,
            "a rotation must not empty the log -- it keeps the recent tail: {} bytes",
            content.len()
        );
        let first = content.lines().next().unwrap_or("");
        assert!(
            first.starts_with("HEAD"),
            "the cut lands on a LINE BOUNDARY -- the first surviving line is never torn, so it              still carries its prefix: {first:.40}"
        );
        assert!(
            content.contains("NEWEST-LINE-MARKER"),
            "the NEWEST line must survive the rotation"
        );
        let _ = std::fs::remove_file(&p);
    }

    /// A5 GUARD -- `RING_CAP` (= 256) bounds the tail ring. The A5 inventory found it had a NUMBER
    /// and no test naming it: an unbounded ring fed by a log file is a memory leak with a cadence.
    /// Both arms: far MORE lines than the cap must leave the ring AT the cap (never above), and the
    /// retained lines must be the NEWEST ones -- a bound that silently kept the oldest would be a
    /// different bug wearing the same length.
    #[test]
    fn ring_cap_is_256_and_the_breach_is_loud() {
        let path = tmp("ringcap");
        {
            let mut f = std::fs::File::create(&path).expect("create");
            for i in 0..(RING_CAP * 3) {
                writeln!(f, "line-{i}").expect("write");
            }
        }
        let mut t = Tailer::new();
        t.poll(path.to_str().expect("utf8"));
        assert_eq!(
            t.ring.len(),
            RING_CAP,
            "the ring must saturate AT the cap, never above it"
        );
        assert_eq!(
            t.ring.back().map(String::as_str),
            Some(format!("line-{}", RING_CAP * 3 - 1).as_str()),
            "the ring must retain the NEWEST line, dropping oldest"
        );
        let _ = std::fs::remove_file(&path);
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("torta-logtier-{name}.log"));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn incremental_only_reads_new_bytes() {
        let p = tmp("incr");
        let path = p.to_string_lossy().to_string();
        std::fs::write(&p, "line1\nline2\n").unwrap();
        assert_eq!(log_tail_recent(&path, 10), "line1\nline2");
        // Append; a second poll must surface ONLY the new line on top of the retained ring.
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "line3").unwrap();
        assert_eq!(log_tail_recent(&path, 10), "line1\nline2\nline3");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn latches_readiness_marker() {
        let p = tmp("ready");
        let path = p.to_string_lossy().to_string();
        std::fs::write(&p, "[NOTICE] starting\n").unwrap();
        assert!(!log_started_ok(&path));
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "[NOTICE] [resolver] OK (DNSCrypt) - rtt: 30ms").unwrap();
        assert!(log_started_ok(&path));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn truncation_resets_safely() {
        let p = tmp("trunc");
        let path = p.to_string_lossy().to_string();
        std::fs::write(&p, "a\nb\nc\n").unwrap();
        assert_eq!(log_tail_recent(&path, 10), "a\nb\nc");
        // Rotate: shorter file ⇒ reset + re-read from 0, never a torn tail.
        std::fs::write(&p, "x\n").unwrap();
        assert_eq!(log_tail_recent(&path, 10), "x");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn per_pillar_append_writes_and_bounds() {
        let p = tmp("pillar-append");
        let path = p.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&p);
        // #133: a pillar appends events; the SAME tailer reads them back (the shared substrate).
        log_append(&path, "beast tick cwnd=1 aqm=44 relay=cloudflare");
        log_append(&path, "beast tick cwnd=2 aqm=43 relay=cloudflare");
        let got = log_tail_recent(&path, 10);
        assert!(
            got.contains("cwnd=1") && got.contains("cwnd=2"),
            "appended pillar lines must be readable: {got}"
        );
        // Anti-bloat: drive past the cap, the tail-rewrite must keep the file bounded.
        let big = "x".repeat(1000);
        for _ in 0..400 {
            log_append(&path, &big); // ~400 KiB written, well over the 256 KiB cap
        }
        let sz = std::fs::metadata(&p).unwrap().len();
        assert!(
            sz <= MAX_LOG_BYTES,
            "bounded after overflow: {sz} <= {MAX_LOG_BYTES}"
        );
        let _ = std::fs::remove_file(&p);
    }
}
