/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Blocklist compiler + matcher — the "Zero Fatigue Zone" transcoder.
//!
//! The evolved design (not `HashSet<String>::contains`):
//!   - **Reversed-label trie** (`com·google·www`): blocking a domain blocks every subdomain beneath
//!     it as a single prefix-walk, not N string comparisons.
//!   - **Rust-native compactness**: labels live in a trie, so a million domains cost a fraction of
//!     the RAM + GC churn a JVM `HashSet<String>` would — the battery win, in the right language.
//!   - **Source-agnostic**: compiles a local FILE (manual .txt pick) OR an in-memory STRING (a GitHub
//!     search hit, a custom URL's bytes, an injected list) and can **merge** several into one matcher.
//!   - **Set-deterministic content fingerprint**: computed from the canonical blocked SET (a final
//!     trie walk), so the same blocking set always yields the same digest regardless of input order
//!     or cosmetic formatting. P9 upgrades the digest to a cryptographic hash for the integrity root.
//!
//! KNOWN GAP (intentionally deferred to P8): no public-suffix guard, so a list entry at a shared
//! suffix (`co.uk`, `github.io`, a CDN apex) would block every tenant beneath it. That is P8's CDN
//! over-block **safety score** — warn before arming such a list — not silently patched here.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::RwLock;

// P8 Wave A2 — provenance / trust store. Declared via `#[path]` so `blocklist.rs` stays a FLAT file
// (no rename to `blocklist/mod.rs`) and `lib.rs`'s `mod blocklist;` stays byte-identical.
// `pub(crate)` (not bare `mod`): the Centauri mirror crosses the Beast trust engine IN — `mirror::localcdn`
// reuses `SIGNED_FLOOR`/`CORR_STEP`/`CORR_CAP`/`recency_pct` so the mirror's resolution trust and the
// blocklist's source trust share ONE tuned constant set. Crate-internal only (the parent `mod blocklist` is
// private → this never enters the cdylib API; no external surface change).
#[path = "blocklist/trust.rs"]
pub(crate) mod trust;
use trust::SourceMask;

// R4 Warden — Slice 5: the GitHub Trust Crown (`github.rs`) is declared at the CRATE ROOT (`lib.rs`,
// `#[cfg(feature = "mirror")] mod github;`), NOT here. It depends on `crate::mirror`/`crate::runtime_tier`/
// `crate::tls_shared` (all lib-only) and carries `#[uniffi::export]`s, while THIS file is `#[path]`-mounted
// into standalone host bins/tests that lack those modules — so keeping `mod github;` out of this path-mounted
// file is what keeps `blocklist_vectors` + `tests/*` green under `--features mirror`. (`trust` stays here: it
// has no lib-only deps, so it path-mounts cleanly.)

/// Real DNS bounds — also cap trie DEPTH so the recursive trie Drop / walks cannot overflow the stack.
const MAX_NAME_LEN: usize = 253;
const MAX_LABELS: usize = 127;
/// A single over-long line (e.g. a no-newline blob) is skipped, never allocated whole.
const MAX_LINE_BYTES: usize = 8192;
/// Streaming chunk size for the bounded reader.
const CHUNK: usize = 8192;

// ---- P8 Wave A1: pre-compiled artifact codec ----
//
// A blocklist can be shipped as a SIGNED, pre-canonicalized binary artifact instead of raw text — the
// device skips line-parsing and gets a structurally self-checked set. The codec is ADDITIVE: it only
// READS the matcher (via `walk_terminals`) on the encode side and REPLAYS each domain through the
// EXISTING `insert` + `finalize` on the decode side, so it shares the legacy text path's exact
// canonicalization and fingerprint — zero behavior change to that path.
//
// Header (20 bytes, all little-endian, fixed width):
//   off 0  : magic   b"TBLK"        (4 bytes)
//   off 4  : u16     format_version (= ARTIFACT_VERSION)
//   off 6  : u8      hash_algo_id   (= HASH_ALGO_FNV1A_64; 1/2 reserved for SHA-256/BLAKE3)
//   off 7  : u8      flags          (reserved, must be 0)
//   off 8  : u64     embedded_fingerprint (the SAME value `finalize()` emits)
//   off 16 : u32     domain_count
// Body (starts at off 20): `domain_count` records, each `u16 byte_len` (LE) + that many UTF-8 bytes.
// Bodies are the canonical terminal set as a FLAT SORTED list (sort is for stable on-disk diff/
// signature input only; the XOR-fold fingerprint is order-independent, so sort never moves it).
const ARTIFACT_MAGIC: [u8; 4] = *b"TBLK";
const ARTIFACT_VERSION: u16 = 1;
const HASH_ALGO_FNV1A_64: u8 = 0;
const ARTIFACT_HEADER_LEN: usize = 20;

/// One trie node, keyed by DNS label (e.g. "com", "google").
#[derive(Default)]
struct Node {
    children: HashMap<Box<str>, Node>,
    /// A domain terminates here — blocks this domain AND everything beneath it.
    terminal: bool,
    /// P8 Wave A2 — provenance bitset (which sources armed this terminal). ADDITIVE: `#[derive(Default)]`
    /// defaults it to `0`, so every node the legacy/source-less path builds is behaviorally identical to
    /// pre-A2. It is WRITTEN only by [`insert_with_source`](Matcher::insert_with_source) and READ only by
    /// the source-aware walk/accessors — NEVER by `is_blocked`, `walk_terminals` or `finalize`, so
    /// verdicts and the fingerprint are untouched. Provenance rides ALONGSIDE the set, never in the hash.
    sources: SourceMask,
}

impl Node {
    /// Visit every canonical blocked domain (each terminal node, top-down; terminals are leaves so
    /// subsumed descendants never appear). `suffix` is the domain built so far (deeper label first).
    /// Depth is bounded by [`MAX_LABELS`], so this recursion cannot overflow the stack.
    fn walk_terminals(&self, suffix: &str, f: &mut impl FnMut(&str)) {
        if self.terminal {
            f(suffix);
            return;
        }
        for (label, child) in &self.children {
            let next = if suffix.is_empty() {
                label.to_string()
            } else {
                format!("{}.{}", label, suffix)
            };
            child.walk_terminals(&next, f);
        }
    }

    /// P8 Wave A2 — like [`walk_terminals`](Node::walk_terminals) but ALSO yields each terminal's
    /// provenance [`SourceMask`]. This is the SEPARATE source-aware read path: the fingerprint walk
    /// ([`walk_terminals`]) stays the pure SET oracle and never sees `sources`. It lets a consumer
    /// enumerate the blocked set together with its provenance without ever touching the hash.
    fn walk_terminals_with_sources(&self, suffix: &str, f: &mut impl FnMut(&str, SourceMask)) {
        if self.terminal {
            f(suffix, self.sources);
            return;
        }
        for (label, child) in &self.children {
            let next = if suffix.is_empty() {
                label.to_string()
            } else {
                format!("{}.{}", label, suffix)
            };
            child.walk_terminals_with_sources(&next, f);
        }
    }
}

/// A compiled blocklist: the trie plus its set-derived stats.
#[derive(Default)]
pub struct Matcher {
    root: Node,
    count: usize,
    fingerprint: u64,
}

impl Matcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// Insert a domain. Idempotent; if a parent zone is already blocked this is a no-op (the parent
    /// covers it), and setting a node terminal prunes any now-subsumed descendants so the trie stays
    /// canonical. Stats are NOT updated here — call [`finalize`](Self::finalize) once after a batch.
    pub fn insert(&mut self, domain: &str) {
        let domain = normalize(domain);
        if domain.is_empty() {
            return;
        }
        let mut node = &mut self.root;
        // Walk labels TLD-first (rsplit) so a suffix/parent domain is a PREFIX of the path.
        for label in domain.rsplit('.') {
            node = node.children.entry(label.into()).or_default();
            if node.terminal {
                return; // an ancestor already blocks this — redundant
            }
        }
        if !node.terminal {
            node.terminal = true;
            node.children.clear(); // prune subsumed descendants — keeps the set canonical
        }
    }

    /// P8 Wave A2 — provenance-tagging sibling of [`insert`](Self::insert). Performs the IDENTICAL
    /// `rsplit('.')` trie walk and the same canonicalization/pruning, but additionally ORs `mask` into
    /// the winning terminal's [`Node::sources`] so we record WHICH source armed this domain. A domain
    /// armed by two sources accumulates BOTH bits (the OR is cumulative across calls).
    ///
    /// On the ancestor-already-terminal early return (a parent zone already blocks this), the new source
    /// still corroborates the parent, so the bit is ORed into the COVERING ancestor terminal — the only
    /// node that survives in the canonical set. `mask == 0` reproduces [`insert`] byte-for-byte (it sets
    /// no bit), which is exactly the legacy/anonymous path.
    ///
    /// Like [`insert`], stats are NOT updated here — call [`finalize`](Self::finalize) after a batch.
    /// `sources` is never read by `finalize`/`is_blocked`/`walk_terminals`, so the fingerprint and
    /// verdicts are untouched regardless of `mask`.
    pub fn insert_with_source(&mut self, domain: &str, mask: SourceMask) {
        let domain = normalize(domain);
        if domain.is_empty() {
            return;
        }
        let mut node = &mut self.root;
        // Walk labels TLD-first (rsplit) so a suffix/parent domain is a PREFIX of the path.
        for label in domain.rsplit('.') {
            node = node.children.entry(label.into()).or_default();
            if node.terminal {
                node.sources |= mask; // an ancestor already blocks this — corroborate the covering terminal
                return;
            }
        }
        if !node.terminal {
            node.terminal = true;
            node.children.clear(); // prune subsumed descendants — keeps the set canonical
        }
        node.sources |= mask;
    }

    /// Recompute [`count`] + [`fingerprint`] from the canonical blocked set. Order- and
    /// format-independent: two lists describing the same blocking set produce the same digest.
    pub fn finalize(&mut self) {
        let mut count = 0usize;
        let mut fingerprint = 0u64;
        self.root.walk_terminals("", &mut |domain| {
            count += 1;
            fingerprint ^= fnv1a(domain);
        });
        self.count = count;
        self.fingerprint = fingerprint;
    }

    /// True if `domain` or any parent domain is blocked.
    ///
    /// D21 — ZERO-ALLOC on the hot path (step 1 of every `resolve_inner`). The old `normalize(domain)`
    /// minted three heap allocations per query (`to_lowercase` plus `split.collect` plus `join`) to
    /// produce a byte-identical copy, yet `parse_question` already lowercases the qname. The trie walk
    /// now consumes BORROWED labels via [`walk_labels`] (rsplit, empty labels dropped, per-label
    /// lowercase only when needed), which is semantically identical to walking `normalize(domain)`
    /// because the stored keys are already `normalize_rule`'d. The insert/authoring path keeps
    /// [`normalize`] (cold) so keys stay normalized while lookup only borrows.
    pub fn is_blocked(&self, domain: &str) -> bool {
        let mut node = &self.root;
        let mut walked = false;
        for label in walk_labels(domain) {
            walked = true;
            match node.children.get(label.as_ref()) {
                Some(child) => {
                    if child.terminal {
                        return true; // a parent domain is blocked → so is this
                    }
                    node = child;
                }
                None => return false,
            }
        }
        // No labels at all (empty/dots-only input) was a hard `false` before — preserve it exactly.
        walked && node.terminal
    }

    /// P8 Wave A2 — the provenance [`SourceMask`] for the terminal that blocks `domain` (the covering
    /// parent if `domain` is subsumed), or `0` if `domain` is not blocked or carries no source tags.
    /// READ-ONLY and SEPARATE from `is_blocked`'s verdict path: it walks the SAME trie but returns the
    /// `sources` bitset of the FIRST terminal on the path. Never consulted by `finalize`/`is_blocked`.
    pub fn source_mask(&self, domain: &str) -> SourceMask {
        // D21 — the same zero-alloc borrowed-label walk as `is_blocked` (one lookup discipline).
        let mut node = &self.root;
        let mut walked = false;
        for label in walk_labels(domain) {
            walked = true;
            match node.children.get(label.as_ref()) {
                Some(child) => {
                    if child.terminal {
                        return child.sources; // covering parent terminal
                    }
                    node = child;
                }
                None => return 0,
            }
        }
        if walked {
            node.sources
        } else {
            0
        }
    }

    /// Serialize the canonical blocked SET into a self-describing binary artifact (see the header
    /// layout above). READ-ONLY over the matcher — collects each terminal domain via
    /// [`walk_terminals`](Node::walk_terminals), sorts for a stable on-disk/signature order, and
    /// length-prefixes each as UTF-8. The embedded fingerprint is exactly [`self.fingerprint`], so a
    /// round-trip can self-check. Does NOT mutate the matcher or touch the legacy text path.
    ///
    /// The on-device `.so` only ever DECODES artifacts (`from_artifact`); encoding is the producer /
    /// offline side (and the round-trip tests), so this is dead in the non-test cdylib build — the
    /// attr keeps it warning-free without dropping it from the codec's public API.
    pub fn to_artifact(&self) -> Vec<u8> {
        let mut domains: Vec<String> = Vec::with_capacity(self.count);
        self.root
            .walk_terminals("", &mut |d| domains.push(d.to_string()));
        // Stable emission order for diff/signature inputs. (XOR-fold fingerprint is order-free.)
        domains.sort();

        let mut out = Vec::with_capacity(ARTIFACT_HEADER_LEN + domains.len() * 24);
        out.extend_from_slice(&ARTIFACT_MAGIC);
        out.extend_from_slice(&ARTIFACT_VERSION.to_le_bytes());
        out.push(HASH_ALGO_FNV1A_64);
        out.push(0u8); // flags / reserved
        out.extend_from_slice(&self.fingerprint.to_le_bytes());
        out.extend_from_slice(&(domains.len() as u32).to_le_bytes());
        for d in &domains {
            let bytes = d.as_bytes();
            // Every emitted domain is a canonical terminal (already <= MAX_NAME_LEN); the cast is safe.
            out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        out
    }

    /// Parse + verify a binary artifact into a finalized [`Matcher`]. Validates magic, version and
    /// hash-algo, then REPLAYS each domain through the EXISTING [`insert`](Self::insert) (re-normalize
    /// + re-prune) and [`finalize`](Self::finalize) — so the rebuilt matcher is byte-identical to the
    ///   legacy text path for the same set. Returns `None` on bad magic / wrong version / wrong algo /
    ///   nonzero flags / truncation / count overflow, OR if the recomputed fingerprint does not match the
    ///   embedded one (a structural self-check that the bytes describe the set they claim to).
    pub fn from_artifact(bytes: &[u8]) -> Option<Matcher> {
        if bytes.len() < ARTIFACT_HEADER_LEN {
            return None;
        }
        if bytes[0..4] != ARTIFACT_MAGIC {
            return None;
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != ARTIFACT_VERSION {
            return None;
        }
        if bytes[6] != HASH_ALGO_FNV1A_64 {
            return None; // only FNV-1a-64 is defined for v1
        }
        if bytes[7] != 0 {
            return None; // reserved flags must be zero
        }
        let embedded_fp = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let domain_count =
            u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;

        let mut matcher = Matcher::new();
        let mut pos = ARTIFACT_HEADER_LEN;
        for _ in 0..domain_count {
            // Need 2 bytes for the length prefix.
            if pos + 2 > bytes.len() {
                return None; // truncated length prefix
            }
            let len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
            pos += 2;
            if len > MAX_NAME_LEN {
                return None; // a record claims an over-long name → reject the whole artifact
            }
            if pos + len > bytes.len() {
                return None; // truncated body
            }
            let domain = match std::str::from_utf8(&bytes[pos..pos + len]) {
                Ok(s) => s,
                Err(_) => return None, // not valid UTF-8 → reject
            };
            pos += len;
            matcher.insert(domain);
        }
        matcher.finalize();

        // Structural self-check: the rebuilt set's fingerprint MUST equal the one the artifact carries.
        // A mismatch means the body was tampered with, truncated mid-set, or the producer disagrees on
        // canonicalization — reject rather than arm a list we cannot vouch for.
        if matcher.fingerprint != embedded_fp {
            return None;
        }
        Some(matcher)
    }
}

/// Canonicalize: trim, drop a trailing dot AND any empty labels, then full-Unicode lowercase (DNS is
/// case-insensitive; `to_lowercase` folds É→é, Cyrillic, etc. — `to_ascii_lowercase` would not).
/// COLD path only (insert/authoring) — the query hot path walks [`walk_labels`] borrowed (D21).
fn normalize(domain: &str) -> String {
    let lowered = domain.trim().trim_end_matches('.').to_lowercase();
    lowered
        .split('.')
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

/// D21 — the ZERO-ALLOC lookup twin of [`normalize`]: yield the domain's labels in **rsplit (trie
/// walk) order**, trailing dots trimmed, empty labels dropped, each label lowercased ONLY when it
/// actually carries an uppercase/non-ASCII byte (the common already-lowercase qname borrows — zero
/// heap). Per-label full-Unicode `to_lowercase` equals whole-string folding because case folding
/// never produces or consumes a `.`; so walking these labels is semantically identical to walking
/// `normalize(domain).rsplit('.')` — against keys the insert side stored via [`normalize`]. The
/// Warden's `DomainTrie::matches` carries the same twin rework (`warden/mod.rs`, D21's other half).
fn walk_labels(domain: &str) -> impl Iterator<Item = std::borrow::Cow<'_, str>> {
    domain
        .trim()
        .trim_end_matches('.')
        .rsplit('.')
        .filter(|l| !l.is_empty())
        .map(|l| {
            if l.bytes().all(|b| b.is_ascii() && !b.is_ascii_uppercase()) {
                std::borrow::Cow::Borrowed(l)
            } else {
                std::borrow::Cow::Owned(l.to_lowercase())
            }
        })
}

/// FNV-1a 64-bit — a fast, non-cryptographic content digest (P9 swaps in SHA-256/BLAKE3).
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Extract a domain from one line of a host-file / plain / adblock-style blocklist, or `None` for
/// comments, blanks, bare IPs, over-long names and unrepresentable wildcards.
fn parse_line(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return None;
    }
    // host format: "<ip> domain" → take the domain (any leading token that parses as an IP is a sink)
    let token = match line.split_once(char::is_whitespace) {
        Some((first, rest)) if is_host_sink(first) => rest.trim(),
        _ => line,
    };
    // adblock-ish wrappers: ||domain^
    let token = token.trim_start_matches("||").trim_end_matches('^');
    // first whitespace token, then drop any inline comment
    let token = token.split_whitespace().next().unwrap_or("");
    let token = token.split('#').next().unwrap_or("").trim();
    // adblock wildcard: "*.ads.com" means the whole ads.com zone — which the trie already subsumes.
    let token = token.strip_prefix("*.").unwrap_or(token);
    // the trie cannot represent mid-label / mid-zone wildcards (ad*.com, a.*.com)
    if token.contains('*') {
        return None;
    }
    if token.is_empty() || !token.contains('.') || token.contains('/') {
        return None;
    }
    // DNS bounds — also caps trie depth so recursive drop/walk can't overflow the stack
    if token.len() > MAX_NAME_LEN || token.split('.').count() > MAX_LABELS {
        return None;
    }
    // reject a bare IPv4 (all labels are digits)
    if token
        .split('.')
        .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some(token)
}

/// True if `addr` parses as any IP (v4 or v6) — i.e. a hosts-file sink address.
fn is_host_sink(addr: &str) -> bool {
    addr.parse::<std::net::IpAddr>().is_ok()
}

/// Compile any byte source into a finalized [`Matcher`] with a BOUNDED, streaming reader: lines
/// longer than [`MAX_LINE_BYTES`] are skipped (never allocated whole), so a hostile no-newline blob
/// cannot OOM the device.
fn compile_reader<R: Read>(reader: R) -> Matcher {
    let mut reader = BufReader::new(reader);
    let mut matcher = Matcher::new();
    let mut line: Vec<u8> = Vec::with_capacity(256);
    let mut skipping = false; // current line exceeded the cap → skip to next newline
    let mut chunk = [0u8; CHUNK];

    loop {
        let n = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        for &b in &chunk[..n] {
            if b == b'\n' {
                if !skipping {
                    feed_line(&line, &mut matcher);
                }
                line.clear();
                skipping = false;
            } else if !skipping {
                if line.len() < MAX_LINE_BYTES {
                    line.push(b);
                } else {
                    skipping = true; // too long — stop accumulating until the next newline
                    line.clear();
                }
            }
        }
    }
    if !skipping && !line.is_empty() {
        feed_line(&line, &mut matcher); // final line without a trailing newline
    }
    matcher.finalize();
    matcher
}

fn feed_line(bytes: &[u8], matcher: &mut Matcher) {
    if let Ok(s) = std::str::from_utf8(bytes) {
        if let Some(domain) = parse_line(s) {
            matcher.insert(domain);
        }
    }
}

/// Stream-compile a local blocklist FILE (manual .txt selection) into a finalized [`Matcher`].
pub fn compile_file(path: &str) -> std::io::Result<Matcher> {
    Ok(compile_reader(File::open(path)?))
}

/// Compile an in-memory blocklist (injected text, a fetched URL's bytes) into a finalized [`Matcher`].
pub fn compile_text(text: &str) -> Matcher {
    compile_reader(text.as_bytes())
}

/// Preview a blocklist text WITHOUT installing it (K4 dedup — the Kotlin BlocklistSearcher
/// re-implemented this; now there is ONE parser, the Rust parse_line). Returns (domain_count, sample).
/// Reuses the same parse_line + MAX_LINE_BYTES cap as compile_text — byte-identical parsing.
pub fn preview_text(text: &str) -> (usize, Vec<String>) {
    let mut count = 0usize;
    let mut sample: Vec<String> = Vec::with_capacity(5);
    for raw in text.lines() {
        if raw.len() > MAX_LINE_BYTES {
            continue;
        }
        if let Some(domain) = parse_line(raw) {
            count += 1;
            if sample.len() < 5 {
                sample.push(domain.to_string());
            }
        }
    }
    (count, sample)
}

// ---- Global installed matcher (queried by the JNI surface) ----

static GLOBAL: RwLock<Option<Matcher>> = RwLock::new(None);

/// P8 Wave A2 — process-shared provenance registry mapping `source_id` → a stable mask bit (and trust/
/// label metadata). Lives ALONGSIDE the matcher: the trie only holds the compact `SourceMask` bitset.
/// Lazily initialized (bit 0 pre-bound to the anonymous source). Never read by the fingerprint path.
static REGISTRY: RwLock<Option<trust::SourceRegistry>> = RwLock::new(None);

// REMOVED: the `RegistryExt` mixin (a write-guard trait whose sole method lazily created the
// registry then delegated to `SourceRegistry::bit_for`). It had exactly one call site, in
// `install_with_source`, and that site now needs TWO registry operations in one critical section —
// `bit_for` AND the B1 `note_fingerprint` — so it binds `guard.get_or_insert_with(...)` once and
// calls both on the registry directly. The mixin could only ever express the first, so keeping it
// would mean taking the write lock twice for one install. Superseded by its own call site, not
// silenced: the lazy-init behaviour it provided is preserved verbatim at that site.

/// Install `new` as the active matcher, or MERGE its domains into the existing one (stacking lists).
/// Returns the resulting (count, fingerprint). Recovers from a poisoned lock so the JNI boundary lives.
fn install_compiled(new: Matcher, merge: bool) -> (usize, u64) {
    let mut guard = GLOBAL.write().unwrap_or_else(|e| e.into_inner());
    if merge {
        if let Some(existing) = guard.as_mut() {
            new.root.walk_terminals("", &mut |d| existing.insert(d));
            existing.finalize();
            return (existing.count, existing.fingerprint);
        }
    }
    let stats = (new.count, new.fingerprint);
    *guard = Some(new);
    stats
}

/// P8 Wave A2 — provenance-recording sibling of [`install_compiled`]. Behaves identically for the SET
/// (same merge/replace semantics, same returned `(count, fingerprint)` since the fingerprint is the SET
/// oracle), but tags every domain it installs with `source_id`'s bit so the active matcher remembers
/// which source armed each terminal.
///
/// On MERGE it replays `new`'s terminals through the source-tagged [`Matcher::insert_with_source`] via
/// the source-aware walk, so the merged set records `source_id` as a corroborating provenance bit (and
/// preserves any provenance already present on the existing terminals). On REPLACE it re-tags `new`'s
/// own terminals with `source_id` (rebuilding the trie through `insert_with_source`) and stores that.
///
/// `source_id == ANON_SOURCE_ID` (0) maps to bit 0 in the shared registry; the source-LESS legacy path
/// ([`compile_and_install_text`], artifact decode) does NOT route through here and sets NO bit, so its
/// fingerprint is byte-identical to pre-A2. This entry exists for callers that DO want provenance.
///
/// #61B: first LIVE caller is the Underground lane-catalog ingest (`crate::catalogs`, `mirror`-gated —
/// the Centauri half of the Underground''s Warden+Centauri binding). The `allow(dead_code)` stays for
/// the base (non-`mirror`) build, where that caller is compiled out.
pub(crate) fn install_with_source(new: Matcher, source_id: u32, merge: bool) -> (usize, u64) {
    // B1 — the fingerprint of THE LIST THIS SOURCE PRODUCED, captured BEFORE the set is merged or
    // re-tagged. `compile_text`/`compile_file` return a finalized Matcher and `finalize` derives the
    // fingerprint purely from content (`fingerprint ^= fnv1a(domain)` over terminals, blocklist.rs:210),
    // so this value identifies the source's own list on BOTH paths below. Deliberately NOT the merged
    // installed-set fingerprint: on the merge path that set is the union of several lists, and
    // recording it against this one source would claim it produced content it never shipped —
    // which would then collapse UNRELATED sources into one dedup bucket and let `list_trust` return
    // another list's trust for this one.
    let source_fp = new.fingerprint;
    let mask = {
        let mut guard = REGISTRY.write().unwrap_or_else(|e| e.into_inner());
        let reg = guard.get_or_insert_with(trust::SourceRegistry::new);
        let mask = trust::bit_to_mask(reg.bit_for(source_id));
        // Record which list this source produced, so that importing ONE list under two source ids
        // collapses into a single dedup bucket and `trust::list_trust` returns MAX-over-bucket
        // rather than an inflated sum. Idempotent: re-noting the same fp does not duplicate.
        reg.note_fingerprint(source_id, source_fp);
        mask
    };
    let mut guard = GLOBAL.write().unwrap_or_else(|e| e.into_inner());
    if merge {
        if let Some(existing) = guard.as_mut() {
            new.root
                .walk_terminals("", &mut |d| existing.insert_with_source(d, mask));
            existing.finalize();
            return (existing.count, existing.fingerprint);
        }
    }
    // Replace: re-tag `new`'s own terminals with this source by rebuilding through insert_with_source.
    let mut tagged = Matcher::new();
    new.root
        .walk_terminals("", &mut |d| tagged.insert_with_source(d, mask));
    tagged.finalize();
    let stats = (tagged.count, tagged.fingerprint);
    *guard = Some(tagged);
    stats
}

/// #61B — register (or refresh) a source's provenance metadata (label / trust tier / signed bit) in the
/// process-shared [`trust::SourceRegistry`]. The Underground lane-catalog ingest (`crate::catalogs`,
/// `mirror`-gated) records each lane's identity here BEFORE installing its set, so every
/// [`Matcher::source_mask`] bit stays explainable (slug + signed provenance, never a bare bit). The mask
/// bit itself is still bound lazily by [`install_with_source`]'s `bit_for` — this only attaches the
/// human-readable meta. Recovers from a poisoned lock like every other REGISTRY surface here.
/// The day a source was FIRST registered, if it is already known.
///
/// Exists so a re-ingest can PRESERVE first-seen rather than overwrite it. A lane re-downloaded
/// next week is the same source first seen last week; resetting it at every refresh would make
/// every source read as brand new forever, which quietly destroys recency as a trust signal while
/// leaving every panel looking populated and plausible.
///
/// `None` = never registered, or registered with the unknown (`0`) default.
pub fn source_first_seen(source_id: u32) -> Option<u32> {
    let guard = REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .and_then(|r| r.meta(source_id))
        .map(|m| m.first_seen_epoch_days)
        .filter(|d| *d != 0)
}

/// Every registered source's provenance, for the SOURCES panel.
///
/// Returns `(source_id, label, trust, reputation, signed, first_seen_epoch_days,
/// last_seen_epoch_days, domains_in_installed_set)`.
///
/// The domain count is computed by walking the INSTALLED set's terminals and testing each one's
/// provenance mask, so it reports what this source actually contributes to the set in force —
/// not what its catalog claimed at ingest time. A source whose list was wholly superseded by a
/// later install therefore reports 0 here while still appearing in the registry, which is the
/// honest answer to "is this list doing anything for me?".
/// One row of [`source_provenance_table`].
///
/// A tuple cannot name its own fields, which is exactly why the bare
/// `Vec<(u32, String, u8, u8, bool, u32, u32, u32)>` was unreadable at the call site -- three u32s
/// and two u8s in a row, distinguishable only by counting commas. The alias does not fix that by
/// itself; the position list below is the part that does.
///
/// 0. `id`          — the source's registry id.
/// 1. `name`        — its display name.
/// 2. `kind`        — source kind discriminant.
/// 3. `format`      — parsed list format discriminant.
/// 4. `enabled`     — whether it is currently switched on.
/// 5. `rules`       — rules this source contributed to the set IN FORCE, after provenance masking.
/// 6. `superseded`  — rules it contributed that a later install overrode.
/// 7. `total`       — rules its catalog claimed at ingest time.
///
/// Kept as a tuple rather than promoted to a struct on purpose: this crosses the UniFFI boundary
/// and changing the shape is an ABI change for every caller. The alias is transparent, so it
/// carries the documentation at zero risk -- which a struct would not.
pub type SourceProvenanceRow = (u32, String, u8, u8, bool, u32, u32, u32);
pub fn source_provenance_table() -> Vec<SourceProvenanceRow> {
    let guard = REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    let Some(reg) = guard.as_ref() else {
        return Vec::new();
    };

    // Tally per-bit contributions in ONE walk of the installed set rather than one walk per
    // source: the set can hold hundreds of thousands of terminals and there may be 32 sources.
    let mut per_bit = [0u32; trust::MAX_SOURCE_BITS as usize];
    {
        let g = GLOBAL.read().unwrap_or_else(|e| e.into_inner());
        if let Some(m) = g.as_ref() {
            m.root
                .walk_terminals_with_sources("", &mut |_domain, mask| {
                    for (bit, slot) in per_bit.iter_mut().enumerate() {
                        if mask & (1u32 << bit) != 0 {
                            *slot = slot.saturating_add(1);
                        }
                    }
                });
        }
    }

    reg.metas()
        .map(|m| {
            let domains = reg
                .assigned_bit(m.id)
                .map(|b| per_bit[b as usize])
                .unwrap_or_default();
            (
                m.id,
                m.label.to_string(),
                m.trust,
                m.reputation,
                m.signed,
                m.first_seen_epoch_days,
                m.last_seen_epoch_days,
                domains,
            )
        })
        .collect()
}

/// Resolve every source's REPUTATION from the Underground's locally-grown evidence.
///
/// Reputation is NOT a curator's opinion and NOT an operator constant — it is resolved by the
/// Underground, the licence-based store that grows on the box's OWN observations
/// (`underground.rs:7`). A source earns reputation here by the share of the domains it contributes
/// to the installed set that the Underground independently judges bad
/// ([`crate::underground::corroborates_bad`]): a list whose entries this box has actually seen
/// misbehave is worth more than one whose entries it has never encountered.
///
/// Nothing is asked of a cloud — the whole computation is local, which is the Underground's law.
///
/// HONEST ZERO, and it is the load-bearing case. When the store knows NO hosts yet (a fresh box),
/// this returns `0` and writes NOTHING: every source would otherwise score 0% corroboration and the
/// panel would report that every list is worthless, when the truth is that the box has not learned
/// anything yet. "No evidence" and "evidence of no value" must never render the same.
///
/// Returns how many sources had their reputation resolved.
pub fn resolve_source_reputations() -> usize {
    if crate::underground::reputation_rows() == 0 {
        return 0;
    }

    // Per-bit tallies in ONE walk: how many of this source's domains the Underground corroborates.
    let mut contributed = [0u32; trust::MAX_SOURCE_BITS as usize];
    let mut corroborated = [0u32; trust::MAX_SOURCE_BITS as usize];
    {
        let g = GLOBAL.read().unwrap_or_else(|e| e.into_inner());
        if let Some(m) = g.as_ref() {
            m.root.walk_terminals_with_sources("", &mut |domain, mask| {
                let bad = crate::underground::corroborates_bad(domain);
                for bit in 0..trust::MAX_SOURCE_BITS as usize {
                    if mask & (1u32 << bit) != 0 {
                        contributed[bit] = contributed[bit].saturating_add(1);
                        if bad {
                            corroborated[bit] = corroborated[bit].saturating_add(1);
                        }
                    }
                }
            });
        }
    }

    let mut guard = REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    let Some(reg) = guard.as_mut() else {
        return 0;
    };

    let ids: Vec<u32> = reg.metas().map(|m| m.id).collect();
    let mut resolved = 0usize;
    for id in ids {
        let Some(bit) = reg.assigned_bit(id) else {
            continue;
        };
        let total = contributed[bit as usize];
        if total == 0 {
            // Contributes nothing to the set in force — leave its reputation untouched rather than
            // zeroing a value earned when it WAS installed.
            continue;
        }
        let share = (u64::from(corroborated[bit as usize]) * 100 / u64::from(total)) as u8;
        let Some(existing) = reg.meta(id).cloned() else {
            continue;
        };
        reg.register(existing.with_reputation(share));
        resolved += 1;
    }
    resolved
}

pub(crate) fn register_source_meta(meta: trust::SourceMeta) {
    let mut reg = REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    reg.get_or_insert_with(trust::SourceRegistry::new)
        .register(meta);
}

pub fn compile_and_install_file(path: &str, merge: bool) -> std::io::Result<(usize, u64)> {
    let matcher = compile_file(path)?;
    Ok(install_compiled(matcher, merge))
}

pub fn compile_and_install_text(text: &str, merge: bool) -> (usize, u64) {
    install_compiled(compile_text(text), merge)
}

/// P8 Wave A1: install a pre-compiled, self-checked binary artifact (a signed/shipped list) instead of
/// raw text. Verifies the artifact ([`Matcher::from_artifact`]) BEFORE arming — a bad/tampered/
/// truncated/fp-mismatched artifact yields `None` and the GLOBAL matcher is left untouched. On success
/// it routes through the SAME poison-recovering [`install_compiled`] as the text path, so the swap is
/// atomic and the resolver (`resolver::resolve_inner` block-check) + observe path never see a
/// half-installed matcher. `merge` stacks the artifact's set onto the current list, identical to text.
pub fn compile_and_install_artifact(bytes: &[u8], merge: bool) -> Option<(usize, u64)> {
    let matcher = Matcher::from_artifact(bytes)?;
    Some(install_compiled(matcher, merge))
}

pub fn query(domain: &str) -> bool {
    let guard = GLOBAL.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().is_some_and(|m| m.is_blocked(domain))
}

// ---- P12 R2: configurable block action (cloaking) ----
//
// Today the resolver's step-1 block path (resolver/mod.rs:310-313) hard-wires `build_nxdomain_response`
// for every blocked name. P12 dnsmasq parity wants the block to be able to CHOOSE its reply: deny it
// (NXDOMAIN, the default + today's behaviour), sink it to the all-zeros address (dnsmasq's `0.0.0.0` /
// `::` cloak), or pin it to a custom IP (`address=/blocked/<ip>`-style redirect). This module owns the
// ACTION ENUM + the process-shared SELECTOR; the actual answer SYNTHESIS lives in `crate::dns` (R1
// `build_sinkhole_response` / `build_address_response`) and is dispatched at the resolver seam (R2 wire).
// Defining the choice HERE keeps the verdict and its action co-located with the matcher that fires it,
// and lets the step-1 path become a `match` over `query_action(...)` instead of a bare `if query(...)`.
//
// ADDITIVE: `query`/`is_blocked`/`finalize`/the fingerprint are untouched — the SET oracle is unchanged.
// The selector is a STANDALONE `AtomicU8` (the `REBIND_ENFORCE` template, resolver/mod.rs:147/151), so it
// is flipped INDEPENDENTLY of `configure`/list installs — P10 rotation re-arming a blocklist never resets
// the user's cloak choice. Default = `NXDOMAIN` ⇒ byte-identical to today until the Expert toggle drives it.

use std::net::IpAddr;

/// What a step-1 block does to the query, once a name is found on the list.
///
/// - [`BlockAction::NxDomain`] — synthesize an authoritative NXDOMAIN (today's behaviour, the default).
/// - [`BlockAction::ZeroSink`] — answer with the all-zeros address (`0.0.0.0` for A, `::` for AAAA), the
///   classic dnsmasq sinkhole: the name "resolves" but to an address that goes nowhere.
/// - [`BlockAction::CustomIp`] — answer with a caller-pinned IP (a redirect / walled-garden landing page).
///
/// `Copy` + small (≤ 17 bytes incl. an `IpAddr`) so the resolver can read it out of the selector and
/// dispatch without allocation. The synthesis for each variant is performed by the resolver via R1's
/// `crate::dns` primitives; this enum only NAMES the choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BlockAction {
    /// Deny the name — authoritative NXDOMAIN. The default; identical to pre-P12 behaviour.
    #[default]
    NxDomain,
    /// Sink the name to the all-zeros address (`0.0.0.0` / `::`). dnsmasq's classic null-route cloak.
    ZeroSink,
    /// Redirect the name to a custom pinned IP (`address=/name/<ip>` redirect).
    CustomIp(IpAddr),
}

// Discriminant codes for the standalone `AtomicU8` selector (the `REBIND_ENFORCE` AtomicBool template,
// widened to a u8 because there are three states + a pinned-IP payload). The IP payload for `CustomIp`
// is held alongside in its own lock — an `AtomicU8` cannot carry 16 bytes — so the selector stays a
// single lock-free read for the hot NXDOMAIN/ZeroSink path and only the rare CustomIp branch takes the
// (read) lock to fetch the pinned address.
const ACTION_NXDOMAIN: u8 = 0;
const ACTION_ZEROSINK: u8 = 1;
const ACTION_CUSTOMIP: u8 = 2;

/// The process-shared block-action selector. Defaults to `ACTION_NXDOMAIN` (0) ⇒ today's behaviour.
/// Flipped by [`set_block_action`] independently of any list install, so rotation never resets it.
static BLOCK_ACTION: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(ACTION_NXDOMAIN);

/// The pinned IP for [`BlockAction::CustomIp`]. Read only when the selector is `ACTION_CUSTOMIP`; a
/// `None` here with a `CustomIp` selector is treated as a fall-back to NXDOMAIN by [`block_action`]
/// (a redirect was selected but no address was ever pinned — deny rather than sink to nowhere-useful).
static BLOCK_ACTION_IP: RwLock<Option<IpAddr>> = RwLock::new(None);

/// Set the active block action. `CustomIp` also pins the address; the other variants clear the pin so a
/// later `CustomIp` cannot accidentally inherit a stale IP. Recovers from a poisoned lock (the
/// `install_compiled`/`query` idiom) so a panic in one holder cannot wedge the action selector.
///
/// ADDITIVE + dead-code-until-wired: the Kotlin/JNI Expert toggle (P12 D5 `dashboard_dnsmasq_cloak`)
/// will call this; until that seam lands the selector stays at its `NxDomain` default and the `.so`
/// is byte-identical to pre-P12.
pub fn set_block_action(action: BlockAction) {
    use std::sync::atomic::Ordering;
    match action {
        BlockAction::NxDomain => {
            *BLOCK_ACTION_IP.write().unwrap_or_else(|e| e.into_inner()) = None;
            BLOCK_ACTION.store(ACTION_NXDOMAIN, Ordering::Relaxed);
        }
        BlockAction::ZeroSink => {
            *BLOCK_ACTION_IP.write().unwrap_or_else(|e| e.into_inner()) = None;
            BLOCK_ACTION.store(ACTION_ZEROSINK, Ordering::Relaxed);
        }
        BlockAction::CustomIp(ip) => {
            // Pin the address BEFORE flipping the selector so a concurrent reader that observes
            // `ACTION_CUSTOMIP` always sees the IP already in place (store-release ordering on the u8).
            *BLOCK_ACTION_IP.write().unwrap_or_else(|e| e.into_inner()) = Some(ip);
            BLOCK_ACTION.store(ACTION_CUSTOMIP, Ordering::Release);
        }
    }
}

/// Read the active block action. Lock-free for the common `NxDomain`/`ZeroSink` path; only `CustomIp`
/// takes the `BLOCK_ACTION_IP` read-lock to fetch the pinned address. A `CustomIp` selector with no
/// pinned IP degrades to `NxDomain` (deny, never a half-configured redirect).
pub fn block_action() -> BlockAction {
    use std::sync::atomic::Ordering;
    match BLOCK_ACTION.load(Ordering::Acquire) {
        ACTION_ZEROSINK => BlockAction::ZeroSink,
        ACTION_CUSTOMIP => {
            let ip = *BLOCK_ACTION_IP.read().unwrap_or_else(|e| e.into_inner());
            match ip {
                Some(ip) => BlockAction::CustomIp(ip),
                None => BlockAction::NxDomain, // redirect selected but never pinned → deny
            }
        }
        // ACTION_NXDOMAIN and any unexpected value both mean "deny" — the safe default.
        _ => BlockAction::NxDomain,
    }
}

/// Combined verdict + action for the resolver step-1 seam: returns `Some(action)` when `domain` is on
/// the list (so the caller dispatches the synthesis), or `None` when it is not blocked (control falls
/// through to never-forward / routing / cache / egress as today). This lets `resolve_inner` (R2 wire)
/// replace the bare `if blocklist::query(...)` with `match blocklist::query_action(...)` — the block
/// decision and its action stay co-located, ONE matcher lookup, no double-query.
///
/// Dead-code-until-wired: the resolver still calls the bool `query` at mod.rs:310 today; the R2 wire in
/// resolver/mod.rs switches it to this. Until then the `.so` is byte-identical.
pub fn query_action(domain: &str) -> Option<BlockAction> {
    if query(domain) {
        Some(block_action())
    } else {
        None
    }
}

/// W4: run `f` with a SCOPED borrow of the live installed [`Matcher`] (or `None` when no blocklist is
/// armed), under the `GLOBAL` read-lock. The closure runs WHILE the read-guard is held, so the borrow
/// can never outlive the lock — `GLOBAL` stays PRIVATE (no `&Matcher` ever escapes). Recovers from a
/// poisoned lock (the `install_compiled`/`query` idiom, blocklist.rs:499) so a panic in one holder cannot
/// wedge the firewall verdict path.
///
/// The scoped live-matcher accessor. REWORKED (slice 1): the Warden `torta_firewall_verdict` is now the
/// PURE-FIREWALL cascade (no blocklist param), so this accessor is no longer on the verdict hot path — the
/// resolver path NXDOMAINs blocklisted domains on its OWN gate. The accessor is retained for the resolver's
/// scoped borrows + the host tests (and banked for a future qname-bearing seam that wants the live list).
/// Do NOT rebuild a `Matcher` per packet — borrow the installed one through here.
pub fn with_global<R>(f: impl FnOnce(Option<&Matcher>) -> R) -> R {
    let guard = GLOBAL.read().unwrap_or_else(|e| e.into_inner());
    f(guard.as_ref())
}

/// The provenance + trust readout for ONE domain — the Blocklist panel's "which lists blocked this,
/// and how much do we trust them?" surface.
///
/// Composes the two process-shared stores that were never read together before: the live `Matcher`
/// (via [`with_global`], for the domain's [`Matcher::source_mask`]) and the [`trust::SourceRegistry`]
/// (for per-source [`trust::trust_score`] over that mask).
///
/// Returns `(mask, corroboration, best_trust, signed_backed)`:
///   - `mask` — the raw SourceMask bitset that tagged this domain (0 = untagged / legacy path).
///   - `corroboration` — popcount of the mask: how many DISTINCT sources agree on this domain.
///   - `best_trust` — the highest [`trust::trust_score`] among the sources holding a bit in the mask.
///     MAX, never a sum: two sources agreeing must not multiply into a fake certainty.
///   - `signed_backed` — at least one contributing source is signature-backed. Derived from the score
///     crossing [`trust::SIGNED_FLOOR`], which is sound precisely because the signed and unsigned
///     bands cannot overlap (proved for ALL inputs in D:/Lean/proofs/Proofs/TrustBands.lean --
///     `unsigned_always_below_signed`), so a score in the signed band can ONLY have come from a
///     genuinely signed source and a forged fingerprint can never fake it.
///
/// Read-only: takes read locks on both stores and releases them. Never panics (poison-recovering).
pub fn domain_provenance(domain: &str, now_days: u32) -> (u64, u32, u8, bool) {
    let mask = with_global(|m| m.map_or(0, |m| m.source_mask(domain)));
    if mask == 0 {
        return (0, 0, 0, false);
    }
    let corroboration = trust::SourceRegistry::corroboration(mask);
    let guard = REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    let best = guard.as_ref().map_or(0, |reg| {
        // Only sources whose assigned bit is actually SET in this domain's mask may speak for it.
        reg.source_ids()
            .filter(|&id| reg.mask_has_source(mask, id))
            .map(|id| trust::trust_score(reg, id, mask, now_days))
            .max()
            .unwrap_or(0)
    });
    (mask as u64, corroboration, best, best >= trust::SIGNED_FLOOR)
}

/// The trust of a LIST identified by its content fingerprint, and the source that vouches for it.
///
/// The B1 dedup read: [`trust::list_trust`] returns the MAX trust over every source that produced
/// this identical set, never the sum — so importing one list under two source ids yields the SAME
/// value as importing it once. `fp == 0` (nothing installed / unknown list) reads an honest 0.
///
/// `active_mask` rides on the CURRENT installed corroboration, so a list's trust reflects how many
/// distinct sources presently agree with it, not a figure frozen at import time.
///
/// Returns `(trust, contributing_sources)`.
pub fn list_trust_of(fp: u64, active_mask: trust::SourceMask, now_days: u32) -> (u8, u32) {
    if fp == 0 {
        return (0, 0);
    }
    let guard = REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map_or((0, 0), |reg| {
        let contributors = reg.ids_for_fingerprint(fp).map_or(0, |ids| ids.len() as u32);
        (
            trust::list_trust(reg, fp, active_mask, now_days),
            contributors,
        )
    })
}

/// The union of the mask bits of every source that produced the currently-installed set.
///
/// This is the ACTIVE corroboration for the installed list: the distinct sources presently backing
/// it. Uses [`trust::SourceRegistry::mask_for`] per contributing source and ORs the bits, so two
/// imports of the same list under ONE source id contribute one bit, not two — the property that
/// keeps corroboration honest.
pub fn installed_active_mask() -> trust::SourceMask {
    let fp = installed_fingerprint();
    if fp == 0 {
        return 0;
    }
    let mut guard = REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    let Some(reg) = guard.as_mut() else {
        return 0;
    };
    let ids: Vec<u32> = reg.ids_for_fingerprint(fp).map(<[u32]>::to_vec).unwrap_or_default();
    ids.into_iter().fold(0, |acc, id| acc | reg.mask_for(id))
}

/// The fingerprint a given source last reported, if any — the inverse B1 index
/// ([`trust::SourceRegistry::fingerprint_of`]). Lets a panel answer "which list is this source
/// currently backing?" without re-reading the set.
pub fn source_fingerprint(source_id: u32) -> Option<u64> {
    let guard = REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().and_then(|reg| reg.fingerprint_of(source_id))
}

pub fn installed_count() -> usize {
    let guard = GLOBAL.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map_or(0, |m| m.count())
}

/// Encode the INSTALLED set as a self-describing `.tblk` artifact, or `None` when nothing is
/// installed.
///
/// This is the encoder half of the artifact codec. The device only ever DECODED artifacts, so
/// [`Matcher::to_artifact`] had no caller on this side at all — which meant the codec's two halves
/// were never exercised against each other anywhere the device could observe.
///
/// Two things it buys, and the second is the reason it is worth having:
/// 1. Export: the set in force becomes a portable, fingerprinted artifact.
/// 2. A round-trip SELF-CHECK that runs on the real device, on the real installed set, rather than
///    only on fixtures in a test binary. An encoder that silently disagreed with the decoder — the
///    classic way a format drifts — is invisible to a decode-only device until a real artifact
///    fails to load.
pub fn export_installed_artifact() -> Option<Vec<u8>> {
    let guard = GLOBAL.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map(|m| m.to_artifact())
}

/// Encode the installed set and immediately DECODE it back, reporting whether the round trip
/// preserved the fingerprint and the domain count.
///
/// Returns `(bytes_len, round_trips_clean)`. A `false` here is a codec defect, not a user problem,
/// and it is worth surfacing on device precisely because a decode-only build can never notice it.
pub fn verify_artifact_round_trip() -> Option<(usize, bool)> {
    // ONE read guard across BOTH the encode and the comparison.
    //
    // The first draft called `export_installed_artifact()` and then re-acquired the lock to fetch
    // the original — two non-atomic reads. If the installed set was REPLACED in between, the
    // decoded artifact was compared against a DIFFERENT matcher and the function reported a codec
    // defect that did not exist. Found as an intermittent test failure; the honest fix is to make
    // the read atomic, not to relax the assertion that caught it.
    let guard = GLOBAL.read().unwrap_or_else(|e| e.into_inner());
    let original = guard.as_ref()?;
    let bytes = original.to_artifact();
    let clean = match Matcher::from_artifact(&bytes) {
        Some(decoded) => {
            decoded.fingerprint() == original.fingerprint() && decoded.count() == original.count()
        }
        None => false,
    };
    Some((bytes.len(), clean))
}

/// The installed list's set-deterministic content fingerprint (0 if none) — P8's trust/dedup handle.
pub fn installed_fingerprint() -> u64 {
    let guard = GLOBAL.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map_or(0, |m| m.fingerprint())
}

// Tests that mutate the process-shared `GLOBAL` matcher must NOT run concurrently, or one test's
// `false` (replace) install races another's `installed_count()`/`query()` view. Serialize them
// through this lock (recover from poison so one panicking test does not wedge the others).
// #61B: hoisted to FILE scope + `pub(crate)` so SIBLING suites (`crate::catalogs`, the Underground
// lane catalogs) serialize against the SAME lock — ONE lock for every test that mutates the
// process-shared `GLOBAL`/`REGISTRY`, or the suites race each other across modules.
#[cfg(test)]
pub(crate) static GLOBAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_global() -> std::sync::MutexGuard<'static, ()> {
        GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn compiled(domains: &[&str]) -> Matcher {
        let mut m = Matcher::new();
        for d in domains {
            m.insert(d);
        }
        m.finalize();
        m
    }

    #[test]
    fn blocks_exact_and_subdomains_but_never_overblocks() {
        let m = compiled(&["doubleclick.net"]);
        assert!(m.is_blocked("doubleclick.net"));
        assert!(m.is_blocked("ads.doubleclick.net"));
        assert!(m.is_blocked("a.b.doubleclick.net"));
        assert!(!m.is_blocked("doubleclick.net.evil.com"));
        assert!(!m.is_blocked("notdoubleclick.net"));
        assert!(!m.is_blocked("net"));
        assert!(!m.is_blocked("example.com"));
    }

    #[test]
    fn case_dot_and_unicode_insensitive() {
        let m = compiled(&["Ads.Example.COM.", "CAFÉ.com"]);
        assert!(m.is_blocked("ads.example.com"));
        assert!(m.is_blocked("x.ADS.example.com."));
        assert!(m.is_blocked("café.com")); // Unicode fold É → é
        assert!(m.is_blocked("www.café.com"));
    }

    #[test]
    fn d21_zero_alloc_walk_matches_normalize_exactly() {
        // D21 — the borrowed-label lookup walk must be byte-identical to walking `normalize(domain)`.
        // Cover every branch the old alloc path handled: trailing dots, empty inner labels, mixed case,
        // a high-octet Unicode label (forces the Cow::Owned lowercase branch), and the empty/dots-only
        // inputs (which stay a hard `false`, never a root-terminal hit).
        let m = compiled(&["ads.example.com", "CAFÉ.tld"]);
        for weird in [
            "ads.example.com.",    // trailing dot
            "ADS.Example.COM",     // mixed case (all-ASCII borrow path)
            "ads..example.com",    // empty inner label dropped
            "  ads.example.com  ", // surrounding whitespace trimmed
            ".ads.example.com.",   // leading + trailing dot
        ] {
            assert!(
                m.is_blocked(weird),
                "the zero-alloc walk must match normalize for {weird:?}"
            );
        }
        assert!(
            m.is_blocked("CAFÉ.TLD"),
            "high-octet label folds via the owned branch"
        );
        // Empty / dots-only inputs are a hard miss (no labels walked ⇒ never a root-terminal hit).
        assert!(!m.is_blocked(""));
        assert!(!m.is_blocked("."));
        assert!(!m.is_blocked("..."));
        // Non-member with a shared suffix stays unblocked (no over-block from the borrowed walk).
        assert!(!m.is_blocked("notexample.com"));
    }

    #[test]
    fn wildcard_entries_block_the_zone() {
        assert_eq!(parse_line("*.ads.com"), Some("ads.com"));
        assert_eq!(parse_line("||*.ads.com^"), Some("ads.com"));
        assert_eq!(parse_line("ad*.com"), None); // mid-label wildcard is unrepresentable
        assert_eq!(parse_line("a.*.com"), None);
        // exercise the real compile path (parse_line strips the *. ), not a raw insert
        let m = compile_text("*.ads.com\n");
        assert!(m.is_blocked("ads.com"));
        assert!(m.is_blocked("x.ads.com"));
        assert!(m.is_blocked("deep.sub.ads.com"));
    }

    #[test]
    fn parse_host_adblock_ip_and_junk() {
        assert_eq!(
            parse_line("0.0.0.0 ads.example.com"),
            Some("ads.example.com")
        );
        assert_eq!(parse_line("127.0.0.1 tracker.io # x"), Some("tracker.io"));
        assert_eq!(parse_line("0.0.0.1 realdomain.com"), Some("realdomain.com")); // any-IP sink
        assert_eq!(parse_line("::1 v6sink.com"), Some("v6sink.com"));
        assert_eq!(parse_line("||doubleclick.net^"), Some("doubleclick.net"));
        assert_eq!(parse_line("plain.domain.com"), Some("plain.domain.com"));
        assert_eq!(parse_line("# comment"), None);
        assert_eq!(parse_line("! adblock"), None);
        assert_eq!(parse_line(""), None);
        assert_eq!(parse_line("localhost"), None);
        assert_eq!(parse_line("192.168.1.1"), None); // bare IPv4
    }

    #[test]
    fn rejects_over_deep_names() {
        let deep = format!("{}com", "a.".repeat(200));
        assert_eq!(parse_line(&deep), None); // > 127 labels / > 253 chars
    }

    #[test]
    fn fingerprint_and_count_are_order_and_format_independent() {
        let a = compiled(&[
            "ads.doubleclick.net",
            "doubleclick.net",
            "g.doubleclick.net",
        ]);
        let b = compiled(&[
            "doubleclick.net",
            "g.doubleclick.net",
            "ads.doubleclick.net",
        ]);
        assert_eq!(a.count(), b.count());
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.count(), 1); // the parent subsumes both children

        let c = compiled(&["ads.com"]);
        let d = compiled(&[".ads.com"]); // leading dot, same set
        assert_eq!(c.fingerprint(), d.fingerprint());
        assert_eq!(d.count(), 1);
    }

    #[test]
    fn compile_text_and_bounded_lines() {
        let m = compile_text("0.0.0.0 ads.example.com\n||*.tracker.io^\n# note\nplain.net\n");
        assert!(m.is_blocked("x.ads.example.com"));
        assert!(m.is_blocked("a.tracker.io"));
        assert!(m.is_blocked("plain.net"));
        assert_eq!(m.count(), 3);

        let huge = format!("{}\nreal.com\n", "x".repeat(MAX_LINE_BYTES * 4));
        let m2 = compile_text(&huge);
        assert!(m2.is_blocked("real.com")); // over-long line skipped, parsing survives
    }

    #[test]
    fn merge_stacks_lists() {
        let _g = lock_global();
        let _ = compile_and_install_text("ads.one.com\n", false);
        let (count, _fp) = compile_and_install_text("ads.two.com\n", true);
        assert!(query("x.ads.one.com"));
        assert!(query("y.ads.two.com"));
        assert_eq!(count, 2);
        assert_eq!(installed_count(), 2);
    }

    // ---- P8 Wave A1: artifact codec ----

    #[test]
    fn artifact_roundtrip_preserves_count_fp_and_verdicts() {
        let raw = "0.0.0.0 ads.example.com\n||*.tracker.io^\n# note\nplain.net\ndoubleclick.net\nads.doubleclick.net\n";
        let m = compile_text(raw);
        let art = m.to_artifact();
        let back = Matcher::from_artifact(&art).expect("valid artifact must decode");

        // Count + fingerprint are byte-identical across the round-trip (replay through insert/finalize).
        assert_eq!(m.count(), back.count());
        assert_eq!(m.fingerprint(), back.fingerprint());

        // Identical is_blocked verdicts on a probe set (positive + negative + subsumption).
        let probes = [
            ("x.ads.example.com", true),
            ("a.tracker.io", true),
            ("plain.net", true),
            ("ads.doubleclick.net", true), // subsumed by doubleclick.net
            ("deep.sub.doubleclick.net", true),
            ("doubleclick.net.evil.com", false),
            ("notplain.net", false),
            ("example.com", false),
            ("net", false),
        ];
        for (d, want) in probes {
            assert_eq!(m.is_blocked(d), want, "source verdict for {d}");
            assert_eq!(back.is_blocked(d), want, "decoded verdict for {d}");
        }
    }

    #[test]
    fn artifact_header_layout_is_exact() {
        let m = compile_text("doubleclick.net\nads.example.com\n");
        let art = m.to_artifact();
        assert!(art.len() >= ARTIFACT_HEADER_LEN);
        assert_eq!(&art[0..4], b"TBLK");
        assert_eq!(u16::from_le_bytes([art[4], art[5]]), ARTIFACT_VERSION);
        assert_eq!(art[6], HASH_ALGO_FNV1A_64);
        assert_eq!(art[7], 0); // reserved flags
        let embedded_fp = u64::from_le_bytes([
            art[8], art[9], art[10], art[11], art[12], art[13], art[14], art[15],
        ]);
        assert_eq!(embedded_fp, m.fingerprint());
        let count = u32::from_le_bytes([art[16], art[17], art[18], art[19]]) as usize;
        assert_eq!(count, m.count());
        assert_eq!(count, 2);
        // Bodies are SORTED (stable on-disk order): ads.example.com < doubleclick.net.
        let first_len = u16::from_le_bytes([art[20], art[21]]) as usize;
        let first = std::str::from_utf8(&art[22..22 + first_len]).unwrap();
        assert_eq!(first, "ads.example.com");
    }

    #[test]
    fn empty_set_artifact_roundtrips() {
        let m = compile_text("# only comments\n\n");
        assert_eq!(m.count(), 0);
        let art = m.to_artifact();
        assert_eq!(art.len(), ARTIFACT_HEADER_LEN); // header only, zero records
        let back = Matcher::from_artifact(&art).expect("empty set is a valid artifact");
        assert_eq!(back.count(), 0);
        assert_eq!(back.fingerprint(), 0);
        assert!(!back.is_blocked("anything.com"));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut art = compile_text("ads.com\n").to_artifact();
        art[0] = b'X';
        assert!(Matcher::from_artifact(&art).is_none());
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut art = compile_text("ads.com\n").to_artifact();
        art[4] = 2; // bump the LE u16 low byte → version 2, undefined
        assert!(Matcher::from_artifact(&art).is_none());
    }

    #[test]
    fn wrong_algo_and_nonzero_flags_are_rejected() {
        let mut art = compile_text("ads.com\n").to_artifact();
        art[6] = 1; // SHA-256 reserved, not defined for v1
        assert!(Matcher::from_artifact(&art).is_none());

        let mut art2 = compile_text("ads.com\n").to_artifact();
        art2[7] = 1; // reserved flags must be zero
        assert!(Matcher::from_artifact(&art2).is_none());
    }

    #[test]
    fn truncated_artifacts_are_rejected() {
        let art = compile_text("ads.example.com\ntracker.io\n").to_artifact();
        // Truncated header.
        assert!(Matcher::from_artifact(&art[..ARTIFACT_HEADER_LEN - 1]).is_none());
        // Header present but a length prefix is cut.
        assert!(Matcher::from_artifact(&art[..ARTIFACT_HEADER_LEN + 1]).is_none());
        // A body cut mid-domain.
        assert!(Matcher::from_artifact(&art[..art.len() - 1]).is_none());
        // Truncated to header but count claims records → length-prefix read fails.
        assert!(Matcher::from_artifact(&art[..ARTIFACT_HEADER_LEN]).is_none());
    }

    #[test]
    fn fingerprint_mismatch_is_rejected() {
        let mut art = compile_text("ads.com\ntracker.io\n").to_artifact();
        // Flip a fingerprint byte: the replayed set will recompute a DIFFERENT fp → reject.
        art[8] ^= 0xff;
        assert!(Matcher::from_artifact(&art).is_none());
    }

    #[test]
    fn over_long_record_len_is_rejected() {
        let mut art = compile_text("ads.com\n").to_artifact();
        // First record's u16 length prefix at offset 20 → claim 254 (> MAX_NAME_LEN).
        let bad = (MAX_NAME_LEN as u16 + 1).to_le_bytes();
        art[20] = bad[0];
        art[21] = bad[1];
        assert!(Matcher::from_artifact(&art).is_none());
    }

    #[test]
    fn artifact_installs_into_global_and_query_sees_it() {
        let _g = lock_global();
        // Domains unique to this test so the shared-process GLOBAL count is deterministic.
        let m = compile_text("a8x-artifact-probe.example\nz9q-artifact-probe.example\n");
        let art = m.to_artifact();
        let (count, fp) =
            compile_and_install_artifact(&art, false).expect("valid artifact installs");
        assert_eq!(count, 2);
        assert_eq!(fp, m.fingerprint());
        assert!(query("sub.a8x-artifact-probe.example"));
        assert!(query("z9q-artifact-probe.example"));
        assert!(!query("never-blocked-9j2.example"));
        assert_eq!(installed_count(), 2);
        assert_eq!(installed_fingerprint(), m.fingerprint());
    }

    #[test]
    fn artifact_merges_onto_a_text_list() {
        let _g = lock_global();
        // Fresh install from text, then stack an artifact on top (merge = true).
        let _ = compile_and_install_text("base-merge-7k.example\n", false);
        let extra = compile_text("addon-merge-3p.example\n");
        let art = extra.to_artifact();
        let (count, _fp) =
            compile_and_install_artifact(&art, true).expect("artifact merge installs");
        assert!(query("x.base-merge-7k.example"));
        assert!(query("y.addon-merge-3p.example"));
        assert_eq!(count, 2);
        assert_eq!(installed_count(), 2);
    }

    #[test]
    fn bad_artifact_does_not_arm_and_returns_none() {
        let mut art = compile_text("would-be-armed-q4.example\n").to_artifact();
        art[0] = b'Z'; // corrupt magic
        assert!(compile_and_install_artifact(&art, false).is_none());
    }

    #[test]
    fn adversarial_domains_survive_with_stable_fingerprint() {
        // Subsumed pairs (parent prunes child), Unicode fold (É/Cyrillic), trailing dots, mixed case.
        let raw = "doubleclick.net\nads.doubleclick.net\nCAFÉ.com.\nАproduced.example\n  Trailing.Dot.NET.  \n";
        let m = compile_text(raw);
        let art = m.to_artifact();
        let back = Matcher::from_artifact(&art).expect("adversarial set decodes");
        assert_eq!(m.count(), back.count());
        assert_eq!(m.fingerprint(), back.fingerprint());
        // Verdicts hold through the canonicalization replay.
        assert!(back.is_blocked("café.com"));
        assert!(back.is_blocked("www.café.com"));
        assert!(back.is_blocked("ads.doubleclick.net")); // subsumed by the parent
        assert!(back.is_blocked("x.doubleclick.net"));
        assert!(back.is_blocked("trailing.dot.net"));
        assert!(back.is_blocked("аproduced.example")); // Cyrillic а, lowercased
                                                       // A second independent encode of the SAME source is byte-stable (sorted body).
        let art2 = compile_text(raw).to_artifact();
        assert_eq!(art, art2);
    }

    // ---- P8 Wave A2: provenance / trust (rides ALONGSIDE the set, never in the hash) ----

    /// (a) A domain armed by TWO sources records BOTH source bits on its terminal.
    #[test]
    fn a2_two_sources_record_both_bits() {
        let mut reg = trust::SourceRegistry::new();
        let mask_a = reg.mask_for(11); // bit 1
        let mask_b = reg.mask_for(22); // bit 2
        assert_ne!(mask_a, mask_b);

        let mut m = Matcher::new();
        m.insert_with_source("ads.example.com", mask_a);
        m.insert_with_source("ads.example.com", mask_b); // same domain, second source corroborates
        m.finalize();

        let got = m.source_mask("ads.example.com");
        assert_eq!(got, mask_a | mask_b, "both source bits must be recorded");
        assert!(reg.mask_has_source(got, 11));
        assert!(reg.mask_has_source(got, 22));
        assert_eq!(trust::SourceRegistry::corroboration(got), 2);

        // A subsumed child armed by a third source corroborates the COVERING parent terminal.
        let mask_c = reg.mask_for(33); // bit 3
        m.insert_with_source("x.ads.example.com", mask_c); // parent ads.example.com already terminal
        m.finalize();
        let got2 = m.source_mask("x.ads.example.com"); // resolves to the covering parent's mask
        assert_eq!(got2, mask_a | mask_b | mask_c);
        assert_eq!(m.count(), 1); // still one terminal — provenance did not split the set
    }

    /// (b) THE FINGERPRINT INVARIANT: identical blocked SET + DIFFERENT source tags ⇒ IDENTICAL
    /// finalize() fingerprint (and identical count). Provenance never perturbs the SET oracle.
    #[test]
    fn a2_provenance_never_perturbs_the_fingerprint() {
        let domains = ["ads.one.com", "tracker.two.io", "doubleclick.net"];

        // Same set, source A.
        let mut ma = Matcher::new();
        for d in domains {
            ma.insert_with_source(d, trust::bit_to_mask(1));
        }
        ma.finalize();

        // Same set, source B (different bit) — and even a multi-source variant.
        let mut mb = Matcher::new();
        for d in domains {
            mb.insert_with_source(d, trust::bit_to_mask(7));
        }
        mb.finalize();

        let mut mc = Matcher::new();
        for d in domains {
            mc.insert_with_source(d, trust::bit_to_mask(2) | trust::bit_to_mask(9));
        }
        mc.finalize();

        // The source-LESS legacy path over the SAME set.
        let mut m0 = Matcher::new();
        for d in domains {
            m0.insert(d);
        }
        m0.finalize();

        assert_eq!(ma.fingerprint(), mb.fingerprint());
        assert_eq!(ma.fingerprint(), mc.fingerprint());
        assert_eq!(
            ma.fingerprint(),
            m0.fingerprint(),
            "tagged set == legacy set fingerprint"
        );
        assert_eq!(ma.count(), mc.count());
        assert_eq!(ma.count(), m0.count());

        // But the provenance DID differ (rides alongside, not in the hash).
        assert_ne!(ma.source_mask("ads.one.com"), mb.source_mask("ads.one.com"));
        assert_eq!(m0.source_mask("ads.one.com"), 0); // legacy path tags nothing
    }

    /// (c) A legacy `compile_text` install yields a fingerprint BYTE-IDENTICAL to pre-A2: the
    /// source-less text path sets no source bit and routes through the UNCHANGED `install_compiled`.
    #[test]
    fn a2_legacy_compile_text_fingerprint_byte_identical() {
        let _g = lock_global();
        let raw = "0.0.0.0 ads.example.com\n||*.tracker.io^\n# note\nplain.net\ndoubleclick.net\nads.doubleclick.net\n";

        // The pure compile (no install) fingerprint — this is exactly what pre-A2 produced for this text.
        let compiled_fp = compile_text(raw).fingerprint();

        // The legacy install path returns the SAME fingerprint (install_compiled is byte-identical).
        let (_count, installed_fp) = compile_and_install_text(raw, false);
        assert_eq!(installed_fp, compiled_fp);
        assert_eq!(installed_fingerprint(), compiled_fp);

        // And every terminal the legacy text path armed carries NO provenance (mask 0).
        let guard = GLOBAL.read().unwrap_or_else(|e| e.into_inner());
        let m = guard.as_ref().expect("installed");
        assert_eq!(m.source_mask("ads.example.com"), 0);
        assert_eq!(m.source_mask("doubleclick.net"), 0);
        assert_eq!(m.source_mask("plain.net"), 0);
    }

    /// (d) `is_blocked` verdicts are IDENTICAL whether the set was armed with or without source tags,
    /// for a probe set — A2 must not change the blocked-SET verdicts vs A1.
    #[test]
    fn a2_is_blocked_verdicts_unchanged_by_provenance() {
        let domains = ["doubleclick.net", "ads.example.com", "tracker.io"];

        let mut legacy = Matcher::new();
        for d in domains {
            legacy.insert(d);
        }
        legacy.finalize();

        let mut tagged = Matcher::new();
        for d in domains {
            tagged.insert_with_source(d, trust::bit_to_mask(3));
        }
        tagged.finalize();

        let probes = [
            ("doubleclick.net", true),
            ("ads.doubleclick.net", true), // subsumed
            ("a.b.doubleclick.net", true),
            ("ads.example.com", true),
            ("x.ads.example.com", true),
            ("tracker.io", true),
            ("doubleclick.net.evil.com", false),
            ("notdoubleclick.net", false),
            ("net", false),
            ("example.com", false),
        ];
        for (d, want) in probes {
            assert_eq!(legacy.is_blocked(d), want, "legacy verdict for {d}");
            assert_eq!(tagged.is_blocked(d), want, "tagged verdict for {d}");
        }
        // Same SET ⇒ same fingerprint, confirming verdicts ride on the same canonical set.
        assert_eq!(legacy.fingerprint(), tagged.fingerprint());
    }

    /// `install_with_source` records provenance on the active matcher and merges corroboration across
    /// two sources for the same domain, while keeping the SET fingerprint equal to the legacy install.
    #[test]
    fn a2_install_with_source_merges_provenance() {
        let _g = lock_global();
        // Replace-install from source 101.
        let base = compile_text("shared-a2-probe.example\nonly-src1-a2.example\n");
        let base_fp_legacy = base.fingerprint();
        let (c1, fp1) = install_with_source(base, 101, false);
        assert_eq!(c1, 2);
        assert_eq!(
            fp1, base_fp_legacy,
            "source tag must not move the SET fingerprint"
        );

        // Merge a second source 202 that re-arms the shared domain + adds a new one.
        let add = compile_text("shared-a2-probe.example\nonly-src2-a2.example\n");
        let (c2, _fp2) = install_with_source(add, 202, true);
        assert_eq!(c2, 3);

        // Read provenance off the active matcher.
        let guard = GLOBAL.read().unwrap_or_else(|e| e.into_inner());
        let m = guard.as_ref().expect("installed");
        let reg = REGISTRY.read().unwrap_or_else(|e| e.into_inner());
        let reg = reg
            .as_ref()
            .expect("registry initialized by install_with_source");

        let shared = m.source_mask("shared-a2-probe.example");
        assert!(
            reg.mask_has_source(shared, 101),
            "source 101 must be recorded on the shared domain"
        );
        assert!(
            reg.mask_has_source(shared, 202),
            "source 202 must corroborate the shared domain"
        );
        assert_eq!(trust::SourceRegistry::corroboration(shared), 2);

        let s1 = m.source_mask("only-src1-a2.example");
        assert!(reg.mask_has_source(s1, 101));
        assert!(!reg.mask_has_source(s1, 202));
    }

    /// The source-aware walk enumerates the blocked SET together with provenance, and the masks it
    /// yields match `source_mask`. (Exercises `walk_terminals_with_sources` — the separate read path.)
    #[test]
    fn a2_source_aware_walk_matches_source_mask() {
        let mut m = Matcher::new();
        m.insert_with_source("alpha.example", trust::bit_to_mask(1));
        m.insert_with_source(
            "beta.example",
            trust::bit_to_mask(2) | trust::bit_to_mask(3),
        );
        m.finalize();

        let mut seen: Vec<(String, SourceMask)> = Vec::new();
        m.root
            .walk_terminals_with_sources("", &mut |d, mask| seen.push((d.to_string(), mask)));
        seen.sort();
        assert_eq!(seen.len(), 2);
        for (domain, mask) in &seen {
            assert_eq!(
                *mask,
                m.source_mask(domain),
                "walk mask must equal source_mask for {domain}"
            );
            assert_ne!(*mask, 0);
        }
    }

    // ---- P12 R2: configurable block action (cloaking) ----

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Tests that mutate the process-shared `BLOCK_ACTION`/`BLOCK_ACTION_IP` selector must serialize
    /// (the same reason the GLOBAL matcher tests do). Reuse the existing GLOBAL test lock so an action
    /// test and an install test cannot interleave a `query_action` against a mid-swap GLOBAL.
    fn reset_block_action() {
        set_block_action(BlockAction::NxDomain);
    }

    /// The default action is NXDOMAIN — byte-identical to pre-P12 behaviour.
    #[test]
    fn block_action_defaults_to_nxdomain() {
        let _g = lock_global();
        reset_block_action();
        assert_eq!(block_action(), BlockAction::NxDomain);
        assert_eq!(BlockAction::default(), BlockAction::NxDomain);
    }

    /// Each variant set through the selector reads back as itself: NXDOMAIN, ZeroSink, and a pinned
    /// CustomIp (v4 and v6). This is the contract the resolver R2 wire dispatches on.
    #[test]
    fn block_action_selector_round_trips_each_variant() {
        let _g = lock_global();
        reset_block_action();

        set_block_action(BlockAction::ZeroSink);
        assert_eq!(block_action(), BlockAction::ZeroSink);

        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        set_block_action(BlockAction::CustomIp(v4));
        assert_eq!(block_action(), BlockAction::CustomIp(v4));

        let v6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        set_block_action(BlockAction::CustomIp(v6));
        assert_eq!(block_action(), BlockAction::CustomIp(v6));

        // Flipping back to NXDOMAIN clears the pin so a later CustomIp cannot inherit a stale IP.
        set_block_action(BlockAction::NxDomain);
        assert_eq!(block_action(), BlockAction::NxDomain);
        assert_eq!(
            *BLOCK_ACTION_IP.read().unwrap_or_else(|e| e.into_inner()),
            None,
            "switching away from CustomIp must clear the pinned address"
        );

        reset_block_action();
    }

    /// Switching ZeroSink → CustomIp → ZeroSink leaves NO stale pinned IP behind: ZeroSink reads back
    /// cleanly and the pin is cleared (a CustomIp set never bleeds into a later non-CustomIp action).
    #[test]
    fn block_action_zerosink_clears_a_prior_custom_pin() {
        let _g = lock_global();
        reset_block_action();

        set_block_action(BlockAction::CustomIp(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1,
        ))));
        assert!(BLOCK_ACTION_IP
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_some());

        set_block_action(BlockAction::ZeroSink);
        assert_eq!(block_action(), BlockAction::ZeroSink);
        assert_eq!(
            *BLOCK_ACTION_IP.read().unwrap_or_else(|e| e.into_inner()),
            None,
            "ZeroSink must clear any prior CustomIp pin"
        );

        reset_block_action();
    }

    /// `query_action` fuses the verdict with the action in ONE lookup: blocked names return
    /// `Some(<active action>)`, unblocked names return `None` (control falls through as today).
    #[test]
    fn query_action_returns_active_action_only_for_blocked_names() {
        let _g = lock_global();
        // Domains unique to this test so the shared GLOBAL set is deterministic.
        let _ = compile_and_install_text("blocked-r2-probe.example\n", false);

        // NXDOMAIN default: a blocked name yields Some(NxDomain), an unblocked name yields None.
        reset_block_action();
        assert_eq!(
            query_action("sub.blocked-r2-probe.example"),
            Some(BlockAction::NxDomain)
        );
        assert_eq!(query_action("never-blocked-r2-zzz.example"), None);

        // Flip to ZeroSink: the SAME blocked name now reports the new action; unblocked stays None.
        set_block_action(BlockAction::ZeroSink);
        assert_eq!(
            query_action("blocked-r2-probe.example"),
            Some(BlockAction::ZeroSink)
        );
        assert_eq!(query_action("never-blocked-r2-zzz.example"), None);

        // CustomIp: the blocked name carries the pinned redirect IP.
        let pin = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        set_block_action(BlockAction::CustomIp(pin));
        assert_eq!(
            query_action("blocked-r2-probe.example"),
            Some(BlockAction::CustomIp(pin))
        );

        reset_block_action();
    }

    /// A `CustomIp` selector with no pinned address degrades to `NxDomain` (deny, never a
    /// half-configured redirect). This guards the resolver dispatch from a None-IP CustomIp branch.
    #[test]
    fn custom_ip_without_a_pin_degrades_to_nxdomain() {
        let _g = lock_global();
        reset_block_action();

        // Force the rare inconsistent state directly: selector says CustomIp but no IP is pinned.
        *BLOCK_ACTION_IP.write().unwrap_or_else(|e| e.into_inner()) = None;
        BLOCK_ACTION.store(ACTION_CUSTOMIP, std::sync::atomic::Ordering::Release);

        assert_eq!(
            block_action(),
            BlockAction::NxDomain,
            "an unpinned CustomIp must deny, not redirect to nowhere"
        );

        reset_block_action();
    }

    /// The action selector is INDEPENDENT of list installs: re-installing a blocklist (the P10 rotation
    /// path) does NOT reset the user's chosen action — `install_compiled` never touches `BLOCK_ACTION`.
    #[test]
    fn block_action_survives_a_blocklist_reinstall() {
        let _g = lock_global();
        reset_block_action();
        set_block_action(BlockAction::ZeroSink);

        // A fresh install + a merge (the rotation re-arm path) must not disturb the action selector.
        let _ = compile_and_install_text("rotate-r2-a.example\n", false);
        let _ = compile_and_install_text("rotate-r2-b.example\n", true);

        assert_eq!(
            block_action(),
            BlockAction::ZeroSink,
            "re-installing the blocklist must NOT reset the cloak action"
        );

        reset_block_action();
    }
}
