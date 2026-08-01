// SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
//! ★ #65 · THE ABSORB LANE — how a CDN this device MET becomes a CDN this device SERVES.
//!
//! The corpus lane and this lane answer two different questions, and keeping them apart is the whole
//! design:
//!
//! * The **corpus lane** serves hosts this build already ships knowledge of. Every asset has a
//!   ResourceMap (`localcdn_maps.rs`) and a signed catalog pin, so `fetch_once` can VERIFY bytes against
//!   a hash that existed before the request did. That lane is fail-closed and stays exactly as it was.
//! * The **absorb lane** (here) serves hosts DISCOVERY earned into the roster — a CDN met while the user
//!   browsed. It ships no map and no pin, because the device had never heard of it until now. So the
//!   first request ADDRESSES what arrives instead of verifying it (`fetch_absorb`), remembers the
//!   `name → content address` binding here, and serves every later request out of the content-addressed
//!   cache with ZERO egress.
//!
//! The trust model is stated honestly rather than blurred: the FIRST fetch of an absorbed asset trusts
//! the upstream TLS connection and nothing more — there is no earlier pin it could be checked against.
//! Everything after that first fetch is as strong as the corpus lane, because the binding is by content
//! address and every later serve re-checks that address against the bytes in the cache. An absorbed asset
//! that changes upstream does not silently swap: the binding still names the old address, which is what
//! makes revalidation a deliberate act rather than an accident.
//!
//! Bindings are durable (`absorbed-assets.tsv`, beside the catalog in the cache dir) so an absorbed CDN
//! survives process death and reboot — "populates this CDN one time when they are Online, absorbs them
//! offline, so the call is Private forever". The bytes themselves live in the ordinary content-addressed
//! cache; this file only remembers WHICH address a name resolved to.

#![forbid(unsafe_code)]

use super::cache::ContentHash;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

/// TSV wire version (bump only on an incompatible column change; the reader is fail-open per row).
const STORE_VERSION: &str = "v1";
/// The durable binding file, written beside the device-signed catalog in the mirror's cache dir.
const STORE_FILE_NAME: &str = "absorbed-assets.tsv";
/// Hard ceiling on remembered bindings — a hostile site cannot grow the index without bound. Once
/// reached, further absorptions still SERVE (the bytes are cached) but no new binding is remembered.
const MAX_BINDINGS: usize = 8192;

static INDEX: OnceLock<RwLock<HashMap<String, ContentHash>>> = OnceLock::new();
static STORE_DIR: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();
/// Fast gate: false until [`arm`] binds a durable dir AND at least one binding exists, so the per-request
/// consult on a device that has absorbed nothing costs one relaxed atomic load and never takes the lock.
static ANY_BINDING: AtomicBool = AtomicBool::new(false);
/// Signature of the index at the last persisted write (change gate — an unchanged index does no IO).
static LAST_PERSIST_SIG: AtomicU64 = AtomicU64::new(0);

fn index() -> &'static RwLock<HashMap<String, ContentHash>> {
    INDEX.get_or_init(|| RwLock::new(HashMap::new()))
}

fn store_dir_cell() -> &'static RwLock<Option<PathBuf>> {
    STORE_DIR.get_or_init(|| RwLock::new(None))
}

/// The canonical absorbed-asset name for a request: `<host><path>`, normalized the same way the cloak
/// consult normalizes a host (trim, strip a trailing FQDN dot, lowercase) with the path left byte-exact
/// (paths ARE case-sensitive on real CDNs, and a query string is part of the identity of what was served).
///
/// Deterministic by construction, so the same URL always names the same binding across processes.
pub fn absorb_name(host: &str, path: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut name = String::with_capacity(h.len() + path.len());
    name.push_str(&h);
    name.push_str(path);
    name
}

/// The upstream URL an absorbed request is fetched from — the request rebuilt against its REAL origin.
/// https-only by construction (`fetch_bytes` re-enforces it); an empty host yields `None` so a malformed
/// request can never become a fetch.
/// A path that is not origin-form fails CLOSED. Substituting `/` for it (the previous behaviour) would
/// fetch the CDN's HOMEPAGE and then [`remember`] that HTML under the asset's name — every later request
/// for the script would be served the homepage from cache, with no second fetch to ever correct it. A
/// missing asset is recoverable; a poisoned binding is not.
pub fn absorb_url(host: &str, path: &str) -> Option<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.contains('/') || !path.starts_with('/') {
        return None;
    }
    Some(format!("https://{h}{path}"))
}

/// Bind the durable dir + rehydrate any previously absorbed bindings. Idempotent.
pub fn arm(dir: PathBuf) {
    if let Ok(mut slot) = store_dir_cell().write() {
        *slot = Some(dir);
    }
    load();
}

/// The content address previously absorbed for `name`, if any. Gated on [`ANY_BINDING`] so the common
/// "nothing absorbed yet" case never takes the lock. A poisoned lock reads as a miss (fail-open to a
/// fresh absorb — never a panic on the serve path).
pub fn lookup(name: &str) -> Option<ContentHash> {
    if !ANY_BINDING.load(Ordering::Relaxed) {
        return None;
    }
    index().read().ok().and_then(|m| m.get(name).copied())
}

/// Remember that `name` resolved to `hash`, and persist the index. Re-absorbing the same name with a NEW
/// address overwrites the binding — that is how a revalidated asset moves forward. Returns false when the
/// ceiling is reached and the name is new (the asset still serves this request; it just is not remembered).
pub fn remember(name: String, hash: ContentHash) -> bool {
    let stored = match index().write() {
        Ok(mut m) => {
            if m.len() >= MAX_BINDINGS && !m.contains_key(&name) {
                false
            } else {
                m.insert(name, hash);
                ANY_BINDING.store(true, Ordering::Relaxed);
                true
            }
        }
        Err(_) => false,
    };
    if stored {
        persist();
    }
    stored
}

/// How many assets this device has absorbed (the dashboard's absorbed-asset tally).
pub fn count() -> u64 {
    if !ANY_BINDING.load(Ordering::Relaxed) {
        return 0;
    }
    index().read().map(|m| m.len() as u64).unwrap_or(0)
}

// ── Durability ────────────────────────────────────────────────────────────────────────────────────

fn store_path() -> Option<PathBuf> {
    store_dir_cell()
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|d| d.join(STORE_FILE_NAME)))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    s
}

fn parse_hash(hex: &str) -> Option<ContentHash> {
    if hex.len() != 64 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// FNV-1a over each binding, XOR-folded per row so a HashMap walk order cannot change the signature.
fn signature(m: &HashMap<String, ContentHash>) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut folded: u64 = m.len() as u64;
    for (name, hash) in m.iter() {
        let mut h = FNV_OFFSET;
        for b in name.as_bytes().iter().chain(hash.iter()) {
            h ^= *b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        folded ^= h;
    }
    folded
}

/// Write the index to disk when it has actually changed. A failed write is fail-open: the RAM index
/// stands and the next absorb retries the write.
fn persist() {
    let Some(path) = store_path() else {
        return;
    };
    let Ok(m) = index().read() else {
        return;
    };
    let sig = signature(&m);
    if LAST_PERSIST_SIG.swap(sig, Ordering::Relaxed) == sig {
        return; // unchanged ⇒ no IO
    }
    let mut body = String::with_capacity(m.len() * 96 + 32);
    body.push_str("#version\t");
    body.push_str(STORE_VERSION);
    body.push('\n');
    for (name, hash) in m.iter() {
        // A name can never contain a tab or newline: it is `<host><path>` from a parsed HTTP request.
        if name.contains('\t') || name.contains('\n') {
            continue;
        }
        body.push_str(name);
        body.push('\t');
        body.push_str(&hex_lower(hash));
        body.push('\n');
    }
    drop(m);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, body);
}

/// Rehydrate bindings from disk. Fail-open per row: one malformed line is skipped, never fatal, so a
/// partially-written file still restores every good binding.
fn load() {
    let Some(path) = store_path() else {
        return;
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let mut restored: HashMap<String, ContentHash> = HashMap::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, hex)) = line.split_once('\t') else {
            continue;
        };
        let Some(hash) = parse_hash(hex.trim()) else {
            continue;
        };
        if name.is_empty() || restored.len() >= MAX_BINDINGS {
            continue;
        }
        restored.insert(name.to_string(), hash);
    }
    if restored.is_empty() {
        return;
    }
    if let Ok(mut m) = index().write() {
        let sig = signature(&restored);
        *m = restored;
        ANY_BINDING.store(true, Ordering::Relaxed);
        // Seed the change gate with what is already on disk, so a rehydrate does not rewrite it.
        LAST_PERSIST_SIG.store(sig, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The index is process-global; serialize the tests that mutate it (the discovery-test precedent).
    static SCRUB: Mutex<()> = Mutex::new(());

    /// A non-origin-form path must NOT collapse to the CDN root. The old code substituted `/`, which
    /// fetched the homepage and then remembered that HTML under the asset's name — a permanently
    /// poisoned binding, since a remembered name is served from cache and never re-fetched.
    #[test]
    fn absorb_url_fails_closed_on_a_path_without_a_leading_slash() {
        assert_eq!(
            absorb_url("cdn.example.com", "/lib/1.0/x.js").as_deref(),
            Some("https://cdn.example.com/lib/1.0/x.js")
        );
        assert_eq!(absorb_url("cdn.example.com", "lib/1.0/x.js"), None);
        assert_eq!(absorb_url("cdn.example.com", ""), None);
        // The host guards still hold.
        assert_eq!(absorb_url("", "/x.js"), None);
        assert_eq!(absorb_url("cdn.example.com/evil", "/x.js"), None);
    }

    fn scrub() -> std::sync::MutexGuard<'static, ()> {
        let g = SCRUB.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut m) = index().write() {
            m.clear();
        }
        ANY_BINDING.store(false, Ordering::Relaxed);
        LAST_PERSIST_SIG.store(0, Ordering::Relaxed);
        if let Ok(mut d) = store_dir_cell().write() {
            *d = None;
        }
        g
    }

    #[test]
    fn name_is_deterministic_and_host_normalized() {
        assert_eq!(
            absorb_name("CDN.Example.COM.", "/lib/App.js"),
            "cdn.example.com/lib/App.js",
            "host lowercases + loses the root dot; the path stays byte-exact"
        );
        assert_eq!(
            absorb_name("cdn.example.com", "/a?v=2"),
            "cdn.example.com/a?v=2",
            "the query is part of what was served, so it is part of the identity"
        );
    }

    #[test]
    fn url_is_https_only_and_rejects_a_malformed_host() {
        assert_eq!(
            absorb_url("cdn.example.com", "/x.js").as_deref(),
            Some("https://cdn.example.com/x.js")
        );
        assert_eq!(absorb_url("", "/x.js"), None, "an empty host never becomes a fetch");
        assert_eq!(
            absorb_url("evil.com/../", "/x.js"),
            None,
            "a host carrying a path separator is malformed, not a host"
        );
    }

    #[test]
    fn lookup_is_free_until_something_is_absorbed() {
        let _s = scrub();
        assert_eq!(lookup("cdn.example.com/x.js"), None, "nothing absorbed ⇒ a gated miss");
        assert_eq!(count(), 0);
    }

    #[test]
    fn remember_then_lookup_round_trips_and_revalidation_overwrites() {
        let _s = scrub();
        let first = [7u8; 32];
        assert!(remember("cdn.example.com/x.js".to_string(), first));
        assert_eq!(lookup("cdn.example.com/x.js"), Some(first));
        assert_eq!(count(), 1);

        // Re-absorbing the SAME name with a new address moves the binding forward (revalidation).
        let second = [9u8; 32];
        assert!(remember("cdn.example.com/x.js".to_string(), second));
        assert_eq!(
            lookup("cdn.example.com/x.js"),
            Some(second),
            "the binding follows the newly absorbed content address"
        );
        assert_eq!(count(), 1, "revalidation replaces, it never duplicates");
    }

    #[test]
    fn bindings_round_trip_through_the_tsv() {
        let _s = scrub();
        let dir = std::env::temp_dir().join("torta-absorb-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        arm(dir.clone());

        let hash = [0xABu8; 32];
        assert!(remember("cdn.example.com/app.js".to_string(), hash));

        // Drop the RAM index, then rehydrate from disk alone.
        if let Ok(mut m) = index().write() {
            m.clear();
        }
        ANY_BINDING.store(false, Ordering::Relaxed);
        load();

        assert_eq!(
            lookup("cdn.example.com/app.js"),
            Some(hash),
            "an absorbed asset survives process death"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_row_is_skipped_not_fatal() {
        let _s = scrub();
        let dir = std::env::temp_dir().join("torta-absorb-malformed");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let good = "f".repeat(64);
        std::fs::write(
            dir.join(STORE_FILE_NAME),
            format!("#version\tv1\nbroken-row-no-tab\ncdn.example.com/ok.js\t{good}\nbad\tnothex\n"),
        )
        .expect("seed");
        arm(dir.clone());

        assert_eq!(count(), 1, "only the well-formed row restores");
        assert!(lookup("cdn.example.com/ok.js").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
