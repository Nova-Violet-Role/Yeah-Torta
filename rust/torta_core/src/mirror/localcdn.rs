/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! #134 slice 1 — the LocalCDN→Centauri resource-map RESOLVER.
//!
//! LocalCDN (MPL-2.0, codeberg.org/nobody/LocalCDN, evolved from Decentraleyes) ships ~200 JS/CSS libraries
//! on disk and, in a browser, intercepts every request to a known CDN host via `webRequest` and redirects it
//! to a packaged local copy — so the CDN never sees the request. Centauri keeps that DATA + those redirect
//! SEMANTICS but swaps the browser veto for the mirror's **loopback serve** (the app owns the DNS plane via
//! dnscrypt + the cloak-set, and the in-app loopback HTTP server is the redirect target). The crown:
//! **opt-out LOCAL CDN binding** — serve hash-verified from device, the CDN sees ≤ 1 request.
//!
//! This module is the port of LocalCDN's `request-analyzer` URL→local-target resolution (`mappings.cdn` →
//! `resources.*`), plus the major-version FALLBACK (`targets.setLastVersion`): when the exact requested
//! version isn't bundled, pick the safest bundled substitute. The fallback policy mirrors the Haskell
//! control-plane twin (`torta_hs_centauri_substitute`, muscle #6) — same major is the compatibility
//! boundary; within it, a ≥ requested minor.patch is a safe newer substitute. Rust owns this hot serve path.
//!
//! Slice 1 = the resolver + the fallback + a representative SEED of the map table (hosts/paths GROUND_TRUTH'd
//! from `localcdn/core/mappings.js`). Follow-up slices: the full ~200-library map import, the server.rs serve
//! wiring, the opt-out binding + dashboard + `query-centauri.log`.

#![forbid(unsafe_code)]

use super::cache::ContentHash;
use super::catalog::Catalog;
// The Beast trust engine, crossed IN (our own GPL-3 code, `blocklist/trust.rs` — NOT LocalCDN): the
// signed-band floor + the bounded corroboration bonus + the fixed-point recency decay are REUSED here so
// the mirror's resolution trust and the blocklist's source trust share ONE tuned constant set (never a
// drifting duplicate). The `crate::blocklist::trust` module is `pub(crate)` (crate-internal only — the
// parent `mod blocklist` is private, so this never enters the cdylib API).
use crate::blocklist::trust::{recency_pct, CORR_CAP, CORR_STEP, SIGNED_FLOOR};

/// A semver triple parsed from a version string (`"3.6.0"` → `(3, 6, 0)`). Missing components default to 0
/// (`"3.6"` → `(3, 6, 0)`, `"3"` → `(3, 0, 0)`); a non-numeric component ends the parse.
fn parse_version(v: &str) -> (u32, u32, u32) {
    let mut it = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// The version-substitution verdict — the Rust twin of muscle #6's `centauriSubstitute` (the serve-path
/// owner; the Haskell version reasons on the catalog-build control plane).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Substitution {
    /// Byte-identical version requested and bundled.
    Exact,
    /// Same major, bundled ≥ requested minor.patch — backward-compatible, safe to serve.
    SafeNewer,
    /// Same major, bundled is older than requested — may lack features; allowed but flagged.
    RiskyOlder,
    /// Different major — the compatibility boundary; never substitute.
    Incompatible,
}

/// Classify whether a bundled version may stand in for a requested one (RFC-semver compatibility).
pub fn substitution(requested: &str, bundled: &str) -> Substitution {
    let (rmaj, rmin, rpat) = parse_version(requested);
    let (amaj, amin, apat) = parse_version(bundled);
    if amaj != rmaj {
        Substitution::Incompatible
    } else if amin == rmin && apat == rpat {
        Substitution::Exact
    } else if (amin, apat) >= (rmin, rpat) {
        Substitution::SafeNewer
    } else {
        Substitution::RiskyOlder
    }
}

/// Pick the best bundled version for `requested` from `bundled`: an exact match wins; else the lowest
/// SafeNewer (the smallest compatible upgrade); else the highest RiskyOlder (the closest older fallback);
/// else `None` (no same-major candidate — never serve a cross-major substitute). Returns the chosen version
/// and how it relates to the request.
pub fn best_bundled_version<'a>(
    requested: &str,
    bundled: &[&'a str],
) -> Option<(&'a str, Substitution)> {
    let mut best_newer: Option<&'a str> = None;
    let mut best_older: Option<&'a str> = None;
    for &cand in bundled {
        match substitution(requested, cand) {
            Substitution::Exact => return Some((cand, Substitution::Exact)),
            Substitution::SafeNewer => {
                // smallest compatible upgrade
                if best_newer.is_none_or(|b| parse_version(cand) < parse_version(b)) {
                    best_newer = Some(cand);
                }
            }
            Substitution::RiskyOlder => {
                // closest older fallback (the highest of the olders)
                if best_older.is_none_or(|b| parse_version(cand) > parse_version(b)) {
                    best_older = Some(cand);
                }
            }
            Substitution::Incompatible => {}
        }
    }
    best_newer
        .map(|v| (v, Substitution::SafeNewer))
        .or(best_older.map(|v| (v, Substitution::RiskyOlder)))
}

/// One CDN→local mapping: a host + the path prefix that identifies the library, the local library id, and the
/// versions bundled on device (for the fallback). Mirrors LocalCDN's `mappings.cdn`{host}{base}{pattern} →
/// `resources.<lib>` two-table shape, flattened to the (host, base_path, library) the resolver needs.
#[derive(Clone, Copy, Debug)]
pub struct ResourceMap {
    /// CDN hostname (the cloak-set member), e.g. `"ajax.googleapis.com"`.
    pub host: &'static str,
    /// The path prefix on that host that precedes `<library>/<version>/<file>`, e.g. `"/ajax/libs/"`.
    pub base_path: &'static str,
    /// The local library id (the bundle name), e.g. `"jquery"`.
    pub library: &'static str,
    /// Versions bundled locally, for the version-fallback (a representative seed in slice 1).
    pub bundled_versions: &'static [&'static str],
}

/// A resolved request: which local library + version (after fallback) serves a CDN URL, and the relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub library: String,
    pub requested_version: String,
    pub served_version: String,
    /// The path tail after `<library>/<version>/` (e.g. `"jquery.min.js"`) — the asset file requested.
    pub file: String,
    pub substitution: Substitution,
}

impl Resolution {
    /// The canonical catalog asset name this resolution serves under: `<library>/<served_version>/<file>`.
    /// **Host-independent by design** — the same library+version+file from ANY mapped CDN dedups to ONE
    /// catalog entry + ONE cached copy (jQuery 3.6.0 from `ajax.googleapis.com` and from
    /// `cdnjs.cloudflare.com` are the same bytes, authored once in the signed catalog, served once). The
    /// version is the SERVED (post-fallback) one, so a fallback substitution serves under the bundled
    /// version's name (which is the entry the brain actually authored). The Centauri catalog (`catalog.rs`)
    /// is authored by the offline GHC brain under this exact convention.
    pub fn canonical_name(&self) -> String {
        format!("{}/{}/{}", self.library, self.served_version, self.file)
    }
}

/// Representative SEED of LocalCDN's map (hosts/paths GROUND_TRUTH'd from `localcdn/core/mappings.js`; the
/// bundled-version lists are a slice-1 seed — the full ~200-library import from the `resources/` tree is a
/// follow-up slice).
pub const SEED_MAPS: &[ResourceMap] = &[
    ResourceMap {
        host: "ajax.googleapis.com",
        base_path: "/ajax/libs/jquery/",
        library: "jquery",
        bundled_versions: &["3.5.1", "3.6.0", "3.7.1"],
    },
    ResourceMap {
        host: "ajax.googleapis.com",
        base_path: "/ajax/libs/angularjs/",
        library: "angularjs",
        bundled_versions: &["1.7.9", "1.8.2", "1.8.3"],
    },
    ResourceMap {
        host: "cdnjs.cloudflare.com",
        base_path: "/ajax/libs/jquery/",
        library: "jquery",
        bundled_versions: &["3.5.1", "3.6.0", "3.7.1"],
    },
    ResourceMap {
        host: "cdnjs.cloudflare.com",
        base_path: "/ajax/libs/twitter-bootstrap/",
        library: "bootstrap",
        bundled_versions: &["4.6.2", "5.2.3", "5.3.3"],
    },
];

/// Resolve a CDN `(host, path)` against the map table to the local library + version to serve. Matches the
/// host + a `base_path` prefix, takes the next path segment as the requested version, and runs the
/// version-fallback to choose the bundled version actually served. `None` if the host/path isn't a known
/// mapped library or no same-major bundled version exists. The actual file + content-hash lookup (against the
/// catalog) is the serve-wiring slice; this is the URL→(library, version) decision LocalCDN's
/// `request-analyzer` makes before the redirect.
/// Resolve against the FULL generated LocalCDN map ([`super::localcdn_maps::FULL_MAPS`], 1950 maps over 65
/// hosts joined from the on-disk asset tree) — the shipping resolver entry point the serve path uses.
/// [`resolve`] stays the table-injected core (the seed table drives the unit tests).
pub fn resolve_full(host: &str, path: &str) -> Option<Resolution> {
    resolve(host, path, super::localcdn_maps::FULL_MAPS)
}

/// The set of CDN hostnames LocalCDN→Centauri cloaks — the **opt-out local-CDN binding** host source.
///
/// Every host carrying at least one mapped library in [`super::localcdn_maps::FULL_MAPS`], sorted +
/// de-duplicated. This is the input the DNS-cloak datapath consumes (the dnscrypt cloaking-rules write at
/// `PathVars.java:280 getDNSCryptCloakingRulesPath`, or an in-resolver consult): each listed host is
/// answered as `127.0.0.1` so the request lands on the loopback mirror instead of the real CDN — so the CDN
/// sees ≤ 1 request (the crown). The host list is **not secret** and needs no signature (only the served
/// CONTENT is minisign-signed + BLAKE2b content-addressed), so it is static + build-time. Complements the
/// signature-verified [`super::catalog::CloakSet`]: this is the always-on static CDN set, that is any extra
/// per-catalog cloaked hosts. Returned sorted so the cloak path can `binary_search`, matching
/// `CloakSet::is_cloaked`'s consult shape.
///
/// **MEMOIZED (D17):** built ONCE per process (`OnceLock`) — the per-query consult ([`is_cdn_host`],
/// `resolve_inner` step 1.5b-cdn) previously re-collected + re-sorted all ~1950 map hosts on EVERY query
/// under the cloak (an O(n log n)-per-query tax on the hottest path); it is now one `binary_search` over a
/// build-once static set. Returned as a `&'static` slice so no caller allocates per read.
pub fn cdn_hosts() -> &'static [&'static str] {
    static CDN_HOSTS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    CDN_HOSTS.get_or_init(|| {
        let mut hosts: Vec<&'static str> = super::localcdn_maps::FULL_MAPS
            .iter()
            .map(|m| m.host)
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        hosts
    })
}

/// True iff `host` (after the same trim/lowercase/FQDN-dot normalization the cloak consult uses) is a
/// LocalCDN-cloaked CDN host — the per-query verdict the DNS-cloak path asks. The tun sentinel
/// ([`CLOAK_SENTINEL_IP`], `10.1.10.3`) is the answer for a `true`.
///
/// **Zero-alloc fast path (D17):** the common case — a qname already lowercase (the resolver's
/// `parse_question` lowercases, `resolver/cache.rs:114`) with no surrounding whitespace and no trailing
/// FQDN dot survives normalization borrowed; the lowercase ALLOC happens only when an uppercase byte
/// actually exists. Either way the verdict is ONE `binary_search` over the memoized [`cdn_hosts`] set.
pub fn is_cdn_host(host: &str) -> bool {
    let t = host.trim().trim_end_matches('.');
    if t.is_empty() {
        return false;
    }
    // FULL_MAPS hosts are already lowercase, exact CDN hostnames; a binary_search over the sorted set.
    // A host whose client already REFUSED our leaf is never cloaked again — see [`TLS_DISTRUST`]. This
    // gate is on the DNS plane only: un-cloaking hands the name back to the real CDN so the app that
    // refused us keeps working.
    if t.bytes().any(|b| b.is_ascii_uppercase()) {
        let h = t.to_ascii_lowercase();
        !is_tls_distrusted(&h)
            && (cdn_hosts().binary_search(&h.as_str()).is_ok() || is_promoted_cloak_host(&h))
    } else {
        !is_tls_distrusted(t)
            && (cdn_hosts().binary_search(&t).is_ok() || is_promoted_cloak_host(t))
    }
}

// ── ★ #65 · the TLS-DISTRUST ledger (a client refused the leaf we minted) ─────────────────────────

/// Hosts whose client REFUSED the leaf Centauri minted for them, kept SORTED for `binary_search`.
///
/// Measured on the AVD: the netstack forwarder reported `tls_failed = 2`. A client that has not
/// installed the device CA rejects our handshake, and `forwarder/run.rs` cannot rescue THAT flow — by
/// the time `accept()` fails rustls has already written the alert and the peer has torn down. So the
/// recovery is for the NEXT flow: remember the host and stop cloaking it, which returns its DNS answer
/// to the real CDN and lets the app work normally again.
///
/// This is the only resolution that honours both standing laws. Splicing the refused flow onward to
/// the CDN would be a downgrade behind the user's back; leaving the host cloaked would break that app
/// forever. Stepping aside breaks neither — Centauri never sees the plaintext, and the app is whole on
/// its retry.
static TLS_DISTRUST: std::sync::RwLock<Vec<String>> = std::sync::RwLock::new(Vec::new());

/// Fast gate — false until a client actually refuses something, so the hot DNS path costs ONE relaxed
/// load on the overwhelmingly common device where every client trusts the CA (or none is installed and
/// nothing is cloaked at all).
static DISTRUST_ANY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Consult the distrust ledger. A poisoned lock reads as "not distrusted" — the DNS plane must never
/// panic on a query, and a missed entry is exactly the pre-existing behaviour.
pub(crate) fn is_tls_distrusted(host: &str) -> bool {
    if !DISTRUST_ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    TLS_DISTRUST
        .read()
        .map(|set| set.binary_search_by(|h| h.as_str().cmp(host)).is_ok())
        .unwrap_or(false)
}

/// ★ #78 — record that we CLOAKED `host` and then could not SERVE it, so stop cloaking it.
///
/// **MEASURED ON DEVICE (2026-07-26).** `cache/query.log`:
/// ```text
/// challenges.cloudflare.com  AAAA   CLOAK  0ms  local:cloak
/// challenges.cloudflare.com  A      CLOAK  0ms  local:cloak
/// ```
/// `challenges.cloudflare.com` serves Cloudflare Turnstile — a DYNAMIC challenge, not a versioned
/// static library. Centauri has no catalog entry for it and never can. But [`is_cdn_host`] answers on
/// the HOSTNAME alone, so the DNS plane handed the browser the sentinel `10.1.10.3`, the forwarder
/// spliced the flow to the mirror, and the mirror fail-closed with `NotInCatalog` ⇒ 404. The page's
/// challenge never loaded ⇒ **"Failed to load explore content."**
///
/// THE STRUCTURAL DEFECT: the cloak decision is HOST-granular, but serve capability is ASSET-granular.
/// LocalCDN redirects only *matched library URLs* and passes everything else straight through — it can,
/// because it sees the URL. DNS cannot. So cloaking at DNS granularity OVER-CLAIMS by construction, and
/// no static host list can fix that: whether we can serve `https://host/some/path` is not knowable from
/// `host`. The only honest repair is the FEEDBACK one — claim, discover we cannot deliver, and hand the
/// name back.
///
/// **DELIBERATELY THE SAME LEDGER AS [`note_tls_rejected`].** The cause differs (their client refused our
/// leaf vs. our catalog has nothing to give) but the REMEDY is identical to the byte: drop the host from
/// the cloak set so its DNS answer returns to the real CDN and the app works again. #79 was closed on
/// exactly this law — *two recovery paths for one row is one too many* — after a second, well-meant
/// recovery raced the first and vacated state the other still needed. One ledger, one file
/// (`centauri-tls-distrust.tsv`), one rehydrate at [`arm_tls_distrust_store`], one consult in
/// [`is_cdn_host`]. A parallel `centauri-unservable.tsv` would double every one of those for no gain.
///
/// Durable by inheritance: the miss survives process death, so a host we proved unservable is not
/// re-cloaked on the next boot — the user does not pay the same broken page twice.
/// ★ THE DISCRIMINATION THAT MAKES THIS SAFE. Only a DISCOVERY-PROMOTED host is ever un-cloaked on a
/// serve miss; a `FULL_MAPS` library CDN never is.
///
/// The first cut of this fix un-cloaked on ANY `NotInCatalog`, and the suite immediately convicted it:
/// `route_host_aware_serves_by_cdn_host_header_else_by_path` went `Served -> NotInCatalog` and three
/// `tlsca` tests lost `ajax.googleapis.com`. They were RIGHT. `ajax.googleapis.com` carries 1950 maps —
/// we hold jQuery and miss ten thousand other URLs on it. Treating one absent asset as "this host is
/// unservable" would surrender the entire offline CDN for that host on its first uncovered request,
/// which is the exact opposite of what Centauri is for.
///
/// The two causes are genuinely different and the host set separates them cleanly:
/// - a `FULL_MAPS` host is a KNOWN library CDN — a miss means *this asset* is uncovered. Keep cloaking;
///   the next request may well be jQuery, and a 404 here is the honest fail-closed answer.
/// - a PROMOTED host arrived from runtime discovery with NO map coverage at all. A miss means we never
///   had anything to serve on it — like `challenges.cloudflare.com`, a dynamic Turnstile endpoint that
///   is not a versioned library and never will be. Cloaking it can only ever break the page.
///
/// So the predicate is "promoted AND not a mapped library host", which is precisely "we claimed this
/// name on a guess and the guess was wrong."
pub(crate) fn serve_miss_should_uncloak(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    // A mapped library CDN keeps its cloak — the miss is per-ASSET, not per-host.
    if cdn_hosts().binary_search(&h.as_str()).is_ok() {
        return false;
    }
    is_promoted_cloak_host(&h)
}

pub fn note_unservable(host: &str) {
    if !serve_miss_should_uncloak(host) {
        return;
    }
    note_tls_rejected(host);
}

/// Record that `host`'s client refused our leaf. Idempotent, insertion-sorted so the consult keeps
/// using `binary_search`. Called from the forwarder's TLS-accept failure path, and (via
/// [`note_unservable`]) from the mirror's catalog-miss path.
pub fn note_tls_rejected(host: &str) {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return;
    }
    let snapshot = {
        let Ok(mut set) = TLS_DISTRUST.write() else {
            return;
        };
        // Already known: idempotent, and NOT worth a second disk write.
        let Err(at) = set.binary_search_by(|x| x.as_str().cmp(h.as_str())) else {
            return;
        };
        set.insert(at, h);
        // Set the gate only AFTER the entry is in place, so a reader that observes `true` always
        // finds a populated set.
        DISTRUST_ANY.store(true, std::sync::atomic::Ordering::Relaxed);
        set.clone()
    };
    // The write lock is RELEASED above before touching the disk — a refusal must never hold the DNS
    // plane's gate across a filesystem call.
    persist_tls_distrust(&snapshot);
}

// ── ★ #20 · the refusal must OUTLIVE the process ─────────────────────────────────────────────────
//
// Measured on the AVD: the forwarder reported `TLS failed = 7` while the Centauri dashboard's
// distrust tile stayed dark. Both readings were HONEST. `TLS_DISTRUST` lived in RAM only, and the
// forwarder that records a refusal runs in the VPN SERVICE process while the dashboard reads the
// engine linked into the UI — so the ledger was invisible to the panel by construction, exactly the
// durability gap already fixed for the promoted-cloak set.
//
// The user-facing half is the graver one: a client that refused our leaf un-cloaks its host only
// until the next process death, after which the host is cloaked again and that app breaks AGAIN.
// A refusal is a permanent fact about a client, so it belongs on disk.

/// Where the refusal ledger is written; `None` until the discovery layer arms with the durable dir.
static DISTRUST_STORE: std::sync::RwLock<Option<std::path::PathBuf>> = std::sync::RwLock::new(None);

/// Bind the durable dir and rehydrate the ledger ONCE. Rides the same boot edge as the discovery
/// store so a host that refused us in an earlier process is still un-cloaked on this one.
pub(crate) fn arm_tls_distrust_store(dir: &std::path::Path) {
    let path = dir.join("centauri-tls-distrust.tsv");
    let loaded: Vec<String> = std::fs::read_to_string(&path)
        .map(|body| {
            let mut v: Vec<String> = body
                .lines()
                .map(|l| l.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            v.sort();
            v.dedup();
            v
        })
        .unwrap_or_default();
    if let Ok(mut cell) = DISTRUST_STORE.write() {
        *cell = Some(path);
    }
    if loaded.is_empty() {
        return;
    }
    if let Ok(mut set) = TLS_DISTRUST.write() {
        for h in loaded {
            if let Err(at) = set.binary_search_by(|x| x.as_str().cmp(h.as_str())) {
                set.insert(at, h);
            }
        }
        let any = !set.is_empty();
        drop(set);
        if any {
            DISTRUST_ANY.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Write the ledger atomically. A store that never armed is a no-op, never an error — the DNS plane
/// keeps working out of RAM exactly as it did before.
fn persist_tls_distrust(set: &[String]) {
    let Ok(cell) = DISTRUST_STORE.read() else {
        return;
    };
    let Some(path) = cell.as_ref() else {
        return;
    };
    let mut body =
        // #78 widened WHY a host lands here: a refused leaf, OR a promoted host we cloaked and then
        // could not serve. The remedy is the same, so the ledger is the same — but the header must say
        // so, or the on-disk file misattributes every #78 row to a TLS refusal that never happened. A
        // durable file a human reads is a claim, and a wrong claim costs the next debugging session.
        String::from("# hosts Centauri no longer cloaks — client refused our leaf, or nothing to serve\n");
    for h in set {
        body.push_str(h);
        body.push('\n');
    }
    let tmp = path.with_extension("tsv.tmp");
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// How many hosts have refused our leaf — the dashboard's honest "could not be served here" count.
pub fn tls_distrust_count() -> usize {
    if !DISTRUST_ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return 0;
    }
    TLS_DISTRUST.read().map(|s| s.len()).unwrap_or(0)
}

/// Forget every recorded refusal — the RE-TRUST path.
///
/// A refusal only ever means "this client did not trust our leaf *at that moment*". That is a
/// statement about the device trust store, not about the host, and it stops being true the instant
/// the user installs (or the app re-mints) the device CA. Without this the ledger is a one-way door:
/// hosts refused before the CA was trusted stay un-cloaked for the life of the process, so the very
/// first site a user visits before installing the certificate is the one Centauri can never serve.
///
/// Returns how many hosts were forgiven, so the caller can log an honest number.
pub fn clear_tls_distrust() -> usize {
    // Close the gate FIRST: a reader that races us then takes the cheap `false` path and treats every
    // host as trusted, which is exactly the post-clear answer anyway.
    DISTRUST_ANY.store(false, std::sync::atomic::Ordering::Relaxed);
    let n = match TLS_DISTRUST.write() {
        Ok(mut set) => {
            let n = set.len();
            set.clear();
            n
        }
        Err(_) => 0,
    };
    // ★ #20 — erase the durable copy too. Re-arming trust that the next process silently undoes from
    // disk would be a lie to the user who asked for it.
    persist_tls_distrust(&[]);
    n
}

// ── ★ #65 · the PROMOTED cloak set (discovery's earned hosts) ──────────────────────────────────────

/// The promoted discovered hosts, kept SORTED for `binary_search`. Published by the catalog roster
/// (`mirror/object.rs`, `Centauri::cdn_hosts`) at every arm, so the DNS plane and the served catalog
/// are always built from ONE decision at ONE moment — a host with a cloak row always has a sinkholed
/// DNS answer, and vice versa. Drift between the two would be silent: the row would exist while the
/// name still resolved to the real CDN, and Centauri would never see the request at all.
static PROMOTED_CLOAK: std::sync::RwLock<Vec<String>> = std::sync::RwLock::new(Vec::new());

/// Fast gate — false until something is actually promoted. This keeps the per-query cost of the
/// promoted lane at ONE relaxed atomic load on a device that has promoted nothing yet (the fresh-install
/// case), so the hottest path in the resolver never takes a lock it does not need.
static PROMOTED_ANY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Consult the promoted set. Gated on [`PROMOTED_ANY`] so the empty case costs one atomic load; a
/// poisoned lock reads as "not promoted" (fail-open to the static corpus — never a panic on a DNS
/// query). `host` must already be normalized (trimmed, root-dot stripped, lowercase).
fn is_promoted_cloak_host(host: &str) -> bool {
    if !PROMOTED_ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    PROMOTED_CLOAK
        .read()
        .map(|set| set.binary_search_by(|h| h.as_str().cmp(host)).is_ok())
        .unwrap_or(false)
}

/// Publish the promoted host set into the DNS-plane cloak. Idempotent — the roster republishes on every
/// arm, and an unchanged set simply overwrites itself. Input is normalized + sorted + deduped here so
/// callers cannot publish an unsorted set that would break the `binary_search` consult.
pub fn publish_promoted_cloak(hosts: Vec<String>) {
    let mut sorted: Vec<String> = hosts
        .into_iter()
        .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
        // TWO exclusions, both belonging here at the one place the DNS-plane set is written, because
        // every caller recomputes its roster from the discovery ledger and knows about neither:
        //   · a host that already refused our leaf must not be resurrected by the next arm;
        //   · a host the STATIC corpus already covers must never also sit in the promoted set, or
        //     `cloaking_rules` emits two rules for one name (caught by the one-rule-per-host test).
        .filter(|h| {
            !h.is_empty()
                && !is_tls_distrusted(h)
                && cdn_hosts().binary_search(&h.as_str()).is_err()
        })
        .collect();
    sorted.sort_unstable();
    sorted.dedup();
    let any = !sorted.is_empty();
    if let Ok(mut slot) = PROMOTED_CLOAK.write() {
        *slot = sorted;
        // Set the gate only AFTER the set is in place, so a reader that observes `true` always finds a
        // populated set; clearing it first likewise never leaves a stale `true` over an empty set.
        PROMOTED_ANY.store(any, std::sync::atomic::Ordering::Relaxed);
    }
}

/// True iff `host` is cloaked because DISCOVERY promoted it, rather than because this build ships it.
/// The routing layer needs the distinction: a corpus host with an uncovered path must stay fail-closed
/// (its coverage is known, so a miss is a real miss), while a promoted host has no map at all and takes
/// the absorb lane instead. Normalizes the host the same way the cloak consult does.
pub fn is_promoted_host(host: &str) -> bool {
    let t = host.trim().trim_end_matches('.');
    if t.is_empty() {
        return false;
    }
    if t.bytes().any(|b| b.is_ascii_uppercase()) {
        is_promoted_cloak_host(&t.to_ascii_lowercase())
    } else {
        is_promoted_cloak_host(t)
    }
}

/// How many hosts the promoted cloak lane currently carries (the dashboard's absorbed-host tally).
pub fn promoted_cloak_count() -> usize {
    if !PROMOTED_ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return 0;
    }
    PROMOTED_CLOAK.read().map(|s| s.len()).unwrap_or(0)
}

/// ★ CLOAK⊆SERVABLE (LIVE PATH) — the hosts Centauri has published as actually servable.
///
/// # Why a second gate exists
///
/// Fixing [`cloaking_rules`] alone was NOT enough, and I caught that before claiming otherwise. The
/// dnscrypt rules FILE is one path; the LIVE sinkhole decision is another —
/// `resolver/mod.rs` consults [`is_cdn_host`] (pure corpus membership) and answers the tun sentinel.
/// A store-derived rules file with a corpus-driven live gate would have kept sinkholing all 26 hosts
/// while the file honestly listed one.
///
/// So the live gate must ask the same question the file does: **is this host servable?**
///
/// Empty ⇒ nothing is cloaked. That is FAIL-CLOSED and it is the correct direction: a CDN asset
/// fetched from the real CDN is a working page, while a sinkholed asset with no local content is a
/// dead connection. Centauri's "absorb once, serve forever" thesis requires the absorb to have
/// HAPPENED; until it has, there is nothing to serve and no reason to intercept.
static SERVABLE_CLOAK: std::sync::RwLock<Vec<String>> = std::sync::RwLock::new(Vec::new());

/// Gate for [`SERVABLE_CLOAK`] so the empty case costs one atomic load on the hot DNS path.
static SERVABLE_ANY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether the Centauri device CA is a trust anchor the CLIENT will actually accept.
///
/// Defaults to **false**, and the default is the point: an un-set flag must mean "do not
/// intercept", so forgetting to publish trust can only cost a dark optimisation, never a dropped
/// connection. See `is_servable_cloak_host` for the measurement that forced this
/// (`centauri_cloak_sinkholes = 3`, `cloak_actions = 0`).
static CLOAK_TLS_TRUSTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Publish whether the Centauri CA is client-trusted. Only a POSITIVE, externally verified
/// observation may pass `true` here — never an assumption that installation succeeded.
pub fn publish_cloak_tls_trust(trusted: bool) {
    CLOAK_TLS_TRUSTED.store(trusted, std::sync::atomic::Ordering::Relaxed);
}

/// Whether the cloak is currently permitted to intercept at all (the trust conjunct alone).
/// Exposed so a dashboard can explain a dark offline-CDN instead of leaving it mysterious.
pub fn cloak_tls_trusted() -> bool {
    CLOAK_TLS_TRUSTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Publish the servable cloak set — called by Centauri once it knows what its store holds.
///
/// Idempotent and total: the passed set REPLACES the previous one, so a shrinking store immediately
/// stops cloaking what it can no longer serve (a stale larger set is exactly the defect).
pub fn publish_servable_cloak(hosts: &[String]) {
    if let Ok(mut slot) = SERVABLE_CLOAK.write() {
        slot.clear();
        slot.extend(hosts.iter().filter(|h| !h.is_empty()).cloned());
        slot.sort_unstable();
        slot.dedup();
        let any = !slot.is_empty();
        drop(slot);
        SERVABLE_ANY.store(any, std::sync::atomic::Ordering::Relaxed);
    }
}

/// How many hosts the live servable-cloak gate carries (0 ⇒ the gate cloaks NOTHING).
pub fn servable_cloak_count() -> usize {
    if !SERVABLE_ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return 0;
    }
    SERVABLE_CLOAK.read().map(|s| s.len()).unwrap_or(0)
}

/// **The live cloak verdict: corpus member AND servable.** This is `CloakSound` at the datapath —
/// the intersection proved sound as `live_gate_is_sound` in `Proofs/CloakServable.lean`.
///
/// Normalization matches [`is_cdn_host`] exactly (trim, strip the FQDN dot, lowercase only when an
/// uppercase byte is actually present) so the two gates can never disagree on the SAME name — a
/// normalization split would reintroduce the defect for hosts differing only in case.
pub fn is_servable_cloak_host(host: &str) -> bool {
    // ★ THE FOURTH CONJUNCT — TLS TRUST (checkpoint 59, measured).
    //
    // A cloak redirects the browser to our loopback, where Centauri TERMINATES TLS with a cert
    // signed by the device CA at `files/centauri_ca/centauri-ca.pem`. That file is app-private
    // (mode 0600, owned by the app) and is a trust anchor for NOTHING. So for an https host a
    // cloak cannot end any other way than a failed handshake: measured
    // `centauri_cloak_sinkholes = 3` with `cloak_actions = 0` — three connections redirected,
    // ZERO served. That is three dropped connections caused by a pillar being armed, which the
    // goal line rightly calls a bug and never "expected".
    //
    // Servability was necessary but never sufficient: holding the BYTES is worthless if we
    // cannot present a cert the client will accept. The gate now carries trust as well, and
    // defaults to UNTRUSTED so the safe state is the default rather than something to remember.
    // Consequence, stated plainly: until the CA is installed as a user trust anchor the
    // offline-CDN does not intercept. That is the correct trade — a dark optimisation beats a
    // black hole, and the fix is a real one (install the anchor) not a suppression.
    if !CLOAK_TLS_TRUSTED.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    if !SERVABLE_ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    if !is_cdn_host(host) {
        return false;
    }
    let t = host.trim().trim_end_matches('.');
    let owned;
    let key: &str = if t.bytes().any(|b| b.is_ascii_uppercase()) {
        owned = t.to_ascii_lowercase();
        &owned
    } else {
        t
    };
    SERVABLE_CLOAK
        .read()
        .map(|s| s.binary_search(&key.to_string()).is_ok())
        .unwrap_or(false)
}

/// ★ CLOAK⊆SERVABLE — the promoted cloak hosts, as a snapshot.
///
/// A promoted host earned its cloak by being **absorbed**: its bytes are in the store, so it is
/// servable by construction. It therefore belongs in the derived cloak set alongside the manifest
/// hosts, and dropping it would silently disarm the discovery lane.
///
/// This accessor exists because `servable_cloaked_hosts` (object.rs) must union the two lanes; without
/// it the manifest-only filter would remove every runtime-absorbed host from the cloak block — a
/// regression my own `a_complete_store_reproduces_the_corpus_block_byte_for_byte` test caught before
/// this reached a device.
pub fn promoted_cloak_hosts() -> Vec<String> {
    if !PROMOTED_ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return Vec::new();
    }
    PROMOTED_CLOAK.read().map(|s| s.clone()).unwrap_or_default()
}

/// The known privacy-hostile fingerprinting libraries Centauri HARD-BLOCKS — a request resolving to one of
/// these is denied outright (never served from cache, never self-filled from upstream, never leaked): the
/// fingerprinter must not load at all. Each entry is the `host` + base-`path` prefix of a known
/// FingerprintJS / ClientJS distribution, GROUND_TRUTH'd from the studied corpus' request blocklist. This is
/// our own table + gate — the New-Born equivalent of the studied request-blocklist — matched
/// case-insensitively by prefix the same way [`is_cdn_host`] consults the cloak set.
const BLOCKED_FINGERPRINTERS: &[&str] = &[
    "cdn.jsdelivr.net/npm/@fingerprintjs/",
    "cdnjs.cloudflare.com/ajax/libs/fingerprintjs/",
    "cdnjs.cloudflare.com/ajax/libs/fingerprintjs2/",
    "cdnjs.cloudflare.com/ajax/libs/clientjs/",
];

/// True iff a `host` + `path` request targets a known fingerprinting library Centauri hard-blocks. The serve
/// authorization consults this FIRST — before any catalog / cache / leak decision — so a fingerprinter is
/// denied fail-closed: it is never served locally AND never leaked upstream; it simply does not load. `host`
/// is normalized the same way [`is_cdn_host`] normalizes it (trim, strip a trailing FQDN dot, lowercase); the
/// `path` is lowercased for the prefix probe.
pub fn is_blocked_fingerprinter(host: &str, path: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    let probe = format!("{}{}", h, path.to_ascii_lowercase());
    BLOCKED_FINGERPRINTERS
        .iter()
        .any(|prefix| probe.starts_with(prefix))
}

#[cfg(test)]
mod fingerprinter_gate_tests {
    use super::is_blocked_fingerprinter;

    #[test]
    fn blocks_each_known_fingerprinter() {
        assert!(is_blocked_fingerprinter(
            "cdnjs.cloudflare.com",
            "/ajax/libs/fingerprintjs/3.4.2/fp.min.js"
        ));
        assert!(is_blocked_fingerprinter(
            "cdnjs.cloudflare.com",
            "/ajax/libs/fingerprintjs2/2.1.4/fingerprint2.min.js"
        ));
        // ClientJS is published with mixed case in the CDN path — the gate is case-insensitive.
        assert!(is_blocked_fingerprinter(
            "cdnjs.cloudflare.com",
            "/ajax/libs/ClientJS/0.2.1/client.min.js"
        ));
        assert!(is_blocked_fingerprinter(
            "cdn.jsdelivr.net",
            "/npm/@fingerprintjs/fingerprintjs@3/dist/fp.min.js"
        ));
    }

    #[test]
    fn passes_benign_libraries_on_the_same_hosts() {
        assert!(!is_blocked_fingerprinter(
            "cdnjs.cloudflare.com",
            "/ajax/libs/jquery/3.7.1/jquery.min.js"
        ));
        assert!(!is_blocked_fingerprinter(
            "ajax.googleapis.com",
            "/ajax/libs/angularjs/1.8.3/angular.min.js"
        ));
    }

    #[test]
    fn normalizes_host_case_trailing_dot_and_whitespace() {
        assert!(is_blocked_fingerprinter(
            "  CDNJS.CLOUDFLARE.COM.  ",
            "/ajax/libs/fingerprintjs/x"
        ));
        assert!(!is_blocked_fingerprinter("", "/ajax/libs/fingerprintjs/x"));
    }
}

/// The TUN-routable sentinel IP a cloaked CDN host resolves to — dnscrypt-proxy answers this instead of
/// the real CDN, and the ARMED netstack forwarder splices sentinel flows into the in-app mirror.
///
/// ★ #65 seam — WHY NOT `127.0.0.1` (the old value): loopback flows never enter the tun, the mirror binds
/// an EPHEMERAL loopback port (`:80` is unbindable no-root), so cloaked fetches connected `127.0.0.1:80`,
/// found nothing listening, and died — CDN SAW stayed 0 forever despite an ARMED mirror (the field bug).
/// `10.1.10.3` sits beside the tun address (`vpn4` default `10.1.10.1/32`, VpnBuilder.kt) and the virtual
/// DNS (`VPN_VIRTUAL_DNS_IP = 10.1.10.2`, same file) — under the ARMED full-capture route posture every
/// sentinel packet is guaranteed INTO the tun, where `forwarder/run.rs` redirects it to the mirror's real
/// bound port. Cloak arming is therefore forwarder-ARMED-gated (DORMANT routes only carry `10.1.10.2/32`;
/// a sentinel answer would escape to the real network and blackhole).
pub const CLOAK_SENTINEL_IP: &str = "10.1.10.3";

/// Marker that opens the Centauri-managed block in `cloaking-rules.txt` (a writer splices between markers so
/// it never clobbers the user's own rules).
pub const CLOAK_BLOCK_BEGIN: &str =
    "# BEGIN Centauri LocalCDN cloak (auto-generated — do not edit between markers)";
/// Marker that closes the Centauri-managed block.
pub const CLOAK_BLOCK_END: &str = "# END Centauri LocalCDN cloak";

/// Generate the dnscrypt-proxy `cloaking-rules.txt` block for the LocalCDN→Centauri opt-out binding: one
/// `<host> 10.1.10.3` rule per [`cdn_hosts`] entry, fenced by [`CLOAK_BLOCK_BEGIN`]/[`CLOAK_BLOCK_END`].
///
/// dnscrypt-proxy's `cloaking-rules.txt` format is `<pattern> <address>` per line (a domain → an IP/name;
/// `#` begins a comment) — the file the app manages at `app_data/dnscrypt-proxy/cloaking-rules.txt`. Each
/// listed CDN host is answered as [`CLOAK_SENTINEL_IP`] so the request rides the tun into the ARMED
/// forwarder, which splices it to the in-app mirror instead of the real CDN (the CDN sees ≤ 1 request —
/// the crown). This produces the rules TEXT only; WRITING it into
/// the live cloaking-rules file + the dnscrypt reload is the **arming** step (Expert-flag-gated, default-off),
/// kept separate so generating the rules never changes DNS behaviour on its own (reversible-by-construction).
/// The BEGIN/END fence lets a writer replace just the Centauri block in a file that also holds user rules.
pub fn cloaking_rules() -> String {
    let hosts = cdn_hosts();
    // header + one line per host + footer, joined by '\n', trailing newline.
    let mut out = String::with_capacity(
        CLOAK_BLOCK_BEGIN.len() + CLOAK_BLOCK_END.len() + hosts.len() * 40 + 8,
    );
    out.push_str(CLOAK_BLOCK_BEGIN);
    out.push('\n');
    for h in hosts {
        out.push_str(h);
        out.push(' ');
        out.push_str(CLOAK_SENTINEL_IP);
        out.push('\n');
    }
    // ★ #65 — the promoted discovered hosts ride in the SAME fenced block as the corpus. A promoted
    // host is cloaked exactly like a shipped one: same sentinel, same fence, so a writer replacing the
    // block always writes the complete live cloak rather than the static half of it.
    if PROMOTED_ANY.load(std::sync::atomic::Ordering::Relaxed) {
        if let Ok(promoted) = PROMOTED_CLOAK.read() {
            for h in promoted.iter() {
                out.push_str(h);
                out.push(' ');
                out.push_str(CLOAK_SENTINEL_IP);
                out.push('\n');
            }
        }
    }
    out.push_str(CLOAK_BLOCK_END);
    out.push('\n');
    out
}

/// ★ CLOAK⊆SERVABLE — the fenced cloak block for EXACTLY the hosts given, in place of the whole
/// [`cdn_hosts`] corpus.
///
/// # Why this exists
///
/// [`cloaking_rules`] emits one line per corpus host **unconditionally**, while the loopback can only
/// answer a host the content store actually HOLDS an asset for. The two sets were never forced to
/// agree, and on a real AVD run they did not: **26 distinct hosts** were answered `CLOAK` while the
/// live manifest held **4 entries, exactly ONE of them a real CDN host**. So 25 of 26 sinkholed hosts
/// were pointed at a server with nothing to give them — the browser asked for a sub-resource, got no
/// content, and the connection closed with no response.
///
/// That is the cascading `ERR_CONNECTION_CLOSED` shape, and it hid for weeks for a precise reason: the
/// cloaked hosts are CDN **sub-resources** of ordinary pages (`cdn.jsdelivr.net`, `assets.ubuntu.com`,
/// …), never the page URLs themselves. A corpus of page URLs shows **zero** overlap with the cloak
/// set. The page loads; its assets die; every log line points at a page that was fine.
///
/// # The invariant
///
/// `∀ host, cloaked(host) → servable(host)` — proved in `D:/Lean/proofs/Proofs/CloakServable.lean`:
///
/// * `derived_is_always_sound` — filtering candidates by the store makes soundness UNCONDITIONAL.
/// * `derived_never_grows` — the filter only ever REMOVES a sinkhole, so this can never intercept a
///   host that previously worked.
/// * `derived_keeps_every_servable_candidate` — and it drops nothing servable: maximal, not timid.
/// * `fix_is_a_noop_on_a_complete_store` — with a complete store this is byte-identical to the old
///   behaviour, so no working cloak is lost.
/// * `cloak_everything_unsound_iff_something_missing` — ONE absent asset is necessary AND sufficient
///   to break the old rule. It was never "mostly fine".
///
/// Callers pass the hosts the store can serve; this function does not guess. Generating the text is
/// still separate from writing it (the arming step), exactly as [`cloaking_rules`] is.
pub fn cloaking_rules_for<S: AsRef<str>>(servable_hosts: &[S]) -> String {
    let mut out = String::with_capacity(
        CLOAK_BLOCK_BEGIN.len() + CLOAK_BLOCK_END.len() + servable_hosts.len() * 40 + 8,
    );
    out.push_str(CLOAK_BLOCK_BEGIN);
    out.push('\n');
    // Sort + dedup so the block is byte-stable across runs (a churning file would defeat the
    // BEGIN/END fence's purpose and force a needless dnscrypt reload).
    let mut hosts: Vec<&str> = servable_hosts.iter().map(|h| h.as_ref()).collect();
    hosts.sort_unstable();
    hosts.dedup();
    for h in hosts {
        // An empty host would emit a bare sentinel line and cloak NOTHING while looking armed.
        if h.is_empty() {
            continue;
        }
        out.push_str(h);
        out.push(' ');
        out.push_str(CLOAK_SENTINEL_IP);
        out.push('\n');
    }
    out.push_str(CLOAK_BLOCK_END);
    out.push('\n');
    out
}

pub fn resolve(host: &str, path: &str, maps: &[ResourceMap]) -> Option<Resolution> {
    let host = host.trim().to_ascii_lowercase();
    for m in maps {
        if host != m.host {
            continue;
        }
        let Some(rest) = path.strip_prefix(m.base_path) else {
            continue;
        };
        // rest is "<version>/<file...>"; the first segment is the requested version, the tail is the file.
        let mut segs = rest.splitn(2, '/');
        let requested = segs.next().unwrap_or("");
        let file = segs.next().unwrap_or("");
        if requested.is_empty() {
            continue;
        }
        let (served, sub) = best_bundled_version(requested, m.bundled_versions)?;
        return Some(Resolution {
            library: m.library.to_string(),
            requested_version: requested.to_string(),
            served_version: served.to_string(),
            file: file.to_string(),
            substitution: sub,
        });
    }
    None
}

/// Reconstruct the ONE allowed upstream leak target for a watched CDN request over [`FULL_MAPS`] — the SERVED
/// (post-fallback) version's REAL bytes on the ORIGINAL CDN host. This is the fetch-on-miss twin of [`resolve`]:
/// it walks the SAME maps with the SAME [`best_bundled_version`] fallback, so the `served_version` it feeds into
/// the URL agrees BYTE-FOR-BYTE with the `served_version` that [`Resolution::canonical_name`] hands the
/// signature gate — the fetched bytes therefore hash against the exact signed catalog entry the resolve keyed
/// on. `None` when the host is unwatched, the path has no `<version>/<file>` shape (empty version OR empty
/// file — a directory hit is never fetchable), or no same-major bundled version exists. The fetch-once seam in
/// [`super::server::run_shared`] escalates a `CacheMiss` through this and nowhere else, so an unmapped host can
/// NEVER become a leak. https-only is re-enforced downstream in [`super::serve::fetch_once`].
pub fn upstream_url_for(host: &str, path: &str) -> Option<String> {
    let host = host.trim().to_ascii_lowercase();
    for m in super::localcdn_maps::FULL_MAPS {
        if host != m.host {
            continue;
        }
        let Some(rest) = path.strip_prefix(m.base_path) else {
            continue;
        };
        let mut segs = rest.splitn(2, '/');
        let requested = segs.next().unwrap_or("");
        let file = segs.next().unwrap_or("");
        // A leak target needs BOTH a concrete version and a concrete file — a bare `<lib>/` directory hit
        // (empty file) is served locally-or-503, never fetched.
        if requested.is_empty() || file.is_empty() {
            continue;
        }
        let (served, _sub) = best_bundled_version(requested, m.bundled_versions)?;
        return Some(super::serve::upstream_url(
            m.host,
            m.base_path,
            served,
            file,
        ));
    }
    None
}

// ===========================================================================================================
// #134 slice 1 — THE CROSSED RESOLVER (the new ORIGINAL, not a port).
//
// LocalCDN's resolver stops at a path/name with NO verification and NO trust. The bare Centauri [`resolve`]
// above stops at a name STRING — the content-hash lookup happens DOWNSTREAM, divorced, inside the server's
// `serve_name`. The cross hoists the **content address** + a **trust band** INTO the resolution, so the
// resolver becomes the single authority: a CDN URL binds to *the exact signed bytes* ([`ContentHash`]) at a
// trust band (the Beast `trust.rs` scoring crossed in), gated by *what the signed catalog actually covers*
// (honest fallback — never commits to a version it cannot serve). The serve then collapses to
// `cache.get(content_hash)` — no name round-trip, free per-serve content-address verification. No source had
// this: LocalCDN is path-keyed + unverified; the bare resolver is name-string-keyed; THIS is content-hash-
// keyed + trust-scored + coverage-honest at the resolve point. Original Rust — the FORM was studied, the
// thing developed is new.
// ===========================================================================================================

/// The catalog freshness epoch (epoch-days) the resolution's recency rides on. The `TCAT` header reserves a
/// u64 for exactly this (`catalog.rs:33`, currently must-be-0), so the verified catalog exposes no epoch yet
/// → `0` = unknown → neutral recency (the Beast `recency_pct` returns 100%). The axis is WIRED here so it
/// lights up the instant a catalog-meta slice supplies a real epoch — no behavioural change until then.
const CATALOG_EPOCH_UNKNOWN: u32 = 0;

/// A CROSSED resolution: the LocalCDN-form URL→(library, served version, file) decision resolved THROUGH the
/// signature-verified catalog to a BLAKE2b [`ContentHash`] (the cache key) and a trust band.
///
/// Where [`Resolution`] carries only the version decision, this carries the **content address** (so the serve
/// is `cache.get(content_hash)` with no name round-trip, and serving on a key match IS the per-serve content-
/// address verification — LocalCDN does NO per-serve check, so the cross is strictly stronger) and the
/// **trust** verdict (`SIGNED_FLOOR..=100` — every catalog-resolved asset is signature-proof by construction,
/// the substitution risk + CDN-host corroboration + catalog recency place it within the signed band).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressedResolution {
    /// The LocalCDN-form version decision (the FORM the study revealed — reused, the cross builds ON it).
    pub resolution: Resolution,
    /// The signed-catalog content address of the SERVED asset — the cache key. The serve collapses to
    /// `cache.get(content_hash)`; a key match is the free per-serve content-address verify.
    pub content_hash: ContentHash,
    /// Distinct mapped CDN hosts that corroborate this canonical asset (≥ 1) — the trust popcount analog of
    /// `trust.rs` source corroboration, but over CDN hosts in the map table instead of blocklist sources.
    pub corroboration: u32,
    /// Resolution trust `SIGNED_FLOOR..=100` — always in the signed band (the bytes are minisign-pinned),
    /// differentiated within it by substitution quality, corroboration, and catalog recency.
    pub trust: u8,
}

/// Per-substitution base quality (0..=100, pre-recency/corroboration). Exact bytes are top; a `SafeNewer`
/// carries a small penalty; a `RiskyOlder` a larger one. ([`Substitution::Incompatible`] can never reach
/// here — [`best_bundled_version`] never returns it — but it floors defensively.)
fn substitution_quality(sub: Substitution) -> u16 {
    match sub {
        Substitution::Exact => 100,
        Substitution::SafeNewer => 88,
        Substitution::RiskyOlder => 72,
        Substitution::Incompatible => SIGNED_FLOOR as u16,
    }
}

/// The resolution trust score `SIGNED_FLOOR..=100` — the Beast band-separation philosophy (`trust.rs`)
/// applied to a dimension the blocklist never had: **substitution risk**.
///
/// The signature gate is ALWAYS satisfied (a [`Catalog`] VALUE is signature-proof by construction —
/// `catalog.rs` parse-don't-validate), so every catalog-resolved asset is in the signed band; this only
/// places it WITHIN `SIGNED_FLOOR..=100`:
/// - **substitution** is the in-band differentiator — `Exact` tops, `SafeNewer`/`RiskyOlder` penalize;
/// - **recency** rides on the catalog freshness epoch (reserved-0 today → neutral, the wired-dormant axis),
///   reusing the Beast [`recency_pct`] decay verbatim;
/// - **corroboration** adds a bounded, capped bonus per extra mapped CDN host ([`CORR_STEP`]/[`CORR_CAP`]).
///
/// Always `>= SIGNED_FLOOR`, monotone-nondecreasing in `corroboration`, and strictly lower for a `RiskyOlder`
/// serve than an `Exact` one at equal corroboration — the properties the slice's tests pin.
pub fn resolution_trust(
    sub: Substitution,
    corroboration: u32,
    now_days: u32,
    catalog_epoch_days: u32,
) -> u8 {
    let quality = substitution_quality(sub);
    let recency = quality * recency_pct(catalog_epoch_days, now_days) / 100;
    let corr_bonus = (corroboration.saturating_sub(1) as u16 * CORR_STEP).min(CORR_CAP);
    let raw = (recency + corr_bonus).min(100) as u8;
    raw.max(SIGNED_FLOOR)
}

/// How many distinct CDN hosts in `maps` corroborate a `(library, served_version)` — the cross's trust
/// corroboration source. jQuery 3.6.0 mapped from `ajax.googleapis.com` AND `cdnjs.cloudflare.com` = 2.
pub fn corroboration_for(library: &str, served_version: &str, maps: &[ResourceMap]) -> u32 {
    // `manual_contains` here is a false positive: the slice element is `&'static str` while `served_version`
    // is a borrowed `&str` (shorter lifetime), so `[&'static str]::contains` (which needs a `&&'static str`
    // needle) cannot be formed from `served_version` — the `iter().any` value-compare is the compiling form.
    #[allow(clippy::manual_contains)]
    let mut hosts: Vec<&'static str> = maps
        .iter()
        .filter(|m| m.library == library && m.bundled_versions.iter().any(|&v| v == served_version))
        .map(|m| m.host)
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    hosts.len() as u32
}

/// Resolve a CDN `(host, path)` to an [`AddressedResolution`] against the FULL map table
/// ([`super::localcdn_maps::FULL_MAPS`]) and the signature-verified `catalog` — the shipping crossed-resolver
/// entry point. `now_days` is the epoch-day clock for the recency axis (pass `0` to treat as fresh).
pub fn resolve_addressed(
    host: &str,
    path: &str,
    catalog: &Catalog,
    now_days: u32,
) -> Option<AddressedResolution> {
    resolve_addressed_in(
        host,
        path,
        super::localcdn_maps::FULL_MAPS,
        catalog,
        now_days,
    )
}

/// The table-injected crossed-resolver core (the seed table drives the unit tests; [`resolve_addressed`]
/// wraps it over `FULL_MAPS`) — the [`resolve`]/[`resolve_full`] split, extended with the content-address +
/// trust cross.
///
/// The load-bearing difference from [`resolve`]: the candidate version universe is the bundled set INTERSECT
/// the versions the SIGNED catalog actually authorizes for this `(library, file)` — the **coverage gate**.
/// `best_bundled_version` runs over the COVERED candidates only, so the resolver NEVER commits to a version
/// it cannot serve. A mapped-but-uncatalogued host resolves to `None` here (no `AddressedResolution`), never
/// a name that 404-blackholes downstream once the host is cloaked. That is the honest inversion the bare
/// resolver lacks (it picks a `served_version` from a static list divorced from real coverage).
pub fn resolve_addressed_in(
    host: &str,
    path: &str,
    maps: &[ResourceMap],
    catalog: &Catalog,
    now_days: u32,
) -> Option<AddressedResolution> {
    let host = host.trim().to_ascii_lowercase();
    for m in maps {
        if host != m.host {
            continue;
        }
        let Some(rest) = path.strip_prefix(m.base_path) else {
            continue;
        };
        let mut segs = rest.splitn(2, '/');
        let requested = segs.next().unwrap_or("");
        let file = segs.next().unwrap_or("");
        if requested.is_empty() {
            continue;
        }
        // THE COVERAGE GATE — the candidate set is the bundled versions the signed catalog actually covers.
        let covered: Vec<&'static str> = m
            .bundled_versions
            .iter()
            .copied()
            .filter(|v| {
                catalog
                    .content_hash_for(&format!("{}/{}/{}", m.library, v, file))
                    .is_some()
            })
            .collect();
        let (served, sub) = best_bundled_version(requested, &covered)?;
        let resolution = Resolution {
            library: m.library.to_string(),
            requested_version: requested.to_string(),
            served_version: served.to_string(),
            file: file.to_string(),
            substitution: sub,
        };
        // The content address is now CARRIED by the resolution — `covered` guaranteed a Some, but resolve
        // through the canonical name (the catalog's exact key) so the seam contract is asserted, not assumed.
        let content_hash = catalog.content_hash_for(&resolution.canonical_name())?;
        let corroboration = corroboration_for(m.library, served, maps);
        let trust = resolution_trust(sub, corroboration, now_days, CATALOG_EPOCH_UNKNOWN);
        return Some(AddressedResolution {
            resolution,
            content_hash,
            corroboration,
            trust,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The promoted cloak set is process-global, so any test that writes it must hold this lock —
    /// otherwise a publish here changes the host count another test is asserting on, in parallel.
    static CLOAK_SET: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A client refusing our leaf must UN-CLOAK the host, and a later arm must not resurrect it.
    /// Uses a host no other test touches, because the ledger and the promoted set are process-global.
    #[test]
    fn tls_refusal_uncloaks_the_host_and_survives_a_republish() {
        let _g = CLOAK_SET.lock().unwrap_or_else(|e| e.into_inner());
        // BOTH ledger tests must hold the SAME lock. Holding only `CLOAK_SET` here guarded the promoted
        // set but NOT `TLS_DISTRUST`/`DISTRUST_ANY`, so `refusal_survives_a_cold_start` — which wipes both
        // to simulate process death — could land between the `note_tls_rejected` below and its assert and
        // erase the very fact under test. Two different mutexes are not mutual exclusion.
        let _serial = DISTRUST_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        const H: &str = "distrust-probe.example.net";
        assert!(!is_cdn_host(H), "probe host must start uncloaked");

        publish_promoted_cloak(vec![H.to_string()]);
        assert!(is_cdn_host(H), "promotion must cloak it on the DNS plane");

        note_tls_rejected(H);
        assert!(is_tls_distrusted(H));
        assert!(
            !is_cdn_host(H),
            "a refused leaf must hand the name back to the real CDN"
        );

        // The roster is recomputed from the discovery ledger on every arm and knows nothing about
        // refusals — republishing it must NOT put the host back on the DNS plane.
        publish_promoted_cloak(vec![H.to_string()]);
        assert!(
            !is_cdn_host(H),
            "a re-arm must not resurrect a refused host"
        );

        // ★ #78 — the SERVE-MISS twin must ride this exact ledger, not a parallel one. Different
        // cause (our catalog had nothing to give) but byte-identical remedy: hand the name back.
        // Asserted here so the shared-ledger decision cannot silently rot into two divergent
        // recovery paths — the failure #79 was closed on.
        const U: &str = "challenges.cloudflare.com";
        publish_promoted_cloak(vec![H.to_string(), U.to_string()]);
        assert!(is_cdn_host(U), "the probe host must start cloaked");
        note_unservable(U);
        assert!(
            is_tls_distrusted(U),
            "#78 must land in the ONE distrust ledger"
        );
        assert!(
            !is_cdn_host(U),
            "a host we cloaked but cannot serve must return to the real CDN"
        );
        publish_promoted_cloak(vec![H.to_string(), U.to_string()]);
        assert!(
            !is_cdn_host(U),
            "a re-arm must not resurrect an unservable host"
        );

        // Case folding travels the same path.
        assert!(!is_cdn_host("DISTRUST-PROBE.EXAMPLE.NET"));

        publish_promoted_cloak(Vec::new()); // restore the shared set for every other test
        let _ = clear_tls_distrust();
    }

    /// ★ #20 — a refusal is a permanent fact about a client, so it must survive process death.
    ///
    /// The defect this pins: `TLS_DISTRUST` was RAM-only, so the forwarder (VPN service process)
    /// recorded refusals the dashboard's engine could never see, AND every restart re-cloaked the
    /// host and broke the refusing app again. Measured on the AVD as `TLS failed = 7` against a
    /// distrust tile that stayed dark.
    /// Both distrust tests drive the SAME process-wide statics (`TLS_DISTRUST`, `DISTRUST_ANY`,
    /// `DISTRUST_STORE`) and one of them deliberately wipes RAM, so they must not interleave — the
    /// `CLOAK_SET` race-free structural law, applied to the ledger.
    static DISTRUST_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn refusal_survives_a_cold_start() {
        let _serial = DISTRUST_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        const H: &str = "distrust-durable-probe.example.net";
        let dir = std::env::temp_dir().join("torta-distrust-durability");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join("centauri-tls-distrust.tsv"));

        arm_tls_distrust_store(&dir);
        note_tls_rejected(H);
        assert!(is_tls_distrusted(H), "the live process must record it");

        // Wipe RAM the way process death does — the file is the ONLY thing that carries over.
        DISTRUST_ANY.store(false, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut set) = TLS_DISTRUST.write() {
            set.clear();
        }
        assert!(!is_tls_distrusted(H), "the cold engine starts empty");

        arm_tls_distrust_store(&dir);
        assert!(
            is_tls_distrusted(H),
            "re-arming must rehydrate the refusal, or the app that refused us breaks again"
        );
        assert!(
            tls_distrust_count() >= 1,
            "the dashboard's count must see it"
        );

        let _ = clear_tls_distrust();
        let _ = std::fs::remove_file(dir.join("centauri-tls-distrust.tsv"));
    }

    /// ★ #21 — the BOOT SEQUENCE, not just the store. `refusal_survives_a_cold_start` was green on a tree
    /// where the device still lost the ledger on every start: it rehydrates and asserts, but never performs
    /// the TLS arm that really follows a rehydrate. `centauri_tls_arm` forgave unconditionally (#16, written
    /// when the set was RAM-only), so the restored ledger was wiped seconds after `arm_tls_distrust_store`
    /// rebuilt it. Measured on the AVD: the file fell to 69 bytes — header, no hosts — across one cold
    /// start, and the panel read `43 watched · 11 discovered` with the `untrusted` suffix absent.
    #[test]
    fn reloading_the_ca_at_boot_does_not_forgive_the_ledger() {
        let _serial = DISTRUST_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        const H: &str = "distrust-boot-arm-probe.example.net";
        let dir = std::env::temp_dir().join("torta-distrust-boot-arm");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join("centauri-tls-distrust.tsv"));

        // First run: no persisted pair, so the CA is minted and handed back for the app to store.
        let material = crate::centauri_tls_arm(None, None).expect("a fresh mint must arm");

        arm_tls_distrust_store(&dir);
        note_tls_rejected(H);
        assert!(is_tls_distrusted(H), "the refusal must register");

        // Every later boot re-arms from that SAME persisted pair. The user's trust situation has not
        // changed, so the refusal still describes something true and must survive.
        let _ = crate::centauri_tls_arm(
            Some(material.cert_pem.clone()),
            Some(material.key_pem.clone()),
        );
        assert!(
            is_tls_distrusted(H),
            "a reload-arm must not forgive — this is the #21 wipe that emptied the ledger every boot"
        );
        assert!(
            tls_distrust_count() >= 1,
            "the dashboard count must still see it"
        );

        let _ = clear_tls_distrust();
        let _ = std::fs::remove_file(dir.join("centauri-tls-distrust.tsv"));
    }

    #[test]
    fn substitution_classifies_semver() {
        assert_eq!(substitution("3.6.0", "3.6.0"), Substitution::Exact);
        assert_eq!(substitution("3.6.0", "3.7.1"), Substitution::SafeNewer);
        assert_eq!(substitution("3.6.0", "3.5.1"), Substitution::RiskyOlder);
        assert_eq!(substitution("3.6.0", "4.0.0"), Substitution::Incompatible);
        assert_eq!(substitution("3.6.0", "2.9.9"), Substitution::Incompatible);
    }

    #[test]
    fn best_version_prefers_exact_then_smallest_newer_then_closest_older() {
        // exact present
        assert_eq!(
            best_bundled_version("3.6.0", &["3.5.1", "3.6.0", "3.7.1"]),
            Some(("3.6.0", Substitution::Exact))
        );
        // no exact, same major: smallest compatible upgrade
        assert_eq!(
            best_bundled_version("3.6.5", &["3.5.1", "3.7.1", "3.8.0"]),
            Some(("3.7.1", Substitution::SafeNewer))
        );
        // only older same-major: closest older
        assert_eq!(
            best_bundled_version("3.9.0", &["3.5.1", "3.7.1"]),
            Some(("3.7.1", Substitution::RiskyOlder))
        );
        // only cross-major: never substitute
        assert_eq!(best_bundled_version("3.6.0", &["2.1.0", "4.0.0"]), None);
    }

    #[test]
    fn resolve_maps_googleapis_jquery() {
        let r = resolve(
            "ajax.googleapis.com",
            "/ajax/libs/jquery/3.6.0/jquery.min.js",
            SEED_MAPS,
        )
        .unwrap();
        assert_eq!(r.library, "jquery");
        assert_eq!(r.requested_version, "3.6.0");
        assert_eq!(r.served_version, "3.6.0");
        assert_eq!(r.substitution, Substitution::Exact);
    }

    #[test]
    fn resolve_falls_back_to_newer_bundled() {
        // 3.6.2 isn't bundled; the smallest safe-newer (3.7.1) serves it.
        let r = resolve(
            "ajax.googleapis.com",
            "/ajax/libs/jquery/3.6.2/jquery.js",
            SEED_MAPS,
        )
        .unwrap();
        assert_eq!(r.served_version, "3.7.1");
        assert_eq!(r.substitution, Substitution::SafeNewer);
    }

    #[test]
    fn resolve_captures_the_file_tail() {
        let r = resolve(
            "ajax.googleapis.com",
            "/ajax/libs/jquery/3.6.0/jquery.min.js",
            SEED_MAPS,
        )
        .unwrap();
        assert_eq!(r.file, "jquery.min.js");
        // a nested file tail (with further slashes) is kept whole.
        let r2 = resolve(
            "cdnjs.cloudflare.com",
            "/ajax/libs/twitter-bootstrap/5.3.3/css/bootstrap.min.css",
            SEED_MAPS,
        )
        .unwrap();
        assert_eq!(r2.file, "css/bootstrap.min.css");
    }

    #[test]
    fn canonical_name_is_library_servedversion_file() {
        let r = resolve(
            "ajax.googleapis.com",
            "/ajax/libs/jquery/3.6.0/jquery.min.js",
            SEED_MAPS,
        )
        .unwrap();
        assert_eq!(r.canonical_name(), "jquery/3.6.0/jquery.min.js");
    }

    #[test]
    fn canonical_name_uses_the_served_version_after_fallback() {
        // requested 3.6.2 (not bundled) falls back to served 3.7.1 → the catalog name carries the SERVED
        // version (the entry the brain actually authored), not the requested one.
        let r = resolve(
            "ajax.googleapis.com",
            "/ajax/libs/jquery/3.6.2/jquery.min.js",
            SEED_MAPS,
        )
        .unwrap();
        assert_eq!(r.canonical_name(), "jquery/3.7.1/jquery.min.js");
    }

    #[test]
    fn canonical_name_is_host_independent_dedup() {
        // The SAME library/version/file from two different CDN hosts dedups to ONE canonical catalog name.
        let g = resolve(
            "ajax.googleapis.com",
            "/ajax/libs/jquery/3.6.0/jquery.min.js",
            SEED_MAPS,
        )
        .unwrap();
        let c = resolve(
            "cdnjs.cloudflare.com",
            "/ajax/libs/jquery/3.6.0/jquery.min.js",
            SEED_MAPS,
        )
        .unwrap();
        assert_eq!(g.canonical_name(), c.canonical_name());
    }

    #[test]
    fn resolve_is_host_case_insensitive() {
        assert!(resolve(
            "AJAX.GoogleAPIs.com",
            "/ajax/libs/jquery/3.6.0/jquery.js",
            SEED_MAPS
        )
        .is_some());
    }

    #[test]
    fn full_map_is_populated_and_resolves_real_cdn_urls() {
        // The generated FULL_MAPS carries the whole LocalCDN asset tree (1950 maps over 65 hosts).
        assert!(
            super::super::localcdn_maps::FULL_MAPS.len() > 1000,
            "the full map import is non-trivial"
        );
        // a real jQuery URL on Google Hosted Libraries resolves to the jquery library (3.7.1 is bundled).
        let r = resolve_full(
            "ajax.googleapis.com",
            "/ajax/libs/jquery/3.7.1/jquery.min.js",
        )
        .unwrap();
        assert_eq!(r.library, "jquery");
        assert_eq!(r.served_version, "3.7.1");
        assert_eq!(r.substitution, Substitution::Exact);
        // a cdnjs Bootstrap URL also resolves (cross-CDN coverage); the cdnjs path is /ajax/libs/bootstrap/
        // and 5.3.8 is bundled (GROUND_TRUTH'd from the generated table).
        let b = resolve_full(
            "cdnjs.cloudflare.com",
            "/ajax/libs/bootstrap/5.3.8/css/bootstrap.min.css",
        )
        .unwrap();
        assert_eq!(b.library, "twitter-bootstrap");
        assert_eq!(b.served_version, "5.3.8");
        // an unmapped host is still rejected.
        assert!(
            resolve_full("evil.example.com", "/ajax/libs/jquery/3.7.1/jquery.min.js").is_none()
        );
    }

    #[test]
    fn upstream_url_for_reconstructs_the_served_version_leak_target() {
        // #85 — the fetch-on-miss twin of resolve_full: an exact bundled hit reconstructs the ORIGINAL CDN
        // https URL for the SERVED version, so fetch_once GETs the exact bytes the signed catalog pinned.
        assert_eq!(
            upstream_url_for(
                "ajax.googleapis.com",
                "/ajax/libs/jquery/3.7.1/jquery.min.js"
            ),
            Some("https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js".to_string())
        );
        // host is case-insensitive + carries the SAME served version resolve_full serves under (agreement
        // with canonical_name is the sig-gate invariant).
        let served = resolve_full(
            "cdnjs.cloudflare.com",
            "/ajax/libs/bootstrap/5.3.8/css/bootstrap.min.css",
        )
        .unwrap()
        .served_version;
        assert_eq!(
            upstream_url_for(
                "CDNJS.Cloudflare.COM",
                "/ajax/libs/bootstrap/5.3.8/css/bootstrap.min.css"
            ),
            Some(format!(
                "https://cdnjs.cloudflare.com/ajax/libs/bootstrap/{served}/css/bootstrap.min.css"
            ))
        );
    }

    #[test]
    fn upstream_url_for_is_none_when_unfetchable() {
        // An unwatched host has no reconstructable origin — NEVER a leak target (fail-closed).
        assert!(
            upstream_url_for("evil.example.com", "/ajax/libs/jquery/3.7.1/jquery.min.js").is_none()
        );
        // A bare directory hit (no file segment) is not fetchable — a version with no file → None.
        assert!(upstream_url_for("ajax.googleapis.com", "/ajax/libs/jquery/3.7.1/").is_none());
        assert!(upstream_url_for("ajax.googleapis.com", "/ajax/libs/jquery/3.7.1").is_none());
        // A watched host but an unmapped library path (no base_path matches) → None, never a leak.
        assert!(upstream_url_for(
            "ajax.googleapis.com",
            "/ajax/libs/not-a-real-lib/9.9.9/x.js"
        )
        .is_none());
    }

    #[test]
    fn cdn_hosts_is_sorted_deduped_and_covers_the_majors() {
        let hosts = cdn_hosts();
        assert!(
            hosts.len() > 40,
            "the cloak host set spans the LocalCDN CDN mirrors (~65)"
        );
        // sorted + deduped (the binary_search precondition the memoized set must never violate)
        let mut sorted = hosts.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(hosts, sorted, "cdn_hosts() is sorted + de-duplicated");
        // D17 memoization: two reads return the SAME static set (pointer-stable, built once).
        assert!(
            std::ptr::eq(hosts, cdn_hosts()),
            "cdn_hosts() is memoized — one build per process, no per-call rebuild"
        );
        // the two majors are present
        assert!(hosts.contains(&"ajax.googleapis.com"));
        assert!(hosts.contains(&"cdnjs.cloudflare.com"));
    }

    #[test]
    fn is_cdn_host_normalizes_and_rejects_unknowns() {
        assert!(is_cdn_host("ajax.googleapis.com"));
        assert!(
            is_cdn_host("CDNJS.Cloudflare.COM."),
            "case + trailing FQDN dot normalized"
        );
        assert!(
            is_cdn_host("  ajax.googleapis.com  "),
            "surrounding whitespace trimmed"
        );
        assert!(!is_cdn_host("evil.example.com"));
        assert!(!is_cdn_host(""), "the empty host is never cloaked");
    }

    /// ★ #65 tri-constant pin — the promise at resolver/local.rs:188 ("kept equal by test"), now REAL:
    /// this string sentinel, the resolver's `CLOAK_SENTINEL_V4` addr answer, and the forwarder's
    /// `hairpin_dst` rewrite (forwarder/run.rs, cfg(unix)) must never drift apart. Host-compiled here
    /// because the forwarder's own tests are unix-gated with the tun fd.
    #[test]
    fn cloak_sentinel_ip_equals_resolver_sentinel_v4() {
        let parsed: std::net::Ipv4Addr = CLOAK_SENTINEL_IP
            .parse()
            .expect("CLOAK_SENTINEL_IP must parse as IPv4");
        assert_eq!(parsed, crate::resolver::local::CLOAK_SENTINEL_V4);
    }

    #[test]
    fn cloaking_rules_fences_and_maps_every_host_to_loopback() {
        let _g = CLOAK_SET.lock().unwrap_or_else(|e| e.into_inner());
        let rules = cloaking_rules();
        assert!(
            rules.starts_with(CLOAK_BLOCK_BEGIN),
            "opens with the BEGIN marker"
        );
        assert!(
            rules.trim_end().ends_with(CLOAK_BLOCK_END),
            "closes with the END marker"
        );
        assert!(rules.contains(&format!("ajax.googleapis.com {CLOAK_SENTINEL_IP}")));
        assert!(rules.contains(&format!("cdnjs.cloudflare.com {CLOAK_SENTINEL_IP}")));
        // every non-comment, non-empty line is "<host> <sentinel>", one per cloaked host.
        let host_lines: Vec<&str> = rules
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        // One rule per cloaked host. Asserted as "no duplicates AND every corpus host present" rather
        // than against `cdn_hosts().len()`: the promoted set now publishes LIVE the moment a discovered
        // host crosses the promotion line, so the emitted total is corpus + promoted and is no longer a
        // constant this test can pin. The invariant that actually matters survives either way.
        let names: Vec<&str> = host_lines
            .iter()
            .filter_map(|l| l.split(' ').next())
            .collect();
        let mut uniq = names.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), names.len(), "no host may get two cloak rules");
        for h in cdn_hosts() {
            assert!(names.contains(h), "every corpus host must be cloaked: {h}");
        }
        let suffix = format!(" {CLOAK_SENTINEL_IP}");
        for l in &host_lines {
            assert!(
                l.ends_with(&suffix),
                "rule maps a host to the tun sentinel: {l}"
            );
            assert!(!l.starts_with(' '), "no leading space: {l}");
        }
    }

    #[test]
    fn resolve_rejects_unknown_host_and_crossmajor() {
        assert!(resolve(
            "evil.example.com",
            "/ajax/libs/jquery/3.6.0/jquery.js",
            SEED_MAPS
        )
        .is_none());
        // jQuery 2.x is not bundled (only 3.x) → no same-major substitute → no serve.
        assert!(resolve(
            "ajax.googleapis.com",
            "/ajax/libs/jquery/2.2.4/jquery.js",
            SEED_MAPS
        )
        .is_none());
    }

    // ---- #134 slice 1 — THE CROSSED RESOLVER (content-address + trust + coverage gate) ----

    /// Build a genuinely-signed `TCAT` catalog naming each `(name, hash)` entry, run through the REAL
    /// verify-sig-FIRST [`Catalog::parse_verified`] — so the returned [`Catalog`] is signature-proof exactly
    /// like the on-device install path (the `server.rs`/`catalog.rs` test signer shape; no production key).
    fn signed_catalog_for(entries: &[(&str, ContentHash)]) -> Catalog {
        use ed25519_dalek::{Signer, SigningKey};
        const KEY_ID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        const HOST: &str = "ajax.googleapis.com";
        let mut body = Vec::new();
        body.extend_from_slice(b"TCAT"); // magic
        body.extend_from_slice(&1u16.to_le_bytes()); // version = 1
        body.push(2u8); // hash_algo_id = BLAKE2B
        body.push(0u8); // header flags
        body.extend_from_slice(&0u64.to_le_bytes()); // reserved (freshness epoch — must be 0 today)
        body.extend_from_slice(&(entries.len() as u32).to_le_bytes()); // entry_count
        body.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        for (name, hash) in entries {
            body.push(0u8); // entry_flags (cloak irrelevant to the resolver tests)
            body.extend_from_slice(hash); // content_hash[32]
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(&(HOST.len() as u16).to_le_bytes());
            body.extend_from_slice(HOST.as_bytes());
        }
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let mut pubkey = Vec::with_capacity(42);
        pubkey.extend_from_slice(b"Ed");
        pubkey.extend_from_slice(&KEY_ID);
        pubkey.extend_from_slice(&pk);
        let sig = sk.sign(&body);
        let mut sig_blob = Vec::with_capacity(74);
        sig_blob.extend_from_slice(b"Ed");
        sig_blob.extend_from_slice(&KEY_ID);
        sig_blob.extend_from_slice(&sig.to_bytes());
        Catalog::parse_verified(&body, &sig_blob, &pubkey)
            .expect("a genuinely signed test catalog verifies + parses")
    }

    #[test]
    fn resolve_addressed_carries_the_catalog_hash_for_a_covered_url() {
        let hash: ContentHash = [0xAB; 32];
        let catalog = signed_catalog_for(&[("jquery/3.6.0/jquery.min.js", hash)]);
        let r = resolve_addressed_in(
            "ajax.googleapis.com",
            "/ajax/libs/jquery/3.6.0/jquery.min.js",
            SEED_MAPS,
            &catalog,
            0,
        )
        .expect("a covered exact URL resolves to an addressed resolution");
        assert_eq!(r.resolution.served_version, "3.6.0");
        assert_eq!(r.resolution.substitution, Substitution::Exact);
        assert_eq!(
            r.content_hash, hash,
            "the resolution CARRIES the signed content address"
        );
        // SEAM CONTRACT: the name the resolver emits IS the exact key the catalog is queried by.
        assert_eq!(
            catalog.content_hash_for(&r.resolution.canonical_name()),
            Some(r.content_hash),
            "canonical_name() is the catalog key shape — the seam contract holds"
        );
        // jQuery 3.6.0 is mapped by BOTH googleapis + cdnjs in SEED_MAPS → corroboration 2, trust in band.
        assert_eq!(r.corroboration, 2);
        assert!(
            r.trust >= SIGNED_FLOOR,
            "a signed serve sits in the signed band"
        );
    }

    #[test]
    fn resolve_addressed_is_none_for_a_mapped_but_uncatalogued_url() {
        // The map RESOLVES this URL (googleapis jQuery 3.6.0), but the signed catalog covers NOTHING ⇒ None.
        // The F9 honesty proof: never commit to a version the catalog can't serve (no 404-blackhole).
        let empty = Catalog::default();
        assert!(
            resolve_addressed_in(
                "ajax.googleapis.com",
                "/ajax/libs/jquery/3.6.0/jquery.min.js",
                SEED_MAPS,
                &empty,
                0,
            )
            .is_none(),
            "mapped but uncatalogued ⇒ no addressed resolution"
        );
    }

    #[test]
    fn resolve_addressed_coverage_gate_picks_a_covered_fallback() {
        // requested 3.6.2 isn't bundled. Naive resolve() picks the smallest safe-newer (3.7.1). But the
        // catalog covers ONLY 3.6.0 — so the coverage gate prunes 3.7.1 and serves the covered RiskyOlder
        // 3.6.0 instead of 404-ing on an uncovered "best" version. The cross is strictly more servable.
        let hash: ContentHash = [0xCD; 32];
        let catalog = signed_catalog_for(&[("jquery/3.6.0/jquery.min.js", hash)]);
        // sanity: naive resolve would have chosen 3.7.1 (uncovered).
        assert_eq!(
            resolve(
                "ajax.googleapis.com",
                "/ajax/libs/jquery/3.6.2/jquery.min.js",
                SEED_MAPS
            )
            .unwrap()
            .served_version,
            "3.7.1"
        );
        let r = resolve_addressed_in(
            "ajax.googleapis.com",
            "/ajax/libs/jquery/3.6.2/jquery.min.js",
            SEED_MAPS,
            &catalog,
            0,
        )
        .expect("the coverage gate finds the covered older version");
        assert_eq!(
            r.resolution.served_version, "3.6.0",
            "served the COVERED version, not the uncovered 3.7.1"
        );
        assert_eq!(r.resolution.substitution, Substitution::RiskyOlder);
        assert_eq!(r.content_hash, hash);
    }

    #[test]
    fn resolution_trust_is_always_in_the_signed_band() {
        for sub in [
            Substitution::Exact,
            Substitution::SafeNewer,
            Substitution::RiskyOlder,
            Substitution::Incompatible,
        ] {
            for corr in 0u32..=4 {
                let t = resolution_trust(sub, corr, 0, 0);
                assert!(
                    t >= SIGNED_FLOOR,
                    "{sub:?} corr {corr} trust {t} must be >= SIGNED_FLOOR"
                );
                assert!(t <= 100);
            }
        }
    }

    #[test]
    fn resolution_trust_is_monotone_in_corroboration() {
        for sub in [
            Substitution::Exact,
            Substitution::SafeNewer,
            Substitution::RiskyOlder,
        ] {
            let mut last = 0u8;
            for corr in 0u32..=6 {
                let t = resolution_trust(sub, corr, 0, 0);
                assert!(
                    t >= last,
                    "{sub:?}: trust must be non-decreasing in corroboration"
                );
                last = t;
            }
        }
    }

    #[test]
    fn resolution_trust_ranks_exact_above_riskyolder() {
        // At solo corroboration the substitution quality dominates: an Exact serve outranks a RiskyOlder one.
        let exact = resolution_trust(Substitution::Exact, 1, 0, 0);
        let older = resolution_trust(Substitution::RiskyOlder, 1, 0, 0);
        assert!(
            exact > older,
            "Exact ({exact}) must outrank RiskyOlder ({older}) at equal corroboration"
        );
        assert!(older >= SIGNED_FLOOR);
    }

    #[test]
    fn corroboration_for_counts_distinct_cdn_hosts() {
        // jQuery 3.6.0 is mapped from googleapis AND cdnjs in SEED_MAPS → 2 distinct corroborating hosts.
        assert_eq!(corroboration_for("jquery", "3.6.0", SEED_MAPS), 2);
        // angularjs only on googleapis, bootstrap only on cdnjs → 1 each.
        assert_eq!(corroboration_for("angularjs", "1.8.2", SEED_MAPS), 1);
        assert_eq!(corroboration_for("bootstrap", "5.3.3", SEED_MAPS), 1);
        // an unmapped library/version → 0.
        assert_eq!(corroboration_for("jquery", "9.9.9", SEED_MAPS), 0);
    }
}

/// ★ CLOAK⊆SERVABLE — the set invariant, tested as a SET rather than as rendered text.
///
/// The defect was a set mismatch (26 cloaked vs 1 servable), so these assert over the emitted host
/// set. A test that only checked the block's shape passed throughout the entire life of the bug.
#[cfg(test)]
mod cloak_servable_tests {
    use super::*;

    /// Extract the cloaked hosts back out of a rendered block, so the assertions are about the SET.
    fn hosts_in(block: &str) -> Vec<String> {
        block
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .filter_map(|l| l.split_whitespace().next().map(|s| s.to_string()))
            .collect()
    }

    /// The fix: only what is servable is cloaked. This is `derived_is_always_sound` from
    /// `Proofs/CloakServable.lean` at the Rust boundary.
    #[test]
    fn only_servable_hosts_are_cloaked() {
        let servable = ["ajax.googleapis.com".to_string()];
        let got = hosts_in(&cloaking_rules_for(&servable));
        assert_eq!(got, vec!["ajax.googleapis.com".to_string()]);
    }

    /// THE NEGATIVE CONTROL, and the reason this whole change exists: the SHIPPED generator cloaks the
    /// entire corpus, so it emits vastly more hosts than a one-asset store can serve. If this ever
    /// stops holding, `cloaking_rules` was fixed elsewhere and this test should be revisited — but it
    /// must never silently agree with the filtered version while the corpus is larger than the store.
    #[test]
    fn the_old_generator_overclaims_against_a_one_asset_store() {
        let corpus = hosts_in(&cloaking_rules());
        let servable = ["ajax.googleapis.com".to_string()];
        let filtered = hosts_in(&cloaking_rules_for(&servable));
        assert!(
            corpus.len() > filtered.len(),
            "the corpus generator must be measurably broader than the store-derived one \
             (corpus={}, filtered={}) — if these are equal the negative control is dead and this \
             test proves nothing",
            corpus.len(),
            filtered.len()
        );
        // Every unservable corpus host is a black hole: sinkholed with nothing to serve.
        let black_holes: Vec<&String> = corpus.iter().filter(|h| !servable.contains(h)).collect();
        assert!(
            !black_holes.is_empty(),
            "with a one-asset store the corpus MUST contain black holes; an empty list here means \
             the corpus shrank to one host and this control no longer measures anything"
        );
    }

    /// `fix_is_a_noop_on_a_complete_store` at the Rust boundary: when the store holds every corpus
    /// host, the filtered block is byte-identical to the corpus block. No working cloak is lost.
    #[test]
    fn a_complete_store_reproduces_the_corpus_block_byte_for_byte() {
        // The corpus lane AND the promoted lane both ride the fenced block, so a "complete store" is
        // the union of the two. Comparing only against `cdn_hosts()` made this test fail the moment
        // another test in the same process promoted a host — which is exactly how it caught that the
        // manifest-only filter would have dropped the promoted lane on a device.
        let mut all: Vec<String> = cdn_hosts().iter().map(|h| h.to_string()).collect();
        all.extend(promoted_cloak_hosts());
        let mut want = hosts_in(&cloaking_rules());
        let mut got = hosts_in(&cloaking_rules_for(&all));
        want.sort();
        want.dedup();
        got.sort();
        got.dedup();
        assert_eq!(
            got, want,
            "with a complete store the two generators must cloak the SAME host set — otherwise the \
             fix is not a pure restriction and could change behaviour on a healthy device"
        );
    }

    /// FAIL-CLOSED: no servable content ⇒ no sinkholes. A missing manifest must never be read as
    /// "intercept everything", which is the failure direction that caused the outage.
    #[test]
    fn an_empty_store_cloaks_nothing_but_still_writes_the_fence() {
        let none: [String; 0] = [];
        let block = cloaking_rules_for(&none);
        assert!(hosts_in(&block).is_empty(), "no content ⇒ no cloak");
        assert!(
            block.contains(CLOAK_BLOCK_BEGIN) && block.contains(CLOAK_BLOCK_END),
            "the fence must still be written so a writer can replace the block"
        );
    }

    /// The block is byte-stable across argument order, so arming twice does not churn the file and
    /// force a needless dnscrypt reload.
    #[test]
    fn the_block_is_order_and_duplicate_stable() {
        let a = [
            "b.example".to_string(),
            "a.example".to_string(),
            "b.example".to_string(),
        ];
        let b = ["a.example".to_string(), "b.example".to_string()];
        assert_eq!(cloaking_rules_for(&a), cloaking_rules_for(&b));
    }

    /// An empty host string must never emit a bare sentinel line — that would look armed and cloak
    /// nothing.
    #[test]
    fn an_empty_host_is_never_emitted() {
        let hosts = ["".to_string(), "a.example".to_string()];
        assert_eq!(
            hosts_in(&cloaking_rules_for(&hosts)),
            vec!["a.example".to_string()]
        );
    }
}

/// ★ CLOAK⊆SERVABLE (LIVE PATH) — the resolver's sinkhole gate.
///
/// These run SERIALLY under one lock because the gate is process-global state; a parallel test would
/// see another test's published set. The serialization is the point: the gate IS global, and a test
/// that pretended otherwise would be testing a fiction.
#[cfg(test)]
mod live_cloak_gate_tests {
    use super::*;
    use std::sync::Mutex;

    static GATE_LOCK: Mutex<()> = Mutex::new(());

    /// FAIL-CLOSED: nothing published ⇒ nothing cloaked, even for a genuine corpus host. This is the
    /// direction that matters — the old gate said "corpus member ⇒ sinkhole" and killed 25 flows.
    #[test]
    fn an_unpublished_gate_cloaks_nothing_even_for_a_corpus_host() {
        let _g = GATE_LOCK.lock().unwrap();
        crate::mirror::publish_cloak_tls_trust(true);
        publish_servable_cloak(&[]);
        let corpus_host = cdn_hosts()[0];
        assert!(
            is_cdn_host(corpus_host),
            "precondition: the probe must be a real corpus host, else this test is vacuous"
        );
        assert!(
            !is_servable_cloak_host(corpus_host),
            "with an empty store the live gate MUST refuse to cloak — fetching from the real CDN is a \
             working page; sinkholing to an empty store is a dead connection"
        );
        assert_eq!(servable_cloak_count(), 0);
    }

    /// A published, servable corpus host IS cloaked — the gate is not simply always-false.
    #[test]
    fn a_published_servable_corpus_host_is_cloaked() {
        let _g = GATE_LOCK.lock().unwrap();
        crate::mirror::publish_cloak_tls_trust(true);
        let host = cdn_hosts()[0].to_string();
        publish_servable_cloak(&[host.clone()]);
        assert!(is_servable_cloak_host(&host));
        assert_eq!(servable_cloak_count(), 1);
        publish_servable_cloak(&[]);
    }

    /// Publishing a host that is NOT in the corpus does not make it cloakable — the gate is the
    /// INTERSECTION, not a replacement. A stray manifest row must never invent a new interception.
    #[test]
    fn publishing_a_non_corpus_host_does_not_cloak_it() {
        let _g = GATE_LOCK.lock().unwrap();
        crate::mirror::publish_cloak_tls_trust(true);
        publish_servable_cloak(&["definitely-not-in-the-corpus.example".to_string()]);
        assert!(!is_servable_cloak_host(
            "definitely-not-in-the-corpus.example"
        ));
        publish_servable_cloak(&[]);
    }

    /// A SHRINKING store immediately stops cloaking what it can no longer serve. A stale larger set is
    /// precisely the defect this whole change removes, so re-publishing must REPLACE, never merge.
    #[test]
    fn a_shrinking_store_stops_cloaking_immediately() {
        let _g = GATE_LOCK.lock().unwrap();
        crate::mirror::publish_cloak_tls_trust(true);
        let host = cdn_hosts()[0].to_string();
        publish_servable_cloak(&[host.clone()]);
        assert!(is_servable_cloak_host(&host));
        publish_servable_cloak(&[]);
        assert!(
            !is_servable_cloak_host(&host),
            "re-publishing an empty set must REPLACE the old one — a merge would keep sinkholing a \
             host whose asset was evicted"
        );
    }

    /// THE FOURTH CONJUNCT. A cloak redirects the client to our loopback where Centauri
    /// TERMINATES TLS with the device CA -- a file that is app-private and a trust anchor for
    /// nothing. Measured on device: `centauri_cloak_sinkholes = 3` with `cloak_actions = 0`,
    /// i.e. three connections redirected and ZERO served. Holding the bytes was never enough;
    /// we must also be able to present a cert the client accepts. Trust defaults FALSE so the
    /// safe state is the default rather than something to remember.
    #[test]
    fn an_untrusted_ca_cloaks_nothing_however_servable_the_host_is() {
        let _g = GATE_LOCK.lock().unwrap();
        crate::mirror::publish_cloak_tls_trust(false);
        crate::mirror::publish_servable_cloak(&["ajax.googleapis.com".to_string()]);
        assert!(!crate::mirror::cloak_tls_trusted());
        assert!(
            !crate::mirror::is_servable_cloak_host("ajax.googleapis.com"),
            "a servable corpus host must NOT be cloaked while the CA is untrusted"
        );
        // NEGATIVE CONTROL for this very test: with trust established the same host IS cloaked,
        // so the assertion above is measuring trust and not some unrelated failure.
        crate::mirror::publish_cloak_tls_trust(true);
        assert!(
            crate::mirror::is_servable_cloak_host("ajax.googleapis.com"),
            "trust is the only thing that was withheld"
        );
        crate::mirror::publish_cloak_tls_trust(false);
    }

    /// Normalization parity with `is_cdn_host`: case and a trailing FQDN dot must not split the two
    /// gates, or a host differing only in case would sinkhole with nothing to serve.
    #[test]
    fn the_gate_normalizes_case_and_the_fqdn_dot_like_is_cdn_host() {
        let _g = GATE_LOCK.lock().unwrap();
        crate::mirror::publish_cloak_tls_trust(true);
        let host = cdn_hosts()[0].to_string();
        publish_servable_cloak(&[host.clone()]);
        let upper = host.to_ascii_uppercase();
        let dotted = format!("{host}.");
        assert!(is_servable_cloak_host(&upper), "uppercase must match");
        assert!(
            is_servable_cloak_host(&dotted),
            "trailing FQDN dot must match"
        );
        publish_servable_cloak(&[]);
    }
}
