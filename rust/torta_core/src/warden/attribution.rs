/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! # A4 — THE ATTRIBUTION MAP: which domain did the app resolve before it dialed this IP?
//!
//! The tunnel's connection judgments see `(uid, ip, port, proto)` — an IP, never a name. But the
//! loop IS the resolver: every A/AAAA answer the sovereign resolver hands an app passes through
//! our hands first. This map remembers `answer IP → query qname` for the answer's TTL, so a later
//! flow to that IP can carry the domain the app actually asked for — into the per-app domain
//! rules and onto the LIVE FLOWS panel.
//!
//! ## GENESIS
//!
//! Studied rethink's `ipmap.go` (`ReverseGet` — their ip→domain reverse map fed at resolve time,
//! study-cited in GENESIS-pillar-warden.md A4). Originated from scratch as a bounded, TTL-honest
//! `RwLock<HashMap>`: no unbounded growth (rethink's map grows per-process), deadline-clamped
//! (a 0-TTL answer still lingers [`TTL_FLOOR_SECS`] — the app dials right after resolving; a
//! day-long TTL dies at [`TTL_CEIL_SECS`] — stale mislabels must age out), and lazily expired
//! (lookups never take the write lock).
//!
//! ## THE FAIL-OPEN LAW (the A4 spec's one caveat)
//!
//! Attribution is BEST-EFFORT: CDNs collapse many names onto one IP, entries go stale, caches
//! answer queries this map never sees. A wrong label must therefore NEVER drive a DENY — the
//! consumer (tunnel/warden.rs) re-asks the verdict WITHOUT the label before honoring an
//! attribution-driven deny. This module only remembers; it never judges.
//!
//! ## T20 (telemetry discipline)
//!
//! The map is engine-internal state, same consent class as the tracker ring it labels: nothing
//! here is logged, counted into loop TELEMETRY, or exported beyond the consented panel surface.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

/// Hard cap on live entries. A browsing session resolves hundreds of names; 4096 covers hours of
/// heavy use, and at ~100 bytes/entry the worst case stays under half a megabyte.
pub const ATTRIBUTION_CAP: usize = 4096;

/// TTL floor: an app dials the answer it just received even when the record says TTL=0 — the
/// label must outlive the dial (60 s covers the resolve→connect gap with margin).
const TTL_FLOOR_SECS: u64 = 60;

/// TTL ceiling: a wrong label (CDN rotation, stale record) must age out even when the record
/// claims a day — 2 h bounds the mislabel window without churning normal browsing.
const TTL_CEIL_SECS: u64 = 7200;

/// One remembered attribution: the query qname + the instant it stops being trustworthy.
struct Entry {
    domain: Arc<str>,
    expires: Instant,
}

/// The bounded ip→domain map. Read-mostly (one `lookup` per connection judgment, one `record`
/// burst per resolve) — an `RwLock` keeps judgments concurrent. Lock-poison recovers via
/// `into_inner` (the crate idiom, cf. tracker.rs): a panicked writer leaves at worst a stale
/// entry, and stale entries are already the documented failure mode.
pub struct AttributionMap {
    map: RwLock<HashMap<IpAddr, Entry>>,
}

impl AttributionMap {
    pub fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }

    /// Remember `ip → domain` until `now + clamp(ttl)`, on the wall clock. At [`ATTRIBUTION_CAP`],
    /// expired entries sweep first; if the map is STILL full, the earliest-deadline entry is evicted
    /// — the entry closest to death carries the least remaining truth.
    ///
    /// TEST-ONLY, and measured to be so. Production records in BULK through `record_reply` (via
    /// `record_from_reply`) at the two live reply emitters, `forwarder/run.rs:275` and
    /// `tunnel/mod.rs:1116`; `record_reply` is also strictly more efficient, sharing one `Arc<str>`
    /// across a reply's addresses instead of allocating per entry. The real callers of THIS form are
    /// the tunnel verdict tests (`tunnel/warden.rs:339/391/500`), which seed a label with a real
    /// clock to drive the A4 attribution path.
    ///
    /// `#[cfg(test)]` rather than `#[allow(dead_code)]` is the honest declaration: the allow claimed
    /// a production caller was coming, and measurement says the production path is `record_reply`.
    /// Gating states what is true and ships no dead code.
    ///
    /// I also looked for an unattributed production emitter to wire this to, and DISPROVED the one
    /// candidate: `torta_resolve` (lib.rs, the exported C tun seam) emits replies without recording
    /// attribution, but `git grep torta_resolve HEAD` matches no C/H/Kotlin/Java file in this
    /// repository — the seam its doc describes is not present here, so attributing it would have
    /// been wiring a caller that does not exist.
    #[cfg(test)]
    pub fn record(&self, ip: IpAddr, domain: &str, ttl_secs: u32) {
        self.record_at(ip, domain, ttl_secs, Instant::now());
    }

    /// The insert engine with an INJECTED CLOCK. Deadline logic is untestable against a real
    /// `Instant::now()`, so every TTL/eviction test drives this.
    ///
    /// `#[cfg(test)]` rather than `#[allow(dead_code)]`: this is the honest declaration. The allow
    /// claimed "a production caller is coming"; measurement says otherwise — production records in
    /// bulk through `record_reply`. Gating it to test builds states what is true and ships no dead
    /// code, instead of silencing a warning about code that is genuinely not in the product.
    #[cfg(test)]
    fn record_at(&self, ip: IpAddr, domain: &str, ttl_secs: u32, now: Instant) {
        self.record_at_shared(ip, Arc::from(domain), ttl_secs, now);
    }

    /// Record every address of one parsed reply under its query qname — ONE `Arc` allocation
    /// shared across the reply's addresses.
    pub fn record_reply(&self, qname: &str, addrs: &[(IpAddr, u32)], now: Instant) {
        let domain: Arc<str> = Arc::from(qname);
        for &(ip, ttl) in addrs {
            // Entry-by-entry keeps the cap discipline exact; the Arc clone replaces the
            // per-entry allocation.
            self.record_at_shared(ip, Arc::clone(&domain), ttl, now);
        }
    }

    /// The one insert path: clamp the TTL, sweep/evict at cap, insert.
    fn record_at_shared(&self, ip: IpAddr, domain: Arc<str>, ttl_secs: u32, now: Instant) {
        let clamped = (ttl_secs as u64).clamp(TTL_FLOOR_SECS, TTL_CEIL_SECS);
        let expires = now + Duration::from_secs(clamped);
        let mut m = self.map.write().unwrap_or_else(|e| e.into_inner());
        if !m.contains_key(&ip) && m.len() >= ATTRIBUTION_CAP {
            m.retain(|_, e| e.expires > now);
            if m.len() >= ATTRIBUTION_CAP {
                if let Some(victim) = m.iter().min_by_key(|(_, e)| e.expires).map(|(k, _)| *k) {
                    m.remove(&victim);
                }
            }
        }
        m.insert(ip, Entry { domain, expires });
    }

    /// The domain this IP was resolved under, or `None` when unknown/expired. Lazy expiry: an
    /// expired entry returns `None` but is NOT removed here — lookups hold only the read lock
    /// (the judgment hot path never serializes on a write), and the corpse is reclaimed by the
    /// next at-cap sweep.
    pub fn lookup(&self, ip: &IpAddr) -> Option<Arc<str>> {
        self.lookup_at(ip, Instant::now())
    }

    fn lookup_at(&self, ip: &IpAddr, now: Instant) -> Option<Arc<str>> {
        let m = self.map.read().unwrap_or_else(|e| e.into_inner());
        m.get(ip)
            .filter(|e| e.expires > now)
            .map(|e| Arc::clone(&e.domain))
    }

    /// Live entry count (expired-but-unswept corpses included — this is a capacity gauge, not a
    /// truth gauge).
    pub fn len(&self) -> usize {
        self.map.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for AttributionMap {
    fn default() -> Self {
        Self::new()
    }
}

// ===================================================================================================
// The process-global map — the same singleton shape as tracker::global().
// ===================================================================================================

static GLOBAL: OnceLock<AttributionMap> = OnceLock::new();

/// The process-global attribution map — the resolve hooks write here, verdict() reads here.
pub fn global() -> &'static AttributionMap {
    GLOBAL.get_or_init(AttributionMap::new)
}

/// Parse one DNS reply off the wire and record every A/AAAA answer into the global map under the
/// reply's query qname. The ONE-liner both resolve sites call — sync loop (tunnel/mod.rs) and
/// forwarder (forwarder/run.rs). Returns the number of addresses recorded (0 on a reply that is
/// malformed, negative, or address-free — never an error: attribution is best-effort by law).
pub fn record_from_reply(reply: &[u8]) -> usize {
    match crate::tunnel::parse::extract_answer_addrs(reply) {
        Some((qname, addrs)) if !addrs.is_empty() => {
            global().record_reply(&qname, &addrs, Instant::now());
            addrs.len()
        }
        _ => 0,
    }
}

/// Global-map lookup — the verdict() seam.
pub fn lookup(ip: &IpAddr) -> Option<Arc<str>> {
    global().lookup(ip)
}

// ===================================================================================================
// Tests — local map instances (the global is process-wide; only record_from_reply touches it, and
// the test law `--test-threads=1` plus distinct anchor IPs keep residue harmless).
// ===================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn record_then_lookup_roundtrip() {
        let m = AttributionMap::new();
        let now = Instant::now();
        m.record_at(ip("203.0.113.7"), "torta.example", 300, now);
        let got = m
            .lookup_at(&ip("203.0.113.7"), now)
            .expect("recorded ⇒ found");
        assert_eq!(&*got, "torta.example");
        assert!(
            m.lookup_at(&ip("203.0.113.8"), now).is_none(),
            "unknown ip is None"
        );
    }

    #[test]
    fn entry_expires_at_its_deadline() {
        let m = AttributionMap::new();
        let now = Instant::now();
        m.record_at(ip("203.0.113.7"), "torta.example", 300, now);
        assert!(m
            .lookup_at(&ip("203.0.113.7"), now + Duration::from_secs(299))
            .is_some());
        assert!(m
            .lookup_at(&ip("203.0.113.7"), now + Duration::from_secs(301))
            .is_none());
    }

    #[test]
    fn ttl_clamps_floor_and_ceiling() {
        let m = AttributionMap::new();
        let now = Instant::now();
        // TTL=0 floors to 60 s — the app dials right after resolving.
        m.record_at(ip("203.0.113.1"), "zero.example", 0, now);
        assert!(m
            .lookup_at(&ip("203.0.113.1"), now + Duration::from_secs(59))
            .is_some());
        assert!(m
            .lookup_at(&ip("203.0.113.1"), now + Duration::from_secs(61))
            .is_none());
        // TTL=86400 ceils to 7200 s — stale mislabels age out.
        m.record_at(ip("203.0.113.2"), "day.example", 86_400, now);
        assert!(m
            .lookup_at(&ip("203.0.113.2"), now + Duration::from_secs(7199))
            .is_some());
        assert!(m
            .lookup_at(&ip("203.0.113.2"), now + Duration::from_secs(7201))
            .is_none());
    }

    #[test]
    fn rerecord_replaces_domain_and_refreshes_deadline() {
        let m = AttributionMap::new();
        let now = Instant::now();
        m.record_at(ip("203.0.113.7"), "old.example", 60, now);
        m.record_at(
            ip("203.0.113.7"),
            "new.example",
            60,
            now + Duration::from_secs(50),
        );
        let at = now + Duration::from_secs(90); // past the first deadline, inside the second
        let got = m.lookup_at(&ip("203.0.113.7"), at).expect("refreshed");
        assert_eq!(&*got, "new.example");
        assert_eq!(m.len(), 1, "re-record replaces, never duplicates");
    }

    #[test]
    fn at_cap_sweeps_expired_first() {
        let m = AttributionMap::new();
        let now = Instant::now();
        // Fill to cap with entries already dead by insert-time+100s.
        for i in 0..ATTRIBUTION_CAP {
            let a = std::net::Ipv4Addr::from((0x0A00_0000u32) + i as u32);
            m.record_at(IpAddr::V4(a), "dead.example", 60, now);
        }
        assert_eq!(m.len(), ATTRIBUTION_CAP);
        // Insert one more AFTER they expired: the sweep reclaims all corpses.
        m.record_at(
            ip("203.0.113.7"),
            "alive.example",
            300,
            now + Duration::from_secs(100),
        );
        assert_eq!(m.len(), 1, "sweep reclaimed the expired fill");
        assert!(m
            .lookup_at(&ip("203.0.113.7"), now + Duration::from_secs(101))
            .is_some());
    }

    #[test]
    fn at_cap_with_no_corpses_evicts_earliest_deadline() {
        let m = AttributionMap::new();
        let now = Instant::now();
        // Fill to cap, all alive, one entry with a strictly earlier deadline.
        m.record_at(ip("10.9.9.9"), "victim.example", 61, now);
        for i in 1..ATTRIBUTION_CAP {
            let a = std::net::Ipv4Addr::from((0x0A00_0000u32) + i as u32);
            m.record_at(IpAddr::V4(a), "filler.example", 7200, now);
        }
        assert_eq!(m.len(), ATTRIBUTION_CAP);
        m.record_at(
            ip("203.0.113.7"),
            "newcomer.example",
            300,
            now + Duration::from_secs(1),
        );
        assert_eq!(m.len(), ATTRIBUTION_CAP, "cap holds");
        assert!(
            m.lookup_at(&ip("10.9.9.9"), now + Duration::from_secs(2))
                .is_none(),
            "earliest-deadline entry evicted"
        );
        assert!(m
            .lookup_at(&ip("203.0.113.7"), now + Duration::from_secs(2))
            .is_some());
    }

    #[test]
    fn record_reply_shares_one_domain_across_addrs() {
        let m = AttributionMap::new();
        let now = Instant::now();
        let addrs = vec![(ip("203.0.113.10"), 300u32), (ip("2001:db8::10"), 600u32)];
        m.record_reply("multi.example", &addrs, now);
        let a = m.lookup_at(&ip("203.0.113.10"), now).unwrap();
        let b = m.lookup_at(&ip("2001:db8::10"), now).unwrap();
        assert_eq!(&*a, "multi.example");
        assert!(
            Arc::ptr_eq(&a, &b),
            "one shared Arc across the reply's addresses"
        );
    }

    #[test]
    fn record_from_reply_end_to_end_and_rejects_junk() {
        // A real wire reply: example.com → 203.0.113.77 (built the parse.rs test way).
        let mut d = vec![0u8; 12];
        d[0..2].copy_from_slice(&0x4242u16.to_be_bytes());
        d[2] = 0x81; // qr=1
        d[3] = 0x80; // rcode=0
        d[4..6].copy_from_slice(&1u16.to_be_bytes());
        d[6..8].copy_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(b"\x07example\x03com\x00");
        d.extend_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(&[0xC0, 0x0C]);
        d.extend_from_slice(&1u16.to_be_bytes()); // A
        d.extend_from_slice(&1u16.to_be_bytes()); // IN
        d.extend_from_slice(&300u32.to_be_bytes());
        d.extend_from_slice(&4u16.to_be_bytes());
        d.extend_from_slice(&[203, 0, 113, 77]);
        assert_eq!(record_from_reply(&d), 1);
        let got = lookup(&ip("203.0.113.77")).expect("global map fed");
        assert_eq!(&*got, "example.com");
        // Junk never errors — best-effort law.
        assert_eq!(record_from_reply(&[]), 0);
        assert_eq!(record_from_reply(b"\x00\x01"), 0);
    }
}
