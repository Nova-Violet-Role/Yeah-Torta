/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! A5 slice-2 — GEOIP: the `cc` producer the tracker was born waiting for.
//!
//! `IP → ISO-3166 alpha-2`, answered from two embedded START-TABLES built out of the five RIR
//! delegated-stats files (`examples/geoip_gen.rs` is the generator; regenerate + recommit to
//! refresh — the data ages gracefully, allocations move rarely).
//!
//! ## The table (the whole design)
//! A sorted array of fixed-size records `[start key BE][cc: 2 lowercase bytes]` — v4 keys are the
//! address as `u32` (6-byte records), v6 keys are the address's HIGH 64 BITS (10-byte records; RIR
//! country granularity is never finer than /64). A record claims `[start, next.start)`; every
//! allocation gap carries an explicit `cc = [0,0]` UNKNOWN sentinel record. So ONE binary search
//! answers both "which country" and "unallocated/private/reserved" (RFC1918, loopback, multicast —
//! none are RIR-allocated, all land in sentinel gaps): no prefix walk, no second probe.
//!
//! ## GENESIS honesty — a deliberate divergence
//! GENESIS-pillar-warden.md:246-248 sketched this as a CIDR table walked by
//! [`super::cidr_match::CidrMatch`]. Implemented instead as a RANGE table + `partition_point`-style
//! binary search (std, no new matcher crate): RIR v4 delegations are COUNTS, not CIDRs (a 4096-run
//! need not be prefix-shaped), so ranges are the source's native shape — merging adjacent same-cc
//! runs cut the v4 table 45% — and O(log n) over 210k records beats any per-entry match walk.
//! `CidrMatch` remains the RULE matcher; GeoIP is data, not policy.
//!
//! ## The v4-mapped asymmetry (deliberate, the A3 inverse)
//! A3 rule matching keeps `::ffff:a.b.c.d` OUT of v4 rules (a rule's family is a security
//! boundary). GeoIP maps it INTO the v4 table: a v4-mapped destination IS the v4 host, and this
//! path renders geography, never authorizes — attribution here can inform, not deny
//! (the Warden caveat law: wrong attribution must never drive a DENY).

use std::net::IpAddr;

/// The v4 table: 6-byte records `[start: u32 BE][cc]`. ~880 KB baked into `.rodata` — the price of
/// answering "where does my traffic go" with zero runtime I/O, zero parse, zero heap.
static TABLE4: &[u8] = include_bytes!("../../data/geoip4.bin");

/// The v6 table: 10-byte records `[start: u64 BE — high 64 bits][cc]`. ~1.3 MB.
static TABLE6: &[u8] = include_bytes!("../../data/geoip6.bin");

const REC4: usize = 6;
const REC6: usize = 10;

/// The country code for a destination IP, lowercase (`"us"`), or `None` for anything the RIRs have
/// not delegated to a country (private/reserved/unallocated space, and the odd registry gap).
/// `None` is the tracker's `cc = ""` → the 🌐 globe: unknown renders as unknown, never as a guess.
pub fn country_code(ip: IpAddr) -> Option<String> {
    let cc = country_code_raw(ip)?;
    // The generator emits ASCII lowercase; from_utf8 on 2 ASCII bytes cannot fail, but a corrupt
    // table must degrade to "unknown", never to a panic on a render path.
    String::from_utf8(cc.to_vec()).ok()
}

/// The ALLOC-FREE country probe — the same two-lowercase-byte key [`country_code`] returns, but
/// without the `String` heap allocation. The Warden verdict hot path (W-D #79 — the user-explicit
/// GEO-family block tier) calls THIS per connection: one binary search + a fixed `[u8; 2]`, no heap,
/// no I/O — cheap enough to sit under the lock. `country_code` wraps it for the render/display path.
///
/// CAVEAT-LAW NOTE: this producer still merely ATTRIBUTES geography; it authorizes nothing on its own.
/// The GEO-block tier that consumes it is a USER-CHOSEN policy (the user picked "block this country"),
/// not an engine auto-deny — the law forbids the latter, not the former. The block stays best-effort
/// (a mislabeled IP is the user's known trade-off), surfaced as such in the inspector.
pub fn country_code_raw(ip: IpAddr) -> Option<[u8; 2]> {
    match ip {
        IpAddr::V4(v4) => lookup(TABLE4, REC4, u32::from(v4) as u64),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(mapped) => lookup(TABLE4, REC4, u32::from(mapped) as u64),
            None => lookup(TABLE6, REC6, (u128::from(v6) >> 64) as u64),
        },
    }
}

/// Start-table probe ([`super::start_table::lookup`] does the search): `None` when the key
/// precedes the first record or lands on a `[0,0]` UNKNOWN sentinel.
fn lookup(table: &[u8], rec: usize, key: u64) -> Option<[u8; 2]> {
    let key_len = rec - 2;
    let key = &key.to_be_bytes()[8 - key_len..];
    let cc = super::start_table::lookup(table, rec, key_len, key)?;
    if cc == [0, 0] {
        None
    } else {
        Some([cc[0], cc[1]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A hand-built 6-byte-record table exercising every boundary the search has:
    /// [10,20) = aa · [20,30) = SENTINEL gap · [30,50) = bb · [50,∞) = SENTINEL tail.
    fn fixture() -> Vec<u8> {
        let mut t = Vec::new();
        for (start, cc) in [(10u32, *b"aa"), (20, [0, 0]), (30, *b"bb"), (50, [0, 0])] {
            t.extend_from_slice(&start.to_be_bytes());
            t.extend_from_slice(&cc);
        }
        t
    }

    #[test]
    fn lookup_boundary_semantics_on_a_synthetic_table() {
        let t = fixture();
        assert_eq!(lookup(&t, REC4, 0), None, "before the first record");
        assert_eq!(lookup(&t, REC4, 9), None);
        assert_eq!(lookup(&t, REC4, 10), Some(*b"aa"), "inclusive range start");
        assert_eq!(lookup(&t, REC4, 19), Some(*b"aa"), "last key of the range");
        assert_eq!(lookup(&t, REC4, 20), None, "sentinel gap");
        assert_eq!(lookup(&t, REC4, 29), None);
        assert_eq!(lookup(&t, REC4, 30), Some(*b"bb"));
        assert_eq!(lookup(&t, REC4, 49), Some(*b"bb"));
        assert_eq!(lookup(&t, REC4, 50), None, "tail sentinel claims the rest");
        assert_eq!(lookup(&t, REC4, u32::MAX as u64), None);
        assert_eq!(lookup(&[], REC4, 42), None, "empty table never panics");
    }

    #[test]
    fn embedded_tables_are_well_formed() {
        // The geoip_gen contract, verified against the REAL shipped bytes: whole records only, a
        // non-trivial record count, strictly increasing starts (the binary search's precondition),
        // and a REAL first record (gap sentinels only ever follow a range).
        for (table, rec, label) in [(TABLE4, REC4, "v4"), (TABLE6, REC6, "v6")] {
            assert_eq!(table.len() % rec, 0, "{label}: fractured record");
            let n = table.len() / rec;
            assert!(
                n > 100_000,
                "{label}: implausibly small table ({n} records)"
            );
            let key_len = rec - 2;
            let start_of = |i: usize| {
                table[i * rec..i * rec + key_len]
                    .iter()
                    .fold(0u64, |k, &b| (k << 8) | u64::from(b))
            };
            for i in 1..n {
                assert!(
                    start_of(i - 1) < start_of(i),
                    "{label}: starts not strictly increasing at record {i}"
                );
            }
            let first_cc = [table[key_len], table[key_len + 1]];
            assert_ne!(first_cc, [0, 0], "{label}: table opens on a sentinel");
        }
    }

    #[test]
    fn stable_anchors_resolve_to_their_registries() {
        // Decades-stable delegations — chosen so a table refresh never flakes this test:
        // 8.8.8.8 (Google public DNS, ARIN/US), 193.0.10.1 (RIPE NCC's own block, NL),
        // 1.1.1.1 (APNIC research space, AU).
        assert_eq!(country_code(ip("8.8.8.8")).as_deref(), Some("us"));
        assert_eq!(country_code(ip("193.0.10.1")).as_deref(), Some("nl"));
        assert_eq!(country_code(ip("1.1.1.1")).as_deref(), Some("au"));
        // RIPE NCC's own v6 micro-allocation (2001:67c:2e8::/48).
        assert_eq!(country_code(ip("2001:67c:2e8::1")).as_deref(), Some("nl"));
    }

    #[test]
    fn unrouted_space_is_unknown_never_a_guess() {
        for s in [
            "10.0.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "ff02::fb",
        ] {
            assert_eq!(country_code(ip(s)), None, "{s} must be unknown");
        }
    }

    #[test]
    fn v4_mapped_v6_routes_to_the_v4_table() {
        // The deliberate A3 inverse (module doc): ::ffff:8.8.8.8 IS the v4 host — geography, not
        // policy, so the mapping is correct here and forbidden there.
        assert_eq!(country_code(ip("::ffff:8.8.8.8")).as_deref(), Some("us"));
        assert_eq!(country_code(ip("::ffff:10.0.0.1")), None);
    }
}
