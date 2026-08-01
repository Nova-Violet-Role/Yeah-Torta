/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! A5 slice-3 — ASN: the `asn` producer, completing the tracker's attribution trio (cc/flag/asn).
//!
//! `IP → AS name` ("GOOGLE", "CLOUDFLARENET"), answered from three embedded blobs built out of the
//! iptoasn.com aggregated BGP dumps (public domain; `examples/asn_gen.rs` is the generator —
//! re-download, regenerate, recommit to refresh. BGP moves faster than RIR delegations, so this
//! ages quicker than [`super::geoip`]; still: names attribute, they never authorize).
//!
//! ## The tables (the [`super::start_table`] shape, third payload)
//! `asn4.bin` = 7-byte records `[start: u32 BE][name_id: u24 BE]`; `asn6.bin` = 19-byte records
//! `[start: u128 BE][name_id]`. A record claims `[start, next.start)`; unrouted space carries the
//! `0xFF_FFFF` UNKNOWN sentinel. `asnames.bin` = `[u32 count][u32 offsets × count+1][utf8 bytes]`
//! (all BE) — `name_id` indexes the offset table, names interned across both families.
//!
//! ## Why FULL u128 v6 keys (unlike geoip's high-64)
//! Measured, not assumed: 215 routed ranges in the live dump cut BELOW /64 (UNIVHAWAII owns
//! `2001:388:cf0e::`–`::1`, AARNET starts at `::2`). High-64 keys would mis-attribute every one of
//! them; the RIR geoip source never delegates that fine, the BGP table does. 12 extra bytes per
//! record buys correctness.
//!
//! ## The caveat law, same as geoip
//! Nothing on a verdict path reads this module — attribution informs the panel, never a DENY. And
//! every corrupt-data path degrades to `None` (the honest blank), never a panic on a render path.

use std::net::IpAddr;

/// The v4 table: ~3.3 MB of `.rodata`. Zero runtime I/O, zero parse, zero heap until a hit.
static TABLE4: &[u8] = include_bytes!("../../data/asn4.bin");

/// The v6 table: ~2.9 MB (sparse BGP v6 space means many sentinel gap records — the flat-table
/// price, paid once at build).
static TABLE6: &[u8] = include_bytes!("../../data/asn6.bin");

/// The interned name blob: ~2 MB, ~83k distinct AS names shared by both tables.
static NAMES: &[u8] = include_bytes!("../../data/asnames.bin");

const REC4: usize = 7;
const REC6: usize = 19;
/// The u24 UNKNOWN sentinel — a gap record's `name_id`.
const SENTINEL: [u8; 3] = [0xFF; 3];

/// The AS name announcing a destination IP (`"GOOGLE"`), or `None` for unrouted/unknown space —
/// the tracker's `asn = ""`, which the ASN fold skips (the `asName != ''` Dao discipline).
pub fn as_name(ip: IpAddr) -> Option<String> {
    let id = match ip {
        IpAddr::V4(v4) => lookup(TABLE4, REC4, &u32::from(v4).to_be_bytes()),
        // The deliberate A3 inverse, same as geoip: a v4-mapped destination IS the v4 host, and
        // this path renders attribution, never policy.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(mapped) => lookup(TABLE4, REC4, &u32::from(mapped).to_be_bytes()),
            None => lookup(TABLE6, REC6, &u128::from(v6).to_be_bytes()),
        },
    }?;
    name_at(NAMES, id)
}

/// Start-table probe → `name_id`, or `None` on the sentinel / before the first record.
fn lookup(table: &[u8], rec: usize, key: &[u8]) -> Option<u32> {
    let id = super::start_table::lookup(table, rec, key.len(), key)?;
    if id == SENTINEL {
        return None;
    }
    Some(u32::from(id[0]) << 16 | u32::from(id[1]) << 8 | u32::from(id[2]))
}

/// `name_id` → the interned name. Every malformed-blob path (id past count, offsets out of range,
/// non-UTF-8) degrades to `None` — corrupt data renders blank, never panics.
fn name_at(blob: &[u8], id: u32) -> Option<String> {
    let word = |at: usize| -> Option<u32> {
        Some(u32::from_be_bytes(blob.get(at..at + 4)?.try_into().ok()?))
    };
    let count = word(0)?;
    if id >= count {
        return None;
    }
    let id = id as usize;
    let base = 4 + 4 * (count as usize + 1);
    let lo = word(4 + 4 * id)? as usize;
    let hi = word(4 + 4 * (id + 1))? as usize;
    if lo > hi {
        return None;
    }
    let bytes = blob.get(base + lo..base + hi)?;
    String::from_utf8(bytes.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A hand-built 7-byte-record table + name blob exercising every boundary:
    /// [10,20) = ALPHA · [20,30) = SENTINEL gap · [30,50) = BETA · [50,∞) = SENTINEL tail.
    fn fixture() -> (Vec<u8>, Vec<u8>) {
        let mut t = Vec::new();
        for (start, id) in [
            (10u32, [0, 0, 0]),
            (20, [0xFF; 3]),
            (30, [0, 0, 1]),
            (50, [0xFF; 3]),
        ] {
            t.extend_from_slice(&start.to_be_bytes());
            t.extend_from_slice(&id);
        }
        let mut names = Vec::new();
        names.extend_from_slice(&2u32.to_be_bytes());
        for off in [0u32, 5, 9] {
            names.extend_from_slice(&off.to_be_bytes());
        }
        names.extend_from_slice(b"ALPHABETA");
        (t, names)
    }

    #[test]
    fn lookup_and_name_boundary_semantics_on_a_synthetic_table() {
        let (t, names) = fixture();
        let probe = |k: u32| lookup(&t, REC4, &k.to_be_bytes()).and_then(|id| name_at(&names, id));
        assert_eq!(probe(9), None, "before the first record");
        assert_eq!(probe(10).as_deref(), Some("ALPHA"), "inclusive range start");
        assert_eq!(probe(19).as_deref(), Some("ALPHA"), "last key of the range");
        assert_eq!(probe(20), None, "sentinel gap");
        assert_eq!(probe(30).as_deref(), Some("BETA"));
        assert_eq!(probe(49).as_deref(), Some("BETA"));
        assert_eq!(probe(50), None, "tail sentinel claims the rest");
        assert_eq!(
            lookup(&[], REC4, &42u32.to_be_bytes()),
            None,
            "empty table never panics"
        );
        // Corrupt-blob degradation: id past count, truncated blob.
        assert_eq!(
            name_at(&names, 2),
            None,
            "id past count is blank, not a panic"
        );
        assert_eq!(
            name_at(&names[..6], 0),
            None,
            "truncated blob is blank, not a panic"
        );
    }

    #[test]
    fn embedded_tables_are_well_formed() {
        let count = u32::from_be_bytes(NAMES[0..4].try_into().unwrap());
        assert!(count > 50_000, "implausibly few AS names ({count})");
        for (table, rec, floor, label) in
            [(TABLE4, REC4, 300_000, "v4"), (TABLE6, REC6, 100_000, "v6")]
        {
            assert_eq!(table.len() % rec, 0, "{label}: fractured record");
            let n = table.len() / rec;
            assert!(n > floor, "{label}: implausibly small table ({n} records)");
            let key_len = rec - 3;
            for i in 1..n {
                assert!(
                    table[(i - 1) * rec..(i - 1) * rec + key_len]
                        < table[i * rec..i * rec + key_len],
                    "{label}: starts not strictly increasing at record {i}"
                );
                let id = &table[i * rec + key_len..(i + 1) * rec];
                let id = u32::from(id[0]) << 16 | u32::from(id[1]) << 8 | u32::from(id[2]);
                assert!(
                    id == 0xFF_FFFF || id < count,
                    "{label}: record {i} names a ghost (id {id} >= {count})"
                );
            }
            let first = &table[key_len..rec];
            assert_ne!(first, SENTINEL, "{label}: table opens on a sentinel");
        }
    }

    #[test]
    fn stable_anchors_resolve_to_their_networks() {
        // Anchors chosen for years-stable announcements (and measured in the live dump).
        assert_eq!(as_name(ip("8.8.8.8")).as_deref(), Some("GOOGLE"));
        assert_eq!(as_name(ip("1.1.1.1")).as_deref(), Some("CLOUDFLARENET"));
        // THE sub-/64 witness — the measured range that forced full u128 keys: UNIVHAWAII owns
        // exactly `2001:388:cf0e::`–`::1`; AARNET takes over at `::2`. High-64 keys could not
        // tell these apart.
        assert_eq!(
            as_name(ip("2001:388:cf0e::1")).as_deref(),
            Some("UNIVHAWAII")
        );
        assert!(
            as_name(ip("2001:388:cf0e::2")).is_some_and(|n| n.starts_with("AARNET")),
            "the other side of the sub-/64 cut"
        );
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
        ] {
            assert_eq!(as_name(ip(s)), None, "{s} must be unknown");
        }
    }

    #[test]
    fn v4_mapped_v6_routes_to_the_v4_table() {
        assert_eq!(as_name(ip("::ffff:8.8.8.8")).as_deref(), Some("GOOGLE"));
        assert_eq!(as_name(ip("::ffff:10.0.0.1")), None);
    }
}
