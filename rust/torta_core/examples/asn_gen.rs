/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! A5 slice-3 — the ASN table generator (a DEV TOOL: `examples/` never ships in the cdylib).
//!
//! Builds the embedded `IP → AS name` start-tables consumed by `warden::asn` from the iptoasn.com
//! aggregated BGP dumps (public domain / PDDL):
//!
//! ```text
//! curl -O https://iptoasn.com/data/ip2asn-v4.tsv.gz   # gunzip both
//! curl -O https://iptoasn.com/data/ip2asn-v6.tsv.gz
//! cargo run --release --example asn_gen -- <out_dir> <ip2asn-v4.tsv> <ip2asn-v6.tsv>
//! ```
//!
//! ## Source format (measured from the live dumps, 2026-07)
//! One range per line: `start\tend\tas_number\tcc\tas_description` — textual addresses, INCLUSIVE
//! ends. Unrouted space is `0\tNone\tNot routed` (skipped → sentinel gaps). Ends are NOT /64
//! aligned: 215 routed v6 ranges cut below /64 (real BGP slices), so the v6 table keys on the FULL
//! u128 — unlike `geoip6.bin`, whose RIR source never delegates finer than /64.
//!
//! ## Output format (the `warden::start_table` shape)
//! Sorted fixed records `[start key BE][name_id: 3 bytes BE]`; a record claims `[start, next.start)`.
//! `asn4.bin` = 7-byte records (u32 key); `asn6.bin` = 19-byte records (u128 key). Gaps carry the
//! explicit `0xFF_FFFF` UNKNOWN sentinel so one search answers both "which AS" and "unrouted".
//! `asnames.bin` = `[u32 count][u32 offsets × count+1][utf8 bytes]`, all BE — `name_id` indexes the
//! offset table; names are interned across BOTH families (adjacent same-NAME ranges merge, so two
//! ASNs of one org fold into one record when contiguous — attribution is by name, not number).

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The 3-byte UNKNOWN sentinel — also the hard cap on distinct names (asserted at emit).
const SENTINEL: u32 = 0xFF_FFFF;

/// start → (inclusive end, interned name id). BTreeMap keeps emission sorted.
type Ranges = BTreeMap<u128, (u128, u32)>;

#[derive(Default)]
struct Names {
    ids: HashMap<String, u32>,
    list: Vec<String>,
}

impl Names {
    fn intern(&mut self, name: &str) -> u32 {
        if let Some(&id) = self.ids.get(name) {
            return id;
        }
        let id = self.list.len() as u32;
        self.ids.insert(name.to_owned(), id);
        self.list.push(name.to_owned());
        id
    }
}

/// Insert dropping any overlap FIRST-IN-WINS (the dumps should be disjoint; trust nothing).
fn insert(ranges: &mut Ranges, start: u128, end: u128, id: u32, dropped: &mut u64) {
    if let Some((_, &(prev_end, _))) = ranges.range(..=start).next_back() {
        if prev_end >= start {
            *dropped += 1;
            return;
        }
    }
    if let Some((&next_start, _)) = ranges.range(start..).next() {
        if next_start <= end {
            *dropped += 1;
            return;
        }
    }
    ranges.insert(start, (end, id));
}

/// Merge adjacent same-name ranges, then emit start records + gap sentinels.
fn emit(path: &std::path::Path, ranges: &Ranges, key_bytes: usize, key_max: u128) -> (u64, u64, u64) {
    let mut out = Vec::new();
    let mut write_rec = |start: u128, id: u32| {
        out.extend_from_slice(&start.to_be_bytes()[16 - key_bytes..]);
        out.extend_from_slice(&id.to_be_bytes()[1..]);
    };
    let (mut merged, mut gaps) = (0u64, 0u64);
    let mut pending: Option<(u128, u128, u32)> = None;
    let flush = |p: (u128, u128, u32), next_start: Option<u128>, write: &mut dyn FnMut(u128, u32)| {
        write(p.0, p.2);
        let contiguous = next_start == p.1.checked_add(1);
        if !contiguous && p.1 < key_max {
            write(p.1 + 1, SENTINEL);
            return 1;
        }
        0
    };
    for (&start, &(end, id)) in ranges {
        match pending {
            Some(p) if p.1 + 1 == start && p.2 == id => {
                pending = Some((p.0, end, id));
                merged += 1;
            }
            Some(p) => {
                gaps += flush(p, Some(start), &mut write_rec);
                pending = Some((start, end, id));
            }
            None => pending = Some((start, end, id)),
        }
    }
    if let Some(p) = pending {
        gaps += flush(p, None, &mut write_rec);
    }
    std::fs::write(path, &out).expect("write table");
    let records = out.len() as u64 / (key_bytes as u64 + 3);
    (records, merged, gaps)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [out_dir, v4_file, v6_file] = &args[..] else {
        eprintln!("usage: asn_gen <out_dir> <ip2asn-v4.tsv> <ip2asn-v6.tsv>");
        std::process::exit(2);
    };
    let out_dir = std::path::Path::new(out_dir);

    let mut names = Names::default();
    let (mut v4, mut v6) = (Ranges::new(), Ranges::new());
    let (mut kept, mut skipped, mut dropped) = (0u64, 0u64, 0u64);

    for (file, is_v4) in [(v4_file, true), (v6_file, false)] {
        let text = std::fs::read_to_string(file).expect("read tsv");
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            let (Some(&start), Some(&end), Some(&asn), Some(&name)) =
                (f.first(), f.get(1), f.get(2), f.get(4))
            else {
                skipped += 1;
                continue;
            };
            if asn == "0" || name.is_empty() {
                skipped += 1;
                continue;
            }
            let id = names.intern(name);
            let parsed = if is_v4 {
                start
                    .parse::<Ipv4Addr>()
                    .ok()
                    .zip(end.parse::<Ipv4Addr>().ok())
                    .map(|(s, e)| (u32::from(s) as u128, u32::from(e) as u128))
            } else {
                start
                    .parse::<Ipv6Addr>()
                    .ok()
                    .zip(end.parse::<Ipv6Addr>().ok())
                    .map(|(s, e)| (u128::from(s), u128::from(e)))
            };
            let Some((s, e)) = parsed.filter(|(s, e)| s <= e) else {
                skipped += 1;
                continue;
            };
            kept += 1;
            insert(if is_v4 { &mut v4 } else { &mut v6 }, s, e, id, &mut dropped);
        }
    }
    assert!(
        (names.list.len() as u32) < SENTINEL,
        "name count collides with the sentinel"
    );

    let (r4, m4, g4) = emit(&out_dir.join("asn4.bin"), &v4, 4, u32::MAX as u128);
    let (r6, m6, g6) = emit(&out_dir.join("asn6.bin"), &v6, 16, u128::MAX);

    // asnames.bin: [count][offsets × count+1][bytes], offsets relative to the bytes region.
    let mut blob = Vec::new();
    blob.extend_from_slice(&(names.list.len() as u32).to_be_bytes());
    let mut off = 0u32;
    for name in &names.list {
        blob.extend_from_slice(&off.to_be_bytes());
        off += name.len() as u32;
    }
    blob.extend_from_slice(&off.to_be_bytes());
    for name in &names.list {
        blob.extend_from_slice(name.as_bytes());
    }
    let names_path = out_dir.join("asnames.bin");
    let mut fh = std::fs::File::create(&names_path).expect("create asnames");
    fh.write_all(&blob).expect("write asnames");

    println!(
        "kept={kept} skipped={skipped} overlaps_dropped={dropped} names={}",
        names.list.len()
    );
    println!("v4: {} ranges -> {r4} records ({m4} merged, {g4} gaps) = {} bytes", v4.len(), r4 * 7);
    println!("v6: {} ranges -> {r6} records ({m6} merged, {g6} gaps) = {} bytes", v6.len(), r6 * 19);
    println!("names blob = {} bytes", blob.len());
}
