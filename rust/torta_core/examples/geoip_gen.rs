/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! A5 slice-2 GENERATOR (dev tool, never ships — `examples/` is not a cdylib surface): RIR
//! delegated-stats → the two GeoIP start-tables `warden/geoip.rs` embeds.
//!
//! Input: the five RIR "delegated" files (RIR statistics exchange format,
//! `registry|cc|type|start|value|date|status[|opaque]`; v4 `value` = ADDRESS COUNT, v6 `value` =
//! PREFIX LENGTH). Kept: `status ∈ {allocated, assigned}`, 2-ASCII-letter `cc`, `cc != ZZ` (the
//! unspecified placeholder). Source: `https://ftp.ripe.net/pub/stats/<rir>/delegated-<rir>-latest`
//! (RIPE mirrors all five registries; ARIN publishes extended-only).
//!
//! Output format (the `geoip.rs` contract — fixed-size records, START-TABLE with gap sentinels):
//! - `geoip4.bin` — 6-byte records `[start: u32 BE][cc: 2 lowercase bytes]`, sorted by start.
//! - `geoip6.bin` — 10-byte records `[start: u64 BE][cc]`, the address's HIGH 64 BITS (RIR country
//!   granularity is never finer than /64).
//! A record claims `[start, next.start)`; `cc = [0,0]` is the UNKNOWN sentinel filling every
//! allocation gap, so one `partition_point` answers both "which country" and "unallocated".
//! Adjacent same-cc ranges are merged before emission (the RIR files are full of sequential
//! same-country blocks).
//!
//! Usage: `cargo run --release --example geoip_gen -- <out_dir> <delegated-file>...`

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

/// One kept allocation as an inclusive range over the family's key space (v4: u32 as u64; v6: the
/// high 64 bits). BTreeMap keyed by start gives sorted iteration for free.
type Ranges = BTreeMap<u64, (u64, [u8; 2])>;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: geoip_gen <out_dir> <delegated-file>...");
        std::process::exit(2);
    }
    let out_dir = &args[0];

    let mut v4: Ranges = BTreeMap::new();
    let mut v6: Ranges = BTreeMap::new();
    let (mut kept, mut skipped, mut overlaps) = (0u64, 0u64, 0u64);

    for path in &args[1..] {
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        for line in text.lines() {
            let f: Vec<&str> = line.split('|').collect();
            if f.len() < 7 {
                continue; // version header / comments
            }
            let (cc, typ, start, value, status) = (f[1], f[2], f[3], f[4], f[6]);
            if status != "allocated" && status != "assigned" {
                continue;
            }
            let cc_b = cc.as_bytes();
            if cc_b.len() != 2
                || !cc_b[0].is_ascii_alphabetic()
                || !cc_b[1].is_ascii_alphabetic()
                || cc.eq_ignore_ascii_case("zz")
            {
                skipped += 1;
                continue;
            }
            let cc2 = [cc_b[0].to_ascii_lowercase(), cc_b[1].to_ascii_lowercase()];
            match typ {
                "ipv4" => {
                    let (Ok(ip), Ok(count)) =
                        (start.parse::<std::net::Ipv4Addr>(), value.parse::<u64>())
                    else {
                        skipped += 1;
                        continue;
                    };
                    if count == 0 {
                        skipped += 1;
                        continue;
                    }
                    let s = u32::from(ip) as u64;
                    // v4 `value` is a COUNT (need not be a CIDR-shaped power of two) — the
                    // range table absorbs any shape; saturate at the top of the space.
                    let e = (s + count - 1).min(u32::MAX as u64);
                    overlaps += insert(&mut v4, s, e, cc2);
                    kept += 1;
                }
                "ipv6" => {
                    let (Ok(ip), Ok(prefix)) = (start.parse::<Ipv6Addr>(), value.parse::<u32>())
                    else {
                        skipped += 1;
                        continue;
                    };
                    let hi = (u128::from(ip) >> 64) as u64;
                    // Prefix ≤ 64: the block spans 2^(64-prefix) /64-slots. Prefix > 64 (a
                    // sub-/64 assignment, vanishingly rare): one /64 slot.
                    let e = if prefix >= 64 {
                        hi
                    } else {
                        hi | ((1u64 << (64 - prefix)) - 1)
                    };
                    overlaps += insert(&mut v6, hi, e, cc2);
                    kept += 1;
                }
                _ => {} // asn / summary lines
            }
        }
    }

    let (t4, m4, g4) = emit(&v4, 4);
    let (t6, m6, g6) = emit(&v6, 8);
    std::fs::write(format!("{out_dir}/geoip4.bin"), &t4).expect("write geoip4.bin");
    std::fs::write(format!("{out_dir}/geoip6.bin"), &t6).expect("write geoip6.bin");
    println!(
        "kept={kept} skipped={skipped} overlaps_dropped={overlaps}\n\
         v4: {} allocations -> {} merged ranges + {} gap sentinels = {} bytes\n\
         v6: {} allocations -> {} merged ranges + {} gap sentinels = {} bytes",
        v4.len(),
        m4,
        g4,
        t4.len(),
        v6.len(),
        m6,
        g6,
        t6.len(),
    );
}

/// Insert an inclusive range, DROPPING it if it overlaps an already-kept one (first-in wins; the
/// per-family RIR files are disjoint — a cross-file overlap is a transfer artifact worth counting,
/// not worth double-claiming). Returns 1 if dropped as an overlap.
fn insert(map: &mut Ranges, s: u64, e: u64, cc: [u8; 2]) -> u64 {
    // Neighbor before: overlaps if its end reaches s. Neighbor at/after: overlaps if within e.
    if let Some((_, (pe, _))) = map.range(..=s).next_back() {
        if *pe >= s {
            return 1;
        }
    }
    if map.range(s..=e).next().is_some() {
        return 1;
    }
    map.insert(s, (e, cc));
    0
}

/// Merge adjacent same-cc ranges, then serialize the start-table: one record per range start plus
/// a `[0,0]` UNKNOWN sentinel after every range whose successor is not contiguous (and after the
/// final range). Returns (bytes, merged_range_count, gap_sentinel_count).
fn emit(map: &Ranges, key_bytes: usize) -> (Vec<u8>, u64, u64) {
    let mut merged: Vec<(u64, u64, [u8; 2])> = Vec::with_capacity(map.len());
    for (&s, &(e, cc)) in map {
        match merged.last_mut() {
            Some(last) if last.2 == cc && last.1 + 1 == s => last.1 = e,
            _ => merged.push((s, e, cc)),
        }
    }
    let mut out = Vec::with_capacity(merged.len() * (key_bytes + 2) * 2);
    let mut gaps = 0u64;
    let push_key = |out: &mut Vec<u8>, k: u64| match key_bytes {
        4 => out.extend_from_slice(&(k as u32).to_be_bytes()),
        _ => out.extend_from_slice(&k.to_be_bytes()),
    };
    for (i, &(s, e, cc)) in merged.iter().enumerate() {
        push_key(&mut out, s);
        out.extend_from_slice(&cc);
        let contiguous_next = merged.get(i + 1).is_some_and(|n| n.0 == e + 1);
        if !contiguous_next && e < key_max(key_bytes) {
            push_key(&mut out, e + 1);
            out.extend_from_slice(&[0, 0]);
            gaps += 1;
        }
    }
    (out, merged.len() as u64, gaps)
}

fn key_max(key_bytes: usize) -> u64 {
    if key_bytes == 4 {
        u32::MAX as u64
    } else {
        u64::MAX
    }
}
