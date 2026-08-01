/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! The shared START-TABLE search: one binary search under BOTH embedded-data engines
//! ([`super::geoip`], [`super::asn`]).
//!
//! A start-table is a sorted array of fixed-size records `[start key BE][payload]` where a record
//! claims `[start, next.start)` and gaps carry an explicit sentinel payload (each engine defines its
//! own). Keys are BIG-ENDIAN by construction, so lexicographic byte comparison IS numeric
//! comparison — the one search body serves u32, u64, and u128 keys without a generic in sight.

/// The rightmost record with `start <= key` claims the key; returns its payload slice.
/// `None` only when the key precedes the first record (or the table is empty/fractured) — sentinel
/// mapping is the CALLER's contract, this layer doesn't know one payload from another.
pub(crate) fn lookup<'t>(table: &'t [u8], rec: usize, key_len: usize, key: &[u8]) -> Option<&'t [u8]> {
    debug_assert_eq!(key.len(), key_len, "key width must match the table's key field");
    let n = table.len() / rec;
    // partition point of `start <= key` over record indices.
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if &table[mid * rec..mid * rec + key_len] <= key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return None;
    }
    table.get((lo - 1) * rec + key_len..lo * rec)
}
