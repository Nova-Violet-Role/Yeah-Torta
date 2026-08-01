/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! UNIVERSAL pure-Rust muscle ports (Stream B, `pure_rust` feature) — Haskell≡Rust, no GHC.
//!
//! These are byte-faithful Rust ports of the pure-algebra Haskell muscles in
//! `hatter/torta-headless/TortaHs.hs`, so an x86_64 (or any) build with `--features pure_rust` runs the WHOLE
//! engine with NO `libtorta_hs.so` / GHC RTS — letting the host x86_64 AVD test the full app
//! ([[torta-UNIVERSAL-RUST-ONLY-PLAN.md]]). **Completely separate from the arm64 Haskell APK:** the whole
//! module is `#[cfg(feature = "pure_rust")]`, so the shipping arm64 `.so` (`--features mirror`, NO pure_rust)
//! compiles ZERO of it → byte-identical baseline; arm64 keeps dlopen-ing the real Haskell muscles.
//!
//! Each port mirrors its Haskell twin EXACTLY (same clamps, same thresholds, same branch order) — the Haskell
//! is the source of truth; the tests below are hand-computed from the published Haskell formula (cross-checkable
//! against `hatter/torta-headless/Test.hs`). #3 resolver_score · #4 blocklist_band · #5 beast_preset/clamp ·
//! #9 dnscrypt_trust · #10 update_verdict. (Muscles #1/#2 = the Rust Fortress validator; #6/#7/#8 already have
//! Rust twins in mirror/localcdn.rs + warden.rs.)

#![forbid(unsafe_code)]
// SLICE-1 SCAFFOLD: the ports are exercised in full by the unit tests below; the feature-gated binding cascade
// in lib.rs (slice 2) wires them into the JNI surface (replacing the dlopen-Haskell arm under `pure_rust`),
// which drops this allow. NEVER a fabricated green — `cargo test --features pure_rust` proves every port.

/// Integer clamp to `[lo, hi]` (Haskell `clampI`).
fn clamp_i(lo: i32, hi: i32, x: i32) -> i32 {
    x.max(lo).min(hi)
}

// ---- #3 resolver_score (TortaHs.hs:138 resolverScore) ----

/// Latency band: ≤20 ms = 100, ≥500 ms = 0, linear between (TortaHs.hs:148).
fn latency_score(rtt: i32) -> i32 {
    if rtt <= 20 {
        100
    } else if rtt >= 500 {
        0
    } else {
        100 - ((rtt - 20) * 100) / 480
    }
}

/// Recency band: ≤60 s = 100, ≥3600 s = 0, linear between (TortaHs.hs:155).
fn recency_score(age: i32) -> i32 {
    if age <= 60 {
        100
    } else if age >= 3600 {
        0
    } else {
        100 - ((age - 60) * 100) / 3540
    }
}

/// The resolver trust score 0..100 (TortaHs.hs:138). `age_secs` is i64 at the binding; clamped to `[0,3600]`
/// before [`recency_score`] (anything ≥3600 → 0, so the clamp preserves the Haskell result without i64 overflow).
pub fn resolver_score(rtt0: i32, success0: i32, fails0: i32, age0: i64) -> i32 {
    let rtt = rtt0.max(0);
    let success = clamp_i(0, 100, success0);
    let fails = fails0.max(0);
    let age = age0.clamp(0, 3600) as i32;
    let score = (latency_score(rtt) * 35 + success * 45 + recency_score(age) * 20) / 100
        - (fails * 5).min(40);
    clamp_i(0, 100, score)
}

// ---- #4 blocklist_band (TortaHs.hs:180 blocklistTrustBand) ----

/// Staleness penalty: ≤7 days = 0, ≥180 = 50, linear between (TortaHs.hs:195).
fn staleness_penalty(d: i32) -> i32 {
    if d <= 7 {
        0
    } else if d >= 180 {
        50
    } else {
        ((d - 7) * 50) / 173
    }
}

/// Size legitimacy: <10 = -20, <100 = 0, ≤5M = +10, else -10 (TortaHs.hs:203).
fn size_legitimacy(n: i32) -> i32 {
    if n < 10 {
        -20
    } else if n < 100 {
        0
    } else if n <= 5_000_000 {
        10
    } else {
        -10
    }
}

/// Blocklist trust band: 0 UNTRUSTED · 1 LOW · 2 MEDIUM · 3 HIGH · 4 VERIFIED (signed + score ≥ 80).
/// (TortaHs.hs:180.) `signed` is the decoded bool (the binding passes `signed != 0`).
pub fn blocklist_band(rep0: i32, age_days0: i32, entries0: i32, signed: bool) -> i32 {
    let rep = clamp_i(0, 100, rep0);
    let age_days = age_days0.max(0);
    let entries = entries0.max(0);
    let sig_boost = if signed { 30 } else { 0 };
    let score = clamp_i(
        0,
        100,
        rep - staleness_penalty(age_days) + size_legitimacy(entries) + sig_boost,
    );
    if signed && score >= 80 {
        4
    } else if score >= 70 {
        3
    } else if score >= 50 {
        2
    } else if score >= 30 {
        1
    } else {
        0
    }
}

// ---- #5 beast_preset / beast_clamp (TortaHs.hs:234 / :245) ----

/// The canonical BEAST preset table (TortaHs.hs:234, GROUND_TRUTH'd from EngineConfig.kt). preset 0 DEFAULT ·
/// 1 FAST_PING · 2 OMEGA_BANDWIDTH · 3 UPLOAD_DOWNLOAD; field 0 cycleMs · 1 maxWindow · 2 freeThreshMilli ·
/// 3 competeThreshMilli. Returns -1 on a bad id/field.
pub fn beast_preset(preset: i32, field: i32) -> i32 {
    let table: &[i32] = match preset {
        0 => &[5000, 16, 1050, 1250],
        1 => &[3000, 8, 1020, 1150],
        2 => &[5000, 32, 1100, 1500],
        3 => &[4000, 24, 1050, 1400],
        _ => return -1,
    };
    if field >= 0 && (field as usize) < table.len() {
        table[field as usize]
    } else {
        -1
    }
}

/// The Expert-mode safe-range clamp (TortaHs.hs:245). An unknown field passes through unchanged.
pub fn beast_clamp(field: i32, raw: i32) -> i32 {
    match field {
        0 => clamp_i(1000, 60000, raw), // cycleMs
        1 => clamp_i(2, 64, raw),       // maxWindow
        2 => clamp_i(1000, 2000, raw),  // freeThresh milliunits
        3 => clamp_i(1010, 3000, raw),  // competeThresh milliunits
        _ => raw,
    }
}

// ---- #9 dnscrypt_trust (TortaHs.hs dnscryptTrust) ----

/// The DNS-Stamps privacy-property trust band: 0 MINIMAL · 1 LOW · 2 MEDIUM · 3 HIGH · 4 MAXIMUM
/// (Haskell `dnscryptTrust`). `props` bits: 0x1 dnssec · 0x2 nolog · 0x4 nofilter; `anon_relay` decoded bool.
pub fn dnscrypt_trust(props: i32, anon_relay: bool) -> i32 {
    let dnssec = props & 1 != 0;
    let nolog = props & 2 != 0;
    let nofilter = props & 4 != 0;
    let score = (if dnssec { 25 } else { 0 })
        + (if nolog { 35 } else { 0 })
        + (if nofilter { 20 } else { 0 })
        + (if anon_relay { 20 } else { 0 });
    if score >= 90 {
        4
    } else if score >= 65 {
        3
    } else if score >= 40 {
        2
    } else if score >= 20 {
        1
    } else {
        0
    }
}

// ---- #10 update_verdict (TortaHs.hs updateVerdict) ----

/// The verify-sig-FIRST update apply-decision (Haskell `updateVerdict`): 0 APPLY · 1 REJECT_BAD_SIG ·
/// 2 REJECT_UNTRUSTED · 3 REJECT_BAD_SIZE · 4 REJECT_DOWNGRADE · 5 ALREADY_CURRENT. Security-first branch order.
pub fn update_verdict(sig_valid: i32, version_cmp: i32, size_ok: i32, source_trusted: i32) -> i32 {
    if sig_valid == 0 {
        1
    } else if source_trusted == 0 {
        2
    } else if size_ok == 0 {
        3
    } else if version_cmp < 0 {
        4
    } else if version_cmp == 0 {
        5
    } else {
        0
    }
}

// ---- probe (TortaHs.hs:48 torta_hs_probe) — the C7 rail proof ----

/// The trivial rail-proof muscle: `n*2+42` (Haskell `torta_hs_probe`; probe(100)=242). Wrapping (CInt 32-bit
/// arithmetic, matching the Haskell `fromIntegral`), never panics.
pub fn probe(n: i32) -> i32 {
    n.wrapping_mul(2).wrapping_add(42)
}

// ---- #6 centauri_entry / centauri_substitute (TortaHs.hs:288 / :302) ----

/// CDN-servable mime ids: 1 JS · 2 CSS · 3 woff · 4 woff2 · 5 wasm (TortaHs.hs:297).
fn valid_mime(m: i32) -> bool {
    matches!(m, 1..=5)
}

/// Catalog-entry serve-eligibility (TortaHs.hs:288): 0 SERVE_OK · 1 BAD_HASH · 2 BAD_SIZE · 3 BAD_MIME ·
/// 4 UNSIGNED. `signed` is the decoded bool; size capped at 50 MiB.
pub fn centauri_entry(hash_len: i32, size: i32, mime_id: i32, signed: bool) -> i32 {
    if hash_len != 32 && hash_len != 64 {
        1
    } else if size <= 0 || size > 52_428_800 {
        2
    } else if !valid_mime(mime_id) {
        3
    } else if !signed {
        4
    } else {
        0
    }
}

/// Version-substitution algebra over semver triples (TortaHs.hs:302): 0 EXACT · 1 SAFE_NEWER · 2 RISKY_OLDER ·
/// 3 INCOMPATIBLE (different major is the compatibility boundary). The version-COMPONENT shape the binding
/// uses (mirror::localcdn::substitution is the &str twin for the serve path).
pub fn centauri_substitute(
    r_maj: i32,
    r_min: i32,
    r_pat: i32,
    a_maj: i32,
    a_min: i32,
    a_pat: i32,
) -> i32 {
    if a_maj != r_maj {
        3
    } else if a_min == r_min && a_pat == r_pat {
        0
    } else if (a_min, a_pat) >= (r_min, r_pat) {
        1
    } else {
        2
    }
}

// ---- #8 warden_cidr_match (TortaHs.hs:355) ----

/// IPv4 CIDR containment (TortaHs.hs:355): prefix 0 = match-all; invalid prefix (>32) = 0; else 32-bit
/// host-order mask compare. Returns 1 (in-range) or 0. The `prefix==0` early-return avoids a 32-bit shift-by-32.
pub fn warden_cidr_match(ip: u32, prefix: i32, net: u32) -> i32 {
    if prefix == 0 {
        1
    } else if !(1..=32).contains(&prefix) {
        0
    } else {
        let mask: u32 = 0xFFFF_FFFFu32 << (32 - prefix);
        i32::from(ip & mask == net & mask)
    }
}

// ---- byte helpers + #1/#2/#7 byte-parsing muscles (TortaHs.hs dnssecVerdict/dsLinkVerdict/wardenDomainMatch) ----

/// Big-endian 16-bit read at `i` (network order). Caller guarantees `b.len() > i+1` (every call site length-
/// guards first, matching the Haskell `be16` which assumes the bounds the verdict guards establish).
fn be16(b: &[u8], i: usize) -> u16 {
    ((b[i] as u16) << 8) | (b[i + 1] as u16)
}

/// Big-endian 32-bit read at `i`. Caller guarantees `b.len() > i+3`.
fn be32(b: &[u8], i: usize) -> u32 {
    ((b[i] as u32) << 24) | ((b[i + 1] as u32) << 16) | ((b[i + 2] as u32) << 8) | (b[i + 3] as u32)
}

/// DNSKEY key tag (RFC 4034 App B), the Haskell `keyTag`: a 16-bit ones-complement-style sum over the rdata,
/// even octets high-byte, odd low-byte, carry folded. Wrapping (never panics, iterates the whole slice).
fn key_tag(rdata: &[u8]) -> u32 {
    let mut ac: u32 = 0;
    for (i, &b) in rdata.iter().enumerate() {
        if i % 2 == 0 {
            ac = ac.wrapping_add((b as u32) << 8);
        } else {
            ac = ac.wrapping_add(b as u32);
        }
    }
    ac = ac.wrapping_add((ac >> 16) & 0xFFFF);
    ac & 0xFFFF
}

/// DNSSEC signing algorithms the STRUCTURAL validator accepts (Haskell `supportedAlgo`, broader than the crypto
/// set — the structural check is permissive; the crypto leg is the Fortress validator's job).
fn supported_algo(a: u8) -> bool {
    matches!(a, 5 | 7 | 8 | 10 | 13 | 14 | 15 | 16)
}

/// DS digest types the validator accepts (Haskell `supportedDigest`): 2 SHA-256, 4 SHA-384 (SHA-1 rejected).
fn supported_digest(d: u8) -> bool {
    matches!(d, 2 | 4)
}

/// #1 — STRUCTURAL RRSIG validation over rdata bytes (TortaHs.hs `dnssecVerdict`). Verdict: 0 VALID · 1
/// KEYTAG_MISMATCH · 2 EXPIRED · 3 NOT_YET_VALID · 4 ALGO_MISMATCH · 5 UNSUPPORTED_ALGO · 6 BAD_DNSKEY ·
/// 7 MALFORMED. The crypto leg is the Fortress validator; this is the cheap structural gate. Never panics (the
/// length guards make every fixed-offset read in-bounds, exactly the Haskell guard order).
pub fn dnssec_validate(rrsig: &[u8], dnskey: &[u8], now: i64) -> i32 {
    if rrsig.len() < 18 || dnskey.len() < 4 {
        return 7;
    }
    if dnskey[2] != 3 {
        return 6; // DNSKEY protocol MUST be 3 (RFC 4034 §2.1.2)
    }
    if be16(dnskey, 0) & 0x0100 == 0 {
        return 6; // ZONE flag (bit 7) must be set
    }
    let rrsig_algo = rrsig[2];
    if !supported_algo(rrsig_algo) {
        return 5;
    }
    if rrsig_algo != dnskey[3] {
        return 4; // RRSIG must be made by THIS DNSKEY's algorithm
    }
    let now = now.max(0);
    if now < be32(rrsig, 12) as i64 {
        return 3; // NOT_YET_VALID (inception)
    }
    if now > be32(rrsig, 8) as i64 {
        return 2; // EXPIRED
    }
    if be16(rrsig, 16) as u32 != key_tag(dnskey) {
        return 1; // KEYTAG_MISMATCH
    }
    0
}

/// #2 — STRUCTURAL DS↔DNSKEY delegation-link validation (TortaHs.hs `dsLinkVerdict`). Verdict: 0 VALID ·
/// 1 KEYTAG_MISMATCH · 2 ALGO_MISMATCH · 3 UNSUPPORTED_DIGEST · 4 BAD_DIGEST_LEN · 5 BAD_DNSKEY · 6 MALFORMED.
/// The SHA digest verify is the Fortress validator's job; this is the structural link gate. Never panics.
pub fn dnssec_ds_link(ds: &[u8], dnskey: &[u8]) -> i32 {
    if ds.len() < 5 || dnskey.len() < 4 {
        return 6;
    }
    if dnskey[2] != 3 {
        return 5;
    }
    if be16(dnskey, 0) & 0x0100 == 0 {
        return 5;
    }
    let digest_type = ds[3];
    if !supported_digest(digest_type) {
        return 3;
    }
    let digest_len = (ds.len() - 4) as i32;
    let expected = match digest_type {
        2 => 32, // SHA-256
        4 => 48, // SHA-384
        _ => -1, // unreachable (supported_digest gate)
    };
    if digest_len != expected {
        return 4;
    }
    if ds[2] != dnskey[3] {
        return 2; // ALGO_MISMATCH
    }
    if be16(ds, 0) as u32 != key_tag(dnskey) {
        return 1; // KEYTAG_MISMATCH
    }
    0
}

/// #7 — the WARDEN domain-rule matcher (TortaHs.hs `wardenDomainMatch`). Case-insensitive (ASCII lowercased).
/// Verdict: 0 NO_MATCH · 1 EXACT · 2 SUFFIX (qname is a subdomain of the rule) · 3 WILDCARD (`*.zone` matches
/// the apex + any subdomain). Never panics.
pub fn warden_domain_match(q0: &[u8], p0: &[u8]) -> i32 {
    fn lower(b: u8) -> u8 {
        if b.is_ascii_uppercase() {
            b + 32
        } else {
            b
        }
    }
    // `"." ++ suf` is a strict suffix of xs (xs longer than ".suf").
    fn ends_with_dot(suf: &[u8], xs: &[u8]) -> bool {
        let mut s = Vec::with_capacity(suf.len() + 1);
        s.push(0x2E); // '.'
        s.extend_from_slice(suf);
        xs.len() > s.len() && xs[xs.len() - s.len()..] == s[..]
    }
    let q: Vec<u8> = q0.iter().map(|&b| lower(b)).collect();
    let p: Vec<u8> = p0.iter().map(|&b| lower(b)).collect();
    if p.is_empty() || q.is_empty() {
        return 0;
    }
    let is_wild = p.len() >= 2 && p[0] == 0x2A && p[1] == 0x2E; // "*."
    if is_wild {
        let base = &p[2..];
        if q == base || ends_with_dot(base, &q) {
            3
        } else {
            0
        }
    } else if q == p {
        1
    } else if ends_with_dot(&p, &q) {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_is_the_c7_rail_proof() {
        assert_eq!(probe(100), 242); // the C7 proof
        assert_eq!(probe(0), 42);
    }

    #[test]
    fn centauri_entry_taxonomy() {
        assert_eq!(centauri_entry(32, 1000, 1, true), 0); // SERVE_OK (256-bit, JS, signed)
        assert_eq!(centauri_entry(64, 1000, 2, true), 0); // SERVE_OK (512-bit, CSS)
        assert_eq!(centauri_entry(20, 1000, 1, true), 1); // BAD_HASH
        assert_eq!(centauri_entry(32, 0, 1, true), 2); // BAD_SIZE (empty)
        assert_eq!(centauri_entry(32, 52_428_801, 1, true), 2); // BAD_SIZE (>50MiB)
        assert_eq!(centauri_entry(32, 1000, 9, true), 3); // BAD_MIME
        assert_eq!(centauri_entry(32, 1000, 1, false), 4); // UNSIGNED
    }

    #[test]
    fn centauri_substitute_semver() {
        assert_eq!(centauri_substitute(3, 6, 0, 3, 6, 0), 0); // EXACT
        assert_eq!(centauri_substitute(3, 6, 0, 3, 7, 1), 1); // SAFE_NEWER
        assert_eq!(centauri_substitute(3, 6, 0, 3, 5, 1), 2); // RISKY_OLDER
        assert_eq!(centauri_substitute(3, 6, 0, 4, 0, 0), 3); // INCOMPATIBLE (major)
    }

    #[test]
    fn warden_cidr_containment() {
        // 10.0.0.5 in 10.0.0.0/8 → 1
        assert_eq!(warden_cidr_match(0x0A000005, 8, 0x0A000000), 1);
        // 11.0.0.5 in 10.0.0.0/8 → 0
        assert_eq!(warden_cidr_match(0x0B000005, 8, 0x0A000000), 0);
        // /0 matches everything
        assert_eq!(warden_cidr_match(0x01020304, 0, 0xFFFFFFFF), 1);
        // /32 exact
        assert_eq!(warden_cidr_match(0x0A000001, 32, 0x0A000001), 1);
        assert_eq!(warden_cidr_match(0x0A000001, 32, 0x0A000002), 0);
        // invalid prefix
        assert_eq!(warden_cidr_match(0, 33, 0), 0);
    }

    #[test]
    fn resolver_score_matches_haskell_formula() {
        // perfect: rtt 10 (latency 100), success 100, fails 0, age 30 (recency 100):
        //   (100*35 + 100*45 + 100*20)/100 - min(40,0) = 10000/100 - 0 = 100.
        assert_eq!(resolver_score(10, 100, 0, 30), 100);
        // worthless: rtt 600 (latency 0), success 0, fails 0, age 7200 (recency 0): 0/100 - 0 = 0.
        assert_eq!(resolver_score(600, 0, 0, 7200), 0);
        // fails penalty: rtt 10, success 100, fails 3 (penalty min(40,15)=15), age 30:
        //   100 - 15 = 85.
        assert_eq!(resolver_score(10, 100, 3, 30), 85);
        // negative inputs clamp; huge age (i64) → recency 0.
        assert_eq!(resolver_score(-5, 200, -2, i64::MAX), {
            // rtt 0→latency 100, success clamp 100, fails 0, age 3600→recency 0:
            // (100*35 + 100*45 + 0*20)/100 = 8000/100 = 80.
            80
        });
    }

    #[test]
    fn blocklist_band_matches_haskell() {
        // signed, rep 80, fresh (age 0 penalty 0), entries 1000 (+10), sigBoost +30 → score clamp(0,100,120)=100
        // signed && score>=80 → VERIFIED 4.
        assert_eq!(blocklist_band(80, 0, 1000, true), 4);
        // unsigned, rep 75, fresh, entries 1000 (+10) → score 85 → HIGH 3 (no sig → not 4).
        assert_eq!(blocklist_band(75, 0, 1000, false), 3);
        // tiny list penalty: rep 60, fresh, entries 5 (-20) → score 40 → LOW 1.
        assert_eq!(blocklist_band(60, 0, 5, false), 1);
        // ancient: rep 100, age 200 (penalty 50), entries 1000 (+10) → score 60 → MEDIUM 2.
        assert_eq!(blocklist_band(100, 200, 1000, false), 2);
        // junk: rep 10, fresh, entries 5 (-20) → score clamp(0,..)=0 → UNTRUSTED 0.
        assert_eq!(blocklist_band(10, 0, 5, false), 0);
    }

    #[test]
    fn beast_preset_table_is_canonical() {
        assert_eq!(beast_preset(0, 0), 5000); // DEFAULT cycleMs
        assert_eq!(beast_preset(0, 2), 1050); // DEFAULT freeThresh 1.05
        assert_eq!(beast_preset(1, 1), 8); // FAST_PING maxWindow
        assert_eq!(beast_preset(2, 3), 1500); // OMEGA competeThresh 1.5
        assert_eq!(beast_preset(3, 0), 4000); // UPLOAD_DOWNLOAD cycleMs
        assert_eq!(beast_preset(9, 0), -1); // bad preset
        assert_eq!(beast_preset(0, 9), -1); // bad field
    }

    #[test]
    fn beast_clamp_bounds_each_field() {
        assert_eq!(beast_clamp(0, 100), 1000); // cycleMs floor 1000
        assert_eq!(beast_clamp(0, 999999), 60000); // cycleMs ceil 60000
        assert_eq!(beast_clamp(1, 1), 2); // maxWindow floor 2
        assert_eq!(beast_clamp(2, 3000), 2000); // freeThresh ceil 2000
        assert_eq!(beast_clamp(3, 1), 1010); // competeThresh floor 1010
        assert_eq!(beast_clamp(9, 12345), 12345); // unknown field pass-through
    }

    #[test]
    fn dnscrypt_trust_bands() {
        // all props (1|2|4=7) + anon: 25+35+20+20 = 100 → MAXIMUM 4.
        assert_eq!(dnscrypt_trust(7, true), 4);
        // dnssec+nolog (3) no anon: 25+35 = 60 → MEDIUM 2 (>=40).
        assert_eq!(dnscrypt_trust(3, false), 2);
        // nolog only (2): 35 → LOW 1 (>=20).
        assert_eq!(dnscrypt_trust(2, false), 1);
        // nothing: 0 → MINIMAL 0.
        assert_eq!(dnscrypt_trust(0, false), 0);
        // nolog+nofilter (6) + anon: 35+20+20 = 75 → HIGH 3 (>=65).
        assert_eq!(dnscrypt_trust(6, true), 3);
    }

    #[test]
    fn update_verdict_security_first_order() {
        assert_eq!(update_verdict(0, 1, 1, 1), 1); // bad sig wins over everything
        assert_eq!(update_verdict(1, 1, 1, 0), 2); // untrusted
        assert_eq!(update_verdict(1, 1, 0, 1), 3); // bad size
        assert_eq!(update_verdict(1, -1, 1, 1), 4); // downgrade
        assert_eq!(update_verdict(1, 0, 1, 1), 5); // already current
        assert_eq!(update_verdict(1, 1, 1, 1), 0); // APPLY
    }

    // ---- byte-parsing muscles (#1 dnssec_validate · #2 dnssec_ds_link · #7 warden_domain_match) ----

    /// A zone DNSKEY: flags 0x0100 (ZONE), protocol 3, algo 13, 2-byte pubkey.
    fn dnskey_zone() -> Vec<u8> {
        vec![0x01, 0x00, 0x03, 13, 0xAA, 0xBB]
    }

    /// RRSIG rdata with the given algo/key_tag/inception/expiration (type=A, labels=2, root signer, 2-byte sig).
    fn rrsig_with(algo: u8, ktag: u16, inception: u32, expiration: u32) -> Vec<u8> {
        let mut r = vec![0x00, 0x01]; // type_covered = A
        r.push(algo);
        r.push(2); // labels
        r.extend_from_slice(&3600u32.to_be_bytes()); // original_ttl
        r.extend_from_slice(&expiration.to_be_bytes());
        r.extend_from_slice(&inception.to_be_bytes());
        r.extend_from_slice(&ktag.to_be_bytes());
        r.push(0x00); // root signer name
        r.extend_from_slice(&[0xDE, 0xAD]); // signature
        r
    }

    #[test]
    fn dnssec_validate_structural() {
        let dk = dnskey_zone();
        let kt = key_tag(&dk) as u16; // self-consistent key tag
        assert_eq!(
            dnssec_validate(
                &rrsig_with(13, kt, 1_000_000_000, 2_000_000_000),
                &dk,
                1_500_000_000
            ),
            0
        ); // VALID
        assert_eq!(dnssec_validate(&[0u8; 10], &dk, 1_500_000_000), 7); // MALFORMED
        let mut dk_bad = dk.clone();
        dk_bad[2] = 2;
        assert_eq!(
            dnssec_validate(
                &rrsig_with(13, kt, 1_000_000_000, 2_000_000_000),
                &dk_bad,
                1_500_000_000
            ),
            6
        ); // BAD_DNSKEY
        assert_eq!(
            dnssec_validate(
                &rrsig_with(99, kt, 1_000_000_000, 2_000_000_000),
                &dk,
                1_500_000_000
            ),
            5
        ); // UNSUPPORTED_ALGO
        assert_eq!(
            dnssec_validate(
                &rrsig_with(14, kt, 1_000_000_000, 2_000_000_000),
                &dk,
                1_500_000_000
            ),
            4
        ); // ALGO_MISMATCH
        assert_eq!(
            dnssec_validate(
                &rrsig_with(13, kt, 1_000_000_000, 2_000_000_000),
                &dk,
                500_000_000
            ),
            3
        ); // NOT_YET_VALID
        assert_eq!(
            dnssec_validate(
                &rrsig_with(13, kt, 1_000_000_000, 2_000_000_000),
                &dk,
                2_500_000_000
            ),
            2
        ); // EXPIRED
        assert_eq!(
            dnssec_validate(
                &rrsig_with(13, kt.wrapping_add(1), 1_000_000_000, 2_000_000_000),
                &dk,
                1_500_000_000
            ),
            1
        ); // KEYTAG_MISMATCH
    }

    #[test]
    fn dnssec_ds_link_structural() {
        let dk = dnskey_zone();
        let kt = key_tag(&dk) as u16;
        let mut ds = Vec::new();
        ds.extend_from_slice(&kt.to_be_bytes()); // key_tag
        ds.push(13); // algo (matches DNSKEY)
        ds.push(2); // digest_type SHA-256
        ds.extend_from_slice(&[0u8; 32]); // 32-byte digest
        assert_eq!(dnssec_ds_link(&ds, &dk), 0); // VALID
        assert_eq!(dnssec_ds_link(&[0u8; 3], &dk), 6); // MALFORMED
        let mut ds_sha1 = ds.clone();
        ds_sha1[3] = 1;
        assert_eq!(dnssec_ds_link(&ds_sha1, &dk), 3); // UNSUPPORTED_DIGEST
        let mut ds_short = ds[..4].to_vec();
        ds_short.extend_from_slice(&[0u8; 30]);
        assert_eq!(dnssec_ds_link(&ds_short, &dk), 4); // BAD_DIGEST_LEN
        let mut ds_algo = ds.clone();
        ds_algo[2] = 14;
        assert_eq!(dnssec_ds_link(&ds_algo, &dk), 2); // ALGO_MISMATCH
        let mut ds_kt = ds.clone();
        ds_kt[0] = ds_kt[0].wrapping_add(1);
        assert_ne!(be16(&ds_kt, 0), kt);
        assert_eq!(dnssec_ds_link(&ds_kt, &dk), 1); // KEYTAG_MISMATCH
    }

    #[test]
    fn warden_domain_match_cases() {
        let ex = b"example.com";
        assert_eq!(warden_domain_match(b"example.com", ex), 1); // EXACT
        assert_eq!(warden_domain_match(b"www.example.com", ex), 2); // SUFFIX
        assert_eq!(warden_domain_match(b"EXAMPLE.COM", ex), 1); // case-insensitive
        assert_eq!(warden_domain_match(b"notexample.com", ex), 0); // NOT a dot-boundary suffix
        assert_eq!(warden_domain_match(b"other.org", ex), 0);
        let wild = b"*.example.com";
        assert_eq!(warden_domain_match(b"example.com", wild), 3); // wildcard apex
        assert_eq!(warden_domain_match(b"a.example.com", wild), 3); // wildcard subdomain
        assert_eq!(warden_domain_match(b"example.org", wild), 0);
        assert_eq!(warden_domain_match(b"", ex), 0); // empty
    }

    #[test]
    fn byte_parsing_muscles_never_panic() {
        for len in 0..40usize {
            let bytes = vec![0xFFu8; len];
            let _ = dnssec_validate(&bytes, &bytes, i64::MAX);
            let _ = dnssec_validate(&bytes, &bytes, i64::MIN);
            let _ = dnssec_ds_link(&bytes, &bytes);
            let _ = warden_domain_match(&bytes, &bytes);
            let _ = key_tag(&bytes);
        }
    }
}
