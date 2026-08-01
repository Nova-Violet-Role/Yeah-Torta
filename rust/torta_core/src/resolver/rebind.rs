/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Resolver-native rebind/spoof + IDN homograph defense.
//!
//! The SEMANTIC security layer the resolver runs ABOVE its DNS parser: **rebind/poison detection**
//! ([`is_rebind`] over the answer IPs skimmed by [`extract_answer_ips`]) and — preserved for a future
//! wiring — **IDN/punycode homograph** look-alike detection ([`homograph_risk`]). The transport
//! authenticates the channel; [`crate::dns::validate_response`] already authenticates the structure; these
//! checks add only semantic signal on top of a validated answer, never replacing it.
//!
//! ## The two LIVE datapath consumers
//! `resolve_inner`'s `rebind_reject` (a structure-VALIDATED answer → drop iff a PUBLIC name mapped to a
//! private/loopback/link-local IP and the Expert rebind-enforce switch is on) and `never_forward`'s
//! private-PTR guard both call [`is_rebind`] as the ONE private-vs-public IP classifier — there is exactly
//! one answer-IP skimmer in the crate (the LAW: reuse [`crate::dns::answer_records`], never a 2nd
//! private-IP scanner). INERT until Stage-1 (#85) arms the resolver primary — it ships dormant like the
//! rest of the resolver.
//!
//! ## REUSE — do NOT write a 2nd DNS parser
//! The rebind check reads the A/AAAA answer IPs through [`crate::dns::answer_records`], which yields
//! [`crate::dns::AnswerRecord`] with `rtype` / `rdlength` / `rdata_at`; the RDATA is opaque bytes this
//! module interprets ONLY for A(1)/AAAA(28) into [`std::net::IpAddr`]. Name parsing is never
//! re-implemented — [`extract_answer_ips`] consumes `answer_records`, which itself runs the bounded
//! AN+NS+AR walk + full-consumption discipline the keystone uses.
//!
//! ## The homograph leg is self-contained — no `idna`, no new dep
//! The IDN look-alike defense ships a **self-contained, `std`-only, zero-dep** RFC-3492 punycode decoder
//! and a curated Cyrillic/Greek→Latin confusable skeleton, all `#![forbid(unsafe_code)]` and bounded
//! (`MAX_PUNYCODE_OUT`). It is a **preserved capability**: nothing on the live `resolve_inner` datapath
//! calls [`homograph_risk`] today (the untouched-datapath law forbids wiring a new gate in here), so it is
//! dead-code-until-wired — the migrated `homograph_*`/`punycode_*` tests are its live exerciser.

#![forbid(unsafe_code)]
// NO module-wide `allow(dead_code)` — every item below has a LIVE caller. The homograph cluster was
// dead-code-until-wired for exactly as long as nothing called it; it is now WIRED into the resolve
// datapath as gate 1c (`Resolver::homograph_reject` → `resolver/mod.rs`), the query-name twin of the
// `rebind_reject` answer-IP gate, with the same observe-by-default posture and its own Expert switch
// (`set_homograph_enforce`). If this file ever warns dead again, the honest fix is to restore the
// caller — never to re-silence the warning.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::dns::answer_records;

/// DNS record type A (IPv4).
const RTYPE_A: u16 = 1;
/// DNS record type AAAA (IPv6).
const RTYPE_AAAA: u16 = 28;
/// RDLENGTH of an A record (4-byte IPv4).
const RDLEN_A: usize = 4;
/// RDLENGTH of an AAAA record (16-byte IPv6).
const RDLEN_AAAA: usize = 16;
/// Hard bound on punycode-decoded code points — a hostile `xn--` label can never balloon memory.
const MAX_PUNYCODE_OUT: usize = 256;

// ===========================================================================================
// (C-1) Rebind / poison detection — the LIVE datapath capability
// ===========================================================================================

/// Extract the A/AAAA answer IPs from a response wire, reusing [`crate::dns::answer_records`] (never a 2nd
/// parser). Returns an empty vec for any malformed/desynced wire (`answer_records` yields `None`) — never
/// panics, never an OOB read. RDATA is interpreted ONLY for well-formed A(4 bytes)/AAAA(16 bytes) records.
///
/// `pub(crate)` (P12 rebind→keystone): the in-app resolver's step-4 rebind ENFORCEMENT reuses this SAME
/// extractor + [`is_rebind`] post-`validate_response` (`resolver/mod.rs`), so there is exactly ONE
/// answer-IP skimmer in the crate (the LAW: reuse `answer_records`, never a 2nd private-IP scanner).
pub(crate) fn extract_answer_ips(response_wire: &[u8]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let records = match answer_records(response_wire) {
        Some(r) => r,
        None => return ips, // malformed / desynced — the keystone discipline already refused it
    };
    for rec in &records {
        let start = rec.rdata_at;
        let len = rec.rdlength as usize;
        match (rec.rtype, len) {
            (RTYPE_A, RDLEN_A) => {
                if let Some(slice) = response_wire.get(start..start + RDLEN_A) {
                    let octets: [u8; 4] = [slice[0], slice[1], slice[2], slice[3]];
                    ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
                }
            }
            (RTYPE_AAAA, RDLEN_AAAA) => {
                if let Some(slice) = response_wire.get(start..start + RDLEN_AAAA) {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(slice);
                    ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
            }
            _ => {} // not an address record (CNAME/MX/TXT/…) — the rebind check ignores it
        }
    }
    ips
}

/// (C-1) Rebind/poison detection — flag a PUBLIC qname mapped to a PRIVATE/loopback/link-local IP.
///
/// Pure, host-testable, `std::net::IpAddr` (NO new dep). The cheapest high-value win. Flags any answer IP
/// that is in one of: RFC1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`, `::1`), link-local
/// (`169.254/16`, `fe80::/10`), or IPv6 unique-local (`fc00::/7`). `true` if ANY answer IP is non-public —
/// the classic DNS-rebind move is a public domain resolving to an internal address to pierce the
/// same-origin / private-network boundary.
///
/// (The caller decides public-vs-private NAME scope: this is run on answers for *public* lookups; a
/// genuine `.local` / split-horizon LAN name resolving to a private IP is legitimate and is filtered at
/// the call-site, not here — keeping this fn a pure IP classifier with no false-positive policy baked in.)
pub fn is_rebind(answer_ips: &[IpAddr]) -> bool {
    answer_ips.iter().any(|ip| !is_public_ip(ip))
}

/// `true` iff `ip` is a globally-routable (public) address — i.e. NOT private/loopback/link-local/
/// unique-local/unspecified/multicast/documentation. Uses only stabilized `std::net` predicates (verified
/// on rustc 1.95) so no new dep and no hand-rolled CIDR math that could drift from std.
fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
                // IPv4-mapped IPv6 (::ffff:a.b.c.d) — re-classify the embedded v4 so a private v4 mapped
                // into v6 is still caught (a known rebind smuggling trick).
                || v6.to_ipv4_mapped().is_some_and(|m| !is_public_ip(&IpAddr::V4(m))))
        }
    }
}

// ===========================================================================================
// (C-2) IDN / punycode homograph defense — a PRESERVED capability (not on the live datapath)
// ===========================================================================================

/// (C-2) The homograph-risk verdict for an IDN/punycode qname (INTELLIGENCE, not a hard block by default).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomographVerdict {
    /// Pure-ASCII or otherwise unambiguous — no look-alike risk.
    NoRisk,
    /// Mixed-script or whole-script confusable detected (e.g. Cyrillic-а in `аpple`, or all-Cyrillic
    /// `аррӏе` masquerading as `apple`).
    LookAlike,
}

/// (C-2) IDN/punycode homograph defense — decode each `xn--` label (self-contained RFC-3492 decoder, no
/// `idna` dep) then check each decoded label for two attack shapes:
///   - **mixed-script confusable** — the label combines scripts that host look-alikes (Latin+Cyrillic,
///     Latin+Greek, Cyrillic+Greek), e.g. `аpple` (Cyrillic-а + Latin `pple`);
///   - **whole-script confusable** — the label is entirely a non-Latin script but EVERY letter maps to a
///     Latin look-alike via the bundled skeleton table, e.g. all-Cyrillic `аррӏе` → `apple`.
///
/// Output is INTELLIGENCE (a warning verdict), not a hard block (simple-UX: "⚠ look-alike domain", never a
/// raw Unicode dump). NEVER panics on any UTF-8 input (the decoder is `MAX_PUNYCODE_OUT`-bounded).
pub fn homograph_risk(qname: &str) -> HomographVerdict {
    // Fast path: a pure-ASCII name with no `xn--` label can carry no Unicode confusable.
    if qname.is_ascii() && !contains_xn_label(qname) {
        return HomographVerdict::NoRisk;
    }
    for label in qname.split('.') {
        if label.is_empty() {
            continue;
        }
        // Resolve the label to its Unicode form: decode `xn--` punycode, else use the label as-is (it may
        // already be raw Unicode if the caller passed a U-label rather than an A-label).
        let unicode: String = match strip_xn_prefix(label) {
            Some(payload) => match punycode_decode(payload) {
                Some(decoded) => decoded,
                // A malformed `xn--` payload is suspicious in its own right, but we do not over-flag: an
                // undecodable label carries no confusable we can prove, so treat it as no-risk (the
                // never-false-positive posture) rather than guess.
                None => continue,
            },
            None => label.to_string(),
        };
        if label_is_confusable(&unicode) {
            return HomographVerdict::LookAlike;
        }
    }
    HomographVerdict::NoRisk
}

/// Does the dotted name contain at least one ACE (`xn--`) label?
fn contains_xn_label(qname: &str) -> bool {
    qname.split('.').any(|l| strip_xn_prefix(l).is_some())
}

/// If `label` is an ACE label (`xn--<payload>`, case-insensitive prefix), return the payload after the
/// prefix; else `None`.
fn strip_xn_prefix(label: &str) -> Option<&str> {
    let b = label.as_bytes();
    if b.len() >= 4
        && (b[0] == b'x' || b[0] == b'X')
        && (b[1] == b'n' || b[1] == b'N')
        && b[2] == b'-'
        && b[3] == b'-'
    {
        Some(&label[4..])
    } else {
        None
    }
}

/// `true` if a (Unicode) label is a mixed-script OR whole-script confusable look-alike.
fn label_is_confusable(label: &str) -> bool {
    is_mixed_confusable(label) || is_whole_script_confusable(label)
}

/// The scripts distinguished for confusable analysis. `Common` = digits/hyphen/dot/underscore
/// (script-neutral); `Other` = any letter not specifically tracked (CJK, kana, Arabic, …) — these do not
/// host the Latin look-alikes we defend against, so they neither trigger nor suppress a verdict.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Script {
    Latin,
    Greek,
    Cyrillic,
    Common,
    Other,
}

/// Classify one `char`'s script (the curated ranges that matter for Latin look-alike defense).
fn script_of(c: char) -> Script {
    let u = c as u32;
    match u {
        0x41..=0x5A | 0x61..=0x7A => Script::Latin, // ASCII A-Z a-z
        0x00C0..=0x024F => Script::Latin,           // Latin-1 supplement + Latin Extended-A/B
        0x0370..=0x03FF => Script::Greek,           // Greek and Coptic
        0x1F00..=0x1FFF => Script::Greek,           // Greek Extended
        0x0400..=0x04FF => Script::Cyrillic,        // Cyrillic
        0x0500..=0x052F => Script::Cyrillic,        // Cyrillic Supplement
        0x30..=0x39 | 0x2D | 0x2E | 0x5F => Script::Common, // 0-9 - . _
        _ => Script::Other,
    }
}

/// Mixed-script confusable: the label combines two scripts that host look-alike glyphs.
fn is_mixed_confusable(label: &str) -> bool {
    let mut latin = false;
    let mut cyr = false;
    let mut grk = false;
    for c in label.chars() {
        match script_of(c) {
            Script::Latin => latin = true,
            Script::Cyrillic => cyr = true,
            Script::Greek => grk = true,
            _ => {}
        }
    }
    // Mixed-script = at least TWO of the three scripts coexist in one label (the homograph signal). The
    // count form is both minimal and clearer than the pairwise OR (and clippy-clean).
    [latin, cyr, grk].iter().filter(|&&present| present).count() >= 2
}

/// Whole-script confusable: the label has NO genuine Latin letter, has at least one non-Latin letter, and
/// EVERY non-common letter maps to a Latin skeleton (so the whole word reads as a Latin string — the
/// classic all-Cyrillic `аррӏе`→`apple` attack).
fn is_whole_script_confusable(label: &str) -> bool {
    let mut saw_mapped_nonlatin = false;
    for c in label.chars() {
        match script_of(c) {
            Script::Common => continue,
            Script::Latin => return false, // a real Latin letter ⇒ this is mixed territory, not whole-script
            _ => match confusable_skeleton(c) {
                Some(_) => saw_mapped_nonlatin = true,
                None => return false, // a non-Latin letter with NO Latin look-alike ⇒ not a Latin disguise
            },
        }
    }
    saw_mapped_nonlatin
}

/// Map a confusable non-Latin code point to its Latin look-alike (a small, curated, highest-value table:
/// the Cyrillic + Greek letters that visually impersonate ASCII Latin). `None` for anything with no Latin
/// look-alike. (A fuller table is a Unicode-confusables follow-up; this curated set covers the
/// load-bearing phishing glyphs without a new dep.)
#[rustfmt::skip]
fn confusable_skeleton(c: char) -> Option<char> {
    Some(match c {
        // ---- Cyrillic (lowercase) → Latin ----
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'х' => 'x',
        'у' => 'y', 'к' => 'k', 'м' => 'm', 'т' => 't', 'н' => 'h', 'в' => 'b',
        'і' => 'i', 'ј' => 'j', 'ѕ' => 's', 'ԁ' => 'd', 'ӏ' => 'l', 'ԛ' => 'q', 'ԝ' => 'w',
        // ---- Cyrillic (uppercase) → Latin ----
        'А' => 'A', 'Е' => 'E', 'О' => 'O', 'Р' => 'P', 'С' => 'C', 'Х' => 'X',
        'В' => 'B', 'М' => 'M', 'Т' => 'T', 'Н' => 'H', 'К' => 'K',
        // ---- Greek → Latin ----
        'ο' => 'o', 'α' => 'a', 'ρ' => 'p', 'ι' => 'i', 'ν' => 'v', 'κ' => 'k',
        'Ο' => 'O', 'Α' => 'A', 'Ρ' => 'P', 'Β' => 'B', 'Ε' => 'E', 'Ζ' => 'Z',
        'Η' => 'H', 'Ι' => 'I', 'Κ' => 'K', 'Μ' => 'M', 'Ν' => 'N', 'Τ' => 'T',
        'Υ' => 'Y', 'Χ' => 'X',
        _ => return None,
    })
}

// ---- RFC 3492 punycode decoder (self-contained, std-only, bounded, never-panic) ----
//
// Decodes the payload of an `xn--<payload>` label into its Unicode form. Every arithmetic step is
// `checked_*` (a hostile payload returns `None`, never overflows/panics) and the output is capped at
// `MAX_PUNYCODE_OUT` code points. Verified against the canonical vectors (`münchen`/`bücher`/`аpple`).

const PUNY_BASE: u32 = 36;
const PUNY_TMIN: u32 = 1;
const PUNY_TMAX: u32 = 26;
const PUNY_SKEW: u32 = 38;
const PUNY_DAMP: u32 = 700;
const PUNY_INITIAL_BIAS: u32 = 72;
const PUNY_INITIAL_N: u32 = 128;

/// RFC 3492 bias adaptation.
fn punycode_adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
    delta = if first_time {
        delta / PUNY_DAMP
    } else {
        delta / 2
    };
    delta = delta.saturating_add(delta / num_points.max(1));
    let mut k = 0u32;
    while delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2 {
        delta /= PUNY_BASE - PUNY_TMIN;
        k = k.saturating_add(PUNY_BASE);
    }
    k.saturating_add(((PUNY_BASE - PUNY_TMIN + 1) * delta) / (delta + PUNY_SKEW))
}

/// Decode one basic-36 digit code point (`0-9`/`A-Z`/`a-z`); `None` for anything else.
fn punycode_digit(cp: u8) -> Option<u32> {
    match cp {
        b'0'..=b'9' => Some((cp - b'0') as u32 + 26),
        b'A'..=b'Z' => Some((cp - b'A') as u32),
        b'a'..=b'z' => Some((cp - b'a') as u32),
        _ => None,
    }
}

/// Decode an `xn--` payload (the bytes AFTER the `xn--` prefix) into a Unicode `String`. `None` on any
/// malformed/overflowing/over-long input. Bounded by `MAX_PUNYCODE_OUT`; never panics.
fn punycode_decode(input: &str) -> Option<String> {
    if !input.is_ascii() {
        return None; // an ACE payload is ASCII by definition
    }
    let bytes = input.as_bytes();
    let mut output: Vec<u32> = Vec::new();

    // The basic (ASCII) code points are everything up to the LAST hyphen; the rest is the encoded part.
    let (basic_part, mut pos) = match input.rfind('-') {
        Some(idx) => (&bytes[..idx], idx + 1),
        None => (&bytes[0..0], 0usize),
    };
    for &b in basic_part {
        if b >= 0x80 {
            return None;
        }
        output.push(b as u32);
    }

    let mut n = PUNY_INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = PUNY_INITIAL_BIAS;

    while pos < bytes.len() {
        if output.len() >= MAX_PUNYCODE_OUT {
            return None;
        }
        let oldi = i;
        let mut w: u32 = 1;
        let mut k: u32 = PUNY_BASE;
        loop {
            if pos >= bytes.len() {
                return None; // ran out of input mid-number
            }
            let d = punycode_digit(bytes[pos])?;
            pos += 1;
            i = i.checked_add(d.checked_mul(w)?)?;
            let t = if k <= bias + PUNY_TMIN {
                PUNY_TMIN
            } else if k >= bias + PUNY_TMAX {
                PUNY_TMAX
            } else {
                k - bias
            };
            if d < t {
                break;
            }
            w = w.checked_mul(PUNY_BASE - t)?;
            k = k.checked_add(PUNY_BASE)?;
        }
        let out_len = output.len() as u32 + 1;
        bias = punycode_adapt(i - oldi, out_len, oldi == 0);
        n = n.checked_add(i / out_len)?;
        i %= out_len;
        if n < 0x80 {
            return None; // a basic code point can never be inserted at a non-basic position
        }
        let idx = i as usize;
        if idx > output.len() {
            return None;
        }
        output.insert(idx, n);
        i = i.checked_add(1)?;
    }

    let mut s = String::with_capacity(output.len());
    for cp in output {
        s.push(char::from_u32(cp)?); // reject surrogates / out-of-range scalars
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // ---------- (C-1) rebind / IP classification ----------

    #[test]
    fn rebind_flags_rfc1918_loopback_linklocal() {
        assert!(is_rebind(&[v4(10, 0, 0, 1)]), "10/8 private");
        assert!(is_rebind(&[v4(172, 16, 5, 5)]), "172.16/12 private");
        assert!(is_rebind(&[v4(192, 168, 1, 1)]), "192.168/16 private");
        assert!(is_rebind(&[v4(127, 0, 0, 1)]), "127/8 loopback");
        assert!(is_rebind(&[v4(169, 254, 1, 1)]), "169.254/16 link-local");
        assert!(
            is_rebind(&[IpAddr::V6(Ipv6Addr::LOCALHOST)]),
            "::1 loopback"
        );
        assert!(
            is_rebind(&["fc00::1".parse().unwrap()]),
            "fc00::/7 unique-local"
        );
        assert!(
            is_rebind(&["fe80::1".parse().unwrap()]),
            "fe80::/10 link-local"
        );
    }

    #[test]
    fn rebind_passes_public_ips() {
        assert!(!is_rebind(&[v4(8, 8, 8, 8)]), "8.8.8.8 public");
        assert!(!is_rebind(&[v4(1, 1, 1, 1)]), "1.1.1.1 public");
        assert!(
            !is_rebind(&["2606:4700:4700::1111".parse().unwrap()]),
            "public v6"
        );
    }

    #[test]
    fn rebind_flags_any_private_in_a_mixed_set() {
        // a public + a private answer (the rebind smuggle) ⇒ flagged
        assert!(is_rebind(&[v4(8, 8, 8, 8), v4(192, 168, 0, 5)]));
    }

    #[test]
    fn rebind_empty_set_is_clean() {
        assert!(!is_rebind(&[]), "no answers ⇒ no rebind signal");
    }

    #[test]
    fn rebind_catches_v4_mapped_v6_private() {
        // ::ffff:192.168.1.1 — a private v4 smuggled inside a v6 mapped address
        let mapped: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(is_rebind(&[mapped]), "v4-mapped private must be caught");
        let mapped_pub: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(!is_rebind(&[mapped_pub]), "v4-mapped public is fine");
    }

    // ---------- (C-2) homograph ----------

    #[test]
    fn homograph_pure_ascii_is_no_risk() {
        assert_eq!(homograph_risk("example.com"), HomographVerdict::NoRisk);
        assert_eq!(homograph_risk("sub.domain.co.uk"), HomographVerdict::NoRisk);
        assert_eq!(homograph_risk(""), HomographVerdict::NoRisk);
        assert_eq!(homograph_risk("a-b-c.test"), HomographVerdict::NoRisk);
    }

    #[test]
    fn homograph_flags_mixed_script_raw_unicode() {
        // "аpple.com" with a Cyrillic 'а' (U+0430) + Latin "pple"
        assert_eq!(
            homograph_risk("\u{0430}pple.com"),
            HomographVerdict::LookAlike
        );
    }

    #[test]
    fn homograph_flags_whole_script_cyrillic() {
        // all-Cyrillic "аррӏе" (a-r-r-l-e lookalikes) → masquerades as "apple"
        let all_cyr = "\u{0430}\u{0440}\u{0440}\u{04CF}\u{0435}";
        assert_eq!(homograph_risk(all_cyr), HomographVerdict::LookAlike);
    }

    #[test]
    fn homograph_flags_punycode_mixed_script() {
        // xn--pple-43d == "аpple" (Cyrillic-а + Latin). Decoded then flagged.
        assert_eq!(
            homograph_risk("xn--pple-43d.com"),
            HomographVerdict::LookAlike
        );
        // case-insensitive ACE prefix
        assert_eq!(
            homograph_risk("XN--pple-43d.com"),
            HomographVerdict::LookAlike
        );
    }

    #[test]
    fn homograph_passes_legit_idn() {
        // xn--mnchen-3ya == "münchen" — a legitimate all-Latin IDN, NOT a confusable.
        assert_eq!(
            homograph_risk("xn--mnchen-3ya.de"),
            HomographVerdict::NoRisk
        );
        // xn--bcher-kva == "bücher" — legitimate German.
        assert_eq!(homograph_risk("xn--bcher-kva.de"), HomographVerdict::NoRisk);
    }

    #[test]
    fn homograph_legit_idn_raw_unicode_not_flagged() {
        assert_eq!(
            homograph_risk("m\u{00FC}nchen.de"),
            HomographVerdict::NoRisk
        ); // münchen
        assert_eq!(
            homograph_risk("\u{65E5}\u{672C}\u{8A9E}.jp"),
            HomographVerdict::NoRisk
        ); // 日本語 (Han, no Latin disguise)
    }

    #[test]
    fn homograph_malformed_punycode_is_no_risk_not_panic() {
        // garbage ACE payloads must never panic and must not over-flag
        for bad in ["xn--", "xn--@@@@", "xn--\u{0000}", "xn--zzzzzzzzzzzzzzzz"] {
            let _ = homograph_risk(bad); // just must not panic
        }
        assert_eq!(homograph_risk("xn--.com"), HomographVerdict::NoRisk);
    }

    // ---------- punycode decoder unit vectors ----------

    #[test]
    fn punycode_known_vectors() {
        assert_eq!(
            punycode_decode("mnchen-3ya").as_deref(),
            Some("m\u{00FC}nchen")
        );
        assert_eq!(
            punycode_decode("bcher-kva").as_deref(),
            Some("b\u{00FC}cher")
        );
        // аpple (first char Cyrillic)
        assert_eq!(punycode_decode("pple-43d").as_deref(), Some("\u{0430}pple"));
    }

    #[test]
    fn punycode_bounded_never_panics_on_garbage() {
        // long all-digit payloads, invalid chars, empty — none may panic; each is Some/None, no overflow
        let _ = punycode_decode("");
        let _ = punycode_decode("999999999999999999999999999999");
        let _ = punycode_decode("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        let _ = punycode_decode("!@#$%^&*()");
        let big = "a".to_string() + &"9".repeat(4096);
        let _ = punycode_decode(&big);
    }
}
