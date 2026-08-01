/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! DNS64 synthesis (RFC 6147 + RFC 6052 + RFC 7050) — the in-app NAT64 prefix store + the A→AAAA
//! record synthesizer. Sovereign-Rewire slice 4.
//!
//! **What this is.** DNS64 lets an IPv6-only client reach an IPv4-only server: when the client asks
//! for a name's AAAA record and the upstream has none (the server is IPv4-only), a DNS64 resolver
//! re-asks for the A record, then *synthesizes* one or more AAAA answers by embedding each IPv4
//! address inside the configured Pref64::/n IPv6 prefix (RFC 6052). The returned packet is a
//! well-formed NOERROR response the client accepts as a real AAAA answer; the IPv6→IPv4 translation
//! (NAT64) happens later in the network, not here. We are the DNS layer of that contract.
//!
//! **Clean-roomed from `dnscrypt-proxy` (Go).** The reference implementation lives at
//! `dnscrypt-proxy-master/dnscrypt-proxy/plugin_dns64.go` (the Socio dropped the upstream source to
//! STUDY, never to vendor). The Go file is `Init`/`Eval`/`fetchPref64`/`translateToIPv6`. This Rust
//! module owns: (a) the **prefix store** (`PluginDNS64.pref64` twin), (b) the **CIDR parser** for the
//! TOML `[dns64] prefix = [...]` shape (the `Init` validation), (c) the **pure synthesis** of a fresh
//! DNS wire from a validated A response (`Eval` + `translateToIPv6`, re-authored in safe Rust). The
//! orchestration (issuing the sub-query, the AAAA-answer short-circuit) lives in the resolver root
//! (`mod.rs::resolve_inner`), exactly as the Go `Eval` runs as a *response* plugin after the upstream
//! reply. **No Go code is reproduced verbatim — only the protocol behaviour, re-derived from RFC 6052.**
//!
//! **Why a SEPARATE module (not inline in `mod.rs`).** Three reasons, all load-bearing:
//! 1. **Self-contained + testable.** `#![forbid(unsafe_code)]`, std-only, zero new deps. The synthesis
//!    is PURE: it takes bytes in, returns bytes out, never touches a socket. So it is testable without
//!    a live transport — we forge a validated A response (the same forge idiom `rebind_tests` uses)
//!    and assert the synthesized AAAA bytes are exactly RFC 6052's embedding. (Class-b honest.)
//! 2. **The reuse-law.** There is ONE RR walker in the crate (`dns::answer_records`); the synth
//!    REUSES it to read the A records out of the upstream reply, never a second parser. And ONE
//!    address-answer appender (`dns::push_address_answer`, reached via `build_address_response`) — the
//!    synth builds its AAAA records through that exact primitive, so the wire layout lives in one
//!    place. We add ONLY the RFC 6052 embedding math + the prefix store.
//! 3. **Disjoint slice.** This is slice 4 of the sovereign rewire — disjoint from slice 1 (relay
//!    routing) and slice 3 (loopback listener). It compiles + tests INDEPENDENTLY, and it is INERT
//!    until the resolver root wires the orchestration (dead-code-until-wired, the `blocklist.rs:235`
//!    idiom) — so a build with `dns64` authored but NOT yet wired emits an honest ZERO synth count and
//!    a byte-identical `.so` (the prefix store defaults to EMPTY = OFF).
//!
//! **The contract with the resolver root** (`mod.rs`): the root holds the `Arc<Pool>` for the
//! sub-query; this module holds the prefixes + the pure wire-builder. Three call sites:
//! - `prefixes()` — read the configured prefixes under one short lock (the empty-fast-path: if the
//!   store is empty, the root skips the whole synth arm, byte-identical to pre-slice-4).
//! - `needs_synthesis(query_qtype, validated_response)` — the AAAA + no-AAAA-answer predicate
//!   (the Go `hasAAAAAnswer` + `qtype != TypeAAAA` early-outs, RFC 6147 §5.1).
//! - `build_synth_aaaa(query_wire, a_response_wire, prefixes)` — the pure synth: read A records out
//!   of the validated A reply, embed each IPv4 in each prefix (RFC 6052), emit a fresh NOERROR wire
//!   echoing the ORIGINAL AAAA question. Returns `None` on any malformed input (never panics, never
//!   an OOB read — the `dns.rs` bounds-checked walker discipline).
//!
//! **The NAT64 prefix shape** (RFC 6052 §2.2): a Pref64::/n where `n ∈ {32,40,48,56,64,96}`. The
//! well-known prefix is `64:ff9b::/96` (RFC 6052 §2.1). The IPv4 address is embedded in the LOW
//! bits such that the suffix-aligned 32 bits of the /n hold the v4. For /96 (the common case) the v4
//! occupies the last 4 bytes; for the other allowed lengths it occupies a position defined by the
//! RFC's suffix table. We implement the full suffix table (not just /96) so a user with a
//! network-specific /48 or /64 Pref64 (an ISP NAT64) is served correctly — parity with the Go
//! reference, which handles the same six lengths.
#![forbid(unsafe_code)]

use std::sync::Mutex;

use crate::dns;

/// The allowed RFC 6052 prefix lengths (Pref64::/n). The IPv4-embedded-suffix positions are defined
/// per-length; any other length is rejected by `set_prefixes` (the Go `Init` validation rejects
/// `ones > 96`; we reject anything outside the RFC's six allowed lengths, which is stricter + correct).
const ALLOWED_PREFIX_BITS: [u8; 6] = [32, 40, 48, 56, 64, 96];

/// The byte-offset within a 16-octet IPv6 address where the 4-octet IPv4 suffix BEGINS, per RFC 6052
/// §2.2 Table 1. For /n, the suffix starts at byte `16 - 4 - extra` where `extra` depends on n (the
/// "u" and "suffix" octets the RFC inserts between the prefix and the v4 for non-/96 lengths). We
/// encode the table directly (the authoritative source) so there is no arithmetic to get wrong:
/// `/32 → byte 6`, `/40 → byte 5`, `/48 → byte 4`, `/56 → byte 3`, `/64 → byte 2`, `/96 → byte 12`.
/// (Derived from RFC 6052 §2.2; the Go reference computes this implicitly via `ipShift = n/8` with a
/// `+1` skip over byte 8 — the "u" octet. We use the explicit table; it is clearer + auditable.)
const SUFFIX_BYTE_OFFSET: [(u8, usize); 6] =
    [(32, 6), (40, 5), (48, 4), (56, 3), (64, 2), (96, 12)];

/// One configured NAT64 prefix: the 16-octet IPv6 prefix (host-order bytes, suffix zeroed) + the
/// RFC 6052 prefix length in bits. Cheap to clone (32 bytes), so the resolver root can snapshot the
/// whole `Vec` under one short lock and run the pure synth lock-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Dns64Prefix {
    /// The 16-octet IPv6 prefix, suffix bits already cleared (so OR-ing the v4 suffix is a pure set).
    prefix: [u8; 16],
    /// The prefix length in bits (one of `ALLOWED_PREFIX_BITS`).
    bits: u8,
}

impl Dns64Prefix {
    /// Embed a 4-octet IPv4 address inside this prefix per RFC 6052 §2.2, returning the synthesized
    /// 16-octet IPv6 address. This is the safe-Rust re-derivation of `translateToIPv6`
    /// (`plugin_dns64.go:186`): copy the prefix, then write the 4 v4 bytes at the suffix offset.
    /// The suffix bits are already zero in `prefix` (enforced by `parse_prefix`), so the write is a
    /// pure overlay — no read-modify-write, no chance of stale low bits.
    fn embed(&self, ipv4: [u8; 4]) -> [u8; 16] {
        let mut out = self.prefix;
        let off = suffix_offset(self.bits).expect("validated at construction");
        // RFC 6052 §2.2: bytes [off..off+4] carry the IPv4 suffix. The "u" octet (byte 8) and the
        // suffix-length octet (byte 9) sit between the prefix and the v4 for non-/96 lengths; we
        // leave them zero (the cleared-suffix invariant), which is a valid encoding (the translator
        // ignores them). For /96 the v4 is the last 4 bytes — the well-known case.
        out[off..off + 4].copy_from_slice(&ipv4);
        out
    }
}

/// Look up the IPv4-suffix byte offset for a prefix length. `None` for a length outside RFC 6052's
/// allowed set (defence-in-depth — `Dns64Prefix` is only ever constructed with an allowed length).
fn suffix_offset(bits: u8) -> Option<usize> {
    SUFFIX_BYTE_OFFSET
        .iter()
        .find(|(b, _)| *b == bits)
        .map(|(_, off)| *off)
}

// ---- the process-global prefix store (the `REBIND_ENFORCE` / `BOGUS_PRIV` template) ----
//
// A standalone `Mutex<Vec<Dns64Prefix>>` (NOT a configure() param) so the DNS64 prefixes are
// installed/rotated/cleared INDEPENDENTLY of an upstream reconfigure — a P10 rotation must NOT reset
// the user's NAT64 prefix choice, exactly as the rebind/bogus-priv switches survive a reconfigure.
// Default EMPTY = DNS64 OFF (byte-identical to pre-slice-4: the resolver root's empty-fast-path skips
// the whole synth arm). Poison-tolerant (`into_inner`) so a panicking thread never cascades.
static PREFIXES: Mutex<Vec<Dns64Prefix>> = Mutex::new(Vec::new());

/// Lock-free fast-path flag — `true` iff `PREFIXES` holds at least one prefix. Read BEFORE taking the
/// `PREFIXES` lock so the common (DNS64-off) AAAA path never locks. Kept in sync by [`set_prefixes`]
/// (the only writer) under the same critical section. Twins `FILTER_RR_ENABLED` (mod.rs:237).
static PREFIXES_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `resolverSetDns64Prefixes(prefixesCsv)` core — install the NAT64 prefix set from a comma/newline-
/// separated list of `Pref64::/n` CIDRs (the dnscrypt-proxy `[dns64] prefix = [...]` TOML shape,
/// flattened to CSV for the JNI/UniFFI surface). Examples: `"64:ff9b::/96"`,
/// `"64:ff9b::/96,2001:db8:64::/48"`. Empty / whitespace-only CSV ⇒ DNS64 OFF (clears the store).
///
/// Validation (RFC 6052 + the Go `Init` posture): each entry must parse as an IPv6 CIDR with a prefix
/// length in `{32,40,48,56,64,96}`. A malformed entry SILENTLY DROPS just that prefix (never fatal —
/// the same posture as a bad upstream at `configure`'s `Err(_) => continue`). The suffix bits of the
/// parsed prefix are CLEARED (so a user entering `64:ff9b:1:2::/96` still synthesizes from a clean
/// `64:ff9b::` prefix — the translator owns the suffix, not the config).
///
/// Idempotent + lock-free-after-store. Re-callable (a rotation re-calls this with the new set).
pub fn set_prefixes(csv: &str) {
    let mut parsed: Vec<Dns64Prefix> = Vec::new();
    for raw in csv.split([',', '\n', '\r']) {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        if let Some(pfx) = parse_prefix(entry) {
            parsed.push(pfx);
        }
        // A malformed entry is silently dropped (never fatal). The resolver root's empty-fast-path
        // then governs whether DNS64 is active: if NO entry parsed, the store is empty = OFF.
    }
    let mut guard = PREFIXES.lock().unwrap_or_else(|e| e.into_inner());
    let enabled = !parsed.is_empty();
    PREFIXES_ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);
    *guard = parsed;
}

/// Parse one `Pref64::/n` CIDR string into a [`Dns64Prefix`] with the suffix bits cleared, or `None`
/// on any malformed input. Re-authored from RFC 6052 §2.2 + RFC 4291 (the Go reference uses Go's
/// `net.ParseCIDR`; we hand-roll the v6 parse because this crate deliberately avoids a networking
/// dep for 2b — std-only, zero new deps, the same posture as `dns.rs`). The parser is intentionally
/// tight: hex groups separated by `:`, a `/bits` suffix, the `::` shorthand NOT supported (a NAT64
/// prefix is a *configuration* value entered by a human who can write it fully — parity with the Go
/// reference is on the WIRE behaviour, not on accepting every IPv6 textual form). The well-known
/// prefix `64:ff9b::/96` is the only form most users ever enter; we accept it + the six RFC lengths.
fn parse_prefix(s: &str) -> Option<Dns64Prefix> {
    let (addr_part, bits_part) = s.split_once('/')?;
    let bits: u8 = bits_part.parse().ok()?;
    if !ALLOWED_PREFIX_BITS.contains(&bits) {
        return None; // RFC 6052 §2.2: only these six lengths are valid Pref64 lengths
    }

    // Parse the IPv6 address into 16 octets. Accept up to 8 hex groups separated by ':'; reject the
    // '::' shorthand (see the doc comment — a config value, not arbitrary input). Each group is 1-4
    // hex digits → 16 bits big-endian.
    let groups: Vec<&str> = addr_part.split(':').collect();
    if groups.len() != 8 {
        return None; // no '::' shorthand ⇒ exactly 8 groups
    }
    let mut octets = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        if g.is_empty() || g.len() > 4 {
            return None;
        }
        let val: u16 = u16::from_str_radix(g, 16).ok()?;
        octets[i * 2] = (val >> 8) as u8;
        octets[i * 2 + 1] = (val & 0xFF) as u8;
    }

    // Clear the suffix bits beyond `bits` (the translator owns them, not the config). RFC 6052 leaves
    // the suffix zero; we enforce that here so `embed()` is a pure overlay.
    let mut mask_byte = (bits / 8) as usize; // full prefix bytes are kept
    let rem_bits = bits % 8;
    if rem_bits != 0 {
        // The partial prefix byte: keep its high `rem_bits`, zero the rest.
        let mask = (0xFFu8) << (8 - rem_bits);
        octets[mask_byte] &= mask;
        mask_byte += 1;
    }
    for b in octets.iter_mut().skip(mask_byte) {
        *b = 0;
    }

    // RFC 6052 §2.2: the "u" octet (byte 8) and the suffix-length octet (byte 9) sit between the
    // prefix and the embedded v4 for non-/96 lengths and MUST be zero. For every allowed length < 96
    // they fall inside the suffix range already cleared by the loop above (bits ≤ 64 ⟹ byte 8 is past
    // the prefix; bits == 96 ⟹ bytes 0..12 are the prefix and 8/9 are inside it, correctly preserved).
    // So no extra clear is needed — the suffix loop is the single source of truth. (The Go reference
    // achieves the same implicitly: it copies the prefix IP verbatim and writes the v4 at `n/8`, never
    // touching the u/suffix octets; we clear them explicitly for a clean prefix, which is equivalent.)

    Some(Dns64Prefix {
        prefix: octets,
        bits,
    })
}

/// Snapshot the configured prefixes (cheap clones — 32 bytes each) under one short lock, or `None`
/// when DNS64 is OFF (the empty store). The resolver root reads this ONCE per AAAA query that
/// reaches the synth arm; the synth itself is then lock-free. `None` here is the empty-fast-path
/// signal: the root never takes the lock when `PREFIXES_ENABLED` is false.
pub(crate) fn prefixes() -> Option<Vec<Dns64Prefix>> {
    if !PREFIXES_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    let guard = PREFIXES.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_empty() {
        return None;
    }
    Some(guard.iter().copied().collect())
}

/// The RFC 6147 §5.1 trigger predicate: should we synthesize? `true` iff (a) the original query was
/// AAAA (qtype 28) AND (b) the validated upstream response carries NO AAAA record in its answer
/// section (the AAAA NODATA / NXDOMAIN / IPv4-only-server case). This is the Go `Eval` early-out:
/// `hasAAAAAnswer(msg)` ⇒ already has a real AAAA, no synth; `qtype != TypeAAAA` ⇒ not our query.
///
/// Takes the ORIGINAL AAAA query's qtype + the VALIDATED upstream AAAA reply wire. Never panics: it
/// runs the `dns::answer_records` bounds-checked walker, and on any malformed input returns `false`
/// (a malformed AAAA reply is NOT a synth trigger — it is the resolver root's `validate_response`
/// rejection path, which already returned `None` upstream of this call).
pub(crate) fn needs_synthesis(query_qtype: u16, validated_aaaa_response: &[u8]) -> bool {
    if query_qtype != dns::TYPE_AAAA {
        return false; // not an AAAA query — never synth (the `qtype != TypeAAAA` early-out)
    }
    let answers = match dns::answer_records(validated_aaaa_response) {
        Some(a) => a,
        None => return false, // malformed — let the root's validate_response own the rejection
    };
    // RFC 6147 §5.1: synthesize ONLY when no real AAAA is present. A reply with a real AAAA answer
    // is returned as-is (the Go `hasAAAAAnswer` short-circuit). CNAMEs in the answer are NOT AAAAs.
    !answers.iter().any(|r| r.rtype == dns::TYPE_AAAA)
}

/// The pure synthesizer (RFC 6147 §5.1.3 + RFC 6052 §2.2): given the ORIGINAL AAAA query wire, a
/// VALIDATED A-record response for the same name, and the configured prefixes, emit a fresh NOERROR
/// AAAA response wire. For each A record in the A reply, for each configured prefix, one AAAA answer
/// is synthesized (v4 embedded per RFC 6052). The TTL is `min(initialTtl, aRecordTtl)` — the Go
/// reference's `initialTTL = 600` cap + the SOA-TTL floor (RFC 6147 §5.1.3 recommends 600 s max for
/// synthesized data so a NAT64 renumber is picked up promptly; we honor that cap).
///
/// Returns `None` if the A response is malformed or carries no A records (never a NODATA synth —
/// RFC 6147 §5.1.1 says "if no A records either, return the original negative AAAA reply unchanged",
/// which the resolver root does by falling through to the original AAAA reply). The synthesized wire
/// passes `dns::validate_response` (it is built from `dns::build_address_response`'s exact primitive,
/// so it is structurally a genuine NOERROR positive). Never panics.
pub(crate) fn build_synth_aaaa(
    query_wire: &[u8],
    a_response: &[u8],
    prefixes: &[Dns64Prefix],
) -> Option<Vec<u8>> {
    if prefixes.is_empty() {
        return None;
    }

    let answers = dns::answer_records(a_response)?;
    // Collect the (ipv4, ttl) pairs from the A records. CNAME records are NOT carried — RFC 6147 §5.1.2
    // allows them in the upstream reply but a synthesized response echoes the asked name with AAAA
    // records only (the Go reference appends CNAMEs to `synth64`; we keep the simpler + cleaner form —
    // a synthesized AAAA-only reply is what a NAT64 client expects, and avoids a CNAME-chain resolver
    // ambiguity the upstream already resolved). A/AAAA are the only records we read here.
    let mut v4s: Vec<([u8; 4], u32)> = Vec::new();
    for r in &answers {
        if r.rtype == dns::TYPE_A && r.rdlength == 4 {
            // RDATA is the 4 IPv4 octets at r.rdata_at..r.rdata_at+4 (validated by skim_records —
            // rdlength is bounds-checked against the buffer, so this slice is in-bounds by construction).
            let rdata = a_response.get(r.rdata_at..r.rdata_at + 4)?;
            let mut ipv4 = [0u8; 4];
            ipv4.copy_from_slice(rdata);
            v4s.push((ipv4, r.ttl));
        }
    }
    if v4s.is_empty() {
        return None; // no A records ⇒ RFC 6147 §5.1.1: return the original negative AAAA unchanged
    }

    // RFC 6147 §5.1.3: the synthesized TTL is min(SOA TTL if present, A-record TTL), capped at 600 s.
    // The Go reference seeds `initialTTL = 600` and lowers it to a SOA TTL if one is in the Authority
    // section. We read the SOA TTL floor from the A reply's Authority section (`dns::authority_records`),
    // else keep the 600 cap. Then each AAAA's TTL is min(cap, that A record's TTL).
    let cap = soa_ttl_floor(a_response).unwrap_or(SYNTH_TTL_CAP);
    let cap = cap.min(SYNTH_TTL_CAP);

    // Synthesize the AAAA answers. One per (A record, prefix) — RFC 6147 §5.1.2: a DNS64 server with
    // multiple Pref64::/n SHOULD synthesize one AAAA per prefix (a multi-prefix NAT64 deployment).
    let mut synth_ips: Vec<std::net::IpAddr> = Vec::new();
    let mut synth_ttls: Vec<u32> = Vec::new();
    for &(ipv4, a_ttl) in &v4s {
        let ttl = a_ttl.min(cap);
        for pfx in prefixes {
            let v6 = pfx.embed(ipv4);
            synth_ips.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(v6)));
            synth_ttls.push(ttl);
        }
    }

    // Build the wire. `dns::build_address_response` emits one answer per IP with a SINGLE shared TTL —
    // but our TTLs can differ per record (each A's TTL × its prefix fan-out). So we build the canvas
    // + append each answer with its own TTL through the CANONICAL `dns::push_address_answer` primitive
    // (the same one the R1 sinkhole + R3 literal-address builders use — the ONE address-record
    // wire-layout site in the crate, reached via its `pub(crate)` widening). We start the canvas via
    // `build_address_response` with an empty IP set (yields a NODATA-shaped NOERROR canvas per its doc)
    // then append per-record + write ANCOUNT at the end.
    //
    // The owner of every answer is a compression pointer to the question at offset 12 (0xC0 0x0C) —
    // `push_address_answer`'s exact form — so the synthesized AAAA echoes the asked AAAA name.
    let mut resp = dns::build_address_response(query_wire, &[], 0)?;
    for (ip, ttl) in synth_ips.iter().zip(synth_ttls.iter()) {
        dns::push_address_answer(&mut resp, *ip, *ttl);
    }
    resp[6..8].copy_from_slice(&(synth_ips.len() as u16).to_be_bytes()); // ANCOUNT = N answers
    Some(resp)
}

/// The RFC 6147 §5.1.3 recommended maximum TTL for synthesized AAAA data (seconds). A NAT64 prefix
/// can be renumbered; a long-lived synthetic AAAA would pin a stale translation. 600 s is the value
/// the Go reference uses + the RFC's recommendation.
const SYNTH_TTL_CAP: u32 = 600;

/// Read the SOA record's TTL from the A reply's AUTHORITY section, if present (RFC 6147 §5.1.3: the
/// synthesized TTL floor is the negative-caching SOA TTL when the A query also carried a negative
/// hint). Returns `None` if there is no SOA — the caller then falls back to the 600 s cap. This is
/// the twin of the Go reference's `for _, ns := range resp.Ns { if SOA { initialTTL = header.TTL } }`
/// loop (`plugin_dns64.go:133`). We read ONLY the TTL (the SOA MINIMUM field is the real floor, but
/// the Go reference uses the record TTL directly + we match that behaviour for parity).
fn soa_ttl_floor(a_response: &[u8]) -> Option<u32> {
    let ns = dns::authority_records(a_response)?;
    ns.iter()
        .find(|r| r.rtype == 6) // SOA = type 6
        .map(|r| r.ttl)
}

#[cfg(test)]
mod tests {
    #![forbid(unsafe_code)]
    use super::*;

    // ---- forge helpers (self-contained — mirror rebind_tests' forge_a_response, kept local) ----

    /// Byte offset just past a single-question `build_query` message (12B header + qname + QTYPE/QCLASS).
    fn question_end(query: &[u8]) -> usize {
        let mut pos = 12;
        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            pos += 1 + len;
        }
        pos + 4
    }

    /// Forge a NOERROR response answering `query` with the given A records (one per `[u8;4]`). The owner
    /// is a compression pointer to the question at offset 12 — `dns::answer_records` + `validate_response`
    /// accept it. TTLs are per-record (300 s default).
    fn forge_a_response_multi(query: &[u8], ips: &[[u8; 4]], ttl: u32) -> Vec<u8> {
        let qend = question_end(query);
        let mut resp = query[..qend].to_vec();
        resp[2] |= 0x80; // QR = 1
        resp[3] = (resp[3] | 0x80) & 0xF0; // RA=1, RCODE=NOERROR
        resp[6..8].copy_from_slice(&(ips.len() as u16).to_be_bytes()); // ANCOUNT
        resp[8..12].copy_from_slice(&[0u8; 4]); // NS/AR = 0
        for ip in ips {
            resp.push(0xC0);
            resp.push(12); // owner = pointer to question at offset 12
            resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
            resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
            resp.extend_from_slice(ip);
        }
        resp
    }

    /// Forge a NOERROR response with an AAAA answer (the "already has AAAA" case — no synth expected).
    fn forge_aaaa_response(query: &[u8], v6: [u8; 16]) -> Vec<u8> {
        let qend = question_end(query);
        let mut resp = query[..qend].to_vec();
        resp[2] |= 0x80;
        resp[3] = (resp[3] | 0x80) & 0xF0;
        resp[6..8].copy_from_slice(&1u16.to_be_bytes());
        resp[8..12].copy_from_slice(&[0u8; 4]);
        resp.push(0xC0);
        resp.push(12);
        resp.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&16u16.to_be_bytes());
        resp.extend_from_slice(&v6);
        resp
    }

    // ---- parse_prefix ----

    #[test]
    fn parses_well_known_96_prefix() {
        let p = parse_prefix("64:ff9b:0:0:0:0:0:0/96").unwrap();
        assert_eq!(p.bits, 96);
        // 64:ff9b:: in 16 octets
        let mut want = [0u8; 16];
        want[0] = 0x00;
        want[1] = 0x64;
        want[2] = 0xff;
        want[3] = 0x9b;
        assert_eq!(p.prefix, want);
    }

    #[test]
    fn rejects_disallowed_prefix_length() {
        // RFC 6052: only 32/40/48/56/64/96. /64 is allowed; /72 is not.
        assert!(parse_prefix("2001:db8:0:0:0:0:0:0/72").is_none());
        // /97 too long (the Go `ones > 96` rejection)
        assert!(parse_prefix("64:ff9b:0:0:0:0:0:0/97").is_none());
        // /24 too short
        assert!(parse_prefix("2001:db8:0:0:0:0:0:0/24").is_none());
    }

    #[test]
    fn clears_suffix_bits_of_a_48_prefix() {
        // 2001:db8:64:0:0:0:0:0/48 — the user enters a clean prefix. If they entered a dirty one
        // (non-zero suffix), the parser must clear it.
        let p = parse_prefix("2001:db8:64:abcd:dead:beef:0:1/48").unwrap();
        assert_eq!(p.bits, 48);
        let mut want = [0u8; 16];
        want[0] = 0x20;
        want[1] = 0x01;
        want[2] = 0x0d;
        want[3] = 0xb8;
        want[4] = 0x00;
        want[5] = 0x64;
        assert_eq!(p.prefix, want, "suffix bits beyond /48 must be cleared");
    }

    #[test]
    fn rejects_malformed_cidr() {
        assert!(parse_prefix("not-a-prefix").is_none());
        assert!(parse_prefix("64:ff9b::/96").is_none()); // no '::' shorthand (8 groups required)
        assert!(parse_prefix("64:ff9b:0:0:0:0:0:0").is_none()); // missing /bits
        assert!(parse_prefix("64:ff9b:0:0:0:0:0:0/abc").is_none()); // non-numeric bits
    }

    // ---- embed (RFC 6052 §2.2) ----

    #[test]
    fn embeds_v4_into_well_known_96_prefix() {
        // 64:ff9b::/96 + 192.0.2.33 → 64:ff9b::c000:221 (RFC 7050 example shape)
        let p = parse_prefix("64:ff9b:0:0:0:0:0:0/96").unwrap();
        let v6 = p.embed([192, 0, 2, 33]);
        // The last 4 bytes are the v4; bytes 12-15 = 192.0.2.33.
        assert_eq!(&v6[12..16], &[192, 0, 2, 33]);
        // The prefix is preserved.
        assert_eq!(&v6[0..4], &[0x00, 0x64, 0xff, 0x9b]);
        // Bytes 4..12 are zero (the middle of the /96).
        assert_eq!(&v6[4..12], &[0u8; 8]);
    }

    #[test]
    fn embeds_v4_into_48_prefix_at_correct_offset() {
        // /48 → suffix byte offset 4. 2001:db8:64::/48 + 203.0.113.5 → 2001:db8:64:0:cb00:7105::
        // Wait — for /48 the suffix is bytes [4..8], then bytes 8 (u) + 9 (suffix-len) are zero,
        // then bytes 10..16 are zero too. RFC 6052 Table 1: /48 → suffix at byte 4.
        let p = parse_prefix("2001:db8:64:0:0:0:0:0/48").unwrap();
        let v6 = p.embed([203, 0, 113, 5]);
        assert_eq!(&v6[4..8], &[203, 0, 113, 5], "v4 at byte 4 for /48");
        assert_eq!(
            &v6[0..4],
            &[0x20, 0x01, 0x0d, 0xb8],
            "prefix bytes 0..4 preserved"
        );
        // Bytes 8..16 are the zero suffix tail (u + suffix-len + trailing).
        assert_eq!(&v6[8..16], &[0u8; 8]);
    }

    // ---- needs_synthesis ----

    #[test]
    fn needs_synthesis_for_aaaa_query_with_no_aaaa_answer() {
        let q = dns::build_query(0x1234, "example.com", 28); // AAAA query
                                                             // An A-record reply (the upstream returned A only — IPv4-only server)
        let a_reply = forge_a_response_multi(&q, &[[93, 184, 216, 34]], 300);
        assert!(needs_synthesis(28, &a_reply));
    }

    #[test]
    fn no_synth_when_query_is_not_aaaa() {
        let q = dns::build_query(0x1234, "example.com", 1); // A query
        let a_reply = forge_a_response_multi(&q, &[[93, 184, 216, 34]], 300);
        assert!(!needs_synthesis(1, &a_reply));
    }

    #[test]
    fn no_synth_when_reply_already_has_aaaa() {
        let q = dns::build_query(0x1234, "example.com", 28);
        let v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let aaaa_reply = forge_aaaa_response(&q, v6);
        assert!(!needs_synthesis(28, &aaaa_reply));
    }

    // ---- build_synth_aaaa (the full synth) ----

    #[test]
    fn synthesizes_one_aaaa_per_a_record_per_prefix_for_96() {
        let q = dns::build_query(0xABCD, "ipv4only.example", 28); // AAAA query
        let a_reply = forge_a_response_multi(&q, &[[192, 0, 2, 1], [198, 51, 100, 7]], 300);
        let prefixes = vec![parse_prefix("64:ff9b:0:0:0:0:0:0/96").unwrap()];

        let synth = build_synth_aaaa(&q, &a_reply, &prefixes).expect("synth must succeed");

        // The synthesized wire must validate (it is a genuine NOERROR positive).
        dns::validate_response(&q, &synth).expect("synth wire must be structurally valid");

        // Two A records × one prefix = two AAAA answers.
        let answers = dns::answer_records(&synth).expect("answers must skim");
        let aaaas: Vec<_> = answers.iter().filter(|r| r.rtype == 28).collect();
        assert_eq!(aaaas.len(), 2, "one AAAA per A record, one prefix");

        // Each AAAA's RDATA must embed its source A record in the last 4 bytes (the /96 suffix).
        let mut embedded: Vec<[u8; 4]> = aaaas
            .iter()
            .map(|r| {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&synth[r.rdata_at + 12..r.rdata_at + 16]);
                v4
            })
            .collect();
        embedded.sort();
        assert_eq!(embedded, vec![[192, 0, 2, 1], [198, 51, 100, 7]]);

        // The owner of each answer is the asked AAAA name (compression pointer to offset 12). The
        // synthesized response echoes the AAAA question, not the A question.
        let parsed = dns::parse_question(&synth).unwrap();
        assert_eq!(parsed.qtype, 28);
        assert_eq!(parsed.qname, "ipv4only.example");
    }

    #[test]
    fn synthesizes_for_multiple_prefixes() {
        let q = dns::build_query(1, "host.example", 28);
        let a_reply = forge_a_response_multi(&q, &[[10, 0, 0, 1]], 300);
        let prefixes = vec![
            parse_prefix("64:ff9b:0:0:0:0:0:0/96").unwrap(),
            parse_prefix("2001:db8:64:0:0:0:0:0/48").unwrap(),
        ];
        let synth = build_synth_aaaa(&q, &a_reply, &prefixes).expect("synth");
        dns::validate_response(&q, &synth).expect("valid");
        // One A × two prefixes = two AAAA answers (RFC 6147 §5.1.2 multi-prefix).
        let answers = dns::answer_records(&synth).unwrap();
        assert_eq!(answers.iter().filter(|r| r.rtype == 28).count(), 2);
    }

    #[test]
    fn synth_ttl_capped_at_600_seconds() {
        let q = dns::build_query(1, "host.example", 28);
        // An A record with an absurdly long TTL.
        let a_reply = forge_a_response_multi(&q, &[[1, 2, 3, 4]], 86400); // 24h
        let prefixes = vec![parse_prefix("64:ff9b:0:0:0:0:0:0/96").unwrap()];
        let synth = build_synth_aaaa(&q, &a_reply, &prefixes).expect("synth");
        let answers = dns::answer_records(&synth).unwrap();
        for r in answers.iter().filter(|r| r.rtype == 28) {
            assert!(
                r.ttl <= 600,
                "synth TTL must be RFC 6147-capped, got {}",
                r.ttl
            );
        }
    }

    #[test]
    fn synth_returns_none_when_no_a_records() {
        let q = dns::build_query(1, "host.example", 28);
        // A NODATA reply (ANCOUNT=0) — no A records either.
        let nodata = {
            let qend = question_end(&q);
            let mut resp = q[..qend].to_vec();
            resp[2] |= 0x80;
            resp[3] = (resp[3] | 0x80) & 0xF0; // NOERROR
            resp[6..12].copy_from_slice(&[0u8; 6]); // AN/NS/AR = 0
            resp
        };
        let prefixes = vec![parse_prefix("64:ff9b:0:0:0:0:0:0/96").unwrap()];
        assert!(build_synth_aaaa(&q, &nodata, &prefixes).is_none());
    }

    // ---- set_prefixes + prefixes (the store) ----

    #[test]
    fn set_prefixes_parses_csv_and_enables_store() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Clean slate.
        set_prefixes("");
        assert!(prefixes().is_none(), "empty CSV = OFF");

        set_prefixes("64:ff9b:0:0:0:0:0:0/96, 2001:db8:64:0:0:0:0:0/48");
        let pfxs = prefixes().expect("two prefixes parsed");
        assert_eq!(pfxs.len(), 2);
        assert_eq!(pfxs[0].bits, 96);
        assert_eq!(pfxs[1].bits, 48);

        // Cleanup so this doesn't leak into other tests.
        set_prefixes("");
        assert!(prefixes().is_none());
    }

    #[test]
    fn set_prefixes_drops_malformed_entries_silently() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_prefixes("garbage, 64:ff9b:0:0:0:0:0:0/96, , not-a-cidr");
        let pfxs = prefixes().expect("one valid prefix survived");
        assert_eq!(
            pfxs.len(),
            1,
            "the malformed entries were dropped, not fatal"
        );
        set_prefixes(""); // cleanup
    }

    /// Process-global serialization lock for the store tests. `PREFIXES` + `PREFIXES_ENABLED` are
    /// SHARED across the whole test binary; any two tests racing a `set_prefixes` + `prefixes()`
    /// read would observe a torn store. Poison-tolerant.
    static TEST_LOCK: Mutex<()> = Mutex::new(());
}
