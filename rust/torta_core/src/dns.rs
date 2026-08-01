/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! DNS wire-format codec (RFC 1035) — the resolver foundation (Wave 2) + the blocklist ENFORCEMENT
//! primitive.
//!
//! Parsing untrusted DNS packets is classic CVE turf: name-compression loops, out-of-bounds reads,
//! length confusion. Every access here is bounds-checked and compression-pointer following is capped,
//! so a hostile packet returns `None`, never a panic or an OOB read. Host-testable against real bytes.
//!
//! Wave 2a = this codec (parse question, build query, build a blocked response). Wave 2b wires it to a
//! transport (DNSCrypt/DoH) + the VPN path for real enforcement and adds the JNI surface, so for now
//! the public items are intentionally not yet called from non-test code.

const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255;
const MAX_POINTER_JUMPS: usize = 16;

/// The question section of a DNS message — enough to decide a block.
pub struct DnsQuestion {
    pub id: u16,
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Read a DNS name at `start`, following compression pointers (capped against loops). Returns the
/// decoded name (lowercased, no trailing dot) and the stream position immediately AFTER the name in
/// the original message (not the position reached by following pointers).
fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<u8> = Vec::with_capacity(MAX_NAME_LEN);
    let mut pos = start;
    let mut jumps = 0usize;
    let mut after: Option<usize> = None; // stream pos after the name (frozen at the first pointer)

    loop {
        let len = *buf.get(pos)?;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // compression pointer (14-bit offset)
            let lo = *buf.get(pos + 1)?;
            let ptr = (((len & 0x3F) as usize) << 8) | lo as usize;
            if after.is_none() {
                after = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS || ptr >= buf.len() {
                return None; // loop / out-of-range pointer
            }
            pos = ptr;
            continue;
        }
        let len = len as usize;
        if len > MAX_LABEL_LEN {
            return None;
        }
        let end = pos + 1 + len;
        if end > buf.len() {
            return None;
        }
        if !labels.is_empty() {
            labels.push(b'.');
        }
        labels.extend_from_slice(&buf[pos + 1..end]);
        if labels.len() > MAX_NAME_LEN {
            return None;
        }
        pos = end;
    }

    let name = String::from_utf8_lossy(&labels).to_lowercase();
    Some((name, after.unwrap_or(pos)))
}

fn parse_question_full(buf: &[u8]) -> Option<(DnsQuestion, usize)> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }
    let (qname, pos) = read_name(buf, 12)?;
    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    Some((
        DnsQuestion {
            id,
            qname,
            qtype,
            qclass,
        },
        pos + 4,
    ))
}

/// Parse the question from a DNS query message. `None` on any malformed input.
pub fn parse_question(buf: &[u8]) -> Option<DnsQuestion> {
    parse_question_full(buf).map(|(q, _)| q)
}

/// Build a standard recursive A/AAAA query for `qname` (qtype 1 = A, 28 = AAAA). Wave 2b's resolver
/// uses this; tested here.
pub fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(qname.len() + 18);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
    for label in qname.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let n = bytes.len().min(MAX_LABEL_LEN);
        msg.push(n as u8);
        msg.extend_from_slice(&bytes[..n]);
    }
    msg.push(0); // root label
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    msg
}

/// Build an NXDOMAIN response to `query` — the blocklist enforcement primitive (echoes the question,
/// flips QR, sets RCODE=3, zeroes the answer counts). `None` if the query is malformed.
pub fn build_nxdomain_response(query: &[u8]) -> Option<Vec<u8>> {
    let (_, qend) = parse_question_full(query)?;
    let mut resp = query[..qend].to_vec();
    resp[2] |= 0x80; // QR = 1 (response), keep Opcode + RD
    resp[3] = ((resp[3] | 0x80) & 0xF0) | 0x03; // RA = 1, clear Z, RCODE = NXDOMAIN(3)
    resp[4] = 0;
    resp[5] = 1; // QDCOUNT = 1
    resp[6] = 0;
    resp[7] = 0; // ANCOUNT = 0
    resp[8] = 0;
    resp[9] = 0; // NSCOUNT = 0
    resp[10] = 0;
    resp[11] = 0; // ARCOUNT = 0
    Some(resp)
}

/// Build a SERVFAIL response to `query` — the DENIAL twin of [`build_nxdomain_response`], identical in
/// every wire detail except RCODE = SERVFAIL(2) instead of NXDOMAIN(3). This is the honest LOAD-SHED
/// rcode: the Tortä Soft-cake AQM sheds a served Normal-tier query under sustained overload by returning
/// SERVFAIL so the client RETRIES / fails over to another resolver (a cached NXDOMAIN would wrongly
/// pin "domain does not exist"). Echoes the question, QR=1/RA=1, AN=NS=AR=0, no OPT. `None` if malformed.
pub fn build_servfail_response(query: &[u8]) -> Option<Vec<u8>> {
    let (_, qend) = parse_question_full(query)?;
    let mut resp = query[..qend].to_vec();
    resp[2] |= 0x80; // QR = 1 (response), keep Opcode + RD
    resp[3] = ((resp[3] | 0x80) & 0xF0) | 0x02; // RA = 1, clear Z, RCODE = SERVFAIL(2)
    resp[4] = 0;
    resp[5] = 1; // QDCOUNT = 1
    resp[6] = 0;
    resp[7] = 0; // ANCOUNT = 0
    resp[8] = 0;
    resp[9] = 0; // NSCOUNT = 0
    resp[10] = 0;
    resp[11] = 0; // ARCOUNT = 0
    Some(resp)
}

// ---- P12 dnsmasq — positive-record synthesis primitives (the R1 keystone) ----
//
// `build_nxdomain_response` above is the DENIAL primitive (no answer, RCODE=3). dnsmasq parity needs
// the POSITIVE twins: a sinkhole (`address=/domain/0.0.0.0`, cloaking) and a literal-IP answer
// (`address=/domain/ip`, static local records). Both synthesize a NOERROR response that echoes the
// question and appends synthetic A/AAAA records, structurally identical to a real upstream reply so the
// resolver can `return` it early (BEFORE the cache read / transport exchange) and it still satisfies
// `validate_response`'s full-consumption walk: ANCOUNT records, NSCOUNT=ARCOUNT=0, no OPT, no trailing
// bytes. The owner name of every answer is a compression pointer to the question at offset 12 (0xC0 0x0C
// — the exact form `read_name` follows and `forge_response`/the cache already forge), so the answer
// echoes the asked name with zero re-serialization.

/// The fixed RDLENGTH of an A record's RDATA (4 octets) and an AAAA record's (16 octets).
///
/// `pub(crate)` since the sovereign-rewire DNS64 synth (`resolver/dns64.rs`) needs the wire constants
/// to forge synthesized AAAA records through [`push_address_answer`]. Widened from private alongside
/// that primitive so there is exactly ONE address-record wire-layout site in the crate (the reuse-law):
/// the synth, the R1 sinkhole, and the R3 literal-address builder all reach THIS function.
pub(crate) const RDLEN_A: u16 = 4;
pub(crate) const RDLEN_AAAA: u16 = 16;
/// DNS TYPE codes for the two address records we synthesize. `pub(crate)` — see [`RDLEN_A`].
pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_AAAA: u16 = 28;
/// QCLASS / CLASS = IN. `pub(crate)` — see [`RDLEN_A`].
pub(crate) const CLASS_IN: u16 = 1;

/// Append one synthetic address answer (owner = compression-pointer-to-question, `ttl`, `rtype`/RDATA
/// derived from `ip`) to an already-question-echoing response buffer. Internal helper for the two R1
/// primitives — keeps the wire layout in exactly one place. The owner is the 2-byte compression pointer
/// `0xC0 0x0C` pointing at the question name at offset 12 (RFC1035 §4.1.4), so the answer's name is the
/// asked name with no re-encoding.
///
/// `pub(crate)` so the DNS64 synth (`resolver/dns64.rs`) reaches the canonical append primitive
/// instead of mirroring its byte layout — the ONE wire-layout site for a single address answer.
pub(crate) fn push_address_answer(resp: &mut Vec<u8>, ip: std::net::IpAddr, ttl: u32) {
    use std::net::IpAddr;
    resp.extend_from_slice(&[0xC0, 0x0C]); // owner = pointer to the question name (offset 12)
    match ip {
        IpAddr::V4(v4) => {
            resp.extend_from_slice(&TYPE_A.to_be_bytes());
            resp.extend_from_slice(&CLASS_IN.to_be_bytes());
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&RDLEN_A.to_be_bytes());
            resp.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            resp.extend_from_slice(&TYPE_AAAA.to_be_bytes());
            resp.extend_from_slice(&CLASS_IN.to_be_bytes());
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&RDLEN_AAAA.to_be_bytes());
            resp.extend_from_slice(&v6.octets());
        }
    }
}

/// Start a NOERROR positive-response canvas from `query`: echo the question, flip QR=1, set RA=1 and
/// RCODE=0, force QDCOUNT=1 and AN/NS/AR=0. The caller appends `ancount` answers via
/// [`push_address_answer`] and then writes the real ANCOUNT. Mirrors `build_nxdomain_response` exactly
/// except RCODE is left at 0 (positive) instead of `|0x03`. `None` if the query is malformed.
fn positive_response_canvas(query: &[u8]) -> Option<Vec<u8>> {
    let (_, qend) = parse_question_full(query)?;
    let mut resp = query[..qend].to_vec();
    resp[2] |= 0x80; // QR = 1 (response), keep Opcode + RD
    resp[3] = (resp[3] | 0x80) & 0xF0; // RA = 1, clear Z, RCODE = NOERROR(0)
    resp[4] = 0;
    resp[5] = 1; // QDCOUNT = 1
    resp[6] = 0;
    resp[7] = 0; // ANCOUNT = 0 (caller sets the real count after appending)
    resp[8] = 0;
    resp[9] = 0; // NSCOUNT = 0
    resp[10] = 0;
    resp[11] = 0; // ARCOUNT = 0
    Some(resp)
}

/// Build a SINKHOLE response to `query` — the dnsmasq `address=/domain/0.0.0.0` (and `::`) cloaking
/// primitive (R2 `BlockAction::ZeroSink` / `CustomIp`). Synthesizes a single A or AAAA answer (per `ip`'s
/// family) for the asked name with TTL=0 (a sinkhole should not be cached downstream), echoing the
/// question, QR=1/RCODE=0, ANCOUNT=1, NSCOUNT=ARCOUNT=0, no OPT. Twins `build_nxdomain_response` as a
/// step-1 early-return; the synthesized wire passes `validate_response` (full consumption, no trailing
/// bytes). `None` if the query is malformed.
pub fn build_sinkhole_response(query: &[u8], ip: std::net::IpAddr) -> Option<Vec<u8>> {
    let mut resp = positive_response_canvas(query)?;
    push_address_answer(&mut resp, ip, 0); // sinkhole TTL = 0
    resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    Some(resp)
}

/// Build a positive ADDRESS response to `query` — the dnsmasq `address=/domain/ip` + static-local-record
/// primitive (R3/R4). Synthesizes one answer per IP in `ips` (A for v4, AAAA for v6) for the asked name
/// with the given `ttl`, echoing the question, QR=1/RCODE=0, ANCOUNT=ips.len(), NSCOUNT=ARCOUNT=0, no OPT.
/// An empty `ips` yields a NODATA-shaped NOERROR (ANCOUNT=0) — the caller normally guards against that.
/// The synthesized wire passes `validate_response`. `None` if the query is malformed.
pub fn build_address_response(query: &[u8], ips: &[std::net::IpAddr], ttl: u32) -> Option<Vec<u8>> {
    let mut resp = positive_response_canvas(query)?;
    for &ip in ips {
        push_address_answer(&mut resp, ip, ttl);
    }
    resp[6..8].copy_from_slice(&(ips.len() as u16).to_be_bytes()); // ANCOUNT = ips.len()
    Some(resp)
}

// ---- P12 dnsmasq — `--filter-rr` answer-section rewriter (N1) ----

/// dnsmasq's RFC 8482 ANY-defang KEEP-set: when a client asks `qtype==ANY`, dnsmasq collapses the reply
/// to only these RR types (A, AAAA, MX, CNAME) and strips the rest (`rrfilter.c` ANY branch). Used by
/// [`filter_rr`] when `any_defang` is set.
const ANY_DEFANG_KEEP: [u16; 4] = [TYPE_A, TYPE_AAAA, /*MX*/ 15, /*CNAME*/ 5];

/// Re-emit the Answer section of a validated `response`, eliding records whose TYPE is in `drop_types`
/// (the `--filter-rr=TYPE` targeted mode) and/or — when `any_defang` is set (`--filter-rr=ANY`, RFC 8482)
/// — keeping ONLY {A, AAAA, MX, CNAME}. Behaviour clean-roomed from dnsmasq `rrfilter.c` (the C is NEVER
/// vendored): targeted mode touches the ANSWER SECTION ONLY (Authority/Additional are left intact) and
/// elides iff `class==IN`; ANY-defang keeps the four headline types.
///
/// To sidestep the pointer-into-elided hazard the C avoids by giving up, kept records are re-serialized
/// with their owner name UNCOMPRESSED (a fresh question-pointer is NOT reused for answers here — each kept
/// record carries its own decoded owner). Behaviour-equivalent, and the rewritten wire is structurally
/// clean: the new ANCOUNT is written into bytes 6-7 (the count fix-up `rrfilter.c` mandates), and the
/// Authority + Additional sections are copied through byte-for-byte so NSCOUNT/ARCOUNT stay correct.
///
/// Returns the rewritten wire, or `None` if `response` is malformed (caller falls back to the unfiltered
/// answer — a filter that cannot parse must not drop the answer). `is_any_query` tells the helper whether
/// the ORIGINAL query was `qtype==ANY` (ANY-defang only triggers then, per RFC 8482 / `rrfilter.c:216`).
pub fn filter_rr(
    response: &[u8],
    drop_types: &[u16],
    any_defang: bool,
    is_any_query: bool,
) -> Option<Vec<u8>> {
    // Anchor on the question and the existing skimmer — REUSE, never a 2nd scanner (the reuse-law).
    let (_q, qend) = parse_question_full(response)?;
    let qdcount = u16::from_be_bytes([response[4], response[5]]);
    if qdcount != 1 {
        return None; // mirror answer_records / the keystone — refuse a desynced buffer
    }
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let (answers, an_end) = skim_records(response, qend, ancount)?;

    // ANY-defang (RFC 8482) only fires when the client asked ANY; otherwise it is a no-op overlay.
    let defang = any_defang && is_any_query;
    if drop_types.is_empty() && !defang {
        return Some(response.to_vec()); // nothing to do — byte-identical
    }

    // Decide kept-vs-elided per Answer record (ANSWER SECTION ONLY; NS/AR are never touched).
    let keep = |rec: &AnswerRecord| -> bool {
        if rec.rclass != CLASS_IN {
            return true; // non-IN records are passed through (targeted mode is IN-only, rrfilter.c)
        }
        if defang && !ANY_DEFANG_KEEP.contains(&rec.rtype) {
            return false; // ANY-defang strips everything but {A,AAAA,MX,CNAME}
        }
        if drop_types.contains(&rec.rtype) {
            return false; // targeted --filter-rr=TYPE
        }
        true
    };

    // Re-emit kept answers with UNCOMPRESSED owner names (sidesteps the pointer-into-elided hazard).
    let mut rebuilt: Vec<u8> = response[..qend].to_vec(); // header + question, counts fixed below
    let mut kept_count: u16 = 0;
    for rec in &answers {
        if !keep(rec) {
            continue;
        }
        encode_name_uncompressed(&mut rebuilt, &rec.name);
        rebuilt.extend_from_slice(&rec.rtype.to_be_bytes());
        rebuilt.extend_from_slice(&rec.rclass.to_be_bytes());
        rebuilt.extend_from_slice(&rec.ttl.to_be_bytes());
        rebuilt.extend_from_slice(&rec.rdlength.to_be_bytes());
        // RDATA is opaque bytes; copy through verbatim. (A/AAAA RDATA never contains a compression
        // pointer; for types that could — e.g. CNAME/MX — the original RDATA may carry a pointer into
        // the elided region. Targeted mode keeps CNAME/MX, and ANY-defang's KEEP-set keeps CNAME/MX,
        // so a kept record's RDATA pointers still resolve against the question/header we copied; the
        // ELIDED records are exactly the ones whose bytes we dropped, and nothing kept points at them
        // because the only back-references in a normal reply are answer→question, preserved here.)
        let rdata_end = rec.rdata_at + rec.rdlength as usize;
        rebuilt.extend_from_slice(&response[rec.rdata_at..rdata_end]);
        kept_count += 1;
    }

    // Count fix-up (MANDATORY, rrfilter.c:288-290): the new ANCOUNT. NSCOUNT/ARCOUNT are unchanged
    // because we copy the Authority+Additional sections through byte-for-byte below.
    rebuilt[6..8].copy_from_slice(&kept_count.to_be_bytes());
    // Copy Authority + Additional verbatim (an_end..response.len()) so NS/AR records + EDNS0 OPT survive
    // and the rewritten wire still fully-consumes under validate_response.
    rebuilt.extend_from_slice(&response[an_end..]);
    Some(rebuilt)
}

/// Serialize a decoded dotted name (lowercased, no trailing dot — as [`read_name`] returns it) into
/// `out` as an UNCOMPRESSED RFC1035 name (length-prefixed labels + root 0). Used by [`filter_rr`] when
/// re-emitting kept records so no answer ever carries a compression pointer into bytes that were elided.
fn encode_name_uncompressed(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let n = bytes.len().min(MAX_LABEL_LEN);
        out.push(n as u8);
        out.extend_from_slice(&bytes[..n]);
    }
    out.push(0); // root label
}

// ---- P12 dnsmasq — `--bogus-priv` private-PTR predicate (R5) ----

/// dnsmasq `--bogus-priv`: a reverse (PTR) lookup for an RFC1918 / ULA / link-local address should be
/// answered NXDOMAIN locally, never forwarded — so LAN topology never leaks to the public resolver
/// (`rfc1035.c` bogus-priv branch). This is the PURE PREDICATE half (the `dns.rs` helper of EVOKE `:66`):
/// it decides "is this a private-address PTR that bogus-priv should sink?"; the caller in
/// `resolver/mod.rs` step-1.5 turns a `true` into [`build_nxdomain_response`] + no egress.
///
/// Reuse-law: this does NOT re-implement private-IP CIDR classification. It decodes the PTR qname via the
/// existing [`decode_ptr_to_ip`] (`#91` ARPA primitive) and delegates the public-vs-private decision to
/// the caller-supplied `is_private` classifier — the call-site threads in `resolver::rebind::is_rebind`
/// (the single source of truth for "non-public IP", `guardian.rs:185`), so private-IP detection lives in
/// exactly one place. `qtype` must be PTR(12); any non-PTR qtype or non-`.arpa` / undecodable qname is
/// `false` (not a private PTR → forward normally).
pub fn is_private_ptr(
    qname: &str,
    qtype: u16,
    is_private: impl Fn(std::net::IpAddr) -> bool,
) -> bool {
    const QTYPE_PTR: u16 = 12;
    if qtype != QTYPE_PTR {
        return false;
    }
    match decode_ptr_to_ip(qname) {
        Some(ip) => is_private(ip),
        None => false, // not an in-addr.arpa / ip6.arpa PTR (or malformed) → not a private PTR
    }
}

/// Decode a reverse-DNS (PTR) qname into the [`IpAddr`] it points at — the #91 sonar/ARPA primitive.
///
/// `.in-addr.arpa` (RFC1035 §3.5): the 4 octets are written in **reverse** order, so
/// `1.0.168.192.in-addr.arpa` → `192.168.0.1`. `.ip6.arpa` (RFC3596 §2.5): each of the 16 address
/// bytes is split into 2 hex nibbles, all 32 nibbles are written **reverse**, low-nibble-first,
/// dot-separated — so `…1.0.0.2.ip6.arpa` (32 nibbles) folds back into the v6 address.
///
/// The qname is expected already lowercased + trailing-dot-stripped (as [`read_name`] returns it).
/// **Never panics:** any malformed input (wrong label count, non-numeric/out-of-range octet,
/// non-hex or wrong-count nibble, neither suffix) returns `None`. Pure `std::net`, no allocation
/// beyond the iterator temporaries; no indexing, no `.unwrap()`.
pub fn decode_ptr_to_ip(qname: &str) -> Option<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // IPv4: <d>.<c>.<b>.<a>.in-addr.arpa  →  Ipv4Addr(a, b, c, d)
    if let Some(stem) = qname.strip_suffix(".in-addr.arpa") {
        let mut octets = [0u8; 4];
        let mut n = 0usize;
        for label in stem.split('.') {
            if n >= 4 {
                return None; // too many labels
            }
            octets[n] = label.parse::<u8>().ok()?; // non-numeric / >255 → None
            n += 1;
        }
        if n != 4 {
            return None; // too few labels (or empty stem)
        }
        // labels are reversed: octets[0] is the LOW byte → Ipv4Addr wants high..low
        return Some(IpAddr::V4(Ipv4Addr::new(
            octets[3], octets[2], octets[1], octets[0],
        )));
    }

    // IPv6: 32 reversed hex nibbles . ip6.arpa  →  Ipv6Addr
    if let Some(stem) = qname.strip_suffix(".ip6.arpa") {
        let mut nibbles = [0u8; 32];
        let mut n = 0usize;
        for label in stem.split('.') {
            if n >= 32 {
                return None; // too many nibbles
            }
            let b = label.as_bytes();
            if b.len() != 1 {
                return None; // each nibble label is exactly one hex char
            }
            nibbles[n] = match b[0] {
                d @ b'0'..=b'9' => d - b'0',
                h @ b'a'..=b'f' => h - b'a' + 10,
                _ => return None, // non-hex (qname is lowercased, so uppercase is not expected)
            };
            n += 1;
        }
        if n != 32 {
            return None; // not exactly 32 nibbles
        }
        // nibbles are reversed + low-nibble-first (RFC3596): wire position `p` holds the LOW nibble of
        // byte `15 - p/2` when `p` is even, and the HIGH nibble when `p` is odd. So `nibbles[0]` is the
        // low nibble of byte 15 and `nibbles[31]` is the high nibble of byte 0. Reconstruct byte `i`
        // from its two wire positions: low at `2*(15-i)`, high at `2*(15-i)+1`.
        let mut bytes = [0u8; 16];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let base = 2 * (15 - i);
            let lo = nibbles[base];
            let hi = nibbles[base + 1];
            *byte = (hi << 4) | lo;
        }
        return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
    }

    None
}

// ---- Wave 2b — response validation (the anti-poisoning keystone) ----

/// Why a response from a transport was refused. The transport authenticates the CHANNEL;
/// `validate_response` authenticates the ANSWER, so even a perfectly TLS-terminated reply that
/// forges a different question, lies about its answer count, or hides a compression bomb is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Either side was too short / structurally malformed (header < 12B, no question, truncated).
    Malformed,
    /// The QR bit was not set — this is a query, not a response.
    NotAResponse,
    /// The response ID did not echo the query ID (T1, per-request TXID guard).
    IdMismatch,
    /// qname / qtype / qclass did not byte-match the question we asked (T2 — the Kaminsky check).
    QuestionMismatch,
    /// The Answer section did not contain exactly ANCOUNT well-formed records, or an RDATA / name
    /// ran past the buffer or tripped the compression-pointer bound (T5 + T7).
    AnswerWalk,
    /// The response carried a true server-failure RCODE — SERVFAIL(2) or REFUSED(5). These are NOT
    /// answers and (C1) must never reach the no-TTL positive cache as a "result". NOERROR(0) and
    /// NXDOMAIN(3) are legitimate (positive / authoritative-negative) and are deliberately NOT here.
    RcodeFailure,
    /// The TC bit (truncation) was set — the answer is incomplete over this transport (M1). The wire
    /// data below the header cannot be trusted as the full answer; the caller must retry, not cache.
    Truncated,
    /// The response did not carry EXACTLY one question (QDCOUNT != 1). A multi-question response lets
    /// an attacker anchor the keystone's question-walk on a region it never validated (H3a).
    ExtraQuestions,
    /// After walking Answer + Authority + Additional records, the buffer was not fully consumed —
    /// unauthenticated trailing/section bytes remained (H3b). A poison record smuggled past the last
    /// authenticated record is rejected here.
    TrailingBytes,
}

/// One Answer record's shape — enough for the cache keying contract + shadow comparison, without
/// interpreting RDATA. Names are decoded with the same bounds as [`read_name`]; RDATA stays opaque
/// bytes (we never follow glue or cache Additional — T4).
pub struct AnswerRecord {
    pub name: String,
    pub rtype: u16,
    // rclass/ttl/rdata_at are part of the skimmer's shape that the cache-keying contract + the 2c
    // shadow comparison read; 2b only asserts name/rtype/rdlength, so they are not read here yet.
    pub rclass: u16,
    pub ttl: u32,
    pub rdlength: u16,
    /// Absolute offset of RDATA within the response buffer (RDATA itself is left opaque).
    pub rdata_at: usize,
}

/// Skim exactly `count` resource records starting at `start`, reusing `read_name`'s
/// compression/length discipline for every owner name and bounds-checking every fixed field +
/// RDLENGTH. Returns the parsed records and the offset just past the last one, or `None` if the
/// section is short, lies about its count, or any field/RDATA runs off the end (T5 + T7).
fn skim_records(buf: &[u8], start: usize, count: usize) -> Option<(Vec<AnswerRecord>, usize)> {
    let mut pos = start;
    let mut records = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let (name, after) = read_name(buf, pos)?;
        pos = after;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 fixed bytes before RDATA.
        if pos + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]);
        let rdata_at = pos + 10;
        let end = rdata_at + rdlength as usize;
        if end > buf.len() {
            return None; // RDLENGTH lies about the bytes that follow
        }
        records.push(AnswerRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdlength,
            rdata_at,
        });
        pos = end;
    }
    Some((records, pos))
}

/// Walk + return the Answer section of a validated-shape `response`, reusing `skim_records`. The
/// caller is expected to have already run [`validate_response`]; this is the answer-record skimmer
/// the resolver/cache consult. `None` on any malformed input (never panics, never an OOB read).
pub fn answer_records(response: &[u8]) -> Option<Vec<AnswerRecord>> {
    let (_q, qend) = parse_question_full(response)?;
    // Defense-in-depth (H3): `parse_question_full` already requires QDCOUNT>=1 and anchors `qend` on
    // the first question; pin it to EXACTLY one so the Answer walk can never start past a smuggled
    // second question. `validate_response` enforces the same invariant upstream.
    let qdcount = u16::from_be_bytes([response[4], response[5]]);
    if qdcount != 1 {
        return None;
    }
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let (records, pos) = skim_records(response, qend, ancount)?;
    // Mirror `validate_response`'s H3b discipline: continue the bounded walk through Authority
    // (NSCOUNT) + Additional (ARCOUNT) and require the three sections to consume the buffer EXACTLY.
    // Without this, a buffer the keystone REJECTS for trailing / extra-section poison could still
    // yield Answer records here — a validator<->consumer desync the keystone is meant to prevent.
    // Keeping the same discipline closes that divergence so the skimmer stays safe even if a later
    // wave (2c+) ever calls it on bytes that did not first pass `validate_response`. (EDNS0 OPT in
    // Additional / SOA in Authority are walked, not rejected — the assert is only on the final tail.)
    let nscount = u16::from_be_bytes([response[8], response[9]]) as usize;
    let (_ns, pos) = skim_records(response, pos, nscount)?;
    let arcount = u16::from_be_bytes([response[10], response[11]]) as usize;
    let (_ar, pos) = skim_records(response, pos, arcount)?;
    if pos != response.len() {
        return None; // unauthenticated trailing / section bytes — refuse to skim a desynced buffer
    }
    Some(records)
}

/// Walk + return the AUTHORITY (NS) section of a validated-shape `response`, reusing the SAME private
/// [`skim_records`] walker [`answer_records`] uses (the reuse-law — there is exactly ONE RR walker in the
/// crate; this is a second public ACCESSOR, never a second parser). The Authority section is where an
/// NXDOMAIN/NODATA reply carries its NSEC/NSEC3 authenticated-denial records + their covering RRSIGs (RFC
/// 4035 §3.1.3); [`answer_records`] (dns.rs:546) walks this section ONLY to assert full consumption and
/// then DISCARDS it (`let (_ns, ..)`, dns.rs:565), so the Fortress denial validator (P9 F5) needs this twin
/// to reach the NSEC/NSEC3 records the answer skimmer throws away.
///
/// Keeps the IDENTICAL H3b discipline: walk Answer(ANCOUNT) → discard, Authority(NSCOUNT) → CAPTURE,
/// Additional(ARCOUNT) → discard, then require the three sections consume the buffer EXACTLY. A wire that
/// does not consume exactly (trailing poison / a desynced section) yields `None` — never an OOB read, never
/// a panic. `None` on any malformed input. The caller is expected to have already run
/// [`validate_response`]; this mirrors that keystone's bounded walk so it stays safe even on bytes that did
/// not first pass it.
pub fn authority_records(response: &[u8]) -> Option<Vec<AnswerRecord>> {
    let (_q, qend) = parse_question_full(response)?;
    // H3 — pin EXACTLY one question so the section walk can never start past a smuggled second question.
    let qdcount = u16::from_be_bytes([response[4], response[5]]);
    if qdcount != 1 {
        return None;
    }
    // Walk the Answer section (discard) to reach the Authority section's start offset.
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let (_an, pos) = skim_records(response, qend, ancount)?;
    // CAPTURE the Authority (NSCOUNT) records — the NSEC/NSEC3 denial + their RRSIGs.
    let nscount = u16::from_be_bytes([response[8], response[9]]) as usize;
    let (ns_records, pos) = skim_records(response, pos, nscount)?;
    // Continue through Additional (ARCOUNT) and require FULL buffer consumption (H3b) — a denial wire that
    // does not consume EXACTLY is desynced ⇒ None, never skim a poisoned/trailing-byte buffer.
    let arcount = u16::from_be_bytes([response[10], response[11]]) as usize;
    let (_ar, pos) = skim_records(response, pos, arcount)?;
    if pos != response.len() {
        return None;
    }
    Some(ns_records)
}

/// **RFC 2308 §5 negative-cache TTL** — the smaller of the SOA record's own TTL and its trailing
/// MINIMUM rdata field, read from the AUTHORITY section of a validated-shape NXDOMAIN/NODATA denial.
///
/// Clean-roomed from the studied dnsmasq `find_soa` idea (`rfc1035.c` — `if (ttl < minttl) minttl = ttl`
/// over the SOA MINIMUM field); reimplemented as ORIGINAL Rust over [`authority_records`] — the ONE RR
/// walker in the crate (never a 2nd parser — the reuse-law). SOA RDATA is `MNAME · RNAME · SERIAL ·
/// REFRESH · RETRY · EXPIRE · MINIMUM`; the five trailing `u32`s are the FINAL 20 bytes and MINIMUM is
/// the LAST 4 — read positionally off the record's `rdata_at + rdlength` (which [`skim_records`] already
/// bounds `<= response.len()`), so no name decoding of MNAME/RNAME is needed.
///
/// Returns `None` when the denial carries no SOA (the caller keeps its own bounded default) or when the
/// SOA rdata is impossibly short (`< 20`, so a name byte can never be mis-read as the minimum). The
/// result is a SUGGESTED neg-TTL only — [`crate::resolver::cache`]'s `put_negative` still HARD-CLAMPS it
/// to the negative ceiling, so a hostile giant SOA-minimum can never pin a denial forever.
pub fn negative_ttl_from_soa(response: &[u8]) -> Option<u32> {
    /// SOA resource-record type (RFC 1035 §3.3.13).
    const RTYPE_SOA: u16 = 6;
    /// The five trailing `u32` fields (SERIAL/REFRESH/RETRY/EXPIRE/MINIMUM) = 20 bytes; the guard that
    /// keeps MINIMUM strictly inside the fixed tail, never a decoded MNAME/RNAME byte.
    const SOA_FIXED_TAIL: usize = 20;
    let records = authority_records(response)?;
    let soa = records.iter().find(|r| r.rtype == RTYPE_SOA)?;
    if (soa.rdlength as usize) < SOA_FIXED_TAIL {
        return None; // not a well-formed SOA — decline rather than read a name byte as the minimum
    }
    let rdata_end = soa.rdata_at + soa.rdlength as usize;
    // rdata_end <= response.len() is guaranteed by skim_records' RDLENGTH bound; the last 4 bytes are
    // the MINIMUM field regardless of how MNAME/RNAME were encoded (compressed or literal).
    let minimum = u32::from_be_bytes([
        response[rdata_end - 4],
        response[rdata_end - 3],
        response[rdata_end - 2],
        response[rdata_end - 1],
    ]);
    Some(soa.ttl.min(minimum))
}

/// THE anti-poisoning keystone. Given the exact `query_wire` we sent and a `response_wire` a
/// transport handed back, decide whether the answer may be trusted:
///   - QR=1 (it is actually a response) and TC=0 (M1 — not a truncated stub),
///   - RCODE is not a true server failure: SERVFAIL(2)/REFUSED(5) are rejected (C1), while NOERROR(0)
///     and NXDOMAIN(3) — positive and authoritative-negative/NODATA — are accepted and returned,
///   - ID echoes the query (T1; per-request, since each DoH POST is its own request),
///   - the question byte-matches case-insensitively on qname + qtype + qclass (T2, Kaminsky),
///   - the response carries EXACTLY one question (H3a — no smuggled second question),
///   - every section is bounded: Answer(ANCOUNT) + Authority(NSCOUNT) + Additional(ARCOUNT) each walk
///     to well-formed records with no name/RDATA off the end and no compression abuse (T5 + T7), and
///     the three walks together consume the buffer EXACTLY (H3b — no unauthenticated trailing bytes;
///     EDNS0 OPT in Additional / SOA in Authority are authenticated, not rejected).
///     The transport authenticates the channel; THIS authenticates the answer.
pub fn validate_response(query_wire: &[u8], response_wire: &[u8]) -> Result<(), RejectReason> {
    // Both sides must be at least a header + a parseable question. (`parse_question_full` already
    // guarantees `response_wire.len() >= 12`, so the fixed-offset header reads below are in bounds.)
    let (q, _qend_query) = parse_question_full(query_wire).ok_or(RejectReason::Malformed)?;
    let (r, rend) = parse_question_full(response_wire).ok_or(RejectReason::Malformed)?;

    // QR bit (high bit of flags byte 2) must be set on the response.
    if response_wire[2] & 0x80 == 0 {
        return Err(RejectReason::NotAResponse);
    }
    // M1 — TC bit (truncation) lives in the SAME flags byte as QR (0x02). A truncated answer is not
    // the full answer over this transport; reject so the caller retries instead of caching a stub.
    if response_wire[2] & 0x02 != 0 {
        return Err(RejectReason::Truncated);
    }
    // C1 (CRITICAL) — RCODE guard. The low nibble of flags byte 3 is the RCODE. Reject TRUE
    // server-failure codes: SERVFAIL(2) and REFUSED(5). Do NOT reject NOERROR(0) or NXDOMAIN(3):
    // those are legitimate answers (positive, or authoritative-negative / NODATA) the resolver must
    // still return — over-rejecting them would be a denial-of-resolution regression.
    let rcode = response_wire[3] & 0x0F;
    if rcode == 2 || rcode == 5 {
        return Err(RejectReason::RcodeFailure);
    }
    // T1 — per-request transaction-ID echo.
    if q.id != r.id {
        return Err(RejectReason::IdMismatch);
    }
    // T2 — the highest-value check. `parse_question_full` already lowercased both qnames, so this
    // comparison is case-insensitive on the name and exact on type + class.
    if q.qname != r.qname || q.qtype != r.qtype || q.qclass != r.qclass {
        return Err(RejectReason::QuestionMismatch);
    }
    // H3a — the response must carry EXACTLY one question. `parse_question_full` only requires
    // QDCOUNT>=1 and anchors the walk on the FIRST question; a second question would shift every
    // following section so the keystone authenticates a region it never validated. Pin it to 1.
    let qdcount = u16::from_be_bytes([response_wire[4], response_wire[5]]);
    if qdcount != 1 {
        return Err(RejectReason::ExtraQuestions);
    }
    // T5 + T7 — walk EXACTLY ANCOUNT records, bounded. A shortfall or an over-long RDATA/name fails.
    let ancount = u16::from_be_bytes([response_wire[6], response_wire[7]]) as usize;
    let (_an, pos) = skim_records(response_wire, rend, ancount).ok_or(RejectReason::AnswerWalk)?;
    // H3b — CONTINUE walking the Authority (NSCOUNT) then Additional (ARCOUNT) sections with the same
    // bounded skimmer, then require FULL buffer consumption. Real responses routinely carry an SOA in
    // Authority (NXDOMAIN/NODATA) and an EDNS0 OPT pseudo-record in Additional; walking AN+NS+AR and
    // demanding the final position reach the buffer tail authenticates the WHOLE structure WITHOUT
    // rejecting those. (Requiring the Answer walk ALONE to reach the tail would reject every EDNS0
    // response and break all resolution — so we only assert the tail AFTER all three sections.)
    let nscount = u16::from_be_bytes([response_wire[8], response_wire[9]]) as usize;
    let (_ns, pos) = skim_records(response_wire, pos, nscount).ok_or(RejectReason::AnswerWalk)?;
    let arcount = u16::from_be_bytes([response_wire[10], response_wire[11]]) as usize;
    let (_ar, pos) = skim_records(response_wire, pos, arcount).ok_or(RejectReason::AnswerWalk)?;
    if pos != response_wire.len() {
        return Err(RejectReason::TrailingBytes);
    }
    Ok(())
}

// ---- SOLVE cross (slice 2) — the resilient-resolution verdict ----

/// SOLVE cross (slice 2) — the RESILIENT-RESOLUTION verdict, the terminal-vs-retryable classifier at the
/// heart of the FlareSolverr SOLVE-form cross (its ACCESS_DENIED-vs-CHALLENGE trichotomy, reimplemented on
/// the DNS plane as ORIGINAL Rust). It answers ONE question about a reply a transport handed back: did the
/// query GET THROUGH, is this a real TERMINAL answer, or is it a RETRYABLE soft-fail the ladder should skip
/// past to try the next, healthier upstream?
///
/// This is a CLASSIFIER, NOT the anti-poisoning keystone — `validate_response` still authenticates the
/// winning answer afterward. The verdict only decides whether to STOP the ladder here or ladder on. Every
/// variant maps to a REAL DNS failure mode the engine already models (SERVFAIL/REFUSED/TC/NXDOMAIN/
/// malformed) — there is NO fabricated "DNS challenge-solver"; the honest cross is retry + failover +
/// classify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolveVerdict {
    /// The query GOT THROUGH: a NOERROR reply (a positive answer OR an authoritative NODATA). Stop the
    /// ladder and return it — the resolver's `validate_response` keystone authenticates the bytes.
    GotThrough,
    /// A RETRYABLE soft-fail — the upstream replied (or didn't) in a way that is NOT a definitive answer.
    /// The ladder skips past it to the next, healthier upstream (FlareSolverr's CHALLENGE → retry).
    SoftFail(SoftReason),
    /// A TERMINAL answer that ENDS the ladder — an authoritative negative (NXDOMAIN). Retrying wastes the
    /// budget on a real "no such name" (FlareSolverr's ACCESS_DENIED → stop, never burn the ladder).
    Terminal(TerminalReason),
}

/// Why a reply was classified RETRYABLE (a soft-fail the ladder skips past). Carried for metrics/logging
/// (slice 6's query-masksolver.log) + test clarity; the ladder itself only matches the 3-way outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftReason {
    /// SERVFAIL(2) — a transient server failure; another upstream may succeed.
    ServerFailure,
    /// REFUSED(5) — a forwarder refusal; worth one more upstream, not the answer.
    Refused,
    /// The TC (truncation) bit was set — an incomplete answer over this transport; retry, don't accept it.
    Truncated,
    /// Too short to read the header, or QR=0 (not a response) — an untrustworthy reply; ladder on.
    Malformed,
    /// Any OTHER non-answer RCODE (FORMERR(1)/NOTIMP(4)/…) — retryable on another upstream.
    OtherRcode,
}

/// Why a reply ENDS the ladder (a terminal answer). Split from `SoftReason` so the classification is
/// explicit + future-extensible (a later slice may add authenticated-denial terminals). `#[non_exhaustive]`
/// keeps adding a variant non-breaking.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalReason {
    /// NXDOMAIN(3) — the authoritative "no such name". A real answer (the slice-3 neg-cache feed); stop.
    NxDomain,
}

/// Classify a reply a transport handed back into a `SolveVerdict` (SOLVE cross, slice 2). A PURE,
/// allocation-free HEADER PEEK — it reads ONLY the fixed DNS header flags (QR + TC in byte 2, RCODE in the
/// low nibble of byte 3), never walking a name or the answer section (the same one-byte-peek discipline as
/// `dnscrypt::should_retry_over_tcp` and `validate_response`'s header reads). The bytes are PLAINTEXT DNS
/// wire — a transport returns the DECRYPTED reply; the channel crypto (TLS/QUIC/DNSCrypt) is the
/// transport's own concern, so byte 2/3 are real DNS header flags here.
///
/// The trichotomy (the terminal-vs-retryable law): NOERROR ⇒ `GotThrough`; NXDOMAIN ⇒ `Terminal` (the
/// authoritative negative IS the answer — stop, never burn the ladder on a real "no such name");
/// SERVFAIL/REFUSED/TC/other/malformed ⇒ `SoftFail` (ladder on to a healthier upstream).
///
/// HONEST BOUNDARY (⚪ anti-fabrication): classifying NXDOMAIN as terminal matches — and is no weaker than
/// — today's `Pool::exchange` ladder, which already returns the first transport's bytes (NXDOMAIN included)
/// for `validate_response` to accept as a legitimate negative. On an ENCRYPTED-upstream resolver the
/// channel is authenticated, so an off-path attacker cannot forge an NXDOMAIN; only the trusted configured
/// resolver answers, and its NXDOMAIN is authoritative. No censorship-resistance is lost vs the baseline.
/// (A bailiwick/DNSSEC-aware terminal is a `TerminalReason` extension seam, not this slice.)
pub fn solve_verdict(reply: &[u8]) -> SolveVerdict {
    // Need bytes 2 + 3 for the flags/RCODE. Anything shorter is not a readable header ⇒ retryable.
    if reply.len() < 4 {
        return SolveVerdict::SoftFail(SoftReason::Malformed);
    }
    // QR (flags byte 2, 0x80) must be set — a query echoed back is not a trustworthy answer.
    if reply[2] & 0x80 == 0 {
        return SolveVerdict::SoftFail(SoftReason::Malformed);
    }
    // TC (flags byte 2, 0x02) — a truncated reply is incomplete over this transport; retry, don't accept.
    if reply[2] & 0x02 != 0 {
        return SolveVerdict::SoftFail(SoftReason::Truncated);
    }
    // RCODE = low nibble of flags byte 3 — the terminal-vs-retryable decision.
    match reply[3] & 0x0F {
        0 => SolveVerdict::GotThrough, // NOERROR — a positive answer or an authoritative NODATA
        3 => SolveVerdict::Terminal(TerminalReason::NxDomain), // NXDOMAIN — the real "no such name"
        2 => SolveVerdict::SoftFail(SoftReason::ServerFailure), // SERVFAIL — transient, try another
        5 => SolveVerdict::SoftFail(SoftReason::Refused), // REFUSED — a forwarder refusal, try another
        _ => SolveVerdict::SoftFail(SoftReason::OtherRcode), // FORMERR/NOTIMP/… — try another
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- A5 budget guards: the wire-name parser's three bounds ----

    /// Build a message whose name at offset 12 is a chain of `n` compression pointers, each aimed
    /// at the next, ending in the literal label `a`. Exactly `n` pointer jumps.
    fn jump_chain(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 12];
        for k in 0..n {
            let target = (12 + 2 * (k + 1)) as u16;
            buf.push(0xC0 | (target >> 8) as u8);
            buf.push((target & 0xFF) as u8);
        }
        buf.extend_from_slice(&[1, b'a', 0]);
        buf
    }

    /// A5 GUARD -- `MAX_POINTER_JUMPS` (= 16, dns.rs:20) is the decompression-loop bound for
    /// `read_name`. The A5 inventory found it had a NUMBER and no test naming it. Both arms, so
    /// the cap is pinned as a BOUND and not as a constant.
    #[test]
    fn max_pointer_jumps_is_16_and_the_breach_is_loud() {
        let under = jump_chain(MAX_POINTER_JUMPS - 4);
        assert!(
            read_name(&under, 12).is_some(),
            "a jump chain UNDER the bound must still resolve"
        );
        let over = jump_chain(MAX_POINTER_JUMPS + 4);
        assert!(
            read_name(&over, 12).is_none(),
            "a jump chain OVER the bound must be refused -- this is the loop guard"
        );
    }

    /// A5 GUARD -- a pointer aimed at ITSELF is the minimal decompression loop: unbounded without
    /// the jump counter, and it must terminate as malformed rather than spin.
    #[test]
    fn a_self_referential_pointer_terminates() {
        let mut buf = vec![0u8; 12];
        buf.extend_from_slice(&[0xC0, 12]);
        assert!(
            read_name(&buf, 12).is_none(),
            "a self-referential pointer must be refused, never spun on"
        );
    }

    /// A5 GUARD -- `MAX_LABEL_LEN` (= 63, dns.rs:18) is the RFC 1035 label ceiling. A label byte
    /// above it is not a length, it is a malformed message (or a mis-parsed pointer).
    #[test]
    fn max_label_len_is_63_and_the_breach_is_loud() {
        // A single label of exactly MAX_LABEL_LEN bytes is legal.
        let mut ok = vec![0u8; 12];
        ok.push(MAX_LABEL_LEN as u8);
        ok.extend(std::iter::repeat(b'a').take(MAX_LABEL_LEN));
        ok.push(0);
        assert!(
            read_name(&ok, 12).is_some(),
            "a label AT the ceiling is legal and must parse"
        );

        // 64 has the top two bits 0b01 -- not a pointer (0b11), so it reaches the length check.
        let mut bad = vec![0u8; 12];
        bad.push((MAX_LABEL_LEN + 1) as u8);
        bad.extend(std::iter::repeat(b'a').take(MAX_LABEL_LEN + 1));
        bad.push(0);
        assert!(
            read_name(&bad, 12).is_none(),
            "a label ABOVE the ceiling must be refused"
        );
    }

    // ---- SOLVE cross (slice 2): the solve_verdict classifier ----

    /// A 12-byte DNS response header with the given flags-high byte (byte 2: QR/TC) + RCODE (low nibble of
    /// byte 3). `solve_verdict` reads ONLY those two bytes, so a bare header is a complete fixture.
    fn reply_header(flags_hi: u8, rcode: u8) -> Vec<u8> {
        let mut h = vec![0u8; 12];
        h[2] = flags_hi;
        h[3] = rcode & 0x0F;
        h
    }

    #[test]
    fn solve_verdict_noerror_got_through() {
        // QR=1 (0x80), RCODE=0 (NOERROR) — the query got through.
        assert_eq!(
            solve_verdict(&reply_header(0x80, 0)),
            SolveVerdict::GotThrough
        );
    }

    #[test]
    fn solve_verdict_nxdomain_is_terminal() {
        // QR=1, RCODE=3 (NXDOMAIN) — authoritative "no such name": TERMINAL, stop the ladder.
        assert_eq!(
            solve_verdict(&reply_header(0x80, 3)),
            SolveVerdict::Terminal(TerminalReason::NxDomain)
        );
    }

    #[test]
    fn solve_verdict_servfail_and_refused_are_soft() {
        assert_eq!(
            solve_verdict(&reply_header(0x80, 2)),
            SolveVerdict::SoftFail(SoftReason::ServerFailure)
        );
        assert_eq!(
            solve_verdict(&reply_header(0x80, 5)),
            SolveVerdict::SoftFail(SoftReason::Refused)
        );
    }

    #[test]
    fn solve_verdict_other_rcode_is_soft_retryable() {
        // FORMERR(1) — a non-answer RCODE another upstream may not return.
        assert_eq!(
            solve_verdict(&reply_header(0x80, 1)),
            SolveVerdict::SoftFail(SoftReason::OtherRcode)
        );
    }

    #[test]
    fn solve_verdict_tc_bit_is_soft_truncated() {
        // QR=1 + TC=1 (0x82), even with RCODE=0 — a truncated stub is not the full answer.
        assert_eq!(
            solve_verdict(&reply_header(0x82, 0)),
            SolveVerdict::SoftFail(SoftReason::Truncated)
        );
    }

    #[test]
    fn solve_verdict_not_a_response_is_soft_malformed() {
        // QR=0 (0x00) — a query echoed back, never a trustworthy answer.
        assert_eq!(
            solve_verdict(&reply_header(0x00, 0)),
            SolveVerdict::SoftFail(SoftReason::Malformed)
        );
    }

    #[test]
    fn solve_verdict_too_short_is_soft_malformed() {
        // Fewer than 4 bytes — no readable flags/RCODE.
        assert_eq!(
            solve_verdict(&[0u8, 0u8, 0u8]),
            SolveVerdict::SoftFail(SoftReason::Malformed)
        );
    }

    #[test]
    fn build_then_parse_round_trips() {
        let msg = build_query(0x1234, "example.com", 1);
        let q = parse_question(&msg).expect("parse");
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.qname, "example.com");
        assert_eq!(q.qtype, 1);
        assert_eq!(q.qclass, 1);
    }

    #[test]
    fn parses_real_query_bytes_and_lowercases() {
        // id=0xABCD, RD=1, qd=1; question "WWW.Example.COM" A IN
        let msg: Vec<u8> = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 3, b'W', b'W', b'W', 7, b'E',
            b'x', b'a', b'm', b'p', b'l', b'e', 3, b'C', b'O', b'M', 0, 0, 1, 0, 1,
        ];
        let q = parse_question(&msg).expect("parse");
        assert_eq!(q.qname, "www.example.com");
        assert_eq!(q.qtype, 1);
    }

    #[test]
    fn follows_compression_pointer() {
        // offset 0: "com"\0 ; offset 5: "example" + pointer->0  => "example.com"
        let buf: Vec<u8> = vec![
            3, b'c', b'o', b'm', 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0xC0, 0x00,
        ];
        let (name, after) = read_name(&buf, 5).expect("name");
        assert_eq!(name, "example.com");
        assert_eq!(after, 15); // right after the 2-byte pointer
    }

    #[test]
    fn rejects_pointer_loops_and_truncation_without_panic() {
        assert!(parse_question(&[]).is_none());
        assert!(parse_question(&[0u8; 5]).is_none()); // header too short / qd=0
                                                      // self-referential pointer at offset 0 → capped, no infinite loop
        assert!(read_name(&[0xC0, 0x00], 0).is_none());
        // label length runs past the buffer
        assert!(read_name(&[5, b'a', b'b'], 0).is_none());
    }

    #[test]
    fn builds_nxdomain_response() {
        let query = build_query(0x7777, "ads.tracker.io", 1);
        let resp = build_nxdomain_response(&query).expect("response");
        assert_eq!(resp[0], 0x77); // id preserved
        assert_eq!(resp[1], 0x77);
        assert_eq!(resp[2] & 0x80, 0x80); // QR = 1
        assert_eq!(resp[3] & 0x0F, 0x03); // RCODE = NXDOMAIN
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT = 0
                                                               // the question is echoed back intact
        let q = parse_question(&resp).expect("parse echoed question");
        assert_eq!(q.qname, "ads.tracker.io");
    }

    // ---- validate_response (Wave 2b anti-poisoning keystone) ----

    /// Forge a minimal DNS response: echoes `query`'s question, sets QR=1 + the given `id`/`ancount`
    /// in the header, then appends `ancount` synthetic A records for `answer_name`. `answer_name`
    /// lets a test point the Answer owner anywhere; the records themselves are well-formed unless a
    /// caller overrides the header counts afterward.
    fn forge_response(query: &[u8], id: u16, ancount: u16, answer_name: &str) -> Vec<u8> {
        let (_q, qend) = parse_question_full(query).expect("query question");
        let mut resp = query[..qend].to_vec();
        resp[0..2].copy_from_slice(&id.to_be_bytes());
        resp[2] |= 0x80; // QR = 1
        resp[6..8].copy_from_slice(&ancount.to_be_bytes());
        for _ in 0..ancount {
            // owner name (uncompressed) + TYPE=A CLASS=IN TTL=300 RDLENGTH=4 RDATA=1.2.3.4
            for label in answer_name.split('.').filter(|l| !l.is_empty()) {
                resp.push(label.len() as u8);
                resp.extend_from_slice(label.as_bytes());
            }
            resp.push(0);
            resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
            resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
            resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            resp.extend_from_slice(&[1, 2, 3, 4]); // RDATA
        }
        resp
    }

    #[test]
    fn validate_accepts_a_matching_well_formed_response() {
        let query = build_query(0x4242, "example.com", 1);
        let resp = forge_response(&query, 0x4242, 1, "example.com");
        assert_eq!(validate_response(&query, &resp), Ok(()));
        // and the skimmer sees exactly one record with the asked-for owner name
        let answers = answer_records(&resp).expect("answers");
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, "example.com");
        assert_eq!(answers[0].rtype, 1);
        assert_eq!(answers[0].rdlength, 4);
    }

    #[test]
    fn validate_rejects_id_mismatch() {
        let query = build_query(0x1111, "example.com", 1);
        let resp = forge_response(&query, 0x2222, 1, "example.com"); // wrong echoed ID
        assert_eq!(
            validate_response(&query, &resp),
            Err(RejectReason::IdMismatch)
        );
    }

    #[test]
    fn validate_rejects_question_mismatch() {
        // Kaminsky: response answers a DIFFERENT name than the one we asked.
        let query = build_query(0x3333, "example.com", 1);
        let resp = forge_response(&query, 0x3333, 1, "attacker.test");
        // rebuild the response so its QUESTION is the attacker name, not just the answer owner
        let bad_query = build_query(0x3333, "attacker.test", 1);
        let resp_bad_q = forge_response(&bad_query, 0x3333, 1, "attacker.test");
        let _ = resp; // (the answer-owner-only swap still validates; the question swap must not)
        assert_eq!(
            validate_response(&query, &resp_bad_q),
            Err(RejectReason::QuestionMismatch)
        );
    }

    #[test]
    fn validate_rejects_a_query_posing_as_response() {
        let query = build_query(0x5555, "example.com", 1);
        // Same bytes back with QR still 0 — not a response.
        let mut not_resp = forge_response(&query, 0x5555, 0, "example.com");
        not_resp[2] &= !0x80; // clear QR
        assert_eq!(
            validate_response(&query, &not_resp),
            Err(RejectReason::NotAResponse)
        );
    }

    #[test]
    fn validate_rejects_ancount_lying() {
        let query = build_query(0x6666, "example.com", 1);
        // Build with one real record, then claim TWO in the header — the second walk runs off the end.
        let mut resp = forge_response(&query, 0x6666, 1, "example.com");
        resp[6..8].copy_from_slice(&2u16.to_be_bytes()); // ANCOUNT lies: says 2, only 1 present
        assert_eq!(
            validate_response(&query, &resp),
            Err(RejectReason::AnswerWalk)
        );
    }

    #[test]
    fn validate_rejects_compression_bomb_in_answer() {
        let query = build_query(0x7777, "example.com", 1);
        let mut resp = forge_response(&query, 0x7777, 1, "example.com");
        // Overwrite the start of the (single) Answer owner name with a self-referential pointer.
        let (_q, qend) = parse_question_full(&resp).expect("q");
        resp[qend] = 0xC0;
        resp[qend + 1] = qend as u8; // points back at itself → read_name caps the jumps → None
        assert_eq!(
            validate_response(&query, &resp),
            Err(RejectReason::AnswerWalk)
        );
    }

    // ---- Wave 2b HARDENING: C1 (RCODE) / M1 (TC) / H3 (QDCOUNT + full-buffer walk) ----
    //
    // Each test below FAILS against the pre-hardening keystone (which read only QR + ANCOUNT) and
    // PASSES now. The "legit" cases prove no over-rejection of valid negatives or EDNS0 responses.

    /// Build a header-only echo of `query`'s question with QR=1, the given `id`, and ALL section
    /// counts forced to 0 — the canvas a negative/forged response paints on. The caller sets RCODE
    /// and any section bytes afterward.
    fn forge_header_echo(query: &[u8], id: u16) -> Vec<u8> {
        let (_q, qend) = parse_question_full(query).expect("query question");
        let mut resp = query[..qend].to_vec();
        resp[0..2].copy_from_slice(&id.to_be_bytes());
        resp[2] |= 0x80; // QR = 1
        resp[2] &= !0x02; // TC = 0
        resp[3] = (resp[3] | 0x80) & 0xF0; // RA = 1, clear Z + RCODE
        resp[4] = 0;
        resp[5] = 1; // QDCOUNT = 1
        resp[6..12].copy_from_slice(&[0u8; 6]); // AN/NS/AR = 0
        resp
    }

    #[test]
    fn validate_rejects_forged_servfail() {
        // SERVFAIL(2), ANCOUNT=0, question echoed exactly — the C1 forged-denial poison. The OLD
        // keystone (QR + ANCOUNT only) returns Ok(()) here; the RCODE guard now rejects it.
        let query = build_query(0x4242, "example.com", 1);
        let mut resp = forge_header_echo(&query, 0x4242);
        resp[3] = (resp[3] & 0xF0) | 0x02; // RCODE = SERVFAIL
        assert_eq!(
            validate_response(&query, &resp),
            Err(RejectReason::RcodeFailure)
        );
    }

    #[test]
    fn validate_rejects_forged_refused() {
        let query = build_query(0x4243, "example.com", 1);
        let mut resp = forge_header_echo(&query, 0x4243);
        resp[3] = (resp[3] & 0xF0) | 0x05; // RCODE = REFUSED
        assert_eq!(
            validate_response(&query, &resp),
            Err(RejectReason::RcodeFailure)
        );
    }

    #[test]
    fn validate_rejects_truncated_tc_bit() {
        // TC=1 in the same flags byte as QR. OLD keystone ignored it; M1 now rejects it.
        let query = build_query(0x4444, "example.com", 1);
        let mut resp = forge_response(&query, 0x4444, 1, "example.com");
        resp[2] |= 0x02; // set TC
        assert_eq!(
            validate_response(&query, &resp),
            Err(RejectReason::Truncated)
        );
    }

    #[test]
    fn validate_rejects_two_questions_with_trailing_poison() {
        // QDCOUNT=2: the asked question + a SECOND attacker question, then a trailing poison record.
        // The OLD keystone anchored on the first question and never checked QDCOUNT → it would walk
        // ANCOUNT records from the wrong offset and could be steered. H3a pins QDCOUNT==1.
        let query = build_query(0x5555, "example.com", 1);
        let (_q, qend) = parse_question_full(&query).expect("q");
        let mut resp = query[..qend].to_vec();
        resp[0..2].copy_from_slice(&0x5555u16.to_be_bytes());
        resp[2] |= 0x80; // QR = 1
        resp[4..6].copy_from_slice(&2u16.to_be_bytes()); // QDCOUNT = 2 (lie)
        resp[6..12].copy_from_slice(&[0u8; 6]); // AN/NS/AR = 0
                                                // second (attacker) question: "attacker.test" A IN
        for label in "attacker.test".split('.') {
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0);
        resp.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        resp.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
                                                     // trailing poison bytes the OLD walk never reached
        resp.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            validate_response(&query, &resp),
            Err(RejectReason::ExtraQuestions)
        );
    }

    #[test]
    fn validate_rejects_trailing_junk_after_well_formed_answer() {
        // Well-formed AN=1 / NS=0 / AR=0 response, then junk appended. OLD keystone discarded the
        // walk's end position → accepted; H3b requires FULL buffer consumption → TrailingBytes.
        let query = build_query(0x6666, "example.com", 1);
        let mut resp = forge_response(&query, 0x6666, 1, "example.com");
        resp.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]); // trailing junk
        assert_eq!(
            validate_response(&query, &resp),
            Err(RejectReason::TrailingBytes)
        );
    }

    #[test]
    fn validate_accepts_legit_nxdomain() {
        // Authoritative NXDOMAIN: RCODE=3, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0 — a legitimate negative
        // answer the resolver MUST still return. Must NOT be over-rejected.
        let query = build_query(0x7001, "no-such.example", 1);
        let mut resp = forge_header_echo(&query, 0x7001);
        resp[3] = (resp[3] & 0xF0) | 0x03; // RCODE = NXDOMAIN
        assert_eq!(validate_response(&query, &resp), Ok(()));
    }

    #[test]
    fn validate_accepts_legit_nodata() {
        // NODATA: RCODE=0 (NOERROR) but ANCOUNT=0 — the name exists, this qtype has no records.
        // Legitimate; must NOT be rejected as a failure.
        let query = build_query(0x7002, "example.com", 28);
        let resp = forge_header_echo(&query, 0x7002); // RCODE already 0 (NOERROR)
        assert_eq!(validate_response(&query, &resp), Ok(()));
    }

    #[test]
    fn validate_accepts_positive_response_with_edns0_opt_in_additional() {
        // The non-regression proof: a POSITIVE answer (AN=1) carrying an EDNS0 OPT pseudo-record in
        // Additional (AR=1). Walking AN+NS+AR and requiring full consumption must ACCEPT this —
        // rejecting it would break every real EDNS0 resolution.
        let query = build_query(0x7003, "example.com", 1);
        let mut resp = forge_response(&query, 0x7003, 1, "example.com");
        resp[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT = 1
                                                           // EDNS0 OPT record: owner = root (0x00), TYPE=41(0x0029), CLASS=4096(0x1000) (UDP payload),
                                                           // TTL=0 (extended-rcode/version/flags), RDLENGTH=0 (no options).
        resp.push(0x00); // root owner
        resp.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        resp.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = requestor UDP payload size
        resp.extend_from_slice(&0u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0
        assert_eq!(validate_response(&query, &resp), Ok(()));
        // and the Answer skimmer still sees exactly the one A record (OPT is in Additional, not here)
        let answers = answer_records(&resp).expect("answers");
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].rtype, 1);
    }

    #[test]
    fn answer_records_mirrors_the_keystone_on_trailing_poison() {
        // Forward-wave desync guard (the re-verify swarm flagged this for 2c): a well-formed AN=1
        // response with junk appended is REJECTED by the keystone (TrailingBytes). `answer_records`
        // must mirror that discipline — it now walks AN+NS+AR and requires full consumption, so it
        // returns None on the same buffer instead of skimming Answer records out of a desynced wire.
        let query = build_query(0x6770, "example.com", 1);
        let mut resp = forge_response(&query, 0x6770, 1, "example.com");
        // sanity: the clean (fully-consuming) buffer still skims exactly one Answer record.
        assert_eq!(answer_records(&resp).map(|r| r.len()), Some(1));
        resp.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]); // trailing poison past the Answer
        assert_eq!(
            validate_response(&query, &resp),
            Err(RejectReason::TrailingBytes)
        );
        assert!(answer_records(&resp).is_none()); // mirrors the keystone now (was Some(1) before)
    }

    // ---- P9 Fortress F5 — authority_records (the NSEC/NSEC3 denial reach) ----

    #[test]
    fn authority_records_returns_ns_section_and_mirrors_full_consumption() {
        // An NXDOMAIN-shaped reply: 0 answers, 1 Authority record (a stand-in NSEC, TYPE 47), 0 additional.
        let query = build_query(0x4711, "absent.example.com", 1);
        let (_q, qend) = parse_question_full(&query).expect("q");
        let mut resp = query[..qend].to_vec();
        resp[0..2].copy_from_slice(&0x4711u16.to_be_bytes());
        resp[2] |= 0x80; // QR = 1
        resp[3] = ((resp[3] | 0x80) & 0xF0) | 0x03; // RA=1, RCODE=NXDOMAIN(3)
        resp[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        resp[8..10].copy_from_slice(&1u16.to_be_bytes()); // NSCOUNT = 1
        resp[10..12].copy_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
                                                           // one Authority record: owner = "example.com" (uncompressed), TYPE=47 (NSEC), CLASS=IN, TTL, RDATA.
        for label in "example.com".split('.') {
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0);
        resp.extend_from_slice(&47u16.to_be_bytes()); // TYPE = NSEC
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        resp.extend_from_slice(&3600u32.to_be_bytes()); // TTL
        let rdata: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(rdata);

        // authority_records returns the one NS-section record (the answer skimmer would have discarded it).
        let auth = authority_records(&resp).expect("authority");
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].name, "example.com");
        assert_eq!(auth[0].rtype, 47);
        assert_eq!(auth[0].rdlength, 4);
        assert_eq!(&resp[auth[0].rdata_at..auth[0].rdata_at + 4], rdata);
        // answer_records on the SAME buffer fully-consumes and returns zero answers (NS is not Answer).
        assert_eq!(answer_records(&resp).map(|r| r.len()), Some(0));

        // Trailing poison past the Authority section ⇒ BOTH skimmers refuse (the H3b desync discipline).
        let mut poisoned = resp.clone();
        poisoned.extend_from_slice(&[0xCA, 0xFE]);
        assert!(authority_records(&poisoned).is_none());
        assert!(answer_records(&poisoned).is_none());

        // A lying NSCOUNT (says 2, only 1 present) ⇒ the second walk runs off the end ⇒ None, never panics.
        let mut lying = resp.clone();
        lying[8..10].copy_from_slice(&2u16.to_be_bytes());
        assert!(authority_records(&lying).is_none());

        // Hostile / truncated wire ⇒ None, never panics.
        assert!(authority_records(&[]).is_none());
        assert!(authority_records(&[0xFF; 8]).is_none());
        assert!(authority_records(&[0u8; 12]).is_none()); // header-only, qd=0
    }

    // ---- MaskSolver CACHE-cross (slice 3) — RFC 2308 negative-cache TTL from the Authority SOA ----

    /// Forge an NXDOMAIN reply carrying ONE Authority SOA for `owner` with the given record `ttl` and
    /// `minimum` field. RDATA = MNAME("ns") · RNAME("hostmaster") · SERIAL · REFRESH · RETRY · EXPIRE ·
    /// MINIMUM — the exact SOA layout (RFC 1035 §3.3.13), MINIMUM the trailing u32.
    fn nxdomain_with_soa(owner: &str, ttl: u32, minimum: u32) -> Vec<u8> {
        let query = build_query(0x2308, owner, 1);
        let (_q, qend) = parse_question_full(&query).expect("q");
        let mut resp = query[..qend].to_vec();
        resp[0..2].copy_from_slice(&0x2308u16.to_be_bytes());
        resp[2] |= 0x80; // QR = 1
        resp[3] = ((resp[3] | 0x80) & 0xF0) | 0x03; // RA=1, RCODE=NXDOMAIN(3)
        resp[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        resp[8..10].copy_from_slice(&1u16.to_be_bytes()); // NSCOUNT = 1
        resp[10..12].copy_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
                                                           // Authority owner = "example.com" (uncompressed), TYPE=6 (SOA), CLASS=IN, TTL, RDATA.
        for label in "example.com".split('.') {
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0);
        resp.extend_from_slice(&6u16.to_be_bytes()); // TYPE = SOA
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        resp.extend_from_slice(&ttl.to_be_bytes()); // the SOA record's own TTL
                                                    // Build the SOA RDATA: MNAME, RNAME, then the 5 fixed u32s.
        let mut rdata: Vec<u8> = Vec::new();
        for label in ["ns", "example", "com"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0); // MNAME terminator
        for label in ["hostmaster", "example", "com"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0); // RNAME terminator
        rdata.extend_from_slice(&1u32.to_be_bytes()); // SERIAL
        rdata.extend_from_slice(&7200u32.to_be_bytes()); // REFRESH
        rdata.extend_from_slice(&3600u32.to_be_bytes()); // RETRY
        rdata.extend_from_slice(&1_209_600u32.to_be_bytes()); // EXPIRE
        rdata.extend_from_slice(&minimum.to_be_bytes()); // MINIMUM (the trailing u32)
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);
        resp
    }

    #[test]
    fn negative_ttl_from_soa_takes_the_min_of_record_ttl_and_minimum() {
        // record TTL 3600, MINIMUM 60 ⇒ min = 60 (the RFC 2308 rule).
        let a = nxdomain_with_soa("absent.example.com", 3600, 60);
        assert_eq!(negative_ttl_from_soa(&a), Some(60));
        // record TTL 30, MINIMUM 900 ⇒ min = 30 (the SMALLER wins, either way round).
        let b = nxdomain_with_soa("gone.example.com", 30, 900);
        assert_eq!(negative_ttl_from_soa(&b), Some(30));
    }

    #[test]
    fn negative_ttl_from_soa_is_none_without_an_soa_and_never_panics() {
        // No SOA (the NSEC-only Authority reply from the sibling test's shape) ⇒ None → caller default.
        let query = build_query(0x2308, "absent.example.com", 1);
        let (_q, qend) = parse_question_full(&query).expect("q");
        let mut nsec = query[..qend].to_vec();
        nsec[2] |= 0x80;
        nsec[3] = ((nsec[3] | 0x80) & 0xF0) | 0x03;
        nsec[6..8].copy_from_slice(&0u16.to_be_bytes());
        nsec[8..10].copy_from_slice(&1u16.to_be_bytes());
        nsec[10..12].copy_from_slice(&0u16.to_be_bytes());
        for label in "example.com".split('.') {
            nsec.push(label.len() as u8);
            nsec.extend_from_slice(label.as_bytes());
        }
        nsec.push(0);
        nsec.extend_from_slice(&47u16.to_be_bytes()); // TYPE = NSEC, not SOA
        nsec.extend_from_slice(&1u16.to_be_bytes());
        nsec.extend_from_slice(&3600u32.to_be_bytes());
        nsec.extend_from_slice(&2u16.to_be_bytes());
        nsec.extend_from_slice(&[0xDE, 0xAD]);
        assert_eq!(negative_ttl_from_soa(&nsec), None);
        // Hostile / truncated wires ⇒ None, never a panic (reuses the bounds-guarded skimmer).
        assert_eq!(negative_ttl_from_soa(&[]), None);
        assert_eq!(negative_ttl_from_soa(&[0xFF; 8]), None);
        assert_eq!(negative_ttl_from_soa(&[0u8; 12]), None);
    }

    // ---- #91 sonar/ARPA — decode_ptr_to_ip (reverse-DNS qname → IpAddr) ----

    #[test]
    fn decode_ptr_ipv4_reverses_octets() {
        use std::net::{IpAddr, Ipv4Addr};
        // the in-tree test vector: 1.0.168.192.in-addr.arpa → 192.168.0.1 (private)
        assert_eq!(
            decode_ptr_to_ip("1.0.168.192.in-addr.arpa"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))
        );
        // loopback 127.0.0.1
        assert_eq!(
            decode_ptr_to_ip("1.0.0.127.in-addr.arpa"),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        // a public IP decodes too (classification happens elsewhere): 8.8.8.8
        assert_eq!(
            decode_ptr_to_ip("8.8.8.8.in-addr.arpa"),
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        );
        // boundary octets 0 and 255: 255.255.255.0.in-addr.arpa → 0.255.255.255
        assert_eq!(
            decode_ptr_to_ip("255.255.255.0.in-addr.arpa"),
            Some(IpAddr::V4(Ipv4Addr::new(0, 255, 255, 255)))
        );
    }

    #[test]
    fn decode_ptr_ipv6_nibble_reversed_rfc3596() {
        use std::net::{IpAddr, Ipv6Addr};

        // Build the canonical RFC3596 `.ip6.arpa` reverse zone for an address, then round-trip it
        // through `decode_ptr_to_ip`. The wire form = the 32 address nibbles in REVERSE order
        // (lowest nibble of the LAST byte first), so the leftmost label is `octets[15] & 0x0F`.
        fn reverse_zone(addr: Ipv6Addr) -> String {
            let hex = |n: u8| -> char {
                if n < 10 {
                    (b'0' + n) as char
                } else {
                    (b'a' + (n - 10)) as char
                }
            };
            // forward nibble stream (hi, lo per byte for bytes 0..15), then reverse the whole vec.
            let mut fwd = Vec::with_capacity(32);
            for b in addr.octets() {
                fwd.push(b >> 4);
                fwd.push(b & 0x0F);
            }
            fwd.reverse();
            let mut name = String::new();
            for (i, n) in fwd.iter().enumerate() {
                if i > 0 {
                    name.push('.');
                }
                name.push(hex(*n));
            }
            name.push_str(".ip6.arpa");
            name
        }

        // The well-known `::1` zone is literally "1." then 31 "0" labels — assert it explicitly so
        // the test is anchored to the published RFC3596 example, not just self-consistent.
        let mut one_expected = String::from("1");
        for _ in 0..31 {
            one_expected.push_str(".0");
        }
        one_expected.push_str(".ip6.arpa");
        assert_eq!(reverse_zone(Ipv6Addr::LOCALHOST), one_expected); // sanity on the harness itself
        assert_eq!(
            decode_ptr_to_ip(&one_expected),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );

        // 2001:db8::1 (documentation prefix) round-trips.
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            decode_ptr_to_ip(&reverse_zone(addr)),
            Some(IpAddr::V6(addr))
        );

        // fc00::abcd (ULA / private) round-trips — the private-classification path #91 cares about.
        let ula: Ipv6Addr = "fc00::abcd".parse().unwrap();
        assert_eq!(decode_ptr_to_ip(&reverse_zone(ula)), Some(IpAddr::V6(ula)));

        // fe80::1 (link-local) round-trips too.
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        assert_eq!(decode_ptr_to_ip(&reverse_zone(ll)), Some(IpAddr::V6(ll)));
    }

    #[test]
    fn decode_ptr_malformed_is_none_never_panics() {
        // not a PTR suffix at all
        assert_eq!(decode_ptr_to_ip("example.com"), None);
        assert_eq!(decode_ptr_to_ip(""), None);
        assert_eq!(decode_ptr_to_ip("in-addr.arpa"), None); // suffix alone, empty stem
        assert_eq!(decode_ptr_to_ip("ip6.arpa"), None);
        // IPv4: too few / too many octets
        assert_eq!(decode_ptr_to_ip("1.2.3.in-addr.arpa"), None);
        assert_eq!(decode_ptr_to_ip("1.2.3.4.5.in-addr.arpa"), None);
        // IPv4: non-numeric / out-of-range octet
        assert_eq!(decode_ptr_to_ip("x.0.168.192.in-addr.arpa"), None);
        assert_eq!(decode_ptr_to_ip("256.0.168.192.in-addr.arpa"), None);
        assert_eq!(decode_ptr_to_ip("1.0.168.999.in-addr.arpa"), None);
        // IPv4: an empty label (double dot) → empty u8 parse fails
        assert_eq!(decode_ptr_to_ip("1..168.192.in-addr.arpa"), None);
        // IPv6: wrong nibble count (31 nibbles)
        let short: String = {
            let mut s = String::new();
            for _ in 0..30 {
                s.push_str("0.");
            }
            s.push('1');
            s.push_str(".ip6.arpa");
            s
        };
        assert_eq!(decode_ptr_to_ip(&short), None);
        // IPv6: a non-hex nibble
        let bad: String = {
            let mut s = String::new();
            for _ in 0..31 {
                s.push_str("0.");
            }
            s.push('g'); // not hex
            s.push_str(".ip6.arpa");
            s
        };
        assert_eq!(decode_ptr_to_ip(&bad), None);
        // IPv6: a multi-char nibble label (e.g. "ab" instead of two labels)
        let multichar: String = {
            let mut s = String::new();
            for _ in 0..30 {
                s.push_str("0.");
            }
            s.push_str("ab"); // 2 chars in one label
            s.push_str(".ip6.arpa");
            s
        };
        assert_eq!(decode_ptr_to_ip(&multichar), None);
        // pure garbage that ends with the suffix string but is not a real zone
        assert_eq!(decode_ptr_to_ip("...in-addr.arpa"), None);
    }

    // ---- P12 dnsmasq — R1 positive-record synthesis (build_sinkhole_response / build_address_response) ----

    #[test]
    fn build_sinkhole_response_synthesizes_one_a_record_echoing_the_question() {
        use std::net::{IpAddr, Ipv4Addr};
        let query = build_query(0x9001, "ads.tracker.io", 1);
        let sink = IpAddr::V4(Ipv4Addr::UNSPECIFIED); // 0.0.0.0 — the dnsmasq zero-sink
        let resp = build_sinkhole_response(&query, sink).expect("sinkhole");

        // QR=1, RCODE=0 (positive, NOT NXDOMAIN), ANCOUNT=1, NSCOUNT=ARCOUNT=0 / no OPT.
        assert_eq!(resp[0], 0x90); // id echoed
        assert_eq!(resp[1], 0x01);
        assert_eq!(resp[2] & 0x80, 0x80, "QR=1");
        assert_eq!(
            resp[3] & 0x0F,
            0x00,
            "RCODE=NOERROR (positive sink, not NXDOMAIN)"
        );
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ANCOUNT=1");
        assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 0, "NSCOUNT=0");
        assert_eq!(
            u16::from_be_bytes([resp[10], resp[11]]),
            0,
            "ARCOUNT=0 / no OPT"
        );

        // The question is echoed back byte-exact.
        let q = parse_question(&resp).expect("echoed question");
        assert_eq!(q.qname, "ads.tracker.io");
        assert_eq!(q.qtype, 1);

        // The owner of the synthesized answer is the compression pointer to the question (0xC0 0x0C).
        let (_, qend) = parse_question_full(&resp).expect("qend");
        assert_eq!(resp[qend], 0xC0, "answer owner = compression pointer hi");
        assert_eq!(
            resp[qend + 1],
            0x0C,
            "answer owner = pointer to question @ offset 12"
        );

        // The synthesized wire passes the anti-poisoning keystone (full consumption, no trailing bytes).
        assert_eq!(validate_response(&query, &resp), Ok(()));

        // And the answer skimmer returns the one synthesized A record (RDATA = 0.0.0.0).
        let answers = answer_records(&resp).expect("answers");
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].rtype, TYPE_A);
        assert_eq!(answers[0].rdlength, RDLEN_A);
        assert_eq!(answers[0].name, "ads.tracker.io");
        assert_eq!(
            &resp[answers[0].rdata_at..answers[0].rdata_at + 4],
            &[0, 0, 0, 0]
        );
    }

    #[test]
    fn build_address_response_synthesizes_a_and_aaaa_arcount_zero_no_opt() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let query = build_query(0x9002, "printer.home.arpa", 1);
        let ips = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5)),
        ];
        let resp = build_address_response(&query, &ips, 600).expect("address response");

        assert_eq!(resp[2] & 0x80, 0x80, "QR=1");
        assert_eq!(resp[3] & 0x0F, 0x00, "RCODE=NOERROR");
        assert_eq!(
            u16::from_be_bytes([resp[6], resp[7]]),
            2,
            "ANCOUNT = ips.len()"
        );
        assert_eq!(
            u16::from_be_bytes([resp[10], resp[11]]),
            0,
            "ARCOUNT=0 / no OPT"
        );

        let q = parse_question(&resp).expect("echoed question");
        assert_eq!(q.qname, "printer.home.arpa");

        // Keystone accepts it; the skimmer returns exactly the A then the AAAA, each owned by the qname.
        assert_eq!(validate_response(&query, &resp), Ok(()));
        let answers = answer_records(&resp).expect("answers");
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].rtype, TYPE_A);
        assert_eq!(answers[0].rdlength, RDLEN_A);
        assert_eq!(
            &resp[answers[0].rdata_at..answers[0].rdata_at + 4],
            &[10, 0, 0, 5]
        );
        assert_eq!(answers[1].rtype, TYPE_AAAA);
        assert_eq!(answers[1].rdlength, RDLEN_AAAA);
        assert_eq!(answers[1].name, "printer.home.arpa");
        // TTL was honored on the first record.
        assert_eq!(answers[0].ttl, 600);

        // An empty ips slice yields a NODATA-shaped NOERROR (ANCOUNT=0) that still validates.
        let empty = build_address_response(&query, &[], 600).expect("empty");
        assert_eq!(u16::from_be_bytes([empty[6], empty[7]]), 0);
        assert_eq!(validate_response(&query, &empty), Ok(()));
    }

    // ---- P12 dnsmasq — N1 filter-rr answer-section rewriter ----

    /// Forge a positive response with N answers, each a chosen (rtype, class, rdata) for `name`. Owner is
    /// uncompressed so the buffer is self-contained. Used to exercise `filter_rr` with mixed RR types.
    fn forge_typed_answers(
        query: &[u8],
        id: u16,
        recs: &[(u16, u16, &[u8])],
        name: &str,
    ) -> Vec<u8> {
        let (_q, qend) = parse_question_full(query).expect("q");
        let mut resp = query[..qend].to_vec();
        resp[0..2].copy_from_slice(&id.to_be_bytes());
        resp[2] |= 0x80; // QR=1
        resp[6..8].copy_from_slice(&(recs.len() as u16).to_be_bytes());
        resp[8..12].copy_from_slice(&[0u8; 4]); // NS=AR=0
        for &(rtype, rclass, rdata) in recs {
            for label in name.split('.').filter(|l| !l.is_empty()) {
                resp.push(label.len() as u8);
                resp.extend_from_slice(label.as_bytes());
            }
            resp.push(0);
            resp.extend_from_slice(&rtype.to_be_bytes());
            resp.extend_from_slice(&rclass.to_be_bytes());
            resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
            resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            resp.extend_from_slice(rdata);
        }
        resp
    }

    #[test]
    fn filter_rr_removes_named_rrtypes_keeps_question_and_arcount_consistent() {
        // AN=3: one A (keep), one AAAA (DROP via --filter-rr=AAAA), one A (keep). Targeted mode.
        let query = build_query(0xA001, "example.com", 1);
        let resp = forge_typed_answers(
            &query,
            0xA001,
            &[
                (TYPE_A, CLASS_IN, &[1, 2, 3, 4]),
                (TYPE_AAAA, CLASS_IN, &[0u8; 16]),
                (TYPE_A, CLASS_IN, &[5, 6, 7, 8]),
            ],
            "example.com",
        );
        // sanity: the clean buffer validates and skims 3 records.
        assert_eq!(validate_response(&query, &resp), Ok(()));
        assert_eq!(answer_records(&resp).map(|r| r.len()), Some(3));

        let filtered = filter_rr(&resp, &[TYPE_AAAA], false, false).expect("filtered");
        // ANCOUNT decremented 3 → 2; question echoed; the AAAA is gone, both A's remain.
        assert_eq!(
            u16::from_be_bytes([filtered[6], filtered[7]]),
            2,
            "ANCOUNT fixed up"
        );
        assert_eq!(parse_question(&filtered).unwrap().qname, "example.com");
        let kept = answer_records(&filtered).expect("kept");
        assert_eq!(kept.len(), 2);
        assert!(
            kept.iter().all(|r| r.rtype == TYPE_A),
            "only A records survive"
        );
        // The rewritten wire is still well-formed under the keystone.
        assert_eq!(validate_response(&query, &filtered), Ok(()));

        // No drop types + not ANY → byte-identical pass-through.
        let untouched = filter_rr(&resp, &[], false, false).expect("untouched");
        assert_eq!(untouched, resp);
    }

    #[test]
    fn filter_rr_any_defang_keeps_only_a_aaaa_mx_cname_rfc8482() {
        // Client asked ANY; reply carries A, TXT(16), MX(15), CNAME(5), SRV(33). RFC8482 defang keeps
        // {A,AAAA,MX,CNAME} → TXT and SRV are stripped.
        let query = build_query(0xA002, "example.com", 255); // qtype 255 = ANY
        let resp = forge_typed_answers(
            &query,
            0xA002,
            &[
                (TYPE_A, CLASS_IN, &[1, 1, 1, 1]),
                (16, CLASS_IN, &[3, b'a', b'b', b'c']), // TXT
                (15, CLASS_IN, &[0, 10, 0xC0, 0x0C]), // MX (pref + a pointer-to-question is fine to copy)
                (5, CLASS_IN, &[0xC0, 0x0C]), // CNAME → question (pointer survives, question kept)
                (33, CLASS_IN, &[0, 0, 0, 0, 0, 53, 0xC0, 0x0C]), // SRV
            ],
            "example.com",
        );
        // is_any_query=true triggers the defang; drop_types empty (defang carries the policy).
        let defanged = filter_rr(&resp, &[], true, true).expect("defanged");
        let kept = answer_records(&defanged).expect("kept");
        let kept_types: Vec<u16> = kept.iter().map(|r| r.rtype).collect();
        assert_eq!(
            kept_types,
            vec![TYPE_A, 15, 5],
            "only A, MX, CNAME survive (TXT+SRV stripped)"
        );
        assert_eq!(
            u16::from_be_bytes([defanged[6], defanged[7]]),
            3,
            "ANCOUNT=3 after defang"
        );
        assert_eq!(validate_response(&query, &defanged), Ok(()));

        // Same reply but the client did NOT ask ANY → defang is a no-op (is_any_query=false).
        let noop = filter_rr(&resp, &[], true, false).expect("noop");
        assert_eq!(
            noop, resp,
            "ANY-defang only fires on an ANY query (RFC8482)"
        );
    }

    // ---- P12 dnsmasq — R5 bogus-priv private-PTR predicate ----

    #[test]
    fn bogus_priv_toggle_gates_the_private_ptr_nxdomain() {
        use std::net::IpAddr;
        // The predicate models what `--bogus-priv` ON does; OFF is the call-site simply not consulting it.
        // Classifier stub = "non-public" (the call-site threads in guardian::is_rebind on a 1-elem slice).
        let is_private = |ip: IpAddr| !ip_is_public_stub(&ip);

        // RFC1918 PTR (192.168.0.1) with qtype=PTR → ON sinks (true).
        assert!(is_private_ptr("1.0.168.192.in-addr.arpa", 12, is_private));
        // ULA v6 PTR (fc00::abcd) → ON sinks.
        let ula_zone = {
            // build the .ip6.arpa reverse zone for fc00::abcd the same way decode round-trips it
            let addr: std::net::Ipv6Addr = "fc00::abcd".parse().unwrap();
            reverse_ip6_zone(addr)
        };
        assert!(is_private_ptr(&ula_zone, 12, is_private));

        // A PUBLIC PTR (8.8.8.8) → NOT sunk even when bogus-priv is ON (forward normally).
        assert!(!is_private_ptr("8.8.8.8.in-addr.arpa", 12, is_private));

        // A non-PTR qtype (A=1) for the same private-looking name → never sunk (only PTR is in scope).
        assert!(!is_private_ptr("1.0.168.192.in-addr.arpa", 1, is_private));

        // A non-.arpa / undecodable qname → false (not a private PTR).
        assert!(!is_private_ptr("example.com", 12, is_private));
    }

    /// Local mirror of the `resolver::rebind` public-vs-private classification, used ONLY to drive the R5 predicate
    /// test without importing the `resolver::rebind` module into this std-only file. (The real call-site threads
    /// in `resolver::rebind::is_rebind`; this stub keeps the dns.rs unit test self-contained.)
    fn ip_is_public_stub(ip: &std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(v4) => {
                !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified())
            }
            std::net::IpAddr::V6(v6) => {
                !(v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local())
            }
        }
    }

    /// Build the canonical RFC3596 `.ip6.arpa` reverse zone for `addr` (32 reversed nibbles). Mirrors the
    /// helper in `decode_ptr_ipv6_nibble_reversed_rfc3596` so the R5 test can round-trip a ULA address.
    fn reverse_ip6_zone(addr: std::net::Ipv6Addr) -> String {
        let hex = |n: u8| -> char {
            if n < 10 {
                (b'0' + n) as char
            } else {
                (b'a' + (n - 10)) as char
            }
        };
        let mut fwd = Vec::with_capacity(32);
        for b in addr.octets() {
            fwd.push(b >> 4);
            fwd.push(b & 0x0F);
        }
        fwd.reverse();
        let mut name = String::new();
        for (i, n) in fwd.iter().enumerate() {
            if i > 0 {
                name.push('.');
            }
            name.push(hex(*n));
        }
        name.push_str(".ip6.arpa");
        name
    }
}
