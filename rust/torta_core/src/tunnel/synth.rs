/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **The reply synthesizer for the Rust tunnel loop** — the GENESIS overhaul of the legacy
//! `jni/invizible/udp.c:621-730 write_udp` (the IP/UDP reply frame builder) + the Risk-4 SERVFAIL
//! synthesizer the C engine never needed (the Go binary was its fall-through safety net).
//!
//! ## GENESIS — study → overhaul → combine
//!
//! Studied (NEVER copy-pasted):
//! - `udp.c:621-730` (`write_udp`) — the IP+UDP reply builder: swap src↔dst, rebuild the IP header
//!   (v4 checksum via `calc_checksum(0, ip4, 20)`), the UDP pseudo-header + checksum, and the
//!   final `write(tun, buffer, len)`. The byte path is proven; this is the pure-Rust twin.
//! - `dns.c:216-229` (`parse_dns_response` SVCB/block rewrite) — the C-side in-place rewrite that
//!   flipped a response into a block-rcode reply. Risk-4 retools it: the C side relied on the Go
//!   binary as the no-answer fall-through; with Go gone, the LOOP synthesizes SERVFAIL itself.
//!
//! Combined into: [`synthesize_servfail`] (Risk-4: rcode 2 around the original query, qr=1, opcode
//! echoed, ancount=0) + [`synth_ip_udp_reply`] (the write_udp twin: swap addrs/ports, valid IP +
//! UDP checksums, full frame).
//!
//! ## Risk 4 — the no-Go-fallback contract (load-bearing)
//!
//! With the Go binary deleted (spec §4), `resolver::resolve_datapath` returning `None` is NO LONGER
//! a fail-safe fall-through to a working upstream. The loop MUST synthesize a SERVFAIL (rcode 2)
//! around the original query and write it back — never silently drop (the app's stub retries
//! forever, the user-visible symptom is "DNS dead"). This module is the contract made code.
//!
//! ## Invariants
//!
//! `#![forbid(unsafe_code)]`, std-only, zero new deps. The checksum is the standard Internet
//! one's-complement sum (the `calc_checksum` of udp.c:650-699, pure Rust). Cross-platform (the
//! Windows host build compiles it) so the logic is host-testable.

#![forbid(unsafe_code)]

use super::parse::{IpAddrBytes, IP4_HEADER_LEN, IP6_HEADER_LEN, UDP_HEADER_LEN};
use super::ParsedPacket;

/// IPDEFTTL (the default TTL the C engine stamps on replies, `<netinet/ip.h>`). udp.c:644.
const IP_DEFAULT_TTL: u8 = 64;

/// SERVFAIL (RFC 1035 §4.1.1, rcode 2). The Risk-4 rcode.
pub const RCODE_SERVFAIL: u8 = 2;

// ===================================================================================================
// synthesize_servfail — Risk 4: a no-Go-fallback contract. Build a DNS reply around the original
// query: qr=1, opcode echoed, rcode = RCODE_SERVFAIL (or the Warden's block rcode), ancount=0.
// ===================================================================================================

/// Synthesize a DNS SERVFAIL reply around the original query bytes (Risk 4). With the Go binary
/// gone, a `resolver::resolve_datapath(query) == None` is NO LONGER a fall-through to a working
/// upstream — the loop must hand the stub a real reply it can retry against, not a silent drop.
///
/// Builds: qr = 1, opcode echoed from the query, AA=0, TC=0, RD echoed, RA=0, rcode = `rcode`
/// (default [`RCODE_SERVFAIL`] = 2); QDCOUNT echoed; ANCOUNT/NSCOUNT/ARCOUNT = 0; the question
/// section is echoed verbatim (the stub needs it to match its pending request). Returns a packet
/// sized to fit the query header + the question (no answer RRs).
///
/// `rcode` is the DNS rcode to stamp: pass [`RCODE_SERVFAIL`] (2) for a resolver None (Risk 4),
/// or a Warden-block rcode when the firewall denied the query. The function is rcode-agnostic —
/// the loop decides which rcode to stamp.
pub fn synthesize_servfail(query_dns: &[u8], rcode: u8) -> Vec<u8> {
    // A DNS message needs at least the 12-byte header to be meaningful. A query shorter than that
    // is already malformed — synthesize a bare minimum SERVFAIL header so the stub sees SOMETHING
    // (Risk 4: never silent, even when the query is garbage).
    if query_dns.len() < DNS_HEADER_LEN {
        let mut bare = vec![0u8; DNS_HEADER_LEN];
        if !query_dns.is_empty() {
            bare[0] = query_dns[0];
            bare[1] = query_dns[1]; // echo the ID so the stub can match it
        }
        apply_servfail_header(&mut bare, rcode, /*qdcount*/ 0);
        return bare;
    }

    // Copy the whole query (header + question), then overwrite the header flags + counts. Echoing
    // the question verbatim is what every DNS server does on SERVFAIL — the stub matches on the
    // question, not just the ID. OPT (EDNS) additional RRs, if present, are dropped implicitly by
    // zeroing arcount (a SERVFAIL with no EDNS is well-formed; the stub falls back to /64).
    let mut reply = query_dns.to_vec();
    let qd = u16::from_be_bytes([query_dns[4], query_dns[5]]);
    apply_servfail_header(&mut reply, rcode, qd);

    // If the query had an OPT or other records after the question, trim them — a SERVFAIL carries
    // only the question (ancount=nscount=arcount=0). Find the end of the question section.
    if let Some(end_q) = end_of_question(query_dns) {
        reply.truncate(end_q);
    }
    reply
}

/// Apply the SERVFAIL-ish header in place: qr=1, opcode echoed, AA=0/TC=0/RD echoed, RA=0, rcode,
/// ANCOUNT/NSCOUNT/ARCOUNT = 0, QDCOUNT = `qdcount`. Bytes 2 + 3 + 6..12 are overwritten.
fn apply_servfail_header(buf: &mut [u8], rcode: u8, qdcount: u16) {
    if buf.len() < DNS_HEADER_LEN {
        return;
    }
    // Echo the opcode (bits 1-5 of byte 2, the 4 opcode bits + the AA/TC bits cleared; RD is bit 0
    // of byte 2 — echoed from the query so the stub's recursion-desired is honored on the reply).
    let opcode = (buf[2] >> 3) & 0x0F;
    let rd = buf[2] & 0x01;
    buf[2] = 0x80 | (opcode << 3) | rd; // QR=1, AA=0, TC=0, RD echoed
    buf[3] = rcode & 0x0F; // RA=0, Z=0, rcode
    buf[4..6].copy_from_slice(&qdcount.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf[10..12].copy_from_slice(&0u16.to_be_bytes()); // ARCOUNT
}

/// Walk the question section to find its byte end (past all qnames + qtype/qclass). Used to trim
/// EDNS OPT / additional RRs from a SERVFAIL reply. Returns None if the question is malformed; in
/// that case the caller keeps the whole query verbatim (a slightly fat SERVFAIL is still valid).
fn end_of_question(dns: &[u8]) -> Option<usize> {
    let mut off = DNS_HEADER_LEN;
    let qd = u16::from_be_bytes([dns[4], dns[5]]) as usize;
    for _ in 0..qd {
        off = skip_qname(dns, off)?;
        off = off.checked_add(4)?; // qtype + qclass
        if off > dns.len() {
            return None;
        }
    }
    Some(off.min(dns.len()))
}

/// Skip one wire qname (the dns.c walker, but only to find the end — no label copy). Honors
/// compression pointers (a pointer terminates the qname) and the same bounds as [`super::parse`].
fn skip_qname(dns: &[u8], mut off: usize) -> Option<usize> {
    let mut hops = 0u8;
    loop {
        if off >= dns.len() {
            return None;
        }
        let len = dns[off];
        if len == 0 {
            return Some(off + 1);
        }
        if (len & 0xC0) != 0 {
            // Compression pointer: the qname ends here (2 bytes consumed). We don't follow it — the
            // question's qname END is the byte after the pointer, regardless of where it points
            // (a pointer never starts a question qname in a well-formed query, but be defensive).
            if off + 1 >= dns.len() {
                return None;
            }
            return Some(off + 2);
        }
        hops += 1;
        if hops > 25 {
            return None;
        }
        off = off.checked_add(1 + len as usize)?;
        if off > dns.len() {
            return None;
        }
    }
}

const DNS_HEADER_LEN: usize = 12;

// ===================================================================================================
// synth_ip_udp_reply — the write_udp (udp.c:621-730) twin. Swap src↔dst, rebuild IP+UDP with valid
// checksums, return the full frame for `write(tun_fd, frame)`.
// ===================================================================================================

/// Synthesize the full IP+UDP reply frame for a DNS payload, swapping the original packet's src↔dst
/// (udp.c:646-677). The original `ParsedPacket` provides the addresses + IP version; the reply
/// carries `dns_payload` as the UDP body. Computes a valid IPv4 header checksum + the UDP checksum
/// (v4 over the IPv4 pseudo-header, v6 over the IPv6 pseudo-header — udp.c:653-688 verbatim).
///
/// Returns the wire frame (IP header + UDP header + payload), sized to fit. The loop `write()`s it
/// back to the tun fd.
pub fn synth_ip_udp_reply(orig: &ParsedPacket<'_>, dns_payload: &[u8]) -> Vec<u8> {
    match (orig.version, &orig.src_ip, &orig.dst_ip) {
        (4, IpAddrBytes::V4(s), IpAddrBytes::V4(d)) => synth_v4_reply(*s, *d, orig, dns_payload),
        (6, IpAddrBytes::V6(s), IpAddrBytes::V6(d)) => synth_v6_reply(*s, *d, orig, dns_payload),
        _ => Vec::new(), // unreachable: parse guarantees the IpAddrBytes discriminant matches version
    }
}

fn synth_v4_reply(
    orig_src: [u8; 4],
    orig_dst: [u8; 4],
    orig: &ParsedPacket<'_>,
    dns_payload: &[u8],
) -> Vec<u8> {
    let udp_sport = orig.udp.map(|u| u.dport).unwrap_or(53); // reply source = the queried :53
    let udp_dport = orig.udp.map(|u| u.sport).unwrap_or(0); // reply dest = the original source
    let total = IP4_HEADER_LEN + UDP_HEADER_LEN + dns_payload.len();
    let mut buf = vec![0u8; total];

    // IPv4 header (udp.c:640-650): src = original dst, dst = original src (the swap).
    buf[0] = 0x45; // version=4, ihl=5
    buf[2..4].copy_from_slice(&(total as u16).to_be_bytes()); // tot_len
    buf[8] = IP_DEFAULT_TTL;
    buf[9] = super::parse::IPPROTO_UDP;
    buf[12..16].copy_from_slice(&orig_dst); // reply src = orig dst
    buf[16..20].copy_from_slice(&orig_src); // reply dst = orig src
    let cksum = finalize_checksum(sum_bytes(&buf[..IP4_HEADER_LEN]));
    buf[10..12].copy_from_slice(&cksum.to_be_bytes());

    // UDP header.
    buf[IP4_HEADER_LEN..IP4_HEADER_LEN + 2].copy_from_slice(&udp_sport.to_be_bytes());
    buf[IP4_HEADER_LEN + 2..IP4_HEADER_LEN + 4].copy_from_slice(&udp_dport.to_be_bytes());
    let udp_len = (UDP_HEADER_LEN + dns_payload.len()) as u16;
    buf[IP4_HEADER_LEN + 4..IP4_HEADER_LEN + 6].copy_from_slice(&udp_len.to_be_bytes());
    // UDP checksum (udp.c:652-660): seed with the IPv4 pseudo-header, fold in the UDP header (check=0,
    // already zero in buf), then the payload.
    let mut s = 0u32;
    // Pseudo: src(4) + dst(4) + zero(1) + proto(1) + udp_len(2, BE).
    s = sum_into(s, &orig_dst);
    s = sum_into(s, &orig_src);
    let pseudo_tail = [
        0u8,
        super::parse::IPPROTO_UDP,
        (udp_len >> 8) as u8,
        (udp_len & 0xFF) as u8,
    ];
    s = sum_into(s, &pseudo_tail);
    // UDP header (with check field = 0): bytes IP4_HEADER_LEN..+6.
    s = sum_into(s, &buf[IP4_HEADER_LEN..IP4_HEADER_LEN + 6]);
    s = sum_into(s, dns_payload);
    let udp_cksum = udp_finalize(s);
    buf[IP4_HEADER_LEN + 6..IP4_HEADER_LEN + 8].copy_from_slice(&udp_cksum.to_be_bytes());

    // Payload.
    buf[IP4_HEADER_LEN + UDP_HEADER_LEN..].copy_from_slice(dns_payload);
    buf
}

fn synth_v6_reply(
    orig_src: [u8; 16],
    orig_dst: [u8; 16],
    orig: &ParsedPacket<'_>,
    dns_payload: &[u8],
) -> Vec<u8> {
    let udp_sport = orig.udp.map(|u| u.dport).unwrap_or(53);
    let udp_dport = orig.udp.map(|u| u.sport).unwrap_or(0);
    let total = IP6_HEADER_LEN + UDP_HEADER_LEN + dns_payload.len();
    let mut buf = vec![0u8; total];

    // IPv6 base header (udp.c:670-677): version=6, plen, nxt=UDP, hlim=64, src=orig dst, dst=orig src.
    buf[0] = 0x60; // version=6 (the high byte of the flow label quad)
    let plen = (UDP_HEADER_LEN + dns_payload.len()) as u16;
    buf[4..6].copy_from_slice(&plen.to_be_bytes());
    buf[6] = super::parse::IPPROTO_UDP;
    buf[7] = IP_DEFAULT_TTL;
    buf[8..24].copy_from_slice(&orig_dst); // reply src = orig dst
    buf[24..40].copy_from_slice(&orig_src); // reply dst = orig src
                                            // IPv6 has NO header checksum; the L4 checksum carries a 40-byte pseudo-header.

    buf[IP6_HEADER_LEN..IP6_HEADER_LEN + 2].copy_from_slice(&udp_sport.to_be_bytes());
    buf[IP6_HEADER_LEN + 2..IP6_HEADER_LEN + 4].copy_from_slice(&udp_dport.to_be_bytes());
    let udp_len = (UDP_HEADER_LEN + dns_payload.len()) as u16;
    buf[IP6_HEADER_LEN + 4..IP6_HEADER_LEN + 6].copy_from_slice(&udp_len.to_be_bytes());

    // UDP checksum (udp.c:680-688): the IPv6 pseudo-header is src(16) + dst(16) + upper-layer-len
    // (4, BE u32) + zero(3) + nxt(1) = 40 bytes.
    let mut s = 0u32;
    s = sum_into(s, &orig_dst);
    s = sum_into(s, &orig_src);
    let ulpl = (UDP_HEADER_LEN + dns_payload.len()) as u32;
    let ulpl_be = ulpl.to_be_bytes();
    s = sum_into(s, &ulpl_be);
    let tail = [0u8, 0u8, 0u8, super::parse::IPPROTO_UDP];
    s = sum_into(s, &tail);
    s = sum_into(s, &buf[IP6_HEADER_LEN..IP6_HEADER_LEN + 6]); // UDP header (check=0)
    s = sum_into(s, dns_payload);
    let udp_cksum = udp_finalize(s);
    buf[IP6_HEADER_LEN + 6..IP6_HEADER_LEN + 8].copy_from_slice(&udp_cksum.to_be_bytes());

    buf[IP6_HEADER_LEN + UDP_HEADER_LEN..].copy_from_slice(dns_payload);
    buf
}

// ===================================================================================================
// The Internet checksum (udp.c:650-699 calc_checksum, pure Rust). One's-complement sum: fold 16-bit
// big-endian words, pad an odd tail with a zero low byte, fold the carry, invert.
// ===================================================================================================

/// Sum the bytes into an accumulator as 16-bit big-endian words (the on-the-wire byte order). An odd
/// tail byte is padded with a zero low byte (RFC 1071 §3.B).
fn sum_into(mut acc: u32, data: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        acc = acc.wrapping_add(u16::from_be_bytes([data[i], data[i + 1]]) as u32);
        i += 2;
    }
    if i < data.len() {
        // Odd tail: the byte becomes the HIGH octet of a final 16-bit word (RFC 1071).
        acc = acc.wrapping_add((data[i] as u32) << 8);
    }
    acc
}

/// Convenience: sum a slice from a fresh accumulator (the `calc_checksum(0, ...)` shape).
fn sum_bytes(data: &[u8]) -> u32 {
    sum_into(0, data)
}

/// Fold the accumulator's carry bits into 16 bits, then invert (the final one's complement). Returns
/// the checksum in host order; the caller stores it big-endian. A computed checksum of all-zero
/// payload is 0xFFFF per UDP convention (UDP allows 0 to mean "no checksum", so a real computed zero
/// is transmitted as 0xFFFF — RFC 768). We apply that ONLY for UDP, not the IP header (the IP header
/// checksum field is never 0xFFFF-special; a zero IP checksum is legitimate only for "unset").
fn finalize_checksum(mut acc: u32) -> u16 {
    while (acc >> 16) != 0 {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    let cksum = !(acc as u16);
    // UDP-only zero→0xFFFF rule: applied at the v4/v6 call sites (NOT here — this fn also feeds the
    // IP header checksum, where 0 is the legitimate "unset" and 0xFFFF would be wrong). The UDP
    // call sites pass through `udp_finalize` below.
    cksum
}

/// UDP checksum finalize: the RFC 768 "computed-zero → 0xFFFF" rule (a UDP checksum of 0 means "no
/// checksum" on IPv4; a real computed zero must be transmitted as 0xFFFF so the receiver knows one
/// was computed). IPv6 REQUIRES a UDP checksum (never 0), so this rule is correct for both.
#[inline]
fn udp_finalize(acc: u32) -> u16 {
    let c = finalize_checksum(acc);
    if c == 0 {
        0xFFFF
    } else {
        c
    }
}

// ===================================================================================================
// Tests — host-runnable. The checksum correctness, the SERVFAIL shape, the address swap.
// ===================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::parse::{
        IpAddrBytes, IP4_HEADER_LEN, IP6_HEADER_LEN, IPPROTO_UDP, UDP_HEADER_LEN,
    };
    use crate::tunnel::ParsedPacket;

    fn parsed_v4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> ParsedPacket<'static> {
        // A ParsedPacket borrows its UDP payload; for synth the payload is irrelevant (only the
        // addresses + ports matter), so we use an empty static slice.
        ParsedPacket {
            version: 4,
            src_ip: IpAddrBytes::V4(src),
            dst_ip: IpAddrBytes::V4(dst),
            proto: IPPROTO_UDP,
            udp: Some(crate::tunnel::parse::UdpLayer {
                sport,
                dport,
                payload: &[],
            }),
            tcp_dport: None,
        }
    }

    fn parsed_v6(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16) -> ParsedPacket<'static> {
        ParsedPacket {
            version: 6,
            src_ip: IpAddrBytes::V6(src),
            dst_ip: IpAddrBytes::V6(dst),
            proto: IPPROTO_UDP,
            udp: Some(crate::tunnel::parse::UdpLayer {
                sport,
                dport,
                payload: &[],
            }),
            tcp_dport: None,
        }
    }

    #[test]
    fn servfail_header_has_qr_set_and_rcode_2() {
        // Risk 4: a resolver-None ⇒ SERVFAIL (rcode 2). Build a real query, synthesize, check the header.
        let mut q = vec![0u8; DNS_HEADER_LEN];
        q[0..2].copy_from_slice(&0xABCDu16.to_be_bytes()); // ID
        q[2] = 0x01; // RD=1
        q[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount=1
        q.extend_from_slice(b"\x07example\x03com\x00");
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        let r = synthesize_servfail(&q, RCODE_SERVFAIL);
        assert_eq!(r[0..2], q[0..2], "ID echoed");
        assert_eq!(r[2] & 0x80, 0x80, "QR set");
        assert_eq!(r[3] & 0x0F, RCODE_SERVFAIL, "rcode = 2");
        assert_eq!(r[6..8], [0, 0], "ancount = 0");
    }

    #[test]
    fn servfail_for_short_query_still_returns_a_header() {
        // A malformed (sub-header) query still yields a SERVFAIL header — never silent (Risk 4).
        let r = synthesize_servfail(&[0x12, 0x34], RCODE_SERVFAIL);
        assert_eq!(r.len(), DNS_HEADER_LEN);
        assert_eq!(r[0..2], [0x12, 0x34]);
        assert_eq!(r[3] & 0x0F, RCODE_SERVFAIL);
    }

    #[test]
    fn v4_reply_swaps_addresses_and_ports() {
        let p = parsed_v4([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53);
        let body = b"reply";
        let frame = synth_ip_udp_reply(&p, body);
        assert_eq!(frame.len(), IP4_HEADER_LEN + UDP_HEADER_LEN + body.len());
        // Reply src IP = original dst IP (10.0.0.2); reply dst IP = original src IP (10.0.0.1).
        assert_eq!(&frame[12..16], &[10, 0, 0, 2]);
        assert_eq!(&frame[16..20], &[10, 0, 0, 1]);
        // Reply UDP sport = original dport (53); dport = original sport (5353).
        let u = IP4_HEADER_LEN;
        assert_eq!(u16::from_be_bytes([frame[u], frame[u + 1]]), 53);
        assert_eq!(u16::from_be_bytes([frame[u + 2], frame[u + 3]]), 5353);
    }

    #[test]
    fn v4_reply_ip_checksum_is_valid() {
        // The IP header checksum must verify: summing the whole header (check=0) → 0xFFFF after
        // invert-fold... equivalently, summing the header INCLUDING the check field == 0.
        let p = parsed_v4([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53);
        let frame = synth_ip_udp_reply(&p, b"abc");
        let s = sum_bytes(&frame[..IP4_HEADER_LEN]);
        // A valid header sums (with the check field present) to 0xFFFF (all-ones) — the
        // one's-complement identity: sum(data + ~sum(data)) == 0xFFFF.
        let folded = {
            let mut a = s;
            while (a >> 16) != 0 {
                a = (a & 0xFFFF) + (a >> 16);
            }
            a as u16
        };
        assert_eq!(folded, 0xFFFF, "IP header checksum must verify");
    }

    #[test]
    fn v4_reply_udp_checksum_is_nonzero_and_valid() {
        let p = parsed_v4([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53);
        let body = b"a-real-dns-reply-payload";
        let frame = synth_ip_udp_reply(&p, body);
        let u = IP4_HEADER_LEN;
        let stored = u16::from_be_bytes([frame[u + 6], frame[u + 7]]);
        assert_ne!(
            stored, 0,
            "UDP checksum must be computed (not 'no checksum')"
        );
        // Re-derive: pseudo-header + UDP header (check=0) + payload, then invert-fold; the stored
        // value MUST make the total (including itself) sum to 0xFFFF.
        let mut hdr_check_zeroed = frame[u..u + 6].to_vec();
        hdr_check_zeroed.extend_from_slice(body);
        let mut s = 0u32;
        s = sum_into(s, &frame[12..16]); // reply src IP
        s = sum_into(s, &frame[16..20]); // reply dst IP
        s = sum_into(s, &[0, IPPROTO_UDP]); // proto + (the u16 udp_len word is folded separately)
        let udp_len_word = (UDP_HEADER_LEN + body.len()) as u16;
        s = sum_into(s, &udp_len_word.to_be_bytes());
        s = sum_into(s, &hdr_check_zeroed);
        s = sum_into(s, &stored.to_be_bytes()); // include the check field itself
        let mut a = s;
        while (a >> 16) != 0 {
            a = (a & 0xFFFF) + (a >> 16);
        }
        assert_eq!(a as u16, 0xFFFF, "UDP checksum must verify");
    }

    #[test]
    fn v6_reply_swaps_addresses_and_has_plen() {
        let src = [0xfd; 16];
        let dst = [0xfe; 16];
        let p = parsed_v6(src, dst, 5353, 53);
        let body = b"reply";
        let frame = synth_ip_udp_reply(&p, body);
        assert_eq!(frame.len(), IP6_HEADER_LEN + UDP_HEADER_LEN + body.len());
        assert_eq!(&frame[8..24], &dst); // reply src = orig dst
        assert_eq!(&frame[24..40], &src); // reply dst = orig src
        let plen = u16::from_be_bytes([frame[4], frame[5]]) as usize;
        assert_eq!(plen, UDP_HEADER_LEN + body.len());
        assert_eq!(frame[6], IPPROTO_UDP);
    }
}
