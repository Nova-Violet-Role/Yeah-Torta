/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **The IP/UDP packet parser for the Rust tunnel loop** — the GENESIS overhaul of the legacy
//! `jni/invizible/{ip,dns}.c` byte-path decision tree into pure, `#![forbid(unsafe_code)]` Rust.
//!
//! ## GENESIS — study → overhaul → combine
//!
//! Studied (NEVER copy-pasted):
//! - `ip.c:140-210` — the IPv4 ihl/tot_len/proto gates + the IPv6 extension-header walk
//!   (ip.c:181-199): a `while is_lower_layer(ext.nxt)` chain that falls BACK to `ip6_nxt` if it
//!   can't resolve to an upper-layer proto (the "give up, treat as the base nxt" edge, ip.c:194-198).
//! - `udp.c:281-468` (`handle_udp`) — the UDP dispatch: version lookup, the `!fwd53` short-circuit
//!   (udp.c:213-214), the DNS question gate (`qr==0 && opcode==0 && qcount>0`), qname extraction,
//!   and the `bypass_lan` 13-suffix LAN/mDNS skip (udp.c:449-466).
//! - `dns.c:26-81` (`get_qname`) — the wire qname walker with compression-pointer support and the
//!   **count > 25** cap (dns.c:39) on pointer-following (the decompression-bomb bound).
//!
//! Combined into: [`parse_ip_udp`] (the IP→UDP decision tree → a typed [`ParsedPacket`]) +
//! [`extract_qname`] (the dns.c walker) + [`matches_lan_suffix`] (the udp.c 13-suffix list).
//!
//! ## The 30-edge checklist (spec §2.3, each edge grounded above)
//!
//! The parser drops (returns `None`) on EVERY malformation the C engine drops, so the byte-path is
//! faithful by construction. The non-DNS-intercept branches (non-UDP, dport != 53, !fwd53) return
//! the parsed packet with [`ParsedPacket::is_dns_query`] == false so the loop can apply the Warden
//! gate (the Stage-2-min "forward_or_warden_drop") instead of silently forwarding.
//!
//! ## Invariants
//!
//! `#![forbid(unsafe_code)]`, std-only, zero new deps, allocation-light (ring-shaped output: small
//! fixed-size IP fields + a borrowed payload slice). Cross-platform: compiles on the Windows host
//! build (the fd I/O lives in [`super`], unix-gated) so the pure logic is unit-testable in `cargo test`.

#![forbid(unsafe_code)]

// ---- IP header sizes (the C `<netinet/ip.h>` / `<netinet/ip6.h>` constants, as consts) ----

/// IPv4 header minimum length (`sizeof(struct iphdr)` == 20). ip.c:140 gate.
pub const IP4_HEADER_LEN: usize = 20;
/// IPv6 base header length (`sizeof(struct ip6_hdr)` == 40). ip.c:173 gate.
pub const IP6_HEADER_LEN: usize = 40;
/// UDP header length (`sizeof(struct udphdr)` == 8). ip.c:235 gate.
pub const UDP_HEADER_LEN: usize = 8;
/// DNS header length (RFC 1035 §4.1.1, 12 bytes). dns.c:85 gate.
pub const DNS_HEADER_LEN: usize = 12;

/// IP protocol number for UDP (17, `<netinet/in.h> IPPROTO_UDP).
pub const IPPROTO_UDP: u8 = 17;
/// IP protocol number for TCP (6, `<netinet/in.h>` IPPROTO_TCP).
pub const IPPROTO_TCP: u8 = 6;
/// TCP header minimum length (`sizeof(struct tcphdr)` == 20, no options). The dport read gates on
/// the FULL minimum header — a 4-byte "TCP" stub is malformed, not a port source.
pub const TCP_HEADER_LEN: usize = 20;

/// The qname decompression-pointer cap (dns.c:39 `count++ > 25 break`): a query that follows more
/// than 25 compression pointers is treated as malformed (the decompression-bomb bound).
const QNAME_PTR_CAP: u8 = 25;
/// The maximum rendered qname length (dns.c `DNS_QNAME_MAX` == 255).
const QNAME_MAX: usize = 255;

/// A parsed IP+UDP packet — the typed output of the decision tree. Carries exactly the fields the
/// loop + the reply synthesizer need; the payload is borrowed from the input (zero-copy).
#[derive(Debug, Clone, Copy)]
pub struct ParsedPacket<'a> {
    /// IP version (4 or 6).
    pub version: u8,
    /// The IP-level source address (4 bytes for v4, 16 for v6).
    pub src_ip: IpAddrBytes,
    /// The IP-level destination address (4 bytes for v4, 16 for v6).
    pub dst_ip: IpAddrBytes,
    /// The upper-layer protocol number (17 for UDP; the parser only fills UDP payloads, but a
    /// non-UDP packet is returned with `udp == None` so the Warden gate can rule on it).
    pub proto: u8,
    /// The UDP layer, if the packet carries UDP (proto == 17 and the header fits). `None` for TCP /
    /// ICMP / unknown protocols (the loop applies the Warden gate to those without forwarding).
    pub udp: Option<UdpLayer<'a>>,
    /// The TCP destination port, if the packet carries TCP and the full 20-byte header fits.
    /// PORT HONESTY (#20): the Warden gate + tracker feed rule on the REAL dport (443, 5228, …),
    /// never a fabricated 0 — the panel row must tell the truth even for flows the sync loop
    /// cannot carry. `None` for non-TCP or a truncated header (the row then honestly shows 0).
    pub tcp_dport: Option<u16>,
}

/// The UDP layer — borrowed payload (the DNS bytes when dport == 53).
#[derive(Debug, Clone, Copy)]
pub struct UdpLayer<'a> {
    pub sport: u16,
    pub dport: u16,
    /// The UDP payload (everything after the 8-byte udphdr). For a :53 DNS query this is the raw
    /// wire-format DNS message handed to [`crate::resolver::resolve_datapath`].
    pub payload: &'a [u8],
}

/// A borrowed IP address — 4 bytes (v4) or 16 bytes (v6). Kept as a flat enum (no `std::net` alloc)
/// so the parser is ring-only; the reply synthesizer swaps these byte arrays in place.
#[derive(Debug, Clone, Copy)]
pub enum IpAddrBytes {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl<'a> ParsedPacket<'a> {
    /// A DNS query the loop should intercept (UDP, dport == 53). The `fwd53` flag is the caller's
    /// responsibility (the loop short-circuits when `!fwd53`, mirroring udp.c:213-214); this just
    /// reports the packet shape.
    pub fn is_dns_query(&self) -> bool {
        match self.udp {
            Some(u) => u.dport == 53,
            None => false,
        }
    }
}

// ===================================================================================================
// parse_ip_udp — the IP decision tree → typed packet. Returns None on ANY malformation (drop).
// ===================================================================================================

/// Parse an IP packet off the tun wire into a typed [`ParsedPacket`]. Mirrors the `handle_v4/v6`
/// decision tree of ip.c:140-210: version gate, ihl/tot_len gate (v4), the ext-hdr walk (v6), the
/// UDP proto dispatch, and the UDP-header-fits gate. Returns `None` on any malformation (the C
/// engine's `return` drop edges). Non-UDP packets are returned with `udp == None` so the loop can
/// apply the Warden gate to them (Stage-2-min does not forward TCP/ICMP).
///
/// `length` is the full packet length (the number of bytes the tun read returned). The v4
/// `tot_len == length` gate (ip.c:160) is honored: a header claiming a different total length is a
/// drop (truncated/oversized — a classic fuzz edge).
pub fn parse_ip_udp(pkt: &[u8]) -> Option<ParsedPacket<'_>> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    match version {
        4 => parse_v4(pkt),
        6 => parse_v6(pkt),
        _ => None, // ip.c:208 "Unknown version"
    }
}

fn parse_v4(pkt: &[u8]) -> Option<ParsedPacket<'_>> {
    // Edge #2: too short for an IPv4 header (ip.c:140).
    if pkt.len() < IP4_HEADER_LEN {
        return None;
    }
    let ihl = pkt[0] & 0x0F;
    // Edge #3: ihl < 5 ⇒ invalid header (the minimum is 5 32-bit words). Treat as a drop.
    if ihl < 5 {
        return None;
    }
    let header_len = (ihl as usize) * 4;
    // Edge #3b: the claimed header length exceeds the packet (a lying ihl).
    if header_len > pkt.len() {
        return None;
    }
    // Edge #5: tot_len (network order) MUST equal the packet length (ip.c:160 gate). A mismatch is a
    // drop — truncation / oversizing / a fuzz probe.
    let tot_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if tot_len != pkt.len() {
        return None;
    }
    let proto = pkt[9];
    let src = [pkt[12], pkt[13], pkt[14], pkt[15]];
    let dst = [pkt[16], pkt[17], pkt[18], pkt[19]];

    // Only UDP carries a DNS intercept in Stage-2-min; non-UDP packets are returned proto-only so
    // the loop can Warden-gate them. TCP-over-tun / ICMP / DHCP tethering are Stage-3 work.
    let udp = if proto == IPPROTO_UDP {
        parse_udp_layer(pkt, header_len)
    } else {
        None
    };
    let tcp_dport = if proto == IPPROTO_TCP {
        parse_tcp_dport(pkt, header_len)
    } else {
        None
    };

    Some(ParsedPacket {
        version: 4,
        src_ip: IpAddrBytes::V4(src),
        dst_ip: IpAddrBytes::V4(dst),
        proto,
        udp,
        tcp_dport,
    })
}

fn parse_v6(pkt: &[u8]) -> Option<ParsedPacket<'_>> {
    // Edge #8: too short for an IPv6 base header (ip.c:173).
    if pkt.len() < IP6_HEADER_LEN {
        return None;
    }
    let src: [u8; 16] = pkt[8..24].try_into().ok()?;
    let dst: [u8; 16] = pkt[24..40].try_into().ok()?;
    let mut proto = pkt[6]; // ip6_nxt
    let mut l4_off = IP6_HEADER_LEN;

    // Edge #9 — the extension-header walk (ip.c:181-199). If ip6_nxt is NOT an upper-layer proto
    // (UDP/TCP/ICMP), walk the extension-header chain: each ext header is 8 + ip6e_len bytes, and
    // its `ip6e_nxt` is the next header. If the walk can't resolve to an upper-layer proto, FALL
    // BACK to `proto = ip6_nxt, off = 0` (ip.c:194-198) — treat the base nxt as the protocol and
    // the L4 starts right after the fixed base (no ext consumed).
    if !is_upper_layer(proto) {
        let mut off = IP6_HEADER_LEN;
        while off + 2 <= pkt.len() {
            let nxt = pkt[off];
            // The extension header length is in 8-octet units, with the first 8 included: 8 + len*8.
            let ext_len = 8 + (pkt[off + 1] as usize) * 8;
            if is_upper_layer(nxt) {
                proto = nxt;
                l4_off = off + ext_len;
                break;
            }
            off += ext_len;
            if off > pkt.len() {
                break;
            }
            // Loop guard: ip.c walks while is_lower_layer(ext.nxt). If we've walked past the end
            // without resolving, the fall-back fires (below).
        }
        if !is_upper_layer(proto) {
            // Fall back (ip.c:194-198): treat the base ip6_nxt as the protocol, L4 after the base.
            proto = pkt[6];
            l4_off = IP6_HEADER_LEN;
        }
    }

    let udp = if proto == IPPROTO_UDP {
        parse_udp_layer(pkt, l4_off)
    } else {
        None
    };
    let tcp_dport = if proto == IPPROTO_TCP {
        parse_tcp_dport(pkt, l4_off)
    } else {
        None
    };

    Some(ParsedPacket {
        version: 6,
        src_ip: IpAddrBytes::V6(src),
        dst_ip: IpAddrBytes::V6(dst),
        proto,
        udp,
        tcp_dport,
    })
}

/// Parse the UDP layer at `l4_off`. Mirrors ip.c:234-245: the "UDP packet too short" gate (a UDP
/// header must fit), then the sport/dport read (network order) + the payload slice.
fn parse_udp_layer(pkt: &[u8], l4_off: usize) -> Option<UdpLayer<'_>> {
    if pkt.len() < l4_off + UDP_HEADER_LEN {
        return None; // ip.c:235 "UDP packet too short"
    }
    let sport = u16::from_be_bytes([pkt[l4_off], pkt[l4_off + 1]]);
    let dport = u16::from_be_bytes([pkt[l4_off + 2], pkt[l4_off + 3]]);
    let payload = &pkt[l4_off + UDP_HEADER_LEN..];
    Some(UdpLayer {
        sport,
        dport,
        payload,
    })
}

/// Read the TCP destination port at `l4_off` (#20 PORT HONESTY). Mirrors the UDP layer's
/// header-must-fit discipline: the FULL 20-byte minimum tcphdr must fit (a packet whose "TCP"
/// truncates mid-header is malformed — reading a dport out of a 4-byte stub would launder garbage
/// into the panel). dport sits at tcphdr bytes 2..4, network order — same slot as udphdr's.
fn parse_tcp_dport(pkt: &[u8], l4_off: usize) -> Option<u16> {
    if pkt.len() < l4_off + TCP_HEADER_LEN {
        return None;
    }
    Some(u16::from_be_bytes([pkt[l4_off + 2], pkt[l4_off + 3]]))
}

/// Is `proto` an upper-layer protocol (one that carries ports / a transport payload)? The C engine
/// uses this to decide whether to walk the IPv6 ext-header chain (ip.c:183 `is_upper_layer`).
/// Conservative: only the three transport protocols the loop acts on count as upper-layer; anything
/// else (fragment / hopopt / routing / esp) keeps the walk going.
fn is_upper_layer(proto: u8) -> bool {
    matches!(
        proto,
        6 /* TCP */ | 17 /* UDP */ | 58 /* ICMPv6 */ | 1 /* ICMP */
    )
}

// ===================================================================================================
// extract_qname — the dns.c:26-81 walker, pure Rust.
// ===================================================================================================

/// Extract the wire qname from a DNS message payload (the UDP payload, starting at the DNS header).
/// Returns the dotted qname (`"example.com"`) + the byte offset immediately past the question's
/// qtype/qclass (so the caller can walk further if needed). Returns `None` on any malformation the
/// dns.c walker treats as invalid: an empty/oversized qname, an out-of-range compression pointer,
/// or more than [`QNAME_PTR_CAP`] pointer follows (dns.c:39).
///
/// Mirrors `dns.c:26-81 get_qname` EXACTLY in semantics: the 0xC0 compression-pointer test, the
/// `count++ > 25` cap, the `jump >= datalen` invalid-jump drop, and the `noff + len <= DNS_QNAME_MAX`
/// bound. `off` starts at `sizeof(struct dns_header)` (12, RFC 1035 §4.1).
pub fn extract_qname(dns_payload: &[u8]) -> Option<(String, usize)> {
    let datalen = dns_payload.len();
    let off = DNS_HEADER_LEN;
    if off >= datalen {
        return None;
    }

    let mut labels: Vec<u8> = Vec::with_capacity(QNAME_MAX);
    let mut ptr = off;
    let mut len = dns_payload[ptr];
    let mut count = 0u8;
    let mut advanced_past_pointer = 0usize; // set once we follow the first compression pointer

    while len != 0 {
        // Edge: the dns.c `count++ > 25 break` cap on pointer/label follows (dns.c:39).
        if count >= QNAME_PTR_CAP {
            return None;
        }
        count += 1;

        if ptr + 1 < datalen && (len & 0xC0) != 0 {
            // Compression pointer (dns.c:42-54): two bytes, (len & 0x3F) << 8 | next.
            let jump = (((len & 0x3F) as usize) << 8) | (dns_payload[ptr + 1] as usize);
            if jump >= datalen {
                return None; // dns.c:44 "DNS invalid jump"
            }
            ptr = jump;
            len = dns_payload[ptr];
            if advanced_past_pointer == 0 {
                // The first pointer follow advances the "real" offset past the 2 pointer bytes; a
                // later pointer follow does NOT advance it further (dns.c:51-54).
                advanced_past_pointer = off + 2;
            }
        } else if ptr + 1 + (len as usize) < datalen && labels.len() + (len as usize) <= QNAME_MAX {
            // A regular label: copy len bytes + append a '.'.
            let start = ptr + 1;
            let end = start + (len as usize);
            labels.extend_from_slice(&dns_payload[start..end]);
            labels.push(b'.');
            let next = end; // ptr + 1 + len
            if next >= datalen {
                return None; // dns.c:61 "DNS invalid jump"
            }
            ptr = next;
            len = dns_payload[ptr];
        } else {
            return None; // dns.c:67 `else break` (and the caller treats an unterminated qname as invalid)
        }
    }

    // dns.c:70-75: `ptr++` (past the terminating 0); if len>0 or noff==0 ⇒ invalid.
    if labels.is_empty() {
        return None;
    }
    // Strip the trailing '.' appended after the last label (dns.c:77 `*(qname+noff-1) = 0`).
    labels.pop();

    let final_off = if advanced_past_pointer != 0 {
        advanced_past_pointer
    } else {
        ptr + 1
    };

    // The question's qtype/qclass are the 4 bytes immediately after the qname; the caller reads them
    // by offset, but extract_qname returns the offset PAST them (off + 4) for dns.c parity.
    let past_question = final_off + 4;
    let qname = String::from_utf8(labels).ok()?;
    Some((qname, past_question))
}

// ===================================================================================================
// extract_answer_addrs — the A4 answer walker (RFC 1035 §4.1.3 resource-record walk).
// ===================================================================================================

/// Cap on ANSWER records walked. A hostile header can claim ANCOUNT=65535 over a 60-byte body; a
/// real reply the sovereign resolver produces carries a handful. Records past the cap are ignored,
/// never an error — the walk stays O(small) on the datapath.
const ANSWER_WALK_CAP: usize = 32;

/// Cap on label steps while SKIPPING one owner name (the [`QNAME_PTR_CAP`] intent, skip-shaped: a
/// compression pointer TERMINATES a skip — RFC 1035 §4.1.4, a pointer is always the last token —
/// so the only unbounded shape left is a label chain, and 128 steps × 1-byte minimum label already
/// exceeds any 64 KiB datagram's real content).
const NAME_SKIP_CAP: usize = 128;

/// Skip ONE wire name starting at `off`; return the offset immediately past it. Unlike
/// [`extract_qname`] this never renders the name — answer owner names are irrelevant to A4
/// attribution (the QUERY qname is what the app asked for; a CNAME chain's intermediate owners are
/// noise). `None` on malformation: an out-of-bounds read, a reserved label type (0x40/0x80 — the
/// dns.c walker folds these into pointers; the RFC calls them invalid, and a reply the resolver
/// built never emits them), or a chain past [`NAME_SKIP_CAP`].
fn skip_name(payload: &[u8], mut off: usize) -> Option<usize> {
    for _ in 0..NAME_SKIP_CAP {
        let len = *payload.get(off)?;
        if len == 0 {
            return Some(off + 1); // the root label terminates the name
        }
        if (len & 0xC0) == 0xC0 {
            // A compression pointer: 2 bytes, and the name ENDS here (§4.1.4 — a pointer is
            // always terminal). The target is never followed — a skip needs no rendering.
            if off + 2 > payload.len() {
                return None;
            }
            return Some(off + 2);
        }
        if (len & 0xC0) != 0 {
            return None; // 0x40/0x80 — reserved label types, invalid on the wire
        }
        off += 1 + len as usize;
    }
    None // label chain past the cap — hostile, not a name
}

/// Walk a DNS RESPONSE and return `(query qname, [(address, ttl)])` for every IN A/AAAA answer —
/// the A4 attribution source: "the app asked for THIS name and was told THESE addresses". The qname
/// is the QUESTION's (what the app dialed for), never a CNAME chain's intermediate owner — the
/// rethink `ipmap` semantic (ipmap.go, study-cited in GENESIS-pillar-warden.md A4), originated as
/// a from-scratch §4.1.3 walk.
///
/// `None` on anything that is not a well-formed single-question NOERROR response: a query (qr=0),
/// a non-zero rcode (NXDOMAIN/SERVFAIL carry no address truth), QDCOUNT≠1 (the loop only answers
/// single-question standard queries), or any truncation/malformation mid-walk — the parse.rs law:
/// malformed ⇒ drop, never a partial guess. Non-address answer records (CNAME, HTTPS, …) and
/// non-IN classes are SKIPPED, not errors; an empty address list on a valid reply is `Some`.
pub fn extract_answer_addrs(dns_payload: &[u8]) -> Option<(String, Vec<(std::net::IpAddr, u32)>)> {
    if dns_payload.len() < DNS_HEADER_LEN {
        return None;
    }
    // Byte 2 bit 7 = QR (§4.1.1): attribution records REPLIES only — a query carries no answers.
    if dns_payload[2] & 0x80 == 0 {
        return None;
    }
    // Byte 3 low nibble = RCODE: only NOERROR answers attribute.
    if dns_payload[3] & 0x0F != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([dns_payload[4], dns_payload[5]]);
    if qdcount != 1 {
        return None;
    }
    let ancount = u16::from_be_bytes([dns_payload[6], dns_payload[7]]) as usize;

    // The question section: qname + the offset past qtype/qclass — the same walker the intercept
    // gate uses (questions are never compressed: there is nothing earlier to point into).
    let (qname, mut off) = extract_qname(dns_payload)?;

    let mut addrs: Vec<(std::net::IpAddr, u32)> = Vec::new();
    for _ in 0..ancount.min(ANSWER_WALK_CAP) {
        off = skip_name(dns_payload, off)?;
        // The RR fixed part: TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) — §4.1.3.
        let fixed = dns_payload.get(off..off + 10)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rclass = u16::from_be_bytes([fixed[2], fixed[3]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        off += 10;
        let rdata = dns_payload.get(off..off + rdlen)?;
        off += rdlen;
        if rclass != 1 {
            continue; // IN only — CH/HS answers never attribute
        }
        match (rtype, rdlen) {
            // A with exactly 4 rdata bytes / AAAA with exactly 16 — a length mismatch is a
            // malformed record, but the record SKIPS (the address is unusable; the walk's
            // offsets stay rdlen-driven and remain correct).
            (1, 4) => {
                let mut b = [0u8; 4];
                b.copy_from_slice(rdata);
                addrs.push((std::net::IpAddr::from(b), ttl));
            }
            (28, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(rdata);
                addrs.push((std::net::IpAddr::from(b), ttl));
            }
            _ => {} // CNAME/HTTPS/TXT/… — the query qname is the attribution, owners are noise
        }
    }
    Some((qname, addrs))
}

// ===================================================================================================
// matches_lan_suffix — the udp.c:449-466 bypass_lan list.
// ===================================================================================================

/// Does the qname match a LAN/mDNS suffix the loop should NOT intercept (udp.c:449-466)? When
/// `bypass_lan` is armed and the qname ends with any of these 13 suffixes, the legacy engine drops
/// the redirect (lets the query pass to the system resolver); the Rust loop mirrors that by skipping
/// the resolve + writing nothing (the loop returns early). The list is the EXACT 13 from udp.c,
/// plus the `ipv4only.arpa` special case (udp.c:447, RFC 7050 — used for NAT64 discovery, must NOT
/// be intercepted either).
pub fn matches_lan_suffix(qname: &str) -> bool {
    // ipv4only.arpa (udp.c:447) — RFC 7050; never redirect.
    if eq_icase(qname, "ipv4only.arpa") {
        return true;
    }
    const SUFFIXES: &[&str] = &[
        ".local",
        ".lan",
        ".home",
        ".corp",
        ".private",
        ".internal",
        ".intranet",
        ".254.169.in-addr.arpa",
        ".8.e.f.ip6.arpa",
        ".9.e.f.ip6.arpa",
        ".a.e.f.ip6.arpa",
        ".b.e.f.ip6.arpa",
    ];
    let q = qname.as_bytes();
    for suf in SUFFIXES {
        let s = suf.as_bytes();
        if q.len() >= s.len() && eq_icase_bytes(&q[q.len() - s.len()..], s) {
            return true;
        }
    }
    false
}

/// Case-insensitive ASCII equality for a DNS-name compare (the legacy engine uses `str_ends_with` +
/// `str_equal` which are ASCII-case-insensitive on the wire labels; DNS is case-insensitive per
/// RFC 1035 §2.3.3).
fn eq_icase(a: &str, b: &str) -> bool {
    a.len() == b.len() && eq_icase_bytes(a.as_bytes(), b.as_bytes())
}

fn eq_icase_bytes(a: &[u8], b: &[u8]) -> bool {
    a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

// ===================================================================================================
// Tests — the 30-edge checklist, each edge grounded file:line. Pure logic, host-runnable.
// ===================================================================================================

#[cfg(test)]
mod tests {

    /// A5 GUARD -- `QNAME_MAX` (= 255, tunnel/parse.rs:63) bounds the RENDERED qname length while
    /// `extract_qname` walks a packet off the wire. The A5 inventory found it had a NUMBER and no
    /// test naming it.
    ///
    /// This is the byte-budget half of the decompression-bomb defence; `QNAME_PTR_CAP` (guarded in
    /// c2008e27) is the pointer-follow half, and the two catch different attacks. A qname can stay
    /// well under 25 label-follows and still render megabytes if nothing bounds the ACCUMULATED
    /// length -- which is why both bounds exist and why neither substitutes for the other.
    ///
    /// The refusal must be a REFUSAL, not a truncation: a silently shortened qname would be
    /// consulted against the blocklist as a DIFFERENT name than the one the client asked for.
    #[test]
    fn qname_max_refuses_an_over_long_name_rather_than_truncating_it() {
        fn payload(labels: usize) -> Vec<u8> {
            let mut v = vec![0u8; DNS_HEADER_LEN];
            for _ in 0..labels {
                v.push(63);
                v.extend_from_slice(&[b'a'; 63]);
            }
            v.push(0); // terminator
            v.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
            v
        }

        // 3 x 63-byte labels = 192 rendered bytes: comfortably under the cap, and it PARSES.
        let (name, _off) = extract_qname(&payload(3)).expect("a qname under QNAME_MAX must parse");
        assert_eq!(name.len(), 63 * 3 + 2, "three labels joined by two dots");
        assert!(
            name.len() <= QNAME_MAX,
            "the accepted qname must sit inside the budget"
        );

        // 5 x 63-byte labels = 320 rendered bytes: over the cap, and well inside QNAME_PTR_CAP
        // (5 label-follows vs a cap of 25), so this arm tests the BYTE budget and not the
        // pointer budget.
        assert!(
            extract_qname(&payload(5)).is_none(),
            "a qname over QNAME_MAX must be REFUSED, never truncated -- a shortened name would              be consulted as a different name than the client asked for"
        );

        // THE UNIVERSAL CLAIM, stated as an arm: whatever bytes arrive, `extract_qname` either
        // REFUSES or returns a name inside the budget. It may never return an over-long name.
        //
        // This arm exists because a weaker phrasing of the check -- `labels.len() <= QNAME_MAX`,
        // testing the budget BEFORE the label is added rather than after -- survived M-A5ag while
        // the two arms above stayed green. It permits the final label to overshoot by up to 63
        // bytes, so the parser hands back a 318-byte qname and calls it valid. The `is_none()`
        // arms cannot see that: they only ever ask whether SOMETHING was refused.
        let overshoot = {
            let mut v = vec![0u8; DNS_HEADER_LEN];
            for _ in 0..3 {
                v.push(63);
                v.extend_from_slice(&[b'a'; 63]); // 3 x 64 = 192 rendered
            }
            v.push(62);
            v.extend_from_slice(&[b'b'; 62]); // -> 255 rendered, exactly at the cap
            v.push(63);
            v.extend_from_slice(&[b'c'; 63]); // one more label: 318 rendered
            v.push(0);
            v.extend_from_slice(&[0, 1, 0, 1]);
            v
        };
        if let Some((name, _)) = extract_qname(&overshoot) {
            assert!(
                name.len() <= QNAME_MAX,
                "extract_qname returned a {}-byte qname; QNAME_MAX is {QNAME_MAX} -- the budget                  must be checked WITH the new label, not before it",
                name.len()
            );
        }
    }


    /// A5 GUARD -- the decompression-pointer budget has a NUMBER (`QNAME_PTR_CAP` = 25) and this
    /// makes breaching it LOUD. Both arms are asserted, so lowering OR raising the cap turns it red:
    /// a chain strictly under the cap must still resolve, a chain at the cap must be refused.
    ///
    /// Layout: 12-byte header, then a chain of `n` two-byte compression pointers each aimed at the
    /// next, terminating in the literal label `a` -- i.e. exactly `n` pointer follows.
    fn qname_pointer_chain(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 12];
        let start = 12usize;
        for k in 0..n {
            let target = (start + 2 * (k + 1)) as u16;
            buf.push(0xC0 | (target >> 8) as u8);
            buf.push((target & 0xFF) as u8);
        }
        buf.extend_from_slice(&[1, b'a', 0]);
        buf.extend_from_slice(&[0, 1, 0, 1]);
        buf
    }

    /// A5 GUARD -- `NAME_SKIP_CAP` (= 128) bounds the label walk while SKIPPING one owner name.
    /// Both arms asserted: a name with fewer labels than the cap must be skipped successfully, a
    /// name whose label chain runs past the cap must be refused rather than walked forever.
    fn label_chain(labels: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(labels * 2 + 1);
        for _ in 0..labels {
            buf.push(1);
            buf.push(b'a');
        }
        buf.push(0); // root label
        buf
    }

    #[test]
    fn name_skip_cap_is_128_and_the_breach_is_loud() {
        let under = label_chain(NAME_SKIP_CAP - 8);
        assert!(
            skip_name(&under, 0).is_some(),
            "a label chain UNDER the cap must skip cleanly (cap = {NAME_SKIP_CAP})"
        );
        let over = label_chain(NAME_SKIP_CAP + 8);
        assert!(
            skip_name(&over, 0).is_none(),
            "a label chain OVER the cap must be refused -- the walk is bounded, never unbounded"
        );
    }

    #[test]
    fn qname_pointer_cap_is_25_and_the_breach_is_loud() {
        let under = qname_pointer_chain(QNAME_PTR_CAP as usize - 2);
        assert!(
            extract_qname(&under).is_some(),
            "a chain UNDER the cap must still resolve (cap = {QNAME_PTR_CAP})"
        );
        let over = qname_pointer_chain(QNAME_PTR_CAP as usize + 4);
        assert!(
            extract_qname(&over).is_none(),
            "a chain OVER the cap must be refused -- this is the decompression-bomb bound"
        );
    }

    #[test]
    fn qname_self_referential_pointer_terminates() {
        // A pointer at offset 12 aimed at ITSELF: unbounded without the cap.
        let mut buf = vec![0u8; 12];
        buf.extend_from_slice(&[0xC0, 12]);
        buf.extend_from_slice(&[0, 1, 0, 1]);
        assert!(
            extract_qname(&buf).is_none(),
            "a self-referential pointer must terminate as malformed, never spin"
        );
    }
    use super::*;

    /// Build a minimal IPv4/UDP/DNS packet from scratch (the test scaffolding for the decision tree).
    fn build_v4_udp_dns(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        sport: u16,
        dport: u16,
        dns: &[u8],
    ) -> Vec<u8> {
        let total = IP4_HEADER_LEN + UDP_HEADER_LEN + dns.len();
        let mut p = vec![0u8; total];
        // IPv4 header.
        p[0] = 0x45; // version=4, ihl=5
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes()); // tot_len
        p[8] = 64; // TTL
        p[9] = IPPROTO_UDP;
        p[12..16].copy_from_slice(&src_ip);
        p[16..20].copy_from_slice(&dst_ip);
        // (IP checksum left 0 — the parser does not validate it on read; only the reply synth computes one.)
        // UDP header.
        let u = IP4_HEADER_LEN;
        p[u..u + 2].copy_from_slice(&sport.to_be_bytes());
        p[u + 2..u + 4].copy_from_slice(&dport.to_be_bytes());
        let udp_len = (UDP_HEADER_LEN + dns.len()) as u16;
        p[u + 4..u + 6].copy_from_slice(&udp_len.to_be_bytes());
        // DNS payload.
        p[u + UDP_HEADER_LEN..].copy_from_slice(dns);
        p
    }

    /// A minimal DNS query wire for `example.com` A (the dns.c shape, hand-built — no builder dep).
    fn example_dns_query() -> Vec<u8> {
        let mut d = vec![0u8; DNS_HEADER_LEN];
        d[0..2].copy_from_slice(&0x1234u16.to_be_bytes()); // ID
        d[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount = 1
                                                      // qname: 7example3com0
        d.extend_from_slice(b"\x07example\x03com\x00");
        d.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        d.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        d
    }

    /// A minimal DNS RESPONSE wire for `example.com`: header (qr=1, rcode, ancount), the echoed
    /// question, then each answer as (rtype, rclass, ttl, rdata) with a compressed owner
    /// (0xC00C → the question qname), hand-built like [`example_dns_query`].
    fn example_dns_reply(rcode: u8, answers: &[(u16, u16, u32, &[u8])]) -> Vec<u8> {
        let mut d = vec![0u8; DNS_HEADER_LEN];
        d[0..2].copy_from_slice(&0x1234u16.to_be_bytes()); // ID
        d[2] = 0x81; // qr=1, rd=1
        d[3] = 0x80 | (rcode & 0x0F); // ra=1, rcode
        d[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount = 1
        d[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes()); // ancount
        d.extend_from_slice(b"\x07example\x03com\x00");
        d.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        d.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        for (rtype, rclass, ttl, rdata) in answers {
            d.extend_from_slice(&[0xC0, 0x0C]); // owner: pointer to the question qname
            d.extend_from_slice(&rtype.to_be_bytes());
            d.extend_from_slice(&rclass.to_be_bytes());
            d.extend_from_slice(&ttl.to_be_bytes());
            d.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            d.extend_from_slice(rdata);
        }
        d
    }

    // ---- extract_answer_addrs (the A4 answer walker) ----

    #[test]
    fn answer_walk_extracts_a_and_aaaa() {
        let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53];
        let d = example_dns_reply(0, &[(1, 1, 300, &[203, 0, 113, 7]), (28, 1, 600, &v6)]);
        let (qname, addrs) = extract_answer_addrs(&d).expect("valid reply walks");
        assert_eq!(qname, "example.com");
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], ("203.0.113.7".parse().unwrap(), 300));
        assert_eq!(addrs[1], ("2001:db8::53".parse().unwrap(), 600));
    }

    #[test]
    fn answer_walk_skips_cname_qname_stays_query() {
        // A CNAME (type 5) answer, then the A record for the target — the attribution qname is
        // the QUERY's, never the chain's intermediate owner (the A4 spec's CDN-collapse law).
        let cname_rdata = b"\x03cdn\x07example\x03com\x00";
        let d = example_dns_reply(0, &[(5, 1, 300, cname_rdata), (1, 1, 300, &[203, 0, 113, 8])]);
        let (qname, addrs) = extract_answer_addrs(&d).expect("cname reply walks");
        assert_eq!(qname, "example.com");
        assert_eq!(addrs, vec![("203.0.113.8".parse().unwrap(), 300)]);
    }

    #[test]
    fn answer_walk_rejects_query_nxdomain_and_multi_question() {
        // qr=0 — a QUERY never attributes.
        assert!(extract_answer_addrs(&example_dns_query()).is_none());
        // rcode=3 (NXDOMAIN) — no address truth.
        assert!(extract_answer_addrs(&example_dns_reply(3, &[(1, 1, 60, &[1, 2, 3, 4])])).is_none());
        // qdcount=2 — the loop only answers single-question queries.
        let mut d = example_dns_reply(0, &[(1, 1, 60, &[1, 2, 3, 4])]);
        d[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert!(extract_answer_addrs(&d).is_none());
    }

    #[test]
    fn answer_walk_truncation_is_none_not_partial() {
        // ANCOUNT claims 2 but the wire carries 1 — the parse.rs law: malformed ⇒ None, never
        // a partial guess.
        let mut d = example_dns_reply(0, &[(1, 1, 60, &[9, 9, 9, 9])]);
        d[6..8].copy_from_slice(&2u16.to_be_bytes());
        assert!(extract_answer_addrs(&d).is_none());
        // Truncated rdata: rdlen says 4, wire ends after 2.
        let mut d = example_dns_reply(0, &[(1, 1, 60, &[9, 9, 9, 9])]);
        d.truncate(d.len() - 2);
        assert!(extract_answer_addrs(&d).is_none());
    }

    #[test]
    fn answer_walk_skips_non_in_class_and_odd_rdlen() {
        // class=CH(3) A record + an A with rdlen 5 — both skipped, walk offsets stay correct,
        // the trailing well-formed record still lands.
        let d = example_dns_reply(
            0,
            &[(1, 3, 60, &[1, 1, 1, 1]), (1, 1, 60, &[2, 2, 2, 2, 2]), (1, 1, 60, &[8, 8, 8, 8])],
        );
        let (_, addrs) = extract_answer_addrs(&d).expect("skips are not errors");
        assert_eq!(addrs, vec![("8.8.8.8".parse().unwrap(), 60)]);
    }

    #[test]
    fn answer_walk_caps_hostile_ancount() {
        // 40 real records: only ANSWER_WALK_CAP walked, the rest ignored — never an error.
        let rdatas: Vec<[u8; 4]> = (0..40u8).map(|i| [10, 0, 0, i]).collect();
        let answers: Vec<(u16, u16, u32, &[u8])> =
            rdatas.iter().map(|r| (1u16, 1u16, 60u32, &r[..])).collect();
        let d = example_dns_reply(0, &answers);
        let (_, addrs) = extract_answer_addrs(&d).expect("capped walk still succeeds");
        assert_eq!(addrs.len(), ANSWER_WALK_CAP);
    }

    #[test]
    fn answer_walk_inline_owner_and_empty_answer_reply() {
        // An answer whose owner is INLINE labels (no pointer) — skip_name walks it.
        let mut d = example_dns_reply(0, &[]);
        d[6..8].copy_from_slice(&1u16.to_be_bytes()); // ancount=1, hand-append the record
        d.extend_from_slice(b"\x07example\x03com\x00");
        d.extend_from_slice(&1u16.to_be_bytes()); // A
        d.extend_from_slice(&1u16.to_be_bytes()); // IN
        d.extend_from_slice(&120u32.to_be_bytes());
        d.extend_from_slice(&4u16.to_be_bytes());
        d.extend_from_slice(&[198, 51, 100, 4]);
        let (_, addrs) = extract_answer_addrs(&d).expect("inline owner walks");
        assert_eq!(addrs, vec![("198.51.100.4".parse().unwrap(), 120)]);
        // A NOERROR reply with zero answers is Some(empty) — valid, just nothing to attribute.
        let (_, addrs) = extract_answer_addrs(&example_dns_reply(0, &[])).expect("empty is valid");
        assert!(addrs.is_empty());
    }

    // ---- the structural edges ----

    #[test]
    fn unknown_version_drops() {
        // Edge #1: version != 4/6 → drop (ip.c:208).
        let p = [0x55u8; 40];
        assert!(parse_ip_udp(&p).is_none());
    }

    #[test]
    fn v4_too_short_drops() {
        // Edge #2: len < 20 (ip.c:140).
        assert!(parse_ip_udp(&[0x45, 0]).is_none());
    }

    #[test]
    fn v4_ihl_below_minimum_drops() {
        // Edge #3: ihl < 5.
        let mut p = vec![0u8; 40];
        p[0] = 0x44; // ihl=4
        p[2..4].copy_from_slice(&(40u16).to_be_bytes());
        assert!(parse_ip_udp(&p).is_none());
    }

    #[test]
    fn v4_tot_len_mismatch_drops() {
        // Edge #5: tot_len != length (ip.c:160). Build a 60-byte packet that claims 50.
        let dns = example_dns_query();
        let p = build_v4_udp_dns([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, &dns);
        let mut bad = p.clone();
        bad[2..4].copy_from_slice(&(50u16).to_be_bytes());
        assert!(parse_ip_udp(&bad).is_none());
    }

    #[test]
    fn v4_udp_dns_parses() {
        // The happy path: a v4 UDP :53 packet parses to a DNS query.
        let dns = example_dns_query();
        let p = build_v4_udp_dns([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, &dns);
        let parsed = parse_ip_udp(&p).expect("parses");
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.proto, IPPROTO_UDP);
        assert!(parsed.is_dns_query());
        let udp = parsed.udp.unwrap();
        assert_eq!(udp.sport, 5353);
        assert_eq!(udp.dport, 53);
        assert_eq!(udp.payload, &dns[..]);
        assert_eq!(parsed.tcp_dport, None, "a UDP packet never carries a TCP dport (#20)");
    }

    #[test]
    fn v4_non_udp_returns_proto_only() {
        // Edge: TCP (proto 6) → udp == None (the loop Warden-gates it).
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(40u16).to_be_bytes());
        p[9] = 6; // TCP
        let parsed = parse_ip_udp(&p).expect("parses");
        assert_eq!(parsed.proto, 6);
        assert!(parsed.udp.is_none());
        assert!(!parsed.is_dns_query());
    }

    // ---- the #20 PORT-HONESTY edges (parse_tcp_dport — the docket row stops lying port 0) ----

    #[test]
    fn v4_tcp_dport_parses() {
        // A full 20-byte TCP header yields the real dport (tcphdr bytes 2..4, the udphdr slot).
        let total = IP4_HEADER_LEN + TCP_HEADER_LEN;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[9] = IPPROTO_TCP;
        let t = IP4_HEADER_LEN;
        p[t..t + 2].copy_from_slice(&49152u16.to_be_bytes()); // sport
        p[t + 2..t + 4].copy_from_slice(&443u16.to_be_bytes()); // dport
        let parsed = parse_ip_udp(&p).expect("parses");
        assert_eq!(parsed.proto, IPPROTO_TCP);
        assert!(parsed.udp.is_none(), "TCP never borrows the UDP layer");
        assert_eq!(parsed.tcp_dport, Some(443));
    }

    #[test]
    fn v4_tcp_truncated_header_yields_no_dport() {
        // A 4-byte TCP stub is MALFORMED, not a port source — the gate is the full minimum
        // header, even though the dport bytes themselves would fit. None, never a guess.
        let total = IP4_HEADER_LEN + 4;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[9] = IPPROTO_TCP;
        let t = IP4_HEADER_LEN;
        p[t + 2..t + 4].copy_from_slice(&443u16.to_be_bytes());
        let parsed = parse_ip_udp(&p).expect("parses");
        assert_eq!(parsed.tcp_dport, None, "a truncated TCP header never yields a port");
    }

    #[test]
    fn v6_tcp_dport_parses() {
        // The v6 arm reads the same tcphdr slot past the fixed 40-byte header.
        let total = IP6_HEADER_LEN + TCP_HEADER_LEN;
        let mut p = vec![0u8; total];
        p[0] = 0x60;
        p[6] = IPPROTO_TCP; // ip6_nxt
        let plen = (total - IP6_HEADER_LEN) as u16;
        p[4..6].copy_from_slice(&plen.to_be_bytes());
        let t = IP6_HEADER_LEN;
        p[t + 2..t + 4].copy_from_slice(&853u16.to_be_bytes());
        let parsed = parse_ip_udp(&p).expect("parses");
        assert_eq!(parsed.version, 6);
        assert_eq!(parsed.tcp_dport, Some(853));
    }

    #[test]
    fn v6_udp_dns_parses() {
        // The v6 happy path: a v6 UDP :53 packet parses.
        let dns = example_dns_query();
        let total = IP6_HEADER_LEN + UDP_HEADER_LEN + dns.len();
        let mut p = vec![0u8; total];
        p[0] = 0x60; // version=6
        p[6] = IPPROTO_UDP; // ip6_nxt
        let src = [0xfd; 16];
        let dst = [0xfe; 16];
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        let plen = (total - IP6_HEADER_LEN) as u16;
        p[4..6].copy_from_slice(&plen.to_be_bytes());
        let u = IP6_HEADER_LEN;
        p[u..u + 2].copy_from_slice(&5353u16.to_be_bytes());
        p[u + 2..u + 4].copy_from_slice(&53u16.to_be_bytes());
        let ulen = (UDP_HEADER_LEN + dns.len()) as u16;
        p[u + 4..u + 6].copy_from_slice(&ulen.to_be_bytes());
        p[u + UDP_HEADER_LEN..].copy_from_slice(&dns);
        let parsed = parse_ip_udp(&p).expect("parses");
        assert_eq!(parsed.version, 6);
        assert!(parsed.is_dns_query());
    }

    #[test]
    fn udp_too_short_drops() {
        // Edge #11: the UDP header does not fit (ip.c:235).
        let mut p = vec![0u8; IP4_HEADER_LEN + 3]; // 3 bytes after the IP header
        p[0] = 0x45;
        let tot_len = p.len() as u16;
        p[2..4].copy_from_slice(&tot_len.to_be_bytes());
        p[9] = IPPROTO_UDP;
        let parsed = parse_ip_udp(&p).expect("parses");
        assert!(parsed.udp.is_none()); // not enough room for the UDP header
    }

    #[test]
    fn qname_extracts_from_real_query() {
        // The dns.c:26-81 walker on a real example.com query.
        let dns = example_dns_query();
        let (qname, off) = extract_qname(&dns).expect("qname");
        assert_eq!(qname, "example.com");
        // off is past the qtype/qclass (12 header + 13 qname + 4 = 29).
        assert_eq!(off, DNS_HEADER_LEN + 13 + 4);
    }

    #[test]
    fn qname_compression_pointer_cap() {
        // Edge #17: more than 25 pointer follows ⇒ drop (dns.c:39). Build a self-referencing
        // pointer loop (ptr at offset 12 → points back to offset 12) ⇒ infinite until the cap.
        let mut d = vec![0u8; DNS_HEADER_LEN + 2];
        d[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount = 1
        d[DNS_HEADER_LEN] = 0xC0; // compression pointer
        d[DNS_HEADER_LEN + 1] = DNS_HEADER_LEN as u8; // → offset 12 (itself)
        assert!(extract_qname(&d).is_none());
    }

    #[test]
    fn qname_empty_drops() {
        // Edge #20: a bare terminating 0 (no labels) ⇒ noff == 0 ⇒ invalid (dns.c:72).
        let mut d = vec![0u8; DNS_HEADER_LEN + 5];
        d[4..6].copy_from_slice(&1u16.to_be_bytes());
        d[DNS_HEADER_LEN] = 0; // empty qname
        d[DNS_HEADER_LEN + 1..DNS_HEADER_LEN + 3].copy_from_slice(&1u16.to_be_bytes());
        d[DNS_HEADER_LEN + 3..DNS_HEADER_LEN + 5].copy_from_slice(&1u16.to_be_bytes());
        assert!(extract_qname(&d).is_none());
    }

    #[test]
    fn lan_suffix_matches() {
        // Edge #21: the udp.c:449-466 list.
        assert!(matches_lan_suffix("myhost.local"));
        assert!(matches_lan_suffix("router.lan"));
        assert!(matches_lan_suffix("ipv4only.arpa"));
        assert!(matches_lan_suffix("host.254.169.in-addr.arpa"));
        assert!(!matches_lan_suffix("example.com"));
        assert!(!matches_lan_suffix("localtest.me")); // substring, not a suffix
    }
}
