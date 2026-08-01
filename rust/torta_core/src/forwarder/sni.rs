/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! ★ #66-A — the SNI PEEK: recover the hostname the DNS-plane cloak collapsed away.
//!
//! ## Why this exists (the seam it closes)
//! The Centauri cloak answers EVERY watched-CDN host with the SAME sentinel address
//! (`resolver::local::CLOAK_SENTINEL_V4` `10.1.10.3` — one IP for all ~43 watched hosts), so by the time
//! a flow reaches [`super::run::forward_tcp`] the destination hostname is GONE: the 5-tuple carries only
//! `10.1.10.3:443`. The mirror cannot serve an asset it cannot name, and the forwarder cannot splice to a
//! real CDN it cannot resolve.
//!
//! A TLS ClientHello, however, still carries the name in its `server_name` extension (RFC 6066 §3). This
//! module parses THAT — a pure, allocation-light, bounds-checked reader over bytes the flow was going to
//! send anyway — and hands back the hostname. Nothing here does IO, so it is host-testable on every
//! platform (the `session`/`shape` discipline: cross-platform pure logic, `#[cfg(unix)]` stays on the
//! runtime arms in `run.rs`).
//!
//! ## Privacy posture (T20)
//! The parsed hostname is a FLOW-LOCAL routing decision — it is handed to the caller and dropped. It is
//! never logged, never counted per-name, never persisted. The forwarder telemetry this feeds
//! (`centauri_sni_peeked` / `centauri_spliced`) is COUNTS-ONLY, exactly like every other
//! [`crate::tunnel::ForwarderStats`] field.
//!
//! ## Robustness law
//! `#![forbid(unsafe_code)]` and every read is length-checked through [`Cursor`] — a truncated, hostile,
//! or simply non-TLS first flight can only ever produce [`SniOutcome::NotTls`] or
//! [`SniOutcome::Incomplete`], NEVER a panic and never an out-of-bounds read. A forwarder that panics on
//! a malformed first packet would tear a user's connection; this returns a verdict instead.

#![forbid(unsafe_code)]

/// TLS `ContentType::handshake` (RFC 8446 §5.1) — the first byte of a ClientHello record.
const CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// TLS `HandshakeType::client_hello` (RFC 8446 §4) — the first byte of the handshake body.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// `ExtensionType::server_name` (RFC 6066 §3) — the extension carrying the SNI.
const EXTENSION_SERVER_NAME: u16 = 0;

/// `NameType::host_name` (RFC 6066 §3) — the only ServerName variant ever defined.
const NAME_TYPE_HOST_NAME: u8 = 0;

/// The TLS record header: content type (1) + legacy version (2) + length (2).
const RECORD_HEADER_LEN: usize = 5;

/// The ClientHello `random` field (RFC 8446 §4.1.2) — fixed 32 bytes, skipped wholesale.
const CLIENT_HELLO_RANDOM_LEN: usize = 32;

/// The largest first-flight we will ever buffer while waiting for a complete ClientHello. A real
/// ClientHello (even with a post-quantum key share and a long ALPN list) is well under 4 KiB; TLS caps a
/// single record's fragment at 2^14. This bound is what stops a hostile or broken peer from making the
/// forwarder buffer without limit — hit it and the flow is [`SniOutcome::NotTls`] (spliced blind, never
/// held open).
pub(crate) const MAX_CLIENT_HELLO_PEEK: usize = 8 * 1024;

/// The verdict of one [`peek_sni`] pass over the bytes read from a flow so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SniOutcome {
    /// A complete ClientHello carrying a `server_name` extension. The payload is the lowercased
    /// host name, ready to hand to the catalog lookup or the uncloaked address resolve.
    Found(String),
    /// The bytes so far ARE a well-formed prefix of a TLS ClientHello, but the record is not complete
    /// yet — the caller should read more (up to [`MAX_CLIENT_HELLO_PEEK`]) and re-parse.
    Incomplete,
    /// The bytes are not a TLS ClientHello at all (a plain-HTTP request, a raw protocol, garbage), or
    /// they are a complete ClientHello with NO `server_name` extension. Either way there is no name to
    /// route by: the caller must fall back to its no-name path rather than hold the flow open.
    NotTls,
}

/// A bounds-checked forward reader. Every accessor returns `Option`, so a truncated buffer degrades to
/// `None` (→ [`SniOutcome::Incomplete`]) instead of panicking. This is the ONLY way this module touches
/// the byte slice.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    /// Remaining unread bytes.
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Take exactly `n` bytes, advancing the cursor. `None` if fewer than `n` remain.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    /// Advance `n` bytes without reading them. `None` if fewer than `n` remain.
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }

    /// A 24-bit big-endian length (the TLS handshake body length).
    fn u24(&mut self) -> Option<u32> {
        self.take(3)
            .map(|s| u32::from_be_bytes([0, s[0], s[1], s[2]]))
    }

    /// Take a `u8`-length-prefixed vector's BODY (the length byte is consumed too).
    fn skip_u8_vec(&mut self) -> Option<()> {
        let n = self.u8()? as usize;
        self.skip(n)
    }

    /// Take a `u16`-length-prefixed vector's BODY (the length pair is consumed too).
    fn skip_u16_vec(&mut self) -> Option<()> {
        let n = self.u16()? as usize;
        self.skip(n)
    }
}

/// Parse the SNI host name out of the first bytes of a TCP flow.
///
/// This is a PEEK in the semantic sense — it never consumes from the socket, it only reads a buffer the
/// caller already owns and will still forward verbatim. The caller's contract is:
///
/// 1. read some bytes from the client into a growing buffer,
/// 2. call this,
/// 3. on [`SniOutcome::Incomplete`] read more (bounded by [`MAX_CLIENT_HELLO_PEEK`]) and repeat,
/// 4. on [`SniOutcome::Found`] / [`SniOutcome::NotTls`] route the flow — and replay the WHOLE buffer to
///    whichever upstream it picked, so the peek is byte-transparent to both peers.
///
/// Returns [`SniOutcome::NotTls`] for anything that is not a handshake record or not a ClientHello (a
/// plain HTTP `GET`, an SSH banner, random bytes), and for a complete ClientHello that simply carries no
/// `server_name` extension. Returns [`SniOutcome::Incomplete`] only when what we have so far is a valid
/// PREFIX — that is the single case where reading more can change the answer.
pub(crate) fn peek_sni(buf: &[u8]) -> SniOutcome {
    // --- TLS record header: is this even a handshake record? -------------------------------------
    let Some(&first) = buf.first() else {
        return SniOutcome::Incomplete; // nothing yet — a read of 0 is not a verdict
    };
    if first != CONTENT_TYPE_HANDSHAKE {
        // A plain-HTTP request, or any non-TLS protocol. Decided on ONE byte: the common `:80` case
        // never pays for a parse attempt.
        return SniOutcome::NotTls;
    }
    if buf.len() < RECORD_HEADER_LEN {
        return SniOutcome::Incomplete;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = RECORD_HEADER_LEN + record_len;
    if buf.len() < record_end {
        // The ClientHello record is still arriving. (A ClientHello split ACROSS records is legal but
        // vanishingly rare in practice; if one ever appears its second record is simply never parsed and
        // the flow falls back to the blind splice — correct, just un-named.)
        return SniOutcome::Incomplete;
    }

    // --- Handshake header: ClientHello, and is its body complete? -------------------------------
    let mut c = Cursor::new(&buf[RECORD_HEADER_LEN..record_end]);
    let Some(handshake_type) = c.u8() else {
        return SniOutcome::Incomplete;
    };
    if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return SniOutcome::NotTls; // a handshake record, but not the one that carries SNI
    }
    let Some(body_len) = c.u24() else {
        return SniOutcome::Incomplete;
    };
    if c.remaining() < body_len as usize {
        return SniOutcome::Incomplete;
    }

    // --- ClientHello body: walk to the extensions ------------------------------------------------
    // Every step below is `?`-guarded: a truncated body yields `None` → Incomplete, never a panic.
    match parse_client_hello_body(&mut c) {
        Some(Some(host)) => SniOutcome::Found(host),
        // Parsed cleanly to the end of the extensions, but no server_name was present. Reading more
        // bytes cannot conjure one — this is a terminal verdict, not Incomplete.
        Some(None) => SniOutcome::NotTls,
        None => SniOutcome::Incomplete,
    }
}

/// Walk a ClientHello body and return `Some(Some(host))` if a `server_name` extension was found,
/// `Some(None)` if the body parsed completely with no SNI, and `None` if the body was truncated.
fn parse_client_hello_body(c: &mut Cursor<'_>) -> Option<Option<String>> {
    c.skip(2)?; // legacy_version
    c.skip(CLIENT_HELLO_RANDOM_LEN)?; // random
    c.skip_u8_vec()?; // legacy_session_id
    c.skip_u16_vec()?; // cipher_suites
    c.skip_u8_vec()?; // legacy_compression_methods

    // Extensions are OPTIONAL in the wire format (an SSLv3-era hello has none). Absent ⇒ no SNI, but
    // the body did parse: a terminal "no name here".
    if c.remaining() == 0 {
        return Some(None);
    }
    let ext_total = c.u16()? as usize;
    let ext_block = c.take(ext_total)?;

    let mut e = Cursor::new(ext_block);
    while e.remaining() > 0 {
        let ext_type = e.u16()?;
        let ext_len = e.u16()? as usize;
        let ext_body = e.take(ext_len)?;
        if ext_type == EXTENSION_SERVER_NAME {
            // A malformed server_name extension is treated as "no name" rather than a truncation: the
            // extension WAS present and complete, it just did not yield a host_name.
            return Some(parse_server_name_extension(ext_body));
        }
    }
    Some(None)
}

/// Parse the `server_name` extension body (RFC 6066 §3) → the first `host_name` entry, lowercased.
///
/// The list may in principle hold several entries; RFC 6066 allows at most one per NameType and every
/// real client sends exactly one `host_name`. We take the FIRST `host_name` and ignore the rest.
fn parse_server_name_extension(body: &[u8]) -> Option<String> {
    let mut c = Cursor::new(body);
    let list_len = c.u16()? as usize;
    let list = c.take(list_len)?;

    let mut l = Cursor::new(list);
    while l.remaining() > 0 {
        let name_type = l.u8()?;
        let name_len = l.u16()? as usize;
        let name = l.take(name_len)?;
        if name_type == NAME_TYPE_HOST_NAME {
            return sanitize_host(name);
        }
    }
    None
}

/// Turn raw `host_name` bytes into a hostname we are willing to route by.
///
/// RFC 6066 requires the value be an ASCII host name (an IDN arrives already punycoded, and a literal IP
/// is explicitly forbidden). We enforce exactly that and lowercase it, so the result drops straight into
/// [`crate::mirror::localcdn::is_cdn_host`] (which expects a lowercase name) and into a DNS query. A
/// value carrying a NUL, a slash, whitespace, or any non-ASCII byte is rejected outright — that is a
/// malformed or hostile hello, and routing on it would be the bug.
fn sanitize_host(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > 253 {
        return None;
    }
    let ok = raw
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    if !ok {
        return None;
    }
    // A leading/trailing dot, or an empty label, is not a routable name.
    let s = String::from_utf8(raw.to_vec()).ok()?.to_ascii_lowercase();
    if s.starts_with('.') || s.ends_with('.') || s.contains("..") {
        return None;
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but WIRE-VALID ClientHello carrying `host` in its server_name extension. This is
    /// the fixture every positive test rides — if the builder drifts from the parser, the tests below
    /// stop proving anything, so it is written to the RFC layout, not to the parser's expectations.
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let mut ext_body = Vec::new();
        // ServerNameList: u16 list length, then one entry {u8 type, u16 len, bytes}
        let entry_len = 1 + 2 + host.len();
        ext_body.extend_from_slice(&(entry_len as u16).to_be_bytes());
        ext_body.push(NAME_TYPE_HOST_NAME);
        ext_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(host.as_bytes());

        let mut exts = Vec::new();
        exts.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);

        client_hello_with_extension_block(&exts)
    }

    /// The same fixture, but with a caller-supplied extensions block (possibly empty / possibly holding
    /// other extension types).
    fn client_hello_with_extension_block(exts: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        body.extend_from_slice(&[0xAB; CLIENT_HELLO_RANDOM_LEN]); // random
        body.push(0); // legacy_session_id: empty
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites: one suite
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression_methods: one
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(exts);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let len = body.len() as u32;
        handshake.extend_from_slice(&len.to_be_bytes()[1..]); // u24
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // legacy record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// The load-bearing case: a real watched-CDN name is recovered from the hello. This is the whole
    /// reason the module exists — the DNS cloak collapsed this name into `10.1.10.3`.
    #[test]
    fn recovers_the_sni_host() {
        let hello = client_hello_with_sni("ajax.googleapis.com");
        assert_eq!(
            peek_sni(&hello),
            SniOutcome::Found("ajax.googleapis.com".to_string())
        );
    }

    /// An uppercase SNI (legal on the wire) must normalize, because `is_cdn_host` and the DNS query
    /// path both expect a lowercase name.
    #[test]
    fn lowercases_the_host() {
        let hello = client_hello_with_sni("AJAX.GoogleAPIs.CoM");
        assert_eq!(
            peek_sni(&hello),
            SniOutcome::Found("ajax.googleapis.com".to_string())
        );
    }

    /// EVERY prefix of a valid hello must read as Incomplete — never NotTls, never a panic. This is the
    /// property that makes the caller's read-more loop correct: a short read can only ever mean "keep
    /// reading", so the forwarder never mis-routes a flow it simply had not finished receiving.
    #[test]
    fn every_prefix_is_incomplete_never_a_panic() {
        let hello = client_hello_with_sni("cdnjs.cloudflare.com");
        for n in 1..hello.len() {
            assert_eq!(
                peek_sni(&hello[..n]),
                SniOutcome::Incomplete,
                "prefix of length {n} must be Incomplete, not a verdict"
            );
        }
        assert_eq!(
            peek_sni(&hello),
            SniOutcome::Found("cdnjs.cloudflare.com".to_string())
        );
    }

    /// A plain-HTTP first flight is rejected on its FIRST byte — the `:80` hairpin path must never pay
    /// for a TLS parse, and must never be held open waiting for more bytes.
    #[test]
    fn plain_http_is_not_tls() {
        assert_eq!(
            peek_sni(b"GET /jquery.min.js HTTP/1.1\r\n"),
            SniOutcome::NotTls
        );
    }

    /// A complete ClientHello with NO server_name is terminal (NotTls), NOT Incomplete: reading more
    /// bytes can never produce a name, so the caller must fall through to its blind-splice path
    /// immediately instead of stalling the flow until timeout.
    #[test]
    fn hello_without_sni_is_terminal_not_incomplete() {
        let hello = client_hello_with_extension_block(&[]);
        assert_eq!(peek_sni(&hello), SniOutcome::NotTls);
    }

    /// An unrelated extension before server_name must be walked over, not mistaken for it.
    #[test]
    fn skips_other_extensions_to_find_server_name() {
        let mut exts = Vec::new();
        // A dummy extension (type 0x000A supported_groups) with a 4-byte body.
        exts.extend_from_slice(&0x000Au16.to_be_bytes());
        exts.extend_from_slice(&4u16.to_be_bytes());
        exts.extend_from_slice(&[0, 2, 0, 23]);
        // Then the real server_name.
        let host = "fonts.gstatic.com";
        let mut ext_body = Vec::new();
        ext_body.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
        ext_body.push(NAME_TYPE_HOST_NAME);
        ext_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(host.as_bytes());
        exts.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);

        let hello = client_hello_with_extension_block(&exts);
        assert_eq!(
            peek_sni(&hello),
            SniOutcome::Found("fonts.gstatic.com".to_string())
        );
    }

    /// A hostile host_name (path traversal / injection shapes / non-ASCII) is refused rather than
    /// routed on. A name that reaches the resolver or the catalog must already be a plain hostname.
    #[test]
    fn refuses_a_hostile_host_name() {
        for bad in [
            "a/../b",
            "host name",
            "hö.st",
            "sub..host",
            ".leading",
            "trailing.",
        ] {
            let hello = client_hello_with_sni(bad);
            assert_eq!(
                peek_sni(&hello),
                SniOutcome::NotTls,
                "{bad:?} must not be routable"
            );
        }
    }

    /// A truncated / malformed record must never panic, whatever the bytes. Cheap fuzz over shapes that
    /// have historically broken hand-rolled TLS peekers.
    #[test]
    fn malformed_records_never_panic() {
        let cases: Vec<Vec<u8>> = vec![
            vec![CONTENT_TYPE_HANDSHAKE],
            vec![CONTENT_TYPE_HANDSHAKE, 3, 1],
            vec![CONTENT_TYPE_HANDSHAKE, 3, 1, 0xFF, 0xFF],
            vec![CONTENT_TYPE_HANDSHAKE, 3, 1, 0, 4, 1, 0xFF, 0xFF, 0xFF],
            vec![
                CONTENT_TYPE_HANDSHAKE,
                3,
                1,
                0,
                1,
                HANDSHAKE_TYPE_CLIENT_HELLO,
            ],
            vec![0; 64],
        ];
        for c in cases {
            let _ = peek_sni(&c); // must simply return
        }
    }
}
