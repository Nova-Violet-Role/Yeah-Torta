/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Plain Do53 (RFC 1035) transport — **loopback-only, SHADOW-only**.
//!
//! This is the deliberate exception to the encrypted-only invariant (T13): it carries no channel
//! security at all, so it MUST only ever target a trusted **loopback** listener — specifically the
//! app's own `dnscrypt-proxy` plaintext listener at `127.0.0.1:<dnsCryptPort>` (the same listener the
//! native tun forwarder redirects user DNS to). It exists for exactly one reason: the P7 Wave-3
//! Stage-0 shadow (`ResolverRuntime`) needs to validate the in-app Rust resolver against the **real
//! upstream the user actually resolves through** — not some public third-party resolver.
//!
//! Why loopback is the right (and safe) seam:
//!   * **No VPN loop.** Loopback (`127.0.0.0/8`, `::1`) traffic never enters the VpnService tun device,
//!     so the socket needs no `VpnService.protect()` — unlike a public-resolver socket, which an active
//!     VPN would route back through our own tun (the egress-loop gotcha). A public-DNSCrypt shadow on a
//!     phone-in-VPN-mode is broken by construction; this loopback shadow is not.
//!   * **It validates THIS proxy.** The plaintext byte we read back from `127.0.0.1:5354` is the answer
//!     `dnscrypt-proxy` produced from the user's *encrypted* upstream — so the shadow compares the Rust
//!     resolver against the exact answer the user received, the genuine Stage-0 claim.
//!   * **The channel is already trusted.** The plaintext hop is host-local only; the upstream encryption
//!     happened inside `dnscrypt-proxy` before it ever reached this loopback socket. T13 is about
//!     *off-host* cleartext; a host-local loopback hop to our own proxy is not that.
//!
//! A `LoopbackGuard` rejects construction for any non-loopback address, so this transport can NEVER be
//! pointed at a remote resolver even by a malformed config. No qname is ever logged (T20); the response
//! read is bounded at 64 KiB (T6); the TC bit drives a TCP fallback (RFC 7766).

use std::net::{IpAddr, SocketAddr};

use super::transport::{ExchangeFuture, Transport, TransportError};

/// T6 — never read more than 64 KiB of a Do53 reply (a DNS message tops out near the EDNS0 buffer).
const MAX_RESPONSE: usize = 64 * 1024;

/// A plain Do53 transport pinned to a single **loopback** resolver address. Cheap to clone-share via
/// `Arc`; each `exchange` binds its own ephemeral socket (no shared connection state).
pub struct Do53 {
    id: String,
    addr: SocketAddr,
}

impl Do53 {
    /// Build a Do53 transport for `addr` (e.g. `127.0.0.1:5354`). Fails if `addr` is unparseable OR is
    /// **not a loopback address** — the loopback guard is a hard invariant (a non-loopback plaintext
    /// resolver would be both a T13 cleartext violation and a VPN egress loop). `id` is the stats label.
    pub fn new(id: &str, addr: &str) -> Result<Self, TransportError> {
        let parsed: SocketAddr = addr
            .parse()
            .map_err(|e| TransportError::Connect(format!("bad do53 addr: {e}")))?;
        if !is_loopback(&parsed.ip()) {
            // Refuse to ever speak plaintext to anything but our own host. This is what makes a Do53
            // transport safe to compile into a privacy app: it is structurally loopback-only.
            return Err(TransportError::Connect(
                "do53 transport is loopback-only".into(),
            ));
        }
        Ok(Do53 {
            id: id.to_string(),
            addr: parsed,
        })
    }
}

/// Loopback test for both families: `127.0.0.0/8` (v4) and `::1` (v6). Pure, never allocates.
fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

impl Transport for Do53 {
    fn id(&self) -> &str {
        &self.id
    }

    /// ★ CP-Attribution — plain Do53 is cleartext UDP (loopback-only here); it shares the UDP family
    /// with DNSCrypt for the Beast's dual-line attribution.
    fn is_udp_family(&self) -> bool {
        true
    }

    fn exchange<'a>(&'a self, query_wire: &'a [u8]) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let reply = udp_exchange(&self.addr, query_wire).await?;
            // TC (truncation) set on this plaintext DNS reply ⇒ retry over TCP for the full message.
            if reply.len() >= 3 && (reply[2] & 0x02) != 0 {
                return tcp_exchange(&self.addr, query_wire).await;
            }
            Ok(reply)
        })
    }

    /// ★ E-FIX r5 — the ONE loopback-proxy transport: Do53 is loopback-BY-CONSTRUCTION (`new`
    /// hard-rejects any non-loopback addr), and its only production target is the app's own Go
    /// `dnscrypt-proxy` listener (the MODE-1 fallback) — whose answers the Go writer logs itself,
    /// so the Rust query-feed skips them (`query_feed::feed_status`).
    fn is_loopback_proxy(&self) -> bool {
        true
    }
}

/// One UDP request/response against a loopback resolver. Binds an ephemeral local socket, `connect`s to
/// pin the peer (so a stray datagram from another source is dropped by the OS), sends, reads one
/// datagram bounded at 64 KiB (T6). No qname logged (T20).
async fn udp_exchange(addr: &SocketAddr, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    use tokio::net::UdpSocket;
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::1]:0".parse().unwrap()
    } else {
        "127.0.0.1:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| TransportError::Connect(format!("udp bind: {e}")))?;
    sock.connect(addr)
        .await
        .map_err(|e| TransportError::Connect(format!("udp connect: {e}")))?;
    sock.send(payload)
        .await
        .map_err(|e| TransportError::Exchange(format!("udp send: {e}")))?;
    let mut buf = vec![0u8; MAX_RESPONSE];
    let n = sock
        .recv(&mut buf)
        .await
        .map_err(|e| TransportError::Exchange(format!("udp recv: {e}")))?;
    buf.truncate(n);
    Ok(buf)
}

/// One DNS-over-TCP request/response (2-byte big-endian length prefix on request and reply, RFC 7766).
/// The reply length prefix is bounded at 64 KiB (T6) before allocating. No qname logged (T20).
async fn tcp_exchange(addr: &SocketAddr, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| TransportError::Connect(format!("tcp connect: {e}")))?;

    let len = u16::try_from(payload.len())
        .map_err(|_| TransportError::Exchange("tcp payload > 64KiB".into()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| TransportError::Exchange(format!("tcp write len: {e}")))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| TransportError::Exchange(format!("tcp write: {e}")))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| TransportError::Exchange(format!("tcp read len: {e}")))?;
    let reply_len = u16::from_be_bytes(len_buf) as usize;
    if reply_len == 0 || reply_len > MAX_RESPONSE {
        return Err(TransportError::BadResponse(
            "tcp reply length out of bounds".into(),
        ));
    }
    let mut buf = vec![0u8; reply_len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| TransportError::Exchange(format!("tcp read: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ipv4_loopback() {
        let t = Do53::new("do53:local", "127.0.0.1:5354").expect("loopback v4 must build");
        assert_eq!(t.id(), "do53:local");
        assert_eq!(t.addr, "127.0.0.1:5354".parse().unwrap());
        // ★ E-FIX r5 — Do53 IS the loopback Go-proxy arm (the query-feed no-double-count marker).
        assert!(t.is_loopback_proxy());
    }

    #[test]
    fn accepts_ipv6_loopback() {
        assert!(Do53::new("do53:local6", "[::1]:5354").is_ok());
    }

    #[test]
    fn rejects_non_loopback_address() {
        // The whole safety story: a Do53 transport can NEVER be pointed off-host, even by config.
        assert!(Do53::new("do53:bad", "9.9.9.9:53").is_err());
        assert!(Do53::new("do53:bad", "192.168.1.1:53").is_err());
        assert!(Do53::new("do53:bad6", "[2606:4700:4700::1111]:53").is_err());
    }

    #[test]
    fn rejects_unparseable_address() {
        assert!(Do53::new("do53:bad", "not-an-addr").is_err());
        assert!(Do53::new("do53:bad", "127.0.0.1").is_err()); // missing port
    }
}
