/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! The transport abstraction — a dumb pipe for opaque DNS wire bytes.
//!
//! A `Transport` authenticates the CHANNEL (TLS / QUIC / DNSCrypt AEAD). It does NOT understand DNS:
//! it takes a wire-format query and returns wire-format response bytes, and `dns::validate_response`
//! authenticates the ANSWER afterward. This separation is the security spine — a transport that is
//! tricked into returning poisoned bytes still can't get them past `validate_response`.
//!
//! Wave 2b ships exactly one implementor: [`super::doh::Http2Doh`]. Wave 2c adds DoH3/DoQ, 2d
//! DNSCrypt — each a new `Transport`, no resolver changes.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

/// What can go wrong on the wire. Kept small and `Copy`-ish; the resolver maps every variant to the
/// same "fall through to dnscrypt-proxy" outcome (null to Kotlin), so the value is for stats/logging
/// — never a qname (T20: no qname in logs at default verbosity).
#[derive(Debug)]
pub enum TransportError {
    /// TLS handshake / connection setup failed (cert rejected, network down, DNS bootstrap failed).
    Connect(String),
    /// The HTTP/transport exchange itself failed mid-flight.
    Exchange(String),
    /// The upstream returned a non-2xx status (DoH) or an oversized body (> 64 KiB cap, T6).
    BadResponse(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Connect(m) => write!(f, "connect: {m}"),
            TransportError::Exchange(m) => write!(f, "exchange: {m}"),
            TransportError::BadResponse(m) => write!(f, "bad-response: {m}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// A boxed, `Send` future — lets [`Transport`] be object-safe (`dyn Transport`) without `async fn`
/// in traits forcing a concrete return type on every impl.
pub type ExchangeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, TransportError>> + Send + 'a>>;

/// A boxed, `Send`, infallible future for [`Transport::warm_setup`] — best-effort by contract
/// (`()` output: a setup fault is surfaced by the timed `exchange` right after, never here).
pub type WarmFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// One encrypted DNS transport. `exchange` sends opaque `query_wire` bytes and resolves to opaque
/// response bytes; it MUST NOT parse, cache, or validate — that is the resolver's job.
pub trait Transport: Send + Sync {
    /// Stable identifier of the configured upstream (for stats), e.g. `"doh:cloudflare"`.
    fn id(&self) -> &str;

    /// Round-trip one DNS message. Returns the raw response bytes or a [`TransportError`].
    fn exchange<'a>(&'a self, query_wire: &'a [u8]) -> ExchangeFuture<'a>;

    /// ★ 2.1.18-absorb (measurement honesty) — perform any one-time SETUP work (certificate
    /// fetch/verify, session establishment) OUTSIDE the pool's RTT stopwatch. The pool awaits this
    /// (bounded by the per-query timeout, UNTIMED for the EWMA) immediately before every timed
    /// `exchange`, so a transport whose first exchange lazily pays a setup round-trip does not
    /// poison its EWMA **seed** with setup latency (`TransportStats::observe` seeds on the FIRST
    /// sample — a poisoned seed misprices the transport for its whole life, and rotation ranking
    /// consumes these EWMAs). Mirrors upstream dnscrypt-proxy 2.1.18: "resolver latency
    /// measurements no longer include setup or certificate-transfer time". Best-effort by
    /// contract: MUST be a fast no-op when already warm, MUST swallow its own errors (the timed
    /// exchange surfaces + records any real failure as the loss sample). Default: ready no-op;
    /// only [`super::dnscrypt::DnsCrypt`] (lazy cert fetch) overrides.
    fn warm_setup<'a>(&'a self) -> WarmFuture<'a> {
        Box::pin(std::future::ready(()))
    }

    /// ★ E-FIX r5 — does this transport hop through the app's OWN loopback Go `dnscrypt-proxy`
    /// listener (the MODE-1 fallback arm)? Answers that traverse it are logged by the Go proxy's
    /// own `query.log` writer, so the Rust query-feed must NOT double-log them
    /// (`query_feed::feed_status` — the no-double-count law). Default `false`; only the
    /// loopback-only plain-Do53 arm overrides to `true` (it is loopback-BY-CONSTRUCTION:
    /// `Do53::new` hard-rejects any non-loopback address).
    fn is_loopback_proxy(&self) -> bool {
        false
    }

    /// ★ CP-Attribution — does this transport ride the connectionless UDP datapath (DNSCrypt / plain
    /// Do53)? The Beast tracks a SEPARATE `udp_base_rtt` + true-min floor for the UDP family (the
    /// dual-line dashboard, `beast/mod.rs:155-163`); the host governor routes a UDP-family winner's
    /// live-forward RTT to `Beast::apply_udp_samples`, and everything else (DoH/DoH3/ODoH over
    /// TLS/QUIC, plus loopback cache-hits) to the shared `apply_samples` door. Declared per-type from
    /// the transport's OWN nature — never parsed from the caller-set `id()` string (the family is a
    /// property of the wire, not the label). Default `false`; only the two cleartext-UDP transports
    /// override to `true`.
    fn is_udp_family(&self) -> bool {
        false
    }

    /// ★ G5 — the friendly NAME of the anonymized-DNSCrypt relay (0x81) this transport egresses
    /// through, for the query.log `relay` column (the anonymization proof, the twin of `id()`'s
    /// server-name attribution). `None` = direct (no relay) or a transport class that can't carry one
    /// (DoH/DoH3/ODoH ride HTTP — no 0x81 lane). Only [`super::dnscrypt::DnsCrypt`] overrides, and only
    /// when a NAMED relay chain is attached: the host slate packs each relay as `name|stamp`
    /// (`conductor::slate_to_specs`), the configure seam splits it, and the first hop names the row.
    fn relay_name(&self) -> Option<&str> {
        None
    }
}
