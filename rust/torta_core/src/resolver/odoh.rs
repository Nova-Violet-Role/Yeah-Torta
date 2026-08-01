/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! ODoH — Oblivious DNS-over-HTTPS (RFC 9230) — the MaskSolver **oblivious lane**.
//!
//! Absorbed from the Windows reference `nautilus-rs/odoh.rs` (a host-side, standalone bolt-on) and
//! FORTIFIED to *surpass* it on three axes:
//!
//!   1. **First-class transport.** ODoH here is a real [`Transport`] — it drops straight into the same
//!      pool / rotation / autopick / query-feed as DoH, DoH3, DoQ and DNSCrypt. Nautilus keeps ODoH as
//!      a separate module the resolver never routes through; ours participates in the datapath.
//!   2. **Config caching + auto-refresh.** The target's `ObliviousDoHConfigContents` (its HPKE public
//!      key) is fetched once, cached with a TTL, and **auto-invalidated + re-fetched on a `401` / empty
//!      reply** (the resolver rotated its key). Nautilus explicitly *defers* the refresh loop
//!      ("CP9 run-harness work") — it never shipped it. We do it inline, per exchange, lock-free on the
//!      hot path.
//!   3. **Obliviousness is VISIBLE.** The relay host is surfaced via [`Transport::relay_name`], so the
//!      `query.log` `relay` column names the oblivious hop — the anonymization proof, the same column
//!      the `0x81` anonymized-DNSCrypt lane uses.
//!
//! HPKE is pure RustCrypto (`odoh-rs` → `hpke 0.13` + `aes-gcm 0.10` + `hkdf 0.12`, all X25519 /
//! HKDF-SHA256 / AES-128-GCM) — **zero aws-lc-rs**, the same cross-compile gate every other transport
//! respects. The CSPRNG for the client ephemeral key rides the exact `getrandom` seam the DNSCrypt
//! nonce trusts ([`super::dnscrypt`]), so no `rand` crate enters the graph.
//!
//! Channel trust is the shared, ring-pinned [`super::tls::client_tls_config`] (Android platform
//! verifier / host `webpki-roots`); `dns::validate_response` still authenticates the ANSWER afterward,
//! so a tricked relay or target can never get poisoned bytes past validation (the security spine).

use std::time::{Duration, Instant};

use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
// odoh-rs / hpke 0.13 bound `encrypt_query` on **rand_core 0.9**'s traits (renamed `rand_core_09` in
// Cargo.toml — the dalek stack's `rand_core 0.6` is a distinct crate in the graph).
use rand_core_09::{CryptoRng, RngCore};
use tokio::sync::Mutex;

use odoh_rs::{
    compose, decrypt_response, encrypt_query, parse, ObliviousDoHConfigContents,
    ObliviousDoHConfigs, ObliviousDoHMessage, ObliviousDoHMessagePlaintext, ODOH_HTTP_HEADER,
};

use super::transport::{ExchangeFuture, Transport, TransportError};

/// RFC 9230 well-known path that serves the target's `ObliviousDoHConfigs` (its HPKE public key set).
const WELL_KNOWN_CONFIGS: &str = "/.well-known/odohconfigs";
/// T6 — never read more than 64 KiB of body (a DNS message tops out near the EDNS0 buffer, and a
/// config blob is far smaller). Identical cap to [`super::doh`].
const MAX_BODY: usize = 64 * 1024;
/// Re-fetch the target config after this even absent a `401` — ODoH resolver keys rotate (Cloudflare
/// rotates roughly daily); an hour keeps us fresh without hammering the well-known endpoint.
const CONFIG_TTL: Duration = Duration::from_secs(3600);

/// A `rand_core` 0.6 CSPRNG backed by the OS entropy pool via `getrandom` — the SAME seam the DNSCrypt
/// client nonce trusts ([`super::dnscrypt`] `csprng_fill`). `odoh-rs::encrypt_query` demands
/// `RngCore + CryptoRng`; we hand it OS randomness directly rather than pull the heavier `rand` crate
/// into the graph. A `getrandom` failure PANICS (matching the ecosystem-standard `rand_core::OsRng`):
/// the ODoH ephemeral key MUST be strong, never a silently-weak zero key.
struct OsCsprng;

impl RngCore for OsCsprng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("OS CSPRNG (getrandom) must not fail for ODoH keying");
    }
    // rand_core 0.9 dropped `try_fill_bytes` from `RngCore` (it moved to the `TryRngCore` trait); the
    // infallible `fill_bytes` above — panicking on unrecoverable OS-entropy failure — is the whole seam.
}

impl CryptoRng for OsCsprng {}

/// A parsed https endpoint split into the pieces the ODoH URL builders need: the authority
/// (`host[:port]`, what the TLS connector dials + SNIs) and the path-and-query (what goes after it).
#[derive(Clone)]
struct Endpoint {
    authority: String,
    path_and_query: String,
}

impl Endpoint {
    /// Parse `url`, enforcing **https** (T13 — encrypted-only is an invariant, never cleartext) and a
    /// present authority. An empty path defaults to `default_path` (targets → `/dns-query`).
    fn parse(url: &str, default_path: &str) -> Result<Self, TransportError> {
        let uri: Uri = url
            .parse()
            .map_err(|e| TransportError::Connect(format!("bad odoh url: {e}")))?;
        if uri.scheme_str() != Some("https") {
            return Err(TransportError::Connect("odoh url must be https".into()));
        }
        let authority = uri
            .authority()
            .map(|a| a.as_str().to_string())
            .ok_or_else(|| TransportError::Connect("odoh url has no host".into()))?;
        let pq = uri
            .path_and_query()
            .map(|x| x.as_str())
            .filter(|s| !s.is_empty() && *s != "/")
            .unwrap_or(default_path)
            .to_string();
        Ok(Endpoint {
            authority,
            path_and_query: pq,
        })
    }

    /// Build a **target** endpoint from either the app's stamp-native form — an `sdns://` ODoH-target
    /// (`0x05`) stamp, exactly how every DNSCrypt server is expressed in the pool — or a bare `https://`
    /// URL (the flat-JSON / test path). Stamp first: a `0x05` stamp decodes to `(host, path)`; anything
    /// else falls through to [`Self::parse`]. The path defaults to `/dns-query` when the stamp omits it.
    fn from_target(s: &str) -> Result<Self, TransportError> {
        if let Some((host, path)) = super::dnscrypt::parse_odoh_target_stamp(s) {
            return Ok(Endpoint {
                authority: host,
                path_and_query: normalize_path(&path, "/dns-query"),
            });
        }
        Endpoint::parse(s, "/dns-query")
    }

    /// Build a **relay** endpoint from either an `sdns://` ODoH-relay (`0x85`) stamp — the form
    /// `odoh-relays.md` ships and the ONLY relay form the flat-JSON `parse_relay_stamps_field` gate
    /// admits (it keeps `sdns://` entries) — or a bare `https://` URL. Stamp first; else [`Self::parse`].
    /// The relay path defaults to `/` when the stamp omits it.
    fn from_relay(s: &str) -> Result<Self, TransportError> {
        if let Some((host, path)) = super::dnscrypt::parse_odoh_relay_stamp(s) {
            return Ok(Endpoint {
                authority: host,
                path_and_query: normalize_path(&path, "/"),
            });
        }
        Endpoint::parse(s, "/")
    }
}

/// Normalize a stamp path into a URL path: empty → `default`; otherwise ensure a single leading `/`.
fn normalize_path(path: &str, default: &str) -> String {
    if path.is_empty() {
        default.to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// The cached target config + when it was fetched. Refreshed on TTL expiry or a `401`/empty reply.
struct CachedConfig {
    contents: ObliviousDoHConfigContents,
    fetched: Instant,
}

/// A configured ODoH upstream. Cheap to `Arc`-share; the inner `Client` pools connections and the
/// config `Mutex` is only ever held for micro-durations (never across a network await).
pub struct OdohTransport {
    id: String,
    /// The oblivious **target** resolver (holds the HPKE key; sees the query, never the client IP).
    target: Endpoint,
    /// The oblivious **relay** (proxies to the target; sees the client IP, never the plaintext). `None`
    /// = direct-to-target (degenerate ODoH — still HPKE-encrypted, but not anonymized; useful for the
    /// config-key smoke and single-hop testing).
    relay: Option<Endpoint>,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    config: Mutex<Option<CachedConfig>>,
}

impl OdohTransport {
    /// Build an ODoH transport. `target` is the oblivious target — an `sdns://` ODoH-target (`0x05`)
    /// stamp (the app's stamp-native server form) OR a bare `https://odoh.cloudflare-dns.com/dns-query`
    /// URL. `relay` is the optional oblivious relay — an `sdns://` ODoH-relay (`0x85`) stamp (what
    /// `odoh-relays.md` ships) OR a bare `https://odoh1.surfdomeinen.nl/proxy` URL. Fails only on an
    /// unparseable target / non-https URL — key fetch and TLS/connect errors surface later, per
    /// exchange, so a transiently-down upstream never blocks pool construction (same contract as
    /// [`super::doh::Http2Doh::new`]).
    pub fn new(id: &str, target: &str, relay: Option<&str>) -> Result<Self, TransportError> {
        let target = Endpoint::from_target(target)?;
        let relay = match relay {
            Some(r) if !r.is_empty() => Some(Endpoint::from_relay(r)?),
            _ => None,
        };

        // Shared ring-pinned trust; ALPN is the hyper-rustls builder's job (`enable_http2` stamps h2;
        // the config MUST arrive ALPN-empty — builder.rs:61). Identical recipe to `doh.rs`.
        let tls = super::tls::client_tls_config();
        let https = HttpsConnector::<HttpConnector>::builder()
            .with_tls_config(tls)
            .https_only()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);

        Ok(OdohTransport {
            id: id.to_string(),
            target,
            relay,
            client,
            config: Mutex::new(None),
        })
    }

    /// The POST endpoint for an oblivious query: via the relay when configured (target host+path ride
    /// as percent-encoded `targethost` / `targetpath` query params, per RFC 9230 §6.2), else direct to
    /// the target.
    fn query_endpoint(&self) -> String {
        match &self.relay {
            Some(relay) => format!(
                "https://{}{}{}targethost={}&targetpath={}",
                relay.authority,
                relay.path_and_query,
                if relay.path_and_query.contains('?') {
                    '&'
                } else {
                    '?'
                },
                encode_component(&self.target.authority),
                encode_component(&self.target.path_and_query),
            ),
            None => format!(
                "https://{}{}",
                self.target.authority, self.target.path_and_query
            ),
        }
    }

    /// The direct GET url for the target's `ObliviousDoHConfigs`. Fetched from the target itself (the
    /// key is public); cached + refreshed by [`Self::config_contents`].
    fn config_endpoint(&self) -> String {
        format!("https://{}{}", self.target.authority, WELL_KNOWN_CONFIGS)
    }

    /// Return the target HPKE config, using the fresh cached clone when possible, else fetching it from
    /// the well-known endpoint and repopulating the cache. The `Mutex` is never held across the fetch
    /// await — only for the two micro-critical-sections (read the cached clone / store the new one).
    async fn config_contents(&self) -> Result<ObliviousDoHConfigContents, TransportError> {
        {
            let guard = self.config.lock().await;
            if let Some(c) = guard.as_ref() {
                if c.fetched.elapsed() < CONFIG_TTL {
                    return Ok(c.contents.clone());
                }
            }
        }
        let contents = self.fetch_config().await?;
        {
            let mut guard = self.config.lock().await;
            *guard = Some(CachedConfig {
                contents: contents.clone(),
                fetched: Instant::now(),
            });
        }
        Ok(contents)
    }

    /// Drop the cached config so the next [`Self::config_contents`] re-fetches — called when the target
    /// answers `401`/empty (its key rotated out from under us). This is the auto-refresh nautilus never
    /// shipped.
    async fn invalidate_config(&self) {
        let mut guard = self.config.lock().await;
        *guard = None;
    }

    /// GET the well-known configs, parse the first supported `ObliviousDoHConfig`, and hand back its
    /// HPKE contents. Direct to the target (the config is public, out-of-band by design).
    async fn fetch_config(&self) -> Result<ObliviousDoHConfigContents, TransportError> {
        let uri: Uri = self
            .config_endpoint()
            .parse()
            .map_err(|e| TransportError::Connect(format!("odoh config url: {e}")))?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .map_err(|e| TransportError::Connect(format!("odoh config request: {e}")))?;
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| TransportError::Connect(format!("odoh config fetch: {e}")))?;
        if !resp.status().is_success() {
            return Err(TransportError::Connect(format!(
                "odoh config status {}",
                resp.status()
            )));
        }
        let body = read_capped(resp.into_body()).await?;
        let mut buf = Bytes::from(body);
        let configs: ObliviousDoHConfigs = parse(&mut buf)
            .map_err(|e| TransportError::Connect(format!("odoh config parse: {e}")))?;
        configs
            .supported()
            .into_iter()
            .next()
            .map(ObliviousDoHConfigContents::from)
            .ok_or_else(|| TransportError::Connect("odoh: no supported config version".into()))
    }
}

impl Transport for OdohTransport {
    fn id(&self) -> &str {
        &self.id
    }

    /// The oblivious round-trip. RFC 9230: the query's transaction id is ZEROED before encryption (so
    /// neither relay nor target can use it as a correlation handle) and RESTORED on the decrypted
    /// answer, so the resolver's `validate_response` still matches it. One retry on `401`/empty — the
    /// only case that means "key rotated": invalidate + re-fetch + re-encrypt.
    fn exchange<'a>(&'a self, query_wire: &'a [u8]) -> ExchangeFuture<'a> {
        Box::pin(async move {
            if query_wire.len() < 12 {
                return Err(TransportError::Exchange("odoh: query too short".into()));
            }
            // Zero the transaction id for the wire; keep the original to restore on the answer.
            let tid = [query_wire[0], query_wire[1]];
            let mut zeroed = query_wire.to_vec();
            zeroed[0] = 0;
            zeroed[1] = 0;
            let plaintext = ObliviousDoHMessagePlaintext::new(&zeroed, 0);
            let endpoint = self.query_endpoint();

            let mut last_err: Option<TransportError> = None;
            for attempt in 0..2 {
                let config = self.config_contents().await?;

                // HPKE-seal the query. `encrypt_query` returns the oblivious message + our per-query
                // client secret (needed to open the response).
                let mut rng = OsCsprng;
                let (query_msg, secret) = encrypt_query(&plaintext, &config, &mut rng)
                    .map_err(|e| TransportError::Exchange(format!("odoh encrypt: {e}")))?;
                let body = compose(&query_msg)
                    .map_err(|e| TransportError::Exchange(format!("odoh compose: {e}")))?
                    .freeze();

                let uri: Uri = endpoint
                    .parse()
                    .map_err(|e| TransportError::Exchange(format!("odoh endpoint: {e}")))?;
                let req = Request::builder()
                    .method(Method::POST)
                    .uri(uri)
                    .header(http::header::CONTENT_TYPE, ODOH_HTTP_HEADER)
                    .header(http::header::ACCEPT, ODOH_HTTP_HEADER)
                    .body(Full::new(body))
                    .map_err(|e| TransportError::Exchange(format!("odoh request: {e}")))?;

                let resp = self
                    .client
                    .request(req)
                    .await
                    .map_err(|e| TransportError::Exchange(format!("odoh request: {e}")))?;
                let status = resp.status();

                // 401 = the target rejected our key envelope (its config rotated). Invalidate the cache
                // and retry ONCE with a freshly-fetched key. Any other non-2xx is a hard bad-response.
                if status == http::StatusCode::UNAUTHORIZED {
                    self.invalidate_config().await;
                    last_err = Some(TransportError::BadResponse("odoh 401 (key rotated)".into()));
                    continue;
                }
                if !status.is_success() {
                    return Err(TransportError::BadResponse(format!("odoh status {status}")));
                }

                let raw = read_capped(resp.into_body()).await?;
                if raw.is_empty() {
                    // Some targets answer an empty 200 on a stale key rather than 401 — treat the same.
                    self.invalidate_config().await;
                    last_err = Some(TransportError::BadResponse("odoh empty reply".into()));
                    if attempt == 0 {
                        continue;
                    }
                    break;
                }

                let mut rbuf = Bytes::from(raw);
                let resp_msg: ObliviousDoHMessage = parse(&mut rbuf).map_err(|e| {
                    TransportError::BadResponse(format!("odoh response parse: {e}"))
                })?;
                let opened = decrypt_response(&plaintext, &resp_msg, secret)
                    .map_err(|e| TransportError::BadResponse(format!("odoh decrypt: {e}")))?;

                let mut answer = opened.into_msg().to_vec();
                if answer.len() >= 2 {
                    // Restore the caller's transaction id (we sent it zeroed).
                    answer[0] = tid[0];
                    answer[1] = tid[1];
                }
                return Ok(answer);
            }
            Err(last_err
                .unwrap_or_else(|| TransportError::BadResponse("odoh: exhausted retries".into())))
        })
    }

    /// ODoH's oblivious relay IS an anonymization hop — surface it in the `query.log` relay column, the
    /// twin of `id()`'s target attribution (the obliviousness made visible). `None` = direct-to-target.
    fn relay_name(&self) -> Option<&str> {
        self.relay.as_ref().map(|r| r.authority.as_str())
    }
}

/// Capped streaming body read (T6): stop the instant we cross `MAX_BODY`, never buffer unbounded.
/// Shared shape with [`super::doh`]; kept local so ODoH stays self-contained.
async fn read_capped<B>(mut body: B) -> Result<Vec<u8>, TransportError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| TransportError::Exchange(format!("odoh body: {e}")))?;
        if let Some(chunk) = frame.data_ref() {
            if buf.len() + chunk.len() > MAX_BODY {
                return Err(TransportError::BadResponse(
                    "odoh body exceeds 64KiB cap".into(),
                ));
            }
            buf.extend_from_slice(chunk);
        }
    }
    Ok(buf)
}

/// Percent-encode `s` for use as a URL query component (RFC 3986): unreserved bytes pass through, all
/// else become `%XX`. Used for the relay's `targethost` / `targetpath` params so a target path that
/// contains `/`, `?` or `&` can't break out of its query slot.
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_target_and_defaults_path() {
        let e = Endpoint::parse("https://odoh.example.net", "/dns-query").unwrap();
        assert_eq!(e.authority, "odoh.example.net");
        assert_eq!(e.path_and_query, "/dns-query");
    }

    #[test]
    fn rejects_cleartext() {
        assert!(Endpoint::parse("http://odoh.example.net/dns-query", "/dns-query").is_err());
    }

    #[test]
    fn keeps_explicit_path_and_port() {
        let e = Endpoint::parse("https://relay.example.net:8443/proxy", "/").unwrap();
        assert_eq!(e.authority, "relay.example.net:8443");
        assert_eq!(e.path_and_query, "/proxy");
    }

    #[test]
    fn direct_endpoint_has_no_relay_params() {
        let t =
            OdohTransport::new("odoh:direct", "https://odoh.example.net/dns-query", None).unwrap();
        assert_eq!(t.query_endpoint(), "https://odoh.example.net/dns-query");
        assert!(t.relay_name().is_none());
    }

    #[test]
    fn relayed_endpoint_encodes_target_into_query() {
        let t = OdohTransport::new(
            "odoh:relayed",
            "https://odoh.example.net/dns-query",
            Some("https://relay.example.org/proxy"),
        )
        .unwrap();
        // target host+path ride as percent-encoded params on the relay url.
        assert_eq!(
            t.query_endpoint(),
            "https://relay.example.org/proxy?targethost=odoh.example.net&targetpath=%2Fdns-query"
        );
        // the relay is surfaced as the anonymization hop for the query.log relay column.
        assert_eq!(t.relay_name(), Some("relay.example.org"));
    }

    #[test]
    fn encode_component_escapes_reserved() {
        assert_eq!(encode_component("/dns-query"), "%2Fdns-query");
        assert_eq!(encode_component("a?b&c=d"), "a%3Fb%26c%3Dd");
        assert_eq!(encode_component("safe-._~AZ09"), "safe-._~AZ09");
    }

    /// RFC 4648 base64url (no padding) — test-local, mirrors `dnscrypt::base64url_decode`.
    fn b64url(data: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0u32);
        for &b in data {
            buf = (buf << 8) | b as u32;
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(A[((buf >> bits) & 0x3F) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(A[((buf << (6 - bits)) & 0x3F) as usize] as char);
        }
        out
    }

    fn lp(body: &mut Vec<u8>, s: &[u8]) {
        body.push(s.len() as u8);
        body.extend_from_slice(s);
    }

    #[test]
    fn stamp_native_target_and_relay_build_and_keep_the_relay_path() {
        // TARGET as a 0x05 sdns:// stamp; RELAY as a 0x85 sdns:// stamp. The whole obliviousness point
        // is the relay path (RFC 9230 /proxy) — this asserts we KEEP it, unlike the Kotlin
        // `handleODoHRelay` which decodes a 0x85 stamp to host:port and DISCARDS the path.
        let mut t = vec![0x05u8];
        t.extend_from_slice(&0u64.to_le_bytes());
        lp(&mut t, b"odoh.example.net");
        lp(&mut t, b"/dns-query");
        let target = format!("sdns://{}", b64url(&t));

        let mut r = vec![0x85u8];
        r.extend_from_slice(&0u64.to_le_bytes());
        lp(&mut r, b""); // empty bootstrap addr
        r.push(0); // one empty hash (VLP terminator)
        lp(&mut r, b"relay.example.org");
        lp(&mut r, b"/proxy");
        let relay = format!("sdns://{}", b64url(&r));

        let t = OdohTransport::new("odoh:stamped", &target, Some(&relay)).unwrap();
        assert_eq!(
            t.query_endpoint(),
            "https://relay.example.org/proxy?targethost=odoh.example.net&targetpath=%2Fdns-query"
        );
        assert_eq!(t.relay_name(), Some("relay.example.org"));
    }
}
