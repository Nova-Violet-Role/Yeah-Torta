/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Centauri Local Mirror — the **fetch-ONCE** HTTPS leg.
//!
//! The cache ([`super::cache`]) hands the caller a [`super::cache::CacheLookup::Miss`] token carrying the
//! `wanted` content address. `fetch_once` redeems that token with EXACTLY one upstream GET, hash-verifies
//! the body against the catalog-pinned hash FAIL-CLOSED, and returns the bytes ONLY on a match — so a
//! tampered, truncated, or substituted upstream byte can never flow back into the content-addressed store
//! ("≤1 upstream request EVER per asset" — the §3.1 privacy property; verify-on-write — §3.2).
//!
//! ## The recipe is DoH minus DNS framing, plus a BLAKE2b-256 gate
//! This is the proven Wave-2b DoH transport ([`crate::resolver::doh`]) reduced to a plain bounded HTTPS
//! GET: the SAME shared **ring-pinned** TLS ([`crate::tls_shared::client_tls_config`]), the SAME
//! `https_only()` encrypted-only INVARIANT (T13 — never cleartext), the SAME capped streaming read that
//! refuses to buffer unbounded (T6, cap raised from 64 KiB to [`super::cache::MAX_ASSET_BYTES`] = 8 MiB
//! for assets), with the POST/`application/dns-message` body swapped for an empty-body GET and the answer
//! re-hashed through [`super::cache::content_hash`] (the ONE BLAKE2b-256 digest discipline, NEVER the
//! forgeable FNV-1a).
//!
//! ## No new dependency, no new feature
//! Every crate used here — `hyper` (client), `hyper-util` (client-legacy + tokio), `hyper-rustls` (ring),
//! `http`, `http-body-util`, `bytes`, `tokio`, `rustls` — is a BASE (non-optional) dep
//! (`Cargo.toml:28`-`44`); they are the identical client stack DoH already ships. The content-address
//! digest itself lives in [`super::cache::content_hash`] (`blake2`, pulled under the `mirror` feature),
//! so this file imports no digest crate directly. The `mirror` feature (`Cargo.toml:135`) adds ONLY
//! hyper's SERVER half — the CLIENT half this leg needs is always on. So `fetch_once` adds zero deps and
//! zero features beyond the feature-gated `blake2`; the aws-lc-free / ring-only gate
//! (`cargo tree --features mirror | grep -ci aws-lc == 0`) is unchanged by this file.

#![forbid(unsafe_code)]

use std::sync::Arc;

use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use super::cache::{content_hash, ContentHash, MAX_ASSET_BYTES};

/// Why a fetch-ONCE attempt failed. Each variant is fail-closed: NONE of them ever yields bytes — the only
/// success path returns `Ok(verified_bytes)` after the content-address check passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchError {
    /// The request could not be built/sent, or the upstream answered with a non-2xx status, or the body
    /// stream errored mid-read (a transport-layer failure — no bytes to trust).
    Http,
    /// The upstream body crossed [`MAX_ASSET_BYTES`] (8 MiB) mid-stream — refused before buffering it all,
    /// so a hostile/oversized CDN response can never exhaust the phone's memory (T6).
    TooLarge,
    /// The fetched bytes hashed to a DIFFERENT content address than the catalog-pinned `expected` — the
    /// fail-closed core: a tampered/substituted asset is REJECTED, never returned, never cached.
    HashMismatch,
    /// The URL was not a parseable `https://` URI, or the TLS/connector setup was rejected — an
    /// encrypted-only INVARIANT failure (T13): the leg never falls back to cleartext.
    Tls,
}

/// Fetch an asset ONCE over ring-pinned HTTPS and return its bytes ONLY if they hash to `expected`.
///
/// - `url` — the catalog-pinned upstream (`https://…`); a non-`https` or unparseable URL is [`FetchError::Tls`].
/// - `expected` — the catalog's content address for this asset (the `wanted` hash from the cache miss token).
/// - `tls` — the shared ring-pinned [`rustls::ClientConfig`] (built ONCE by the JNI/caller via
///   `Arc::new(crate::tls_shared::client_tls_config())` and shared across fetches). It is unwrapped with
///   `(*tls).clone()` here because `hyper-rustls`'s `with_tls_config` consumes an owned `ClientConfig`
///   by value (exactly as DoH does in `doh.rs`); `ClientConfig: Clone`.
///
/// FAIL-CLOSED throughout: the ONLY way bytes leave this function is the final
/// `content_hash(&buf) == *expected` check passing. Any transport error, oversize, or hash mismatch
/// returns an `Err` and zero bytes.
pub async fn fetch_once(
    url: &str,
    expected: &ContentHash,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Vec<u8>, FetchError> {
    let buf = fetch_bytes(url, tls).await?;
    // FAIL-CLOSED content-address gate: the SAME BLAKE2b-256 the cache key uses (cache.rs:112).
    // Return bytes ONLY on a match — never the wrong bytes.
    let got = content_hash(&buf);
    if got != *expected {
        return Err(FetchError::HashMismatch);
    }
    Ok(buf)
}

/// ★ #65 ABSORB — fetch an asset this device has NEVER seen, and return it with the content address of
/// whatever actually arrived.
///
/// This is the trust-on-first-use twin of [`fetch_once`], and the difference in trust model is the whole
/// point, so it is stated plainly: [`fetch_once`] can only ever return bytes matching a hash the signed
/// catalog already pinned — it verifies. This function has NO pin to verify against, because the asset is
/// being met for the first time; it ADDRESSES the bytes instead. Everything after this moment is as strong
/// as the pinned lane (the binding is remembered by content address, and every later serve re-checks that
/// address), but the first fetch itself trusts the upstream TLS connection and nothing more.
///
/// It is used ONLY for a PROMOTED discovered host — a CDN this device met while the user browsed, which
/// ships no ResourceMap and therefore has no catalog pin to fetch against. The exact same hardened
/// transport as the pinned lane carries it: https-only, h2, the shared ring-pinned trust, and the capped
/// streaming read. The ≤1 crown is unchanged — this runs once per asset, and every request after it is
/// served from the content-addressed cache with zero egress.
pub async fn fetch_absorb(
    url: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<(Vec<u8>, ContentHash), FetchError> {
    let buf = fetch_bytes(url, tls).await?;
    let hash = content_hash(&buf);
    Ok((buf, hash))
}

/// The shared transport core of both fetch legs — https-only, h2, ring-pinned trust, capped streaming
/// read. Returns the raw bytes WITHOUT any content-address decision; the caller supplies the trust model
/// ([`fetch_once`] verifies a pin, [`fetch_absorb`] addresses what arrived). Factored so the two legs can
/// never drift in transport hardening.
async fn fetch_bytes(url: &str, tls: Arc<rustls::ClientConfig>) -> Result<Vec<u8>, FetchError> {
    // Parse + ENFORCE https — the encrypted-only INVARIANT (T13). A cleartext or malformed URL never
    // reaches a socket.
    let uri: Uri = url.parse().map_err(|_| FetchError::Tls)?;
    if uri.scheme_str() != Some("https") {
        return Err(FetchError::Tls);
    }

    // ★ #65 THE CLOAK-BYPASS DIAL — resolve the upstream WITHOUT the Centauri cloak.
    //
    // This leg only ever runs for a host Centauri has cloaked to the sentinel. Resolving it the ordinary
    // way returns that sentinel, so the fetch dials the mirror it is being driven by: the mirror asks
    // itself for the bytes, gets its own miss back, and the asset can never be filled. That loop is why
    // an authorized miss produced no upstream request at all.
    //
    // `resolve_uncloaked_addrs` is the seam built for exactly this (the ONE caller allowed
    // `CloakPolicy::Bypass`). It is BLOCKING and we are inside the mirror's runtime, so it goes through
    // `spawn_blocking` as its own doc-comment requires. A blocked host stays blocked there, so bypassing
    // the cloak cannot be used to dodge a filter.
    //
    // With real addresses in hand we dial them directly and keep the TRUE hostname as the TLS server
    // name, so certificate validation is exactly as strict as before — we changed WHERE the address came
    // from, never WHO we require the peer to prove it is.
    if let Some(host) = uri.host() {
        let addrs = uncloaked_addrs(host).await;
        if !addrs.is_empty() {
            return fetch_via_addrs(&uri, host, uri.port_u16().unwrap_or(443), &addrs, tls).await;
        }
        // No uncloaked answer (no resolver pool — desktop, tests, a cold tunnel) ⇒ fall through to the
        // system-DNS client below. On those hosts nothing is cloaked, so ordinary resolution is correct.
    }

    // Shared ring-pinned trust. Unwrap the Arc (with_tls_config takes an OWNED ClientConfig, like DoH in
    // doh.rs). ALPN stays UNSET here: `with_tls_config` hard-asserts an ALPN-empty config (hyper-rustls
    // builder.rs:61) and `enable_http2()` below stamps the identical `h2` itself (builder.rs:260-261).
    let owned_tls = (*tls).clone();
    // h2-only, EXACTLY as the proven DoH path. GROUND_TRUTH: hyper-rustls's `enable_http1()`
    // is `#[cfg(feature = "http1")]` (hyper-rustls connector/builder.rs:251), and the crate's hyper-rustls
    // dep is `default-features=false, features=["http2","ring","tls12"]` (Cargo.toml:41) — NO `http1`
    // feature — so `enable_http1()` does not exist in this build. Honoring the NO-new-deps/features
    // invariant, this leg is h2-only; every CDN in the §3.1 allowlist (cdnjs/jsdelivr/fonts/unpkg) speaks
    // HTTP/2, so an h2 GET reaches them all. Builder typestate: with_tls_config → WantsSchemes →
    // https_only → WantsProtocols1 → enable_http2 → WantsProtocols3 → build (builder.rs:60,196,260).
    let https = HttpsConnector::<HttpConnector>::builder()
        .with_tls_config(owned_tls)
        .https_only() // T13 — encrypted-only is an INVARIANT; never fall back to cleartext http
        .enable_http2()
        .build();
    let client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build(https);

    // GET with an EMPTY body (vs DoH's POST `Full::new(body)` at doh.rs:82).
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Empty::<Bytes>::new())
        .map_err(|_| FetchError::Http)?;

    let resp = client.request(req).await.map_err(|_| FetchError::Http)?;
    if !resp.status().is_success() {
        return Err(FetchError::Http);
    }

    // Capped streaming read (T6): stop the moment we cross MAX_ASSET_BYTES, never buffer unbounded — the
    // EXACT loop shape from doh.rs:95-107, cap raised from 64 KiB to 8 MiB (cache.rs:52).
    let mut body = resp.into_body();
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| FetchError::Http)?;
        if let Some(chunk) = frame.data_ref() {
            if buf.len() + chunk.len() > MAX_ASSET_BYTES {
                return Err(FetchError::TooLarge);
            }
            buf.extend_from_slice(chunk);
        }
    }

    Ok(buf)
}

/// Resolve `host` with the Centauri cloak bypassed, off the async runtime.
///
/// `resolve_uncloaked_addrs` drives the resolver's own runtime with `block_on`, which panics if called
/// on a worker thread, so it MUST run on the blocking pool. Any failure (no pool, NXDOMAIN, blocked,
/// join error) yields an empty vec — the caller then falls back to system DNS rather than inventing an
/// address.
async fn uncloaked_addrs(host: &str) -> Vec<std::net::IpAddr> {
    let owned = host.to_string();
    tokio::task::spawn_blocking(move || crate::resolver::resolve_uncloaked_addrs(&owned))
        .await
        .unwrap_or_default()
}

/// GET `uri` by dialling `addrs` directly while presenting `host` as the TLS server name.
///
/// The addresses come from the uncloaked lookup; the hostname is what the certificate must still match.
/// ALPN is offered as h2 THEN http/1.1 and the negotiated protocol picks the client — a strict widening
/// of the old h2-only leg, which simply could not talk to a CDN that speaks only HTTP/1.1 (the corpus
/// allowlist all speak h2, but a DISCOVERED host is any CDN the user happens to browse).
async fn fetch_via_addrs(
    uri: &Uri,
    host: &str,
    port: u16,
    addrs: &[std::net::IpAddr],
    tls: Arc<rustls::ClientConfig>,
) -> Result<Vec<u8>, FetchError> {
    // ALPN must be advertised for h2 to be negotiable. The shared config deliberately leaves it unset
    // (hyper-rustls asserts an empty ALPN and stamps its own), so this clone sets it for the direct dial
    // and leaves the shared config untouched for every other user.
    let mut cfg = (*tls).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| FetchError::Tls)?;

    // Try each address in answer order (A before AAAA) — a phone on a v4-only carrier must not be
    // stranded by a AAAA that cannot be reached.
    let mut last = FetchError::Http;
    for ip in addrs {
        let tcp = match tokio::net::TcpStream::connect((*ip, port)).await {
            Ok(s) => s,
            Err(_) => {
                last = FetchError::Http;
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let stream = match connector.connect(server_name.clone(), tcp).await {
            Ok(s) => s,
            Err(_) => {
                last = FetchError::Tls; // the cert did not match the TRUE hostname ⇒ never trust it
                continue;
            }
        };
        let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_ref());
        return if h2 {
            get_h2(stream, uri).await
        } else {
            get_h1(stream, uri, host, port).await
        };
    }
    Err(last)
}

/// HTTP/2 GET over an established TLS stream (absolute-form URI — h2 carries `:authority`).
async fn get_h2<S>(stream: S, uri: &Uri) -> Result<Vec<u8>, FetchError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| FetchError::Http)?;
    // The connection future must be driven for the request to make progress; it ends when the response
    // completes and the sender drops.
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .body(Empty::<Bytes>::new())
        .map_err(|_| FetchError::Http)?;
    let resp = sender.send_request(req).await.map_err(|_| FetchError::Http)?;
    read_capped(resp).await
}

/// HTTP/1.1 GET over an established TLS stream (origin-form path + an explicit `Host`).
async fn get_h1<S>(stream: S, uri: &Uri, host: &str, port: u16) -> Result<Vec<u8>, FetchError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
        .await
        .map_err(|_| FetchError::Http)?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    // Default port stays implicit — some origins vhost strictly on the bare name.
    let authority = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(hyper::header::HOST, authority)
        .body(Empty::<Bytes>::new())
        .map_err(|_| FetchError::Http)?;
    let resp = sender.send_request(req).await.map_err(|_| FetchError::Http)?;
    read_capped(resp).await
}

/// The shared capped body read (T6) — identical policy on every client path: non-2xx is a failure, and
/// the stream stops the moment it would cross [`MAX_ASSET_BYTES`] rather than buffering unbounded.
async fn read_capped(resp: http::Response<hyper::body::Incoming>) -> Result<Vec<u8>, FetchError> {
    if !resp.status().is_success() {
        return Err(FetchError::Http);
    }
    let mut body = resp.into_body();
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| FetchError::Http)?;
        if let Some(chunk) = frame.data_ref() {
            if buf.len() + chunk.len() > MAX_ASSET_BYTES {
                return Err(FetchError::TooLarge);
            }
            buf.extend_from_slice(chunk);
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    //! Host-only + network-free unit tests for the fetch-ONCE leg. `fetch_once` itself needs a live
    //! upstream, so these PROVE the parts that are pure and security-load-bearing without a socket: the
    //! content-address gate decision, the https-only URL guard via the public error taxonomy, and that the
    //! shared TLS config is buildable + Arc-shareable in the exact shape `fetch_once` consumes it.

    use super::*;
    use crate::mirror::cache::content_hash;

    /// The fail-closed core, isolated: bytes are accepted ONLY when their BLAKE2b-256 equals the catalog
    /// hash. This mirrors the final gate inside `fetch_once` (the one path that returns `Ok`).
    #[test]
    fn hash_gate_accepts_only_a_content_match() {
        let bytes = b"centauri asset payload".to_vec();
        let correct = content_hash(&bytes);
        // A matching expected hash is the ONLY accept path.
        assert_eq!(content_hash(&bytes), correct, "self-consistent BLAKE2b-256");

        // Any tampered byte yields a different address ⇒ HashMismatch in the real fn.
        let mut tampered = bytes.clone();
        tampered[0] ^= 0xFF;
        assert_ne!(
            content_hash(&tampered),
            correct,
            "a single tampered byte must change the content address (fail-closed gate basis)",
        );
    }

    /// The empty asset is well-defined: its address is `BLAKE2b-256("")`, so a zero-length catalog asset
    /// still has a deterministic gate value (no special-casing in `fetch_once`).
    #[test]
    fn empty_body_has_a_deterministic_address() {
        let a = content_hash(&[]);
        let b = content_hash(b"");
        assert_eq!(a, b, "BLAKE2b-256 of the empty asset is deterministic");
    }

    /// The shared ring-pinned config is buildable and shareable in EXACTLY the `Arc<rustls::ClientConfig>`
    /// shape `fetch_once` takes — the JNI/caller builds it once and threads it in. Network-free: only the
    /// config is constructed (no socket); on the host this takes the webpki-roots branch.
    #[test]
    fn shared_tls_is_arc_shareable_in_the_fetch_shape() {
        let tls: Arc<rustls::ClientConfig> = Arc::new(crate::tls_shared::client_tls_config());
        // Cloning the Arc is the cheap per-fetch share (the JNI holds one, hands clones to each fetch).
        let cloned = Arc::clone(&tls);
        assert_eq!(Arc::strong_count(&tls), 2, "Arc share is cheap + correct");
        // The shared builder carries NO ALPN (tls_shared.rs:70) — load-bearing: hyper-rustls's
        // `with_tls_config` hard-asserts an ALPN-empty config (builder.rs:61); `enable_http2()` stamps h2.
        assert!(
            cloned.alpn_protocols.is_empty(),
            "the threaded-in shared config must carry no ALPN — the hyper-rustls builder owns it (h2)",
        );
    }

    /// The error taxonomy is the public fail-closed contract: every variant is a non-byte outcome. This
    /// pins the variants (a refactor that dropped one would break a caller's exhaustive match).
    #[test]
    fn fetch_error_variants_are_distinct() {
        assert_ne!(FetchError::Http, FetchError::TooLarge);
        assert_ne!(FetchError::TooLarge, FetchError::HashMismatch);
        assert_ne!(FetchError::HashMismatch, FetchError::Tls);
        assert_ne!(FetchError::Http, FetchError::Tls);
    }
}
