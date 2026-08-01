/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! DoH over HTTP/2 (RFC 8484) — the Wave 2b workhorse transport.
//!
//! Hand-wired on `hyper` + `hyper-rustls` with the **`ring`** provider (NOT aws-lc-rs — cross-compile
//! safe Windows-host → cargo-ndk). One POST per query: `application/dns-message` body in, the same
//! media type back, with a hard 64 KiB body cap (T6). The transport authenticates only the channel
//! (system trust + hostname, NO `danger_accept_invalid_certs` anywhere — T11); `dns::validate_response`
//! authenticates the answer.
//!
//! Trust roots come from the shared, ring-pinned [`super::tls::client_tls_config`] (the same config
//! DoH3/DoQ reuse): on Android the v0.7 platform verifier, on every other target (incl. the Windows
//! host where `cargo check`/`cargo test` run) the static `webpki-roots` bundle. ALPN is per-transport
//! and OWNED by the hyper-rustls builder: `with_tls_config` hard-asserts the incoming config carries
//! NO pre-set ALPN (hyper-rustls 0.27 connector/builder.rs:61 — "ALPN protocols should not be
//! pre-defined"), and `enable_http2()` stamps `h2` itself (builder.rs:260-261). This client is
//! h2-only by feature set (no `http1` feature → `enable_http1` does not exist in this build).

use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use super::transport::{ExchangeFuture, Transport, TransportError};

/// RFC 8484 media type for both request and response bodies.
const DNS_MESSAGE: &str = "application/dns-message";
/// T6 — never read more than 64 KiB of response body (a DNS message tops out near the EDNS0 buffer).
const MAX_BODY: usize = 64 * 1024;

/// A configured DoH/HTTP-2 upstream. Cheap to clone-share via `Arc`; the inner `Client` pools
/// connections itself.
pub struct Http2Doh {
    id: String,
    uri: Uri,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl Http2Doh {
    /// Build a DoH transport for `url` (e.g. `https://cloudflare-dns.com/dns-query`). `id` is the
    /// stats label. Fails only if the URL is unparseable — TLS/connect errors surface later, per
    /// exchange, so a transiently-down upstream never blocks construction of the pool.
    pub fn new(id: &str, url: &str) -> Result<Self, TransportError> {
        let uri: Uri = url
            .parse()
            .map_err(|e| TransportError::Connect(format!("bad url: {e}")))?;
        if uri.scheme_str() != Some("https") {
            return Err(TransportError::Connect("doh url must be https".into()));
        }

        // Shared ring-pinned trust setup. ALPN is the BUILDER's job: `with_tls_config` hard-asserts
        // the config arrives ALPN-empty (hyper-rustls 0.27 builder.rs:61 — pre-stamping it panics,
        // measured live in the Nautilus II smoke) and `enable_http2()` stamps `h2` itself
        // (builder.rs:260-261).
        let tls = super::tls::client_tls_config();
        let https = HttpsConnector::<HttpConnector>::builder()
            .with_tls_config(tls)
            .https_only() // T13 — encrypted-only is an INVARIANT; never fall back to cleartext http
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);

        Ok(Http2Doh {
            id: id.to_string(),
            uri,
            client,
        })
    }
}

impl Transport for Http2Doh {
    fn id(&self) -> &str {
        &self.id
    }

    fn exchange<'a>(&'a self, query_wire: &'a [u8]) -> ExchangeFuture<'a> {
        let body = Bytes::copy_from_slice(query_wire);
        Box::pin(async move {
            let req = Request::builder()
                .method(Method::POST)
                .uri(self.uri.clone())
                .header(http::header::CONTENT_TYPE, DNS_MESSAGE)
                .header(http::header::ACCEPT, DNS_MESSAGE)
                .body(Full::new(body))
                .map_err(|e| TransportError::Exchange(format!("build request: {e}")))?;

            let resp = self
                .client
                .request(req)
                .await
                .map_err(|e| TransportError::Exchange(format!("request: {e}")))?;

            if !resp.status().is_success() {
                return Err(TransportError::BadResponse(format!(
                    "status {}",
                    resp.status()
                )));
            }

            // Capped streaming read (T6): stop the moment we cross MAX_BODY, never buffer unbounded.
            let mut body = resp.into_body();
            let mut buf: Vec<u8> = Vec::with_capacity(512);
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|e| TransportError::Exchange(format!("body: {e}")))?;
                if let Some(chunk) = frame.data_ref() {
                    if buf.len() + chunk.len() > MAX_BODY {
                        return Err(TransportError::BadResponse("body exceeds 64KiB cap".into()));
                    }
                    buf.extend_from_slice(chunk);
                }
            }
            Ok(buf)
        })
    }
}
