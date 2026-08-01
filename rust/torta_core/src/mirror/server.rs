/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! Centauri Local Mirror — the lean Rust **loopback micro-HTTP(S) server** (E', the spike-RED runtime).
//!
//! ## Why Rust serves the Haskell-signed content (ADR-001 Amendment 1)
//! The GHC-RTS-on-Android spike is **RED-by-prerequisite**: no android-cross GHC toolchain provisions
//! (measured via `Sanctum ssh` to torta-emu — the VM GHC 9.4.7 is the NATIVE-linux offline brain, not an
//! aarch64-android cross-compiler; no ghcup android bindist, no LLVM, no NDK-GHC path). That is the
//! EXPECTED default, NOT a pillar blocker: the offline GHC brain still authors + minisign-signs every CDN
//! catalog/manifest on the VM, and THIS lean Rust loopback server is the on-device RUNTIME that serves the
//! verified, content-addressed assets over `127.0.0.1`. Centauri stays a first-class Haskell-BUILT pillar;
//! only the runtime language is Rust.
//!
//! ## The serve path (content-addressed, fail-closed)
//! A loopback request names an asset; the server looks up its content address in the signature-verified
//! [`super::catalog::Catalog`], then serves the bytes from the content-addressed [`super::cache::CacheStore`]
//! ONLY on a hash match. On a cache miss it triggers the fetch-ONCE leg (hyper-rustls + the FIX-2 shared
//! ring-pinned TLS via [`crate::tls_shared::client_tls_config`]), hash-verifies, caches, then serves.
//!
//! ## FIX-1 weight gate
//! The server half of `hyper` (`hyper/server`, `hyper-util/server`/`server-graceful`) + this listener are
//! ALL gated behind the `mirror` Cargo feature, so a base Android `.so` (no `mirror`) compiles ZERO server
//! symbols and stays byte-identical. The compile-time witness below references `hyper::server::conn` —
//! it builds ONLY because the `mirror` feature pulled the server half (FIX-1 proven at compile time).
//!
//! ## FIX-1 BUILT (mirror-server forge): the loopback accept loop is now real
//! [`MirrorServer::run`] binds a `tokio::net::TcpListener` on `127.0.0.1:port`, reads back the
//! OS-assigned port, and (when `bound`/the accept loop is driven) wraps each accepted connection in
//! [`hyper_util::rt::TokioIo`] and serves it with `hyper::server::conn::http1::Builder::serve_connection`
//! over a `hyper::service::service_fn` that routes to the PURE [`MirrorServer::serve_name`] decision. The
//! routing/serve verdict stays host-testable without a socket; only the bind + accept + HTTP framing are
//! the socket-bound half. GROUND_TRUTH of the hyper 1.10.1 server API:
//!   - `server::conn::http1::Builder::serve_connection<I,S>(&self, io, svc)`
//!     (`hyper-1.10.1/src/server/conn/http1.rs:451`, `I: hyper::rt::Read + Write + Unpin`),
//!   - `service::service_fn` (`hyper-1.10.1/src/service/util.rs:30`),
//!   - `hyper_util::rt::TokioIo` (`hyper-util-0.1.20/src/rt/tokio.rs:82`, re-exported at `rt/mod.rs:12`).
//!
//! Loopback-only (no LAN), no-root, `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use super::cache::{CacheStore, ContentHash};
use super::catalog::Catalog;
use super::localcdn::Resolution;

/// One traced serve event handed to a [`ServeObserver`] — everything the per-pillar review channel needs
/// to write ONE `query-centauri.log` line / ring one `CentauriServeRecord`: the request's `Host` header
/// (port-stripped), the URL path, the LocalCDN resolution (when the request routed as a CDN URL), and the
/// serve verdict. Borrowed — the observer copies what it keeps; the serve path allocates nothing for it.
pub struct ServeTrace<'a> {
    /// The request's `Host` header, port-stripped (`""` when absent).
    pub host: &'a str,
    /// The request's URL path.
    pub path: &'a str,
    /// The LocalCDN URL→(library, served version, file) decision, when the request routed as a CDN URL.
    pub resolution: Option<&'a Resolution>,
    /// The serve verdict (zero-copy `Served` / fail-closed `NotInCatalog` / `CacheMiss` / fingerprinter block).
    pub outcome: &'a ServeOutcome,
}

/// The per-serve observer seam (D29 — "wire the internal accept-loop sink so the ring feeds itself"): the
/// live accept loop calls it ONCE per served request, AFTER the verdict and OFF the response's critical
/// data (borrowed trace, no allocation). The Centauri Object binds its CROWN-counter + recent-ring +
/// `query-centauri.log` + foreign-sink adapter here, so `recentServes`/`served_locally` are LIVE on-device,
/// not host-test-only. `None` ⇒ the loop serves exactly as before (the flat legacy path stays observer-free).
pub type ServeObserver = Arc<dyn Fn(ServeTrace<'_>) + Send + Sync>;

// ---- FIX-1 compile-time witness: the `mirror` feature MUST pull hyper's server half ----
// This type alias names `hyper::server::conn::http1::Builder`, which exists ONLY when `hyper/server` is
// active (hyper gates `pub mod server` behind its `server` feature). If the `mirror` feature failed to
// turn on `hyper/server`, THIS line would fail to compile — so a green `cargo check --features mirror`
// is itself the GROUND_TRUTH that FIX-1's dep gating works. `MirrorServer::run` below uses this exact
// type to drive `serve_connection`, so the witness is no longer dead — the feature gate is exercised, not
// merely named.
type ServerConnBuilder = hyper::server::conn::http1::Builder;

/// Configuration for the loopback Centauri Mirror server.
///
/// Loopback-only by contract: the listener binds `127.0.0.1` (no LAN exposure, no-root). `port = 0` lets
/// the OS pick a free ephemeral port (the Kotlin side reads back the bound port for in-app requests).
#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    /// The loopback port to bind (`0` ⇒ OS-assigned ephemeral — the safe `Default`: never collides with a
    /// fixed port, never reaches beyond loopback). Always on `127.0.0.1`.
    pub port: u16,
}

/// The outcome of serving one loopback request — a typed verdict, never an unwinding error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeOutcome {
    /// Served the named asset's bytes from the content-addressed cache (hash matched the catalog pin).
    /// Carries the store's shared `Arc<[u8]>` — a zero-copy serve (D24): no per-serve memcpy, and the
    /// hyper body is built over the same shared bytes (`Bytes::from_owner`).
    Served(Arc<[u8]>),
    /// The asset name is not in the signature-verified catalog (unauthorized ⇒ 404, fail-closed).
    NotInCatalog,
    /// The request targets a known fingerprinting library (the BadResources hard-block) ⇒ 403 Forbidden,
    /// fail-closed: denied outright, never served locally and never leaked upstream (the fingerprinter must
    /// not load). Distinct from `NotInCatalog` so a privacy block is honest in the log/metric.
    BlockedFingerprinter,
    /// The asset is in the catalog but absent from the cache ⇒ the caller runs the fetch-ONCE leg.
    CacheMiss(ContentHash),
    /// #85 — the LIVE loopback fetched the authorized-but-uncached asset ONCE (the ≤ 1 crown), hash-verified
    /// + cached it, and serves it now. Distinct from `Served` (a 0-egress cache hit) so the per-serve
    /// observer counts the one honest self-fill (`cdn_fetches`) instead of a local hit; the HTTP response is
    /// identical (`200 OK`, the verified bytes). Carries the store's shared `Arc<[u8]>` (zero-copy, D24).
    LeakedThenServed(Arc<[u8]>),
    /// ★ #65 — the request targets a PROMOTED discovered host (a CDN this device met while the user
    /// browsed) and nothing is bound or cached for it yet, so the caller runs the trust-on-first-use
    /// ABSORB leg (`fetch_absorb` → address → cache → remember the binding). Carries the canonical
    /// absorbed-asset name (`<host><path>`). Distinct from `CacheMiss`, which carries a hash the signed
    /// catalog already pinned: here there is no pin, because the asset has never been seen. Without a
    /// bound `FetchCtx` this fail-closes exactly like a miss — it never serves unverified bytes on its own.
    AbsorbMiss(String),
}

/// The loopback Centauri Mirror server: serves the signature-verified, content-addressed assets.
///
/// SCAFFOLD: holds the verified catalog + the content-addressed cache and exposes the pure routing
/// decision ([`MirrorServer::serve_name`]) so the serve logic is host-testable WITHOUT a live socket. The
/// async accept loop ([`MirrorServer::run`]) is the seam the Forge crew fills on the `hyper_util` graceful
/// server.
pub struct MirrorServer {
    config: ServerConfig,
    catalog: Catalog,
    cache: CacheStore,
}

impl MirrorServer {
    /// Build a server over a signature-verified catalog + a content-addressed cache.
    pub fn new(config: ServerConfig, catalog: Catalog, cache: CacheStore) -> Self {
        MirrorServer {
            config,
            catalog,
            cache,
        }
    }

    /// The server's configuration (loopback port).
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The PURE routing decision for one named asset request (host-testable, no socket):
    ///   1. resolve the name → content address via the signature-verified catalog (else `NotInCatalog`);
    ///   2. serve from the content-addressed cache ON a hash match (`Served`);
    ///   3. on a cache miss, return `CacheMiss(hash)` so the caller runs the fetch-ONCE-verify-cache leg.
    ///
    /// Fail-closed: an unknown name is never served.
    pub fn serve_name(&self, name: &str) -> ServeOutcome {
        let hash = match self.catalog.content_hash_for(name) {
            Some(h) => h,
            None => return note_serve(ServeOutcome::NotInCatalog), // unauthorized ⇒ 404
        };
        match self.cache.get(&hash) {
            // D24 zero-copy: clone the shared Arc handle, never memcpy the asset per serve.
            Some(entry) => note_serve(ServeOutcome::Served(entry.bytes_arc())),
            None => note_serve(ServeOutcome::CacheMiss(hash)),
        }
    }

    /// The request name a loopback HTTP request routes on: the URL path with its single leading `/`
    /// stripped (e.g. `GET /blocklist.tblk` ⇒ the catalog name `blocklist.tblk`). Pure + allocation-light;
    /// an empty path (`GET /`) yields `""`, which the fail-closed catalog lookup rejects as `NotInCatalog`.
    fn request_name(path: &str) -> &str {
        path.strip_prefix('/').unwrap_or(path)
    }

    /// #134 — serve a request that arrived as a **CDN URL** (a cloaked CDN host + its `/lib/version/file`
    /// path), the LocalCDN→Centauri path: translate the CDN URL to its canonical catalog asset name via the
    /// [`super::localcdn`] resource-map (host + base-path match → library + version-fallback → host-
    /// independent `<library>/<served_version>/<file>` name), then run the SAME fail-closed
    /// [`MirrorServer::serve_name`] decision (signed catalog → content-addressed cache).
    ///
    /// **Fail-closed twice over:** an unmapped CDN URL (unknown host / path) is `NotInCatalog`, AND a mapped
    /// URL whose canonical asset the signed catalog does not authorize is *also* `NotInCatalog` — the
    /// resource-map names the URL grammar, but ONLY the minisign-verified catalog authorizes a serve. The
    /// map alone never serves bytes. This is the seam the cloak-set redirect (`catalog.rs` `CloakSet`) feeds:
    /// a cloaked CDN host resolves to `127.0.0.1`, the request lands here, and only an authorized+cached
    /// asset is served — so the real CDN sees ≤ 1 request (the opt-out local-CDN crown).
    pub fn serve_cdn_url(&self, host: &str, path: &str) -> ServeOutcome {
        // BadResources hard-block: a known fingerprinting library is denied BEFORE any resolve/serve, so it
        // is never served locally and never leaked upstream (the fingerprinter must not load).
        if super::localcdn::is_blocked_fingerprinter(host, path) {
            return ServeOutcome::BlockedFingerprinter;
        }
        // Catalog-addressed resolve (coverage gate): the candidate versions are the bundled set INTERSECT
        // what the SIGNED catalog actually authorizes — so a request for a version the static map claims
        // bundled but the device catalog lacks (e.g. jquery 3.5.1) falls back to a COVERED substitute
        // (3.7.1) instead of resolving `Exact` to a name that 404-blackholes in `serve_name`.
        match super::localcdn::resolve_addressed(host, path, &self.catalog, 0) {
            Some(ar) => self.serve_name(&ar.resolution.canonical_name()),
            None => {
                // ★ #78 — WE CLOAKED THIS HOST AND HAVE NOTHING TO GIVE IT.
                //
                // Reaching here means DNS already handed the client our sentinel (`is_cdn_host` said
                // yes on the hostname) and the flow was spliced to us — but no map/catalog entry
                // covers this URL. Returning a bare 404 strands the request: the client asked the
                // real CDN, we intercepted, and we answer "not found" for content that DOES exist
                // upstream. That is how `challenges.cloudflare.com` broke monochrome.tf's Hot & New.
                //
                // The cloak is HOST-granular; serve capability is ASSET-granular. No static list can
                // reconcile that, so we repair it with FEEDBACK: mark the host unservable, which
                // un-cloaks it on the very next query (cloaked answers carry TTL 0, so the client
                // re-asks immediately) and hands the name back to the real CDN. Same remedy, same
                // ledger, as a client that refused our leaf — see `localcdn::note_unservable`.
                //
                // This flow still 404s; the recovery is for the NEXT one. Identical shape to the
                // TLS-refusal path, which likewise cannot rescue the flow that taught it.
                super::localcdn::note_unservable(host);
                ServeOutcome::NotInCatalog
            }
        }
    }

    /// Map one routing [`ServeOutcome`] to a loopback HTTP response (the socket-facing half of serving):
    ///   - `Served(bytes)`   ⇒ `200 OK`, `application/octet-stream`, the content-addressed bytes;
    ///   - `NotInCatalog`    ⇒ `404 Not Found` (fail-closed: an unauthorized name is never served);
    ///   - `CacheMiss(hash)` ⇒ `503 Service Unavailable` — the asset is authorized but not yet cached, so
    ///     the caller's fetch-ONCE-verify-cache leg must run first (a later in-app request re-hits the
    ///     cache as `Served`). 503 (not 404) keeps the authorized/unauthorized distinction honest to the
    ///     client without ever serving unverified bytes. `Infallible`: this never errors, so the
    ///     `service_fn` future is total and `serve_connection`'s `S::Error: Into<Box<…>>` bound holds.
    fn outcome_to_response(outcome: ServeOutcome) -> Response<Full<Bytes>> {
        match outcome {
            // D24 zero-copy body: `Bytes::from_owner` wraps the SAME shared `Arc<[u8]>` the store holds —
            // the HTTP body serves the verified bytes without ever copying them (bytes 1.9+ API).
            ServeOutcome::Served(bytes) => Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
                .body(Full::new(Bytes::from_owner(bytes)))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
            // #85 — a fetch-once self-fill serves the SAME verified bytes as a cache hit (200 OK); only the
            // observer's crown accounting differs (`cdn_fetches` vs `served_locally`).
            ServeOutcome::LeakedThenServed(bytes) => Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
                .body(Full::new(Bytes::from_owner(bytes)))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
            ServeOutcome::NotInCatalog => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
            ServeOutcome::BlockedFingerprinter => Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
            // ★ #65 — an absorb that never ran (no `FetchCtx` bound, so no leg could fetch it). Same
            // fail-closed answer as an unfilled cache miss: unavailable, never unaddressed bytes.
            ServeOutcome::AbsorbMiss(_name) => Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
            ServeOutcome::CacheMiss(_hash) => Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
        }
    }

    /// Route one incoming loopback request to a response — the **host-aware** serve seam (slice 2, the
    /// DNS-plane→loopback serve): read the `Host` header, and when it names a watched-CDN host
    /// ([`super::localcdn::is_cdn_host`]) route the request as a CDN URL ([`MirrorServer::serve_cdn_url`]
    /// semantics — translate `Host: cdnjs.cloudflare.com` + `/lib/version/file` → the canonical catalog
    /// asset name); otherwise fall back to the path-keyed [`MirrorServer::serve_name`]. This is the seam a
    /// DNS-cloaked / app-self-redirected request lands on: a request carrying the original CDN host in its
    /// `Host` header is served from the signed catalog + content-addressed cache instead of the real CDN.
    /// Fail-closed throughout (an unmapped/unauthorized URL ⇒ `NotInCatalog` ⇒ 404). Returns
    /// `Result<_, Infallible>` so it slots directly into a `service_fn` whose error type satisfies
    /// `serve_connection`'s `S::Error: Into<Box<dyn StdError + Send + Sync>>`.
    fn handle(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
        // ★ #22 THE READ-ONLY LAW — the mirror answers READS and nothing else.
        //
        // Every serve leg below resolves a PATH to cached bytes and never looks at the verb, so a write whose
        // path happens to name a catalogued asset would come back `200 OK` carrying the cached READ body: the
        // request never reaches the origin, the caller believes it succeeded, and the write is simply gone.
        // That silent-loss shape is why the cloak set has been held to unambiguous read-only CDN hosts.
        //
        // A cloaked host resolves to `127.0.0.1`, so there is no origin socket here to forward a write to —
        // 405 is the honest answer, and it fails LOUDLY at the caller instead of corrupting its state.
        if !is_servable_method(req.method()) {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(hyper::header::ALLOW, "GET, HEAD")
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
        }
        let path = req.uri().path();
        let host = req
            .headers()
            .get(hyper::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let outcome = route_host_aware(&self.catalog, &self.cache, host, path);
        Ok(Self::outcome_to_response(outcome))
    }

    /// Bind the loopback listener and report the OS-assigned port WITHOUT entering the accept loop. The
    /// listener binds `127.0.0.1:port` (`port = 0` ⇒ an ephemeral OS-assigned port the Kotlin side reads
    /// back); loopback-only by contract (never a LAN/`0.0.0.0` bind), no-root. Splitting bind from accept
    /// lets the caller learn the bound port (to hand to the in-app HTTP client) before `accept_loop` takes
    /// the listener for good, and keeps `bind` host-testable (it really opens a socket on loopback).
    pub async fn bind(&self) -> std::io::Result<(TcpListener, u16)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, self.config.port)).await?;
        let port = listener.local_addr()?.port();
        Ok((listener, port))
    }

    /// Drive the loopback accept loop over an already-bound listener until it errors fatally. Each accepted
    /// connection is wrapped in [`TokioIo`] and served by `http1::Builder::serve_connection` with a
    /// `service_fn` that routes to [`MirrorServer::handle`]. Per-connection serve errors are swallowed
    /// (one bad client never tears the loop down); a fatal `accept()` error ends the loop. The connection
    /// future borrows `self` for the request routing (the catalog + cache live on `self`), so this is the
    /// `&self` accept driver — the resolver-runtime owner drives it via `block_on`, exactly like the
    /// resolver's `rt.block_on(exchange)` pattern (`resolver/mod.rs:308`).
    pub async fn accept_loop(&self, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (stream, _peer) = listener.accept().await?;
            let io = TokioIo::new(stream);
            // The `service_fn` closure borrows `self` so the route decision reads the live catalog+cache.
            let service = service_fn(move |req: Request<Incoming>| {
                // `handle` is sync + Infallible; wrap it in a ready future for the async Service contract.
                let resp = self.handle(req);
                async move { resp }
            });
            // `ServerConnBuilder` is the FIX-1 witness type — naming it here both PROVES the `mirror`
            // feature pulled `hyper/server` AND is the real serve path (not a dead alias).
            let builder = ServerConnBuilder::new();
            if let Err(_e) = builder.serve_connection(io, service).await {
                // A single connection failing (client hangup, malformed framing) must not kill the loop.
                continue;
            }
        }
    }

    /// Bind + serve the loopback Centauri Mirror in one call: `bind()` then `accept_loop()`. Loops until a
    /// fatal accept error; the bound port is observable separately via [`MirrorServer::bind`] when the
    /// caller needs it before serving (the common shape — bind, hand the port to the in-app client, then
    /// spawn the accept loop). Returns the bind error if the listener cannot open on loopback.
    pub async fn run(&self) -> std::io::Result<()> {
        let (listener, _port) = self.bind().await?;
        self.accept_loop(listener).await
    }
}

/// Why the free [`run`] seam failed — a typed verdict the JNI maps to a NEGATIVE sentinel (never a panic
/// across the FFI boundary). [`ServerError::Bind`] ⇒ the loopback listener could not open (port in use,
/// no loopback) and NO server is running; [`ServerError::Serve`] is reserved for a fatal serve-loop fault
/// surfaced to a caller that awaits the loop (the spawned-task shape swallows per-conn errors instead).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerError {
    /// The loopback `127.0.0.1` listener could not bind (e.g. the fixed port is busy). No server runs.
    Bind,
    /// A fatal fault in the accept loop (reserved; the spawned-loop shape keeps serving past per-conn errors).
    Serve,
}

/// SEAM:99 — bind the loopback Centauri Mirror, report the OS-assigned port, and KEEP SERVING in the
/// background, sharing the content-addressed cache behind `Arc<Mutex<CacheStore>>`.
///
/// This is the JNI-facing free entry point (the `MirrorServer` struct stays the host-testable, by-value
/// shape). It binds `127.0.0.1:config.port` (`0` ⇒ ephemeral), reads back the bound port, spawns the
/// accept loop on the CURRENT tokio runtime (the JNI export owns a dedicated runtime — NEVER the
/// resolver's current-thread one), and returns the port. Each accepted connection routes through the SAME
/// pure decision the struct exposes ([`MirrorServer::serve_name`] / [`MirrorServer::outcome_to_response`]):
/// here the catalog is the default (empty) one, so EVERY name is `NotInCatalog` ⇒ 404 fail-closed until a
/// signature-verified catalog is installed (the deferred #85 datapath). The shared cache is locked
/// per-request for the serve verdict, then released immediately — a held lock never spans an `.await`.
///
/// Loopback-only (no LAN), fail-closed (unverified bytes are never served), additive + default-inert (this
/// only runs when the JNI export is called, which only fires behind the `CENTAURI_MIRROR_ENABLED` flag).
/// The legacy default-catalog shape — delegates to [`run_shared`] with an empty catalog, no observer, and
/// NO fetch context (every name fail-closed 404, a miss is a 503 with zero egress), byte-identical semantics.
pub async fn run(config: ServerConfig, cache: Arc<Mutex<CacheStore>>) -> Result<u16, ServerError> {
    run_shared(config, Catalog::default(), cache, None, None).await
}

/// #85 — the LIVE loopback's optional fetch-on-miss context: the ring-pinned TLS, the shared single-flight
/// coordinator, and the crown mode. Bound ONLY by the Centauri Object's serve engine
/// ([`super::object::Centauri::start`]); the legacy [`run`] path passes `None`.
///
/// When present, an AUTHORIZED CDN asset that missed the cache escalates to EXACTLY ONE `fetch_once` (the ≤ 1
/// crown) through [`super::serve::serve_addressed`] — the SAME single-flight, hash-verify-on-write, fail-
/// closed privacy flow proven host-side in `serve.rs`. When `None`, a miss stays a 503 exactly as before (no
/// egress). The three fields are cheap to clone per-connection (`Arc` + a `Copy` mode); the `InFlight` is
/// SHARED across all connections (one coordinator ⇒ concurrent misses for one asset drive AT MOST one fetch).
#[derive(Clone)]
pub struct FetchCtx {
    /// The FIX-2 shared ring-pinned rustls client config the one allowed GET rides (https-only in `fetch_once`).
    pub tls: Arc<rustls::ClientConfig>,
    /// The per-content-address single-flight coordinator — SHARED across connections so `≤ 1` holds under
    /// concurrency (the second concurrent miss for an asset awaits the first, then serves the warm cache).
    pub inflight: Arc<super::serve::InFlight>,
    /// The crown mode: `LeakOnMiss` (safe default — self-fill ≤ 1) or `BlockMissing` (strict — CDN sees 0).
    pub mode: super::serve::CacheMode,
}

/// SEAM:99 generalized (D04/D29) — bind the loopback Centauri Mirror over a **live shared cache** + an
/// **installed catalog** + an optional per-serve [`ServeObserver`], report the OS-assigned port, and KEEP
/// SERVING in the background.
///
/// This is the Centauri Object's serve engine ([`super::object::Centauri::start`] drives it): because the
/// cache is the SAME `Arc<Mutex<CacheStore>>` the Object owns, a `warm_up` self-fill (or any later verified
/// insert) is servable by the RUNNING loopback immediately — no restart, no stale serve-snapshot — and the
/// snapshot the dashboard reads is the EXACT store the loopback serves (the read-stats-vs-serve-bytes
/// identity, now literal). The observer (when bound) is called once per served request with the borrowed
/// [`ServeTrace`], feeding the CROWN counters + the recent-serve ring + `query-centauri.log` (D29).
///
/// The shared cache is locked per-request for the synchronous serve verdict, then released immediately — a
/// held lock never spans an `.await`; serves are zero-copy (`Arc<[u8]>`, D24). Loopback-only, fail-closed.
pub async fn run_shared(
    config: ServerConfig,
    catalog: Catalog,
    cache: Arc<Mutex<CacheStore>>,
    observer: Option<ServeObserver>,
    fetch_ctx: Option<FetchCtx>,
) -> Result<u16, ServerError> {
    // Bind the loopback listener and learn the OS-assigned port BEFORE the accept loop takes the listener,
    // so the caller can hand the port to the in-app client (the bind-before-accept split, mirrored from the
    // struct's bind()/accept_loop()).
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, config.port))
        .await
        .map_err(|_| ServerError::Bind)?;
    let port = listener.local_addr().map_err(|_| ServerError::Bind)?.port();

    // Spawn the accept loop on the current runtime so this fn returns the port while serving continues.
    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break, // a fatal accept fault ends this background server (loopback-only).
            };
            let io = TokioIo::new(stream);
            let cache = Arc::clone(&cache);
            let catalog = catalog.clone();
            let observer = observer.clone();
            let fetch_ctx = fetch_ctx.clone();
            let service = service_fn(move |req: Request<Incoming>| {
                let cache = Arc::clone(&cache);
                let catalog = catalog.clone();
                let observer = observer.clone();
                let fetch_ctx = fetch_ctx.clone();
                async move {
                    // ★ #22 THE READ-ONLY LAW — gate the verb BEFORE any resolve, serve, or upstream fetch.
                    // This is the surface the device actually runs (observer + fetch-on-miss), so the law has
                    // to hold HERE or it does not hold at all. Gating first also means a write never triggers
                    // the ≤1 upstream leak: refusing it costs zero requests.
                    if !is_servable_method(req.method()) {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::METHOD_NOT_ALLOWED)
                                .header(hyper::header::ALLOW, "GET, HEAD")
                                .body(Full::new(Bytes::new()))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        );
                    }
                    // Extract the routing inputs (owned) BEFORE locking — host-aware (slice 2): a request
                    // carrying `Host: <cdn>` routes as a CDN URL, else by path. No borrow held across the lock.
                    let path = req.uri().path().to_string();
                    let host = req
                        .headers()
                        .get(hyper::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    // Lock the shared cache ONLY for the synchronous serve verdict, never across an await.
                    let (outcome, resolution) = {
                        let guard = match cache.lock() {
                            Ok(g) => g,
                            // A poisoned mutex ⇒ fail-closed 503 (never serve unverified bytes on a fault).
                            Err(_) => {
                                return Ok::<_, Infallible>(MirrorServer::outcome_to_response(
                                    ServeOutcome::CacheMiss([0u8; 32]),
                                ))
                            }
                        };
                        route_host_aware_traced(&catalog, &guard, &host, &path)
                    };
                    // #85 — the LIVE loopback fetch-on-miss seam. An AUTHORIZED CDN asset that missed the
                    // cache (`CacheMiss` carries its catalog-pinned content address) escalates to EXACTLY ONE
                    // upstream `fetch_once` (the ≤ 1 crown) through the single-flight privacy flow
                    // ([`super::serve::serve_addressed`]) — hash-verified on write, cached, then served
                    // (`LeakedThenServed`). Fires ONLY when a `FetchCtx` is bound (the Object's serve engine)
                    // AND the request resolved to a mapped CDN origin (a real upstream URL exists). A path-
                    // keyed miss, an unmapped host, or the legacy `run` path (no `FetchCtx`) stays a fail-
                    // closed 503 — never a second fetch, never unverified bytes. The cache lock above is
                    // already released; the keyed single-flight lock (not the cache lock) is the only one held
                    // across the fetch await, exactly as `serve_addressed` documents.
                    let outcome = match (outcome, fetch_ctx.as_ref()) {
                        // ★ #65 THE ABSORB LEG — a promoted discovered host's asset, met for the first
                        // time. Fetch it ONCE (trust-on-first-use: there is no pin, because nothing about
                        // this asset was known before the request), address what arrived, admit it to the
                        // content-addressed cache, and remember the binding so every later request for the
                        // same URL is served locally with ZERO egress. Any failure fail-closes to a 503 —
                        // never unaddressed bytes, and never a second fetch for the same miss.
                        (ServeOutcome::AbsorbMiss(name), Some(fc)) => {
                            match super::absorb::absorb_url(host_without_port(&host), &path) {
                                Some(url) => {
                                    let tls = Arc::clone(&fc.tls);
                                    match super::fetch::fetch_absorb(&url, tls).await {
                                        Ok((bytes, hash)) => {
                                            // Admit under the address of the bytes themselves, so the
                                            // cache's verify-on-insert law holds exactly as it does for a
                                            // catalog-pinned asset.
                                            let admitted = match cache.lock() {
                                                Ok(mut store) => store
                                                    .insert_verified(hash, bytes)
                                                    .and_then(|_| store.get(&hash))
                                                    .map(|e| e.bytes_arc()),
                                                Err(_) => None,
                                            };
                                            match admitted {
                                                Some(arc) => {
                                                    super::absorb::remember(name, hash);
                                                    ServeOutcome::LeakedThenServed(arc)
                                                }
                                                None => ServeOutcome::CacheMiss(hash),
                                            }
                                        }
                                        Err(_) => ServeOutcome::CacheMiss([0u8; 32]),
                                    }
                                }
                                None => ServeOutcome::CacheMiss([0u8; 32]),
                            }
                        }
                        (ServeOutcome::CacheMiss(hash), Some(fc)) => {
                            match super::localcdn::upstream_url_for(host_without_port(&host), &path) {
                                Some(url) => {
                                    let tls = Arc::clone(&fc.tls);
                                    let verdict = super::serve::serve_addressed(
                                        &cache,
                                        &fc.inflight,
                                        fc.mode,
                                        hash,
                                        move |h| {
                                            let url = url.clone();
                                            async move {
                                                super::serve::fetch_leg(&url, h, tls)
                                                    .await
                                                    .map_err(|_| ())
                                            }
                                        },
                                    )
                                    .await;
                                    match verdict {
                                        super::serve::ServeVerdict::ServedLocal(b) => {
                                            ServeOutcome::Served(b)
                                        }
                                        super::serve::ServeVerdict::LeakedThenServed(b) => {
                                            ServeOutcome::LeakedThenServed(b)
                                        }
                                        // Strict-mode block, a failed/oversize/tampered fetch, or the (here
                                        // unreachable — we hold the pinned hash) not-in-catalog verdict all
                                        // fail-closed to a 503: never serve unverified or unavailable bytes.
                                        _ => ServeOutcome::CacheMiss(hash),
                                    }
                                }
                                // A watched host with no reconstructable upstream (unmapped path) ⇒ 503.
                                None => ServeOutcome::CacheMiss(hash),
                            }
                        }
                        (other, _) => other,
                    };
                    // D29 — the review channel: hand the traced serve to the bound observer (borrowed, no
                    // alloc on the serve path). The lock is already released; the outcome's Served arm is a
                    // shared Arc so the observer costs O(1) even when it keeps the byte count.
                    if let Some(obs) = observer.as_ref() {
                        obs(ServeTrace {
                            host: host_without_port(&host),
                            path: &path,
                            resolution: resolution.as_ref(),
                            outcome: &outcome,
                        });
                    }
                    Ok::<_, Infallible>(MirrorServer::outcome_to_response(outcome))
                }
            });
            // Per-conn serve errors are swallowed — one bad client never tears the background loop down.
            tokio::spawn(async move {
                let builder = ServerConnBuilder::new();
                let _ = builder.serve_connection(io, service).await;
            });
        }
    });

    Ok(port)
}

/// The pure serve verdict over a shared (locked) cache + a catalog — the same decision as
/// [`MirrorServer::serve_name`], factored so the `Arc<Mutex<CacheStore>>` free [`run`] path can reuse it
/// without owning the cache by value. Fail-closed: an unknown name is `NotInCatalog`, a miss is `CacheMiss`.
fn serve_shared(catalog: &Catalog, cache: &CacheStore, name: &str) -> ServeOutcome {
    let hash = match catalog.content_hash_for(name) {
        Some(h) => h,
        None => return note_serve(ServeOutcome::NotInCatalog), // unauthorized ⇒ 404 (fail-closed)
    };
    match cache.get(&hash) {
        // D24 zero-copy: clone the shared Arc handle, never memcpy the asset per serve.
        Some(entry) => note_serve(ServeOutcome::Served(entry.bytes_arc())),
        None => note_serve(ServeOutcome::CacheMiss(hash)),
    }
}

// ---------------------------------------------------------------------------------------------
// ★ THE SERVE LEDGER — the instrument that did not exist.
//
// MEASURED 2026-08-01: after wiring the cloak's trust conjunct, the DNS plane demonstrably worked
// (`centauri_cloak_sinkholes` 0 → 11, watched host answering 10.1.10.3 instead of the real CDN),
// and there was NO WAY TO TELL whether a single byte had ever been served. The counter reached
// for first, `cloak_actions`, turned out to count blocklist ZeroSink/CustomIp answers
// (`resolver/mod.rs:2445-2462`) and can never move for Centauri at all — so "is the offline-CDN
// serving?" was being answered with a number that measures something else entirely.
//
// The mirror's only atomics lived inside `#[cfg(test)]`. A pillar whose central claim
// ("absorb once, serve forever") has no production instrument cannot be proved to work, and a
// dashboard that says LIVE on top of that is reporting a wish. This is the honest denominator:
// every outcome the shared serve path can produce, counted where it is produced.
// ---------------------------------------------------------------------------------------------

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

/// Assets served from the content-addressed store with ZERO egress — the number that makes the
/// offline-CDN claim true or false.
static SERVE_HITS: AtomicU64 = AtomicU64::new(0);
/// Bytes served locally. The user-visible size of "never fetched twice".
static SERVE_BYTES: AtomicU64 = AtomicU64::new(0);
/// Authorized by the signed catalog but absent from the store ⇒ the fetch-ONCE leg runs.
static SERVE_MISSES: AtomicU64 = AtomicU64::new(0);
/// Requests the signed catalog does not authorize ⇒ 404, fail-closed.
static SERVE_UNAUTHORIZED: AtomicU64 = AtomicU64::new(0);

/// Count one serve outcome and hand it straight back, so counting can never change the decision.
///
/// Placed at the RETURN of the shared path rather than at its call sites: a counter at a call site
/// is one refactor away from being bypassed, and this must not be able to drift from what actually
/// happened.
/// Which bucket a serve outcome belongs to. Separated from the counting so the CLASSIFICATION —
/// the part that can actually be wrong — is a pure function, testable exhaustively and without the
/// cross-test interference that global atomics inflict on any exact-delta assertion.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum ServeBucket {
    /// Served from the store with zero egress, carrying the payload size.
    Hit(u64),
    /// Authorized by the catalog, absent from the store ⇒ the fetch-once leg.
    Miss,
    /// The signed catalog refused it (unknown asset, or a blocked fingerprinter) ⇒ 404/403.
    Refused,
    /// Deliberately uncounted — see `classify_serve`.
    Uncounted,
}

/// Classify one serve outcome. PURE: no atomics, no I/O, total over the enum.
///
/// The live fetch-and-serve leg is `Uncounted` ON PURPOSE. It cost a request upstream, so folding
/// it into the zero-egress hit count would overstate the exact property this ledger exists to
/// measure — "absorb once, serve forever" is a claim about serves that cost NOTHING.
pub(crate) fn classify_serve(outcome: &ServeOutcome) -> ServeBucket {
    match outcome {
        ServeOutcome::Served(bytes) => ServeBucket::Hit(bytes.len() as u64),
        ServeOutcome::CacheMiss(_) => ServeBucket::Miss,
        ServeOutcome::NotInCatalog | ServeOutcome::BlockedFingerprinter => ServeBucket::Refused,
        _ => ServeBucket::Uncounted,
    }
}

pub(crate) fn note_serve(outcome: ServeOutcome) -> ServeOutcome {
    match classify_serve(&outcome) {
        ServeBucket::Hit(n) => {
            SERVE_HITS.fetch_add(1, AtomicOrdering::Relaxed);
            SERVE_BYTES.fetch_add(n, AtomicOrdering::Relaxed);
        }
        ServeBucket::Miss => {
            SERVE_MISSES.fetch_add(1, AtomicOrdering::Relaxed);
        }
        ServeBucket::Refused => {
            SERVE_UNAUTHORIZED.fetch_add(1, AtomicOrdering::Relaxed);
        }
        ServeBucket::Uncounted => {}
    }
    outcome
}

/// Assets served locally, with zero egress.
pub fn serve_hits() -> u64 {
    SERVE_HITS.load(AtomicOrdering::Relaxed)
}

/// Bytes served locally.
pub fn serve_bytes() -> u64 {
    SERVE_BYTES.load(AtomicOrdering::Relaxed)
}

/// Authorized-but-uncached requests (the fetch-once leg).
pub fn serve_misses() -> u64 {
    SERVE_MISSES.load(AtomicOrdering::Relaxed)
}

/// Requests the signed catalog refused.
pub fn serve_unauthorized() -> u64 {
    SERVE_UNAUTHORIZED.load(AtomicOrdering::Relaxed)
}

/// Strip an optional `:port` suffix from a `Host` header value, returning the bare hostname (the
/// trim/lowercase/FQDN-dot normalization is left to [`super::localcdn::is_cdn_host`] / `resolve`):
/// `cdnjs.cloudflare.com:443` → `cdnjs.cloudflare.com`; a bare `cdnjs.cloudflare.com` is unchanged. A
/// bracketed IPv6 literal (`[::1]:8080`) — never a CDN hostname — is returned unchanged (it simply won't
/// match `is_cdn_host`), so this never mis-splits on an IPv6 colon.
fn host_without_port(host: &str) -> &str {
    let h = host.trim();
    if h.starts_with('[') {
        return h; // IPv6 literal — not a CDN hostname; leave intact (won't match is_cdn_host)
    }
    match h.split_once(':') {
        Some((name, _port)) => name,
        None => h,
    }
}

/// ★ #22 THE READ-ONLY LAW — is this verb one the mirror may answer from cache?
///
/// `GET` and `HEAD` are the only safe+idempotent verbs whose response is the resource itself, so they are the
/// only ones a content-addressed cache can honestly satisfy. Everything else (`POST`/`PUT`/`PATCH`/`DELETE`,
/// and anything non-standard) carries INTENT TO CHANGE STATE at the origin, which a local cache cannot do and
/// must not pretend to have done.
///
/// Pure + allocation-free so both serve surfaces can gate on it without drifting, and so the law is testable
/// without standing up a socket.
fn is_servable_method(method: &hyper::Method) -> bool {
    matches!(*method, hyper::Method::GET | hyper::Method::HEAD)
}

/// Host-aware routing for one loopback request (slice 2 — the DNS-plane→loopback serve), shared by the
/// by-value [`MirrorServer::handle`] and the `Arc<Mutex<CacheStore>>` free [`run`] service so the two serve
/// surfaces never drift. When the request carries a `Host` header naming a watched-CDN host
/// ([`super::localcdn::is_cdn_host`]), translate the CDN URL to its canonical catalog asset name + serve it
/// (the [`MirrorServer::serve_cdn_url`] semantics: `Host: cdnjs.cloudflare.com` + `/lib/version/file` →
/// `<library>/<served_version>/<file>` → signed-catalog authorize → content-addressed serve); otherwise
/// fall back to the path-keyed [`MirrorServer::serve_name`]. Fail-closed throughout — an unmapped/
/// unauthorized URL is `NotInCatalog`, an authorized-but-uncached one is `CacheMiss` (never unverified bytes).
fn route_host_aware(catalog: &Catalog, cache: &CacheStore, host: &str, path: &str) -> ServeOutcome {
    route_host_aware_traced(catalog, cache, host, path).0
}

/// The TRACED twin of [`route_host_aware`] — the same decision, ALSO carrying the LocalCDN [`Resolution`]
/// when the request routed as a CDN URL, so the [`ServeObserver`] review channel (D29) can record library /
/// versions / substitution without a second resolve. The untraced wrapper keeps every existing caller
/// byte-identical (one decision, two surfaces, never a drift).
fn route_host_aware_traced(
    catalog: &Catalog,
    cache: &CacheStore,
    host: &str,
    path: &str,
) -> (ServeOutcome, Option<Resolution>) {
    let host = host_without_port(host);
    // BadResources hard-block (consulted first): a known fingerprinter is denied outright — never resolved,
    // never served, never leaked (the fingerprinter must not load).
    if super::localcdn::is_blocked_fingerprinter(host, path) {
        return (ServeOutcome::BlockedFingerprinter, None);
    }
    if !host.is_empty() && super::localcdn::is_cdn_host(host) {
        // Catalog-addressed resolve (coverage gate) — never commit to a version the signed catalog cannot
        // serve; a map-bundled-but-uncatalogued request falls back to a COVERED substitute or fail-closes
        // here instead of 404-blackholing in `serve_shared` (the jquery-3.5.1 Exact-resolve bug).
        match super::localcdn::resolve_addressed(host, path, catalog, 0) {
            Some(ar) => {
                let outcome = serve_shared(catalog, cache, &ar.resolution.canonical_name());
                (outcome, Some(ar.resolution))
            }
            // ★ #65 — no ResourceMap covered this request. WHY the host is cloaked decides what happens:
            //
            // * A CORPUS host stays fail-closed. This build ships its coverage, so an uncovered path is a
            //   real miss and 404 is the honest answer (the deliberate jquery-3.5.1 behaviour).
            // * A PROMOTED host has no map at ALL — discovery earned it into the roster precisely because
            //   this build had never heard of it. Fail-closing here would 404 every asset on a CDN the user
            //   actually browses, so it takes the ABSORB lane: serve the bound content address if this
            //   device already absorbed it, otherwise hand the caller the name to absorb once.
            None if super::localcdn::is_promoted_host(host) => {
                let name = super::absorb::absorb_name(host, path);
                match super::absorb::lookup(&name).and_then(|h| cache.get(&h)) {
                    // Already absorbed AND still cached ⇒ a 0-egress local serve (the whole point).
                    Some(entry) => (ServeOutcome::Served(entry.bytes_arc()), None),
                    // Never absorbed, or absorbed and since evicted ⇒ absorb it once.
                    None => (ServeOutcome::AbsorbMiss(name), None),
                }
            }
            None => (ServeOutcome::NotInCatalog, None), // a watched host, an uncovered path ⇒ fail-closed
        }
    } else {
        (
            serve_shared(catalog, cache, MirrorServer::request_name(path)),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::cache::content_hash;

    /// ★ #65 — a PROMOTED host must never fail-closed. Discovery earned it into the roster precisely
    /// because this build ships no map for it, so the corpus 404 would break every asset on a CDN the
    /// user actually browses. It takes the absorb lane instead, named by the URL it will fetch once.
    #[test]
    fn a_promoted_host_absorbs_instead_of_404() {
        let catalog = Catalog::default();
        let cache = CacheStore::new();
        let host = "cdn.absorb-routing-test.example";

        // Before promotion this host is not cloaked at all — it is simply not Centauri's business, so it
        // falls to the path-keyed lane and fail-closes against the empty catalog.
        assert_eq!(
            route_host_aware(&catalog, &cache, host, "/lib/app.js"),
            ServeOutcome::NotInCatalog,
            "an unpromoted unknown host is untouched"
        );

        crate::mirror::localcdn::publish_promoted_cloak(vec![host.to_string()]);
        let outcome = route_host_aware(&catalog, &cache, host, "/lib/app.js");
        crate::mirror::localcdn::publish_promoted_cloak(Vec::new()); // restore the process-global

        match outcome {
            ServeOutcome::AbsorbMiss(name) => assert_eq!(
                name,
                format!("{host}/lib/app.js"),
                "the absorb name is the URL fetched exactly once, then served locally forever"
            ),
            other => panic!("a promoted host must absorb, not fail-closed; got {other:?}"),
        }
    }

    /// ★ #22 THE READ-ONLY LAW — the mirror may answer reads and nothing else.
    ///
    /// The defect this pins: both serve surfaces routed on the PATH alone and never read the verb, so a
    /// write whose path named a catalogued asset came back `200 OK` carrying the cached READ body. The
    /// origin never saw the request, and the caller could not tell its write had evaporated. That silent
    /// loss is precisely why the cloak set has been confined to unambiguous read-only CDN hosts — a host
    /// that mixes reads and writes (an upload endpoint on a CDN domain) could not be cloaked safely.
    ///
    /// A cloaked host resolves to `127.0.0.1`, so there is no origin socket to forward a write to. 405 is
    /// the honest answer: it fails loudly at the caller instead of corrupting its state.
    #[test]
    fn the_mirror_answers_reads_and_refuses_writes() {
        assert!(is_servable_method(&hyper::Method::GET), "GET is the serve case");
        assert!(
            is_servable_method(&hyper::Method::HEAD),
            "HEAD is GET without the body — same cached resource, safe to answer"
        );
        for verb in [
            hyper::Method::POST,
            hyper::Method::PUT,
            hyper::Method::PATCH,
            hyper::Method::DELETE,
        ] {
            assert!(
                !is_servable_method(&verb),
                "{verb} intends to change state at the ORIGIN — a local cache must never answer it"
            );
        }
    }

    #[test]
    fn unknown_name_is_not_served_fail_closed() {
        let server = MirrorServer::new(
            ServerConfig::default(),
            Catalog::default(),
            CacheStore::new(),
        );
        assert_eq!(server.serve_name("anything"), ServeOutcome::NotInCatalog);
    }

    #[test]
    fn fingerprinter_url_is_hard_blocked_not_served_not_leaked() {
        // BadResources: a known fingerprinting library is denied (403) BEFORE any resolve/serve, on BOTH
        // serve entry points — never served locally, never leaked upstream (the fingerprinter must not load).
        let server = MirrorServer::new(
            ServerConfig::default(),
            Catalog::default(),
            CacheStore::new(),
        );
        let fp_host = "cdnjs.cloudflare.com";
        let fp_path = "/ajax/libs/fingerprintjs/3.4.2/fp.min.js";
        assert_eq!(
            server.serve_cdn_url(fp_host, fp_path),
            ServeOutcome::BlockedFingerprinter,
            "serve_cdn_url must hard-block a fingerprinter"
        );
        assert_eq!(
            route_host_aware(&Catalog::default(), &CacheStore::new(), fp_host, fp_path),
            ServeOutcome::BlockedFingerprinter,
            "the live route must hard-block a fingerprinter"
        );
        // A benign library on the SAME CDN host must NOT be fingerprint-blocked.
        assert_ne!(
            route_host_aware(
                &Catalog::default(),
                &CacheStore::new(),
                fp_host,
                "/ajax/libs/jquery/3.7.1/jquery.min.js"
            ),
            ServeOutcome::BlockedFingerprinter,
            "a benign library must not be fingerprint-blocked"
        );
        // The block maps to 403 Forbidden (no bytes).
        let resp = MirrorServer::outcome_to_response(ServeOutcome::BlockedFingerprinter);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn default_config_is_loopback_ephemeral() {
        assert_eq!(ServerConfig::default().port, 0, "ephemeral by default");
    }

    // ---- #134 LocalCDN→Centauri serve bridge (fail-closed twice over) ----

    #[test]
    fn cdn_url_unmapped_host_is_not_served() {
        // A CDN URL whose host isn't in the resource-map never resolves to a name ⇒ fail-closed.
        let server = MirrorServer::new(
            ServerConfig::default(),
            Catalog::default(),
            CacheStore::new(),
        );
        assert_eq!(
            server.serve_cdn_url("evil.example.com", "/ajax/libs/jquery/3.6.0/jquery.min.js"),
            ServeOutcome::NotInCatalog,
        );
    }

    #[test]
    fn cdn_url_mapped_but_uncatalogued_is_not_served() {
        // The resource-map RESOLVES this URL (googleapis jQuery 3.6.0 → jquery/3.6.0/jquery.min.js), but the
        // signed catalog is empty ⇒ still NotInCatalog. The map names the URL grammar; ONLY the verified
        // catalog authorizes a serve — the map alone never serves bytes.
        let server = MirrorServer::new(
            ServerConfig::default(),
            Catalog::default(),
            CacheStore::new(),
        );
        assert_eq!(
            server.serve_cdn_url(
                "ajax.googleapis.com",
                "/ajax/libs/jquery/3.6.0/jquery.min.js"
            ),
            ServeOutcome::NotInCatalog,
        );
    }

    // ---- #134 END-TO-END serve proof: a CDN URL → Served bytes through the WHOLE chain ----
    // resolve_full (URL → canonical name) → signature-verified Catalog (authorize) → content-addressed
    // CacheStore (hash match) → Served. The positive serve path #134 is named for ("make the mirror actually
    // serve"), proven at the logic level WITHOUT a socket/device — the device only adds the loopback bind +
    // the live DNS cloak; this is the serve VERDICT, fully host-testable.

    /// The legacy-`Ed` key-id used by the test catalog signer (mirrors `catalog.rs` test helpers).
    const E2E_KEY_ID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    /// Build a genuinely-signed 1-entry `TCAT` catalog (the exact wire layout `catalog.rs:28-41` documents)
    /// naming `name` at content address `hash` for `host`, then run it through the REAL verify-sig-first
    /// `Catalog::parse_verified` — so the returned `Catalog` is proof the signature verified, identical to the
    /// on-device install path. Replicates the `catalog.rs` test signer (no production key involved).
    fn signed_catalog(name: &str, hash: ContentHash, host: &str) -> Catalog {
        use ed25519_dalek::{Signer, SigningKey};
        let mut body = Vec::new();
        body.extend_from_slice(b"TCAT"); // magic
        body.extend_from_slice(&1u16.to_le_bytes()); // version = 1
        body.push(2u8); // hash_algo_id = BLAKE2B
        body.push(0u8); // header flags
        body.extend_from_slice(&0u64.to_le_bytes()); // reserved
        body.extend_from_slice(&1u32.to_le_bytes()); // entry_count = 1
        body.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        body.push(0b0000_0001u8); // entry_flags: CLOAK
        body.extend_from_slice(&hash); // content_hash[32]
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&(host.len() as u16).to_le_bytes());
        body.extend_from_slice(host.as_bytes());

        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let mut pubkey = Vec::with_capacity(42);
        pubkey.extend_from_slice(b"Ed");
        pubkey.extend_from_slice(&E2E_KEY_ID);
        pubkey.extend_from_slice(&pk);
        let sig = sk.sign(&body);
        let mut sig_blob = Vec::with_capacity(74);
        sig_blob.extend_from_slice(b"Ed");
        sig_blob.extend_from_slice(&E2E_KEY_ID);
        sig_blob.extend_from_slice(&sig.to_bytes());

        Catalog::parse_verified(&body, &sig_blob, &pubkey)
            .expect("a genuinely signed 1-entry catalog verifies + parses")
    }

    /// THE LEDGER MUST ACTUALLY COUNT.
    ///
    /// The defect this whole instrument exists to answer was a counter that could never move for
    /// the thing it claimed to measure. Shipping an uncounted counter would repeat it exactly, so
    /// this drives all three outcomes through the real serve path and asserts each one lands in
    /// its OWN bucket — a hit must not be recorded as a miss, and a catalog refusal must not be
    /// recorded as either.
    #[test]
    fn the_serve_ledger_counts_hits_misses_and_refusals_separately() {
        // MY FIRST VERSION OF THIS TEST WAS WRONG, and the way it failed is worth keeping: it
        // asserted EXACT deltas against process-global atomics while the rest of the suite runs in
        // parallel and also drives the serve path (`left: 2, right: 1`). Exact deltas on a global
        // counter are unassertable under a parallel runner — the counter was fine, the test was
        // not. The repair is not a looser assertion but a better SEAM: the part that can actually
        // be wrong is the CLASSIFICATION, and that is now a pure function tested exhaustively.
        let bytes: Arc<[u8]> = Arc::from(b"// jQuery v3.7.1 | (c) OpenJS".as_slice());

        // Every variant, into its own bucket. A hit must never be a miss; a refusal must never be
        // either; and the live-fetch leg must never be folded into the zero-egress hit count.
        assert_eq!(
            classify_serve(&ServeOutcome::Served(bytes.clone())),
            ServeBucket::Hit(bytes.len() as u64),
            "a served asset is a HIT carrying its real size"
        );
        assert_eq!(
            classify_serve(&ServeOutcome::CacheMiss(content_hash(b"x"))),
            ServeBucket::Miss,
            "authorized but uncached is a MISS"
        );
        assert_eq!(
            classify_serve(&ServeOutcome::NotInCatalog),
            ServeBucket::Refused,
            "a catalog refusal is its OWN bucket"
        );
        assert_eq!(
            classify_serve(&ServeOutcome::BlockedFingerprinter),
            ServeBucket::Refused,
            "a fingerprinter block is a refusal, never a miss"
        );
    }

    /// The counters MOVE when the real serve path runs. Monotonic only — see the note above about
    /// exact deltas — but it still fails loudly if `note_serve` is ever bypassed, which is the
    /// failure this instrument exists to prevent.
    #[test]
    fn the_serve_ledger_is_actually_wired_to_the_serve_path() {
        let bytes = b"// jQuery v3.7.1 | (c) OpenJS - minified bytes".to_vec();
        let hash = content_hash(&bytes);
        let name = "jquery/3.7.1/jquery.min.js";

        let h0 = serve_hits();
        let b0 = serve_bytes();
        let catalog = signed_catalog(name, hash, "ajax.googleapis.com");
        let mut cache = CacheStore::new();
        assert_eq!(cache.insert_verified(hash, bytes.clone()), Some(hash));
        let server = MirrorServer::new(ServerConfig::default(), catalog, cache);
        assert!(matches!(server.serve_name(name), ServeOutcome::Served(_)));

        assert!(serve_hits() > h0, "a real serve must reach the ledger");
        assert!(
            serve_bytes() >= b0 + bytes.len() as u64,
            "the payload size must reach the ledger"
        );

        let m0 = serve_misses();
        let empty = MirrorServer::new(
            ServerConfig::default(),
            signed_catalog(name, hash, "ajax.googleapis.com"),
            CacheStore::new(),
        );
        assert!(matches!(empty.serve_name(name), ServeOutcome::CacheMiss(_)));
        assert!(serve_misses() > m0, "a real miss must reach the ledger");

        let u0 = serve_unauthorized();
        assert!(matches!(
            empty.serve_name("not-authorized/evil.js"),
            ServeOutcome::NotInCatalog
        ));
        assert!(serve_unauthorized() > u0, "a real refusal must reach the ledger");
    }

    #[test]
    fn cdn_url_served_end_to_end_when_catalogued_and_cached() {
        // jQuery 3.7.1 IS bundled (FULL_MAPS) → the URL resolves to canonical "jquery/3.7.1/jquery.min.js".
        let bytes = b"// jQuery v3.7.1 | (c) OpenJS - minified bytes".to_vec();
        let hash = content_hash(&bytes);
        let name = "jquery/3.7.1/jquery.min.js";
        let catalog = signed_catalog(name, hash, "ajax.googleapis.com");
        let mut cache = CacheStore::new();
        assert_eq!(cache.insert_verified(hash, bytes.clone()), Some(hash));
        let server = MirrorServer::new(ServerConfig::default(), catalog, cache);

        // The WHOLE chain: CDN URL → resolve → canonical name → catalog authorize → cache hit → Served bytes.
        assert_eq!(
            server.serve_cdn_url(
                "ajax.googleapis.com",
                "/ajax/libs/jquery/3.7.1/jquery.min.js"
            ),
            ServeOutcome::Served(bytes.into()),
            "the mirror SERVES the cached, signature-catalogued asset for a real CDN URL",
        );
    }

    // ---- slice 2: host-aware routing — a `Host: <cdn>` header drives the CDN-URL serve ----

    #[test]
    fn route_host_aware_serves_by_cdn_host_header_else_by_path() {
        // The host-aware seam a DNS-cloaked / app-self-redirected request lands on: a request carrying the
        // original CDN host in its `Host` header is served from the signed catalog + content-addressed cache.
        let bytes = b"// jQuery v3.7.1 bytes".to_vec();
        let hash = content_hash(&bytes);
        let name = "jquery/3.7.1/jquery.min.js";
        let catalog = signed_catalog(name, hash, "ajax.googleapis.com");
        let mut cache = CacheStore::new();
        assert_eq!(cache.insert_verified(hash, bytes.clone()), Some(hash));

        // (1) A watched-CDN `Host` header (with a stray `:443`) → the CDN-URL serve → Served bytes.
        assert_eq!(
            route_host_aware(
                &catalog,
                &cache,
                "ajax.googleapis.com:443",
                "/ajax/libs/jquery/3.7.1/jquery.min.js"
            ),
            ServeOutcome::Served(bytes.clone().into()),
            "a Host: <cdn>:443 header routes via the CDN-URL serve to the cached signed asset",
        );

        // (2) A non-CDN `Host` header → the path-keyed serve_name (here the path IS the canonical name).
        assert_eq!(
            route_host_aware(&catalog, &cache, "localhost", "/jquery/3.7.1/jquery.min.js"),
            ServeOutcome::Served(bytes.into()),
            "a non-CDN host falls back to the path-keyed serve_name",
        );

        // (3) A watched-CDN host but an UNMAPPED path → fail-closed NotInCatalog (never the real CDN).
        assert_eq!(
            route_host_aware(
                &catalog,
                &cache,
                "ajax.googleapis.com",
                "/not/a/mapped/path"
            ),
            ServeOutcome::NotInCatalog,
            "a watched host with an unmapped path is fail-closed, not blindly served",
        );

        // host_without_port: strips a port, leaves a bare host + a bracketed IPv6 literal intact.
        assert_eq!(
            host_without_port("ajax.googleapis.com:443"),
            "ajax.googleapis.com"
        );
        assert_eq!(
            host_without_port("cdnjs.cloudflare.com"),
            "cdnjs.cloudflare.com"
        );
        assert_eq!(host_without_port("[::1]:8080"), "[::1]:8080");
    }

    #[test]
    fn cdn_url_catalogued_but_uncached_is_cache_miss_not_served() {
        // Authorized by the signed catalog but absent from the cache ⇒ CacheMiss(hash) (the caller runs the
        // fetch-once-verify-cache leg), NEVER NotInCatalog and NEVER unverified bytes.
        let bytes = b"// jQuery v3.7.1 bytes".to_vec();
        let hash = content_hash(&bytes);
        let catalog = signed_catalog("jquery/3.7.1/jquery.min.js", hash, "ajax.googleapis.com");
        let server = MirrorServer::new(ServerConfig::default(), catalog, CacheStore::new()); // empty cache
        assert_eq!(
            server.serve_cdn_url(
                "ajax.googleapis.com",
                "/ajax/libs/jquery/3.7.1/jquery.min.js"
            ),
            ServeOutcome::CacheMiss(hash),
            "authorized-but-uncached is a fetch-once miss, never an unverified serve",
        );
    }

    #[test]
    fn cache_miss_surfaces_the_expected_content_hash() {
        // A cache with one asset whose content address we know — but a catalog that has no entries yet
        // (scaffold parse) routes everything to NotInCatalog, so this asserts the cache helper directly.
        let mut cache = CacheStore::new();
        let bytes = b"asset".to_vec();
        let h = content_hash(&bytes);
        assert_eq!(cache.insert_verified(h, bytes), Some(h));
        assert!(
            cache.get(&h).is_some(),
            "a verified asset is retrievable by content address"
        );
    }

    // ---- FIX-1: the socket-facing half (pure, host-testable without opening a socket) ----

    #[test]
    fn request_name_strips_the_single_leading_slash() {
        // The loopback path `/blocklist.tblk` routes on the catalog name `blocklist.tblk`.
        assert_eq!(
            MirrorServer::request_name("/blocklist.tblk"),
            "blocklist.tblk"
        );
        // A bare root `/` yields the empty name (which the fail-closed catalog rejects).
        assert_eq!(MirrorServer::request_name("/"), "");
        // No leading slash (defensive) ⇒ unchanged.
        assert_eq!(MirrorServer::request_name("nested/path"), "nested/path");
    }

    #[test]
    fn served_outcome_maps_to_200_octet_stream() {
        let body = b"the verified asset bytes".to_vec();
        let resp = MirrorServer::outcome_to_response(ServeOutcome::Served(body.into()));
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(hyper::header::CONTENT_TYPE)
                .map(|v| v.as_bytes()),
            Some(b"application/octet-stream".as_ref()),
            "served bytes carry the octet-stream content type",
        );
    }

    #[test]
    fn leaked_then_served_maps_to_200_octet_stream_like_a_local_hit() {
        // #85 — the fetch-on-miss seam fired: the ≤ 1 self-fill fetched + hash-verified the asset, so the
        // client sees an ordinary 200 octet-stream — INDISTINGUISHABLE from a local hit (the leak is a
        // privacy fact for the CROWN counters, never a different HTTP contract to the browser).
        let body = b"the fetched-once verified asset".to_vec();
        let resp = MirrorServer::outcome_to_response(ServeOutcome::LeakedThenServed(body.into()));
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(hyper::header::CONTENT_TYPE)
                .map(|v| v.as_bytes()),
            Some(b"application/octet-stream".as_ref()),
        );
    }

    #[test]
    fn not_in_catalog_maps_to_404_fail_closed() {
        // The fail-closed verdict: an unauthorized name is a 404, never served bytes.
        let resp = MirrorServer::outcome_to_response(ServeOutcome::NotInCatalog);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn cache_miss_maps_to_503_not_404() {
        // An AUTHORIZED-but-not-yet-cached asset is 503 (run the fetch-once leg), distinct from the
        // unauthorized 404 — the client never sees unverified bytes either way.
        let resp = MirrorServer::outcome_to_response(ServeOutcome::CacheMiss([7u8; 32]));
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(resp.status(), StatusCode::NOT_FOUND, "miss != unauthorized");
    }

    #[test]
    fn bind_opens_a_loopback_ephemeral_port_and_reads_it_back() {
        // GROUND_TRUTH the bind half WITHOUT an accept loop: an ephemeral (port 0) config really binds
        // 127.0.0.1 and reports a non-zero OS-assigned port. Drives one block_on on a fresh current-thread
        // runtime (the same runtime shape the resolver owns), so the test needs no #[tokio::test] attr.
        let server = MirrorServer::new(
            ServerConfig::default(),
            Catalog::default(),
            CacheStore::new(),
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        let (listener, port) = rt
            .block_on(server.bind())
            .expect("an ephemeral loopback bind must succeed");
        assert_ne!(
            port, 0,
            "port 0 ⇒ the OS assigns a real ephemeral port, read back here"
        );
        assert_eq!(
            listener.local_addr().unwrap().ip(),
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            "the listener is bound to 127.0.0.1 (loopback-only, no LAN exposure)",
        );
    }
}
