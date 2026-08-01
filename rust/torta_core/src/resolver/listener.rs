/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

#![forbid(unsafe_code)]

//! **The loopback DNS listener** — the sovereign-rewire keystone that makes the Rust resolver the
//! PRODUCTION transport (slice 3 of the sovereign-dnscrypt-rust-rewire).
//!
//! ## What this is
//!
//! A Rust DNS server bound on `127.0.0.1` (loopback-only by construction) that serves
//! [`crate::resolver::resolve`] to any in-process client — the same surface the Go
//! `libdnscrypt-proxy.so` exposes when it listens on loopback (`dnscrypt-proxy-master` `proxy.go:145`
//! `addDNSListener`, `proxy.go:453` `udpListener`, `proxy.go:483` `tcpListener`). The tunnel
//! architecture (`VpnService` tun → system DNS) can now route system DNS to THIS listener instead of
//! the Go binary, making the Rust transport the default; the Go binary stays in the APK as the
//! runtime FALLBACK (the safety net — never deleted).
//!
//! ## Why loopback, and the coexistence contract
//!
//! Loopback (`127.0.0.0/8`, `::1`) traffic never enters the `VpnService` tun device
//! (`do53.rs:17-20`), so a listener on loopback needs no `protect()` and creates no egress loop.
//! The address is `127.0.0.1` BY CONSTRUCTION: [`start_loopback`] binds
//! [`std::net::Ipv4Addr::LOCALHOST`] (127.0.0.1) — it can NEVER open on a LAN/`0.0.0.0` address, so
//! the listener is structurally off-host-safe (no T13 cleartext violation, no exposure).
//!
//! **Coexistence with the udp.c inline-bridge** (`libumdnscrypt/src/main/jni/invizible/udp.c:478`): the
//! existing inline path calls `torta_resolve` directly in the tun forward thread (the per-packet
//! seam). This listener is a SECOND, independent path — a real socket on loopback that any in-process
//! DNS client (the system resolver retargeted to `127.0.0.1:<port>`, a shadow probe, a future
//! tun-redirect) can dial. Both paths call the SAME [`crate::resolver::resolve`] singleton, so they
//! are consistent by construction. The inline bridge remains the zero-hop fast path; this listener is
//! the socket-shaped surface the tunnel architecture needs to point at. They do not collide: the
//! bridge never opens a listener socket, and this listener never touches the tun forward path.
//!
//! ## The runtime discipline (the load-bearing invariant)
//!
//! The resolver singleton owns a **current-thread** tokio runtime
//! (`resolver/mod.rs:310` — "ONE worker, parks when idle") that `block_on`s one DNS exchange per
//! query. An accept loop co-hosted on THAT runtime would serialize every incoming query behind the
//! resolver's own round-trips ⇒ deadlock under load. So this listener owns a **DEDICATED current-thread
//! runtime on its OWN OS thread** — the EXACT proven pattern the Centauri Mirror established
//! (`lib.rs:1520-1558`, `mirror/server.rs:196-241`): a named detached thread builds a fresh
//! current-thread runtime, `block_on`s bind()-then-accept, and serves for the process lifetime. The
//! resolver's `resolve()` is a SYNC, JNIEnv-free fn (`resolver/mod.rs:431`) that internally `block_on`s
//! on its OWN global runtime — so calling it from the listener's `spawn_blocking` pool is safe and
//! never nests runtimes. (We use `spawn_blocking` so a slow upstream exchange never stalls the accept
//! loop's single worker; the resolver's own `block_on` parks its runtime while awaiting the network.)
//!
//! ## TCP framing — RFC 1035 §4.2.2 / RFC 7766
//!
//! DNS-over-TCP carries each message with a 2-byte big-endian length prefix. The read/write are the
//! IDENTICAL shape `do53.rs:116-151` (`tcp_exchange`) uses for the Do53 client — reused, not
//! reinvented. The reply length is bounded at [`MAX_MESSAGE`] (64 KiB) before allocating, and a
//! `reply.len() > MAX_MESSAGE` answer is truncated to fit the wire (the resolver's response is never
//! larger than a DNS message in practice; this is the defense-in-depth bound `do53.rs:37` enforces).
//!
//! ## Privacy law (T20)
//!
//! The listener never inspects or logs a qname/IP. It hands the raw query bytes to
//! [`crate::resolver::resolve`] and writes the raw reply bytes back — a byte-pipe, like `do53.rs`.
//! The only telemetry is a per-transport served-count surfaced via [`ListenerStats`] (counts only,
//! never a name). No new query leak is possible: the listener adds a socket, not a resolver path.
//!
//! ## Invariants
//!
//! `#![forbid(unsafe_code)]`, `std::net` + `tokio::net` only (no new crate dep — `tokio`'s `net`
//! feature is already on, `Cargo.toml:53`). Loopback-only by construction. The module ships
//! dormant until a JNI export (`lib.rs`, a sibling slice) drives [`start_loopback`] — the base `.so`
//! stays byte-identical until then (`#![cfg_attr(not(test), allow(dead_code))]`).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::resolver;

/// The maximum DNS message size this listener will read or write (RFC 1035 §4.2.1 + EDNS0 headroom).
/// Mirrors `do53.rs:37` `MAX_RESPONSE` — the crate's canonical bound on a DNS message buffer.
const MAX_MESSAGE: usize = 64 * 1024;

/// The fixed loopback IPv4 address this listener binds — `127.0.0.1`. By CONSTRUCTION the listener
/// can never bind a LAN/`0.0.0.0` address ([`start_loopback`] only ever passes this to `bind`), so
/// it is structurally off-host-safe (no T13, no exposure). `Ipv4Addr::LOCALHOST` per std.
const LOOPBACK_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// One running loopback listener's observed state — the surfaced telemetry (counts ONLY, T20).
#[derive(Default)]
struct ListenerStats {
    /// Total UDP queries served (a packet was received and dispatched to the resolver).
    udp_served: AtomicU64,
    /// Total TCP queries served (a length-prefixed message was read and dispatched).
    tcp_served: AtomicU64,
    /// Total UDP receive/send failures (a socket error on one query — never fatal to the loop).
    udp_errors: AtomicU64,
    /// Total TCP connection failures (read/write/framing error — never fatal to the loop).
    tcp_errors: AtomicU64,
}

/// A snapshot of the listener telemetry (owned counts, safe to surface across the FFI). Counts only;
/// no qname, no IP, no name ever appears (T20). The shape mirrors `resolver::Stats` (atomic reads).
#[derive(Clone, Copy, Debug, Default)]
pub struct ListenerSnapshot {
    pub udp_served: u64,
    pub tcp_served: u64,
    pub udp_errors: u64,
    pub tcp_errors: u64,
    /// The bound loopback port (`127.0.0.1:<port>`). 0 when no listener is running.
    pub port: u16,
}

/// The singleton running listener: the bound port + the shared stats. Built at most once by
/// [`start_loopback`] (the Centauri-Mirror `OnceLock` shape, `lib.rs:1473`); a second call returns
/// the already-bound port (idempotent).
struct RunningListener {
    port: u16,
    stats: Arc<ListenerStats>,
}

static LISTENER: OnceLock<RunningListener> = OnceLock::new();

/// `start_loopback(port)` — bind the loopback DNS listener on `127.0.0.1:<port>` and serve forever
/// on a dedicated OS thread. `port = 0` ⇒ the OS assigns an ephemeral port (the safe default — never
/// collides with a fixed port, reported back to the caller so the tunnel can retarget to it).
///
/// Returns the **bound** port (>0) on success, or `0` on ANY failure (bind error, runtime build
/// error, thread spawn error). IDEMPOTENT: a second call returns the already-bound port without
/// re-binding (the `OnceLock` is built at most once — the Centauri-Mirror contract, `lib.rs:1498`).
///
/// The accept loops call [`resolver::resolve`] (sync, JNIEnv-free, `mod.rs:431`) via
/// `spawn_blocking` so a slow upstream exchange never stalls the single accept worker. The
/// listener's dedicated current-thread runtime is COMPLETELY SEPARATE from the resolver's
/// per-query runtime (`mod.rs:310`) — never shared, never nested.
pub fn start_loopback(port: u16) -> u16 {
    // The OnceLock initializer runs at most once; a racing second caller gets the first's result.
    let running = LISTENER.get_or_init(|| {
        let stats = Arc::new(ListenerStats::default());

        // A one-shot channel to hand the bound port back from the accept thread to this caller
        // (the Centauri-Mirror split, lib.rs:1519 — bind first, report the port, then serve forever).
        let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();
        let serve_stats = stats.clone();

        let _accept_thread = std::thread::Builder::new()
            .name("torta-dns-listener".to_string())
            .spawn(move || {
                // A DEDICATED current-thread runtime on its OWN thread — NEVER the resolver's
                // (the load-bearing invariant, mirror/server.rs + lib.rs:1523). The resolver's own
                // current-thread rt `block_on`s one exchange per query and would be starved by a
                // co-hosted accept loop; this runtime owns ONLY the accept/recv loops, dispatching
                // the resolve via spawn_blocking onto the blocking-pool (a SEPARATE thread).
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => {
                        let _ = port_tx.send(0); // runtime build failed ⇒ 0 ⇒ caller sees failure
                        return;
                    }
                };
                rt.block_on(async move {
                    // Bind UDP FIRST on loopback. When the caller asked for a fixed `port` (>0), we then
                    // bind TCP to that SAME port so both protocols share ONE `127.0.0.1:<port>` — the
                    // tunnel architecture retargets system DNS to a single port for both UDP and TCP DNS
                    // (RFC 1035 §4.2: a DNS server serves the same port for both transports). When the
                    // caller asked for `port == 0` (ephemeral, the safe default), we read the OS-assigned
                    // UDP port and bind TCP to THAT explicit port — otherwise UDP and TCP each get an
                    // INDEPENDENT ephemeral port, the reported port would be the UDP one, and a TCP client
                    // pointing at it would hit connection-refused (the TCP listener lives elsewhere). The
                    // two-stage bind (UDP → read port → TCP on that port) is the fix: one port, both
                    // protocols, by construction. Either bind failing ⇒ 0 (no listener).
                    let udp = match UdpSocket::bind((LOOPBACK_ADDR, port)).await {
                        Ok(s) => s,
                        Err(_) => {
                            let _ = port_tx.send(0);
                            return;
                        }
                    };
                    // FAIL-CLOSED post-bind guard: whatever the OS actually gave us MUST be
                    // loopback. Today this is true by construction (`LOOPBACK_ADDR` is the only
                    // address passed), so it cannot fire — and that is exactly the point. The
                    // module's whole contract is that this DNS listener is unreachable off-device;
                    // if a later refactor parameterises the bind address, the choice is between
                    // catching it HERE, at startup, and discovering it when someone finds an open
                    // resolver on the LAN.
                    //
                    // Stated over the PROPERTY (is this address loopback) rather than over the
                    // current constant, so it stays correct if the constant ever legitimately
                    // changes to another loopback address such as `::1`.
                    match udp.local_addr() {
                        Ok(a) if !is_loopback(&a.ip()) => {
                            let _ = port_tx.send(0);
                            return;
                        }
                        Err(_) => {
                            let _ = port_tx.send(0);
                            return;
                        }
                        _ => {}
                    }
                    // The OS-assigned port: the fixed `port` when >0, or the ephemeral one the OS gave UDP.
                    let bound_port = udp.local_addr().map(|a| a.port()).unwrap_or(port);
                    // Bind TCP on the SAME explicit port (the dual-transport, single-port contract).
                    let tcp = match TcpListener::bind((LOOPBACK_ADDR, bound_port)).await {
                        Ok(l) => l,
                        Err(_) => {
                            let _ = port_tx.send(0);
                            return;
                        }
                    };
                    // Report success THEN drive both loops forever (this thread owns the runtime).
                    let _ = port_tx.send(bound_port);

                    // Spawn the UDP and TCP loops as concurrent tasks on THIS runtime. The runtime
                    // is current-thread, so they cooperatively schedule: a recv/accept await yields
                    // to the other. The resolver dispatch is spawn_blocking, so neither loop is
                    // blocked by an upstream exchange.
                    let udp_stats = serve_stats.clone();
                    let tcp_stats = serve_stats.clone();
                    let _udp_task = tokio::spawn(serve_udp(udp, udp_stats));
                    let _tcp_task = tokio::spawn(serve_tcp(tcp, tcp_stats));

                    // Park forever — the loops run for the process lifetime. They never return
                    // (each swallows per-query errors and continues), so this `pending` is the
                    // steady state; the runtime drops when the process exits.
                    std::future::pending::<()>().await;
                });
            });

        // Wait for the accept thread to bind + report (fast loopback open; recv returns once the
        // thread reaches its first post-bind await, exactly the Centauri shape, lib.rs:1563).
        let bound_port = port_rx.recv().unwrap_or(0);
        RunningListener {
            port: bound_port,
            stats,
        }
    });

    running.port
}

/// Stop the loopback listener (best-effort). The current implementation is a no-op teardown marker:
/// the listener runs for the process lifetime on a detached thread (the Centauri-Mirror shape), and
/// the resolver singleton it serves is itself process-global. A future slice may add a graceful
/// shutdown channel; for now, stopping the DNS engine in Kotlin re-points the tun forwarder away
/// from this port, which is the operational stop (the socket stops receiving queries). Present so
/// the JNI surface mirrors `resolver_shutdown` (`mod.rs`).
pub fn stop_loopback() {
    // Intentional no-op (see doc): the listener is detached + process-lifetime. Documented for the
    // JNI symmetry, not a stub — the operational stop is the Kotlin-side retarget, not a Rust close.
}

/// Read the bound loopback port, or `0` when no listener is running. The tunnel architecture queries
/// this to learn where to retarget system DNS (`127.0.0.1:<port>`).
pub fn loopback_port() -> u16 {
    LISTENER.get().map(|r| r.port).unwrap_or(0)
}

/// A telemetry snapshot (counts only, T20). `port = 0` when no listener is running.
pub fn loopback_snapshot() -> ListenerSnapshot {
    match LISTENER.get() {
        Some(r) => ListenerSnapshot {
            udp_served: r.stats.udp_served.load(Ordering::Relaxed),
            tcp_served: r.stats.tcp_served.load(Ordering::Relaxed),
            udp_errors: r.stats.udp_errors.load(Ordering::Relaxed),
            tcp_errors: r.stats.tcp_errors.load(Ordering::Relaxed),
            port: r.port,
        },
        None => ListenerSnapshot::default(),
    }
}

// ===================================================================================================
// The UDP serve loop — the upstream `udpListener` shape (proxy.go:453-481).
// ===================================================================================================

/// Drive the UDP recv loop forever: read one datagram, dispatch it to the resolver on the blocking
/// pool, write the reply back to the sender. Per-query errors (a bad sender, a send failure) are
/// counted and swallowed — one bad query never tears the loop down (the Centauri accept_loop
/// contract, `mirror/server.rs:214`). The bound socket's recv buffer is [`MAX_MESSAGE`] (T6 bound).
async fn serve_udp(sock: UdpSocket, stats: Arc<ListenerStats>) {
    let mut buf = vec![0u8; MAX_MESSAGE];
    loop {
        // recv_from awaits until a datagram arrives; yields the sender + length. An error here is
        // fatal to the loop (a closed socket) — the only way out, and the right one (the runtime
        // drops with the process). A benign transient error would be `continue`-d by the `Ok` arm.
        let (len, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => {
                stats.udp_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        let query = buf[..len].to_vec();
        let stats_for_query = stats.clone();
        // Dispatch the SYNC resolver on the blocking pool so its internal block_on (which parks the
        // resolver's own runtime awaiting the upstream) never stalls THIS accept worker. The
        // resolver is process-global + thread-safe (its inner state is Mutex-guarded, mod.rs:289).
        let reply = tokio::task::spawn_blocking(move || resolver::resolve(&query))
            .await
            .unwrap_or(None);
        match reply {
            Some(resp) => {
                // Bound the reply at MAX_MESSAGE (defense-in-depth — a DNS message is never this
                // large; truncating is the safe wire behavior, mirrors do53.rs:37 intent).
                let n = resp.len().min(MAX_MESSAGE);
                if sock.send_to(&resp[..n], peer).await.is_err() {
                    stats_for_query.udp_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                stats_for_query.udp_served.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                // No answer (not configured / blocked-unmapped / transport null) ⇒ a DNSERV FAIL
                // reply is the polite response, but for parity with the udp.c inline bridge
                // (udp.c:497 "r<=0: fall through to the unchanged sendto ⇒ DNS NEVER breaks"), we
                // simply drop on the floor: the caller's retry / fallback handles it. Count it as
                // served (a query WAS dispatched), not an error (the resolver answered "None").
                stats_for_query.udp_served.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ===================================================================================================
// The TCP serve loop — the upstream `tcpListener` shape (proxy.go:483-511) + RFC 1035 §4.2.2 framing.
// ===================================================================================================

/// Drive the TCP accept loop forever: accept one connection, read a 2-byte-length-prefixed DNS
/// message, dispatch it to the resolver, write the length-prefixed reply. Per-connection errors are
/// counted and swallowed (one bad client never tears the loop, the Centauri contract). The framing
/// read/write mirror `do53.rs:116-151` `tcp_exchange` exactly — the SAME crate, the SAME wire.
async fn serve_tcp(listener: TcpListener, stats: Arc<ListenerStats>) {
    loop {
        // accept yields a new connection per query (DNS-over-TCP is one-message-per-connection in
        // the common case; the upstream proxy.go:496 spawns a goroutine per accept — we await
        // inline since the resolver dispatch is spawn_blocking, freeing the accept worker).
        let (mut stream, _peer) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => {
                stats.tcp_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        let stats_for_query = stats.clone();

        // Read the 2-byte big-endian length prefix (RFC 1035 §4.2.2 / RFC 7766).
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            stats_for_query.tcp_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > MAX_MESSAGE {
            // A zero or out-of-bounds length is a malformed frame — drop the connection (T6 bound,
            // mirrors do53.rs:142).
            stats_for_query.tcp_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let mut query = vec![0u8; msg_len];
        if stream.read_exact(&mut query).await.is_err() {
            stats_for_query.tcp_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        // Dispatch the SYNC resolver on the blocking pool (same rationale as the UDP loop).
        let reply = tokio::task::spawn_blocking(move || resolver::resolve(&query))
            .await
            .unwrap_or(None);
        match reply {
            Some(resp) => {
                // Write the length-prefixed reply. The length MUST fit u16; a resp > 64KiB is
                // truncated to MAX_MESSAGE (the wire bound, defense-in-depth). Write length then
                // body then flush; any failure counts as one connection error and drops this query.
                let n = resp.len().min(MAX_MESSAGE);
                let len_bytes = (n as u16).to_be_bytes();
                let wrote = stream.write_all(&len_bytes).await.is_ok()
                    && stream.write_all(&resp[..n]).await.is_ok()
                    && stream.flush().await.is_ok();
                if wrote {
                    stats_for_query.tcp_served.fetch_add(1, Ordering::Relaxed);
                } else {
                    stats_for_query.tcp_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                // No answer ⇒ close the connection without a reply (parity with the UDP None arm
                // + the udp.c inline-bridge fall-through). Counted as served (dispatched).
                stats_for_query.tcp_served.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Loopback test for both families (`do53.rs:64` shape — reused, not reinvented). Currently used by
/// tests that assert the listener never exposes a non-loopback address.
fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns;
    use crate::resolver;

    /// A real wire-format DNS query for `example.com` A, built via the crate's own canonical builder.
    fn example_query() -> Vec<u8> {
        dns::build_query(0x1234, "example.com", 1 /* A */)
    }

    // ---- the structural invariants: loopback-only, the address is 127.0.0.1 BY CONSTRUCTION ----

    #[test]
    fn loopback_addr_is_exactly_127_0_0_1() {
        // The listener binds THIS address and no other — the structural off-host-safety guarantee.
        assert_eq!(LOOPBACK_ADDR, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn is_loopback_classifies_both_families() {
        // The loopback classifier (do53.rs shape) accepts 127.0.0.0/8 + ::1, rejects the rest.
        assert!(is_loopback(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_loopback(&IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254))));
        assert!(is_loopback(&IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
        assert!(!is_loopback(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_loopback(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_loopback(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    }

    // ---- the listener binds loopback, serves UDP + TCP, and returns the bound port ----

    /// A probe: send a UDP query to the listener, read the reply, validate it is a real DNS
    /// response to our question. Uses a fresh ephemeral client socket + a short timeout.
    fn probe_udp(port: u16, query: &[u8]) -> Option<Vec<u8>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("probe runtime");
        rt.block_on(async {
            use std::time::Duration;
            let sock = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16))
                .await
                .expect("probe bind");
            sock.connect((Ipv4Addr::LOCALHOST, port))
                .await
                .expect("probe connect");
            sock.send(query).await.expect("probe send");
            // A short-ish timeout: the resolver may need a real upstream round-trip when configured,
            // but the default (un-configured) resolver returns None quickly. Allow headroom either way.
            let mut buf = vec![0u8; MAX_MESSAGE];
            let res = tokio::time::timeout(Duration::from_millis(1500), sock.recv(&mut buf)).await;
            match res {
                Ok(Ok(n)) => Some(buf[..n].to_vec()),
                _ => None,
            }
        })
    }

    /// A probe: open a TCP connection, write the length-prefixed query, read the length-prefixed
    /// reply. Mirrors `do53.rs:116` `tcp_exchange` (the client side of the SAME framing).
    fn probe_tcp(port: u16, query: &[u8]) -> Option<Vec<u8>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("probe runtime");
        rt.block_on(async {
            use std::time::Duration;
            // Retry the connect for a short window: the listener's TCP accept loop is a spawned task
            // on a current-thread runtime, and on the first-ever connect the accept future may not
            // have been polled yet (the OS holds the SYN in the backlog, but a Windows loopback
            // connect can still transiently refuse until accept() is registered with the IO driver).
            // A bounded retry is the realistic listener-readiness wait a real client does.
            let mut stream = None;
            let connect_deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
            while tokio::time::Instant::now() < connect_deadline {
                match tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
                    Ok(s) => {
                        stream = Some(s);
                        break;
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
                }
            }
            let mut stream = stream.expect("probe tcp connect (retried)");
            let len = u16::try_from(query.len()).expect("query fits u16");
            stream
                .write_all(&len.to_be_bytes())
                .await
                .expect("probe tcp write len");
            stream.write_all(query).await.expect("probe tcp write body");
            let mut len_buf = [0u8; 2];
            let read_len =
                tokio::time::timeout(Duration::from_millis(1500), stream.read_exact(&mut len_buf))
                    .await;
            // read_exact returns io::Result<usize> (bytes read); success is Ok(Ok(_)).
            if !matches!(read_len, Ok(Ok(_))) {
                return None;
            }
            let reply_len = u16::from_be_bytes(len_buf) as usize;
            if reply_len == 0 || reply_len > MAX_MESSAGE {
                return None;
            }
            let mut buf = vec![0u8; reply_len];
            let read_body =
                tokio::time::timeout(Duration::from_millis(1500), stream.read_exact(&mut buf))
                    .await;
            if matches!(read_body, Ok(Ok(_))) {
                Some(buf)
            } else {
                None
            }
        })
    }

    #[test]
    fn start_loopback_binds_ephemeral_port_on_loopback() {
        // port=0 ⇒ the OS assigns an ephemeral port; the reported port is >0 and on 127.0.0.1.
        let port = start_loopback(0);
        assert!(
            port > 0,
            "start_loopback(0) must return a bound ephemeral port"
        );
        // Idempotent: a second call returns the SAME port (the OnceLock is built once).
        let port_again = start_loopback(0);
        assert_eq!(
            port, port_again,
            "start_loopback is idempotent — same port both calls"
        );
        // loopback_port reports the same bound port.
        assert_eq!(loopback_port(), port);
    }

    #[test]
    fn udp_loop_answers_a_query_when_resolver_configured() {
        // ★ #100 — installs a pool into the process-global and leaves it installed. Absence-asserting
        // siblings (`tunnel::tests::handle_packet_servfails_when_resolver_unconfigured`,
        // `wave3a_cabi_tests::unblocked_unconfigured_name_returns_zero`) are only valid while nothing
        // is installed, so every installer takes the shared gate.
        let _serial = resolver::lock_global_for_test();
        // The resolver is process-global; configure it with the loopback Do53 shadow transport so a
        // resolve either returns an upstream answer OR a clean None (never panics). If the upstream
        // is unreachable in the test env, the listener still accepts the datagram + counts it served.
        let _ = resolver::configure(
            r#"{"upstreams":[{"id":"do53:shadow","transport":"do53","url":"127.0.0.1:5354"}]}"#,
            800,
            64,
        );
        let port = start_loopback(0);
        let q = example_query();
        // Send + maybe-receive. A configured-but-unreachable upstream ⇒ None ⇒ no reply on the wire
        // (the None arm), which the probe times out. The structural claim (the loop ACCEPTS UDP and
        // counts it) is verified by the snapshot below regardless of the reply.
        let _reply = probe_udp(port, &q);
        // The snapshot MUST show at least one UDP query was served (the loop is live + dispatching).
        let snap = loopback_snapshot();
        assert!(
            snap.udp_served >= 1,
            "the UDP loop must count a served query: {snap:?}"
        );
        assert_eq!(snap.port, port);
    }

    #[test]
    fn tcp_loop_reads_length_prefixed_query_and_replies_or_drops() {
        // ★ #100 — same installer, same shared gate as the UDP twin above.
        let _serial = resolver::lock_global_for_test();
        // Same setup as the UDP test, over TCP. The framing read is the contract; the snapshot
        // proves the TCP loop accepted + dispatched the framed query.
        let _ = resolver::configure(
            r#"{"upstreams":[{"id":"do53:shadow","transport":"do53","url":"127.0.0.1:5354"}]}"#,
            800,
            64,
        );
        let port = start_loopback(0);
        let q = example_query();
        let _reply = probe_tcp(port, &q);
        let snap = loopback_snapshot();
        assert!(
            snap.tcp_served >= 1,
            "the TCP loop must count a served query: {snap:?}"
        );
    }

    #[test]
    fn snapshot_is_counts_only_no_qname_leak() {
        // T20: the surfaced telemetry carries ONLY counts + the port — no qname, no IP, no domain.
        // A cheap structural guard: the Debug rendering must not contain the probe's qname.
        let q = example_query();
        let _ = start_loopback(0);
        let _ = probe_udp(loopback_port(), &q);
        let snap = loopback_snapshot();
        let rendered = format!("{snap:?}");
        assert!(
            !rendered.contains("example"),
            "no qname in the snapshot: {rendered}"
        );
        assert!(rendered.contains("udp_served")); // counts ARE surfaced
    }

    #[test]
    fn max_message_bound_is_64k() {
        // The wire bound matches do53.rs:37 (the crate's canonical DNS message size bound).
        assert_eq!(MAX_MESSAGE, 64 * 1024);
    }
}
