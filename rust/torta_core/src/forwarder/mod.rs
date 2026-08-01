/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! THE NETSTACK GENESIS forwarder (#144) — SPIKE slice (2026-07-05).
//!
//! The North Star: DNSCrypt resolves the *name* but the *page* won't load — the tun is a full `0.0.0.0/0`
//! VPN that DROPS all non-DNS ([`crate::tunnel`] Stage-2-min), so Chrome ERR_TIMED_OUTs. This module is the
//! pure-Rust TCP/UDP forwarder that carries the resolved traffic OUT so the page renders — firestack
//! (Go/gVisor) ported to our ARC, the SAME move as the dnscrypt-proxy Go→Rust port.
//!
//! ## The engine — `ipstack` (verified 2026-07-05)
//! firestack hands the Android tun fd to gVisor's netstack + exposes a per-flow `Proxy(conn,src,dst)`
//! callback. Our Rust twin: [`ipstack::IpStack::new`] takes a `device: AsyncRead + AsyncWrite` (the tun fd
//! wrapped async) and [`IpStack::accept`](ipstack::IpStack::accept) yields an [`ipstack::stream::IpStackStream`]
//! per NEW flow — `Tcp` / `Udp` / `UnknownTransport`. That yield IS the firestack seam. GROUND_TRUTH from
//! the crate source (ipstack 0.1.1): `IpStack::new<D>(cfg, device) where D: AsyncRead+AsyncWrite+Unpin+Send`;
//! `async fn accept() -> Result<IpStackStream>`; `IpStackTcpStream: AsyncRead+AsyncWrite` (spliceable via
//! `copy_bidirectional`); `stream.peer_addr()/local_addr()` (the SessionKey + the Warden verdict src/dst).
//!
//! `#[cfg(feature = "netstack")]` gates the whole module → the base cargo-ndk `.so` is byte-clean until wired.
//!
//! ## Build order (roadmap #144): SPIKE (this) → N1 session map → N3 UDP → N2 TCP (page load) → N4 protect(fd)
//! → N5 beast/Tortä → N6 Forwarder Object + SLINT. THIS slice proves the engine compiles against our crate.

// The SPIKE-era `#![allow(dead_code, unused_imports)]` is GONE. Every item in this module now has a
// real caller: `classify`/`FlowKind` drive `handle_flow`'s accept-time counters, and
// `counts_as_other` carries the flows_other remainder rule. Measured with `--force-warn dead_code`
// on the SHIPPED android target rather than the host, because most of this module is `cfg(unix)`
// and a host measurement would call unix-only code dead when it is merely not compiled.
#![allow(unused_imports)] // ipstack/tokio traits re-exported for the cfg(unix) submodules.

/// Rewrite a dial at the cloak sentinel onto the in-app mirror's loopback listener.
///
/// ★ LIFTED OUT OF `#[cfg(unix)] run.rs` so it can be GATED (Socio: "make the UNIX part testable by
/// making it pure on Cross... instead of pointing that it is unix and we cant do nothing for it").
/// The rule that makes the lift safe: move the pure DECISION, leave the I/O behind the cfg. This
/// function is pure address math — two reads of process-global state and a `SocketAddr` — so nothing
/// about it was ever unix-specific. Same precedent as `classify_tcp` and `centauri_local_serve_ready`.
///
/// The resolver answers a watched-CDN name with an intentionally UNROUTABLE sentinel
/// (`resolver/local.rs:180-183`), so an app chasing that answer must be redirected here to
/// `127.0.0.1:<mirror_hairpin_port()>` and served from the offline-CDN cache.
///
/// ★ THE REFUSAL PATH (#78): when the port is `0` — mirror OFF, or its bind failed — NO rewrite
/// happens and the sentinel is returned unchanged. The dial then goes to an address that cannot be
/// routed, and the stack answers RST: that is `ERR_CONNECTION_REFUSED` in the browser. This is
/// deliberate (a mis-routed loopback connect would be worse than a clean failure), but it means the
/// refusal Socio sees with the forwarder ON is EXPECTED behaviour whenever the mirror is not serving —
/// the bug, if any, is upstream in who gets cloaked, not here. Now that this is testable, that claim is
/// checkable instead of arguable.
///
/// UDP to the sentinel is deliberately NOT hairpinned: the mirror is TCP-only, so a QUIC attempt fails
/// fast and the client falls back to TCP, which lands here.
pub(crate) fn hairpin_dst(dst: std::net::SocketAddr) -> std::net::SocketAddr {
    if !is_cloak_sentinel(dst) {
        return dst;
    }
    #[cfg(feature = "mirror")]
    {
        let port = crate::mirror_hairpin_port();
        if port > 0 {
            return std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
            );
        }
    }
    dst
}

mod session; // N1 — the SessionKey 5-tuple (cross-platform, pure SocketAddr)
mod shape; // N5 — Tortä shaping over REAL flows: widened CAKE key + tin classifier + per-flow YeAH pacer (cross-platform, host-testable)
mod sni; // ★ #66-A — the SNI peek: recover the hostname the DNS cloak collapsed into ONE sentinel IP (cross-platform, host-testable)
             // N1 — the AsyncRead+AsyncWrite adapter over the raw tun fd. UNIX-ONLY (libc + std::os::unix +
             // tokio::io::unix::AsyncFd) — the SAME cfg-gate the sync tun loop uses (`tunnel/mod.rs:271`). On the Windows
             // HOST the tun fd path does not exist; the forwarder engine construction still type-checks (host build proves
             // the API), the AVD (android = unix) supplies the real fd.
#[cfg(unix)]
mod tun_device;
// N3/N4 — the async forwarder loop + the protected upstream. UNIX-ONLY (drive the real tun fd + open
// protected sockets). The demux answers `:53` via DNSCrypt (DNS preserved), forwards everything else.
/// Can Centauri's local-serve leg actually take a flow? Answered BEFORE the client stream is touched.
///
/// DELIBERATELY NOT in `run.rs`: that module is `#[cfg(unix)]`, so on a Windows host it is never
/// compiled and anything inside it is unreachable by `cargo test` — a test written there silently does
/// not exist. This predicate carries no unix dependency (two reads of process-global state), so it
/// lives here where EVERY host compiles and tests it.
///
/// The two refusals below are *recoverable*: the ClientHello is still unread, so the caller can hand
/// the flow to the splice path instead of dropping it. That is the contract `lib.rs` states — "until
/// the user installs the returned certificate the fallback carries the flow" — which the call site
/// broke by returning unconditionally once `CENTAURI_TLS_ARMED` was set, leaving the splice
/// unreachable and every armed flow dead as ERR_CONNECTION_CLOSED whenever the CA or the mirror was
/// not ready. A handshake REFUSAL is a different animal and is NOT decided here: by then rustls has
/// written the alert and the peer has torn down, so that flow is genuinely lost and its recovery
/// (un-cloaking the host for the next attempt) stays inside `centauri_serve_local_tls`.
#[cfg(feature = "mirror")]
pub(crate) fn centauri_local_serve_ready(fwd: &crate::tunnel::ForwarderStats) -> bool {
    use std::sync::atomic::Ordering;
    if crate::CENTAURI_TLS_CONFIG.get().is_none() {
        fwd.centauri_tls_failed.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    // The mirror must actually be listening; port 0 means it never bound (see `mirror_hairpin_port`).
    if crate::mirror_hairpin_port() == 0 {
        fwd.centauri_tls_failed.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    true
}

// ★ #51 N9 — the ECHO lane. UNGATED on purpose, per the law stated 30 lines up: a module behind
// `#[cfg(unix)]` is never compiled on a Windows host, so tests written inside it silently do not
// exist. The ICMP WIRE (checksum/parse/build) carries no unix dependency, so it lives here where
// every host compiles and tests it; only the inner `icmp::lane` — which opens a real protected ping
// socket — is `#[cfg(unix)]`.
mod icmp;
#[cfg(unix)]
mod run;
#[cfg(unix)]
mod upstream;

#[cfg(unix)]
pub(crate) use run::{run_forwarder, ProtectFn, UidFn};
pub(crate) use session::{Proto, SessionKey};
#[cfg(unix)]
pub(crate) use tun_device::AsyncTunDevice;

use ipstack::stream::IpStackStream;
use ipstack::{IpStack, IpStackConfig};
use tokio::io::{AsyncRead, AsyncWrite};

/// The HTTPS port. A cloaked flow aimed here speaks TLS, so it must NOT reach the plain-HTTP mirror.
pub(crate) const HTTPS_PORT: u16 = 443;

/// Is this flow aimed at the DNS-plane cloak's sentinel address? The resolver answers EVERY watched-CDN
/// host with this ONE address (`resolver::local::CLOAK_SENTINEL_V4`/`_V6`), so `true` means "an app is
/// chasing a name we intercepted" — while saying nothing about WHICH name (that is [`sni`]'s job).
pub(crate) fn is_cloak_sentinel(dst: std::net::SocketAddr) -> bool {
    match dst.ip() {
        std::net::IpAddr::V4(v4) => v4 == crate::resolver::local::CLOAK_SENTINEL_V4,
        std::net::IpAddr::V6(v6) => v6 == crate::resolver::local::CLOAK_SENTINEL_V6,
    }
}

/// ★ #66-A — how a TCP flow should be routed once the cloak has had its say. Pure and cross-platform
/// ON PURPOSE: the live arms live in `run.rs`, which is `#[cfg(unix)]` and therefore invisible to the
/// host test runner, so the DECISION is lifted here where it can actually be proven. The invariant it
/// encodes — `:443` never reaches the plain-HTTP mirror, `:80` still hairpins, a real flow is never
/// touched — is exactly the one whose violation broke every HTTPS asset before #66.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpRoute {
    /// Not a cloaked flow — dial the real destination, byte-identical to pre-Centauri behavior.
    Direct,
    /// A cloaked plain-HTTP flow — hairpin to the in-app mirror's loopback listener (#65).
    HairpinToMirror,
    /// A cloaked TLS flow — peek the SNI, then splice to the genuine CDN (#66-A `centauri_https_seam`).
    HttpsSeam,
}

/// Classify one TCP flow's destination. See [`TcpRoute`].
pub(crate) fn classify_tcp(dst: std::net::SocketAddr) -> TcpRoute {
    if !is_cloak_sentinel(dst) {
        return TcpRoute::Direct;
    }
    if dst.port() == HTTPS_PORT {
        TcpRoute::HttpsSeam
    } else {
        TcpRoute::HairpinToMirror
    }
}

/// One classified new flow the netstack `accept()` yielded — the firestack `Proxy(conn,src,dst)` seam, typed.
/// The SPIKE only *names* the shape (proto + the 5-tuple ends); N1 threads it into a `SessionKey` + the
/// Warden verdict, N2/N3 splice the stream to a protected upstream socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowKind {
    /// A TCP flow (a real page load rides these) — needs the handshake + `copy_bidirectional` splice (N2).
    Tcp,
    /// A UDP flow (QUIC/HTTP3/plain) — the simpler witness, no handshake (N3).
    Udp,
    /// An unknown TRANSPORT over an IP version we DO parse — where ICMP lands, and since ★ #51 N9 that
    /// is a lane we ANSWER (`forwarder::icmp` dials a real protected ping socket and writes the reply
    /// back into the tun), not a drop.
    ///
    /// Split out from the old catch-all `Other` deliberately. Merging the two made this enum stale the
    /// moment the echo lane landed: an answered `ping` would have been named the same as a protocol we
    /// cannot parse at all, and counting from that name would have inflated the `flows_other`
    /// remainder with traffic the forwarder actually served. The echo lane counts only what it
    /// REFUSES, so this variant is deliberately NOT counted at accept time.
    Icmp,
    /// An unknown NETWORK layer — not even an IP version we parse. Nothing to forward, and the only
    /// shape that is unconditionally part of the `flows_other` remainder.
    Unknown,
}

/// Construct the netstack engine over an async tun `device` (the SPIKE keystone: proves `IpStack::new`
/// type-checks against our crate with the real ipstack 0.1.1 API). `device` is the tun fd wrapped so it is
/// `AsyncRead + AsyncWrite` (N1 supplies the `AsyncFd` adapter over the dup'd fd from `tunnel/mod.rs`).
///
/// The netstack MTU derived from the REAL tun MTU, as a `u16`, by a SATURATING cast that can never
/// truncate.
///
/// ★ THE ERR_CONNECTION_CLOSED CAUSE (#63). `IpStackConfig::default()` sets `mtu: u16::MAX` — 65535
/// (`ipstack-0.1.1/src/lib.rs:60`, consumed for real segmentation at `:173`, `:210`, `:230`). The
/// forwarder built its segments for a 65535-byte path while the tun is 1400, so every full-size TCP
/// segment the userspace stack emitted was ~46x the interface MTU. DNS survived (queries are 60-100
/// bytes and never reach the limit); TLS did not (a certificate record is full-size and is the FIRST
/// full-size packet of any HTTPS connection), so the handshake died mid-flight and Chromium reported
/// `net_error -100` = ERR_CONNECTION_CLOSED. MEASURED on device: 509 such failures over 111 URLs with
/// the tunnel verified up, all from `ssl_client_socket_impl.cc`, zero from any other tag.
///
/// WHY SATURATING AND NOT `as u16`: a bare `tun_mtu as u16` TRUNCATES modulo 65536 — 65536 becomes 0
/// (a netstack that can emit nothing) and 65600 becomes 64. The tun MTU arrives from Kotlin as an
/// `i32` and is only clamped to [`crate::tunnel::TUN_MTU_CEILING`] on the config path, so this
/// function must be safe for EVERY `usize`, not merely for the value we ship today.
///
/// Proved for ALL inputs in D:/Lean/proofs/Proofs/NetstackMtu.lean: `netstack_mtu_never_exceeds_tun`
/// (the result never exceeds the tun MTU, which is the property that makes the segment fit),
/// `saturating_cast_never_truncates`, and `the_bare_cast_can_collapse_to_zero` — the negative control
/// showing what the naive cast does.
pub(crate) fn netstack_mtu(tun_mtu: usize) -> u16 {
    if tun_mtu > u16::MAX as usize {
        u16::MAX
    } else {
        tun_mtu as u16
    }
}

/// Returns the live [`IpStack`] whose [`accept`](IpStack::accept) is the per-flow forwarder loop.
///
/// `tun_mtu` is the REAL tun MTU (`TunnelConfig::mtu`, already clamped by
/// [`crate::tunnel::clamp_tun_mtu`]). It is threaded into [`IpStackConfig::mtu`] via
/// [`netstack_mtu`] because the crate default is `u16::MAX` — see that function for the failure this
/// repairs. Passing the tun's own MTU is what makes the userspace stack segment to a size the
/// interface can actually carry.
///
/// PILLAR SAFETY: this changes only the SEGMENT SIZE the forwarder emits. No pillar gate, verdict,
/// counter or log token is touched, so no pillar capability is narrowed by it.
pub(crate) fn build_netstack<D>(device: D, tun_mtu: usize) -> IpStack
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut config = IpStackConfig::default();
    config.mtu(netstack_mtu(tun_mtu));
    IpStack::new(config, device)
}

/// The netstack-MTU derivation, mirroring D:/Lean/proofs/Proofs/NetstackMtu.lean. A Rust test
/// SAMPLES the space; the Lean file SETTLES it. These exist so the mirror is executable in CI.
#[cfg(test)]
mod netstack_mtu_tests {
    use super::netstack_mtu;

    /// THE REPAIR. The shipped tun MTU now reaches the netstack instead of `u16::MAX`.
    #[test]
    fn the_shipped_tun_mtu_reaches_the_netstack() {
        assert_eq!(netstack_mtu(crate::tunnel::TUN_MTU_CEILING), 1400);
    }

    /// NEGATIVE CONTROL. The crate default is what shipped, and it is 46x the interface.
    #[test]
    fn the_crate_default_would_have_overshot_the_tun() {
        assert_eq!(u16::MAX, 65535);
        assert!(
            (u16::MAX as usize) > crate::tunnel::TUN_MTU_CEILING,
            "the ipstack default must be provably larger than the tun, or there was no defect"
        );
    }

    /// The load-bearing property, sampled across the whole band plus the wrap boundary.
    #[test]
    fn the_netstack_mtu_never_exceeds_the_tun() {
        for m in 0..4096usize {
            assert!(netstack_mtu(m) as usize <= m, "overshoot at {m}");
        }
        for m in [65535usize, 65536, 65600, usize::MAX] {
            assert!(netstack_mtu(m) as usize <= m, "overshoot at {m}");
        }
    }

    /// NEGATIVE CONTROL for the cast: the naive `as u16` collapses 65536 to zero and 65600 to 64.
    /// The saturating helper must do neither.
    #[test]
    fn the_bare_cast_would_have_truncated() {
        assert_eq!(65536usize as u16, 0, "the naive cast collapses to zero");
        assert_eq!(65600usize as u16, 64, "the naive cast shrinks catastrophically");
        assert_eq!(netstack_mtu(65536), u16::MAX);
        assert_eq!(netstack_mtu(65600), u16::MAX);
    }

    /// Inside the representable range nothing is thrown away.
    #[test]
    fn values_inside_u16_pass_through_exactly() {
        for m in [0usize, 1, 64, 576, 1360, 1400, 1500, 65535] {
            assert_eq!(netstack_mtu(m) as usize, m, "not preserved at {m}");
        }
    }

    /// Monotone, and idempotent under re-derivation.
    #[test]
    fn the_derivation_is_monotone_and_idempotent() {
        let mut prev = 0u16;
        for m in 0..3000usize {
            let v = netstack_mtu(m);
            assert!(v >= prev, "not monotone at {m}");
            assert_eq!(netstack_mtu(v as usize), v, "not idempotent at {m}");
            prev = v;
        }
    }

    /// A live tun never yields a netstack that can emit nothing.
    #[test]
    fn a_live_tun_never_yields_a_zero_mtu() {
        for m in 1..2048usize {
            assert!(netstack_mtu(m) > 0, "zero mtu at {m}");
        }
    }
}

/// Is this shape part of the `flows_other` REMAINDER at accept time?
///
/// The rule `handle_flow` counts by, named so it is testable on a host that cannot construct an
/// `IpStackStream`. Only [`FlowKind::Unknown`] — an IP version we cannot parse — is unconditionally
/// the remainder. [`FlowKind::Icmp`] is NOT: the ★ #51 N9 echo lane may ANSWER it, and counts only
/// what it REFUSES, so counting it here would double-count a refusal and mis-count every `ping` the
/// forwarder successfully served as unparseable traffic.
pub(crate) const fn counts_as_other(kind: FlowKind) -> bool {
    matches!(kind, FlowKind::Unknown)
}

/// Classify one accepted [`IpStackStream`] into a [`FlowKind`] — the demux at the head of the
/// forwarder loop, and THE single place a flow's shape is named.
///
/// WIRED: `run::handle_flow` calls this once per accepted flow and bumps the accept-time counter from
/// the returned NAME, so the counter and the classification cannot drift apart. Previously the loop
/// re-matched the stream inline and incremented counters arm-by-arm, which meant the demux existed
/// twice — and the two copies had already diverged, this one being the stale half.
pub(crate) fn classify(stream: &IpStackStream) -> FlowKind {
    match stream {
        IpStackStream::Tcp(_) => FlowKind::Tcp,
        IpStackStream::Udp(_) => FlowKind::Udp,
        // ICMP and friends: an IP packet whose TRANSPORT we do not demux. The echo lane may still
        // answer it, so this is NOT the unconditional `flows_other` remainder.
        IpStackStream::UnknownTransport(_) => FlowKind::Icmp,
        IpStackStream::UnknownNetwork(_) => FlowKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The SPIKE proof: FlowKind is a real 3-way + the module type-checks against ipstack 0.1.1. The live
    // accept()-loop witness (a UDP flow through a real tun) is N3 on the AVD — this host test only proves
    // the engine + the demux compile in our crate (the make-or-break "does the API fit our tree" gate).
    #[test]
    fn flowkind_is_a_real_four_way() {
        let all = [
            FlowKind::Tcp,
            FlowKind::Udp,
            FlowKind::Icmp,
            FlowKind::Unknown,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(i == j, a == b, "FlowKind variants must be pairwise distinct");
            }
        }
    }

    /// THE SPLIT THAT MATTERS. `Icmp` and `Unknown` were ONE variant (`Other`) until the ★ #51 N9
    /// echo lane made ICMP a shape the forwarder ANSWERS rather than drops. They must stay distinct,
    /// because `handle_flow` counts the `flows_other` remainder from this name: merging them again
    /// would count every answered `ping` as unparseable traffic and inflate the remainder with flows
    /// the forwarder actually served.
    #[test]
    fn icmp_is_not_the_unparseable_remainder() {
        assert_ne!(
            FlowKind::Icmp,
            FlowKind::Unknown,
            "an ICMP flow the echo lane can answer is NOT the same shape as an IP version we \
             cannot parse -- the flows_other remainder depends on this distinction"
        );
    }

    /// A cloaked `:443` flow takes the HTTPS seam — NEVER the plain-HTTP hairpin.
    ///
    /// THE #66-A REGRESSION GUARD. Before this, `hairpin_dst` rewrote every sentinel flow to the mirror
    /// regardless of port, so a browser's TLS ClientHello was posted into a plain-HTTP server and every
    /// HTTPS asset on a watched CDN broke while the cloak was armed. If this assertion ever flips back,
    /// that breakage is back.
    #[test]
    fn cloaked_https_takes_the_seam_not_the_plain_mirror() {
        for ip in [
            std::net::IpAddr::V4(crate::resolver::local::CLOAK_SENTINEL_V4),
            std::net::IpAddr::V6(crate::resolver::local::CLOAK_SENTINEL_V6),
        ] {
            let dst = std::net::SocketAddr::new(ip, HTTPS_PORT);
            assert_eq!(
                classify_tcp(dst),
                TcpRoute::HttpsSeam,
                "a cloaked :443 flow must be SNI-peeked + spliced, never posted at the HTTP mirror"
            );
        }
    }

    /// A cloaked plain-HTTP flow still hairpins to the in-app mirror — #66-A must not regress #65's
    /// working leg (the loopback serve that is already AVD-proven).
    #[test]
    fn cloaked_http_still_hairpins_to_the_mirror() {
        let dst = std::net::SocketAddr::new(
            std::net::IpAddr::V4(crate::resolver::local::CLOAK_SENTINEL_V4),
            80,
        );
        assert_eq!(classify_tcp(dst), TcpRoute::HairpinToMirror);
    }

    /// ★ THE FALLBACK CONTRACT — an ARMED but UNABLE local-serve leg must not eat the flow.
    ///
    /// Socio's field report: with the netstack forwarder ON every site died as ERR_CONNECTION_CLOSED.
    /// Cause: the armed branch returned unconditionally, so a leg that could not possibly serve (no CA
    /// config, mirror never bound) still swallowed the flow and left the splice unreachable.
    #[cfg(feature = "mirror")]
    #[test]
    fn armed_but_unready_local_serve_yields_the_flow_to_the_splice() {
        use std::sync::atomic::Ordering;
        let fwd = crate::tunnel::ForwarderStats::default();
        // In the test process the CA-config OnceLock is unset and the mirror never bound.
        assert!(
            !centauri_local_serve_ready(&fwd),
            "with no CA config and no bound mirror the leg CANNOT serve — it must yield to the splice"
        );
        assert_eq!(
            fwd.centauri_tls_failed.load(Ordering::Relaxed),
            1,
            "the refusal must be COUNTED, never silent"
        );
    }

    /// The gate must stay ON the armed branch in `run.rs`, which this host never compiles — so the
    /// guarantee is held as a SOURCE law instead. Without the gate the splice is dead code again.
    ///
    /// Every needle is ASSEMBLED from fragments: a literal would match this very test through
    /// `include_str!` and the check would pass while asserting nothing (earned the hard way).
    #[cfg(feature = "mirror")]
    #[test]
    fn the_armed_branch_stays_gated_on_readiness() {
        let src = include_str!("run.rs");
        let gate = ["centauri", "local", "serve", "ready"].join("_");
        let armed = ["CENTAURI", "TLS", "ARMED"].join("_");
        let idx = src
            .find(&armed)
            .expect("the armed branch must exist in run.rs");
        // The gate may sit on the next line after a rustfmt wrap, so read a small window forward.
        let window = &src[idx..src.len().min(idx + 200)];
        assert!(
            window.contains(&gate),
            "the armed branch MUST be gated on readiness or the splice becomes unreachable: {window}"
        );
    }

    /// A REAL destination is never touched, on any port — the cloak only ever claims its own sentinel.
    ///
    /// Addresses here are RFC 5737 / RFC 3849 documentation ranges on purpose: a fixture must never read
    /// as this engine endorsing a public resolver. Tortä resolves ONLY over its own DNSCrypt pool.
    #[test]
    fn real_destinations_route_direct() {
        for (addr, port) in [("203.0.113.10", 443), ("203.0.113.10", 80), ("198.51.100.7", 53)] {
            let dst = std::net::SocketAddr::new(addr.parse().unwrap(), port);
            assert_eq!(
                classify_tcp(dst),
                TcpRoute::Direct,
                "{dst} is a real flow and must pass through untouched"
            );
        }
    }
}

#[cfg(test)]
mod hairpin_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// ★ The #78 refusal path, now GATED instead of argued about.
    ///
    /// This logic lived in `#[cfg(unix)] run.rs` and therefore did not compile — let alone run — on this
    /// host, so its behaviour could only be reasoned about from the source. Lifting the pure decision
    /// makes the claim checkable: an ordinary destination is untouched, and a sentinel dial with NO
    /// mirror listening is returned UNCHANGED (unroutable ⇒ RST ⇒ ERR_CONNECTION_REFUSED), which is the
    /// exact symptom Socio reports with the Netstack Forwarder ON.
    #[test]
    fn a_sentinel_dial_with_no_mirror_listening_is_left_unroutable() {
        // An ordinary destination is never rewritten.
        let ordinary = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        assert_eq!(hairpin_dst(ordinary), ordinary, "a normal dial must pass through untouched");

        // The sentinel with the mirror NOT serving (port 0 is the default in a host test): unchanged.
        // The address is intentionally unroutable, so the connect fails — by design, not by accident.
        let sentinel = SocketAddr::new(
            IpAddr::V4(crate::resolver::local::CLOAK_SENTINEL_V4),
            443,
        );
        assert!(is_cloak_sentinel(sentinel), "the fixture must actually BE the sentinel");
        let routed = hairpin_dst(sentinel);
        if crate::mirror_hairpin_port() == 0 {
            assert_eq!(
                routed, sentinel,
                "with no mirror listening the sentinel MUST be left alone — a mis-routed loopback \
                 connect would be worse than a clean failure"
            );
        } else {
            assert_eq!(
                routed.ip(),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "a serving mirror must hairpin the flow to loopback"
            );
        }
    }
}

/// The `flows_other` REMAINDER RULE — which shapes are counted as unparseable at accept time.
///
/// `classify` and `handle_flow` are `cfg(unix)` and need a live `IpStackStream`, so they cannot run
/// in the host suite. The RULE they count by is pure, so it is named and tested here: this is the
/// part that decides whether the panel's "other" figure is honest.
#[cfg(test)]
mod remainder_rule_tests {
    use super::*;

    /// THE LOAD-BEARING RULE. An answered `ping` must never land in the unparseable remainder.
    #[test]
    fn only_unparseable_network_counts_as_other() {
        assert!(
            counts_as_other(FlowKind::Unknown),
            "an IP version we cannot parse IS the remainder"
        );
        assert!(
            !counts_as_other(FlowKind::Icmp),
            "ICMP is answered by the ★ #51 N9 echo lane, which counts only what it REFUSES -- \
             counting it here would report served pings as unparseable traffic"
        );
        assert!(!counts_as_other(FlowKind::Tcp), "TCP has its own counter");
        assert!(!counts_as_other(FlowKind::Udp), "UDP has its own counter");
    }

    /// EXHAUSTIVE over every variant: exactly ONE shape is the remainder. If a future variant is
    /// added and silently falls into the remainder, this fails.
    #[test]
    fn exactly_one_shape_is_the_remainder() {
        let all = [
            FlowKind::Tcp,
            FlowKind::Udp,
            FlowKind::Icmp,
            FlowKind::Unknown,
        ];
        let n = all.iter().filter(|k| counts_as_other(**k)).count();
        assert_eq!(
            n, 1,
            "exactly one FlowKind may be the unconditional flows_other remainder; found {n}"
        );
    }
}
