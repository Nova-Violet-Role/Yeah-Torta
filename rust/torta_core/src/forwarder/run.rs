/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! N3 — the FORWARDER LOOP (the async accept()-loop that carries traffic OUT of the tun).
//!
//! UNIX-ONLY (drives the real tun fd). The Rust twin of firestack's forwarder + NetGuard's session loop, but
//! tokio-async: [`ipstack::IpStack`] owns the tun fd (via [`AsyncTunDevice`]), and each `accept()` yields ONE
//! new flow. We demux:
//!   - **DNS** (a UDP flow to port 53) → answered IN-LOOP via [`crate::resolver::resolve_datapath`] — DNS is
//!     PRESERVED (the North Star discipline: never break name resolution while adding the page-load path).
//!   - **UDP non-53** → forward: a protected upstream [`tokio::net::UdpSocket`] to the flow's dst, splice
//!     bytes both ways (N3 — the first witness: QUIC/HTTP3/plain UDP flows through the tun).
//!   - **TCP** → forward: a protected upstream [`tokio::net::TcpStream`] + `copy_bidirectional` (N2 — a PAGE
//!     loads). Wired here in the same loop; the witness order is UDP first (simpler), then TCP.
//!
//! protect(fd) (N4): every upstream socket is opened via `socket2` BEFORE connect so the
//! [`ProtectFn`] (Kotlin's `vpnService.protect(fd)`) can exclude it from the tun — the anti-loop keystone
//! (without it the upstream packet re-enters the 0.0.0.0/0 tun and the flow dies).

#![cfg(unix)]

use log::{error, warn};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ipstack::stream::IpStackStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::session::{Proto, SessionKey};
use super::shape::{tin_for_flow, FlowShaper};
use super::tun_device::AsyncTunDevice;
use super::upstream::{connect_tcp_protected, connect_udp_protected};
use super::FlowKind;
use crate::beast::ProbePriority;
use crate::tunnel::ForwarderStats;

/// The socket-protect hook (N4): `protect_fd(raw_fd) -> bool`. A thin `Fn` alias so the forwarder does not
/// depend on `tunnel::ProtectCallback` directly — the caller adapts its `Arc<dyn ProtectCallback>` into this.
pub(crate) type ProtectFn = Arc<dyn Fn(i32) -> bool + Send + Sync>;

/// ★ N-warden — the flow-owner uid hook: `(proto, src, dst) -> uid` (`-1` unresolved). The ProtectFn
/// shape: the caller adapts its `Arc<dyn UidResolver>` (Kotlin's `ConnectivityManager` lookup) into this,
/// so the forwarder never depends on the UniFFI trait directly.
pub(crate) type UidFn = Arc<dyn Fn(u8, SocketAddr, SocketAddr) -> i32 + Send + Sync>;

/// The DNS DEMUX port — a UDP flow whose DESTINATION port is this is a DNS query the OS routed into the tun
/// (VpnBuilder tells the OS `addDnsServer(10.1.10.2)`, so system DNS arrives as `10.1.10.2:53` INTO the tun —
/// `VpnBuilder.java:328`, `parse.rs:98` `dport == 53`). We MATCH it here (a read off the tun — NO bind, so the
/// privileged-port trap that deleted the old `:53` LISTENER, `ResolverRuntime.kt:321`, does NOT apply) and
/// answer inline via the sovereign resolver → DNSCrypt. This PRESERVES DNS: every `:53` query is forced
/// through DNSCrypt (even an app hardcoding `8.8.8.8:53` is captured, never leaked in the clear — the
/// no-fallback sovereignty). This is DISTINCT from DNSCrypt's OWN local listener `127.0.0.1:5354` (the Socio's
/// high-port trick, `dnscrypt_config.rs:739` — the MODE-1 loopback endpoint), which the forwarder never touches:
/// the netstack answers `:53` off the tun, the 5354 endpoint is DNSCrypt's separate local-listener concern.
const DNS_DEMUX_PORT: u16 = 53;

/// Run the async forwarder over the tun `device` until `running` clears. Owns the netstack; each accepted
/// flow is spawned onto the current tokio runtime (task-per-flow — the firestack supervisor fan-out that
/// tokio gives us free). NEVER returns on a single-flow error (a bad flow is dropped, the loop continues).
pub(crate) async fn run_forwarder(
    device: AsyncTunDevice,
    protect: ProtectFn,
    running: Arc<AtomicBool>,
    fwd: Arc<ForwarderStats>,
    uid: Option<UidFn>,
    tun_mtu: usize,
) {
    let mut stack = super::build_netstack(device, tun_mtu);
    // N6 — the live witness: the fork actually took (vs. armed-but-declined → sync loop).
    fwd.live.store(true, Ordering::Relaxed);
    while running.load(Ordering::Acquire) {
        let stream = match stack.accept().await {
            Ok(s) => s,
            Err(_) => continue, // a demux/parse error on one packet — never tear the loop
        };
        let protect = protect.clone();
        let fwd = fwd.clone();
        let uid = uid.clone();
        // Task-per-flow: the slow-splice of one flow never blocks accept() of the next.
        tokio::spawn(async move {
            handle_flow(stream, protect, fwd, uid).await;
        });
    }
    fwd.live.store(false, Ordering::Relaxed);
}

/// ★ N-warden — the forwarder's Warden gate (the sync loop's Stage-2-min `forward_or_warden_drop`, now
/// LIVE on the forwarding path with a REAL uid). Returns `true` when the flow may forward.
///
/// The uid is resolved ONCE per flow via the Kotlin [`UidFn`] (`-1` when no resolver is installed or the
/// OS cannot attribute the flow — then `torta_firewall_verdict`'s `uid < 0` guard ABSTAINs, fail-safe
/// pass). DENY is the ONLY blocking verdict — the additive-block contract: an unconfigured/absent Warden
/// can never break forwarding, only an armed one can ADD a drop. The `:53` DNS-intercept path NEVER
/// passes here — the resolver owns its own blocklist gate (NXDOMAIN), per the warden.rs charter.
pub(crate) fn warden_allows(key: &SessionKey, uid: &Option<UidFn>, fwd: &ForwarderStats) -> bool {
    let owner = uid
        .as_ref()
        .map(|f| f(key.proto.ip_number(), key.src, key.dst))
        .unwrap_or(-1);
    let (version, daddr) = match key.dst_ip() {
        std::net::IpAddr::V4(v4) => (4u8, crate::tunnel::IpAddrBytes::V4(v4.octets())),
        std::net::IpAddr::V6(v6) => (6u8, crate::tunnel::IpAddrBytes::V6(v6.octets())),
    };
    let verdict = crate::tunnel::warden::verdict(
        owner,
        version,
        key.proto.ip_number(),
        &daddr,
        key.dst_port(),
        None, // the firewall seam is qname-less — the DNS-domain half lives on the resolver path
        true, // #20 — the forwarder CARRIES what it allows; the row is an honest ALLOW
    );
    if verdict.is_deny() {
        fwd.warden_denied.fetch_add(1, Ordering::Relaxed);
    }
    !verdict.is_deny()
}

/// N6 — count a flow into its Tortä tin (the fountain's per-tin totals).
fn note_tin(fwd: &ForwarderStats, tin: ProbePriority) {
    let counter = match tin {
        ProbePriority::Critical => &fwd.tin_critical,
        ProbePriority::High => &fwd.tin_high,
        ProbePriority::Normal => &fwd.tin_normal,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Route ONE accepted flow: DNS answered in-loop, everything else Warden-gated (N-warden) then forwarded
/// through a protected upstream.
/// N6 counts every arm into [`ForwarderStats`] (accepted/tin at entry, active gauge across the flow's life).
async fn handle_flow(
    stream: IpStackStream,
    protect: ProtectFn,
    fwd: Arc<ForwarderStats>,
    uid: Option<UidFn>,
) {
    fwd.active_flows.fetch_add(1, Ordering::Relaxed);
    // ONE demux. `super::classify` is the single place a flow's shape is named, and the accept-time
    // counter is bumped from that NAME — so the classification and the counter cannot drift apart.
    // They previously could: the loop re-matched the stream arm-by-arm while `classify` described the
    // same demux separately, and the two had already diverged (classify still lumped ICMP in with
    // unparseable traffic, from before the ★ #51 N9 echo lane existed).
    //
    // SEMANTICS PRESERVED EXACTLY: Icmp is deliberately NOT counted here, because the echo lane
    // counts only what it REFUSES (`forwarder::icmp`) — an answered `ping` must never inflate the
    // `flows_other` remainder. Unknown (an IP version we cannot parse) is the only unconditional
    // remainder, exactly as the old `_` arm had it.
    match super::classify(&stream) {
        FlowKind::Tcp => {
            fwd.flows_tcp.fetch_add(1, Ordering::Relaxed);
        }
        FlowKind::Udp => {
            fwd.flows_udp.fetch_add(1, Ordering::Relaxed);
        }
        // The remainder rule lives in `super::counts_as_other` so it is testable on a host that
        // cannot construct an `IpStackStream`. Icmp answers false there: the echo lane counts only
        // what it REFUSES.
        other => {
            if super::counts_as_other(other) {
                fwd.flows_other.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    match stream {
        IpStackStream::Udp(mut udp) => {
            let dst: SocketAddr = udp.peer_addr();
            let session = SessionKey::new(Proto::Udp, udp.local_addr(), dst);
            note_tin(&fwd, tin_for_flow(&session));
            if dst.port() == DNS_DEMUX_PORT {
                // DNS is NEVER Warden-gated here — the resolver owns its own blocklist (NXDOMAIN).
                answer_dns_udp(&mut udp, &fwd).await;
            } else if !warden_allows(&session, &uid, &fwd) {
                // DENY ⇒ fall through: the flow is dropped, never dialed (the additive block).
            } else {
                // ★ #22 slice 3 · N7 — the UDP twin of the N5 tin demux: BULK (Normal tin —
                // QUIC/HTTP3, the modern web's bulk lane) is YeAH-paced; CRITICAL/HIGH splice
                // unshaped, latency-first. The FIRST UDP congestion algorithm now shapes the
                // forwarder's UDP datapath, not just the resolver's DNS transactions.
                let shaper = FlowShaper::new(&session);
                // ★ #47 N8 — enroll the flow in the per-flow docket. `paced` is recorded as the fact
                // it is (NORMAL tin only), so an unshaped row reads "unpaced" rather than "window 0".
                let paced = shaper.tin() == ProbePriority::Normal;
                let live = docket_enroll(&shaper, Proto::Udp.ip_number() as i32, paced);
                if paced {
                    fwd.paced_flows.fetch_add(1, Ordering::Relaxed);
                    forward_udp_paced(udp, dst, protect, shaper, &live, &fwd).await;
                } else {
                    forward_udp(udp, dst, protect, &live, &fwd).await;
                }
                crate::tunnel::docket_release(&live);
            }
        }
        IpStackStream::Tcp(tcp) => {
            let dst: SocketAddr = tcp.peer_addr();
            // N5 — the Tortä tin demux: BULK (Normal tin) is YeAH-paced; CRITICAL/HIGH (DNS plane +
            // interactive page-load class) splice unshaped — latency-first, never behind a pacer.
            let session = SessionKey::new(Proto::Tcp, tcp.local_addr(), dst);
            let shaper = FlowShaper::new(&session);
            note_tin(&fwd, shaper.tin());
            if !warden_allows(&session, &uid, &fwd) {
                // DENY — dropped before the upstream dial (the additive block); tin/flow counts above
                // stay (accept-time facts), `warden_denied` carries the story. NOT docketed: a denied
                // flow never becomes a live flow, and listing it would misreport the datapath.
            } else {
                // ★ #47 N8 — enroll in the per-flow docket for the life of the flow.
                let paced = shaper.tin() == ProbePriority::Normal;
                let live = docket_enroll(&shaper, Proto::Tcp.ip_number() as i32, paced);
                if paced {
                    fwd.paced_flows.fetch_add(1, Ordering::Relaxed);
                    forward_tcp_paced(tcp, dst, protect, shaper, &live, &fwd).await;
                } else {
                    forward_tcp(tcp, dst, protect, &live, &fwd).await;
                }
                crate::tunnel::docket_release(&live);
            }
        }
        // ★ #51 N9 — the ECHO lane. An unknown TRANSPORT is where ICMP lands, so a `ping` is
        // dialed for real through a protected unprivileged ping socket and its reply written back
        // into the tun (`forwarder::icmp`). Anything that lane refuses — ICMPv6, IGMP, ESP, a
        // non-echo ICMP type — increments `flows_other` there, so the remainder stays honest.
        IpStackStream::UnknownTransport(unknown) => {
            super::icmp::handle_icmp(unknown, protect, uid, fwd.clone()).await;
        }
        // An unknown NETWORK layer: not even an IP version we parse. Nothing to forward.
        // Counted above from the classification; nothing to forward.
        _ => {}
    }
    fwd.active_flows.fetch_sub(1, Ordering::Relaxed);
}

/// ★ #47 N8 — birth ONE docket row from the flow's own shaper and enroll it.
///
/// The row takes its identity from the SAME widened CAKE key the shaper paces on
/// (`shape::flow_key`), so the docket and the engine agree on what "a flow" is by construction
/// rather than by a parallel definition that could drift.
///
/// Registration may be REFUSED when the docket is full ([`crate::tunnel::FLOW_DOCKET_CAP`]); the
/// `Arc` is returned either way and the flow forwards identically. Telemetry never gates traffic —
/// an unlisted flow is a reporting gap, and a dropped flow would be a user-visible outage.
fn docket_enroll(
    shaper: &FlowShaper,
    proto: i32,
    paced: bool,
) -> std::sync::Arc<crate::tunnel::FlowLive> {
    let tin = match shaper.tin() {
        ProbePriority::Critical => 0,
        ProbePriority::High => 1,
        _ => 2,
    };
    docket_enroll_raw(shaper.key(), proto, tin, paced)
}

/// ★ #51 N9 — enroll a docket row for a flow that has NO shaper.
///
/// The ICMP echo lane never constructs a [`FlowShaper`]: a single probe packet has no window to
/// grow and no queue to drain, and building one would seed a YeAH brain from a flow it never paces
/// (`shape::FlowShaper::sample` documents the same boundary). It still deserves a row — a `ping` in
/// flight is exactly the kind of thing an operator wants to SEE on the dashboard — so the enrolment
/// half is split out here and the shaper-driven [`docket_enroll`] now delegates to it. One
/// registration path, two ways to reach it, so the two can never drift.
pub(crate) fn docket_enroll_raw(
    key: i64,
    proto: i32,
    tin: i32,
    paced: bool,
) -> std::sync::Arc<crate::tunnel::FlowLive> {
    let live = std::sync::Arc::new(crate::tunnel::FlowLive::new(key, proto, tin, paced));
    crate::tunnel::docket_register(&live);
    live
}

/// DNS PRESERVE: read the query off the UDP flow, answer via the sovereign resolver, write the reply back.
/// This is why turning the forwarder on does NOT break DNS — a :53 flow is resolved, never forwarded.
async fn answer_dns_udp(udp: &mut ipstack::stream::IpStackUdpStream, fwd: &ForwarderStats) {
    let mut buf = vec![0u8; 1500];
    // One datagram (a DNS query is a single packet on this flow).
    let n = match udp.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    buf.truncate(n);
    // The resolver is a SYNC seam whose transports `block_on` their own runtime (resolver/mod.rs) —
    // it MUST ride the blocking pool here (the listener.rs law). Called inline on this tokio worker,
    // the inner `block_on` panics ("cannot block within a runtime"), `resolve`'s catch_unwind
    // firewall converts that to None + a `panics` tick, and every :53 flow silently answers nothing.
    let reply = tokio::task::spawn_blocking(move || crate::resolver::resolve_datapath(&buf)).await;
    if let Some(reply) = reply.ok().flatten() {
        // A4 — remember `answer IP → query qname` while the reply is in our hands: the flow the
        // app dials next carries the domain into warden_allows' judgment + the LIVE FLOWS row.
        // Best-effort by law (attribution.rs) — a malformed/empty reply records nothing.
        let _ = crate::warden::attribution::record_from_reply(&reply);
        if udp.write_all(&reply).await.is_ok() {
            fwd.dns_answered.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// N3 — forward a UDP flow: a protected upstream UdpSocket connected to `dst`, splice both directions until
/// idle/EOF. The first witness: a QUIC/HTTP3 (or plain UDP) app flows through the tun.
async fn forward_udp(
    mut client: ipstack::stream::IpStackUdpStream,
    dst: SocketAddr,
    protect: ProtectFn,
    live: &std::sync::Arc<crate::tunnel::FlowLive>,
    fwd: &ForwarderStats,
) {
    let upstream = match connect_udp_protected(dst, &protect, fwd).await {
        Some(u) => u,
        None => {
            error!("forward_udp: connect_udp_protected failed for dst={}", dst);
            return;
        }
    };
    let mut cbuf = vec![0u8; 65535];
    let mut ubuf = vec![0u8; 65535];
    loop {
        tokio::select! {
            r = client.read(&mut cbuf) => match r {
                Ok(n) if n > 0 => {
                    if upstream.send(&cbuf[..n]).await.is_err() { break; }
                    fwd.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                    live.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                }
                _ => break,
            },
            r = upstream.recv(&mut ubuf) => match r {
                Ok(n) if n > 0 => {
                    if client.write_all(&ubuf[..n]).await.is_err() { break; }
                    fwd.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                    live.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                }
                _ => break,
            },
        }
    }
}

/// ★ #22 slice 3 · N7 — forward a BULK (Normal-tin) UDP flow YeAH-PACED: the UDP twin of N5, with
/// UDP-NATIVE signals (UDP has no write-drain backpressure — sendto rarely blocks — so N5's signal
/// pair is replaced by the transaction pair the resolver's own YEAH-UDP lane pioneered):
///   - PACER — each client→upstream burst is capped by the live `write_budget()` (cwnd × segment).
///   - RTT EAR — a clean request→response pair (EXACTLY one send outstanding when the answer lands)
///     is a real transaction RTT: fed as the flow's sample. A second in-flight send breaks the
///     pairing → disarmed, NO fake sample (the honesty law; pipelined QUIC gets pacing, not noise).
///   - LOSS EAR — a paired request unanswered past the flow's live `adaptive_timeout_ms()` IS the
///     UDP loss event: the YeAH loss reaction fires (RHO-gated surgical/halve) and the flow LIVES
///     (QUIC retransmits; a truly-dead path keeps shedding to MIN_WINDOW — backoff, never a kill).
///     A send error stalls + ends the flow (N5 parity).
async fn forward_udp_paced(
    mut client: ipstack::stream::IpStackUdpStream,
    dst: SocketAddr,
    protect: ProtectFn,
    mut shaper: FlowShaper,
    live: &std::sync::Arc<crate::tunnel::FlowLive>,
    fwd: &ForwarderStats,
) {
    let upstream = match connect_udp_protected(dst, &protect, fwd).await {
        Some(u) => u,
        None => {
            error!(
                "forward_udp_paced: connect_udp_protected failed for dst={}",
                dst
            );
            return;
        }
    };
    let mut cbuf = vec![0u8; 65535];
    let mut ubuf = vec![0u8; 65535];
    // Armed when EXACTLY one request awaits its answer (the transaction pairing).
    let mut pending: Option<std::time::Instant> = None;
    loop {
        // The pacer: never read (hence never send) more than the live cwnd budget per burst.
        let budget = shaper.write_budget().min(cbuf.len());
        // The loss-ear deadline anchors to the ORIGINAL send instant, not the loop turn.
        let answer_deadline = match pending {
            Some(t0) => {
                tokio::time::Instant::from_std(t0)
                    + std::time::Duration::from_millis(shaper.adaptive_timeout_ms() as u64)
            }
            None => tokio::time::Instant::now() + std::time::Duration::from_secs(3600),
        };
        tokio::select! {
            r = client.read(&mut cbuf[..budget]) => match r {
                Ok(n) if n > 0 => {
                    // Pairing law: first send arms; a second in-flight send breaks the pair.
                    pending = if pending.is_none() {
                        Some(std::time::Instant::now())
                    } else {
                        None
                    };
                    if upstream.send(&cbuf[..n]).await.is_err() {
                        shaper.on_stall();
                        // ★ #52 — the REACTION, not the I/O event: `stalls` below counts the failed
                        // write; this counts the YeAH window collapse the shaper took because of it.
                        crate::beast::feed_live_flow_loss();
                        fwd.stalls.fetch_add(1, Ordering::Relaxed);
                        live.stalls.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    fwd.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                    live.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                }
                _ => break,
            },
            r = upstream.recv(&mut ubuf) => match r {
                Ok(n) if n > 0 => {
                    if let Some(t0) = pending.take() {
                        // A clean transaction pair — the flow's REAL RTT sample.
                        let rtt_ms = t0.elapsed().as_secs_f64() * 1000.0;
                        shaper.sample(rtt_ms);
                        // ★ #52 — THE RETURN LEG (UDP side): the same completed-transaction RTT the
                        // flow's brain consumed, with the window it reached. DISPLAY lane.
                        crate::beast::feed_live_flow_shape(rtt_ms, shaper.cwnd());
                        // ★ THE STEERING LEG (UDP side). The display leg above shows the Beast
                        // what happened; this one lets it ACT. Before it existed the window brain
                        // had one reachable caller in the whole crate (resolver/mod.rs:1662), so a
                        // device resolving through the external dnscrypt-proxy left cwnd pinned at
                        // 1/16 for every logged tick while the display RTT read live.
                        crate::beast::feed_live_flow_rtt(rtt_ms, true);
                        // #96 — floor a real sub-millisecond sample at 1ms. `round()` alone lands
                        // on 0, the value the docket reserves for "impossible" (see
                        // `rtt_display_ms`), and the panel then shows a working flow as if it had
                        // no reading at all.
                        live.rtt_ms
                            .store(crate::tunnel::rtt_display_ms(rtt_ms), Ordering::Relaxed);
                        fwd.rtt_samples.fetch_add(1, Ordering::Relaxed);
                        fwd.cwnd_last.store(shaper.cwnd(), Ordering::Relaxed);
                        live.cwnd.store(shaper.cwnd(), Ordering::Relaxed);
                    }
                    if client.write_all(&ubuf[..n]).await.is_err() { break; }
                    fwd.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                    live.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                }
                _ => break,
            },
            _ = tokio::time::sleep_until(answer_deadline), if pending.is_some() => {
                // THE UDP TRANSACTION-LOSS EAR: request sent, adaptive window elapsed, no answer.
                pending = None;
                shaper.on_stall();
                // ★ #52 — the UDP transaction-loss ear IS a congestion event (the first UDP
                // congestion algorithm's loss sense), so it reaches the engine's reaction count.
                crate::beast::feed_live_flow_loss();
                fwd.stalls.fetch_add(1, Ordering::Relaxed);
                live.stalls.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// ★ #65 hairpin — a TCP flow dialed at the cloak sentinel (`CLOAK_SENTINEL_V4` `10.1.10.3` / its V6
/// twin) is an app chasing the resolver's LocalCDN→Centauri redirect answer (resolver/local.rs:180-181).
/// The sentinel is intentionally unroutable: rewrite the dst to the in-app mirror's live loopback
/// listener (`127.0.0.1:<mirror_hairpin_port()>`) so the asset is served from the offline-CDN cache.
/// Port `0` (mirror OFF / bind failed) ⇒ NO rewrite — the sentinel dial fails naturally, never a
/// mis-routed loopback connect. UDP to the sentinel is deliberately NOT hairpinned (the mirror is
/// TCP-only; a QUIC attempt fails fast and the client falls back to TCP, which lands here).
/// LIFTED to [`super::hairpin_dst`] — see the note there. `run.rs` is `#[cfg(unix)]`, so anything left
/// here can never be gated on this host; the decision now lives cross-platform and only the CALL stays.
use super::hairpin_dst;

/// How long we will wait for a client to finish sending its ClientHello before giving up on naming the
/// flow. A local app writes its hello in the same breath as the SYN-ACK; 5s is generous. Without this a
/// client that connects and then says nothing would pin a task forever.
#[cfg(feature = "mirror")]
const SNI_PEEK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// ★ #66 — TERMINATE the cloaked TLS flow locally and serve the asset from the OFFLINE catalog.
///
/// This is Centauri's actual promise, finally reachable on `:443`: the asset is fetched from the CDN at
/// most ONCE in its life (and often never — the catalog ships pre-absorbed), then served from the
/// on-device content-addressed store forever after. The CDN does not see the user on any subsequent
/// load, on any app, across restarts.
///
/// ## How it reuses the proven path instead of duplicating it
/// After the handshake completes we hold a plaintext byte stream carrying an ordinary HTTP/1.1 request
/// (`GET /ajax/libs/... Host: ajax.googleapis.com`). Rather than re-implement routing, catalog
/// authorization, hash verification and the absorb-once fetch, we splice that plaintext straight to the
/// mirror's EXISTING loopback listener — the same server the `:80` hairpin has been serving from since
/// #65. Every guarantee it already carries applies unchanged:
///   - a catalog-authorized cache hit ⇒ served local, ZERO egress;
///   - an authorized miss ⇒ EXACTLY ONE upstream `fetch_once`, hash-verified against the minisign-signed
///     catalog, cached, then served (`LeakedThenServed`) — and local forever after;
///   - anything unauthorized ⇒ fail-closed 503/404. It does NOT quietly fall through to the network.
///
/// So this function adds a TLS wrapper and nothing else. The security-relevant logic stays in one place.
/// ★ #65 — a stream that REPLAYS already-consumed bytes before delegating to the real one.
///
/// The SNI peek must read the ClientHello off the wire to learn the hostname, which consumes it. The
/// splice path always knew this and replayed its buffer verbatim before handing the socket on; the
/// LOCAL-SERVE path did not, so it passed a drained socket to `TlsAcceptor::accept` and rustls sat
/// waiting for a ClientHello the client had already sent. Nothing failed and nothing logged — the flow
/// simply hung until the browser gave up with `ERR_TIMED_OUT`.
///
/// Wrapping the socket so the peeked bytes are re-served first makes the acceptor see the byte stream
/// the client actually sent, unmodified and in order.
#[cfg(feature = "mirror")]
struct ReplayStream<S> {
    /// The bytes the peek already took. Drained first, then never touched again.
    prefix: Vec<u8>,
    /// How much of `prefix` has been handed back.
    pos: usize,
    inner: S,
}

#[cfg(feature = "mirror")]
impl<S> tokio::io::AsyncRead for ReplayStream<S>
where
    S: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let take = (self.prefix.len() - self.pos).min(buf.remaining());
            let end = self.pos + take;
            let start = self.pos;
            // Split the borrow: copy out of `prefix` before touching `pos`.
            let slice = &self.prefix[start..end];
            buf.put_slice(slice);
            self.pos = end;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "mirror")]
impl<S> tokio::io::AsyncWrite for ReplayStream<S>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "mirror")]
async fn centauri_serve_local_tls<S>(
    client: S,
    host: &str,
    live: &std::sync::Arc<crate::tunnel::FlowLive>,
    fwd: &ForwarderStats,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(cfg) = crate::CENTAURI_TLS_CONFIG.get() else {
        fwd.centauri_tls_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // The mirror must actually be listening; port 0 means it never bound (see `mirror_hairpin_port`).
    let port = crate::mirror_hairpin_port();
    if port == 0 {
        fwd.centauri_tls_failed.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Complete the handshake using a leaf minted for the SNI rustls itself parsed. A client that has not
    // installed the device CA REJECTS here — never silently downgraded to a CDN fetch behind the user's
    // back. THIS flow is already lost when `accept()` returns Err (rustls has written the alert and the
    // peer has torn down), so the recovery is for the NEXT one: record the refusal, which un-cloaks the
    // host on the DNS plane so its name resolves to the real CDN again and the app that refused us is
    // whole on its retry. Measured need — the forwarder reported `tls_failed = 2` on the AVD.
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::clone(cfg));
    let Ok(mut tls) = acceptor.accept(client).await else {
        fwd.centauri_tls_failed.fetch_add(1, Ordering::Relaxed);
        crate::mirror::localcdn::note_tls_rejected(host);
        return;
    };

    // Loopback to our own listener — no `protect(fd)` needed (127.0.0.1 never enters the tun) and no
    // network involved at all.
    let local = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port);
    let Ok(mut mirror) = tokio::net::TcpStream::connect(local).await else {
        fwd.centauri_tls_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    fwd.centauri_tls_served.fetch_add(1, Ordering::Relaxed);
    if let Ok((up, down)) = tokio::io::copy_bidirectional(&mut tls, &mut mirror).await {
        fwd.bytes_up.fetch_add(up, Ordering::Relaxed);
        live.bytes_up.fetch_add(up, Ordering::Relaxed);
        fwd.bytes_down.fetch_add(down, Ordering::Relaxed);
        live.bytes_down.fetch_add(down, Ordering::Relaxed);
    }
}

/// ★ #66-A — the Centauri HTTPS seam: name the flow, then splice it to the REAL CDN.
///
/// ## The problem this exists to solve
/// The DNS cloak answers every watched-CDN host with ONE sentinel address, and (before this) the hairpin
/// rewrote every sentinel flow to the plain-HTTP mirror REGARDLESS of port. A browser fetching
/// `https://ajax.googleapis.com/...` therefore sent a TLS ClientHello into a plain-HTTP server: the
/// handshake could not complete, and the asset broke with no fallback. Arming the cloak degraded
/// browsing — the opposite of the pillar's purpose.
///
/// ## What it does
/// Peeks the ClientHello ([`super::sni::peek_sni`]) to recover the hostname the DNS layer collapsed, resolves
/// it with the cloak bypassed ([`crate::resolver::resolve_uncloaked_addrs`]), dials the genuine CDN over
/// a protected socket, replays the peeked bytes verbatim, and splices. The client completes a normal,
/// end-to-end-authentic TLS handshake with the REAL server: no MITM, no certificate to trust, nothing
/// for the client to detect. The peek is byte-transparent — every byte read is forwarded.
///
/// ## Why a splice and not a local serve (yet)
/// Serving a cached asset over HTTPS means terminating TLS, which means presenting a certificate for a
/// name we do not own — only possible once a device CA exists and is trusted (checkpoints B/C). Until
/// then the honest behavior is to carry the flow through unchanged. When C lands, this same function
/// gains ONE branch — servable-and-trusted terminates locally, EVERYTHING else keeps falling through to
/// this splice — so the never-break guarantee stays structural rather than becoming a mode.
///
/// A flow we cannot name (a non-TLS protocol on `:443`, or a client that never finishes its hello) is
/// DROPPED rather than guessed at: with no hostname there is no correct upstream, and dialling
/// something invented would be worse than a closed connection.
#[cfg(feature = "mirror")]
async fn centauri_https_seam(
    mut client: ipstack::stream::IpStackTcpStream,
    protect: ProtectFn,
    live: &std::sync::Arc<crate::tunnel::FlowLive>,
    fwd: &ForwarderStats,
) {
    // ---- 1. Peek until the hello names the flow (bounded in BOTH bytes and time) ----------------
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let host = loop {
        match super::sni::peek_sni(&buf) {
            super::sni::SniOutcome::Found(h) => break h,
            // No name is coming: a non-TLS first flight, or a hello with no SNI. Terminal.
            super::sni::SniOutcome::NotTls => return,
            super::sni::SniOutcome::Incomplete => {}
        }
        if buf.len() >= super::sni::MAX_CLIENT_HELLO_PEEK {
            return; // never buffer without bound for a peer that will not complete a hello
        }
        match tokio::time::timeout(SNI_PEEK_TIMEOUT, client.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return, // clean EOF, read error, or a silent peer
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    fwd.centauri_sni_peeked.fetch_add(1, Ordering::Relaxed);

    // ---- 1b. LOCAL SERVE: the destination, not a fallback ---------------------------------------
    // Centauri's thesis: a watched CDN asset is fetched at most ONCE and is local forever after. When
    // the TLS leg is armed we terminate the handshake here with a leaf minted for the peeked SNI and
    // hand the decrypted request to the SAME `MirrorServer` serve path the `:80` hairpin already uses —
    // which serves from the content-addressed store, absorbs exactly once on an authorized miss
    // (`serve::serve_addressed` → `fetch_leg`), and fail-closes on anything unauthorized. The CDN is
    // contacted at most one time in the asset's entire life, and never again on any device restart.
    // ARMED alone is NOT enough: the leg must be able to serve. When it cannot (no CA config, mirror
    // not bound) the ClientHello is still unread, so the flow falls through to the splice below rather
    // than dying — the `lib.rs` fallback contract, which an unconditional `return` here used to break.
    if crate::CENTAURI_TLS_ARMED.load(Ordering::Relaxed) && super::centauri_local_serve_ready(fwd) {
        // The peek above CONSUMED the ClientHello into `buf`. Hand the acceptor a stream that replays
        // those bytes first — without this it waits for a hello that has already been sent and the flow
        // hangs until the browser times out.
        centauri_serve_local_tls(
            ReplayStream {
                prefix: buf,
                pos: 0,
                inner: client,
            },
            &host,
            live,
            fwd,
        )
        .await;
        return;
    }

    // ---- 2. Resolve the REAL address, cloak bypassed --------------------------------------------
    // `resolve_uncloaked_addrs` drives the resolver's OWN runtime with `block_on`; calling that on a
    // tokio worker would panic ("cannot start a runtime from within a runtime"), so it goes to the
    // blocking pool. A join error (pool shutting down mid-flight) is a dead flow, never an unwind.
    let addrs =
        match tokio::task::spawn_blocking(move || crate::resolver::resolve_uncloaked_addrs(&host))
            .await
        {
            Ok(a) => a,
            Err(_) => {
                fwd.centauri_splice_failed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
    let Some(&ip) = addrs.first() else {
        // NXDOMAIN, blocked, or no pool. A BLOCKED CDN host lands here too — and dropping the flow is
        // exactly right for it: the block must hold on the HTTPS leg just as it does at the DNS layer.
        fwd.centauri_splice_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };

    // ---- 3. Dial the genuine CDN and splice ------------------------------------------------------
    let real = SocketAddr::new(ip, super::HTTPS_PORT);
    let dial = std::time::Instant::now();
    let Some(mut upstream) = connect_tcp_protected(real, &protect, fwd).await else {
        fwd.centauri_splice_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    crate::beast::feed_live_tcp_dial(dial.elapsed().as_secs_f64() * 1000.0);
    // Replay the peeked hello FIRST — the upstream must see the client's bytes unmodified and in order,
    // or the handshake it completes is not the one the client started.
    if upstream.write_all(&buf).await.is_err() {
        fwd.centauri_splice_failed.fetch_add(1, Ordering::Relaxed);
        return;
    }
    fwd.bytes_up.fetch_add(buf.len() as u64, Ordering::Relaxed);
    live.bytes_up.fetch_add(buf.len() as u64, Ordering::Relaxed);
    fwd.centauri_spliced.fetch_add(1, Ordering::Relaxed);
    if let Ok((up, down)) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        fwd.bytes_up.fetch_add(up, Ordering::Relaxed);
        live.bytes_up.fetch_add(up, Ordering::Relaxed);
        fwd.bytes_down.fetch_add(down, Ordering::Relaxed);
        live.bytes_down.fetch_add(down, Ordering::Relaxed);
    }
}

/// N2 — forward a TCP flow: a protected upstream TcpStream connected to `dst`, `copy_bidirectional`. This is
/// the PAGE-LOAD path (the North Star: a real page renders when these flow).
async fn forward_tcp(
    mut client: ipstack::stream::IpStackTcpStream,
    dst: SocketAddr,
    protect: ProtectFn,
    live: &std::sync::Arc<crate::tunnel::FlowLive>,
    fwd: &ForwarderStats,
) {
    // ★ #66-A — a sentinel flow on :443 is a TLS client; the plain-HTTP mirror cannot answer it.
    // Name it by its SNI and splice it to the real CDN instead (never a broken asset).
    #[cfg(feature = "mirror")]
    if matches!(super::classify_tcp(dst), super::TcpRoute::HttpsSeam) {
        centauri_https_seam(client, protect, live, fwd).await;
        return;
    }
    // ★ #65 — remaining sentinel flows (:80) hairpin to the in-app mirror before the protected dial.
    let dst = hairpin_dst(dst);
    let dial = std::time::Instant::now();
    let mut upstream = match connect_tcp_protected(dst, &protect, fwd).await {
        Some(u) => u,
        None => {
            error!("forward_tcp: connect_tcp_protected failed for dst={}", dst);
            return;
        }
    };
    // #3-EXT — the dial elapsed (SYN→established) IS this flow's TCP network RTT: feed the live
    // Beast's TCP display lane (base-RTT EWMA + true-min floor) — the YeAH TCP metrics' real food.
    crate::beast::feed_live_tcp_dial(dial.elapsed().as_secs_f64() * 1000.0);
    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok((up, down)) => {
            fwd.bytes_up.fetch_add(up, Ordering::Relaxed);
            live.bytes_up.fetch_add(up, Ordering::Relaxed);
            fwd.bytes_down.fetch_add(down, Ordering::Relaxed);
            live.bytes_down.fetch_add(down, Ordering::Relaxed);
        }
        Err(e) => {
            error!(
                "forward_tcp: copy_bidirectional failed for dst={}: {:?}",
                dst, e
            );
        }
    }
}

/// N5 — forward a BULK (Normal-tin) TCP flow YeAH-PACED: each client→upstream burst is capped at the
/// shaper's live `write_budget()` (cwnd × segment), and the upstream write-drain latency is fed back as
/// the flow's REAL RTT sample. When the upstream path congests, the kernel send buffer fills, `write_all`
/// awaits, the sample rises, YeAH sheds window → the bulk flow backs off BEFORE it bloats the queue the
/// CRITICAL/HIGH tins share. The download direction (upstream→client) splices unpaced — the remote drives
/// it and our uplink is the queue we own. A write error is a stall (the YeAH loss reaction) + flow end.
async fn forward_tcp_paced(
    mut client: ipstack::stream::IpStackTcpStream,
    dst: SocketAddr,
    protect: ProtectFn,
    mut shaper: FlowShaper,
    live: &std::sync::Arc<crate::tunnel::FlowLive>,
    fwd: &ForwarderStats,
) {
    // ★ #66-A — same law as `forward_tcp`: a :443 sentinel flow is TLS, so it takes the SNI-peek splice
    // rather than the plain-HTTP hairpin. (The seam splices unpaced: the CDN drives the download and a
    // cached-asset fetch is short — pacing belongs on the bulk flows this arm was built for.)
    #[cfg(feature = "mirror")]
    if matches!(super::classify_tcp(dst), super::TcpRoute::HttpsSeam) {
        centauri_https_seam(client, protect, live, fwd).await;
        return;
    }
    // ★ #65 — same law as `forward_tcp`: remaining sentinel flows hairpin to the in-app mirror.
    let dst = hairpin_dst(dst);
    let dial = std::time::Instant::now();
    let mut upstream = match connect_tcp_protected(dst, &protect, fwd).await {
        Some(u) => u,
        None => {
            error!(
                "forward_tcp_paced: connect_tcp_protected failed for dst={}",
                dst
            );
            return;
        }
    };
    // #3-EXT — same law as `forward_tcp`: the handshake elapsed feeds the TCP display lane.
    crate::beast::feed_live_tcp_dial(dial.elapsed().as_secs_f64() * 1000.0);
    let mut cbuf = vec![0u8; 64 * 1024];
    let mut ubuf = vec![0u8; 64 * 1024];
    loop {
        // The pacer: never read (hence never write) more than the live cwnd budget per burst.
        let budget = shaper.write_budget().min(cbuf.len());
        tokio::select! {
            r = client.read(&mut cbuf[..budget]) => match r {
                Ok(n) if n > 0 => {
                    let start = std::time::Instant::now();
                    if upstream.write_all(&cbuf[..n]).await.is_err() {
                        shaper.on_stall();
                        // ★ #52 — same law as the UDP side: report the REACTION, not just the I/O.
                        crate::beast::feed_live_flow_loss();
                        fwd.stalls.fetch_add(1, Ordering::Relaxed);
                        live.stalls.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    // Write-drain latency = the real congestion signal for THIS flow (backpressure
                    // surfaces here when the kernel send buffer is full).
                    let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
                    shaper.sample(rtt_ms);
                    // ★ #52 — THE RETURN LEG: hand the Beast pillar the SAME sample this flow's own
                    // YeAH brain just consumed, paired with the window it converged on. Display
                    // lane: the DISPLAY half (`beast::fold_shaped_sample`).
                    crate::beast::feed_live_flow_shape(rtt_ms, shaper.cwnd());
                    // ★ THE STEERING LEG (TCP side) — the same sample into the WINDOW BRAIN,
                    // through the identical door and guards the resolver uses (`feed_rtt_into`).
                    // This comment used to read "it steers nothing". It now steers.
                    crate::beast::feed_live_flow_rtt(rtt_ms, false);
                    // N6 — the fountain's live gauges: samples fed + the freshest window.
                    fwd.rtt_samples.fetch_add(1, Ordering::Relaxed);
                    fwd.cwnd_last.store(shaper.cwnd(), Ordering::Relaxed);
                    // ★ #47 N8 — the per-flow twin of those gauges: THIS flow's own window and its
                    // own measured RTT, so the docket row shows what the engine is doing to it.
                    live.cwnd.store(shaper.cwnd(), Ordering::Relaxed);
                    // #96 — the TCP paced-write sample. This is the site the AVD caught: a BULK
                    // PACED flow that had moved 989 B in 40 s still rendered `rtt 0ms`, because
                    // `round()` alone lands on the value the docket reserves for "impossible".
                    // Same law as the other two sample sites — see `tunnel::rtt_display_ms`.
                    live.rtt_ms.store(
                        crate::tunnel::rtt_display_ms(start.elapsed().as_secs_f64() * 1000.0),
                        Ordering::Relaxed,
                    );
                    fwd.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                    live.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                }
                _ => break,
            },
            r = upstream.read(&mut ubuf) => match r {
                Ok(n) if n > 0 => {
                    if client.write_all(&ubuf[..n]).await.is_err() { break; }
                    fwd.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                    live.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                }
                _ => break,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ★ #65 tri-constant pin — the hairpin's sentinel match (`resolver::local::CLOAK_SENTINEL_V4`),
    /// the DNS-layer string form (`mirror::localcdn::CLOAK_SENTINEL_IP`, the hostfile rule the resolver
    /// emits), and this rewrite seam must NEVER drift apart: the forwarder only ever sees the address
    /// localcdn.rs told the resolver to answer.
    #[cfg(feature = "mirror")]
    #[test]
    fn hairpin_sentinel_matches_localcdn_string() {
        let from_localcdn: std::net::Ipv4Addr = crate::mirror::localcdn::CLOAK_SENTINEL_IP
            .parse()
            .expect("CLOAK_SENTINEL_IP must parse as IPv4");
        assert_eq!(from_localcdn, crate::resolver::local::CLOAK_SENTINEL_V4);
    }

    /// A non-sentinel dst passes through IDENTICAL — the hairpin must never touch a real flow.
    #[test]
    fn hairpin_leaves_real_flows_untouched() {
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        assert_eq!(hairpin_dst(dst), dst);
    }

    /// Mirror not started (port 0) ⇒ NO rewrite: the sentinel dial fails naturally rather than
    /// mis-routing to `127.0.0.1:0`. (With the OnceLock unset in the test process this is the
    /// observable branch; the ARMED rewrite is proved on-device per the GROUND_TRUTH gate.)
    #[test]
    fn hairpin_without_mirror_leaves_sentinel_alone() {
        let dst = SocketAddr::new(
            std::net::IpAddr::V4(crate::resolver::local::CLOAK_SENTINEL_V4),
            443,
        );
        let out = hairpin_dst(dst);
        assert!(out == dst || out.ip().is_loopback());
        assert_ne!(out.port(), 0, "never a rewrite to port 0");
    }
}
